//! Plugin lifecycle, native registration, and SA:MP/Pawn boundary for PGStream.

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::str::FromStr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

use crate::abi::amx::{self, Amx, Cell};
use crate::abi::callbacks;
use crate::config;
use crate::database::connection::{ConnectionStatus, PgConnection};
use crate::database::format::{self, FormatArgKind};
use crate::database::parameters::SqlParam;
use crate::database::result::QueryResult;
use crate::handles::{self, CONNECTIONS, RESULTS};
use crate::runtime::{self, CompletionEvent};

static AMX_TABLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static LOGPRINTF: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// Result id exposed as the "active cache" during a PG_TQuery callback
/// dispatch, or right after PG_SyncQuery. Main-thread only (ProcessTick /
/// natives).
static ACTIVE_RESULT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

pub(crate) unsafe fn table_fn<T: Copy>(idx: usize) -> Option<T> {
    let table = AMX_TABLE.load(Ordering::Relaxed);
    if table.is_null() {
        return None;
    }
    Some(ptr::read(
        (table as *const *const c_void).add(idx) as *const T
    ))
}

pub fn logprintf(msg: &str) {
    let lp_ptr = LOGPRINTF.load(Ordering::Relaxed);
    if !lp_ptr.is_null() {
        let lp: amx::LogPrintfFn = unsafe { std::mem::transmute(lp_ptr) };
        let mut text = msg.to_owned();
        text.push('\0');
        unsafe {
            lp(
                b"%s\0".as_ptr() as *const c_char,
                text.as_ptr() as *const c_char,
            )
        };
    }
}

pub const VERSION_CODE: Cell = 302;
pub const VERSION_TEXT: &str = "PGStream 0.3.2";

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

/// TLS connector with full certificate validation (sslmode=verify-full).
/// Uses ring provider, TLS1.2/TLS1.3, and webpki roots for hostname check.
fn make_tls_connector_verified() -> tokio_postgres_rustls::MakeRustlsConnect {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = rustls::crypto::ring::default_provider();
    let tls_config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tokio_postgres_rustls::MakeRustlsConnect::new(tls_config)
}

/// TLS connector that encrypts but does NOT verify the server certificate.
/// Matches PostgreSQL sslmode=require behavior.
fn make_tls_connector_novalidate() -> tokio_postgres_rustls::MakeRustlsConnect {
    let provider = rustls::crypto::ring::default_provider();
    let tls_config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerifier))
        .with_no_client_auth();
    tokio_postgres_rustls::MakeRustlsConnect::new(tls_config)
}

/// Certificate verifier that accepts everything — for sslmode=require.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Plugin Lifecycle
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Supports() -> u32 {
    amx::SAMP_PLUGIN_VERSION | amx::SUPPORTS_AMX_NATIVES | amx::SUPPORTS_PROCESS_TICK
}

#[no_mangle]
pub unsafe extern "system" fn Load(pp_data: *mut *mut c_void) -> bool {
    AMX_TABLE.store(*pp_data.add(amx::slot::AMX_EXPORTS), Ordering::Relaxed);
    LOGPRINTF.store(*pp_data.add(amx::slot::LOGPRINTF), Ordering::Relaxed);

    runtime::init_runtime();

    let cfg = config::Config::global();
    logprintf(&format!(
        "{} initialized (Max connections: {}, Host: {})",
        VERSION_TEXT, cfg.pool.max_size, cfg.database.host
    ));

    !AMX_TABLE.load(Ordering::Relaxed).is_null()
}

#[no_mangle]
pub extern "system" fn Unload() {
    runtime::shutdown_runtime();
    logprintf("[PGStream] unloaded.");
}

#[no_mangle]
pub unsafe extern "system" fn AmxLoad(amx_ptr: *mut Amx) -> c_int {
    callbacks::register_amx(amx_ptr);
    let register: Option<amx::AmxRegisterFn> = table_fn(amx::slot::REGISTER);
    match register {
        Some(register) => register(amx_ptr, PG_NATIVES.as_ptr(), -1),
        None => amx::AMX_ERR_NATIVE,
    }
}

#[no_mangle]
pub extern "system" fn AmxUnload(amx_ptr: *mut Amx) -> c_int {
    callbacks::unregister_amx(amx_ptr);
    amx::AMX_ERR_NONE
}

#[no_mangle]
pub extern "system" fn ProcessTick() {
    let events = runtime::poll_completions();
    for event in events {
        match event {
            CompletionEvent::Connected {
                conn_id,
                success,
                callback,
            } => {
                let s: Cell = if success { 1 } else { 0 };
                callbacks::dispatch_callback(&callback, &[conn_id, s]);
                flush_pending(conn_id);
            }
            CompletionEvent::QueryFinished {
                conn_id,
                result_id,
                callback,
                extra,
            } => {
                callbacks::dispatch_callback(&callback, &[conn_id, result_id, extra]);
            }
            CompletionEvent::QueryFinishedExtras {
                conn_id,
                result_id,
                callback,
                query,
                extras,
            } => {
                // mysql_tquery compat: expose the result as the "active cache"
                // for the duration of the dispatch, fire OnQueryError on SQL
                // errors, then free the result automatically.
                ACTIVE_RESULT.store(result_id, Ordering::Relaxed);
                let had_error = {
                    let results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
                    results
                        .get(&result_id)
                        .map(|r| r.error.is_some())
                        .unwrap_or(true)
                };
                if had_error {
                    let err = {
                        let results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
                        results
                            .get(&result_id)
                            .and_then(|r| r.error.clone())
                            .unwrap_or_else(|| "unknown query error".into())
                    };
                    callbacks::dispatch_callback_mixed(
                        "OnQueryError",
                        &[
                            runtime::ExtraArg::Cell(0),
                            runtime::ExtraArg::Str(err),
                            runtime::ExtraArg::Str(callback.clone()),
                            runtime::ExtraArg::Str(query),
                            runtime::ExtraArg::Cell(conn_id),
                        ],
                    );
                }
                callbacks::dispatch_callback_mixed(&callback, &extras);
                ACTIVE_RESULT.store(0, Ordering::Relaxed);
                handles::free_result(result_id);
            }
            CompletionEvent::CommandFinished {
                conn_id,
                success,
                callback,
            } => {
                let s: Cell = if success { 1 } else { 0 };
                callbacks::dispatch_callback(&callback, &[conn_id, s]);
            }
            CompletionEvent::Notification {
                conn_id,
                channel,
                payload,
            } => {
                callbacks::dispatch_notification(conn_id, &channel, &payload);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

unsafe fn read_string_arg(amx_ptr: *mut Amx, params: *mut Cell, arg_idx: Cell) -> Option<String> {
    let get_addr: amx::AmxGetAddrFn = table_fn(amx::slot::GET_ADDR)?;
    let get_string: amx::AmxGetStringFn = table_fn(amx::slot::GET_STRING)?;
    let str_len: amx::AmxStrLenFn = table_fn(amx::slot::STR_LEN)?;
    let addr = amx::native_arg(params, arg_idx)?;
    amx::get_amx_string(amx_ptr, addr, get_addr, str_len, get_string)
}

unsafe fn write_string_dest(
    amx_ptr: *mut Amx,
    params: *mut Cell,
    dest_idx: Cell,
    size_idx: Cell,
    text: &str,
) -> Cell {
    let get_addr: amx::AmxGetAddrFn = match table_fn(amx::slot::GET_ADDR) {
        Some(f) => f,
        None => return amx::AMX_ERR_NATIVE,
    };
    let set_string: amx::AmxSetStringFn = match table_fn(amx::slot::SET_STRING) {
        Some(f) => f,
        None => return amx::AMX_ERR_NATIVE,
    };

    let Some(dest_addr) = amx::native_arg(params, dest_idx) else {
        return amx::AMX_ERR_PARAMS;
    };
    let size = amx::native_arg(params, size_idx).unwrap_or(0).max(0) as usize;
    if size == 0 {
        return amx::AMX_ERR_PARAMS;
    }

    let mut phys: *mut Cell = ptr::null_mut();
    if get_addr(amx_ptr, dest_addr, &mut phys) != amx::AMX_ERR_NONE || phys.is_null() {
        return amx::AMX_ERR_NATIVE;
    }

    let mut src = text.to_owned();
    src.push('\0');
    let capacity = size.min(src.len());
    if set_string(phys, src.as_ptr() as *const c_char, 0, 0, capacity) != amx::AMX_ERR_NONE {
        return amx::AMX_ERR_NATIVE;
    }
    1
}

unsafe fn parse_variadic_params(
    amx_ptr: *mut Amx,
    params: *mut Cell,
    format: &str,
    start_arg: Cell,
) -> Vec<SqlParam> {
    let mut sql_params: Vec<SqlParam> = Vec::new();
    let mut arg_cursor = start_arg;
    // get_addr: pawncc 3.2.3664 (SA-MP) pushes `...` varargs as AMX addresses to
    // temporary cells; ints/floats/bools must be dereferenced, strings are also
    // read through their address. shortcut: ties behavior to this compiler
    // version — upgrade check if pawncc/open.mp toolchain changes.
    let get_addr = match table_fn::<amx::AmxGetAddrFn>(amx::slot::GET_ADDR) {
        Some(f) => f,
        None => return sql_params,
    };
    for ch in format.chars() {
        match ch {
            'd' | 'i' => {
                let addr = amx::native_arg(params, arg_cursor).unwrap_or(0);
                let val = deref_vararg_cell(amx_ptr, addr, get_addr);
                sql_params.push(SqlParam::Int(val));
                arg_cursor += 1;
            }
            'f' => {
                let addr = amx::native_arg(params, arg_cursor).unwrap_or(0);
                let bits = deref_vararg_cell(amx_ptr, addr, get_addr);
                let val = f32::from_bits(bits as u32) as f64;
                sql_params.push(SqlParam::Float(val));
                arg_cursor += 1;
            }
            's' => {
                let s = read_string_arg(amx_ptr, params, arg_cursor).unwrap_or_default();
                sql_params.push(SqlParam::String(s));
                arg_cursor += 1;
            }
            'b' => {
                let addr = amx::native_arg(params, arg_cursor).unwrap_or(0);
                let val = deref_vararg_cell(amx_ptr, addr, get_addr);
                sql_params.push(SqlParam::Bool(val != 0));
                arg_cursor += 1;
            }
            'n' => {
                sql_params.push(SqlParam::Null);
                arg_cursor += 1;
            }
            _ => {}
        }
    }
    sql_params
}

/// Resolves an AMX address to the cell value it points at (varargs are by reference).
unsafe fn deref_vararg_cell(amx_ptr: *mut Amx, addr: Cell, get_addr: amx::AmxGetAddrFn) -> Cell {
    let mut phys: *mut Cell = std::ptr::null_mut();
    if get_addr(amx_ptr, addr, &mut phys) == amx::AMX_ERR_NONE && !phys.is_null() {
        *phys
    } else {
        addr
    }
}

fn format_timestamptz(v: chrono::DateTime<chrono::Utc>) -> String {
    v.format("%Y-%m-%dT%H:%M:%S%.f%:z").to_string()
}

fn format_timestamp(v: chrono::NaiveDateTime) -> String {
    v.format("%Y-%m-%d %H:%M:%S%.f").to_string()
}

fn format_date(v: chrono::NaiveDate) -> String {
    v.format("%Y-%m-%d").to_string()
}

fn format_time(v: chrono::NaiveTime) -> String {
    v.format("%H:%M:%S%.f").to_string()
}

/// Temporal columns arrive as Postgres binary, not text, so String decoding rejects them.
fn column_value(row: &tokio_postgres::Row, idx: usize) -> Option<String> {
    if let Ok(s) = row.try_get::<_, String>(idx) {
        Some(s)
    } else if let Ok(v) = row.try_get::<_, i32>(idx) {
        Some(v.to_string())
    } else if let Ok(v) = row.try_get::<_, i64>(idx) {
        Some(v.to_string())
    } else if let Ok(v) = row.try_get::<_, f64>(idx) {
        Some(v.to_string())
    } else if let Ok(v) = row.try_get::<_, bool>(idx) {
        Some(if v { "1".into() } else { "0".into() })
    } else if let Ok(v) = row.try_get::<_, chrono::DateTime<chrono::Utc>>(idx) {
        Some(format_timestamptz(v))
    } else if let Ok(v) = row.try_get::<_, chrono::NaiveDateTime>(idx) {
        Some(format_timestamp(v))
    } else if let Ok(v) = row.try_get::<_, chrono::NaiveDate>(idx) {
        Some(format_date(v))
    } else if let Ok(v) = row.try_get::<_, chrono::NaiveTime>(idx) {
        Some(format_time(v))
    } else {
        None
    }
}

async fn execute_query_internal<T: tokio_postgres::ToStatement + Sync + ?Sized>(
    client: &tokio_postgres::Client,
    query: &T,
    sql_params: &[SqlParam],
) -> QueryResult {
    let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = sql_params
        .iter()
        .map(|p| p as &(dyn tokio_postgres::types::ToSql + Sync))
        .collect();

    let timeout = config::query_timeout();
    let run = async {
        match client.query(query, &params_refs[..]).await {
            Ok(rows) => {
                let mut cols = Vec::new();
                if let Some(first) = rows.first() {
                    for col in first.columns() {
                        cols.push(col.name().to_string());
                    }
                }
                let mut data_rows = Vec::new();
                for row in rows.iter() {
                    let mut r = Vec::new();
                    for (i, _) in row.columns().iter().enumerate() {
                        r.push(column_value(row, i));
                    }
                    data_rows.push(r);
                }
                // shortcut: rows_affected mirrors data-row count (0 for
                // INSERT without RETURNING) — track CommandComplete when
                // tokio_postgres exposes affected rows from query().
                let len = data_rows.len() as u64;
                QueryResult::new(cols, data_rows, len)
            }
            Err(e) => QueryResult::error(e.to_string()),
        }
    };

    match tokio::time::timeout(timeout, run).await {
        Ok(res) => res,
        Err(_) => QueryResult::error(format!("Query timed out after {}s", timeout.as_secs())),
    }
}

fn get_client_arc(conn_id: i32) -> Option<Arc<AsyncMutex<tokio_postgres::Client>>> {
    let conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
    match conns.get(&conn_id) {
        Some(c) if c.status == ConnectionStatus::Connected => c.client.clone(),
        _ => None,
    }
}

/// Request rejected while the client is unavailable (e.g. `Connecting` during
/// a backoff loop). Instead of returning 0 silently, the pending callback is
/// fired with success=0 so a gamemode is never left waiting through an outage.
fn reject_unavailable(conn_id: i32, api: &str, callback: String) {
    {
        let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = conns.get_mut(&conn_id) {
            c.last_error = Some("connection unavailable, reconnecting".into());
        }
    }
    logprintf(&format!(
        "[PGStream] {} skipped on conn {} — connection unavailable, reconnecting",
        api, conn_id
    ));
    if !callback.is_empty() {
        runtime::send_completion(CompletionEvent::CommandFinished {
            conn_id,
            success: false,
            callback,
        });
    }
}

fn escape_identifier(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        s.to_string()
    } else {
        format!("\"{}\"", s.replace('"', "\"\""))
    }
}

// ---------------------------------------------------------------------------
// Native Callbacks Table
// ---------------------------------------------------------------------------

static PG_NATIVES: [amx::NativeInfo; 58] = [
    amx::NativeInfo {
        name: b"PG_Version\0".as_ptr() as *const c_char,
        func: Some(pg_version),
    },
    amx::NativeInfo {
        name: b"PG_Connect\0".as_ptr() as *const c_char,
        func: Some(pg_connect),
    },
    amx::NativeInfo {
        name: b"PG_ConnectUrl\0".as_ptr() as *const c_char,
        func: Some(pg_connect_url),
    },
    amx::NativeInfo {
        name: b"PG_Close\0".as_ptr() as *const c_char,
        func: Some(pg_close),
    },
    amx::NativeInfo {
        name: b"PG_IsConnected\0".as_ptr() as *const c_char,
        func: Some(pg_is_connected),
    },
    amx::NativeInfo {
        name: b"PG_AsyncQuery\0".as_ptr() as *const c_char,
        func: Some(pg_async_query),
    },
    amx::NativeInfo {
        name: b"PG_QueryFormat\0".as_ptr() as *const c_char,
        func: Some(pg_query_format),
    },
    amx::NativeInfo {
        name: b"PG_NumRows\0".as_ptr() as *const c_char,
        func: Some(pg_num_rows),
    },
    amx::NativeInfo {
        name: b"PG_NumFields\0".as_ptr() as *const c_char,
        func: Some(pg_num_fields),
    },
    amx::NativeInfo {
        name: b"PG_GetAffectedRows\0".as_ptr() as *const c_char,
        func: Some(pg_get_affected_rows),
    },
    amx::NativeInfo {
        name: b"PG_GetString\0".as_ptr() as *const c_char,
        func: Some(pg_get_string),
    },
    amx::NativeInfo {
        name: b"PG_GetInt\0".as_ptr() as *const c_char,
        func: Some(pg_get_int),
    },
    amx::NativeInfo {
        name: b"PG_GetFloat\0".as_ptr() as *const c_char,
        func: Some(pg_get_float),
    },
    amx::NativeInfo {
        name: b"PG_IsNull\0".as_ptr() as *const c_char,
        func: Some(pg_is_null),
    },
    amx::NativeInfo {
        name: b"PG_FieldName\0".as_ptr() as *const c_char,
        func: Some(pg_field_name),
    },
    amx::NativeInfo {
        name: b"PG_GetStringByName\0".as_ptr() as *const c_char,
        func: Some(pg_get_string_by_name),
    },
    amx::NativeInfo {
        name: b"PG_GetIntByName\0".as_ptr() as *const c_char,
        func: Some(pg_get_int_by_name),
    },
    amx::NativeInfo {
        name: b"PG_GetFloatByName\0".as_ptr() as *const c_char,
        func: Some(pg_get_float_by_name),
    },
    amx::NativeInfo {
        name: b"PG_IsNullByName\0".as_ptr() as *const c_char,
        func: Some(pg_is_null_by_name),
    },
    amx::NativeInfo {
        name: b"PG_FreeResult\0".as_ptr() as *const c_char,
        func: Some(pg_free_result),
    },
    amx::NativeInfo {
        name: b"PG_GetError\0".as_ptr() as *const c_char,
        func: Some(pg_get_error),
    },
    amx::NativeInfo {
        name: b"PG_EscapeString\0".as_ptr() as *const c_char,
        func: Some(pg_escape_string),
    },
    // Transactions
    amx::NativeInfo {
        name: b"PG_Begin\0".as_ptr() as *const c_char,
        func: Some(pg_begin),
    },
    amx::NativeInfo {
        name: b"PG_Commit\0".as_ptr() as *const c_char,
        func: Some(pg_commit),
    },
    amx::NativeInfo {
        name: b"PG_Rollback\0".as_ptr() as *const c_char,
        func: Some(pg_rollback),
    },
    // Listen / Notify
    amx::NativeInfo {
        name: b"PG_Listen\0".as_ptr() as *const c_char,
        func: Some(pg_listen),
    },
    amx::NativeInfo {
        name: b"PG_Notify\0".as_ptr() as *const c_char,
        func: Some(pg_notify),
    },
    // Prepared Statements
    amx::NativeInfo {
        name: b"PG_Prepare\0".as_ptr() as *const c_char,
        func: Some(pg_prepare),
    },
    amx::NativeInfo {
        name: b"PG_ExecutePrepared\0".as_ptr() as *const c_char,
        func: Some(pg_execute_prepared),
    },
    // MySQL-compat layer (drop-in migration from pBlueG R41-4 gamemodes)
    amx::NativeInfo {
        name: b"PG_Format\0".as_ptr() as *const c_char,
        func: Some(pg_format),
    },
    amx::NativeInfo {
        name: b"PG_TQuery\0".as_ptr() as *const c_char,
        func: Some(pg_tquery),
    },
    amx::NativeInfo {
        name: b"PG_SyncQuery\0".as_ptr() as *const c_char,
        func: Some(pg_sync_query),
    },
    amx::NativeInfo {
        name: b"PG_ActiveResult\0".as_ptr() as *const c_char,
        func: Some(pg_active_result),
    },
    // ---- pBlueG R41-4 API aliases (drop-in gamemode migration) ----
    amx::NativeInfo {
        name: b"mysql_init_options\0".as_ptr() as *const c_char,
        func: Some(mysql_init_options),
    },
    amx::NativeInfo {
        name: b"mysql_set_option\0".as_ptr() as *const c_char,
        func: Some(mysql_set_option),
    },
    amx::NativeInfo {
        name: b"mysql_connect\0".as_ptr() as *const c_char,
        func: Some(mysql_connect),
    },
    amx::NativeInfo {
        name: b"mysql_errno\0".as_ptr() as *const c_char,
        func: Some(mysql_errno),
    },
    amx::NativeInfo {
        name: b"mysql_close\0".as_ptr() as *const c_char,
        func: Some(mysql_close),
    },
    amx::NativeInfo {
        name: b"mysql_escape_string\0".as_ptr() as *const c_char,
        func: Some(mysql_escape_string),
    },
    amx::NativeInfo {
        name: b"mysql_format\0".as_ptr() as *const c_char,
        func: Some(pg_format),
    },
    amx::NativeInfo {
        name: b"mysql_tquery\0".as_ptr() as *const c_char,
        func: Some(pg_tquery),
    },
    amx::NativeInfo {
        name: b"mysql_pquery\0".as_ptr() as *const c_char,
        func: Some(pg_tquery),
    },
    amx::NativeInfo {
        name: b"mysql_query\0".as_ptr() as *const c_char,
        func: Some(mysql_query),
    },
    amx::NativeInfo {
        name: b"cache_num_rows\0".as_ptr() as *const c_char,
        func: Some(cache_num_rows),
    },
    amx::NativeInfo {
        name: b"cache_get_row_count\0".as_ptr() as *const c_char,
        func: Some(cache_num_rows),
    },
    amx::NativeInfo {
        name: b"cache_get_value_name\0".as_ptr() as *const c_char,
        func: Some(cache_get_value_name),
    },
    amx::NativeInfo {
        name: b"cache_get_value\0".as_ptr() as *const c_char,
        func: Some(cache_get_value_name),
    },
    amx::NativeInfo {
        name: b"cache_get_value_name_int\0".as_ptr() as *const c_char,
        func: Some(cache_get_value_name_int),
    },
    amx::NativeInfo {
        name: b"cache_get_value_int\0".as_ptr() as *const c_char,
        func: Some(cache_get_value_name_int),
    },
    amx::NativeInfo {
        name: b"cache_get_value_name_float\0".as_ptr() as *const c_char,
        func: Some(cache_get_value_name_float),
    },
    amx::NativeInfo {
        name: b"cache_get_value_float\0".as_ptr() as *const c_char,
        func: Some(cache_get_value_name_float),
    },
    amx::NativeInfo {
        name: b"cache_get_value_index\0".as_ptr() as *const c_char,
        func: Some(cache_get_value_index),
    },
    amx::NativeInfo {
        name: b"cache_get_value_index_int\0".as_ptr() as *const c_char,
        func: Some(cache_get_value_index_int),
    },
    amx::NativeInfo {
        name: b"cache_insert_id\0".as_ptr() as *const c_char,
        func: Some(cache_insert_id),
    },
    amx::NativeInfo {
        name: b"cache_save\0".as_ptr() as *const c_char,
        func: Some(cache_save),
    },
    amx::NativeInfo {
        name: b"cache_delete\0".as_ptr() as *const c_char,
        func: Some(cache_delete),
    },
    amx::NativeInfo {
        name: b"cache_affected_rows\0".as_ptr() as *const c_char,
        func: Some(cache_affected_rows),
    },
    amx::NativeInfo {
        name: ptr::null(),
        func: None,
    },
];

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

unsafe extern "C" fn pg_version(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let res = write_string_dest(amx_ptr, params, 1, 2, VERSION_TEXT);
    if res != 1 {
        res
    } else {
        VERSION_CODE
    }
}

/// Registers a connection handle, enforcing the configured max active connections.
/// On rejection a `Failed` handle is stored so `PG_GetError` still reports the reason.
pub fn try_register_connection(conn_id: i32, max_size: usize) -> Result<(), String> {
    let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
    let active = conns
        .values()
        .filter(|c| {
            matches!(
                c.status,
                ConnectionStatus::Connecting | ConnectionStatus::Connected
            )
        })
        .count();
    if active >= max_size {
        let msg = format!("Max connections reached ({})", max_size);
        let mut c = PgConnection::new(conn_id);
        c.status = ConnectionStatus::Failed;
        c.last_error = Some(msg.clone());
        conns.insert(conn_id, c);
        return Err(msg);
    }
    conns.insert(conn_id, PgConnection::new(conn_id));
    Ok(())
}

/// Marks a connection as failed (so `PG_GetError` works) and fires the callback with success=0.
fn fail_connect(conn_id: i32, callback: &str, msg: &str) {
    logprintf(&format!("[PGStream] Connect failed: {}", msg));
    {
        let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = conns.get_mut(&conn_id) {
            c.status = ConnectionStatus::Failed;
            c.last_error = Some(msg.to_string());
        }
    }
    runtime::send_completion(CompletionEvent::Connected {
        conn_id,
        success: false,
        callback: callback.to_string(),
    });
}

/// native PG_Connect(const host[], const user[], const password[], const database[], port = 5432, const callback[] = "");
unsafe extern "C" fn pg_connect(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let host = read_string_arg(amx_ptr, params, 1).unwrap_or_default();
    let user = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let pass = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let db = read_string_arg(amx_ptr, params, 4).unwrap_or_default();
    let port = amx::native_arg(params, 5).unwrap_or(5432) as u16;
    let callback = read_string_arg(amx_ptr, params, 6).unwrap_or_default();

    let sslmode = config::Config::global().database.sslmode;
    let config = format!(
        "host={} port={} user={} password={} dbname={} sslmode={}",
        host,
        port,
        user,
        pass,
        db,
        sslmode.trim().to_ascii_lowercase()
    );
    spawn_connect(config, callback)
}

/// native PG_ConnectUrl(const url[], const callback[] = "");
/// Supports: postgresql://user:pass@host:port/dbname?sslmode=require
unsafe extern "C" fn pg_connect_url(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let url = read_string_arg(amx_ptr, params, 1).unwrap_or_default();
    let callback = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    spawn_connect(url, callback)
}

fn spawn_connect(conn_str: String, callback: String) -> Cell {
    let conn_id = handles::next_connection_id();
    if let Err(msg) = try_register_connection(conn_id, config::max_connections()) {
        logprintf(&format!("[PGStream] {}", msg));
        runtime::send_completion(CompletionEvent::Connected {
            conn_id,
            success: false,
            callback,
        });
        return conn_id;
    }

    runtime::spawn(supervise(conn_id, conn_str, callback));

    conn_id
}

/// PostgreSQL NAMEDATALEN: the server truncates names longer than 63 bytes.
pub const MAX_NAME_BYTES: usize = 63;

/// True when a LISTEN/NOTIFY channel name would be truncated by the server.
pub fn channel_name_too_long(channel: &str) -> bool {
    channel.len() > MAX_NAME_BYTES
}

/// Display of an error plus its full cause chain (the `Display` of
/// `tokio_postgres::Error` alone is static, e.g. "error communicating with
/// the server").
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut s = e.to_string();
    let mut src = std::error::Error::source(e);
    while let Some(cause) = src {
        s.push_str(": ");
        s.push_str(&cause.to_string());
        src = cause.source();
    }
    s
}

/// True while the handle is still registered (a `PG_Close` removes it and the
/// supervisor must stop reconnecting).
pub fn handle_exists(conn_id: i32) -> bool {
    CONNECTIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&conn_id)
}

/// Drops a connection handle. Returns true when a handle was removed.
pub fn close_connection(conn_id: i32) -> bool {
    let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
    match conns.remove(&conn_id) {
        Some(mut c) => {
            c.status = ConnectionStatus::Disconnected;
            c.client = None;
            true
        }
        None => false,
    }
}

/// Supervisor for one connection handle.
///
/// Owns the whole lifecycle: connect, keep the session alive, and reconnect
/// after the socket dies (idle pooler close, server restart, backend killed).
///
/// Callback contract:
/// - `success=false` fires exactly once per outage (first connect failure or
///   an established connection dying) — never once per retry.
/// - `success=true` fires exactly once per successful (re)connect, so a
///   gamemode can re-prepare/re-LISTEN on its own if it wants to.
async fn supervise(conn_id: i32, conn_str: String, callback: String) {
    let fallback = config::default_sslmode_value();
    let resolved = config::resolve_ssl_mode(&conn_str, &fallback);
    let mut pg_cfg = match tokio_postgres::Config::from_str(&resolved.conn) {
        Ok(c) => c,
        Err(e) => {
            // Permanent: a broken connection string never becomes valid.
            fail_connect(
                conn_id,
                &callback,
                &format!("Invalid connection config: {}", e),
            );
            return;
        }
    };
    pg_cfg.connect_timeout(config::connect_timeout());

    if resolved.mode == config::TlsMode::NoValidate {
        logprintf(&format!(
            "[PGStream] WARN: TLS tanpa verifikasi sertifikat (sslmode={}). Untuk produksi pakai sslmode=verify-full.",
            resolved.sslmode
        ));
    }

    let tls = match resolved.mode {
        config::TlsMode::Verified => make_tls_connector_verified(),
        _ => make_tls_connector_novalidate(),
    };

    let reconnect_enabled = config::reconnect_enabled();
    let max_delay = config::reconnect_max_delay();
    let keepalive = config::keepalive_interval();
    let mut delay = std::time::Duration::from_secs(1);
    let mut attempt = 0u32;
    let mut outage_reported = false;

    loop {
        if !handle_exists(conn_id) {
            break; // PG_Close — handle gone, stop supervising
        }
        if !reconnect_enabled && attempt > 0 {
            break;
        }
        attempt += 1;

        match pg_cfg.connect(tls.clone()).await {
            Ok((client, connection)) => {
                delay = std::time::Duration::from_secs(1);
                if !handle_exists(conn_id) {
                    return; // PG_Close while connect() ran — drop the socket, no callback
                }
                let client_arc = Arc::new(AsyncMutex::new(client));
                let (death_tx, mut death_rx) = tokio::sync::mpsc::channel::<String>(1);
                let cancel = Arc::new(tokio::sync::Notify::new());
                let pump = tokio::spawn({
                    let cancel = cancel.clone();
                    async move {
                        use futures_util::future::poll_fn;

                        let mut connection = connection;
                        loop {
                            let msg = tokio::select! {
                                _ = cancel.notified() => return,
                                msg = poll_fn(|cx| connection.poll_message(cx)) => msg,
                            };

                            match msg {
                                Some(Ok(tokio_postgres::AsyncMessage::Notification(n))) => {
                                    runtime::send_completion(CompletionEvent::Notification {
                                        conn_id,
                                        channel: n.channel().to_string(),
                                        payload: n.payload().to_string(),
                                    });
                                }
                                Some(Ok(_)) => {} // notices, parameter status updates
                                Some(Err(e)) => {
                                    let _ = death_tx.send(error_chain(&e)).await;
                                    return;
                                }
                                None => {
                                    // EOF: the server (or an idle pooler) closed the socket.
                                    let _ = death_tx
                                        .send("connection closed by server".to_string())
                                        .await;
                                    return;
                                }
                            }
                        }
                    }
                });

                // Restore the dead session state before the client becomes
                // visible: while it runs, PG_IsConnected stays 0 (honest).
                let restore_failures = restore_session(conn_id, &client_arc).await;
                if restore_failures > 0 {
                    logprintf(&format!(
                        "[PGStream] Restore session on conn {}: {} statement(s)/channel(s) failed to restore",
                        conn_id, restore_failures
                    ));
                }

                if !handle_exists(conn_id) {
                    cancel.notify_one();
                    let _ = pump.await;
                    return; // PG_Close during restore
                }

                // F7: the socket may have died mid-restore — never install a
                // dead client; fall through to the outage path instead.
                let mut reason = poll_death(&mut death_rx);

                // Install atomically under one CONNECTIONS lock: the success
                // callback, status flip and client swap are visible together, so
                // PG_Close cannot observe and tear down a half-installed client
                // (T2), and a death racing the install is re-checked inside the
                // lock (T3). send_completion only touches QUEUE, never held
                // across CONNECTIONS anywhere, so this cannot deadlock.
                let mut send_ok = false;
                let mut handle_missing = false;
                {
                    let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
                    match conns.get_mut(&conn_id) {
                        Some(c) => {
                            if reason.is_none() {
                                // T3: second check inside the lock — if the pump
                                // died after the first try_recv, the install is
                                // cancelled instead of installing a dead client.
                                reason = poll_death(&mut death_rx);
                            }
                            if reason.is_none() {
                                c.status = ConnectionStatus::Connected;
                                c.client = Some(client_arc.clone());
                                c.last_error = None;
                                // T2: emitted with the lock held → atomic with
                                // the status flip, exactly one per (re)connect.
                                runtime::send_completion(CompletionEvent::Connected {
                                    conn_id,
                                    success: true,
                                    callback: callback.clone(),
                                });
                                send_ok = true;
                            } else {
                                c.status = ConnectionStatus::Connecting;
                                c.last_error = reason.clone();
                                c.client = None;
                                c.prepared_statements.clear();
                            }
                        }
                        None => handle_missing = true,
                    }
                }

                if handle_missing {
                    // F1: PG_Close removed the handle while we were restoring.
                    cancel.notify_one();
                    let _ = pump.await;
                    return;
                }

                if send_ok {
                    outage_reported = false;
                }

                // One ticker per connection: checks the handle every second and
                // probes the socket every `keepalive`.
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
                let mut last_probe = std::time::Instant::now();
                let mut probe_failures = 0u32;

                let reason = match reason {
                    Some(reason) => reason,
                    None => loop {
                        tokio::select! {
                            reason = death_rx.recv() => {
                                break reason.unwrap_or_else(|| "connection lost".to_string());
                            }
                            _ = ticker.tick() => {
                                if !handle_exists(conn_id) {
                                    cancel.notify_one();
                                    let _ = pump.await;
                                    return; // PG_Close — stop supervising
                                }
                                if !keepalive.is_zero() && last_probe.elapsed() >= keepalive {
                                    match keepalive_probe(&client_arc).await {
                                        Ok(true) => {
                                            // T6: reset the schedule only when
                                            // a probe really ran, so a skipped
                                            // probe (client busy) is retried
                                            // next tick instead of next keepalive.
                                            last_probe = std::time::Instant::now();
                                            probe_failures = 0;
                                        }
                                        Ok(false) => {} // busy with a query — try again next tick
                                        Err(e) => {
                                            last_probe = std::time::Instant::now();
                                            probe_failures += 1;
                                            if probe_failures >= 2 {
                                                cancel.notify_one();
                                                break e;
                                            }
                                            // One slow probe is not death —
                                            // log once and try again next interval.
                                            logprintf(&format!(
                                                "[PGStream] Keepalive probe failed on conn {} ({}): {}",
                                                conn_id, probe_failures, e
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    },
                };

                cancel.notify_one();
                let _ = pump.await;

                {
                    let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(c) = conns.get_mut(&conn_id) {
                        // Slot stays reserved (status Connecting) so the
                        // max_size cap stays honest while reconnecting.
                        c.status = ConnectionStatus::Connecting;
                        c.last_error = Some(reason.clone());
                        c.client = None;
                        c.prepared_statements.clear();
                    }
                }

                if !outage_reported {
                    runtime::send_completion(CompletionEvent::Connected {
                        conn_id,
                        success: false,
                        callback: callback.clone(),
                    });
                    outage_reported = true;
                }

                if !reconnect_enabled {
                    logprintf(&format!(
                        "[PGStream] Connection lost (conn {}): {} — reconnect disabled",
                        conn_id, reason
                    ));
                    {
                        let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(c) = conns.get_mut(&conn_id) {
                            c.status = ConnectionStatus::Failed;
                        }
                    }
                    break;
                }

                logprintf(&format!(
                    "[PGStream] Connection lost (conn {}): {} — reconnecting in {}s",
                    conn_id,
                    reason,
                    delay.as_secs()
                ));
                tokio::time::sleep(delay).await;
                delay = config::next_backoff(delay, max_delay);
            }
            Err(e) => {
                let chain = error_chain(&e);
                {
                    let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(c) = conns.get_mut(&conn_id) {
                        c.status = ConnectionStatus::Connecting;
                        c.last_error = Some(chain.clone());
                    }
                }
                logprintf(&format!(
                    "[PGStream] Connect failed (conn {}): {} — retrying in {}s",
                    conn_id,
                    chain,
                    delay.as_secs()
                ));
                if !outage_reported {
                    runtime::send_completion(CompletionEvent::Connected {
                        conn_id,
                        success: false,
                        callback: callback.clone(),
                    });
                    outage_reported = true;
                }
                if !reconnect_enabled {
                    {
                        let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(c) = conns.get_mut(&conn_id) {
                            c.status = ConnectionStatus::Failed;
                        }
                    }
                    break;
                }
                tokio::time::sleep(delay).await;
                delay = config::next_backoff(delay, max_delay);
            }
        }
    }
}

/// Non-blocking death check for the connection pump: `None` = still alive,
/// `Some(reason)` = dead (a dropped pump sender counts as death).
fn poll_death(death_rx: &mut tokio::sync::mpsc::Receiver<String>) -> Option<String> {
    match death_rx.try_recv() {
        Ok(reason) => Some(reason),
        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
            Some("connection lost".to_string())
        }
        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
    }
}

/// Re-prepares stored statements and re-issues LISTEN after a reconnect:
/// both live on the server/client pair, so they die with the old connection.
///
/// Returns the number of entries that could not be restored (failed prepare +
/// failed LISTEN).
async fn restore_session(conn_id: i32, client: &Arc<AsyncMutex<tokio_postgres::Client>>) -> usize {
    let (sqls, channels) = {
        let conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
        match conns.get(&conn_id) {
            Some(c) => (c.prepared_sqls.clone(), c.listen_channels.clone()),
            None => return 0,
        }
    };

    let lock = client.lock().await;
    let mut statements = std::collections::HashMap::new();
    let mut failed: Vec<String> = Vec::new();
    let mut failures = 0usize;
    for (name, sql) in &sqls {
        // T1: bounded — a hung server must not stall the supervisor forever.
        match tokio::time::timeout(config::query_timeout(), lock.prepare(sql)).await {
            Ok(Ok(stmt)) => {
                statements.insert(name.clone(), stmt);
            }
            Ok(Err(e)) => {
                failures += 1;
                failed.push(name.clone());
                logprintf(&format!(
                    "[PGStream] Re-prepare '{}' failed on conn {}: {}",
                    name, conn_id, e
                ));
            }
            Err(_) => {
                failures += 1;
                failed.push(name.clone());
                logprintf(&format!(
                    "[PGStream] Re-prepare '{}' timed out on conn {}",
                    name, conn_id
                ));
            }
        }
    }
    for channel in &channels {
        let sql = format!("LISTEN {}", escape_identifier(channel));
        match tokio::time::timeout(config::query_timeout(), lock.batch_execute(&sql)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                failures += 1;
                logprintf(&format!(
                    "[PGStream] Re-LISTEN '{}' failed on conn {}: {}",
                    channel, conn_id, e
                ));
            }
            Err(_) => {
                failures += 1;
                logprintf(&format!(
                    "[PGStream] Re-LISTEN '{}' timed out on conn {}",
                    channel, conn_id
                ));
            }
        }
    }
    drop(lock);

    let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = conns.get_mut(&conn_id) {
        // Merge per entry: statements that failed to re-prepare are dropped
        // (they would be dead), the rest are replaced by the fresh ones.
        for name in &failed {
            c.prepared_statements.remove(name);
        }
        for (name, stmt) in statements {
            c.prepared_statements.insert(name, stmt);
        }
    }
    failures
}

/// `SELECT 1` probe that detects half-open sockets. Returns `Ok(false)`
/// (probe skipped) when another query holds the client lock, so callers can
/// keep the probe schedule honest.
async fn keepalive_probe(client: &Arc<AsyncMutex<tokio_postgres::Client>>) -> Result<bool, String> {
    let Ok(lock) = client.try_lock() else {
        return Ok(false); // busy with a query — try again next tick
    };
    match tokio::time::timeout(config::query_timeout(), lock.query_one("SELECT 1", &[])).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(e)) => Err(error_chain(&e)),
        Err(_) => Err("keepalive timeout".to_string()),
    }
}

/// native PG_Close(connection);
unsafe extern "C" fn pg_close(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    if close_connection(conn_id) {
        1
    } else {
        0
    }
}

/// native bool:PG_IsConnected(connection);
unsafe extern "C" fn pg_is_connected(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
    match conns.get(&conn_id) {
        Some(c) if c.status == ConnectionStatus::Connected => 1,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Async Query
// ---------------------------------------------------------------------------

/// native PG_AsyncQuery(connection, const query[], const callback[] = "", const format[] = "", ...);
unsafe extern "C" fn pg_async_query(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let query_str = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let callback = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let format = read_string_arg(amx_ptr, params, 4).unwrap_or_default();

    let sql_params = if format.is_empty() {
        Vec::new()
    } else {
        parse_variadic_params(amx_ptr, params, &format, 5)
    };

    let Some(client) = get_client_arc(conn_id) else {
        reject_unavailable(conn_id, "Query", callback);
        return 0;
    };

    let result_id = handles::next_result_id();

    runtime::spawn(async move {
        let lock = client.lock().await;
        let res = execute_query_internal(&lock, &query_str, &sql_params).await;
        {
            let mut results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
            results.insert(result_id, res);
        }
        runtime::send_completion(CompletionEvent::QueryFinished {
            conn_id,
            result_id,
            callback,
            extra: 0,
        });
    });

    result_id
}

/// Format conversion failed: set last_error on the handle, log, and fire the
/// callback with success=0 (same contract as `reject_unavailable`). Nothing
/// was sent to the database, so no query ever runs on a bad format.
fn reject_bad_format(conn_id: i32, msg: &str, callback: &str) {
    {
        let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = conns.get_mut(&conn_id) {
            c.last_error = Some(msg.to_string());
        }
    }
    logprintf(&format!(
        "[PGStream] QueryFormat error on conn {}: {}",
        conn_id, msg
    ));
    if !callback.is_empty() {
        runtime::send_completion(CompletionEvent::CommandFinished {
            conn_id,
            success: false,
            callback: callback.to_string(),
        });
    }
}

/// native PG_QueryFormat(connection, const query[], const callback[] = "", {Float, _}:...);
///
/// Query printf-Pawn style: `%d %i %f %s %c %x %X %%` become `$N` placeholders
/// with typed parameter binding. There is no format[] argument — the kinds are
/// determined by the specifiers themselves.
unsafe extern "C" fn pg_query_format(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let query_str = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let callback = read_string_arg(amx_ptr, params, 3).unwrap_or_default();

    // Scan first: the kinds come from the specifiers themselves.
    let (_, kinds) = match format::scan_specifiers(&query_str) {
        Ok(scan) => scan,
        Err(msg) => {
            reject_bad_format(conn_id, &msg, &callback);
            return 0;
        }
    };

    // Read one Pawn vararg per specifier, in specifier order. Varargs are
    // pushed as addresses (deref needed) except strings, same as
    // parse_variadic_params — shortcut: pawncc 3.2.3664 ABI.
    let get_addr = table_fn::<amx::AmxGetAddrFn>(amx::slot::GET_ADDR);
    let Some(get_addr) = get_addr else {
        reject_bad_format(conn_id, "AMX address table unavailable", &callback);
        return 0;
    };
    let mut raw_args: Vec<SqlParam> = Vec::with_capacity(kinds.len());
    for (idx, kind) in kinds.iter().enumerate() {
        let arg_idx = 4 + idx as Cell;
        let value = match kind {
            FormatArgKind::Str => {
                SqlParam::String(read_string_arg(amx_ptr, params, arg_idx).unwrap_or_default())
            }
            _ => {
                let addr = amx::native_arg(params, arg_idx).unwrap_or(0);
                let cell = deref_vararg_cell(amx_ptr, addr, get_addr);
                match kind {
                    FormatArgKind::Float => SqlParam::Float(f32::from_bits(cell as u32) as f64),
                    // Int, Char and Hex all read a raw int cell here; the
                    // conversion to String happens inside convert_pawn_format.
                    _ => SqlParam::Int(cell),
                }
            }
        };
        raw_args.push(value);
    }

    let Some(client) = get_client_arc(conn_id) else {
        reject_unavailable(conn_id, "QueryFormat", callback);
        return 0;
    };

    let (new_sql, sql_params) = match format::convert_pawn_format(&query_str, &raw_args) {
        Ok(converted) => converted,
        Err(msg) => {
            reject_bad_format(conn_id, &msg, &callback);
            return 0;
        }
    };

    let result_id = handles::next_result_id();

    runtime::spawn(async move {
        let lock = client.lock().await;
        let res = execute_query_internal(&lock, &new_sql, &sql_params).await;
        {
            let mut results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
            results.insert(result_id, res);
        }
        runtime::send_completion(CompletionEvent::QueryFinished {
            conn_id,
            result_id,
            callback,
            extra: 0,
        });
    });

    result_id
}

// ---------------------------------------------------------------------------
// MySQL-compat natives (pBlueG R41-4 drop-in migration)
// ---------------------------------------------------------------------------

/// Escape a string for interpolation into a SQL literal: with
/// standard_conforming_strings only the quote itself needs doubling.
fn sql_escape_literal(s: &str) -> String {
    s.replace('\'', "''")
}

/// native PG_Format(connection, dest[], size = sizeof(dest), const fmt[], {Float,_}:...);
///
/// pBlueG `mysql_format` clone: interpolates `%d %i %s %f %e %x %X %c` (plus
/// width/precision flags, e.g. `%.2f`) directly into the SQL text. `%e` is
/// escaped for a SQL literal. The connection argument is accepted for
/// signature compatibility but unused.
unsafe extern "C" fn pg_format(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let fmt = match read_string_arg(amx_ptr, params, 4) {
        Some(f) => f,
        None => return 0,
    };

    let get_addr = match table_fn::<amx::AmxGetAddrFn>(amx::slot::GET_ADDR) {
        Some(f) => f,
        None => return 0,
    };

    let mut out = String::with_capacity(fmt.len() + 32);
    let mut arg_cursor: Cell = 5;
    let mut chars = fmt.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            out.push('%');
            continue;
        }
        // Collect optional flags/width/precision (e.g. "-08.2").
        let mut spec = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() || matches!(c, '.' | '-' | '+' | ' ' | '#' | '*') {
                spec.push(c);
                chars.next();
            } else {
                break;
            }
        }
        let conv = match chars.next() {
            Some(c) => c,
            None => break,
        };
        let precision: Option<usize> = spec.split_once('.').and_then(|(_, frac)| frac.parse().ok());

        let read_cell = |cursor: &mut Cell| -> Cell {
            let addr = amx::native_arg(params, *cursor).unwrap_or(0);
            *cursor += 1;
            deref_vararg_cell(amx_ptr, addr, get_addr)
        };

        match conv {
            'd' | 'i' => {
                let v = read_cell(&mut arg_cursor);
                out.push_str(&v.to_string());
            }
            'f' | 'g' => {
                let bits = read_cell(&mut arg_cursor);
                let v = f32::from_bits(bits as u32) as f64;
                match precision {
                    Some(p) => out.push_str(&format!("{:.*}", p, v)),
                    None => out.push_str(&format!("{:.6}", v)),
                }
            }
            's' => {
                let s = read_string_arg(amx_ptr, params, arg_cursor).unwrap_or_default();
                arg_cursor += 1;
                out.push_str(&s);
            }
            'e' | 'q' => {
                let s = read_string_arg(amx_ptr, params, arg_cursor).unwrap_or_default();
                arg_cursor += 1;
                out.push_str(&sql_escape_literal(&s));
            }
            'x' => {
                let v = read_cell(&mut arg_cursor);
                out.push_str(&format!("{:x}", v));
            }
            'X' => {
                let v = read_cell(&mut arg_cursor);
                out.push_str(&format!("{:X}", v));
            }
            'c' => {
                let v = read_cell(&mut arg_cursor);
                if let Some(c) = char::from_u32(v as u32) {
                    out.push(c);
                }
            }
            _ => {
                // Unknown specifier: emit as-is, do not consume an argument.
                out.push('%');
                out.push_str(&spec);
                out.push(conv);
            }
        }
    }

    write_string_dest(amx_ptr, params, 2, 3, &out)
}

/// Reads mysql_tquery-style extra args (format `d i f s b`) into ExtraArg
/// values for callback dispatch.
unsafe fn parse_variadic_extras(
    amx_ptr: *mut Amx,
    params: *mut Cell,
    format: &str,
    start_arg: Cell,
) -> Vec<runtime::ExtraArg> {
    use runtime::ExtraArg;

    let mut extras: Vec<ExtraArg> = Vec::new();
    let get_addr = match table_fn::<amx::AmxGetAddrFn>(amx::slot::GET_ADDR) {
        Some(f) => f,
        None => return extras,
    };
    let mut arg_cursor = start_arg;
    for ch in format.chars() {
        match ch {
            'd' | 'i' | 'f' | 'b' => {
                let addr = amx::native_arg(params, arg_cursor).unwrap_or(0);
                extras.push(ExtraArg::Cell(deref_vararg_cell(amx_ptr, addr, get_addr)));
                arg_cursor += 1;
            }
            's' => {
                extras.push(ExtraArg::Str(
                    read_string_arg(amx_ptr, params, arg_cursor).unwrap_or_default(),
                ));
                arg_cursor += 1;
            }
            _ => {}
        }
    }
    extras
}

/// native PG_TQuery(connection, const query[], const callback[] = "", const format[] = "", {Float,_}:...);
///
/// pBlueG `mysql_tquery` clone: runs fully-interpolated SQL async, then calls
/// `callback` with exactly the extra args described by `format`. During the
/// dispatch `PG_ActiveResult()` exposes the result; it is freed automatically
/// after the callback returns. SQL errors fire `OnQueryError`.
unsafe extern "C" fn pg_tquery(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let query_str = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let callback = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let format = read_string_arg(amx_ptr, params, 4).unwrap_or_default();

    let extras = if format.is_empty() {
        Vec::new()
    } else {
        parse_variadic_extras(amx_ptr, params, &format, 5)
    };

    dispatch_or_park(conn_id, query_str, callback, extras)
}

/// native PG_SyncQuery(connection, const query[]);
///
/// pBlueG `mysql_query` clone: blocking query returning a result handle. The
/// result persists (is the active result) until PG_FreeResult — matching the
/// Cache save/delete lifecycle. Blocks the main thread up to the configured
/// query timeout.
unsafe extern "C" fn pg_sync_query(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    use std::sync::mpsc::channel;

    let Some(conn_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let query_str = read_string_arg(amx_ptr, params, 2).unwrap_or_default();

    let Some(client) = get_client_arc(conn_id) else {
        logprintf(&format!(
            "[PGStream] SyncQuery skipped on conn {conn_id} — connection unavailable"
        ));
        ACTIVE_RESULT.store(0, Ordering::Relaxed);
        return 0;
    };

    let result_id = handles::next_result_id();
    let (tx, rx) = channel();
    let query_for_error = query_str.clone();

    runtime::spawn(async move {
        let lock = client.lock().await;
        let res = execute_query_internal(&lock, &query_str, &[]).await;
        drop(lock);
        let _ = tx.send(res);
    });

    let timeout = config::query_timeout();
    let res = match rx.recv_timeout(timeout + std::time::Duration::from_secs(1)) {
        Ok(res) => res,
        Err(_) => QueryResult::error(format!("Query timed out after {}s", timeout.as_secs())),
    };

    let had_error = res.error.is_some();
    {
        let mut results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
        results.insert(result_id, res);
    }
    if had_error {
        let err = {
            let results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
            results
                .get(&result_id)
                .and_then(|r| r.error.clone())
                .unwrap_or_else(|| "unknown query error".into())
        };
        callbacks::dispatch_callback_mixed(
            "OnQueryError",
            &[
                runtime::ExtraArg::Cell(0),
                runtime::ExtraArg::Str(err),
                runtime::ExtraArg::Str(String::new()),
                runtime::ExtraArg::Str(query_for_error),
                runtime::ExtraArg::Cell(conn_id),
            ],
        );
    }

    ACTIVE_RESULT.store(result_id, Ordering::Relaxed);
    result_id
}

/// native PG_ActiveResult();
///
/// Returns the result id currently exposed as the "active cache" — set during
/// a PG_TQuery callback dispatch or after PG_SyncQuery. 0 when none.
unsafe extern "C" fn pg_active_result(_amx_ptr: *mut Amx, _params: *mut Cell) -> Cell {
    ACTIVE_RESULT.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// pBlueG R41-4 API aliases
// ---------------------------------------------------------------------------

/// A tquery-style query parked while its connection is `Connecting`; flushed
/// (or failed) when the connection settles.
struct PendingQuery {
    query: String,
    callback: String,
    extras: Vec<runtime::ExtraArg>,
}

static PENDING: Lazy<Lock<HashMap<i32, Vec<PendingQuery>>>> =
    Lazy::new(|| Lock::new(HashMap::new()));

type Lock<T> = std::sync::Mutex<T>;

/// Runs `run_query` if the connection is ready; otherwise parks it in the
/// pending queue so callbacks are never dispatched with a wrong signature
/// during an outage. Returns the reserved result id either way.
fn dispatch_or_park(
    conn_id: i32,
    query: String,
    callback: String,
    extras: Vec<runtime::ExtraArg>,
) -> i32 {
    let result_id = handles::next_result_id();
    let client = get_client_arc(conn_id);
    let pending_now = client.is_none() && connection_is_connecting(conn_id);

    if let Some(client) = client {
        let query_for_task = query.clone();
        let callback_for_task = callback.clone();
        let extras_for_task = extras.clone();
        runtime::spawn(async move {
            let lock = client.lock().await;
            let res = execute_query_internal(&lock, &query_for_task, &[]).await;
            drop(lock);
            {
                let mut results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
                results.insert(result_id, res);
            }
            runtime::send_completion(CompletionEvent::QueryFinishedExtras {
                conn_id,
                result_id,
                callback: callback_for_task,
                query,
                extras: extras_for_task,
            });
        });
    } else if pending_now {
        let mut map = PENDING.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(conn_id).or_default().push(PendingQuery {
            query,
            callback,
            extras,
        });
    } else {
        // Genuinely dead (reconnect disabled / closed): fail via OnQueryError.
        logprintf(&format!(
            "[PGStream] TQuery dropped on conn {conn_id} — connection unavailable"
        ));
        runtime::send_completion(CompletionEvent::QueryFinishedExtras {
            conn_id,
            result_id,
            callback,
            query,
            extras,
        });
    }
    result_id
}

fn connection_is_connecting(conn_id: i32) -> bool {
    let conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
    conns
        .get(&conn_id)
        .map(|c| c.status == ConnectionStatus::Connecting)
        .unwrap_or(false)
}

/// Flush the pending queue for a connection after it (re)connects, or fail
/// every parked query when the connection is gone for good.
pub fn flush_pending(conn_id: i32) {
    let pending = {
        let mut map = PENDING.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(&conn_id).unwrap_or_default()
    };
    if pending.is_empty() {
        return;
    }
    logprintf(&format!(
        "[PGStream] Flushing {} queued quer{} on conn {}",
        pending.len(),
        if pending.len() == 1 { "y" } else { "ies" },
        conn_id
    ));
    let ready = get_client_arc(conn_id).is_some();
    for p in pending {
        if ready {
            dispatch_or_park(conn_id, p.query, p.callback, p.extras);
        } else {
            let result_id = handles::next_result_id();
            {
                let mut results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
                results.insert(
                    result_id,
                    QueryResult::error("connection unavailable".into()),
                );
            }
            runtime::send_completion(CompletionEvent::QueryFinishedExtras {
                conn_id,
                result_id,
                callback: p.callback,
                query: p.query,
                extras: p.extras,
            });
        }
    }
}

unsafe extern "C" fn mysql_init_options(_amx_ptr: *mut Amx, _params: *mut Cell) -> Cell {
    1 // dummy option handle; options are no-ops under PGStream
}

unsafe extern "C" fn mysql_set_option(_amx_ptr: *mut Amx, _params: *mut Cell) -> Cell {
    1
}

/// native MySQL:mysql_connect(const host[], const user[], const password[],
///                             const database[], MySQLOpt:option_id, port = 5432)
unsafe extern "C" fn mysql_connect(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let host = read_string_arg(amx_ptr, params, 1).unwrap_or_default();
    let user = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let pass = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let db = read_string_arg(amx_ptr, params, 4).unwrap_or_default();
    let port = amx::native_arg(params, 6).unwrap_or(5432).max(0) as u16;

    let sslmode = config::Config::global().database.sslmode;
    let cfg = format!(
        "host={} port={} user={} password={} dbname={} sslmode={}",
        host,
        port,
        user,
        pass,
        db,
        sslmode.trim().to_ascii_lowercase()
    );
    spawn_connect(cfg, String::new())
}

/// native mysql_errno(MySQL:handle) — 0 when connected. Approximation: PG
/// connects async, so errno is also nonzero while still connecting.
unsafe extern "C" fn mysql_errno(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else {
        return 1;
    };
    match get_client_arc(conn_id) {
        Some(_) => 0,
        None => 1,
    }
}

unsafe extern "C" fn mysql_close(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    // Reuse pg_close, then drop any parked queries.
    let ret = pg_close(std::ptr::null_mut(), params);
    if let Some(conn_id) = amx::native_arg(params, 1) {
        PENDING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&conn_id);
    }
    ret
}

/// native mysql_escape_string(MySQL:handle, const source[], destination[])
unsafe extern "C" fn mysql_escape_string(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let src = match read_string_arg(amx_ptr, params, 2) {
        Some(s) => s,
        None => return 0,
    };
    let escaped = sql_escape_literal(&src);
    // No explicit destination size in the R41 signature: size the write from
    // the destination array itself (arg 3) — write_string_dest needs a size
    // param index; pass the escaped length so amx_SetString truncates safely.
    write_string_dest(amx_ptr, params, 3, 3, &escaped)
}

unsafe extern "C" fn mysql_query(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    pg_sync_query(amx_ptr, params)
}

/// Writes `value` through a by-reference Pawn argument (e.g. `&dest`).
unsafe fn write_cell_ref(amx_ptr: *mut Amx, params: *mut Cell, arg_idx: Cell, value: Cell) -> Cell {
    let get_addr: amx::AmxGetAddrFn = match table_fn(amx::slot::GET_ADDR) {
        Some(f) => f,
        None => return amx::AMX_ERR_NATIVE,
    };
    let Some(addr) = amx::native_arg(params, arg_idx) else {
        return amx::AMX_ERR_PARAMS;
    };
    let mut phys: *mut Cell = ptr::null_mut();
    if get_addr(amx_ptr, addr, &mut phys) != amx::AMX_ERR_NONE || phys.is_null() {
        return amx::AMX_ERR_NATIVE;
    }
    unsafe { *phys = value };
    1
}

fn parse_cell_i64(s: Option<&str>) -> Cell {
    s.and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(0)
        .clamp(i32::MIN as i64, i32::MAX as i64) as Cell
}

fn parse_cell_f32bits(s: Option<&str>) -> Cell {
    let v: f32 = s.and_then(|v| v.trim().parse().ok()).unwrap_or(0.0);
    v.to_bits() as Cell
}

unsafe extern "C" fn cache_num_rows(_amx_ptr: *mut Amx, _params: *mut Cell) -> Cell {
    let active = ACTIVE_RESULT.load(Ordering::Relaxed);
    let results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    results
        .get(&active)
        .map(|r| r.rows.len() as Cell)
        .unwrap_or(0)
}

/// cache_get_value_name(row, const field_name[], destination[], max_len)
unsafe extern "C" fn cache_get_value_name(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let row = amx::native_arg(params, 1).unwrap_or(0).max(0) as usize;
    let field = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let active = ACTIVE_RESULT.load(Ordering::Relaxed);
    let value = {
        let results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
        results.get(&active).and_then(|r| {
            r.get_col_index(&field)
                .and_then(|col| r.get_value(row, col))
                .map(|s| s.to_string())
        })
    };
    match value {
        Some(v) => write_string_dest(amx_ptr, params, 3, 4, &v),
        None => 0,
    }
}

unsafe extern "C" fn cache_get_value_name_int(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let row = amx::native_arg(params, 1).unwrap_or(0).max(0) as usize;
    let field = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let active = ACTIVE_RESULT.load(Ordering::Relaxed);
    let value = {
        let results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
        results.get(&active).and_then(|r| {
            r.get_col_index(&field)
                .and_then(|col| r.get_value(row, col))
                .map(|s| s.to_string())
        })
    };
    write_cell_ref(amx_ptr, params, 3, parse_cell_i64(value.as_deref()))
}

unsafe extern "C" fn cache_get_value_name_float(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let row = amx::native_arg(params, 1).unwrap_or(0).max(0) as usize;
    let field = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let active = ACTIVE_RESULT.load(Ordering::Relaxed);
    let value = {
        let results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
        results.get(&active).and_then(|r| {
            r.get_col_index(&field)
                .and_then(|col| r.get_value(row, col))
                .map(|s| s.to_string())
        })
    };
    write_cell_ref(amx_ptr, params, 3, parse_cell_f32bits(value.as_deref()))
}

/// cache_get_value_index(row, field_idx, destination[], max_len)
unsafe extern "C" fn cache_get_value_index(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let row = amx::native_arg(params, 1).unwrap_or(0).max(0) as usize;
    let col = amx::native_arg(params, 2).unwrap_or(0).max(0) as usize;
    let active = ACTIVE_RESULT.load(Ordering::Relaxed);
    let value = {
        let results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
        results
            .get(&active)
            .and_then(|r| r.get_value(row, col))
            .map(|s| s.to_string())
    };
    match value {
        Some(v) => write_string_dest(amx_ptr, params, 3, 4, &v),
        None => 0,
    }
}

unsafe extern "C" fn cache_get_value_index_int(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let row = amx::native_arg(params, 1).unwrap_or(0).max(0) as usize;
    let col = amx::native_arg(params, 2).unwrap_or(0).max(0) as usize;
    let active = ACTIVE_RESULT.load(Ordering::Relaxed);
    let value = {
        let results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
        results
            .get(&active)
            .and_then(|r| r.get_value(row, col))
            .map(|s| s.to_string())
    };
    write_cell_ref(amx_ptr, params, 3, parse_cell_i64(value.as_deref()))
}

/// cache_insert_id() — PostgreSQL has no connection-wide last-insert id, so
/// this reads the `id` column (or the first column) of row 0. INSERT queries
/// must be written with `RETURNING id` for this to work.
unsafe extern "C" fn cache_insert_id(_amx_ptr: *mut Amx, _params: *mut Cell) -> Cell {
    let active = ACTIVE_RESULT.load(Ordering::Relaxed);
    let results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(r) = results.get(&active) else {
        return 0;
    };
    if r.rows.is_empty() {
        return 0;
    }
    let col = r.get_col_index("id").unwrap_or(0);
    parse_cell_i64(r.get_value(0, col))
}

unsafe extern "C" fn cache_save(_amx_ptr: *mut Amx, _params: *mut Cell) -> Cell {
    ACTIVE_RESULT.load(Ordering::Relaxed)
}

unsafe extern "C" fn cache_delete(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    handles::free_result(result_id) as Cell
}

unsafe extern "C" fn cache_affected_rows(_amx_ptr: *mut Amx, _params: *mut Cell) -> Cell {
    let active = ACTIVE_RESULT.load(Ordering::Relaxed);
    let results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    results
        .get(&active)
        .map(|r| r.rows_affected.clamp(0, i32::MAX as u64) as Cell)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

/// native PG_Begin(connection, const callback[] = "");
unsafe extern "C" fn pg_begin(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    tx_command(amx_ptr, params, "BEGIN")
}

/// native PG_Commit(connection, const callback[] = "");
unsafe extern "C" fn pg_commit(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    tx_command(amx_ptr, params, "COMMIT")
}

/// native PG_Rollback(connection, const callback[] = "");
unsafe extern "C" fn pg_rollback(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    tx_command(amx_ptr, params, "ROLLBACK")
}

unsafe fn tx_command(amx_ptr: *mut Amx, params: *mut Cell, sql: &str) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let callback = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let Some(client) = get_client_arc(conn_id) else {
        reject_unavailable(conn_id, sql, callback);
        return 0;
    };

    let sql_owned = sql.to_string();
    runtime::spawn(async move {
        let lock = client.lock().await;
        let success = lock.batch_execute(&sql_owned).await.is_ok();
        if !success {
            logprintf(&format!(
                "[PGStream] {} failed on conn {}",
                sql_owned, conn_id
            ));
        }
        runtime::send_completion(CompletionEvent::CommandFinished {
            conn_id,
            success,
            callback,
        });
    });
    1
}

// ---------------------------------------------------------------------------
// Listen / Notify
// ---------------------------------------------------------------------------

/// native PG_Listen(connection, const channel[], const callback[] = "");
unsafe extern "C" fn pg_listen(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let channel = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let callback = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    if channel_name_too_long(&channel) {
        logprintf(&format!(
            "[PGStream] LISTEN channel '{}' rejected: name exceeds {} bytes (server NAMEDATALEN)",
            channel, MAX_NAME_BYTES
        ));
        if !callback.is_empty() {
            runtime::send_completion(CompletionEvent::CommandFinished {
                conn_id,
                success: false,
                callback,
            });
        }
        return 0;
    }
    let Some(client) = get_client_arc(conn_id) else {
        reject_unavailable(conn_id, "LISTEN", callback);
        return 0;
    };

    runtime::spawn(async move {
        let lock = client.lock().await;
        let sql = format!("LISTEN {}", escape_identifier(&channel));
        let success = lock.batch_execute(&sql).await.is_ok();
        if !success {
            logprintf(&format!(
                "[PGStream] LISTEN '{}' failed on conn {}",
                channel, conn_id
            ));
        } else {
            {
                let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(c) = conns.get_mut(&conn_id) {
                    c.record_listen(&channel);
                }
            }
            logprintf(&format!(
                "[PGStream] Listening on channel '{}' (conn {})",
                channel, conn_id
            ));
        }
        if !callback.is_empty() {
            runtime::send_completion(CompletionEvent::CommandFinished {
                conn_id,
                success,
                callback,
            });
        }
    });
    1
}

/// native PG_Notify(connection, const channel[], const payload[] = "");
unsafe extern "C" fn pg_notify(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let channel = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let payload = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    if channel_name_too_long(&channel) {
        logprintf(&format!(
            "[PGStream] NOTIFY channel '{}' rejected: name exceeds {} bytes (server NAMEDATALEN)",
            channel, MAX_NAME_BYTES
        ));
        return 0;
    }
    let Some(client) = get_client_arc(conn_id) else {
        reject_unavailable(conn_id, "NOTIFY", String::new());
        return 0;
    };

    runtime::spawn(async move {
        let lock = client.lock().await;
        let sql = format!(
            "NOTIFY {}, '{}'",
            escape_identifier(&channel),
            payload.replace('\'', "''")
        );
        if let Err(e) = lock.batch_execute(&sql).await {
            logprintf(&format!(
                "[PGStream] NOTIFY '{}' failed on conn {}: {}",
                channel, conn_id, e
            ));
        }
    });
    1
}

// ---------------------------------------------------------------------------
// Prepared Statements
// ---------------------------------------------------------------------------

/// native PG_Prepare(connection, const stmt_name[], const query[], const callback[] = "");
unsafe extern "C" fn pg_prepare(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let stmt_name = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let query = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let callback = read_string_arg(amx_ptr, params, 4).unwrap_or_default();
    let Some(client) = get_client_arc(conn_id) else {
        reject_unavailable(conn_id, &format!("PREPARE '{}'", stmt_name), callback);
        return 0;
    };

    runtime::spawn(async move {
        let lock = client.lock().await;
        match lock.prepare(&query).await {
            Ok(stmt) => {
                {
                    let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(c) = conns.get_mut(&conn_id) {
                        // T4: a `Statement` is bound to the client that made
                        // it — if a reconnect swapped the client meanwhile,
                        // the statement is stale and must not be stored.
                        let same_client =
                            c.client.as_ref().is_some_and(|a| Arc::ptr_eq(a, &client));
                        if same_client {
                            c.prepared_statements.insert(stmt_name.clone(), stmt);
                        }
                        // The SQL always survives: the supervisor re-prepares
                        // it on the new client after a reconnect.
                        c.record_prepared(&stmt_name, &query);
                    }
                }
                logprintf(&format!(
                    "[PGStream] Prepared '{}' on conn {}",
                    stmt_name, conn_id
                ));
                if !callback.is_empty() {
                    runtime::send_completion(CompletionEvent::CommandFinished {
                        conn_id,
                        success: true,
                        callback,
                    });
                }
            }
            Err(e) => {
                logprintf(&format!("[PGStream] Prepare '{}' failed: {}", stmt_name, e));
                {
                    let mut conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(c) = conns.get_mut(&conn_id) {
                        c.last_error = Some(e.to_string());
                    }
                }
                if !callback.is_empty() {
                    runtime::send_completion(CompletionEvent::CommandFinished {
                        conn_id,
                        success: false,
                        callback,
                    });
                }
            }
        }
    });
    1
}

/// native PG_ExecutePrepared(connection, const stmt_name[], const callback[] = "", const format[] = "", ...);
unsafe extern "C" fn pg_execute_prepared(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let stmt_name = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let callback = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let format = read_string_arg(amx_ptr, params, 4).unwrap_or_default();

    let sql_params = if format.is_empty() {
        Vec::new()
    } else {
        parse_variadic_params(amx_ptr, params, &format, 5)
    };

    let (client, stmt) = {
        let conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
        match conns.get(&conn_id) {
            Some(c) if c.status == ConnectionStatus::Connected => {
                match c.prepared_statements.get(&stmt_name) {
                    Some(s) => match c.client.clone() {
                        Some(cl) => (cl, s.clone()),
                        None => return 0,
                    },
                    None => {
                        logprintf(&format!(
                            "[PGStream] Error: no prepared statement '{}' on conn {}",
                            stmt_name, conn_id
                        ));
                        return 0;
                    }
                }
            }
            _ => {
                reject_unavailable(conn_id, "ExecutePrepared", callback);
                return 0;
            }
        }
    };

    let result_id = handles::next_result_id();

    runtime::spawn(async move {
        let lock = client.lock().await;
        let res = execute_query_internal(&lock, &stmt, &sql_params).await;

        {
            let mut results = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
            results.insert(result_id, res);
        }

        runtime::send_completion(CompletionEvent::QueryFinished {
            conn_id,
            result_id,
            callback,
            extra: 0,
        });
    });

    result_id
}

// ---------------------------------------------------------------------------
// Result API
// ---------------------------------------------------------------------------

unsafe extern "C" fn pg_num_rows(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let res_map = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    res_map
        .get(&result_id)
        .map(|r| r.rows.len() as Cell)
        .unwrap_or(0)
}

unsafe extern "C" fn pg_num_fields(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let res_map = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    res_map
        .get(&result_id)
        .map(|r| r.columns.len() as Cell)
        .unwrap_or(0)
}

unsafe extern "C" fn pg_get_affected_rows(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let res_map = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    res_map
        .get(&result_id)
        .map(|r| r.rows_affected as Cell)
        .unwrap_or(0)
}

unsafe extern "C" fn pg_get_string(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col = amx::native_arg(params, 3).unwrap_or(0) as usize;
    let res_map = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    let text = res_map
        .get(&result_id)
        .and_then(|r| r.get_value(row, col))
        .unwrap_or("");
    write_string_dest(amx_ptr, params, 4, 5, text)
}

unsafe extern "C" fn pg_get_int(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col = amx::native_arg(params, 3).unwrap_or(0) as usize;
    let res_map = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    res_map
        .get(&result_id)
        .and_then(|r| r.get_value(row, col))
        .and_then(|s| s.parse::<Cell>().ok())
        .unwrap_or(0)
}

unsafe extern "C" fn pg_get_float(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col = amx::native_arg(params, 3).unwrap_or(0) as usize;
    let res_map = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    let f = res_map
        .get(&result_id)
        .and_then(|r| r.get_value(row, col))
        .and_then(|s| s.parse::<f32>().ok())
        .unwrap_or(0.0);
    f.to_bits() as Cell
}

unsafe extern "C" fn pg_is_null(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 1;
    };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col = amx::native_arg(params, 3).unwrap_or(0) as usize;
    let res_map = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    if res_map
        .get(&result_id)
        .map(|r| r.is_null(row, col))
        .unwrap_or(true)
    {
        1
    } else {
        0
    }
}

unsafe extern "C" fn pg_field_name(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let col = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let res_map = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    let name = res_map
        .get(&result_id)
        .and_then(|r| r.columns.get(col))
        .map(|s| s.as_str())
        .unwrap_or("");
    write_string_dest(amx_ptr, params, 3, 4, name)
}

unsafe extern "C" fn pg_get_string_by_name(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col_name = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let res_map = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    let col_idx = res_map
        .get(&result_id)
        .and_then(|r| r.get_col_index(&col_name));
    let text = match col_idx {
        Some(idx) => res_map
            .get(&result_id)
            .and_then(|r| r.get_value(row, idx))
            .unwrap_or(""),
        None => "",
    };
    write_string_dest(amx_ptr, params, 4, 5, text)
}

unsafe extern "C" fn pg_get_int_by_name(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col_name = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let res_map = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    let col_idx = res_map
        .get(&result_id)
        .and_then(|r| r.get_col_index(&col_name));
    match col_idx {
        Some(idx) => res_map
            .get(&result_id)
            .and_then(|r| r.get_value(row, idx))
            .and_then(|s| s.parse::<Cell>().ok())
            .unwrap_or(0),
        None => 0,
    }
}

unsafe extern "C" fn pg_get_float_by_name(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col_name = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let res_map = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    let col_idx = res_map
        .get(&result_id)
        .and_then(|r| r.get_col_index(&col_name));
    let f = match col_idx {
        Some(idx) => res_map
            .get(&result_id)
            .and_then(|r| r.get_value(row, idx))
            .and_then(|s| s.parse::<f32>().ok())
            .unwrap_or(0.0),
        None => 0.0,
    };
    f.to_bits() as Cell
}

unsafe extern "C" fn pg_is_null_by_name(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 1;
    };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col_name = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let res_map = RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    let col_idx = res_map
        .get(&result_id)
        .and_then(|r| r.get_col_index(&col_name));
    match col_idx {
        Some(idx) => {
            if res_map
                .get(&result_id)
                .map(|r| r.is_null(row, idx))
                .unwrap_or(true)
            {
                1
            } else {
                0
            }
        }
        None => 1,
    }
}

unsafe extern "C" fn pg_free_result(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    if handles::free_result(result_id) {
        1
    } else {
        0
    }
}

unsafe extern "C" fn pg_get_error(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else {
        return 0;
    };
    let conns = CONNECTIONS.lock().unwrap_or_else(|e| e.into_inner());
    let err = conns
        .get(&conn_id)
        .and_then(|c| c.last_error.as_deref())
        .unwrap_or("");
    write_string_dest(amx_ptr, params, 2, 3, err)
}

unsafe extern "C" fn pg_escape_string(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let src = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let mut escaped = String::with_capacity(src.len() * 2);
    for ch in src.chars() {
        match ch {
            '\'' => escaped.push_str("''"),
            '\\' => escaped.push_str("\\\\"),
            '\0' => break,
            c => escaped.push(c),
        }
    }
    write_string_dest(amx_ptr, params, 3, 4, &escaped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_postgres::types::{FromSql, Type};

    #[test]
    fn error_chain_walks_the_full_cause_chain() {
        #[derive(Debug)]
        struct Fake(
            &'static str,
            Option<Box<dyn std::error::Error + Send + Sync>>,
        );
        impl std::fmt::Display for Fake {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.0)
            }
        }
        impl std::error::Error for Fake {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.1
                    .as_ref()
                    .map(|c| c.as_ref() as &(dyn std::error::Error + 'static))
            }
        }

        let leaf = Fake("connection closed", None);
        let root = Fake("db error", Some(Box::new(leaf)));
        assert_eq!(error_chain(&root), "db error: connection closed");
        assert_eq!(error_chain(&Fake("solo", None)), "solo");
    }

    #[test]
    fn temporal_columns_decode_to_non_empty_text() {
        // Postgres binary payloads: microseconds since 2000-01-01, days since 2000-01-01.
        let ts_raw = 1_026_490i64.to_be_bytes();
        let date_raw = 30i32.to_be_bytes();
        let time_raw = 3_661_500_000i64.to_be_bytes();

        // Row::try_get dispatches on Type::accepts: text rejects temporal types.
        assert!(!<String as FromSql>::accepts(&Type::TIMESTAMPTZ));
        assert!(<chrono::DateTime<chrono::Utc> as FromSql>::accepts(
            &Type::TIMESTAMPTZ
        ));
        assert!(<chrono::NaiveDateTime as FromSql>::accepts(
            &Type::TIMESTAMP
        ));
        assert!(<chrono::NaiveDate as FromSql>::accepts(&Type::DATE));
        assert!(<chrono::NaiveTime as FromSql>::accepts(&Type::TIME));

        let tz = <chrono::DateTime<chrono::Utc> as FromSql>::from_sql(&Type::TIMESTAMPTZ, &ts_raw)
            .unwrap();
        let ts = <chrono::NaiveDateTime as FromSql>::from_sql(&Type::TIMESTAMP, &ts_raw).unwrap();
        let date = <chrono::NaiveDate as FromSql>::from_sql(&Type::DATE, &date_raw).unwrap();
        let time = <chrono::NaiveTime as FromSql>::from_sql(&Type::TIME, &time_raw).unwrap();

        let tz_text = format_timestamptz(tz);
        let ts_text = format_timestamp(ts);
        let date_text = format_date(date);
        let time_text = format_time(time);

        assert!(!tz_text.is_empty());
        assert!(!ts_text.is_empty());
        assert!(!date_text.is_empty());
        assert!(!time_text.is_empty());
        assert_eq!(tz_text, "2000-01-01T00:00:01.026490+00:00");
        assert_eq!(ts_text, "2000-01-01 00:00:01.026490");
        assert_eq!(date_text, "2000-01-31");
        assert_eq!(time_text, "01:01:01.500");
    }

    /// Live check of the keepalive probe. Needs `PGSTREAM_TEST_URL`; skipped
    /// (but green) when the variable is absent so the suite runs without a DB.
    #[tokio::test]
    async fn keepalive_probe_succeeds_on_live_db() {
        let Ok(url) = std::env::var("PGSTREAM_TEST_URL") else {
            println!("SKIP: PGSTREAM_TEST_URL not set");
            return;
        };
        let resolved = config::resolve_ssl_mode(&url, "require");
        let mut cfg = tokio_postgres::Config::from_str(&resolved.conn).expect("valid config");
        cfg.connect_timeout(config::connect_timeout());
        let (client, connection) = cfg
            .connect(make_tls_connector_novalidate())
            .await
            .expect("live connect");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let client = Arc::new(AsyncMutex::new(client));
        assert!(
            keepalive_probe(&client).await.is_ok(),
            "keepalive probe must succeed on a healthy connection"
        );
    }
}
