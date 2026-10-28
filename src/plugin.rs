//! Plugin lifecycle, native registration, and SA:MP/Pawn boundary for PGStream.

use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

use crate::abi::amx::{self, Amx, Cell};
use crate::abi::callbacks;
use crate::config::Config;
use crate::database::connection::{ConnectionStatus, PgConnection};
use crate::database::parameters::SqlParam;
use crate::database::result::QueryResult;
use crate::handles::{self, CONNECTIONS, RESULTS};
use crate::runtime::{self, CompletionEvent};

static AMX_TABLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static LOGPRINTF: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

pub(crate) unsafe fn table_fn<T: Copy>(idx: usize) -> Option<T> {
    let table = AMX_TABLE.load(Ordering::Relaxed);
    if table.is_null() {
        return None;
    }
    Some(ptr::read((table as *const *const c_void).add(idx) as *const T))
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

pub const VERSION_CODE: Cell = 200;
const VERSION_TEXT: &str = "PGStream 0.2.0";

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

/// TLS connector with full certificate validation (sslmode=verify-full).
fn make_tls_connector_verified() -> tokio_postgres_rustls::MakeRustlsConnect {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = rustls::ClientConfig::builder()
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

    let cfg = Config::load_from_file("pgstream.toml");
    logprintf(&format!(
        "[PGStream] v0.2.0 initialized (Pool size: {}, Host: {})",
        cfg.pool.max_size, cfg.database.host
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
            }
            CompletionEvent::QueryFinished {
                conn_id,
                result_id,
                callback,
                extra,
            } => {
                callbacks::dispatch_callback(&callback, &[conn_id, result_id, extra]);
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

async fn execute_query_internal(
    client: &tokio_postgres::Client,
    query: &str,
    sql_params: &[SqlParam],
) -> QueryResult {
    let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = sql_params
        .iter()
        .map(|p| p as &(dyn tokio_postgres::types::ToSql + Sync))
        .collect();

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
            let len = data_rows.len() as u64;
            QueryResult::new(cols, data_rows, len)
        }
        Err(e) => {
            if let Ok(affected) = client.execute(query, &params_refs[..]).await {
                QueryResult::empty_success(affected)
            } else {
                QueryResult::error(e.to_string())
            }
        }
    }
}

fn get_client_arc(conn_id: i32) -> Option<Arc<AsyncMutex<tokio_postgres::Client>>> {
    let conns = CONNECTIONS.lock().unwrap();
    match conns.get(&conn_id) {
        Some(c) if c.status == ConnectionStatus::Connected => c.client.clone(),
        _ => None,
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

static PG_NATIVES: [amx::NativeInfo; 29] = [
    amx::NativeInfo { name: b"PG_Version\0".as_ptr() as *const c_char, func: Some(pg_version) },
    amx::NativeInfo { name: b"PG_Connect\0".as_ptr() as *const c_char, func: Some(pg_connect) },
    amx::NativeInfo { name: b"PG_ConnectUrl\0".as_ptr() as *const c_char, func: Some(pg_connect_url) },
    amx::NativeInfo { name: b"PG_Close\0".as_ptr() as *const c_char, func: Some(pg_close) },
    amx::NativeInfo { name: b"PG_IsConnected\0".as_ptr() as *const c_char, func: Some(pg_is_connected) },
    amx::NativeInfo { name: b"PG_AsyncQuery\0".as_ptr() as *const c_char, func: Some(pg_async_query) },
    amx::NativeInfo { name: b"PG_NumRows\0".as_ptr() as *const c_char, func: Some(pg_num_rows) },
    amx::NativeInfo { name: b"PG_NumFields\0".as_ptr() as *const c_char, func: Some(pg_num_fields) },
    amx::NativeInfo { name: b"PG_GetAffectedRows\0".as_ptr() as *const c_char, func: Some(pg_get_affected_rows) },
    amx::NativeInfo { name: b"PG_GetString\0".as_ptr() as *const c_char, func: Some(pg_get_string) },
    amx::NativeInfo { name: b"PG_GetInt\0".as_ptr() as *const c_char, func: Some(pg_get_int) },
    amx::NativeInfo { name: b"PG_GetFloat\0".as_ptr() as *const c_char, func: Some(pg_get_float) },
    amx::NativeInfo { name: b"PG_IsNull\0".as_ptr() as *const c_char, func: Some(pg_is_null) },
    amx::NativeInfo { name: b"PG_FieldName\0".as_ptr() as *const c_char, func: Some(pg_field_name) },
    amx::NativeInfo { name: b"PG_GetStringByName\0".as_ptr() as *const c_char, func: Some(pg_get_string_by_name) },
    amx::NativeInfo { name: b"PG_GetIntByName\0".as_ptr() as *const c_char, func: Some(pg_get_int_by_name) },
    amx::NativeInfo { name: b"PG_GetFloatByName\0".as_ptr() as *const c_char, func: Some(pg_get_float_by_name) },
    amx::NativeInfo { name: b"PG_IsNullByName\0".as_ptr() as *const c_char, func: Some(pg_is_null_by_name) },
    amx::NativeInfo { name: b"PG_FreeResult\0".as_ptr() as *const c_char, func: Some(pg_free_result) },
    amx::NativeInfo { name: b"PG_GetError\0".as_ptr() as *const c_char, func: Some(pg_get_error) },
    amx::NativeInfo { name: b"PG_EscapeString\0".as_ptr() as *const c_char, func: Some(pg_escape_string) },
    // Transactions
    amx::NativeInfo { name: b"PG_Begin\0".as_ptr() as *const c_char, func: Some(pg_begin) },
    amx::NativeInfo { name: b"PG_Commit\0".as_ptr() as *const c_char, func: Some(pg_commit) },
    amx::NativeInfo { name: b"PG_Rollback\0".as_ptr() as *const c_char, func: Some(pg_rollback) },
    // Listen / Notify
    amx::NativeInfo { name: b"PG_Listen\0".as_ptr() as *const c_char, func: Some(pg_listen) },
    amx::NativeInfo { name: b"PG_Notify\0".as_ptr() as *const c_char, func: Some(pg_notify) },
    // Prepared Statements
    amx::NativeInfo { name: b"PG_Prepare\0".as_ptr() as *const c_char, func: Some(pg_prepare) },
    amx::NativeInfo { name: b"PG_ExecutePrepared\0".as_ptr() as *const c_char, func: Some(pg_execute_prepared) },
    amx::NativeInfo { name: ptr::null(), func: None },
];

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

unsafe extern "C" fn pg_version(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let res = write_string_dest(amx_ptr, params, 1, 2, VERSION_TEXT);
    if res != 1 { res } else { VERSION_CODE }
}

/// native PG_Connect(const host[], const user[], const password[], const database[], port = 5432, const callback[] = "");
unsafe extern "C" fn pg_connect(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let host = read_string_arg(amx_ptr, params, 1).unwrap_or_default();
    let user = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let pass = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let db = read_string_arg(amx_ptr, params, 4).unwrap_or_default();
    let port = amx::native_arg(params, 5).unwrap_or(5432) as u16;
    let callback = read_string_arg(amx_ptr, params, 6).unwrap_or_default();

    let config = format!(
        "host={} port={} user={} password={} dbname={}",
        host, port, user, pass, db
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

fn spawn_connect(config: String, callback: String) -> Cell {
    let conn_id = handles::next_connection_id();
    {
        let mut conns = CONNECTIONS.lock().unwrap();
        conns.insert(conn_id, PgConnection::new(conn_id));
    }

    runtime::spawn(async move {
        // Choose TLS mode: verify-full/verify-ca use validated, everything else uses novalidate
        let use_verified = config.contains("sslmode=verify-full")
            || config.contains("sslmode=verify-ca");
        let tls = if use_verified {
            make_tls_connector_verified()
        } else {
            make_tls_connector_novalidate()
        };
        match tokio_postgres::connect(&config, tls).await {
            Ok((client, connection)) => {
                // Spawn connection handler that processes notifications via Stream
                let cid = conn_id;
                tokio::spawn(async move {
                    use futures_util::future::poll_fn;
                    use std::task::Poll;

                    let mut conn = connection;
                    loop {
                        let msg = poll_fn(|cx| match conn.poll_message(cx) {
                            Poll::Ready(Some(r)) => Poll::Ready(Some(r)),
                            Poll::Ready(None) => Poll::Ready(None),
                            Poll::Pending => Poll::Pending,
                        })
                        .await;

                        match msg {
                            Some(Ok(tokio_postgres::AsyncMessage::Notification(n))) => {
                                runtime::send_completion(CompletionEvent::Notification {
                                    conn_id: cid,
                                    channel: n.channel().to_string(),
                                    payload: n.payload().to_string(),
                                });
                            }
                            Some(Ok(_)) => {} // notices, parameter status updates
                            Some(Err(e)) => {
                                logprintf(&format!("[PGStream] Connection error: {}", e));
                                let mut conns = CONNECTIONS.lock().unwrap();
                                if let Some(c) = conns.get_mut(&cid) {
                                    c.status = ConnectionStatus::Failed;
                                    c.last_error = Some(e.to_string());
                                }
                                break;
                            }
                            None => break, // connection closed
                        }
                    }
                });

                {
                    let mut conns = CONNECTIONS.lock().unwrap();
                    if let Some(c) = conns.get_mut(&conn_id) {
                        c.status = ConnectionStatus::Connected;
                        c.client = Some(Arc::new(AsyncMutex::new(client)));
                    }
                }

                runtime::send_completion(CompletionEvent::Connected {
                    conn_id,
                    success: true,
                    callback,
                });
            }
            Err(e) => {
                let err_msg = e.to_string();
                logprintf(&format!("[PGStream] Connect failed: {}", err_msg));
                {
                    let mut conns = CONNECTIONS.lock().unwrap();
                    if let Some(c) = conns.get_mut(&conn_id) {
                        c.status = ConnectionStatus::Failed;
                        c.last_error = Some(err_msg);
                    }
                }
                runtime::send_completion(CompletionEvent::Connected {
                    conn_id,
                    success: false,
                    callback,
                });
            }
        }
    });

    conn_id
}

/// native PG_Close(connection);
unsafe extern "C" fn pg_close(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else { return 0; };
    let mut conns = CONNECTIONS.lock().unwrap();
    if let Some(mut c) = conns.remove(&conn_id) {
        c.status = ConnectionStatus::Disconnected;
        c.client = None;
        1
    } else {
        0
    }
}

/// native bool:PG_IsConnected(connection);
unsafe extern "C" fn pg_is_connected(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else { return 0; };
    let conns = CONNECTIONS.lock().unwrap();
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
    let Some(conn_id) = amx::native_arg(params, 1) else { return 0; };
    let query_str = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let callback = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let format = read_string_arg(amx_ptr, params, 4).unwrap_or_default();

    let sql_params = if format.is_empty() {
        Vec::new()
    } else {
        parse_variadic_params(amx_ptr, params, &format, 5)
    };

    let Some(client) = get_client_arc(conn_id) else {
        logprintf(&format!(
            "[PGStream] Error: connection {} not connected for query",
            conn_id
        ));
        return 0;
    };

    let result_id = handles::next_result_id();

    runtime::spawn(async move {
        let lock = client.lock().await;
        let res = execute_query_internal(&lock, &query_str, &sql_params).await;
        {
            let mut results = RESULTS.lock().unwrap();
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
    let Some(conn_id) = amx::native_arg(params, 1) else { return 0; };
    let callback = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let Some(client) = get_client_arc(conn_id) else { return 0; };

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
    let Some(conn_id) = amx::native_arg(params, 1) else { return 0; };
    let channel = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let callback = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let Some(client) = get_client_arc(conn_id) else { return 0; };

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
    let Some(conn_id) = amx::native_arg(params, 1) else { return 0; };
    let channel = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let payload = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let Some(client) = get_client_arc(conn_id) else { return 0; };

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
    let Some(conn_id) = amx::native_arg(params, 1) else { return 0; };
    let stmt_name = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let query = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let callback = read_string_arg(amx_ptr, params, 4).unwrap_or_default();
    let Some(client) = get_client_arc(conn_id) else { return 0; };

    runtime::spawn(async move {
        let lock = client.lock().await;
        match lock.prepare(&query).await {
            Ok(stmt) => {
                {
                    let mut conns = CONNECTIONS.lock().unwrap();
                    if let Some(c) = conns.get_mut(&conn_id) {
                        c.prepared_statements.insert(stmt_name.clone(), stmt);
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
                logprintf(&format!(
                    "[PGStream] Prepare '{}' failed: {}",
                    stmt_name, e
                ));
                {
                    let mut conns = CONNECTIONS.lock().unwrap();
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
    let Some(conn_id) = amx::native_arg(params, 1) else { return 0; };
    let stmt_name = read_string_arg(amx_ptr, params, 2).unwrap_or_default();
    let callback = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let format = read_string_arg(amx_ptr, params, 4).unwrap_or_default();

    let sql_params = if format.is_empty() {
        Vec::new()
    } else {
        parse_variadic_params(amx_ptr, params, &format, 5)
    };

    let (client, stmt) = {
        let conns = CONNECTIONS.lock().unwrap();
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
            _ => return 0,
        }
    };

    let result_id = handles::next_result_id();

    runtime::spawn(async move {
        let lock = client.lock().await;

        let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = sql_params
            .iter()
            .map(|p| p as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();

        let res = match lock.query(&stmt, &params_refs[..]).await {
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
                let len = data_rows.len() as u64;
                QueryResult::new(cols, data_rows, len)
            }
            Err(e) => {
                if let Ok(affected) = lock.execute(&stmt, &params_refs[..]).await {
                    QueryResult::empty_success(affected)
                } else {
                    QueryResult::error(e.to_string())
                }
            }
        };

        {
            let mut results = RESULTS.lock().unwrap();
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
    let Some(result_id) = amx::native_arg(params, 1) else { return 0; };
    let res_map = RESULTS.lock().unwrap();
    res_map.get(&result_id).map(|r| r.rows.len() as Cell).unwrap_or(0)
}

unsafe extern "C" fn pg_num_fields(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else { return 0; };
    let res_map = RESULTS.lock().unwrap();
    res_map.get(&result_id).map(|r| r.columns.len() as Cell).unwrap_or(0)
}

unsafe extern "C" fn pg_get_affected_rows(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else { return 0; };
    let res_map = RESULTS.lock().unwrap();
    res_map.get(&result_id).map(|r| r.rows_affected as Cell).unwrap_or(0)
}

unsafe extern "C" fn pg_get_string(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else { return 0; };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col = amx::native_arg(params, 3).unwrap_or(0) as usize;
    let res_map = RESULTS.lock().unwrap();
    let text = res_map
        .get(&result_id)
        .and_then(|r| r.get_value(row, col))
        .unwrap_or("");
    write_string_dest(amx_ptr, params, 4, 5, text)
}

unsafe extern "C" fn pg_get_int(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else { return 0; };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col = amx::native_arg(params, 3).unwrap_or(0) as usize;
    let res_map = RESULTS.lock().unwrap();
    res_map
        .get(&result_id)
        .and_then(|r| r.get_value(row, col))
        .and_then(|s| s.parse::<Cell>().ok())
        .unwrap_or(0)
}

unsafe extern "C" fn pg_get_float(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else { return 0; };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col = amx::native_arg(params, 3).unwrap_or(0) as usize;
    let res_map = RESULTS.lock().unwrap();
    let f = res_map
        .get(&result_id)
        .and_then(|r| r.get_value(row, col))
        .and_then(|s| s.parse::<f32>().ok())
        .unwrap_or(0.0);
    f.to_bits() as Cell
}

unsafe extern "C" fn pg_is_null(_amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else { return 1; };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col = amx::native_arg(params, 3).unwrap_or(0) as usize;
    let res_map = RESULTS.lock().unwrap();
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
    let Some(result_id) = amx::native_arg(params, 1) else { return 0; };
    let col = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let res_map = RESULTS.lock().unwrap();
    let name = res_map
        .get(&result_id)
        .and_then(|r| r.columns.get(col))
        .map(|s| s.as_str())
        .unwrap_or("");
    write_string_dest(amx_ptr, params, 3, 4, name)
}

unsafe extern "C" fn pg_get_string_by_name(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(result_id) = amx::native_arg(params, 1) else { return 0; };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col_name = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let res_map = RESULTS.lock().unwrap();
    let col_idx = res_map.get(&result_id).and_then(|r| r.get_col_index(&col_name));
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
    let Some(result_id) = amx::native_arg(params, 1) else { return 0; };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col_name = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let res_map = RESULTS.lock().unwrap();
    let col_idx = res_map.get(&result_id).and_then(|r| r.get_col_index(&col_name));
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
    let Some(result_id) = amx::native_arg(params, 1) else { return 0; };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col_name = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let res_map = RESULTS.lock().unwrap();
    let col_idx = res_map.get(&result_id).and_then(|r| r.get_col_index(&col_name));
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
    let Some(result_id) = amx::native_arg(params, 1) else { return 1; };
    let row = amx::native_arg(params, 2).unwrap_or(0) as usize;
    let col_name = read_string_arg(amx_ptr, params, 3).unwrap_or_default();
    let res_map = RESULTS.lock().unwrap();
    let col_idx = res_map.get(&result_id).and_then(|r| r.get_col_index(&col_name));
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
    let Some(result_id) = amx::native_arg(params, 1) else { return 0; };
    if handles::free_result(result_id) { 1 } else { 0 }
}

unsafe extern "C" fn pg_get_error(amx_ptr: *mut Amx, params: *mut Cell) -> Cell {
    let Some(conn_id) = amx::native_arg(params, 1) else { return 0; };
    let conns = CONNECTIONS.lock().unwrap();
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
    fn temporal_columns_decode_to_non_empty_text() {
        // Postgres binary payloads: microseconds since 2000-01-01, days since 2000-01-01.
        let ts_raw = 1_026_490i64.to_be_bytes();
        let date_raw = 30i32.to_be_bytes();
        let time_raw = 3_661_500_000i64.to_be_bytes();

        // Row::try_get dispatches on Type::accepts: text rejects temporal types.
        assert!(!<String as FromSql>::accepts(&Type::TIMESTAMPTZ));
        assert!(<chrono::DateTime<chrono::Utc> as FromSql>::accepts(&Type::TIMESTAMPTZ));
        assert!(<chrono::NaiveDateTime as FromSql>::accepts(&Type::TIMESTAMP));
        assert!(<chrono::NaiveDate as FromSql>::accepts(&Type::DATE));
        assert!(<chrono::NaiveTime as FromSql>::accepts(&Type::TIME));

        let tz = <chrono::DateTime<chrono::Utc> as FromSql>::from_sql(&Type::TIMESTAMPTZ, &ts_raw)
            .unwrap();
        let ts =
            <chrono::NaiveDateTime as FromSql>::from_sql(&Type::TIMESTAMP, &ts_raw).unwrap();
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
}
