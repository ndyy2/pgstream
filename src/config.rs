use once_cell::sync::Lazy;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

/// Effective TLS decision for a connection attempt.
pub struct ResolvedTls {
    /// Connection string safe for `tokio_postgres::Config::from_str`.
    pub conn: String,
    /// TLS behavior to apply.
    pub mode: TlsMode,
    /// Effective `sslmode` value (for logging).
    pub sslmode: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub pool: PoolConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Runtime configuration, loaded once from `pgstream.toml` in the server cwd.
pub static CONFIG: Lazy<Mutex<Config>> =
    Lazy::new(|| Mutex::new(Config::load_from_file("pgstream.toml")));

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    #[serde(default)]
    pub password: String,
    pub password_env: Option<String>,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_query_timeout")]
    pub query_timeout_seconds: u64,
    /// Default `require` is the conservative production choice: TLS is always
    /// negotiated (encrypted), only `verify-ca`/`verify-full` verify the cert.
    #[serde(default = "default_sslmode")]
    pub sslmode: String,
}

fn default_connect_timeout() -> u64 {
    5
}
fn default_query_timeout() -> u64 {
    15
}
fn default_sslmode() -> String {
    "require".into()
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 5432,
            database: "samp_db".into(),
            username: "postgres".into(),
            password: "".into(),
            password_env: None,
            connect_timeout_seconds: 5,
            query_timeout_seconds: 15,
            sslmode: default_sslmode(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PoolConfig {
    #[serde(default = "default_pool_size")]
    pub max_size: usize,
}

fn default_pool_size() -> usize {
    5
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self { max_size: 5 }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_log_level() -> String {
    "info".into()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
        }
    }
}

/// TLS behavior selected by the `sslmode` connection parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// `sslmode=disable` — no TLS at all.
    Disabled,
    /// `sslmode=require|prefer|empty` — TLS without certificate verification.
    NoValidate,
    /// `sslmode=verify-ca|verify-full` — TLS with webpki roots + hostname check.
    Verified,
}

/// Maps an `sslmode` value to its TLS behavior. `require`/`prefer`/empty and
/// unknown values map to `NoValidate` (libpq's `prefer`); unknown values are
/// rejected later by tokio-postgres, so they never reach a live socket.
pub fn tls_mode_for(sslmode: &str) -> TlsMode {
    match sslmode.trim().to_ascii_lowercase().as_str() {
        "disable" => TlsMode::Disabled,
        "verify-ca" | "verify-full" => TlsMode::Verified,
        _ => TlsMode::NoValidate,
    }
}

/// Helper to determine if a connection string is a URL.
fn is_url(conn: &str) -> bool {
    conn.starts_with("postgres://") || conn.starts_with("postgresql://")
}

/// Injects a default sslmode into a connection string if missing.
fn inject_sslmode(conn: &str, fallback: &str) -> String {
    let fb = fallback.trim();
    if is_url(conn) {
        let sep = if conn.contains('?') { '&' } else { '?' };
        format!("{conn}{sep}sslmode={fb}")
    } else if conn.trim().is_empty() {
        format!("sslmode={fb}")
    } else {
        format!("{} sslmode={fb}", conn.trim_end())
    }
}

/// Collects all `sslmode=` parameter occurrences in a connection string.
/// Each hit: (value_start, value_end, raw_value) in document order.
/// Multiple hits happen when the same parameter is duplicated — the caller
/// treats the LAST one as effective (matches tokio-postgres `Config::from_str`).
fn find_sslmodes(conn: &str) -> Vec<(usize, usize, String)> {
    let mut hits = Vec::new();
    if is_url(conn) {
        let q = conn.find('?').map(|p| p + 1).unwrap_or(0);
        let mut cursor = q;
        for part in conn[q..].split('&') {
            let start = cursor;
            cursor += part.len() + 1;
            if let Some(eq) = part.find('=') {
                if part[..eq].eq_ignore_ascii_case("sslmode") {
                    hits.push((
                        start + eq + 1,
                        start + part.len(),
                        part[eq + 1..].to_string(),
                    ));
                }
            }
        }
        return hits;
    }
    // Key-value form: walk whitespace-separated tokens.
    let mut rest = conn;
    let mut base = 0;
    loop {
        let ws = rest.len() - rest.trim_start().len();
        base += ws;
        rest = &rest[ws..];
        if rest.is_empty() {
            break;
        }
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let tok = &rest[..end];
        if let Some(eq) = tok.find('=') {
            if tok[..eq].eq_ignore_ascii_case("sslmode") {
                hits.push((base + eq + 1, base + end, tok[eq + 1..].to_string()));
            }
        }
        base += end;
        rest = &rest[end..];
    }
    hits
}

/// Resolves a raw connection string into effective TLS behavior.
///
/// tokio-postgres only understands `disable|prefer|require`, so
/// `verify-ca`/`verify-full` are rewritten to `require`; the verification
/// itself is carried by the TLS connector built from the returned mode.
/// Empty or absent `sslmode` is replaced with the fallback configured value.
/// Unknown `sslmode` values are left verbatim, causing tokio-postgres to fail.
///
/// Duplicate `sslmode` parameters: the LAST occurrence wins (same rule as
/// `tokio_postgres::Config::from_str`), and every occurrence is rewritten so
/// the plugin's TLS decision can never disagree with the wire behavior.
pub fn resolve_ssl_mode(conn: &str, fallback: &str) -> ResolvedTls {
    let hits = find_sslmodes(conn);
    // Effective sslmode: last explicit value wins, empty/absent -> fallback.
    let explicit = hits.last().map(|(_, _, v)| v.trim().to_string());
    let effective = match explicit {
        Some(v) if !v.is_empty() => v.to_ascii_lowercase(),
        _ => fallback.trim().to_ascii_lowercase(),
    };
    let mode = tls_mode_for(&effective);
    // Rewrite to tokio-postgres-understandable values.
    let replacement: String = match effective.as_str() {
        "verify-ca" | "verify-full" => "require".to_string(),
        _ => effective.clone(), // unknown values left unchanged (fail closed)
    };
    // Rebuild connection string: replace EVERY sslmode occurrence.
    let mut out = String::with_capacity(conn.len());
    if hits.is_empty() {
        out = inject_sslmode(conn, &replacement);
    } else {
        let mut prev = 0;
        for (start, end, _) in &hits {
            out.push_str(&conn[prev..*start]);
            out.push_str(&replacement);
            prev = *end;
        }
        out.push_str(&conn[prev..]);
    }
    ResolvedTls {
        conn: out,
        mode,
        sslmode: effective.to_string(),
    }
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Self {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(mut cfg) = toml::from_str::<Config>(&content) {
                if let Some(ref env_var) = cfg.database.password_env {
                    if let Ok(env_pass) = std::env::var(env_var) {
                        cfg.database.password = env_pass;
                    }
                }
                return cfg;
            }
        }
        Config::default()
    }

    pub fn default() -> Self {
        Self {
            database: DatabaseConfig::default(),
            pool: PoolConfig::default(),
            logging: LoggingConfig::default(),
        }
    }

    /// Snapshot of the runtime config loaded from `pgstream.toml`.
    pub fn global() -> Config {
        CONFIG.lock().unwrap().clone()
    }
}

/// Connect timeout from the runtime config (default 5s when not loaded).
pub fn connect_timeout() -> Duration {
    Duration::from_secs(CONFIG.lock().unwrap().database.connect_timeout_seconds)
}

/// Query timeout from the runtime config (default 15s when not loaded).
pub fn query_timeout() -> Duration {
    Duration::from_secs(CONFIG.lock().unwrap().database.query_timeout_seconds)
}

/// Max concurrent PG connections from the runtime config (default 5).
pub fn max_connections() -> usize {
    CONFIG.lock().unwrap().pool.max_size
}

/// Configured default `sslmode` for key-value connects.
pub fn default_sslmode_value() -> String {
    CONFIG.lock().unwrap().database.sslmode.clone()
}
