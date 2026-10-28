use std::fs;
use std::str::FromStr;

use pgstream::config::{resolve_ssl_mode, TlsMode};
use pgstream::database::connection::{ConnectionStatus, PgConnection};
use pgstream::handles::CONNECTIONS;
use pgstream::plugin::try_register_connection;
use tokio_postgres::config::SslMode;

#[test]
fn sslmode_resolution_key_value_forms() {
    let r = resolve_ssl_mode("host=db user=postgres sslmode=verify-full", "require");
    assert_eq!(r.mode, TlsMode::Verified);
    assert_eq!(r.sslmode, "verify-full");
    assert!(r.conn.contains("sslmode=require")); // rewritten for tokio-postgres
    assert!(!r.conn.contains("verify-full"));

    let r = resolve_ssl_mode("host=db user=postgres sslmode=verify-ca", "require");
    assert_eq!(r.mode, TlsMode::Verified);

    let r = resolve_ssl_mode("host=db sslmode=disable", "require");
    assert_eq!(r.mode, TlsMode::Disabled);
    assert!(r.conn.contains("sslmode=disable"));
    assert!(!r.conn.contains("require"));

    let r = resolve_ssl_mode("host=db sslmode=require", "require");
    assert_eq!(r.mode, TlsMode::NoValidate);
    assert!(r.conn.contains("sslmode=require") && !r.conn.contains("verify"));

    let r = resolve_ssl_mode("host=db sslmode=prefer", "require");
    assert_eq!(r.mode, TlsMode::NoValidate);
}

#[test]
fn sslmode_resolution_url_forms() {
    let r = resolve_ssl_mode("postgresql://u@h:5432/db?sslmode=verify-full", "require");
    assert_eq!(r.mode, TlsMode::Verified);
    assert!(r.conn.contains("sslmode=require"));

    // Existing params preserved, only sslmode rewritten.
    let r = resolve_ssl_mode(
        "postgresql://u@h:5432/db?application_name=x&sslmode=verify-full",
        "require",
    );
    assert!(r.conn.contains("application_name=x"));
    assert!(r.conn.contains("&sslmode=require"));

    let r = resolve_ssl_mode("postgresql://u@h/db", "disable");
    assert_eq!(r.mode, TlsMode::Disabled);
    assert!(r.conn.contains("sslmode=disable"));
}

#[test]
fn sslmode_resolution_absent_and_empty() {
    // Absent sslmode -> configured fallback injected and rewritten.
    let r = resolve_ssl_mode("host=db user=postgres", "verify-full");
    assert_eq!(r.mode, TlsMode::Verified);
    assert_eq!(r.sslmode, "verify-full");
    assert!(r.conn.contains("sslmode=require"));

    // Empty sslmode -> treated as absent -> fallback.
    let r = resolve_ssl_mode("host=db sslmode=", "require");
    assert_eq!(r.mode, TlsMode::NoValidate);
    assert_eq!(r.sslmode, "require");
    assert!(r.conn.contains("sslmode=require"));
}

#[test]
fn unknown_sslmode_is_fail_closed() {
    let r = resolve_ssl_mode("host=db sslmode=bogus", "require");
    assert_eq!(r.mode, TlsMode::NoValidate);
    assert_eq!(r.sslmode, "bogus");
    assert!(r.conn.contains("sslmode=bogus")); // left verbatim -> tokio-postgres rejects
}

#[test]
fn config_defaults_require_sslmode() {
    let cfg = pgstream::config::Config::default();
    assert_eq!(cfg.database.sslmode, "require");
    assert_eq!(cfg.database.connect_timeout_seconds, 5);
    assert_eq!(cfg.database.query_timeout_seconds, 15);
    assert_eq!(cfg.pool.max_size, 5);
}

#[test]
fn toml_without_sslmode_falls_back_to_require() {
    let path = std::path::PathBuf::from(format!(
        "/tmp/opencode/pgstream_sslmode_{}",
        std::process::id()
    ));
    let content = toml_without_sslmode();
    fs::write(&path, content).unwrap();

    let cfg = pgstream::config::Config::load_from_file(&path);
    assert_eq!(cfg.database.sslmode, "require");
    assert_eq!(cfg.database.port, 5432);

    let _ = fs::remove_file(&path);
}

#[test]
fn max_connections_rejects_beyond_limit() {
    let mut conns = CONNECTIONS.lock().unwrap();
    conns.clear();
    for id in 900_001..900_003 {
        let mut c = PgConnection::new(id);
        c.status = ConnectionStatus::Connected;
        conns.insert(id, c);
    }
    drop(conns);

    let id = 900_004;
    assert!(try_register_connection(id, 2).is_err());

    {
        let conns = CONNECTIONS.lock().unwrap();
        let c = conns.get(&id).expect("rejected handle stored");
        assert_eq!(c.status, ConnectionStatus::Failed);
        assert!(
            c.last_error.is_some(),
            "last_error must be populated on rejection"
        );
    }
    CONNECTIONS.lock().unwrap().clear();
}

/// Regression (F1): duplicate `sslmode` must not let the plugin's TLS decision
/// disagree with the wire behavior. tokio-postgres takes the LAST occurrence;
/// the plugin must do the same and rewrite every occurrence.
#[test]
fn duplicate_sslmode_last_wins_and_all_occurrences_rewritten() {
    // URL: verify-full first, disable last -> effective disable (plaintext).
    let r = resolve_ssl_mode(
        "postgresql://u@h/db?sslmode=verify-full&sslmode=disable",
        "require",
    );
    assert_eq!(r.mode, TlsMode::Disabled);
    assert_eq!(r.sslmode, "disable");
    assert!(!r.conn.contains("verify-full"));

    // Cross-check: what tokio-postgres will actually parse must match the mode.
    let parsed = tokio_postgres::Config::from_str(&r.conn).unwrap();
    assert_eq!(parsed.get_ssl_mode(), SslMode::Disable);

    // URL: disable first, verify-full last -> effective verified.
    let r = resolve_ssl_mode(
        "postgresql://u@h/db?sslmode=disable&sslmode=verify-full",
        "require",
    );
    assert_eq!(r.mode, TlsMode::Verified);
    assert_eq!(r.sslmode, "verify-full");
    assert!(!r.conn.contains("verify-full"));
    let parsed = tokio_postgres::Config::from_str(&r.conn).unwrap();
    assert_eq!(parsed.get_ssl_mode(), SslMode::Require);

    // Key-value form: same last-wins rule.
    let r = resolve_ssl_mode("host=db sslmode=verify-full sslmode=disable", "require");
    assert_eq!(r.mode, TlsMode::Disabled);
    assert_eq!(r.sslmode, "disable");
    assert!(!r.conn.contains("verify-full"));
    assert!(r.conn.ends_with("sslmode=disable"));
}

fn toml_without_sslmode() -> String {
    [
        "[database]",
        "host = \"db.example.com\"",
        "port = 5432",
        "database = \"samp\"",
        "username = \"postgres\"",
        "",
        "[pool]",
        "max_size = 5",
        "",
        "[logging]",
        "level = \"info\"",
    ]
    .join("\n")
}
