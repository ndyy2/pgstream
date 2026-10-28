use std::fs;
use std::time::Duration;

use pgstream::config::{next_backoff, Config};
use pgstream::database::connection::PgConnection;
use pgstream::handles::CONNECTIONS;
use pgstream::plugin::{
    channel_name_too_long, close_connection, handle_exists, try_register_connection,
};

#[test]
fn config_defaults_enable_reconnect() {
    let cfg = Config::default();
    assert!(cfg.database.reconnect_enabled);
    assert_eq!(cfg.database.reconnect_max_delay_seconds, 30);
    assert_eq!(cfg.database.keepalive_interval_seconds, 60);
}

#[test]
fn global_accessors_match_loaded_config() {
    let cfg = Config::global();
    assert_eq!(
        pgstream::config::reconnect_enabled(),
        cfg.database.reconnect_enabled
    );
    assert_eq!(
        pgstream::config::reconnect_max_delay(),
        Duration::from_secs(cfg.database.reconnect_max_delay_seconds)
    );
    assert_eq!(
        pgstream::config::keepalive_interval(),
        Duration::from_secs(cfg.database.keepalive_interval_seconds)
    );
}

/// Backward compatibility: a `pgstream.toml` written for v0.2.x has no
/// reconnect keys — defaults must apply instead of failing to parse.
#[test]
fn old_toml_without_reconnect_keys_uses_defaults() {
    let path = std::path::PathBuf::from(format!(
        "/tmp/opencode/pgstream_reconnect_old_{}",
        std::process::id()
    ));
    fs::write(&path, old_toml()).unwrap();

    let cfg = Config::load_from_file(&path);
    assert!(cfg.database.reconnect_enabled);
    assert_eq!(cfg.database.reconnect_max_delay_seconds, 30);
    assert_eq!(cfg.database.keepalive_interval_seconds, 60);

    let _ = fs::remove_file(&path);
}

#[test]
fn toml_with_reconnect_keys_is_used() {
    let path = std::path::PathBuf::from(format!(
        "/tmp/opencode/pgstream_reconnect_new_{}",
        std::process::id()
    ));
    fs::write(
        &path,
        [
            "[database]",
            "host = \"db.example.com\"",
            "port = 5432",
            "database = \"samp\"",
            "username = \"postgres\"",
            "reconnect_enabled = false",
            "reconnect_max_delay_seconds = 7",
            "keepalive_interval_seconds = 0",
            "",
        ]
        .join("\n"),
    )
    .unwrap();

    let cfg = Config::load_from_file(&path);
    assert!(!cfg.database.reconnect_enabled);
    assert_eq!(cfg.database.reconnect_max_delay_seconds, 7);
    assert_eq!(cfg.database.keepalive_interval_seconds, 0);

    let _ = fs::remove_file(&path);
}

#[test]
fn backoff_doubles_and_caps_at_max() {
    let max = Duration::from_secs(30);
    let mut d = Duration::from_secs(1);
    for expected in [2, 4, 8, 16, 30, 30] {
        d = next_backoff(d, max);
        assert_eq!(d, Duration::from_secs(expected));
    }
    assert_eq!(
        next_backoff(Duration::from_secs(0), max),
        Duration::from_secs(0)
    );
}

/// F2: `reconnect_max_delay_seconds = 0` must not collapse the backoff into a
/// busy retry loop.
#[test]
fn backoff_never_below_one_second() {
    let max = Duration::from_secs(0);
    assert_eq!(
        next_backoff(Duration::from_secs(1), max),
        Duration::from_secs(1)
    );
    assert!(next_backoff(Duration::from_secs(4), max) >= Duration::from_secs(1));
}

/// F10: LISTEN/NOTIFY channel names are truncated by the server (NAMEDATALEN).
#[test]
fn channel_name_limit_is_63_bytes() {
    assert!(!channel_name_too_long(&"a".repeat(63)));
    assert!(channel_name_too_long(&"a".repeat(64)));
    // Counting bytes, not characters.
    assert!(channel_name_too_long(&"é".repeat(32))); // 2 bytes each -> 64
}

#[test]
fn pg_connection_tracks_prepared_sqls_and_listen_channels() {
    let mut c = PgConnection::new(1);
    assert!(c.prepared_sqls.is_empty());
    assert!(c.listen_channels.is_empty());

    c.record_prepared("get_player", "SELECT id FROM players");
    c.record_listen("pgstream_events");
    c.record_listen("pgstream_events");

    assert_eq!(
        c.prepared_sqls.get("get_player").map(String::as_str),
        Some("SELECT id FROM players")
    );
    assert_eq!(c.listen_channels, vec!["pgstream_events".to_string()]);
}

/// A closed handle must disappear from the registry, otherwise the supervisor
/// would keep reconnecting for a connection the gamemode already dropped.
#[test]
fn close_removes_handle_so_supervisor_stops() {
    let id = 910_001;
    CONNECTIONS.lock().unwrap().clear();
    try_register_connection(id, 10).expect("registration must succeed");
    assert!(handle_exists(id));

    assert!(close_connection(id));
    assert!(!handle_exists(id));
    assert!(!close_connection(id));
}

fn old_toml() -> String {
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
