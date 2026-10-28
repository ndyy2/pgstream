use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_postgres::{Client, Statement};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Connecting,
    Connected,
    Disconnected,
    Failed,
}

pub struct PgConnection {
    pub id: i32,
    pub status: ConnectionStatus,
    pub client: Option<Arc<Mutex<Client>>>,
    pub prepared_statements: HashMap<String, Statement>,
    /// SQL behind each prepared statement name, kept so a reconnect can
    /// re-prepare them: a `Statement` is bound to the client it was made on.
    pub prepared_sqls: HashMap<String, String>,
    /// Channels currently LISTENed; server-side state lost on reconnect.
    pub listen_channels: Vec<String>,
    pub last_error: Option<String>,
}

impl PgConnection {
    pub fn new(id: i32) -> Self {
        Self {
            id,
            status: ConnectionStatus::Connecting,
            client: None,
            prepared_statements: HashMap::new(),
            prepared_sqls: HashMap::new(),
            listen_channels: Vec::new(),
            last_error: None,
        }
    }

    /// Records a prepared statement plus its SQL (SQL survives reconnect,
    /// the `Statement` object does not).
    pub fn record_prepared(&mut self, name: &str, sql: &str) {
        self.prepared_sqls.insert(name.to_string(), sql.to_string());
    }

    /// Records a channel after a successful `LISTEN` (deduplicated).
    pub fn record_listen(&mut self, channel: &str) {
        if !self.listen_channels.iter().any(|c| c == channel) {
            self.listen_channels.push(channel.to_string());
        }
    }
}
