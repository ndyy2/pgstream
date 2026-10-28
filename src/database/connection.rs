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
    pub last_error: Option<String>,
}

impl PgConnection {
    pub fn new(id: i32) -> Self {
        Self {
            id,
            status: ConnectionStatus::Connecting,
            client: None,
            prepared_statements: HashMap::new(),
            last_error: None,
        }
    }
}
