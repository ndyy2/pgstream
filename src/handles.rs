use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

use crate::database::connection::PgConnection;
use crate::database::result::QueryResult;

static NEXT_CONN_ID: AtomicI32 = AtomicI32::new(1);
static NEXT_RESULT_ID: AtomicI32 = AtomicI32::new(1);

pub static CONNECTIONS: Lazy<Mutex<HashMap<i32, PgConnection>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub static RESULTS: Lazy<Mutex<HashMap<i32, QueryResult>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn next_connection_id() -> i32 {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn next_result_id() -> i32 {
    NEXT_RESULT_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn free_result(id: i32) -> bool {
    let mut map = RESULTS.lock().unwrap();
    map.remove(&id).is_some()
}
