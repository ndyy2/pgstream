use once_cell::sync::Lazy;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use tokio::runtime::Runtime;

pub enum CompletionEvent {
    Connected {
        conn_id: i32,
        success: bool,
        callback: String,
    },
    QueryFinished {
        conn_id: i32,
        result_id: i32,
        callback: String,
        extra: i32,
    },
    CommandFinished {
        conn_id: i32,
        success: bool,
        callback: String,
    },
    Notification {
        conn_id: i32,
        channel: String,
        payload: String,
    },
}

struct QueueState {
    sender: Sender<CompletionEvent>,
    receiver: Receiver<CompletionEvent>,
}

static QUEUE: Lazy<Mutex<QueueState>> = Lazy::new(|| {
    let (tx, rx) = channel();
    Mutex::new(QueueState {
        sender: tx,
        receiver: rx,
    })
});

static RUNTIME: Lazy<Mutex<Option<Runtime>>> = Lazy::new(|| Mutex::new(None));

pub fn init_runtime() {
    let mut rt = RUNTIME.lock().unwrap();
    if rt.is_none() {
        let created = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to create PGStream Tokio runtime");
        *rt = Some(created);
    }
}

pub fn shutdown_runtime() {
    let mut rt = RUNTIME.lock().unwrap();
    if let Some(rt) = rt.take() {
        rt.shutdown_background();
    }
}

pub fn spawn<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let rt = RUNTIME.lock().unwrap();
    if let Some(ref rt) = *rt {
        rt.spawn(fut);
    }
}

pub fn send_completion(event: CompletionEvent) {
    let q = QUEUE.lock().unwrap();
    let _ = q.sender.send(event);
}

pub fn poll_completions() -> Vec<CompletionEvent> {
    let q = QUEUE.lock().unwrap();
    let mut events = Vec::new();
    while let Ok(evt) = q.receiver.try_recv() {
        events.push(evt);
    }
    events
}
