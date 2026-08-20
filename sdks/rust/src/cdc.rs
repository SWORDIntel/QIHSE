//! CDC (Change Data Capture) client for QIHSE

use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

/// CDC event operation type
#[derive(Debug, Clone)]
pub enum CdcOp {
    Insert, Update, Delete,
}

impl CdcOp {
    pub fn as_str(&self) -> &str {
        match self {
            CdcOp::Insert => "insert", CdcOp::Update => "update", CdcOp::Delete => "delete",
        }
    }
}

/// A single CDC event
#[derive(Debug, Clone)]
pub struct CdcEvent {
    pub op: CdcOp,
    pub table: String,
    pub key: Vec<u8>,
    pub old_value: Option<Vec<u8>>,
    pub new_value: Option<Vec<u8>>,
    pub lsn: u64,
    pub timestamp: u64,
}

/// CDC subscription callback type
pub type CdcCallback = Arc<dyn Fn(CdcEvent) + Send + Sync>;

/// CDC client
pub struct CdcClient {
    host: String,
    port: u16,
    subscriptions: Mutex<Vec<(String, CdcCallback)>>,
    running: Mutex<bool>,
}

impl CdcClient {
    pub fn new(host: &str, port: u16) -> Self {
        CdcClient {
            host: host.to_string(), port,
            subscriptions: Mutex::new(Vec::new()),
            running: Mutex::new(false),
        }
    }

    pub fn subscribe<F>(&self, name: &str, callback: F)
    where F: Fn(CdcEvent) + Send + Sync + 'static
    {
        self.subscriptions.lock().unwrap().push((name.to_string(), Arc::new(callback)));
    }

    pub fn unsubscribe(&self, name: &str) {
        let mut subs = self.subscriptions.lock().unwrap();
        subs.retain(|(n, _)| n != name);
    }

    pub fn start_blocking(&self) {
        *self.running.lock().unwrap() = true;
        // In real implementation, connect and receive events
        while *self.running.lock().unwrap() {
            thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
    }

    pub fn get_lsn(&self) -> u64 { 0 }
}
