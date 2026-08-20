//! Prometheus-compatible metrics and OpenTelemetry-compatible tracing

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// ---- Metrics ----

pub struct Counter {
    name: String,
    value: Mutex<f64>,
}

impl Counter {
    pub fn new(name: &str) -> Self {
        Counter { name: name.to_string(), value: Mutex::new(0.0) }
    }
    pub fn inc(&self, amount: f64) {
        *self.value.lock().unwrap() += amount;
    }
    pub fn value(&self) -> f64 { *self.value.lock().unwrap() }
    pub fn name(&self) -> &str { &self.name }
}

pub struct Gauge {
    name: String,
    value: Mutex<f64>,
}

impl Gauge {
    pub fn new(name: &str) -> Self {
        Gauge { name: name.to_string(), value: Mutex::new(0.0) }
    }
    pub fn set(&self, v: f64) { *self.value.lock().unwrap() = v; }
    pub fn inc(&self, v: f64) { *self.value.lock().unwrap() += v; }
    pub fn dec(&self, v: f64) { *self.value.lock().unwrap() -= v; }
    pub fn value(&self) -> f64 { *self.value.lock().unwrap() }
    pub fn name(&self) -> &str { &self.name }
}

pub struct Histogram {
    name: String,
    count: Mutex<u64>,
    sum: Mutex<f64>,
}

impl Histogram {
    pub fn new(name: &str) -> Self {
        Histogram { name: name.to_string(), count: Mutex::new(0), sum: Mutex::new(0.0) }
    }
    pub fn observe(&self, v: f64) {
        *self.count.lock().unwrap() += 1;
        *self.sum.lock().unwrap() += v;
    }
    pub fn count(&self) -> u64 { *self.count.lock().unwrap() }
    pub fn sum(&self) -> f64 { *self.sum.lock().unwrap() }
    pub fn name(&self) -> &str { &self.name }
}

pub struct CollectorRegistry {
    counters: Mutex<Vec<Arc<Counter>>>,
    gauges: Mutex<Vec<Arc<Gauge>>>,
    histograms: Mutex<Vec<Arc<Histogram>>>,
}

impl CollectorRegistry {
    pub fn new() -> Self {
        CollectorRegistry {
            counters: Mutex::new(Vec::new()),
            gauges: Mutex::new(Vec::new()),
            histograms: Mutex::new(Vec::new()),
        }
    }

    pub fn register_counter(&self, c: Arc<Counter>) {
        self.counters.lock().unwrap().push(c);
    }
    pub fn register_gauge(&self, g: Arc<Gauge>) {
        self.gauges.lock().unwrap().push(g);
    }
    pub fn register_histogram(&self, h: Arc<Histogram>) {
        self.histograms.lock().unwrap().push(h);
    }

    pub fn export(&self) -> String {
        let mut out = String::new();
        for c in self.counters.lock().unwrap().iter() {
            out.push_str(&format!("{} {}\n", c.name(), c.value()));
        }
        for g in self.gauges.lock().unwrap().iter() {
            out.push_str(&format!("{} {}\n", g.name(), g.value()));
        }
        for h in self.histograms.lock().unwrap().iter() {
            out.push_str(&format!("{}_count {}\n", h.name(), h.count()));
            out.push_str(&format!("{}_sum {}\n", h.name(), h.sum()));
        }
        out
    }
}

// ---- Tracing ----

pub struct Span {
    pub operation: String,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub start_ns: u128,
    pub end_ns: Option<u128>,
    pub attributes: Mutex<Vec<(String, String)>>,
    pub status: Mutex<u8>,
}

impl Span {
    pub fn set_attribute(&self, key: &str, value: &str) {
        self.attributes.lock().unwrap().push((key.to_string(), value.to_string()));
    }
    pub fn end(&self) {
        *self.status.lock().unwrap() = 0;
    }
    pub fn duration_ns(&self) -> u128 {
        self.end_ns.map(|e| e - self.start_ns).unwrap_or(0)
    }
}

pub struct Tracer {
    spans: Mutex<Vec<Span>>,
    enabled: Mutex<bool>,
}

impl Tracer {
    pub fn new() -> Self {
        Tracer { spans: Mutex::new(Vec::new()), enabled: Mutex::new(true) }
    }

    pub fn start_span(&self, operation: &str, parent: Option<&Span>) -> Span {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        Span {
            operation: operation.to_string(),
            trace_id: format!("{:032x}", rand_u128()),
            span_id: format!("{:016x}", rand_u64()),
            parent_span_id: parent.map(|p| p.span_id.clone()),
            start_ns: now,
            end_ns: None,
            attributes: Mutex::new(Vec::new()),
            status: Mutex::new(0),
        }
    }

    pub fn finish_span(&self, mut span: Span) {
        span.end_ns = Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        self.spans.lock().unwrap().push(span);
    }

    pub fn export_json(&self) -> String {
        let spans = self.spans.lock().unwrap();
        let mut out = String::from("{\"spans\":[");
        for (i, s) in spans.iter().enumerate() {
            if i > 0 { out.push(','); }
            out.push_str(&format!(
                "{{\"operation\":\"{}\",\"trace_id\":\"{}\",\"span_id\":\"{}\",\"duration_ns\":{}}}",
                s.operation, s.trace_id, s.span_id, s.duration_ns()
            ));
        }
        out.push_str("]}");
        out
    }

    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.lock().unwrap() = enabled;
    }
}

fn rand_u128() -> u128 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as u128
}
fn rand_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish()
}
