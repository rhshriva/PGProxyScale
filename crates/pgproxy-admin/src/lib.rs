//! Bounded operational telemetry and authenticated diagnostics.
#![forbid(unsafe_code)]
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub mod http;
pub mod usage;
pub use usage::{UsageIdentity, UsageReport, UsageSample};
const BOUNDS_US: [u64; 16] = [
    100,
    250,
    500,
    1000,
    2500,
    5000,
    10000,
    25000,
    50000,
    100000,
    250000,
    500000,
    1000000,
    2500000,
    5000000,
    u64::MAX,
];
#[derive(Debug, Serialize, Clone)]
pub struct Client {
    pub id: u64,
    pub principal: String,
    pub database: String,
    pub peer: String,
    pub transaction: String,
    pub pin_reasons: Vec<String>,
    pub messages_in: u64,
    pub messages_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}
#[derive(Debug, Default)]
struct Histogram {
    buckets: [u64; 16],
    count: u64,
    sum_us: u128,
}
impl Histogram {
    fn observe(&mut self, elapsed: Duration) {
        let us = elapsed.as_micros().min(u64::MAX as u128) as u64;
        let index = BOUNDS_US.iter().position(|b| us <= *b).unwrap_or(15);
        self.buckets[index] += 1;
        self.count += 1;
        self.sum_us += us as u128;
    }
    fn quantile(&self, numerator: u64) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let rank = (self.count * numerator).div_ceil(100);
        let mut count = 0;
        for (i, n) in self.buckets.iter().enumerate() {
            count += n;
            if count >= rank {
                return Some(BOUNDS_US[i]);
            }
        }
        None
    }
}
#[derive(Debug, Default)]
pub struct Operations {
    ready: AtomicBool,
    paused: AtomicBool,
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub errors: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    clients: Mutex<BTreeMap<u64, Client>>,
    latency: Mutex<Histogram>,
    usage: Mutex<usage::UsageLedger>,
    identities: Mutex<BTreeMap<u64, UsageIdentity>>,
}
impl Operations {
    pub fn usage_identity(&self, id: u64, identity: UsageIdentity) {
        self.identities.lock().unwrap().insert(id, identity);
    }
    pub fn record_usage(&self, identity: &UsageIdentity, sample: UsageSample) {
        self.usage.lock().unwrap().record(identity, sample);
    }
    pub fn record_client_usage(&self, id: u64, sample: UsageSample) {
        let identity = self.identities.lock().unwrap().get(&id).cloned();
        if let Some(identity) = identity {
            self.record_usage(&identity, sample);
        }
    }
    pub fn usage_report(&self) -> Vec<UsageReport> {
        self.usage.lock().unwrap().snapshot()
    }
    pub fn add_usage_dropped(&self, count: u64) {
        let mut usage = self.usage.lock().unwrap();
        usage.dropped = usage.dropped.saturating_add(count);
    }
    pub fn usage_dropped(&self) -> u64 {
        self.usage.lock().unwrap().dropped
    }
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Release);
    }
    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire) && !self.paused.load(Ordering::Acquire)
    }
    pub fn register(self: &Arc<Self>, id: u64, peer: String) -> ClientGuard {
        self.accepted.fetch_add(1, Ordering::Relaxed);
        self.clients.lock().unwrap().insert(
            id,
            Client {
                id,
                principal: String::new(),
                database: String::new(),
                peer,
                transaction: "startup".into(),
                pin_reasons: vec![],
                messages_in: 0,
                messages_out: 0,
                bytes_in: 0,
                bytes_out: 0,
            },
        );
        ClientGuard {
            operations: Arc::clone(self),
            id,
        }
    }
    pub fn identity(&self, id: u64, user: &str, database: &str) {
        self.usage_identity(
            id,
            UsageIdentity {
                user: user.chars().take(256).collect(),
                tenant: String::new(),
                agent: None,
            },
        );
        if let Some(client) = self.clients.lock().unwrap().get_mut(&id) {
            client.principal = user.chars().take(256).collect();
            client.database = database.chars().take(256).collect();
        }
    }
    pub fn pins(&self, id: u64, reasons: &[&str]) {
        if let Some(client) = self.clients.lock().unwrap().get_mut(&id) {
            client.pin_reasons = reasons.iter().map(|r| r.to_string()).collect();
        }
    }
    pub fn observe(&self, id: u64, from_client: bool, tag: u8, payload: &[u8], len: usize) {
        let counter = if from_client {
            &self.bytes_in
        } else {
            &self.bytes_out
        };
        counter.fetch_add(len as u64, Ordering::Relaxed);
        if let Some(client) = self.clients.lock().unwrap().get_mut(&id) {
            if from_client {
                client.messages_in += 1;
                client.bytes_in += len as u64;
            } else {
                client.messages_out += 1;
                client.bytes_out += len as u64;
                if tag == b'Z' && payload.len() == 1 {
                    client.transaction = match payload[0] {
                        b'I' => "idle",
                        b'T' => "transaction",
                        b'E' => "failed",
                        _ => "invalid",
                    }
                    .into();
                }
            }
        }
    }
    pub fn latency(&self, elapsed: Duration) {
        self.latency.lock().unwrap().observe(elapsed);
    }
    pub fn clients(&self) -> Vec<Client> {
        self.clients.lock().unwrap().values().cloned().collect()
    }
    pub fn prometheus(&self) -> String {
        let latency = self.latency.lock().unwrap();
        let clients = self.clients.lock().unwrap().len();
        let mut out = format!(
            "pgproxy_ready {}\npgproxy_clients {}\npgproxy_connections_total {}\npgproxy_connections_rejected_total {}\npgproxy_session_errors_total {}\npgproxy_bytes_in_total {}\npgproxy_bytes_out_total {}\n",
            u8::from(self.ready()),
            clients,
            self.accepted.load(Ordering::Relaxed),
            self.rejected.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
            self.bytes_in.load(Ordering::Relaxed),
            self.bytes_out.load(Ordering::Relaxed)
        );
        let mut cumulative = 0;
        for (i, n) in latency.buckets.iter().enumerate() {
            cumulative += n;
            let bound = if i == 15 {
                "+Inf".into()
            } else {
                format!("{}", BOUNDS_US[i] as f64 / 1e6)
            };
            out += &format!(
                "pgproxy_exchange_duration_seconds_bucket{{le=\"{bound}\"}} {cumulative}\n"
            );
        }
        out += &format!(
            "pgproxy_exchange_duration_seconds_count {}\npgproxy_exchange_duration_seconds_sum {}\n",
            latency.count,
            latency.sum_us as f64 / 1e6
        );
        for (label, q) in [("0.5", 50), ("0.95", 95), ("0.99", 99)] {
            if let Some(us) = latency.quantile(q) {
                out += &format!(
                    "pgproxy_exchange_duration_seconds{{quantile=\"{label}\"}} {}\n",
                    if us == u64::MAX {
                        f64::INFINITY
                    } else {
                        us as f64 / 1e6
                    }
                );
            }
        }
        out
    }
}
pub struct ClientGuard {
    operations: Arc<Operations>,
    id: u64,
}
impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.operations.clients.lock().unwrap().remove(&self.id);
        self.operations.identities.lock().unwrap().remove(&self.id);
    }
}
/// Tracks Sync-delimited protocol exchange durations, including pool wait and relay.
/// These are exchange latencies, not execution-time or per-statement claims.
#[derive(Debug, Default)]
pub struct ExchangeClock {
    pending: VecDeque<Instant>,
    extended: Option<Instant>,
    suppressed: u64,
}
impl ExchangeClock {
    fn enqueue(&mut self, start: Instant) {
        if self.suppressed > 0 || self.pending.len() >= 4096 {
            self.suppressed = self.suppressed.saturating_add(1);
        } else {
            self.pending.push_back(start);
        }
    }
    pub fn observe(&mut self, from_client: bool, tag: u8) -> Option<Duration> {
        if from_client {
            match tag {
                b'Q' => self.enqueue(Instant::now()),
                b'P' | b'B' | b'E' => {
                    self.extended.get_or_insert_with(Instant::now);
                }
                b'S' => {
                    let start = self.extended.take().unwrap_or_else(Instant::now);
                    self.enqueue(start);
                }
                _ => {}
            }
        } else if tag == b'Z' {
            let measured = self.pending.pop_front().map(|start| start.elapsed());
            if measured.is_none() {
                self.suppressed = self.suppressed.saturating_sub(1);
            }
            return measured;
        }
        None
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn histogram_percentiles_and_cumulative_buckets() {
        let ops = Operations::default();
        for _ in 0..95 {
            ops.latency(Duration::from_micros(200));
        }
        for _ in 0..5 {
            ops.latency(Duration::from_millis(9));
        }
        let h = ops.latency.lock().unwrap();
        assert_eq!(h.quantile(50), Some(250));
        assert_eq!(h.quantile(95), Some(250));
        assert_eq!(h.quantile(99), Some(10000));
        drop(h);
        assert!(ops.prometheus().contains("le=\"+Inf\"} 100"));
    }
    #[test]
    fn diagnostics_lifetime_and_identity() {
        let ops = Arc::new(Operations::default());
        let guard = ops.register(42, "127.0.0.1".into());
        ops.identity(42, "alice", "app");
        ops.observe(42, false, b'Z', b"T", 6);
        ops.pins(42, &["cursor"]);
        let c = ops.clients();
        assert_eq!(c[0].principal, "alice");
        assert_eq!(c[0].transaction, "transaction");
        assert_eq!(c[0].bytes_out, 6);
        drop(guard);
        assert!(ops.clients().is_empty());
    }
    #[test]
    fn exchange_clock_memory_is_bounded_without_misattributing_overflow() {
        let mut clock = ExchangeClock::default();
        for _ in 0..5000 {
            clock.observe(true, b'Q');
        }
        assert_eq!(clock.pending.len(), 4096);
        for _ in 0..4096 {
            assert!(clock.observe(false, b'Z').is_some());
        }
        for _ in 0..904 {
            assert!(clock.observe(false, b'Z').is_none());
        }
        clock.observe(true, b'Q');
        assert!(clock.observe(false, b'Z').is_some());
    }
    #[test]
    fn clock_tracks_pipeline_sync_batches() {
        let mut clock = ExchangeClock::default();
        assert!(clock.observe(false, b'Z').is_none());
        clock.observe(true, b'P');
        clock.observe(true, b'S');
        clock.observe(true, b'Q');
        assert!(clock.observe(false, b'Z').is_some());
        assert!(clock.observe(false, b'Z').is_some());
        assert!(clock.observe(false, b'Z').is_none());
    }
}
