//! Bounded attribution of client exchanges. No SQL text or bind values are retained.
use pgproxy_admin::UsageSample;
use pgproxy_parser::ParseOptions;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::Instant,
};
#[derive(Debug)]
struct Cycle {
    started: Instant,
    fingerprints: BTreeSet<String>,
    rows: u64,
    bytes: u64,
    errors: u64,
}
impl Cycle {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            fingerprints: BTreeSet::new(),
            rows: 0,
            bytes: 0,
            errors: 0,
        }
    }
    fn add(&mut self, fingerprint: String) {
        if self.fingerprints.contains("mixed") {
            return;
        }
        if self.fingerprints.len() < 8 {
            self.fingerprints.insert(fingerprint);
        } else {
            self.fingerprints.clear();
            self.fingerprints.insert("mixed".into());
        }
    }
    fn sample(self) -> UsageSample {
        UsageSample {
            fingerprint: if self.fingerprints.len() == 1 {
                self.fingerprints.into_iter().next().unwrap()
            } else {
                "mixed".into()
            },
            source: "wire_exchange".into(),
            rows: self.rows,
            result_bytes: self.bytes,
            elapsed_us: self.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            errors: self.errors,
            cache_hits: 0,
        }
    }
}
#[derive(Debug, Default)]
pub struct AccountingTracker {
    enabled: bool,
    options: ParseOptions,
    statements: BTreeMap<String, String>,
    portals: BTreeMap<String, String>,
    current: Option<Cycle>,
    cycles: VecDeque<Cycle>,
    suppressed: u64,
    dropped: u64,
}
fn string<'a>(bytes: &mut &'a [u8]) -> Option<&'a str> {
    let n = bytes.iter().position(|b| *b == 0)?;
    let result = std::str::from_utf8(&bytes[..n]).ok()?;
    *bytes = &bytes[n + 1..];
    Some(result)
}
impl AccountingTracker {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ..Default::default()
        }
    }
    pub fn options(&mut self, options: ParseOptions) {
        self.options = options;
    }
    fn fingerprint(&self, sql: &str) -> String {
        pgproxy_parser::parse(sql, self.options, 65536, 4 * 1024 * 1024)
            .map(|p| {
                format!(
                    "pg{}:{:016x}",
                    p.fingerprint.backend_major, p.fingerprint.hash
                )
            })
            .unwrap_or_else(|_| "unclassified".into())
    }
    fn seal(&mut self, cycle: Cycle) {
        if self.cycles.len() < 256 && self.suppressed == 0 {
            self.cycles.push_back(cycle);
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            self.dropped = self.dropped.saturating_add(1);
        }
    }
    pub fn take_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.dropped)
    }
    pub fn finish(&mut self) -> Vec<UsageSample> {
        let mut cycles: Vec<_> = self.cycles.drain(..).collect();
        if let Some(current) = self.current.take() {
            cycles.push(current);
        }
        cycles
            .into_iter()
            .map(|mut cycle| {
                cycle.errors = cycle.errors.saturating_add(1);
                let mut sample = cycle.sample();
                sample.source = "wire_aborted".into();
                sample
            })
            .collect()
    }
    pub fn observe(
        &mut self,
        from_client: bool,
        tag: u8,
        payload: &[u8],
        frame_len: usize,
    ) -> Option<UsageSample> {
        if !self.enabled {
            return None;
        }
        if from_client {
            let mut bytes = payload;
            match tag {
                b'Q' => {
                    let sql = string(&mut bytes)?;
                    let mut cycle = self.current.take().unwrap_or_else(Cycle::new);
                    cycle.add(self.fingerprint(sql));
                    self.seal(cycle);
                    self.statements.remove("");
                    self.portals.clear();
                }
                b'P' => {
                    self.current.get_or_insert_with(Cycle::new);
                    let name = string(&mut bytes)?;
                    let sql = string(&mut bytes)?;
                    if name.len() <= 128 {
                        if self.statements.len() >= 256 {
                            self.statements.clear();
                            self.portals.clear();
                        }
                        self.statements.insert(name.into(), self.fingerprint(sql));
                    }
                }
                b'B' => {
                    self.current.get_or_insert_with(Cycle::new);
                    let portal = string(&mut bytes)?;
                    let statement = string(&mut bytes)?;
                    if portal.len() <= 128 {
                        if self.portals.len() >= 256 {
                            self.portals.clear();
                        }
                        self.portals.insert(
                            portal.into(),
                            self.statements
                                .get(statement)
                                .cloned()
                                .unwrap_or_else(|| "unclassified".into()),
                        );
                    }
                }
                b'E' => {
                    let portal = string(&mut bytes)?;
                    let fp = self
                        .portals
                        .get(portal)
                        .cloned()
                        .unwrap_or_else(|| "unclassified".into());
                    self.current.get_or_insert_with(Cycle::new).add(fp);
                }
                b'S' => {
                    let cycle = self.current.take().unwrap_or_else(Cycle::new);
                    self.seal(cycle);
                }
                b'C' => {
                    let kind = *bytes.first()?;
                    bytes = &bytes[1..];
                    let name = string(&mut bytes)?;
                    if kind == b'S' {
                        self.statements.remove(name);
                    } else if kind == b'P' {
                        self.portals.remove(name);
                    }
                }
                _ => {}
            }
            return None;
        }
        if tag == b'Z' {
            if let Some(cycle) = self.cycles.pop_front() {
                return Some(cycle.sample());
            }
            if self.suppressed > 0 {
                self.suppressed -= 1;
            }
            return None;
        }
        if self.cycles.is_empty() && self.suppressed > 0 {
            return None;
        }
        if tag == b'E' {
            self.statements.clear();
            self.portals.clear();
        }
        // Replies precede Sync when a client explicitly Flushes an extended query.
        let active = self.cycles.front_mut().or(self.current.as_mut());
        if let Some(cycle) = active {
            match tag {
                b'D' => {
                    cycle.rows = cycle.rows.saturating_add(1);
                    cycle.bytes = cycle.bytes.saturating_add(frame_len as u64);
                }
                b'E' => cycle.errors = cycle.errors.saturating_add(1),
                _ => {}
            }
        }
        None
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_and_bind_errors_before_execute_are_accounted() {
        for tag in [b'P', b'B'] {
            let mut tracker = AccountingTracker::new(true);
            let payload: &[u8] = if tag == b'P' {
                b"s\0bad SQL\0\0\0"
            } else {
                b"p\0missing\0"
            };
            tracker.observe(true, tag, payload, payload.len() + 5);
            tracker.observe(false, b'E', b"failure", 20);
            tracker.observe(true, b'S', b"", 5);
            let sample = tracker.observe(false, b'Z', b"I", 6).unwrap();
            assert_eq!(sample.errors, 1);
            assert_eq!(sample.rows, 0);
        }
    }
    #[test]
    fn overflowing_fingerprint_set_remains_mixed() {
        let mut cycle = Cycle::new();
        for n in 0..20 {
            cycle.add(n.to_string());
        }
        assert_eq!(cycle.sample().fingerprint, "mixed");
    }
    #[test]
    fn pipeline_results_are_attributed_to_correct_exchange() {
        let mut tracker = AccountingTracker::new(true);
        tracker.observe(true, b'Q', b"SELECT 42\0", 14);
        tracker.observe(true, b'Q', b"SELECT 'a'\0", 16);
        tracker.observe(false, b'D', b"row", 16);
        let first = tracker.observe(false, b'Z', b"I", 6).unwrap();
        assert_eq!(first.rows, 1);
        assert_eq!(first.result_bytes, 16);
        tracker.observe(false, b'E', b"failure", 20);
        let second = tracker.observe(false, b'Z', b"I", 6).unwrap();
        assert_eq!(second.errors, 1);
        // Literal-only changes intentionally share a normalized query fingerprint.
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(second.rows, 0);
    }
    #[test]
    fn flush_before_sync_and_prepared_bind_provenance() {
        let mut tracker = AccountingTracker::new(true);
        tracker.observe(true, b'P', b"stmt\0SELECT 42\0\0\0", 25);
        tracker.observe(true, b'B', b"portal\0stmt\0", 17);
        tracker.observe(true, b'E', b"portal\0\0\0\0\0", 17);
        tracker.observe(false, b'D', b"row", 16);
        tracker.observe(true, b'S', b"", 5);
        let sample = tracker.observe(false, b'Z', b"I", 6).unwrap();
        assert_eq!(sample.rows, 1);
        assert!(sample.fingerprint.starts_with("pg18:"));
    }
    #[test]
    fn unfinished_exchanges_retain_partial_delivered_usage_on_disconnect() {
        let mut tracker = AccountingTracker::new(true);
        tracker.observe(true, b'Q', b"SELECT 1\0", 14);
        tracker.observe(false, b'D', b"row", 16);
        let samples = tracker.finish();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].rows, 1);
        assert_eq!(samples[0].source, "wire_aborted");
        assert_eq!(samples[0].errors, 1);
        assert!(tracker.finish().is_empty());
    }

    #[test]
    fn queue_overflow_preserves_alignment_and_bounds_memory() {
        let mut tracker = AccountingTracker::new(true);
        for _ in 0..300 {
            tracker.observe(true, b'Q', b"SELECT 1\0", 14);
        }
        assert_eq!(tracker.cycles.len(), 256);
        assert_eq!(tracker.suppressed, 44);
        assert_eq!(tracker.take_dropped(), 44);
        assert_eq!(tracker.take_dropped(), 0);
        for _ in 0..300 {
            tracker.observe(false, b'Z', b"I", 6);
        }
        assert_eq!(tracker.suppressed, 0);
        assert!(tracker.cycles.is_empty());
    }
}
