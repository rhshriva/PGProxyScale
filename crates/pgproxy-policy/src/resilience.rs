//! Conservative retry, replica consistency and explicitly invalidated result caching.
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
/// PostgreSQL LSN, compared numerically rather than lexically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lsn(pub u64);
impl std::str::FromStr for Lsn {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (high, low) = s.split_once('/').ok_or("invalid LSN")?;
        let high = u32::from_str_radix(high, 16).map_err(|_| "invalid LSN")?;
        let low = u32::from_str_radix(low, 16).map_err(|_| "invalid LSN")?;
        Ok(Self((u64::from(high) << 32) | u64::from(low)))
    }
}
#[derive(Debug, Default)]
pub struct Consistency {
    required: Option<Lsn>,
}
impl Consistency {
    pub fn committed(&mut self, lsn: Lsn) {
        self.required = Some(self.required.map_or(lsn, |old| old.max(lsn)));
    }
    pub fn replica_ready(&self, replay: Lsn) -> bool {
        self.required.is_none_or(|needed| replay >= needed)
    }
}
#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    NotSent,
    SentUnknown,
    ResponseStarted,
    TransactionFailed,
}
/// Lost acknowledgements are never retried: a read can call a mutating function.
pub fn safe_retry(outcome: Outcome, attempts: u32, budget: u32) -> bool {
    attempts < budget && matches!(outcome, Outcome::NotSent)
}
struct Entry {
    bytes: Vec<u8>,
    charged: usize,
    dependencies: BTreeSet<String>,
    generation: u64,
    expires: Instant,
}
/// Disabled unless caller proves immutable input and a synchronized invalidation feed.
/// Exact SQL plus parameters/principal/context must be included in caller's key;
/// normalized fingerprints alone are insufficient (SELECT 1 and SELECT 2 collide).
pub struct ResultCache {
    entries: BTreeMap<String, Entry>,
    capacity: usize,
    used: usize,
    generation: u64,
    synchronized: bool,
}
impl ResultCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity,
            used: 0,
            generation: 0,
            synchronized: false,
        }
    }
    pub fn synchronize(&mut self) {
        self.synchronized = true;
    }
    pub fn disconnect(&mut self) {
        self.synchronized = false;
        self.clear();
    }
    pub fn invalidate(&mut self, table: &str) {
        self.entries
            .retain(|_, entry| !entry.dependencies.contains(table));
        self.used = self.entries.values().map(|e| e.charged).sum();
    }
    pub fn clear(&mut self) {
        self.entries.clear();
        self.used = 0;
        self.generation = self.generation.wrapping_add(1);
    }
    pub fn insert(
        &mut self,
        key: String,
        bytes: Vec<u8>,
        dependencies: BTreeSet<String>,
        ttl: Duration,
        immutable: bool,
    ) -> bool {
        let Some(expires) = Instant::now().checked_add(ttl) else {
            return false;
        };
        let charged = bytes
            .capacity()
            .saturating_add(key.capacity())
            .saturating_add(std::mem::size_of::<Entry>() + 128)
            .saturating_add(
                dependencies
                    .iter()
                    .map(|d| d.capacity().saturating_add(64))
                    .sum::<usize>(),
            );
        if !self.synchronized || !immutable || charged > self.capacity || ttl.is_zero() {
            return false;
        }
        if let Some(old) = self.entries.remove(&key) {
            self.used -= old.charged;
        }
        if self.used.saturating_add(charged) > self.capacity {
            self.clear();
        }
        self.used += charged;
        self.entries.insert(
            key,
            Entry {
                bytes,
                charged,
                dependencies,
                generation: self.generation,
                expires,
            },
        );
        true
    }
    /// Caller must supply transaction dirty state and feed synchronization evidence.
    pub fn get(&self, key: &str, transaction_written: bool) -> Option<&[u8]> {
        if !self.synchronized || transaction_written {
            return None;
        }
        self.entries
            .get(key)
            .filter(|e| e.generation == self.generation && e.expires > Instant::now())
            .map(|e| e.bytes.as_slice())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_and_dirty_reads_refused() {
        let mut c = ResultCache::new(1024);
        assert!(!c.insert(
            "q".into(),
            vec![1],
            ["public.a".into()].into(),
            Duration::from_secs(1),
            true
        ));
        c.synchronize();
        assert!(c.insert(
            "q".into(),
            vec![1],
            ["public.a".into()].into(),
            Duration::from_secs(1),
            true
        ));
        assert!(c.get("q", true).is_none());
        assert_eq!(c.get("q", false), Some([1].as_slice()));
        c.invalidate("public.a");
        assert!(c.get("q", false).is_none());
        c.disconnect();
        assert!(c.get("q", false).is_none());
    }
    #[test]
    fn unknown_commit_never_replayed_and_lsn_order_correct() {
        assert!(!safe_retry(Outcome::SentUnknown, 0, 3));
        assert!(safe_retry(Outcome::NotSent, 0, 3));
        assert!(!safe_retry(Outcome::NotSent, 3, 3));
        let mut c = Consistency::default();
        c.committed("1/FF".parse().unwrap());
        assert!(!c.replica_ready("0/FFFFFFFF".parse().unwrap()));
        assert!(c.replica_ready("1/100".parse().unwrap()));
    }
}
