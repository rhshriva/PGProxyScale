//! Client exchange accounting and separate measured PostgreSQL role aggregates.
use serde::Serialize;
use std::collections::BTreeMap;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct UsageIdentity {
    pub user: String,
    pub tenant: String,
    pub agent: Option<String>,
}
#[derive(Debug, Default, Clone, Serialize)]
pub struct UsageSample {
    pub fingerprint: String,
    pub source: String,
    pub rows: u64,
    pub result_bytes: u64,
    pub elapsed_us: u64,
    pub errors: u64,
    pub cache_hits: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct UsageReport {
    pub identity: UsageIdentity,
    pub fingerprint: String,
    pub source: String,
    pub exchanges: u64,
    pub rows: u64,
    pub result_bytes: u64,
    pub elapsed_us: u64,
    pub errors: u64,
    pub cache_hits: u64,
    pub cpu_us: Option<u64>,
    pub buffers: Option<u64>,
    pub wal_bytes: Option<u64>,
}
#[derive(Debug, Default)]
pub(crate) struct UsageLedger {
    entries: BTreeMap<(UsageIdentity, String, String), UsageReport>,
    pub dropped: u64,
}
impl UsageLedger {
    pub fn record(&mut self, identity: &UsageIdentity, sample: UsageSample) {
        if identity.user.len() > 256
            || identity.tenant.len() > 256
            || identity.agent.as_ref().is_some_and(|a| a.len() > 256)
            || sample.fingerprint.len() > 128
            || sample.source.len() > 32
        {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let key = (
            identity.clone(),
            sample.fingerprint.clone(),
            sample.source.clone(),
        );
        if !self.entries.contains_key(&key) && self.entries.len() >= 4096 {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let entry = self.entries.entry(key).or_insert_with(|| UsageReport {
            identity: identity.clone(),
            fingerprint: sample.fingerprint.clone(),
            source: sample.source.clone(),
            exchanges: 0,
            rows: 0,
            result_bytes: 0,
            elapsed_us: 0,
            errors: 0,
            cache_hits: 0,
            cpu_us: None,
            buffers: None,
            wal_bytes: None,
        });
        entry.exchanges = entry.exchanges.saturating_add(1);
        entry.rows = entry.rows.saturating_add(sample.rows);
        entry.result_bytes = entry.result_bytes.saturating_add(sample.result_bytes);
        entry.elapsed_us = entry.elapsed_us.saturating_add(sample.elapsed_us);
        entry.errors = entry.errors.saturating_add(sample.errors);
        entry.cache_hits = entry.cache_hits.saturating_add(sample.cache_hits);
    }
    pub fn snapshot(&self) -> Vec<UsageReport> {
        self.entries.values().cloned().collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_measured_usage_isolated_and_unmeasured_cost_remains_unknown() {
        let mut ledger = UsageLedger::default();
        for tenant in ["a", "b"] {
            let who = UsageIdentity {
                user: "same".into(),
                tenant: tenant.into(),
                agent: None,
            };
            ledger.record(
                &who,
                UsageSample {
                    fingerprint: "f".into(),
                    source: "wire".into(),
                    rows: 3,
                    result_bytes: 128,
                    elapsed_us: 25,
                    ..Default::default()
                },
            );
        }
        let report = ledger.snapshot();
        assert_eq!(report.len(), 2);
        assert!(report.iter().all(|r| r.exchanges == 1
            && r.rows == 3
            && r.cpu_us.is_none()
            && r.wal_bytes.is_none()));
    }
    #[test]
    fn cardinality_and_labels_are_bounded_without_evicting_existing_accounts() {
        let mut ledger = UsageLedger::default();
        let who = UsageIdentity {
            user: "u".into(),
            tenant: "t".into(),
            agent: None,
        };
        for i in 0..4100 {
            ledger.record(
                &who,
                UsageSample {
                    fingerprint: i.to_string(),
                    source: "wire".into(),
                    ..Default::default()
                },
            );
        }
        assert_eq!(ledger.snapshot().len(), 4096);
        assert_eq!(ledger.dropped, 4);
        ledger.record(
            &who,
            UsageSample {
                fingerprint: "0".into(),
                source: "wire".into(),
                ..Default::default()
            },
        );
        assert_eq!(ledger.snapshot()[0].exchanges, 2);
    }
}

/// Server extension measurements are cumulative PostgreSQL-role aggregates, not
/// exclusive per-request or per-tenant bills. Query text and bind values are omitted.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerStatementCost {
    pub database_oid: u32,
    pub role_oid: u32,
    pub role: String,
    pub query_id: String,
    pub top_level: bool,
    pub calls: u64,
    /// Per-entry reset/creation epoch when PostgreSQL exposes it (17+).
    pub statistics_since: Option<String>,
    pub rows: u64,
    pub execution_ms: f64,
    pub shared_blocks_hit: u64,
    pub shared_blocks_read: u64,
    pub shared_blocks_dirtied: u64,
    pub shared_blocks_written: u64,
    pub local_blocks_hit: u64,
    pub local_blocks_read: u64,
    pub local_blocks_dirtied: u64,
    pub local_blocks_written: u64,
    pub temp_blocks_read: u64,
    pub temp_blocks_written: u64,
    /// Decimal representation preserves PostgreSQL's numeric WAL counter exactly.
    pub wal_bytes: String,
    pub wal_records: u64,
    pub wal_full_page_images: u64,
    pub execution_user_cpu_seconds: Option<f64>,
    pub execution_system_cpu_seconds: Option<f64>,
}
#[derive(Debug, Clone, Serialize)]
pub struct ServerCostReport {
    pub scope: &'static str,
    pub cluster_system_identifier: String,
    pub postmaster_started_at: String,
    pub collected_at: String,
    pub server_major: u32,
    pub database: String,
    /// Global pg_stat_statements reset epoch only; targeted resets can differ,
    /// and pg_stat_kcache has an independent reset lifecycle.
    pub statistics_reset_at: String,
    pub statement_evictions: u64,
    pub cpu_source: &'static str,
    pub limitations: Vec<&'static str>,
    pub statements: Vec<ServerStatementCost>,
}
