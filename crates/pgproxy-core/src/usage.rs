//! Adapter between MCP observations and the process usage ledger.
use pgproxy_admin::{Operations, UsageIdentity, UsageSample};
use std::{sync::Arc, time::Duration};
pub struct UsageObserver(pub Arc<Operations>);
impl pgproxy_policy::mcp::UsageObserver for UsageObserver {
    fn record(
        &self,
        principal: &pgproxy_policy::Principal,
        fingerprint: pgproxy_parser::Fingerprint,
        rows: usize,
        bytes: usize,
        elapsed: Duration,
        error: bool,
        cache_hit: bool,
    ) {
        self.0.record_usage(
            &UsageIdentity {
                user: principal.user.clone(),
                tenant: principal.tenant.clone(),
                agent: principal.agent.clone(),
            },
            UsageSample {
                fingerprint: format!("pg{}:{:016x}", fingerprint.backend_major, fingerprint.hash),
                source: "mcp_tool".into(),
                rows: rows as u64,
                result_bytes: bytes as u64,
                elapsed_us: elapsed.as_micros().min(u64::MAX as u128) as u64,
                errors: u64::from(error),
                cache_hits: u64::from(cache_hit),
            },
        );
    }
}
