# ADR 0007 — Exclusive tenant cost attribution for shared backend roles

- **Status:** Proposed — decision required
- **Date:** 2026-09-30
- **Depends on:** ADR 0003

---

## Context

Two cost-measurement surfaces exist today and are deliberately kept separate
(`docs/testing/credentials-and-usage.md`):

1. **Proxy-observed wire usage.** Per principal and versioned normalized
   fingerprint: simple/extended rows, `DataRow` frame bytes, elapsed client
   exchange time, errors and partial aborted exchanges. Elapsed client time is not
   CPU, and delivered rows are not server rows scanned.
2. **Operator server-cost export.** Actual cumulative database / role /
   `queryid` counters from `pg_stat_statements`: WAL bytes/records/FPIs, shared and
   local/temp block hits/reads/dirtied/written, calls, rows and elapsed. Optional
   `pg_stat_kcache` supplies measured execution user/system CPU.

The proxy authenticates many tenants onto **one shared backend service role**
(after optional `SET ROLE`, which does not change the `userid` that
`pg_stat_statements` attributes a statement to). Therefore the server-cost export
aggregates all activity under that role — including writers outside the proxy — and
**cannot identify an individual tenant's share**. Wire usage cannot substitute:
it is not actual CPU/WAL/buffer consumption.

"Exclusive tenant cost allocation" (per-tenant WAL/buffer/CPU) is therefore not
implementable from the current collection surface. Inventing a share (e.g. pro-rata
by query count or elapsed time) would be a fabricated number and is rejected.

---

## Decision

**Do not infer per-tenant CPU/WAL/buffer from shared-role counters.** Keep the two
surfaces separate and honest until one of the options below is chosen and
implemented behind an explicit architecture decision:

1. **Per-tenant PostgreSQL roles.** Require tenants to execute as distinct backend
   roles so `pg_stat_statements.userid` separates them. Cost: role lifecycle
   management, grant surface, connection/role churn, and shared objects still
   aggregate if a tenant uses SET ROLE.
2. **Per-backend server-side sampling.** A server-side agent attributes activity to
   the physical backend / logical session it observes. Cost: another deployment
   artifact, version sensitivity, and its own correctness/overhead budget.
3. **Explicitly non-exclusive accounting.** Continue exporting role/database/queryid
   aggregates, document them as non-exclusive, and reconcile chargeback outside the
   proxy. No per-tenant CPU/WAL claim is made.

Unless and until (1) or (2) is approved and verified, the product reports
server-cost measurements **scoped to database/role/queryid only**, with the
existing limitations list (cumulative counters, reset epochs, eviction, extension
accounting, elapsed ≠ CPU) and makes **no exclusive tenant allocation**.

---

## Alternatives considered

1. **Pro-rata allocation from wire data** (assign shared counters by request share).
   Rejected: fabricates numbers that are wrong under contention, parallelism and
   out-of-proxy activity.
2. **Correlate proxy fingerprints with `queryid`.** Insufficient: many statements
   share a queryid across tenants, and role-level counters cannot be split by
   fingerprint without per-request server timing.
3. **Per-tenant roles (option 1).** Viable but a deployment/identity decision, not a
   proxy-only change.
4. **Server-side sampling (option 2).** Most accurate; largest deployment cost.
5. **Non-exclusive accounting (option 3).** Honest interim; accepted as current state.

---

## Consequences

**Positive**
- No fabricated per-tenant billing/chargeback numbers.
- The exported server-cost report is reproducible and independently reconcilable
  from raw counters.
- Keeps the proxy a single binary (ADR 0005) unless option 1/2 is chosen.

**Negative / risky**
- No exclusive per-tenant CPU/WAL/buffer allocation is available; noisy-neighbour
  cost cannot be attributed precisely from the proxy alone.
- Operators needing chargeback must choose option 1, 2, or reconcile externally.

---

## Open questions

1. Is per-tenant backend-role execution acceptable for the target deployments, and
   how are role lifecycle and grants managed?
2. If per-backend sampling is pursued, what overhead and version envelope are
   acceptable, and how is it authenticated/fenced?
3. What reconciliation SLO is required before billing/chargeback may consume these
   numbers?
