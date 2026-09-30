# Remaining-feature integration — 2026-09-29

The parallel work has implemented the following additional mechanisms:

- Persistent SET ROLE/RESET ROLE replay with preparation context and rollback isolation.
- Opt-in bounded pristine SCROLL WITH HOLD text cursor materialization, preserving the original
  snapshot while multiple clients reuse a physical backend. Ineligible/budget-limited cursors keep
  native ownership; unsupported extended access to virtual cursors is explicitly refused.
- Ordered endpoint failover on acquisition before user SQL, verified writable-primary admission,
  stale generation fencing within the proxy, physical cancellation ownership and expiring credentials.
  Promotion/fencing is external. Uncertain transactions are never replayed.
- Snapshot-validated relation cache for a conservative ordinary-heap projection subset. A fresh
  repeatable-read transaction locks and validates the relation and exact visibility snapshot before
  returning cached rows. External writes/DDL, TRUNCATE, permission changes and failed validation
  cannot fall back to stale data. It is global/conservative invalidation, not logical decoding.
- Environment/file/command broker credentials and delegated AWS RDS IAM/Vault dynamic credentials.
- Measured principal/fingerprint usage, including MCP cache hits and errors, without pretending
  client elapsed time is server CPU or delivered rows are rows scanned.
- A certification evidence runner that blocks dependent tests on failed builds, records logs and
  reports unmet external gates rather than labelling a passing local suite production-certified.

## Evidence

Live: virtualization **6 cases**, physical replicated failover/fault **5 cases**, credential/wire
usage **5 cases**, snapshot cache/MCP accounting **10 cases**. The final native and Linux workspace suites each pass **323 unit/integration tests**, strict lint
and optimized release builds. Exact source/binary hashes and logs are in
`deliverables/verification/`, with reproduction in `tests/conformance/VERIFICATION.md`.
The runners use isolated PostgreSQL instances and public test credentials.

## Explicit remaining gates

The full product roadmap is still open: temp-schema/advisory-lock/notification virtualization,
exactly-once durable delivery and proxy-restart durability, idempotency dedupe/write replay,
replica read-your-writes admission, dependency-specific logical decoding cache invalidation,
OAuth/token exchange, exclusive tenant CPU/buffer/WAL allocation for shared roles, per-core pool performance and
long-running production topology/provider/fencing/bare-metal/security review. The two
architecture decisions behind the first and the exclusive-allocation item are now recorded
in [ADR-0006](../adr/0006-session-state-virtualization-boundary.md) and
[ADR-0007](../adr/0007-shared-role-tenant-cost-attribution.md) respectively.

A physical replica promotion test is a useful fault drill but cannot prove absence of split brain
without infrastructure fencing. Snapshot cache hits still require a database validation round trip;
no latency benefit is claimed without a matching benchmark. The local evidence runner cannot
perform an independent review or certify a production deployment it cannot access.

## Follow-on implementation — 2026-09-29

The next parallel development round adds PostgreSQL extended-protocol access to
held-cursor snapshots, actual server-cost collection, internal security fixes,
and authenticated production-evidence evaluation. Its final verification evidence
will be recorded separately from the earlier source snapshot above.

Server-cost collection exports actual database/role/PostgreSQL-queryid cumulative
WAL, buffer, call, row and elapsed counters; optional pg_stat_kcache supplies
execution user/system CPU. PostgreSQL 17+ per-entry statistics epochs are exposed
when available. It does not allocate shared-role activity to individual tenants,
subtract counters across resets, or equate elapsed time with CPU.

The internal security review closes protected-column whole-row and renamed-alias
bypasses, enforces private atomic report exports, and applies a single checked
MCP deadline through metadata, context, cache validation, user SQL and commit.
Internal review is not an independent external audit.

Certification decisions require a separately provisioned trust root, issuer
scopes, source/binary/deployment binding and authenticated supporting evidence.
Local unit tests with synthetic signing keys prove rejection/acceptance logic;
they are not production security, infrastructure, provider or hardware evidence.
The actual deployment still requires independent security review, authoritative
fencing, live AWS/Vault lifecycle acceptance and dedicated load/soak measurement.

Complete migration of temporary schemas, session advisory locks and notification
state remains an architecture decision ([ADR-0006](../adr/0006-session-state-virtualization-boundary.md)).
Unmodified PostgreSQL stores these in backend-owned resources; safe physical affinity
preserves their native semantics. Claiming full migration by replay would change OIDs,
locking/reentrancy, transaction visibility and notification timing. A PostgreSQL-side
component needs a separately defined integration and compatibility contract before
implementation.

Closed-cursor delivery is complete for the proxy-owned path: the tested PostgreSQL
builds crash on the native suspended-`CLOSE` path, so the proxy services the `CLOSE`
locally and keeps the suspended portal's cached descriptor and rows. The invariant is
enforced by a Rust unit test and documented in
[ledger semantics](../testing/ledger-semantics.md#closed-cursor-safety-and-the-native-suspended-close-defect).
