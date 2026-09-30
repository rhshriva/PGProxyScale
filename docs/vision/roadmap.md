# Roadmap

Current remaining-work plan, reviewed 2026-09-30. Implemented behavior and recorded
results are in [implementation status](../plans/implementation-status.md).

## Product goal

A PostgreSQL gateway that preserves supported application session semantics under
transaction pooling, enforces parsed SQL permissions, controls tenant/agent load,
and provides measurable usage, reliable operation and safe caching. The product
is pre-alpha and has not completed production certification.

## Remaining work and exit criteria

| Area | Remaining work | Acceptance criterion |
|---|---|---|
| State virtualization | Extended cursor access in explicit transactions, mixed physical/virtual cycles, SQL PREPARE interoperability, catalog visibility and comprehensive retained-plan DDL invalidation | Differential native PostgreSQL tests preserve transaction/savepoint atomicity, message order, cancellation and DDL behavior |
| Temp/lock/notification migration | Decide and validate a PostgreSQL-side logical-session contract; continue native affinity meanwhile | Stable object identity, lock reentrancy/conflicts, subscription commit ordering, bounded ownership and fault cleanup verified across supported majors |
| Notification durability | Define durable events, recovery, overflow and client acknowledgement | Stated delivery guarantees demonstrated through backend loss, proxy restart and reconnect; no exactly-once processing claim without acknowledgement |
| Policy and identity | Actual result masking, OAuth/token exchange, identity lifecycle and independent adversarial review | Reviewed objects/roles/RLS and all protocol paths enforce the same identity and permissions under adversarial tests |
| Pools and fairness | Per-core pool ownership, background health monitoring, storm/fault soak and production noisy-neighbor bounds | Shared process cap remains correct across cores/generations; measured latency bounds under controlled contention |
| Cost attribution | Resolve exclusive allocation for tenants sharing a backend role and reconcile server measurements | Actual measurements reconcile within an agreed tolerance; no pro-rata inference presented as measured tenant CPU/WAL |
| Resilience | Deployed promotion/fencing integration, replica read-your-writes and bounded retry/idempotency design | Authoritative fencing prevents split brain; replica admission respects consistency; uncertain writes are never duplicated |
| Cache invalidation | Dependency-specific live invalidation, DDL coverage and measured benefit | Concurrent writes/DDL cannot produce stale reads; correctness and overhead validated for each admitted query class |
| Compatibility | Remaining drivers/extensions, protocol 3.2 extensions and grammar/version coverage | Reproducible driver/version matrix bound to the release source and binary |
| Production verification | Instrumented long fuzz campaigns, independent security review, real AWS/Vault lifecycle, deployed fencing and dedicated Linux performance/soak | Authenticated source/binary/deployment-bound evidence satisfies every required external gate |
| Release packaging | Licence decision, configuration/deployment guidance and current sales material | Release metadata and examples agree with the tested product and its limitations |

## Architectural choices

[Proposal 0006](../adr/0006-session-state-virtualization-boundary.md) describes the
server-side dependency for complete resource migration.
[Proposal 0007](../adr/0007-shared-role-tenant-cost-attribution.md) describes options
for exclusive tenant cost attribution. Neither is an approved implementation plan.

Current caching uses exact SQL/identity and fresh snapshot validation. Acquisition
failover selects a writable backend before user SQL; it does not promote or fence
PostgreSQL servers. Planned drain waits for old sessions to disconnect. Zero
pinning, universal drop-in compatibility, zero dropped work and production security
are acceptance goals that have not been established.

## Scope

Develop against PostgreSQL 14–18 with version-specific compatibility evidence.
Linux is the deployment target; macOS supports development. Optional monitoring
extensions and provider adapters require documented privileges and configuration.
The standalone binary remains the delivery shape. Sharding, a new storage engine,
WASM plugins and operator/embedding work are deferred until separately justified.
