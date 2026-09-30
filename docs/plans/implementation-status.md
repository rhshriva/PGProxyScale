# Implementation status and remaining work

Audit date: 2026-09-29 (local). This document describes the working tree and verified behavior.
The product remains pre-alpha; implementation of a mechanism is not completion of its
production acceptance gate.

## Final product goal

A PostgreSQL gateway that preserves application session semantics under transaction pooling,
adds authenticated SQL governance and tenant fairness, and exposes bounded agent access.
The roadmap also requires reliable failover, correctly invalidated caching and production
compatibility/performance evidence. See `docs/vision/roadmap.md` and ADRs 0001–0005.

## Implemented behavior

| Area | Working behavior | Limits still open |
|---|---|---|
| Transport | Expiring credential adapters; client MD5/SCRAM/certificate authentication; frontend TLS/channel binding; verified backend TLS, separate credentials, bound SCRAM and encrypted cancellation; protocol 3.x downgrade/extension negotiation and graceful GSS fallback | Native protocol 3.2 extensions and wider certificate/driver compatibility need more evidence |
| Pools | Idle connection probes, primary-role checks, bounded admission/timeouts, reusable connections, cancellation ownership, shutdown budgets and a process-wide physical backend cap across reload generations | Per-core backend pools, background health monitoring and fault soak |
| Parser | Vendored libpg_query 18, bounded FFI/cache/input/tree memory, version-tagged fingerprints and parser-setting context | One grammar rather than separately validated grammars for each major; fast-path and sanitizer campaigns remain gates |
| Ledger | Confirmed settings and wire/SQL prepares; rollback/savepoints; startup defaults through RESET/RESET ALL/DISCARD; parser settings; preparation context; persistent role replay and opt-in held cursor snapshots; conservative resource ownership | Full temp/cursor/lock/notification virtualization, comprehensive retained-plan DDL invalidation and durable notification fault semantics |
| Operations | Authenticated loopback metrics/client/pool endpoints, health/readiness, bounded diagnostics, tracing, exchange latency histogram/percentiles, atomic config/TLS reload and planned drain/commit/abort | Full admin console and longer operational/fault soak |
| Policy | Immutable configured identities, deny-default parsed SQL capabilities, table/function grants, protected-column denial, audit decisions, trusted role/tenant/read-only/timeouts on handoff | Data masking transformations, OAuth/provider production validation and independent adversarial/security review |
| Fairness | Principal quotas, bounded weighted queues, concurrency caps, adaptive feedback and idle-transaction containment | Server CPU/buffer/WAL attribution, chargeback reconciliation and production noisy-neighbor latency guarantees |
| Agent access | Stdio MCP query/explain/schema with immutable principal, shared policy/context, request/query/row/byte/time limits and read-only fresh backends | Remote identity adapters and broader adversarial review |
| Resilience/cache | Validated generations, planned draining, cancellation continuity, verified endpoint failover before user SQL, lease/epoch retirement, immutable literals and snapshot-validated relation caching | Infrastructure promotion/fencing, replica routing, live consistency feed, dependency-specific invalidation and durable retry semantics |

Protected columns are refused, not transformed. Unknown SQL/functions and session effects are
conservatively denied or retain physical ownership. Compatibility through retention does not
prove zero pinning. Approved custom functions, views, triggers and database roles are trusted
server-side objects requiring operator review.

A reload applies new credentials/policy/routes to new sessions. Existing sessions retain their
validated generation until they finish. Planned switchover pauses new logins, permits cancellation
and commits only after draining; promotion of a PostgreSQL primary remains an operator action.
The shared backend cap includes idle authenticated data connections; cancellation/control sockets
are transient additional connections. It cannot be resized by a live reload.

The literal result cache admits only proven immutable, relation-free SQL and keys by exact SQL
and full principal identity. Hits still consume authorization/query budgets. Ordinary relation projections can use the separate fresh-snapshot validation cache described
in the governance test README. Views/RLS/replicas/complex expressions bypass that cache; a
dependency-specific asynchronous cache stays disabled without an invalidation feed. No automatic replay of uncertain writes occurs.

## Verification evidence

The final macOS and Linux suites each passed **290 unit/integration tests**, strict Clippy
and builds. PostgreSQL 14–18 passed **260 compatibility scenarios** and **40 backend TLS
checks**, with a further **8 RSA-PSS PostgreSQL 18 checks**. Reproduction is documented in
`tests/conformance/VERIFICATION.md`. Durable system drivers also verify:

- Ledger **5/5**: startup defaults, command statuses, preparation context and rollback/ownership.
- Reload **4/4**: actual certificate rotation, existing-session continuity, cancellation, atomic
  rejection, quiesce/drain/commit/abort. Shared physical-cap checks **2/2** span modes/generations.
- Wire policy **9/9** and MCP **16/16** including actual timeout and row/byte ceilings.
- RLS/fairness **4/4**, including 20 alternating prepared handoffs, immutable tenant identity,
  excess quota refusal and idle-transaction containment. The isolated victim query completed in
  0.9 ms during a noisy 400 ms query; this is one functional sample, not a p99 guarantee.
- MCP RLS **8/8**: both tenants, protected columns, filtered schema and trusted timeout.
- Protocol startup **3/3**: downgrade/unknown extension negotiation, GSS refusal followed by
  successful startup and rejection of an unsupported major version.
- Operations acceptance: bearer auth, health/readiness, active transaction and byte diagnostics,
  latency metrics and pool diagnostics without credentials.
- Prior area acceptance **8/8** and frontend security **5/5**, with reproducible fresh certificate
  fixtures. Tests cover size-one prepared/state handoff, cancellation/recovery, DDL handoff,
  backend termination/reconnection and read-only-primary refusal.

Native PostgreSQL 14–18 compatibility, asyncpg, backend TLS and Linux verification are driven by
`tests/conformance/native-matrix.sh`, `tests/conformance/backend-tls/run.sh` and CI workflows.
Codec/parser fuzz targets and benchmark comparison guards are durable. Uninstrumented mutations
and container benchmarks do not certify sanitizer coverage or bare-metal performance gates.

## Remaining acceptance work

1. Complete ledger virtualization and comprehensive DDL invalidation with resource/fault tests.
   The remaining temp/lock/notification scope and its server-side dependency are decided in
   [ADR-0006](../adr/0006-session-state-virtualization-boundary.md).
2. Integrate external identity lifecycle, actual masking and independently reviewed policy security.
3. Integrate live replica consistency/invalidation, controlled automatic failover and durable retry
   design; notification exactly-once claims require an acknowledgement/durability design.
4. Add the remaining drivers/extensions, instrumented long fuzz campaigns, fault soak and measured
   Linux bare-metal throughput/latency/noisy-neighbor gates.
5. Complete per-core backend pools and production cost attribution before claiming the full roadmap.
   Exclusive per-tenant allocation from shared-role counters is decided in
   [ADR-0007](../adr/0007-shared-role-tenant-cost-attribution.md).

The technical sales PPTX/PDF in `deliverables/` reflects the earlier prototype snapshot; refresh
its feature/status slides before using it to represent these new implementation results.


## Additional parallel implementation

The subsequent round implemented role/held-cursor virtualization, acquisition failover, snapshot
relation caching, expiring credential adapters and measured principal usage. A release evidence
runner records local automated gates and explicit external certification requirements. See
[remaining-feature integration](remaining-features-implementation.md),
[credential and usage semantics](../testing/credentials-and-usage.md), and
`tests/certification/README.md`. Previous verification counts above identify the earlier snapshot;
current tree results are recorded separately in the verification document.
