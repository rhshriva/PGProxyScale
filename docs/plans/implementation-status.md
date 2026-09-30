# Implementation status and remaining work

Audit date: 2026-09-30 (local). This document describes the working tree and verified behavior.
The product remains pre-alpha; implementation of a mechanism is not completion of its
production acceptance gate.

## Final product goal

A PostgreSQL gateway that preserves application session semantics under transaction pooling,
adds authenticated SQL governance and tenant fairness, and exposes bounded agent access.
The roadmap also requires reliable failover, correctly invalidated caching and production
compatibility/performance evidence. See [the roadmap](../vision/roadmap.md) and [ADR index](../adr/README.md).
ADRs 0006 and 0007 are proposed choices, not accepted decisions.

## Implemented behavior

| Area | Working behavior | Limits still open |
|---|---|---|
| Transport | Expiring credential adapters; client MD5/SCRAM/certificate authentication; frontend TLS/channel binding; verified backend TLS, separate credentials, bound SCRAM and encrypted cancellation; protocol 3.x downgrade/extension negotiation and graceful GSS fallback | Native protocol 3.2 extensions and wider certificate/driver compatibility need more evidence |
| Pools | Idle connection probes, primary-role checks, bounded admission/timeouts, reusable connections, cancellation ownership, shutdown budgets and a process-wide physical backend cap across reload generations | Per-core backend pools, background health monitoring and fault soak |
| Parser | Vendored libpg_query 18, bounded FFI/cache/input/tree memory, version-tagged fingerprints and parser-setting context | One grammar rather than separately validated grammars for each major; fast-path and sanitizer campaigns remain gates |
| Ledger | Confirmed settings and wire/SQL prepares; rollback/savepoints; startup defaults through RESET/RESET ALL/DISCARD; parser settings; preparation context; persistent role replay and opt-in held cursor snapshots with bounded extended-protocol delivery; conservative resource ownership | Full temp/cursor/lock/notification virtualization, comprehensive retained-plan DDL invalidation and durable notification fault semantics |
| Operations | Authenticated loopback metrics/client/pool endpoints, health/readiness, bounded diagnostics, tracing, exchange latency histogram/percentiles, atomic config/TLS reload and planned drain/commit/abort | Full admin console and longer operational/fault soak |
| Policy | Immutable configured identities, deny-default parsed SQL capabilities, table/function grants, protected-column denial, audit decisions, trusted role/tenant/read-only/timeouts on handoff | Data masking transformations, OAuth/provider production validation and independent adversarial/security review |
| Fairness | Principal quotas, bounded weighted queues, concurrency caps, adaptive feedback and idle-transaction containment | Exclusive per-tenant CPU/buffer/WAL allocation, chargeback reconciliation and production noisy-neighbor latency guarantees; separate cumulative server counters are implemented |
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

The latest recorded source hash is
`dec7d96fe787023540efc4f5b4e01d116ee4fdf4a8d47b3bd9a92f2a8dfa0a77`;
it matches the implementation source at this audit. The recorded local run passed
**339 workspace unit/integration tests**, strict Clippy, an optimized release build,
13 Python certification evidence contracts and source stability. Its report records
Linux and replicated failover as **not-run**, and production certification as **false**.
See [the current evidence summary](../../deliverables/verification-next/README.md)
and [machine-readable report](../../deliverables/verification-next/report.json).
The report was collected from a working tree based on `7cf9f22`; the included harness
changes were subsequently committed as `b71640b`. Source hashes, not test counts or
report timestamps alone, bind evidence to the implementation.

After the current evidence report, the CI harness fix was also exercised locally:
17/17 SCRAM session conformance scenarios, wrong-password rejection and both
standalone SCRAM interop cases passed. These checks are narrower than a complete
Linux/version/TLS matrix and are not included as gates in that report.

Native PostgreSQL 14–18 compatibility, asyncpg, backend TLS and Linux verification are driven by
`tests/conformance/native-matrix.sh`, `tests/conformance/backend-tls/run.sh` and CI workflows.
Codec/parser fuzz targets and benchmark comparison guards are durable. Uninstrumented mutations
and container benchmarks do not certify sanitizer coverage or bare-metal performance gates.

## Remaining acceptance work

1. Complete ledger virtualization and comprehensive DDL invalidation with resource/fault tests.
   The remaining temp/lock/notification scope and its server-side dependency are described in the proposed
   [ADR-0006](../adr/0006-session-state-virtualization-boundary.md).
2. Integrate external identity lifecycle, actual masking and independently reviewed policy security.
3. Integrate live replica consistency/invalidation, controlled automatic failover and durable retry
   design; notification exactly-once claims require an acknowledgement/durability design.
4. Add the remaining drivers/extensions, instrumented long fuzz campaigns, fault soak and measured
   Linux bare-metal throughput/latency/noisy-neighbor gates.
5. Complete per-core backend pools, exclusive tenant cost allocation and production cost reconciliation before claiming the full roadmap.
   Exclusive per-tenant allocation from shared-role counters is described in the proposed
   [ADR-0007](../adr/0007-shared-role-tenant-cost-attribution.md).

The technical sales PPTX/PDF in `deliverables/` reflects the earlier prototype snapshot; refresh
its feature/status slides before using it to represent these new implementation results.


For reproduction and exact semantics, see [credentials and usage](../testing/credentials-and-usage.md),
[ledger verification](../testing/ledger-semantics.md), and the
[certification runner](../../tests/certification/README.md).
