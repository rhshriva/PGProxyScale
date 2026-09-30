# PGProxyScale

A protocol-aware PostgreSQL gateway. The thesis, the competitive research and the
sequencing plan all live in `docs/`.

**Start here:** [`docs/vision/roadmap.md`](docs/vision/roadmap.md) — what to build, in what order,
and why the Session-State Ledger comes before the policy engine.

## What this is

Three differentiators, in build order:

1. **Session-State Ledger** — transaction pooling that does not break stateful applications, and
   schema migrations that do not require draining the pooler. Today every pooler either forbids
   session state, pins silently, rejects it, or leaks it between clients.
2. **Protocol-enforced policy** — capability-based, deny-by-default SQL policy enforced on the wire
   with the real PostgreSQL grammar, so it cannot be bypassed the way an application-layer allowlist
   can (cf. CVE-2026-85620).
3. **Per-principal fairness and attribution** — quotas, admission control and chargeback-grade cost
   attribution, so one tenant or agent cannot degrade another.

Explicitly *not* the product: raw pooling speed, and sharding-first. See `docs/vision/roadmap.md` §6.

## Project stage

Pre-alpha. Session and transaction relays, the PostgreSQL parser, a bounded Session-State Ledger,
client/backend authentication, cancellation routing, and the connection pool are implemented.
Backend TLS, authenticated operations, SQL policy, tenant scheduling, trusted role/RLS contexts, bounded MCP tools, verified endpoint failover, expiring credentials, cursor snapshots and validated relation caching are also implemented. Production readiness and the full roadmap remain unfinished.

## Layout

```
docs/
  vision/roadmap.md            sequencing plan and phase gates       ← start here
  vision/product-thesis.md     positioning, buyers, non-goals
  adr/                         architecture decision records
  architecture/overview.md     component map, threading, data path
  architecture/                session-state-taxonomy.md = Phase 1 spec
  plans/                       phase-0 plan + measured spike findings
  research/                    the competitive and technical research base
crates/                        Rust workspace (see ADR 0001)
tests/conformance/             wire-protocol conformance harness (run against
                               direct PostgreSQL first - it is the control)
spikes/                        the throwaway experiments behind the ADR revisions
benchmarks/                    reproducible protocol latency smoke harness
tools/                         PostgreSQL version matrix
pgproxy.toml                   example configuration
```

## Decisions so far

| ADR | Decision |
|---|---|
| [0001](docs/adr/0001-language-and-runtime.md) | **Rust**, thread-per-core runtime (confirmed by spike S1); no async runtime, no splice bypass |
| [0002](docs/adr/0002-parser-strategy.md) | `libpg_query` over FFI; three-tier parsing; never parse per `Bind`/`Execute` |
| [0003](docs/adr/0003-session-state-ledger.md) | Explicit per-client session image with a three-class state taxonomy; fail closed on the unclassifiable |
| [0004](docs/adr/0004-licence.md) | Licence — **deliberately deferred** |
| [0005](docs/adr/0005-deliverable-shape.md) | **Standalone binary first**; sidecar/library kept open structurally |

## Status

**M0 reached.** `pgproxy` serves real sessions: it reads the startup packet, routes the client's
database to a configured backend, relays authentication (passthrough — it never needs the password
or the SCRAM verifier), and proxies the session.

All 17 conformance scenarios pass **through** the proxy, not just against direct PostgreSQL:
extended protocol, named and unnamed prepared statements, SQL-level `PREPARE`, `search_path`,
`WITH HOLD` cursors, advisory locks, `LISTEN`/`NOTIFY`, `COPY FROM STDIN`, a 50k-row result set,
and 16 concurrent clients.

```sh
cargo build --workspace
cargo test  --workspace
./target/debug/pgproxy --config pgproxy.toml --check    # validate config only
./tests/conformance/run.sh                              # control run against PostgreSQL 18
PROXY=1 ./tests/conformance/run.sh                      # the same scenarios, through pgproxy
./tests/conformance/scram_interop.sh                    # SCRAM verified against real libpq
```

**Still unfinished:** full state virtualization, comprehensive DDL invalidation
on retained connections, durable notification failover, replica/cache invalidation integration,
OAuth/token exchange, exclusive per-tenant server cost allocation for shared roles, and production acceptance. Optional frontend TLS supports SCRAM channel
binding and CA-verified certificate identity mapping. Without TLS configuration, SSLRequest receives N.

**Transaction pooling** relays both directions using socket readiness, including Flush,
pipelined Sync batches and COPY. A per-client ledger restores confirmed settings and prepared
statements. LISTEN, held cursors, temp tables, session locks and opaque effects conservatively
retain the backend. Connections eligible for reuse undergo `DISCARD ALL`; interrupted exchanges
are discarded. This preserves compatibility but does not achieve zero pinning.

Transaction routes must explicitly select `client_auth = "trust"`, `"md5"`, `"scram-sha256"`, or `"certificate"`.
MD5/SCRAM routes use `auth_users` stored verifiers and reject clients before pool acquisition.
Backend credentials are separate. Session routes support passthrough or terminated authentication;
terminated session mode retains its backend across DISCARD ALL. Certificate routes require
`general.tls.client_ca` and map usernames to canonical SHA256 certificate fingerprints in `auth_users`.
Per-client cancellation keys route to the current backend and revoke before reuse.
Session timeout/message/memory limits are configurable in `[general.session]`.
Global client and login-rate limits apply before starting authentication threads. Idle connections
with EOF or unexpected pending data are discarded. `require_primary = true` checks writable-primary
status before each handoff; it requires terminated authentication. Shutdown waits for active clients
within its configured budget. TLS currently uses an internal loopback bridge; performance gates remain open.

See [the implementation status and remaining work](docs/plans/implementation-status.md) for the
current goal, completed increment, and ordered backlog.

## Open questions

The **licence** is deferred (ADR-0004) and only becomes urgent before external contributions. The
**v1 conformance scope** — which drivers and PostgreSQL majors are launch requirements — is still
open; the harness currently covers psycopg3 × PostgreSQL 18, and the M0 milestone calls for a
second driver.

## Building

Requires Rust 1.91+ and a C toolchain (`libpg_query` is built from source).

```sh
cargo build --workspace
cargo test --workspace
```


## Operations, policy and agent tools

Optional loopback operations endpoints expose authenticated metrics, bounded client diagnostics,
pool status, configuration reload, and planned draining. Reload creates a validated generation;
existing clients retain their original policy and pools. A process-wide physical backend limit
also bounds overlapping generations. See [reload and capacity](docs/testing/reload-and-capacity.md).

Governed routes require verified client identities. SQL capability grants are deny by default;
protected columns are refused, and trusted role/tenant contexts apply to every backend handoff.
Bounded weighted scheduling and principal quotas constrain contention. The immutable principal
selected for `--mcp-stdio --mcp-database <route> --mcp-user <user>` shares these policy rules;
query, explain and schema tools enforce time, row, byte and request limits. Literal-only immutable
results can be cached; eligible ordinary relation projections can use freshly validated repeatable-read snapshots.
Views, RLS, replicas and complex expressions bypass this cache.

Actual server WAL, buffer and optional CPU measurements can be exported by an operator:

```sh
./target/debug/pgproxy --config pgproxy.toml --server-cost-database <route> \
  --server-cost-user <monitor-user> --server-cost-report /private/path/cost.json
```

This requires `pg_stat_statements` and monitoring privileges; actual CPU additionally
requires `pg_stat_kcache`. These are cumulative database/role/PostgreSQL-queryid
measurements, including activity outside the proxy. They are separate from client
usage and do not invent an exclusive tenant share.

Reproducible fixture and driver instructions live in
[governance tests](tests/conformance/governance/README.md),
[verification](tests/conformance/VERIFICATION.md), and the
[implementation status](docs/plans/implementation-status.md).

The additional work and its precise limits are documented in
[remaining-feature integration](docs/plans/remaining-features-implementation.md).
`tests/certification/run.py` collects reproducible evidence, source hashes and unmet external
security/fencing/provider/performance gates; a passing local run does not certify deployment.
