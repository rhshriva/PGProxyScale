# Architecture overview

Current implementation: 2026-09-30. This page describes the code, while
[the roadmap](../vision/roadmap.md) describes acceptance targets. See
[implementation status](../plans/implementation-status.md) for verification evidence.

## Component map

```text
PostgreSQL wire clients                    MCP stdio client
           |                                    |
           v                                    v
   pgproxy-core Runtime                 pgproxy-core MCP executor
   per-worker SO_REUSEPORT                       |
   listener + connection threads                |
           |                                    |
           v                                    |
   pgproxy-wire service <----- shared policy/context/budgets
   framing, authentication,                     |
   frontend/backend TLS, cancellation           |
           |                                    |
           +--> pgproxy-parser: PG18 grammar, bounded cache, fingerprints
           +--> pgproxy-session: confirmed state, prepares, cursor snapshots
           +--> pgproxy-policy: SQL grants, admission, fairness, cache rules
           +--> pgproxy-pool: reusable connections, waits, physical socket cap
           |                                    |
           +------------------+-----------------+
                              v
                    PostgreSQL 14–18

Control plane: validated config/service generations, credential adapters,
loopback operations HTTP, diagnostics, tracing and server-cost exports.
Packaging: one pgproxy binary from pgproxy-cli.
```

## Threading and ownership

The runtime creates worker listeners using `SO_REUSEPORT` and runs each accepted
client connection on its own OS thread. Transaction relay advances frontend and
backend frames using socket readiness. This is a blocking connection-thread
implementation, not a monoio/io_uring executor.

Routing services and backend pools are shared within a service generation. Pool
state uses a mutex and condition variable; admission, parser caches, scheduling
and diagnostics also have shared synchronization. Fully per-core backend pool
ownership and a lock-free hot path remain goals, not current properties.

A process-wide permit bounds authenticated physical data sockets across session
mode, transaction pools and reload generations, including idle pooled sockets.
Cancellation/control sockets are additional transient connections. Reload stages a
new validated service; existing sessions retain their generation until disconnect.
See [reload and capacity semantics](../testing/reload-and-capacity.md).

## Protocol and session state

Session mode can relay backend authentication and keep a native backend for the
client's lifetime. Transaction mode terminates client authentication and obtains
separately authenticated backend connections. TLS, certificate authentication,
SCRAM channel binding and cancellation routing are implemented with documented
configuration requirements. Startup negotiation supports downgrade/fallback;
full native protocol 3.2 extension support is not claimed.

The ledger records confirmed successful changes and transaction/savepoint state.
Settings, roles and wire/SQL prepared statements are restored with preparation
context. A backend is released only at a safe idle protocol boundary with no
outstanding completion or resource ownership. Error, cancellation and uncertain
session effects can retain ownership or discard a connection.

Opt-in bounded held-cursor snapshots support a restricted set of types and simple
and extended access. Extended access inside explicit transactions and mixed
physical/virtual cycles remain restricted. Temporary relations, session advisory
locks, LISTEN subscriptions and opaque effects retain native affinity. There is
no listener fan-out, lock-lease migration or durable notification service.
See [ledger semantics](../testing/ledger-semantics.md) and
[remaining virtualization](remaining-state-virtualization.md).

## Parsing, governance and caches

The parser wraps vendored libpg_query 18 through audited FFI, exposes JSON-derived
AST data and versioned fingerprints, and bounds input, tree and cache memory.
The implementation has one grammar; the compatibility matrix does not establish
separate per-major grammar selection. Governed SQL uses full parsing and a
conservative deny-by-default policy. Reviewed database roles, RLS, functions and
objects remain part of the security boundary. Protected columns are denied;
result masking and OAuth/token exchange are not implemented.

Wire and MCP clients share configured principal identities, policy, trusted
context and budgets. Fairness uses bounded weighted queues and concurrency
limits. MCP stdio tools execute on fresh read-only backends with a shared deadline.
Literal caching admits immutable relation-free SQL. Restricted relation caching
requires fresh snapshot validation; it is not a logical-decoding invalidation feed.
See [operations and governance](../testing/operations-and-governance.md).

## Crate responsibilities and dependencies

Direct internal dependencies below reflect the Cargo manifests.

| Crate | Current responsibility | Direct internal dependencies |
|---|---|---|
| `pgproxy-parser` | libpg_query FFI, AST data, fingerprints, bounded parse cache | — |
| `pgproxy-session` | Session image, prepared registry, rollback, cursor snapshots/portals | parser |
| `pgproxy-pool` | Generic reusable pools and shared physical admission cap | — |
| `pgproxy-policy` | SQL capabilities, context, scheduling, MCP contracts and cache eligibility | parser, session |
| `pgproxy-admin` | HTTP operations, metrics, diagnostics and usage ledger | pool, session |
| `pgproxy-wire` | Protocol, auth/TLS, session relay/replay, failover, credentials and usage | policy, admin, parser, pool, session |
| `pgproxy-core` | Config, runtime, router, reload, credential/MCP execution and server-cost export | parser, policy, admin, pool, wire |
| `pgproxy-cli` | Binary arguments and private report publication | policy, core, wire |

## Operations and measurement

The loopback HTTP surface exposes health/readiness and authenticated metrics,
clients, pools, usage, reload and planned-drain controls. It is not an admin SQL
pseudo-database. Latency uses bounded histogram buckets with approximate
percentiles, not HDR per-statement server timings. Structured tracing is
implemented; a complete OpenTelemetry context/export integration remains a goal.

Per-principal wire usage measures delivered rows/bytes, elapsed exchanges and
errors. Separate server-cost exports collect cumulative database/role/queryid
WAL and buffer counters from pg_stat_statements and optional execution CPU from
pg_stat_kcache. They do not establish exclusive tenant allocation for shared roles.
See [credentials and usage](../testing/credentials-and-usage.md).

Endpoint acquisition can fail over to a verified writable candidate before user
SQL. PostgreSQL promotion and authoritative infrastructure fencing remain external.
Uncertain writes are not automatically replayed. Local smoke benchmarks and fault
fixtures do not satisfy independent security, real-provider, production fencing
or bare-metal performance/soak certification gates.
