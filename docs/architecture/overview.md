# Architecture Overview

> Phase 0 target architecture. Anything marked *(later)* is not built yet.

## 1. Component map

```
                         client drivers
        psycopg3 · asyncpg · pgjdbc · node-postgres · pgx · npgsql · Rails
                                │
                                │  PostgreSQL wire protocol v3 / 3.2
                                ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                              pgproxy (single binary)                      │
│                                                                           │
│  ┌────────────────────────── per-core worker ──────────────────────────┐   │
│  │  pgproxy-wire      protocol codec + connection state machine       │   │
│  │        │                                                           │   │
│  │        ├─► pgproxy-parser   T0/T1/T2 classification, fingerprints  │   │
│  │        │                                                           │   │
│  │        ├─► pgproxy-session  Session-State Ledger (ADR 0003)        │   │
│  │        │        · session image · statement registry · DDL stream  │   │
│  │        │        · advisory-lock leases · LISTEN fan-out            │   │
│  │        │                                                           │   │
│  │        ├─► pgproxy-policy   (later) capability + AST enforcement   │   │
│  │        │                                                           │   │
│  │        └─► pgproxy-pool     per-core pools, fairness, admission    │   │
│  └────────────────────────────────────────────────────────────────────┘   │
│                                                                           │
│  pgproxy-admin     admin SQL surface, metrics, health   (control plane)   │
│  pgproxy-core      config, runtime bootstrap, TLS, auth (control plane)   │
│  pgproxy-cli       the `pgproxy` binary                                   │
└───────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                     PostgreSQL 14 · 15 · 16 · 17 · 18
```

## 2. Threading and state ownership

Thread-per-core (ADR 0001). The consequences are load-bearing and must be designed in from the first commit, not retrofitted:

- Each core owns its listener (via `SO_REUSEPORT`), its accept loop, its slice of pooled backend connections, and its parse/fingerprint caches. **No cross-core locking on the hot path.**
- Client connections are pinned to a core for their lifetime. Backend connections belong to the core that created them.
- Cross-core coordination is confined to the control plane: metrics aggregation, config reload, and the admin surface. It uses channels and snapshots, never shared mutable hot state.
- Consequence to accept consciously: **pool limits are per-core**, and aggregate limits must be enforced globally by coordination. This is the exact weakness of PgBouncer's `so_reuseport` workaround (pool limits are not shared across processes) — we must not reproduce it. A global admission decision made on the control plane, with per-core enforcement, is the design.

## 3. Data path, in order of preference

1. **Passthrough** — relay bytes with `TCP_NODELAY` on both sockets, no SQL inspection. This is the
   default fast path and, per spike S1, it is as fast as anything more exotic: a zero-copy
   `splice(2)` bypass measured **statistically identical** to plain userspace `io::copy`
   (217,867 vs 215,827 TPS at c=64). **The bottleneck is not byte copying**, so the data path stays
   simple and auditable. Do not build a splice path in Phase 0.
2. **Framed inspection** — parse message headers, not SQL. Correct for `COPY` and large result sets.
3. **Classified (T1)** — statement class for routing.
4. **Full (T2)** — parse and enforce. Only when the ledger or policy requires it.

Nothing forces us into tier 4 by default. A pooler that parses every statement is a pooler that loses
the benchmark: S3 measured a full parse at 2.5 µs for a small statement and 333 µs for an 8 KB one,
versus 18 ns to hash the same text.

`io_uring` and fd-passing remain *later, measured* optimisations, not Phase 0 requirements.

## 4. Crate responsibilities

| Crate | Owns | Depends on |
|---|---|---|
| `pgproxy-wire` | Protocol codec, message framing, connection state machine, auth, TLS, cancel routing | `pgproxy-parser` (weak) |
| `pgproxy-parser` | `libpg_query` FFI, AST views, fingerprints, sharded parse cache, T0/T1/T2 classification | — |
| `pgproxy-session` | Session image, statement registry, DDL event stream, advisory-lock leases, `LISTEN` fan-out | wire, parser |
| `pgproxy-pool` | Backend pools, checkout/checkin, health checks, fairness, admission control | session |
| `pgproxy-policy` *(later)* | Principal model, capability model, AST policy, masking, audit | parser, session |
| `pgproxy-admin` | Admin SQL surface, Prometheus/OTel, health, introspection of ledger state | all |
| `pgproxy-core` | Config, runtime bootstrap, supervision, TLS, shutdown | all |
| `pgproxy-cli` | The binary | core |

Dependency direction is strictly downward. `pgproxy-wire` and `pgproxy-parser` are the only crates permitted `unsafe` (ADR 0001).

## 5. What the ledger means for the pool

The pool does not hand out "a connection". It hands out **a backend that has been reconciled to a client's session image**, and takes it back with a known delta. That inverts the usual ownership model and is why `pgproxy-pool` depends on `pgproxy-session` rather than the other way round.

Checkout becomes: acquire backend → diff image → batched restore → serve.
Checkin becomes: apply reset policy → record delta → mark clean or owned.

## 6. Observability as a first-class subsystem

The research is unambiguous: `SHOW POOLS`-style text consoles are the reason operators cannot diagnose pinning. Therefore introspection is designed in, not bolted on:

- Every client exposes: principal, session-image digest, pinned/owned state and why, queued time, parse tier in use.
- Metrics are Prometheus-native with HDR histograms (p50/p90/p99) and OpenTelemetry traces.
- Trace context is carried in a **proxy-side index keyed by `(connection, Bind)`**, never injected as SQL comments — comments change the query string and pollute plan caches.

## 7. Non-goals for Phase 0

Policy engine, agent/MCP surface, caching, read-your-writes, failover automation, sharding, WASM plugins. See `docs/vision/roadmap.md` §6.
