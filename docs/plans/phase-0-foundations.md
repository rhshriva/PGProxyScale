# Phase 0 — Foundations and the Correctness Spine

> Phase plan derived from [`../vision/roadmap.md`](../vision/roadmap.md) §3.
> **Objective:** a proxy that is *correct* across the full driver matrix and *competitive* on
> latency, with the measurement harness already in place so that no later phase is self-assessed.

This phase ships **no differentiator**. Everything in it is a prerequisite, and the two spikes at
the front of it exist to kill the project early if its core assumptions are wrong.

---

## Exit gates (all must pass before Phase 1 starts)

| # | Gate | How it is measured |
|---|---|---|
| G1 | Zero conformance failures | Driver × PostgreSQL version matrix, all green in CI |
| G2 | Low-concurrency latency parity | p50 overhead ≤ PgBouncer at 4 clients, same host, same config |
| G3 | Scale win | ≥ 2× PgBouncer TPS at ≥ 64 clients |
| G4 | Parser is not on the hot path | Parsing accounts for < 2% CPU on a simple-protocol pgbench run |
| G5 | No memory-safety class bugs in the codec | `cargo-fuzz` on the codec and parser FFI runs clean for a sustained soak |
| G6 | Benchmark suite is reproducible | A third party can reproduce G2/G3 from the repo on a documented box |

---

## W0 — Spikes (run first, timeboxed, in parallel)

These are the risk-retirement tasks. **Do not write production code until S1–S3 have answers.**
Their outcomes are recorded as ADR amendments, not as tribal knowledge.

### S1 — Can Rust match libevent at low concurrency? (decision: runtime)

libevent beats Tokio at 1–10 connections (16.7k vs 15.5k TPS at 1 client), and PgDog plateaus from
c16 to c64. This is the single most likely way for the product to fail its own performance claim.

- Build a **throwaway** echo proxy (no pooling, no parsing) with two runtimes: `monoio` (io_uring)
  and Tokio, each with per-core `SO_REUSEPORT` listeners.
- Benchmark against PgBouncer and against direct Postgres at c1/c4/c16/c64, `pgbench -S`.
- Then add a **bypass/splice path** (hand off the socket after assignment) and re-measure.
- **Decision rule:** if we cannot get within 10% of PgBouncer at 4 clients, adopt the hybrid
  fallback (per-core blocking reactor for the fast path) rather than abandoning Rust.
- **Deliverable:** results table appended to this plan, and an amendment to ADR-0001's runtime section.

### S2 — Session-state taxonomy (de-risks ADR-0003, the central decision)

The ledger is only safe if we know exactly what can and cannot be virtualised.

- Enumerate the session-state surface from the PostgreSQL source (`guc_tables.c`, `guc.c`,
  `postinit.c`, `xact.c`) for PG 14–18.
- Classify every item as **A (virtualisable)**, **B (emulatable)** or **C (must refuse or pin)** per
  ADR-0003.
- Specifically resolve: `search_path`, `SET ROLE` vs `SET SESSION AUTHORIZATION`, `client_encoding`,
  `DateStyle`/`IntervalStyle`/`TimeZone` (server-reported vs not), custom/extension GUCs, RLS
  interaction, `application_name`, and anything set by `options=` in the startup packet.
- **Deliverable:** a table in `docs/architecture/session-state-taxonomy.md` with a row per state class
  and its handling. This table *is* the Phase 1 specification.

### S3 — Parser viability (de-risks ADR-0002)

- Build `libpg_query` on macOS and Linux; measure cold and warm parse throughput for representative
  statements (simple SELECT, 20-column INSERT, CTE, PL/pgSQL `DO` block, 8 KB query).
- Measure fingerprint stability **across PG 14–18** — expect breaks; determine what the version tag
  must cover.
- Fuzz the FFI boundary (`cargo-fuzz`) for a soak period; confirm no panics or UB.
- Measure the T0/T1 fast path: what fraction of a real pgbench run can avoid an AST entirely?
- **Deliverable:** numbers appended here; go/no-go on the three-tier design.

---

## W1 — Workspace and runtime foundation

- [ ] Config loading (TOML), layered defaults → file → env → flags; validation with good errors
- [ ] Structured logging and `tracing` setup; log levels per subsystem
- [ ] Error taxonomy in `pgproxy-core` (`thiserror`), with a rule that no `unwrap`/`expect` on a
      protocol path is permitted
- [ ] Thread-per-core runtime per S1's outcome; per-core state container
- [ ] `SO_REUSEPORT` listener and accept loop; graceful shutdown that does not drop in-flight work
- [ ] CI: `fmt`, `clippy -D warnings`, `test`, fuzz smoke, driver conformance

## W2 — Wire protocol (`pgproxy-wire`)

- [x] Streaming message codec for all v3 messages, with borrowed views over a reused buffer.
      Deliberately *not* zero-copy: spike S1 measured a zero-copy `splice(2)` path as
      statistically identical to userspace copying, so the simpler design wins.
- [x] Length discipline pinned by golden vectors: the length field includes its own four
      bytes and excludes the tag; lengths below 4 and above the cap are rejected *before*
      allocating, so an untrusted client cannot request memory.
- [x] Startup: `StartupMessage`, `SSLRequest`, `GSSENCRequest`, 3.0 and 3.2 version
      decoding, `_pq_.` protocol grease detected and rejected clearly, `options=` GUCs
      parsed out rather than dropped. Validated against bytes captured from real psycopg3.
- [~] Auth primitives: SCRAM-SHA-256 in **both directions** (RFC 7677 vectors pinned as
      known-answer tests) and MD5, plus the whole `Authentication*` message set. Verified
      against a real driver, not just against itself: `examples/scram_probe` +
      `tests/conformance/scram_interop.sh` connect psycopg to our server and assert the
      right password is accepted and the wrong one is rejected with no information leak.
      **Not implemented:** cert auth, and channel binding (`SCRAM-SHA-256-PLUS`) — a client
      demanding channel binding is refused rather than silently downgraded, because
      downgrading removes the protection it asked for.
- [ ] Auth **wiring**: the state machine choosing terminate vs passthrough per database.
      Both directions of the crypto exist; which one runs is a connection-lifecycle
      decision. Passthrough needs no secret and is the answer to PgBouncer's documented
      managed-cloud weakness; terminate is needed for the policy engine to reject a client
      before touching a backend.
- [ ] Extended-protocol state machine: `Parse`/`Bind`/`Describe`/`Execute`/`Sync`/`Flush`/`Close`,
      **including unnamed statements** and their documented death on the next `Parse` *or any simple
      `Query`*
- [ ] Completion counted by `ReadyForQuery`, never `CommandComplete`; error → skip to `Sync`
- [ ] Pipelining within `Sync`-delimited batches
- [ ] Simple query protocol; `COPY` framing passthrough without buffering
- [~] `CancelRequest` **parsing** done, including the variable-length key protocol 3.2
      introduced (4 bytes in 3.0, up to 32 in 3.2). *Routing* still needs ADR-0007.
- [ ] TLS via `rustls`; server-side TLS
- [ ] Admin pseudo-database surface

## W3 — Parser (`pgproxy-parser`)

- [ ] `libpg_query` build integration (vendored, `build.rs`), pinned per PG major
- [ ] Safe, lifetime-bound AST views over the C tree — no owned tree unless required
- [ ] Fingerprint generation with an explicit **version tag**
- [ ] Sharded, bounded LRU parse cache keyed on raw SQL hash
- [ ] T0/T1/T2 classifier with tests proving T0 never needs an AST
- [ ] Fuzz targets for the FFI boundary

## W4 — Pool (`pgproxy-pool`)

- [ ] Backend connection lifecycle, checkout/checkin, LIFO reuse
- [ ] Timeouts: `server_idle`, `query`, `client_idle`, `query_wait`
- [ ] Transaction-pooling semantics with correct handling of implicit transactions
- [ ] Per-core pools **plus** globally coordinated admission control (so we do not reproduce
      PgBouncer's `so_reuseport` weakness where pool limits are not shared between processes)
- [ ] Health checks; fail fast when no backend is reachable, instead of silent queueing
- [ ] Connection-storm protection (serverless/Lambda burst, restart login flood)
- [ ] Never hand out a connection to a demoted primary

## W5 — Test and measurement

- [ ] `tools/docker-compose.yml` version matrix (done)
- [ ] Driver conformance harness: psycopg3, asyncpg, pgjdbc, node-postgres, pgx, npgsql, Rails
- [ ] Hard-case benchmark suite — the thing nobody has published:
      prepared statements, DDL during traffic, mixed OLTP+analytics, agent-style N+1, `LISTEN` under
      load, advisory-lock contention, failover drill
- [ ] Fault injection: backend kill, proxy restart, mid-transaction disconnect
- [ ] A test that deliberately attempts to observe another client's session state (must fail)

## W6 — Observability baseline

- [ ] Prometheus metrics, HDR histograms (p50/p90/p99)
- [ ] OpenTelemetry traces, with trace context carried in a **proxy-side index keyed by
      `(connection, Bind)`** — never injected as SQL comments, which pollute plan caches
- [ ] Per-client introspection: principal, session-image digest, pin/ownership reason, queue time,
      parse tier in use
- [ ] Health and readiness endpoints

---

## Explicitly NOT in Phase 0

Policy engine, MCP/agent surface, caching, read-your-writes, automatic failover, sharding, WASM
plugins, any cloud-specific auth adapter. See roadmap §6.

---

## Definition of done

Phase 0 is done when a person who has never seen the repository can clone it, bring up the version
matrix with one command, run the conformance suite and the benchmark suite, and reproduce gates
G1–G6 — and when spikes S1–S3 have produced written answers rather than opinions.
