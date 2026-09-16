# ADR 0002 — SQL Parsing Strategy

- **Status:** Accepted
- **Date:** 2026-09-16
- **Depends on:** ADR 0001

---

## Decision

Use **`libpg_query`** (the real PostgreSQL parser, vendored and linked over FFI) for anything that requires understanding SQL — and **avoid parsing entirely** on the hot path wherever the decision can be made from protocol state or a cheap keyword classification.

Three tiers, chosen per statement, not per connection:

| Tier | Cost | Used for | Mechanism |
|---|---|---|---|
| **T0 — no parse** | ~0 | Pure transaction control and protocol plumbing | Protocol state machine only. `ReadyForQuery` status byte tells us transaction state; `BEGIN`/`COMMIT`/`ROLLBACK` are recognised by a first-keyword check, not an AST. |
| **T1 — classify** | very low | Read/write routing, pinning-risk detection | Bounded prefix scan → statement class. No AST. |
| **T2 — full parse** | real | Policy enforcement, fingerprinting, statement keying, DDL detection | `libpg_query` → normalised AST → fingerprint. |

**Hard rules**
- Never parse per `Bind`/`Execute`. Parse once per unique statement text.
- Every parse is keyed on a hash of the raw SQL text and cached in a sharded, bounded LRU.
- Any statement that will reach the policy engine is parsed at T2, always. A policy decision made on a heuristic is a bypass waiting to be found (CVE-2026-85620 was exactly a classification gap).

---

## Why `libpg_query` rather than a pure-Rust parser

A pure-Rust SQL parser is not equivalent to PostgreSQL's. `sqlparser-rs` (and the `datafusion-sqlparser-rs` fork) lacks PostgreSQL-specific operators and grammar; PgCat has an open issue to migrate away from it precisely because of correctness gaps. Since our policy engine's entire credibility rests on understanding SQL the way PostgreSQL understands it — including `FROM`-clause functions, CTEs, `DO` blocks, `DISTINCT ON`, `RETURNING`, operator classes, `::` casts, and PL/pgSQL bodies — an approximate parser is not an option.

`libpg_query` vendors the actual server parser and exposes parse, scan, fingerprint and PL/pgSQL parsing. It is the same library that powers pganalyze and `pg_query_go`/`pg_query.rs`/`pglast`. Critically, **PgDog already runs a Rust FFI binding to it in production** (`pg_raw_parse`), so this is a proven path, not a research bet.

### The cost is real and was measured

PgDog profiled its parser and found that converting the AST across a protobuf boundary dominated everything else. Replacing it with direct C→Rust FFI took:

- parse throughput **613 → 3,357 queries/s**
- deparse throughput **759 → 7,319 queries/s**
- and yielded **+25% on pgbench**

**Corrected by spike S3** — see [`../plans/spike-findings.md`](../plans/spike-findings.md). The
paragraph that used to sit here assumed protobuf was the faster intermediate serialisation. It is not.
Measured with libpg_query commit `7632d03` (PG 18 grammar), release + LTO, in a Linux container:

| API | `pk_select` (41 B) | `oltp_update` (89 B) | `wide_8kb` (6,225 B) |
|---|---|---|---|
| `pg_query_parse` (JSON) | 2,194 ns | 3,089 ns | 311,030 ns |
| `pg_query_parse_protobuf` | 8,631 ns | 11,636 ns | 1,415,299 ns |

**Protobuf is 2–5× slower than JSON, not faster.** Verified in the source rather than taken on faith:
both paths call `pg_query_raw_parse` and differ only in the serialiser — `pg_query_nodes_to_json` is a
hand-written writer, while `pg_query_nodes_to_protobuf` goes through protobuf-c, and protobuf-c loses
badly. The correct reading of PgDog's "replacing protobuf with Rust to go 5× faster" is that they
stopped serialising **at all**, not that they changed format.

**Consequence for us:** bind the **JSON** API for Phase 0 — it is the best available public API — and
do not use protobuf. But treat this as a waypoint, not the destination: **both public APIs materialise
a serialised copy of the tree**, and the fast path is walking the raw C `RawStmt`/`Node` tree in place.
That tree is deliberately absent from `pg_query.h`, which is exactly why PgDog wrote a separate
`pg_raw_parse` crate to reach it. A raw-tree accessor is therefore a *measured optimisation on the
roadmap*, not a prerequisite.

### Parsing must be cached, because a parse is not cheap

| statement | bytes | T0 hash | T2 parse | parse ÷ hash |
|---|---|---|---|---|
| `pk_select` | 41 | 18 ns | 2,533 ns | **142×** |
| `wide_8kb` | 6,225 | 6,123 ns | 333,044 ns | **54×** |

At 50k queries/s, parsing every small statement costs roughly 11% of a core, and a single 8 KB
statement costs 333 µs. "Parse once per unique statement, keyed by hash" is an architectural
requirement, not an optimisation.

---

## Fingerprinting

Fingerprints are what make the parse cache, the statement registry, the chargeback attribution and the policy audit all cheap.

- Use `libpg_query`'s fingerprint (a hash of the parse tree), which erases literals and formatting. This is the same principle as `pg_stat_statements`' `queryid` jumbling — note that PostgreSQL 18 **changed** jumbling behaviour for constant lists and same-relation names, so fingerprints must carry a version tag and never be assumed stable across server major versions.
- Fingerprint version is part of the cache key. Mixing fingerprints across a server upgrade silently corrupts attribution.
- Fingerprints are the join key between our per-principal accounting and server-side `pg_stat_statements.queryid`. This is what lets chargeback work **without** requiring `pg_read_all_stats` or superuser — a concrete advantage over anything built purely on the server's view.

---

## Anonymous `Parse` — the driver-default case

Most drivers use **unnamed** prepared statements by default. PgBouncer and PgDog cache only *named* statements; only pg_doorman handles anonymous `Parse` (remapping to `DOORMAN_<N>` and synthesising `ParseComplete` on a hit).

We handle both, with two corrections over pg_doorman's implementation:

1. **Correct invalidation.** pg_doorman can return `ERROR: unnamed prepared statement does not exist` (SQLSTATE `26000`) on stale state. Our registry is invalidated by the Phase 1 DDL stream rather than by best-effort expiry.
2. **Bounded memory with per-tenant partitioning.** pg_doorman's worst case is documented at 8192 entries × ~100 KB ≈ **800 MB** of backend plan memory, and its `max_memory_usage` explicitly excludes prepared-statement bookkeeping. Our budget is per-principal and enforced, not global and best-effort.

Anonymous statement identity is `fingerprint(text, parameter type OIDs, planner-relevant GUC digest)` — the same triple pg_doorman uses, extended with the GUC digest so that two clients with different `work_mem`/`enable_seqscan` settings cannot share a plan that was chosen under the other's settings.

---

## Alternatives considered

| Option | Rejected because |
|---|---|
| Pure-Rust parser (`sqlparser-rs`) | Not semantically equivalent to PostgreSQL; correctness gaps in exactly the constructs a policy engine must reason about. |
| Parse everything, always | Measured cost is prohibitive on a proxied hot path; and it is unnecessary — most protocol traffic needs only transaction state. |
| Parse per `Bind`/`Execute` | Wastes the dominant share of CPU for zero additional information. |
| Delegate all parsing to the server (`EXPLAIN`, `pg_stat_statements`) | Requires elevated privileges, adds round trips, and cannot gate a statement *before* it executes — which is the entire point of a policy engine. |
| Hand-written recursive-descent parser | Years of work to reach PostgreSQL grammar parity, permanently behind new syntax. |

---

## Risks

- **C dependency with per-major-version branches.** Mitigation: pin a version per supported PostgreSQL major; `cargo-fuzz` the FFI boundary from Phase 0; treat any FFI panic as a crash-worthy bug.
- **AST lifetime hazards.** The C tree owns its memory; Rust views must not outlive it. Mitigation: wrap in a type whose lifetime is tied to the tree, forbid `unsafe` outside the two permitted crates (ADR 0001), and add Miri coverage where the FFI permits.
- **Fingerprint instability across server upgrades.** Mitigation: version-tag fingerprints and treat a version change as a cache flush, not a cache miss.
