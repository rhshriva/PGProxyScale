# Spike Findings

Outcomes of the Phase 0 risk spikes (see [`phase-0-foundations.md`](phase-0-foundations.md) §W0).
Each spike exists to kill an assumption cheaply, and each result is recorded whether or not it was
the expected one.

| Spike | Question | Status |
|---|---|---|
| S1 | Can a Rust proxy match PgBouncer at low concurrency, with a bypass path? | *in progress* |
| S2 | What exactly is PostgreSQL session state, and what can be virtualised? | **done** — see below |
| S3 | Is `libpg_query` fast and stable enough, and how should we bind it? | **done** — see below |

---

## S2 — Session-state taxonomy

**Outcome: the central design assumption is confirmed, and the case is stronger than expected.**

Full deliverable: [`../architecture/session-state-taxonomy.md`](../architecture/session-state-taxonomy.md).
Raw data: `spikes/s2/`.

Headline numbers, extracted from the PostgreSQL source for PG 14–18:

| | PG14 | PG18 |
|---|---|---|
| Total GUCs | 357 | **406** |
| Client-settable (`PGC_USERSET`) | — | **154** |
| **Reported to the client (`GUC_REPORT`)** | 13 | **15** |
| **Client-settable *and* reported** | 9 | **10** |

**144 of 154 client-settable GUCs are never reported to any client by any PostgreSQL version.**
This is the quantified proof that `track_extra_parameters` — the only passive channel a pooler has —
is structurally incapable of tracking session state, not merely incomplete.

Two findings that change downstream design:

1. **`search_path` only became reportable in PostgreSQL 18.** On PG 14–17 there is no protocol
   mechanism for a pooler to observe it at all. This is the precise mechanism behind the documented
   cross-tenant schema leak. Our design does not use that channel, which is why it is correct on
   every version rather than only on 18+.
2. **63 of the 154 client-settable GUCs are planner-relevant**, and **9 are parser-affecting**.
   A prepared-statement cache key must include the first group, and the proxy's *own parser* must
   mirror the second. This converts two vague risks into concrete, testable requirements.

---

## S3 — `libpg_query` viability

**Outcome: viable, but ADR-0002's binding recommendation was wrong and is corrected.**

Harness: `spikes/s3/harness/` · raw report: `spikes/s3/s3-report.md` ·
libpg_query commit `7632d03`, PG major 18, release + LTO, in a `rust:1-slim-bookworm` container.

### 1. Parse throughput (the surprise)

| statement | bytes | JSON ns/op | protobuf ns/op | protobuf vs JSON |
|---|---|---|---|---|
| `pk_select` | 41 | 2,194 | 8,631 | **3.9× slower** |
| `oltp_update` | 89 | 3,089 | 11,636 | 3.8× slower |
| `join_agg` | 160 | 6,743 | 26,159 | 3.9× slower |
| `plpgsql_do` | 114 | 963 | 2,226 | 2.3× slower |
| `wide_8kb` | 6,225 | 311,030 | 1,415,299 | **4.6× slower** |

**Protobuf is 2–5× *slower* than JSON, not faster.** This contradicted the premise in ADR-0002, so it
was verified in the source rather than taken on faith:

- `pg_query_parse_opts` → `pg_query_raw_parse` → `pg_query_nodes_to_json` — a hand-written JSON writer.
- `pg_query_parse_protobuf_opts` → `pg_query_raw_parse` → `pg_query_nodes_to_protobuf` — protobuf-c.

Both parse the same tree; they differ only in the serialiser, and protobuf-c loses badly.
The correct reading of PgDog's "replacing protobuf with Rust to go 5× faster" is that they stopped
serialising **at all**, not that they switched serialisation formats.

**Neither public API is the destination.** Both materialise a serialised copy of the tree. The fast
path is to walk the raw C `RawStmt`/`Node` tree in place — and **that tree is deliberately not in
`pg_query.h`**, which is exactly why PgDog wrote a separate crate (`pg_raw_parse`) to reach it.

**Decision recorded in ADR-0002:** bind the **JSON** API for Phase 0 (it is the best available public
API, ~4× better than protobuf), always behind the fingerprint-keyed cache, and treat a raw-tree
accessor as a measured optimisation rather than a prerequisite. Do not use protobuf.

### 2. The tiered design is quantitatively justified

| statement | bytes | T0 hash ns/op | T2 parse ns/op | parse ÷ hash |
|---|---|---|---|---|
| `pk_select` | 41 | 18 | 2,533 | **142×** |
| `wide_8kb` | 6,225 | 6,123 | 333,044 | **54×** |

A T0 decision costs tens of nanoseconds; a full parse costs microseconds to *hundreds of*
microseconds. At 50k queries/s, parsing every small statement would consume roughly 11% of a core,
and a single 8 KB statement costs 333 µs — which is why "parse once per unique statement, keyed by
hash" is an architectural requirement rather than an optimisation.

### 3. Fingerprint stability — 3/3 pass

| Test | Result |
|---|---|
| Different literals, identical structure → same fingerprint | **PASS** |
| Whitespace / case / inline comment differences → same fingerprint | **PASS** |
| Commented vs plain query → same fingerprint | **PASS** |

Fingerprints are fit to key a cache, a statement registry and a chargeback ledger.

### 4. Parser options change the result — independent corroboration of S2

Query: `SELECT 'a\'b' AS s`

| parser options | parse | fingerprint |
|---|---|---|
| default (`standard_conforming_strings=on`) | **ERROR** | **ERROR** |
| `DISABLE_STANDARD_CONFORMING_STRINGS` | ok | `0x50fde20626009aba` |
| `DISABLE_BACKSLASH_QUOTE` | **ERROR** | **ERROR** |

The same bytes are a syntax error or a valid statement depending on a session GUC — and
`libpg_query` exposes exactly the switches for the two that matter. This closes the loop with S2:
**the parse cache key must include the session's parser-affecting GUCs**, and the capability is
already available in the library we intend to use. A parser that ignores them is both wrong and, in
Phase 2, a policy bypass.

### 5. FFI boundary smoke test

7,087 malformed, truncated and byte-mutated inputs through `pg_query_parse_opts`:
5,132 parsed, 1,955 returned a structured `PgQueryError`, **0 crashes, panics or aborts**.
Every failure came back through the error struct, never a signal.

This is a smoke test, not a fuzzing campaign. A sustained `cargo-fuzz` target remains Phase 0 gate G5.

### 6. Version pinning is mandatory

The build reports `PG_MAJORVERSION = 18`. A single libpg_query build vendors a single PostgreSQL
grammar, so fingerprints are **not** comparable across server majors, and a PG14 server's syntax must
be parsed by a PG14 grammar. This confirms ADR-0002's requirement for a version tag in the
fingerprint key, and adds a build-matrix requirement: **one libpg_query build per supported server
major**, selected at runtime.

---

## S1 — Runtime and data-path overhead

**Outcome: thread-per-core is confirmed and the work-stealing runtime plateaus exactly as predicted.
The zero-copy bypass showed no measurable benefit and is deprioritised.**

Harness: `spikes/s1/` (`run.sh` for the matrix, `verify.sh` for the anomaly follow-up).
Raw data: `spikes/s1/s1-report.md`, `spikes/s1/s1-report.md.raw.tsv`.

### Method

Everything in containers on one Docker bridge network: PostgreSQL 18, PgBouncer 1.18 (session mode,
`default_pool_size=100`), three variants of a deliberately dumb pass-through proxy, and pgbench in its
own container. Best of 2 passes, targets interleaved inside the concurrency loop, global warmup first,
`pgbench -S -n`, 8 s measured after 4 s warmup, scale 100, 16 CPUs.

The proxy speaks no PostgreSQL and pools nothing. It exists only to measure the floor.

### Results

**TPS** (best of 2 passes):

| target | c=1 | c=4 | c=16 | c=64 |
|---|---|---|---|---|
| direct | 15,542 | 51,649 | 148,597 | 122,921 |
| pgbouncer-session | 9,486 | **34,347** | 70,253 | 71,183 |
| rust-thread | 9,678 | 33,049 | **107,599** | **215,827** |
| rust-tokio | 9,563 | 33,919 | 91,013 | 93,625 |
| rust-splice | **9,808** | 32,518 | 109,345 | **217,867** |

**Average latency (ms)**:

| target | c=1 | c=4 | c=16 | c=64 |
|---|---|---|---|---|
| direct | 0.064 | 0.077 | 0.108 | 0.521 |
| pgbouncer-session | 0.105 | **0.116** | 0.228 | 0.899 |
| rust-thread | 0.103 | 0.121 | 0.149 | 0.297 |
| rust-tokio | 0.105 | 0.118 | 0.176 | 0.684 |
| rust-splice | 0.102 | 0.123 | 0.146 | 0.294 |

### What this settles

**1. Gate G2 (low-concurrency parity) — met, with a small honest deficit at c=4.**
At c=1 the Rust relay is marginally *faster* than PgBouncer (9,678 vs 9,486 TPS; splice 9,808). At c=4
it is **3.8% slower in TPS and 4.3% higher in latency** (33,049 vs 34,347 TPS; 0.121 vs 0.116 ms).
That is inside ADR-0001's "within 10%" decision rule, so the language and runtime stay — but the
deficit is real, and closing it is what the bypass path was meant to do.

**2. Gate G3 (scale win) — met decisively.**
At c=16 the Rust relay is **+53%** over PgBouncer; at c=64 it is **+203% (3.0×)**. PgBouncer is flat
across c=16→c=64 (70,253 → 71,183), which is the single-threaded ceiling reproducing exactly as the
research predicted.

**3. Thread-per-core beats work-stealing, and the plateau reproduces.**
This is the most decision-relevant result. Rust-tokio **plateaus at ~92k TPS from c=16 to c=64**
(91,013 → 93,625), reproducing PgDog's published plateau almost exactly — while `rust-thread` under
the identical harness keeps scaling (107,599 → 215,827). The difference is the runtime, not the
language and not the code path. ADR-0001's provisional runtime choice is therefore **confirmed**.

**4. The zero-copy bypass earns nothing at this scale — deprioritised.**
`rust-splice` (blocking `splice(2)` through a 1 MiB pipe, zero copies through user space) is
statistically indistinguishable from `rust-thread` (userspace `io::copy`): 217,867 vs 215,827 TPS at
c=64, and 109,345 vs 107,599 at c=16. **The bottleneck is not byte copying.** This is worth real
money: the most technically exciting item on the roadmap can be moved off the critical path, and the
Phase 0 data path should be simple, auditable userspace copying with `TCP_NODELAY` rather than a
syscall-level bypass. Revisit only if a future workload is COPY- or analytics-dominated.

### The anomaly that must not be reported as a win

The proxies beat **direct PostgreSQL** at c=64 (215,827 vs 122,921 TPS, and 0.297 ms vs 0.521 ms
latency). A pass-through relay cannot make a round trip faster, so this was treated as a defect in the
measurement and chased down with `verify.sh`:

| condition | direct | via proxy |
|---|---|---|
| c=64, j=8, rep 1 | 117,359 TPS / 0.545 ms | 193,067 TPS / 0.331 ms |
| c=64, j=8, rep 2 | 130,471 TPS / 0.491 ms | 213,997 TPS / 0.299 ms |
| c=64, j=8, rep 3 | 144,322 TPS / 0.443 ms | 217,386 TPS / 0.294 ms |
| c=64, j=64 | 167,555 TPS / 0.382 ms | 188,562 TPS / 0.339 ms |
| **c=16, j=8** | **158,349 TPS / 0.101 ms** | **119,103 TPS / 0.134 ms** |

It is **reproducible**, and pgbench's own transaction counts agree (2,169,256 transactions through the
proxy vs 1,440,767 direct in the same 10 s), so it is not an artefact of how TPS is computed. It is
also **internally inconsistent**: the proxy is *slower* than direct at c=16 and *faster* at c=64, and
raising pgbench's client threads from 8 to 64 nearly closes the gap.

The most likely explanation is a property of this test bed rather than of the proxy — Docker Desktop's
container networking and CPU scheduling on Apple Silicon under 64+ concurrent connections. **The
conclusion is not that the proxy is fast; it is that this substrate cannot be trusted for absolute
numbers at high concurrency.**

This does **not** undermine the proxy-versus-PgBouncer comparison, because both are relays measured on
the same substrate under the same harness. It does mean the c=64 absolute figures should not be quoted
as evidence of anything.

### Follow-ups before this gate is formally signed off

1. **Re-run on bare-metal Linux** (the real target) before quoting any absolute number.
2. pgbench reports *average* latency, never percentiles. Gate G2 says "p50". The Phase 0 harness must
   emit real percentiles (HDR histogram) rather than leaning on pgbench.
3. PgBouncer here is **1.18** (Debian bookworm), not 1.25.x. Re-run against a current build.
4. `rust-tokio` used 2 worker threads on one shared runtime; `rust-thread` used 2 OS listener threads
   with a thread per direction. A stricter like-for-like (1 worker each) is worth one more pass.
5. Scope note: the pass-through proxy does **no pooling, no parsing and no session handling**. These
   numbers bound the I/O framework's cost only. Pooling and the Session-State Ledger will add work
   that this harness does not measure — which is precisely why the parse/session costs measured in S2
   and S3 matter.
