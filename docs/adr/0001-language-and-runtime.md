# ADR 0001 — Implementation Language and Runtime

- **Status:** Accepted (runtime sub-decision provisional, pending spike S1)
- **Date:** 2026-09-16
- **Decides:** the implementation language for the data path and the surrounding services

---

## Decision

**Rust.** Not C, not C++, not Go.

**Runtime:** thread-per-core with per-core state (`monoio`/`io_uring` on Linux, epoll fallback), *not* a work-stealing async runtime as the default. Provisional — revisit after spike S1.

**Interop:** exactly one C dependency — `libpg_query`, compiled and linked over FFI, wrapped in a safe Rust module with a fuzz harness. We do not write C.

---

## Why Rust

### 1. The product's primary differentiator is a security boundary, and C has a demonstrated failure record here

The policy engine must be *bypass-proof*. That is the whole point: CVE-2026-85620 (CVSS 9.2) bypassed Postgres MCP Pro's restricted mode with `SELECT * FROM pg_read_file('/etc/passwd')` because the validator checked `FuncCall` nodes and not `RangeFunction`. The architectural conclusion is that enforcement must sit below the untrusted thing — which means our parser and policy code sits directly on attacker-controlled bytes and attacker-controlled SQL.

PgBouncer is a beautifully engineered C program and it shipped **five CVEs in 2025–2026**, including:

- **CVE-2026-6664** — integer overflow in network packet parsing; an *unauthenticated remote attacker* can crash PgBouncer with a malformed SCRAM packet.
- **CVE-2026-6665** — unchecked `strlcat()` return value leading to a stack overflow from a malicious backend.
- **CVE-2025-12819** — arbitrary SQL execution *during authentication* via a malicious `search_path` in the StartupMessage.

These are not sloppiness. They are the class of bug you get when a C program parses a hostile wire protocol. Choosing C means committing to out-engineering that class of bug for the next decade, in the one component whose selling point is that it cannot be bypassed.

Rust makes the entire memory-safety class impossible by construction. That is not a productivity argument; it is a *product* argument.

### 2. Three specific ecosystem dependencies matter, and all three are Rust-shaped

| Need | Why Rust is the right host |
|---|---|
| Real PostgreSQL SQL parsing | `libpg_query` is a C library, but the proven, actively used bindings are Rust (`pg_query.rs`) — and PgDog (`pg_raw_parse`) already runs this in production. FFI to C is a well-trodden path, not a research project. |
| WASM plugin sandbox (Phase 5+) | `wasmtime` is the best-in-class implementation and is Rust-native. Building the plugin ABI in any other language means FFI-ing into it forever. |
| Thread-per-core / io_uring | `monoio` and `glommio` are Rust. ByteDance's `monoio` is in production for exactly this shape of workload. |

### 3. Momentum is unambiguous

Every new PostgreSQL pooler of the last two years is Rust: **PgDog** (Rust/Tokio), **pg_doorman** (Rust, three years in production at Ozon), **pgwire** (the "hyper for the pg wire protocol" crate), and **Neon's proxy** (Rust). The only C++ entry, **ProxySQL**, is MySQL-first and its PostgreSQL mode is explicitly second-class — named portals, `COPY FROM STDIN` in extended mode, `LISTEN`/`NOTIFY` and the `Flush` message are all unsupported, and the extended query protocol only arrived in 3.0.3.

### 4. Go is out for the data path

Garbage collection shows up as tail latency, and tail latency is the metric that matters here. The Feb 2026 benchmark puts Multigres (Go) at **+0.424 ms** overhead at 4 clients versus PgBouncer's **+0.047 ms**; SPQR (Go) is **+0.099 ms**. Some of that is architecture — Multigres' etcd + pgctld + multipooler + multigateway stack is inherently heavier — but both Go proxies sit at the slow end of the latency table while the Rust proxy (PgDog, +0.070 ms) does not.

Go remains a reasonable choice for the **control plane** (API, CLI, operator) if we ever want faster iteration there. It is not a reasonable choice for the byte path.

---

## Rejected alternatives

### C — rejected

**Genuine strengths:** maximum control; mature (PgBouncer has been hardened for 15+ years); trivially links `libpg_query`; smallest binaries; and it *currently holds the low-concurrency latency crown* — libevent beats Tokio at 1–10 connections (16.7k vs 15.5k TPS at 1 client).

**Rejected because:** the CVE record above is precisely the class of bug we must not have; manual memory management at an auth/policy boundary is a liability we cannot out-engineer; and the ergonomics cost compounds across an async state machine, a WASM sandbox, and a policy DSL. We would also inherit PgBouncer's single-threaded culture, which is the ceiling we are trying to break.

**Where C still appears:** in our dependency tree, as `libpg_query`. Nowhere else.

### C++ — rejected

**Genuine strengths:** links `libpg_query` naturally; mature `io_uring` wrappers; the largest hiring pool; zero-cost abstractions without a borrow checker.

**Rejected because:** no memory safety, which is the whole argument above; slower iteration on the two hardest subsystems (parser FFI edges, policy engine); and the weakest signal in the evidence — *no successful PostgreSQL pooler is written in C++*. ProxySQL is the only C++ entrant and its Postgres support is the least complete in the category. Betting on C++ here means betting against the entire field's revealed preference with no offsetting advantage.

### Hybrid (C data path + Rust control plane) — rejected

Two languages, two build systems, two skill sets — and it puts the **security-critical** code (the data path, which is where policy must be enforced) in the unsafe language while putting the safe code in the safe language. That is exactly backwards.

---

## Runtime decision (provisional)

The language is settled; the concurrency model is a measured question, and the evidence points away from a default work-stealing runtime:

- PgDog on 2 Tokio threads beats single-threaded PgBouncer only past ~50 connections, and its throughput **plateaus from c16 to c64** (76,850 → 76,789 TPS).
- SPQR (Go) **scales linearly to c64** (25,105 → 80,247 TPS), suggesting the concurrency model matters more than the language.
- PgBouncer's own multi-core answer is N processes behind `SO_REUSEPORT` with a `[peers]` cancel-forwarding protocol — effective (~336k TPS on a 16-process fleet) but operationally fragile: pool limits are not shared across processes, and query cancellation silently no-ops when peering is misconfigured.

**Therefore:** thread-per-core, per-core state, `SO_REUSEPORT` accept, no cross-core synchronisation on the hot path, `io_uring` for batched syscalls, and a **bypass/splice path** so that bulk traffic can be handed off without traversing a shared event loop. Cancellation gets a first-class design rather than a peering bolt-on — note that PostgreSQL 18's protocol 3.2 makes cancel keys variable-length (up to 256 bits), which breaks the fixed 12-byte assumption every current implementation makes.

**Revisit trigger (spike S1):** if we cannot get within 10% of PgBouncer at 4 clients once the bypass path exists, the runtime is wrong — not the language. In that case the fallback is a hybrid: a per-core blocking-I/O reactor for the fast path with the same Rust codebase.

---

## Unsafe-code policy

- `#![forbid(unsafe_code)]` in every crate.
- Exceptions, each requiring a written safety comment per block and a dedicated fuzz target:
  - `pgproxy-wire` — buffer/codec internals where zero-copy slicing requires it.
  - `pgproxy-parser` — `libpg_query` FFI.
- `cargo-fuzz` targets for the codec and the parser FFI from Phase 0, and the parser FFI is additionally exercised through Miri where the FFI boundary permits.

---

## Consequences

**Positive**
- The memory-safety CVE class is eliminated in the component that sells itself on being unbypassable.
- One language for data path, policy, admin API and plugins; one build; one profiling story.
- Direct access to the two ecosystem pieces that matter most (`libpg_query` bindings, `wasmtime`).
- Rust's ownership model is a natural fit for the Session-State Ledger, where the central invariant is "who owns this server connection, and what state is on it right now."

**Negative**
- Slower initial velocity than Go, and a smaller hiring pool than C++.
- We must actively defeat the low-concurrency latency regression that libevent currently wins (~10–15% at 1–10 clients). The bypass path is the answer, and it must be built, not assumed.
- Build times and binary size are worse than C.

**Neutral**
- We take on a C dependency (`libpg_query`) with a per-major-version branch, mitigated by fuzzing and by the fact that the same library is what PostgreSQL itself uses.
