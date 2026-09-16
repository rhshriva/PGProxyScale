# ADR 0001 — Implementation Language and Runtime

- **Status:** Accepted — language settled, runtime **confirmed by spike S1**
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

## Runtime decision — **CONFIRMED by spike S1**

The language is settled; the concurrency model was a measured question, and the evidence pointed away from a default work-stealing runtime:

- PgDog on 2 Tokio threads beats single-threaded PgBouncer only past ~50 connections, and its throughput **plateaus from c16 to c64** (76,850 → 76,789 TPS).
- SPQR (Go) **scales linearly to c64** (25,105 → 80,247 TPS), suggesting the concurrency model matters more than the language.
- PgBouncer's own multi-core answer is N processes behind `SO_REUSEPORT` with a `[peers]` cancel-forwarding protocol — effective (~336k TPS on a 16-process fleet) but operationally fragile: pool limits are not shared across processes, and query cancellation silently no-ops when peering is misconfigured.

**Therefore:** thread-per-core, per-core state, `SO_REUSEPORT` accept, no cross-core synchronisation on the hot path. Cancellation gets a first-class design rather than a peering bolt-on — note that PostgreSQL 18's protocol 3.2 makes cancel keys variable-length (up to 256 bits), which breaks the fixed 12-byte assumption every current implementation makes.

### Spike S1 result

Measured on a pass-through relay (no pooling, no parsing), best of 2 passes, in containers on one
bridge network — full data in [`../plans/spike-findings.md`](../plans/spike-findings.md):

| runtime | c=1 | c=4 | c=16 | c=64 |
|---|---|---|---|---|
| PgBouncer 1.18 (single process) | 9,486 | **34,347** | 70,253 | 71,183 |
| Rust, `io::copy` + thread-per-core | 9,678 | 33,049 | 107,599 | **215,827** |
| Rust, `splice(2)` bypass | **9,808** | 32,518 | 109,345 | **217,867** |
| Rust, **Tokio work-stealing** | 9,563 | 33,919 | 91,013 | 93,625 |

1. **Parity at low concurrency, decisively ahead at high.** The 10% tolerance holds (3.8% behind
   PgBouncer at c=4, marginally ahead at c=1) and the scale win is 3.0× at c=64.
2. **The work-stealing plateau reproduces.** Tokio flattens at ~92k TPS from c=16 to c=64 while
   thread-per-core keeps scaling under an identical harness — the runtime, not the language, is the
   variable. **Thread-per-core is confirmed; the "hybrid fallback" trigger is not met.**
3. **The bypass/splice path earns nothing and is dropped from Phase 0.** `splice(2)` is
   indistinguishable from userspace `io::copy` (217,867 vs 215,827 TPS at c=64). The bottleneck is not
   byte copying, so the data path should stay simple, auditable userspace copying with `TCP_NODELAY`.
   `io_uring` remains a later, measured optimisation rather than a Phase 0 requirement.
4. **Caveat carried forward:** this substrate cannot be trusted for absolute numbers at high
   concurrency (the relay appeared to beat direct PostgreSQL, which is physically impossible); gates
   G2/G3 must be re-measured on bare-metal Linux before absolutes are quoted.

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
- libevent still wins a small amount at low concurrency: measured at **3.8% behind PgBouncer at c=4** (spike S1). This is a real but bounded deficit, inside the 10% tolerance, and it must be tracked rather than assumed away.
- Build times and binary size are worse than C.

**Neutral**
- We take on a C dependency (`libpg_query`) with a per-major-version branch, mitigated by fuzzing and by the fact that the same library is what PostgreSQL itself uses.
