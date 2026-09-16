# ADR 0005 — Deliverable Shape

- **Status:** Accepted
- **Date:** 2026-09-16
- **Decides:** what v1 ships as, and what stays possible later

---

## Decision

**Ship a standalone binary first.** `pgproxy --config pgproxy.toml`, a single self-contained
executable, deployable exactly like PgBouncer or PgDog.

Defer the Kubernetes operator, and treat the **embeddable library** and **sidecar** forms as
deliberately-preserved future options rather than v1 deliverables.

---

## Why the binary first

1. **It matches how the category is adopted.** PgBouncer, PgDog, pg_doorman, Odyssey, pgagroal and
   pgpool-II are all deployed as a process in front of Postgres. The entire evaluation path a
   prospective user follows — install, point a DSN at it, run their own conformance suite, benchmark
   it against PgBouncer — assumes a binary. Anything else adds friction before we have earned trust.

2. **It is the only shape that can be benchmarked against the incumbents honestly.** Spike S1
   measured a binary against PgBouncer under an identical harness. An embedded library cannot be
   compared to PgBouncer at all, and a sidecar changes the network topology being measured.

3. **The operator is a distribution problem, not a data-plane problem.** It can be added once the
   data plane is trustworthy, and it is pure addition — the binary remains the unit of deployment
   underneath it.

4. **It keeps the runtime honest.** Spike S1 validated per-core `SO_REUSEPORT` listeners with
   thread-per-core state. That model assumes the process owns its listening sockets, its fd table
   and its signal handling. Designing for an embeddable library *first* would have forced a
   different, weaker concurrency model on the strength of an unvalidated hypothesis about demand.

---

## The trade-off being accepted

The research identified **embedded/sidecar mode as a genuinely unserved differentiator** — nobody
ships a pooler with proxy-grade semantics in-process, and removing a network hop is real value for
Kubernetes and serverless deployments. Deferring it is a deliberate bet that *correctness and policy
win the first customers*, not topology.

That bet is only defensible if the option stays genuinely open, which constrains W1:

- **The data path must be a library-friendly core.** `pgproxy-core` exposes a `Service` trait and a
  `Runtime`; the binary is one implementation of a host process, not the architecture. Nothing in the
  core may assume it owns `main()`, the process's signals, or the whole fd table.
- **Configuration is data, not argv.** Config is a validated struct loaded from a file with env
  overrides. An embedder can construct it programmatically; the CLI is a thin adapter over the same
  loader.
- **No global mutable state.** Per-core state is passed explicitly. This is already required by
  ADR-0001's thread-per-core model, so the two decisions agree.
- **Embedding is a later ADR, not a later rewrite.** If we ship a sidecar or an FFI surface, it should
  be a new host for `pgproxy-core`, ideally without touching the wire or session crates.

## What would reverse this decision

- A design-partner platform vendor who needs in-process embedding to adopt us at all.
- Evidence that per-connection latency, not correctness or policy, is the actual buying blocker.

If either appears, write a superseding ADR rather than bolting an embed mode onto a binary-shaped
architecture.
