# ADR 0006 — Session-state virtualization boundary and the PostgreSQL-side component

- **Status:** Proposed — decision required
- **Date:** 2026-09-30
- **Depends on:** ADR 0001, ADR 0003

---

## Context

ADR 0003 defines a three-class taxonomy and a ledger that records client intent.
The implemented ledger virtualizes the states that can be reconstructed from the
wire plus ordinary SQL: confirmed settings, role/preparation context, prepared
statements (wire and SQL), and a bounded, opt-in subset of `SCROLL WITH HOLD` SQL
cursors. Everything else keeps **native backend affinity** — safe compatibility,
not virtualization (`docs/architecture/remaining-state-virtualization.md`).

The states that still own a native backend are:

| Resource | Why replay/emulation is not equivalent |
|---|---|
| Temporary relations / `pg_temp` | Recreating rows changes relation identity, OIDs/`regclass` values, prepared-plan dependencies, indexes, constraints, sequences, triggers, `ON COMMIT` behaviour, savepoint rollback, large objects, temp schemas and dynamic SQL inside server functions. Rewriting identifiers to permanent private tables changes DDL locking, visibility and cleanup. |
| Session advisory locks | A broker connection preserves conflicts with external callers but breaks same-session reentrancy and can self-deadlock against the client's own data backend. Lock calls from arbitrary functions/extensions cannot be rewritten transparently, and a retained broker connection is itself physical ownership. |
| `LISTEN`/`NOTIFY` | Subscriptions are transactional; notifications carry commit ordering, duplicate coalescing, original sender PIDs and in-transaction delivery restrictions. Registering a broker after the user's `COMMIT` creates a loss window; overlapping old/new listeners create duplicates without a server event identity; deduplicating on (channel, payload, PID) can discard legitimate distinct notifications. |
| Opaque extension state | Unknown session effects the proxy cannot classify. Class C in ADR 0003: detect and refuse, or pin with a reported cost. |

Each of these is stored by unmodified PostgreSQL in **backend-owned** resources.
The transparent equivalent therefore cannot be produced by the proxy alone. It
requires a PostgreSQL-side logical-session component that can:

- accept an authenticated logical-session identity and isolate object access;
- retain stable object identities/dependencies across physical workers;
- attach operations to the real user transaction;
- provide session/transaction advisory-lock counts, modes, try-lock responses,
  savepoint release, deadlock detection, lock timeout, cancellation and
  `pg_locks` observability for a logical owner;
- coordinate subscription commit boundaries and ordered event identities; and
- clean up on confirmed session termination.

Such a component needs its own bounded metadata, version negotiation, cancellation,
fencing and explicit failure policy. Whether an ordinary extension can provide all
of these semantics is unproven and may require server changes.

---

## Decision

**Do not emulate these resources in the proxy, and do not claim full state
virtualization.** The boundary is fixed as follows until a PostgreSQL-side
component is separately approved:

1. Resources in the table above keep native backend affinity, or return explicit
   unsupported errors. Native affinity is a deliberate, documented compatibility
   mechanism — not a virtualization claim.
2. The proxy continues to make the cost visible (pin reasons, `is_pinned`) rather
   than hiding it, per ADR 0003's ownership invariant.
3. Any move to transparent migration is a **new architecture decision** gated on a
   defined integration and compatibility contract for the server-side component,
   including proxy ownership, cancellation, fencing, bounded metadata and an
   explicit failure policy.
4. Acceptance criteria must always distinguish: functioning proxy features, native
   ownership fallback, server-component requirements, and restart durability.

Pursuing the server-side component is a separate, externally-visible dependency
and is out of scope for the current proxy-only release.

---

## Alternatives considered

1. **Emulate by replay/export in the proxy** (recreate temp tables, broker locks,
   fan out notifications). Rejected: it changes OIDs, reentrancy, transaction
   visibility and notification timing; some cases are impossible to make
   transparent from the client side.
2. **Proxy-only brokers with documented limitations** (lock broker, single
   listener). Rejected for transparent semantics: they introduce self-deadlock,
   loss windows or duplicate notifications that native PostgreSQL does not have.
   They may return as explicitly-opt-in, clearly-labelled compatibility shims.
3. **Native affinity + honest reporting (this decision).** Accepted as the interim
   and current state.
4. **PostgreSQL-side component.** Deferred: needs the contract in this ADR before
   implementation, and changes the deployment surface.

---

## Consequences

**Positive**
- No correctness or tenant-isolation risk from behavioural emulation that cannot
  be made exact.
- Shipping surface stays a single self-hosted binary (ADR 0005).
- Pin cost is reported, not hidden.

**Negative / risky**
- Full session-state virtualization remains unachieved; applications that rely on
  temp/lock/notify state across transactions still pin a backend.
- Multiplexing efficiency is reduced for those workloads.
- A future server component would add a PostgreSQL-version-sensitive dependency
  and an operator-managed artifact.

---

## Open questions

1. Can an ordinary extension provide all required lock and subscription semantics,
   or are server changes unavoidable?
2. What is the minimal contract (identity handoff, event identity, cleanup/fencing)
   the proxy can verify before trusting a server component?
3. How is the component versioned and negotiated against supported PostgreSQL
   majors, and what happens when it is absent?
4. What is the restart-durability model for notifications (durable event log,
   acknowledgement contract), given the wire protocol has no app-level ack?

