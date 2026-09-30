# Full session-state virtualization: remaining design and dependencies

The implemented ledger virtualizes persistent settings, role/preparation contexts,
prepared statements and a bounded subset of held SQL cursors. Temporary relations,
session advisory locks, LISTEN subscriptions and opaque extension state currently
retain their native backend. Affinity is a compatibility mechanism; it is not
resource migration, durable ownership or full session-state virtualization.

## Cursor completion work

The opt-in held cursor implementation preserves committed snapshots, simple-query
positioning including rollback behavior, text/binary extended descriptors and
results, and limited Execute/PortalSuspended delivery with native comparison.
Non-scroll, binary DECLARE cursors, unsupported output types, pre-accessed cursors,
other affinity resources and oversize snapshots keep native ownership.

Remaining protocol work includes extended virtual cursor execution in an explicit
transaction, mixed physical/virtual extended cycles within a single transaction,
SQL PREPARE/DEALLOCATE interoperability with virtual protocol statement names, and
physical catalog visibility such as pg_cursors. Mixed-cycle staging cannot simply
inject Sync: PostgreSQL would commit earlier physical writes before later virtual
errors. A correct coordinator must preserve transaction/savepoint status, force
physical transaction failure when a local execution fails, preserve message order,
and recover at the client's own Sync/ROLLBACK boundaries. This needs differential
cases for physical writes followed by local errors, savepoints, COPY, portal
interleaving, cancellation and driver pipelines.

Closed-cursor delivery is implemented and locked in by proxy-side tests rather than
native comparison: the tested PostgreSQL builds crash when a cursor is closed
while a suspended extended portal still references it, so the proxy services the
`CLOSE` locally and keeps the suspended portal's cached descriptor and rows. See
[the ledger semantics note](../testing/ledger-semantics.md#closed-cursor-safety-and-the-native-suspended-close-defect).

## Temporary relations

Exporting rows and recreating a temp table on each backend does not preserve native
relation identity, OIDs/regclass values, prepared-plan dependencies, indexes,
constraints, sequences, triggers, ON COMMIT behavior, savepoint rollback, large
objects, temp schemas or dynamic SQL inside server functions. Rewriting visible SQL
identifiers into permanent private tables also misses catalog lookup and
server-generated SQL, and changes DDL locking, visibility and cleanup semantics.
No such substitution is implemented.

Transparent migration needs a PostgreSQL-side logical-session component with
verified namespace, planner/catalog, resource-owner and transaction hooks. Native
temp namespaces are backend-owned; an ordinary extension's ability to emulate all
of these semantics must be established first and may require server changes. The
component would accept an authenticated logical-session identity, isolate object
access, retain stable object identities/dependencies, attach operations to the real
user transaction, and clean up on confirmed session termination. Proxy ownership
needs bounded metadata, version negotiation, cancellation, fencing and an explicit
failure policy. Prototype tests must cover pg_temp references, regclass/OIDs,
functions with dynamic SQL, prepared plans across DDL, savepoints, ON COMMIT modes,
concurrent clients, malicious cross-session access and backend loss.

## Advisory locks

A separate lock-broker connection preserves conflicts with external PostgreSQL
callers, but fails same-session reentrancy. A transaction lock on the data backend
can block on that client's own session lock held by the broker, producing a
self-deadlock absent in native PostgreSQL. SQL rewriting cannot transparently cover
lock calls from arbitrary functions or extensions. One retained broker connection
per locking client also remains physical ownership and consumes backend capacity.
This is not implemented or presented as full virtualization.

Transparent ownership requires PostgreSQL lock-manager support for a logical
session owner shared across physical workers, including session and transaction
lock counts, shared/exclusive modes, try-lock responses, transaction/savepoint
release, deadlock detection, lock timeout, cancellation, pg_locks observability and
termination cleanup. The proxy must fence abandoned owners without revoking an
active user's locks. Native external-client conflict tests, same-session mixed
session/transaction locks, stored-function calls and fault/cancellation tests are
required before enabling it.

## LISTEN/NOTIFY

A listener broker can reduce physical listeners, but subscriptions are
transactional and notifications have commit ordering, duplicate coalescing,
original sender PIDs and delivery restrictions while the receiver is in a
transaction. Registering the broker after the user's COMMIT creates a loss window;
overlapping old/new listeners creates duplicates without a server event identity.
Deduplicating equal channel/payload/PID values can discard legitimate distinct
notifications. Current native affinity avoids inventing these guarantees.

A live handoff design needs server-coordinated subscription commit boundaries and
ordered event identities, a bounded per-client queue, logical-session delivery
barriers, sender identity rules, backpressure, cancellation and reconnect/fencing.
A PostgreSQL-side component can register logical subscriptions in the actual user
transaction and expose an ordered handoff boundary to the proxy.

Restart persistence additionally needs a durable event log, committed subscription
state, recovery checkpoints, retention and overflow policy. The PostgreSQL wire
NotificationResponse has no application acknowledgement. Exactly-once application
processing across reconnect/restart therefore requires an additional client
acknowledgement contract; TCP delivery alone cannot establish it. No durable event
log, restart delivery or exactly-once notification claim is implemented.

## Architecture choice

Until a PostgreSQL-side component is approved, implemented and verified, unsupported
resources keep native affinity or return explicit unsupported errors. Enabling a
new server dependency or changing user-visible transactional guarantees is an
architecture decision. The existing safe behavior must remain available throughout
any migration. Acceptance criteria must distinguish functioning proxy features,
native ownership fallback, server component requirements and restart durability.
