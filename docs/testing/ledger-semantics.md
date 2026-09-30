# Session ledger verification

The ledger records successful PostgreSQL completions, including settings,
transaction/savepoint rollback, prepared statements, listeners, held cursors, and
temporary relations. Prepared statements are session objects and survive rollback;
settings and temporary DDL follow transaction rollback. Physical ownership remains
with clients whose state cannot safely be reconstructed.

Startup settings form the client's RESET baseline. The wire layer sends a safely
quoted startup SET for an individual RESET or SET DEFAULT. RESET ALL is rewritten
as one trusted PL/pgSQL DO statement containing RESET ALL and startup SET commands,
so it remains a single statement in the extended protocol. This requires the normal
PostgreSQL `plpgsql` language. The original SQL stays in the ledger and policy
checks; only backend transport SQL changes. Prepared replay stores the rewritten
transport payload with the original statement intent.

After successful DISCARD ALL, the wire layer silently reapplies startup settings
at the idle response boundary. It holds pipelined requests across this boundary.
An extended DISCARD execution still accepts Flush and Sync to reach that boundary;
other executable messages before Sync are rejected instead of running with wrong
defaults.

Parser-affecting settings update the parser cache context and follow rollback and
RESET. These settings retain conservative backend affinity. Session locks and
unknown functions protect ownership before execution: a function may mutate a
nontransactional session resource and then fail without CommandComplete. Such
uncertain effects retain affinity until DISCARD ALL. LISTEN, unsupported held cursors, temp
relations, session authorization, and opaque extension behavior remain physical backend state.
This is safe compatibility through affinity, not full state virtualization.

Run unit checks with `cargo test -p pgproxy-session`. Run the live checks against an
isolated PostgreSQL database and a transaction route with a size-one backend pool:

```sh
python tests/conformance/drivers/ledger_check.py \
  --host 127.0.0.1 --port 6439 --database areas_transaction \
  --backend-port 55439 --backend-database conformance
```

The driver checks simultaneous-client handoff after simple and extended RESET,
DISCARD, rollback/savepoint behavior, PREPARE survival, resource lifecycles,
retained-backend DDL, and a function that takes a session lock before raising an
error. The direct backend connection provides independent DDL and lock probes.
Use test-only credentials with permission to create isolated tables/functions.

## Opt-in held cursor snapshots and role replay

`general.session.virtualize_hold_cursors = true` enables bounded snapshots of
pristine, explicitly SCROLL WITH HOLD, non-binary SQL cursors. PostgreSQL performs
its native commit materialization first; the proxy reads that snapshot once,
closes the physical cursor only after storing its rows, and releases the backend.
The original SELECT is never re-executed. Independently held cursors can therefore
share a size-one pool. Snapshot bytes count toward `memory_bytes`; each capture
is additionally capped at half that budget and an absolute `query_timeout_secs`.

Eligibility excludes attempted FETCH/MOVE, pre-existing prepared statements,
other affinity resources, and opaque effects. Only bool, integer, text/varchar/
bpchar, and UUID text output is copied; dates, floats, custom types and binary
formats retain native ownership. Overflow or unsupported output drains the
internal response and rewinds the pristine native cursor to before its first row.
It then retains native ownership without repeatedly attempting capture.

Virtual cursors accept one simple-query FETCH/MOVE/CLOSE at a protocol boundary,
with PostgreSQL forward, backward, absolute, relative, negative and ALL positioning.
Multi-statement cursor access and duplicate DECLARE names return a typed 0A000
connection error rather than incorrect results. Extended access and transactional
simple queries are described below.
Physical `pg_cursors` visibility does not include these client-owned snapshots.
The feature is opt-in because those access restrictions are deliberate compatibility
limits. LISTEN durability/exactly-once delivery, virtual temp tables and virtual
session advisory locks remain unimplemented.

Persistent SET ROLE and RESET ROLE now replay with each prepared statement's role
context. RESET ALL preserves the current role; rollback restores prior role state.
Policy authorization still examines original SQL and denies principal-changing
SQL on governed routes. Session authorization continues to retain affinity.

Run `virtual_state_check.py` on an isolated PostgreSQL database and a size-one
transaction route with cursor virtualization enabled. Its cases compare cursor
positions directly with PostgreSQL, verify simultaneous frontend ownership,
verify snapshot stability after independent table updates, exercise budget/type
fallback and extended rejection, and check native role/RLS isolation.

### Extended virtual cursor protocol

The opt-in snapshot feature now also implements PostgreSQL Parse, Bind, Describe,
Execute, Close, Flush and Sync for parameterless virtual FETCH/MOVE/CLOSE statements.
It emits ParseComplete/BindComplete/CloseComplete, ParameterDescription and typed
RowDescription/NoData at the appropriate protocol stages. Text and binary formats
can vary per column for the supported snapshot types, including NULL values.
Named prepared cursor statements survive Sync; portals are dropped at idle Sync.

Limited Execute delivers PortalSuspended chunks. Native comparison establishes
that the underlying SQL cursor advances across the requested FETCH on first
Execute; later Execute calls consume the portal's stored results. An exact-limit
chunk suspends even at the final row, requiring an additional empty Execute to
complete. FETCH CommandComplete counts the final Execute's rows. Completed FETCH
portals subsequently return FETCH 0; completed MOVE/CLOSE portals return error
55000 and ignore frames until Sync. Suspended portal rows share immutable snapshot
allocations and convert formats only for delivered chunks. Retained capacities
count toward the budget. A pre-execution portal budget failure rewinds the virtual
cursor and releases the rejected portal's row references.

Simple-query FETCH/MOVE/CLOSE also works inside explicit transactions: cursor
positioning and closing an already-held cursor remain nontransactional across
rollback, as PostgreSQL does. Extended virtual access inside explicit transactions,
parameters, and mixed physical/virtual extended cycles still fail closed with a
typed 0A000 response. A Sync boundary is required between physical and virtual
cycles. Automatically inserting Sync would commit physical writes before a later
virtual error; this is not an acceptable substitute for native atomicity.

`virtual_state_check.py` now compares binary formats, chunk counts, exact-limit
suspension, portal interleaving and error recovery with native PostgreSQL. It also
checks that rejected mixed cycles never emit reordered result packets.

### Closed-cursor safety and the native suspended-CLOSE defect

The `extended_closed_cursor_portal` case closes a virtual cursor through the
extended protocol while an earlier portal over that same cursor is still suspended.
**The tested PostgreSQL builds crash in the native equivalent of this sequence** —
issuing `CLOSE` on a cursor while a suspended extended portal still references it.
Because that native path is unsafe, the driver deliberately omits its native
comparison and instead asserts the proxy's own behavior directly.

This is a dependency risk, not a proxy feature gap. The proxy never forwards a
`CLOSE` (or any `FETCH`/`MOVE`) for a virtualized cursor to a backend:

- Simple-query and extended cursor statements are intercepted before forwarding
  (`virtual_cursor_request`, `CursorProtocol::handle`).
- A `CLOSE` is serviced locally and returns `CLOSE CURSOR` while the suspended
  portal retains its cached `RowDescription` and immutable snapshot rows.
- After the cursor is closed the portal still delivers its remaining rows,
  suspends at exact limits and completes; `Sync` then clears portals but keeps the
  prepared virtual statement.

The proxy-side sequence is locked in by the Rust unit test
`suspended_portal_survives_a_local_cursor_close_without_reaching_a_backend` and
by `extended_closed_cursor_portal` in `virtual_state_check.py`. Both exist
precisely because the native oracle is unavailable for this case. Any future
change that would route a virtual cursor `CLOSE` to a backend must be rejected:
on an affected server build it would crash the backend rather than return an
error. Re-enabling native differential comparison requires a PostgreSQL version
or patch level where the suspended-CLOSE path is confirmed fixed.

