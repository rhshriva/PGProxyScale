# The Design, Technically

A precise account of what the component is, why it is built this way, and where the
difficulty actually lies. No analogies — the protocol itself is the explanation.

---

## 1. What the component is

A PostgreSQL **wire-protocol proxy**. It accepts client connections, speaks protocol v3
(and v3.2), and multiplexes them onto a smaller set of backend connections.

```
   N clients  ──►  [ proxy ]  ──►  M backends        M << N
```

It is not an extension, not a fork of the server, and not in the query path as a library.
It is a separate process that terminates TCP on both sides and interprets the protocol.

---

## 2. Why multiplexing is necessary

Each PostgreSQL client connection is served by a dedicated backend **process**, not a
thread. Cost per connection:

```
   ~10 MB baseline RSS
   + work_mem (per sort/hash node, per query)
   + catalog caches, relcache, plancache
   + one entry in the proc array (a contention point)
   + scheduler pressure: N processes competing for C cores
```

So `max_connections = 1000` is not a knob you turn; it is a commitment to 1000 processes
and the contention that comes with them. Applications that open one connection per
request (serverless, or an ORM with a large pool) exhaust it immediately.

The proxy decouples **client concurrency** from **backend concurrency**. That is the
entire justification for the category, and it is a solved problem.

---

## 3. Pooling modes and the transaction boundary

Three modes, defined by when a backend is returned to the pool:

```
   session       backend bound for the client's whole session
   transaction   backend bound until the current transaction ends
   statement     backend bound until the current statement ends
```

**The transaction boundary is observable in the protocol.** Every command sequence ends
with `ReadyForQuery`:

```
   'Z' ReadyForQuery        payload: exactly one byte
                              'I'  idle              <- NOT in a transaction
                              'T'  in transaction
                              'E'  failed transaction
```

`I` is the release signal for transaction mode: the backend has no open transaction, so it
can be handed to another client.

### The extended query protocol is the complication

Simple query (`'Q'`) is self-contained: one message in, results and `ReadyForQuery` out.
The extended protocol is not:

```
   client -> backend                 backend -> client
   'P' Parse      ────────────────►  '1' ParseComplete
   'B' Bind       ────────────────►  '2' BindComplete
   'D' Describe   ────────────────►  'T' RowDescription
   'E' Execute    ────────────────►  'D' DataRow, 'C' CommandComplete
   'S' Sync       ────────────────►  'Z' ReadyForQuery     <- only here

   ReadyForQuery arrives AFTER Sync, not after each message.
```

This matters operationally: a proxy loop that forwards one client message and then waits
for `ReadyForQuery` will block forever on the second message, because the boundary it is
waiting for will not arrive until `Sync`. That is the defect in our current transaction
implementation, and why the relay must be bidirectional and concurrent rather than
request/response.

`COPY` has the same shape for a different reason: after `CopyInResponse` the client sends
an unbounded stream of `CopyData` messages, so both directions must be live at once.

---

## 4. The session-state problem

A PostgreSQL session is stateful, and the state lives in the **backend process** — not in
the protocol, not in the client. Returning a backend to a pool therefore either leaks that
state to the next client or destroys it.

The state surface, by category:

```
   GUCs — 406 total in PG18
     PGC_USERSET      154   set by any client
     PGC_SUSET         60   superuser only
     PGC_SIGHUP       101   config file
     PGC_POSTMASTER    64   restart
     others            27

   Non-GUC session state
     named prepared statements          session-scoped
     unnamed prepared statement         destroyed by next Parse OR any simple Query
     SQL-level PREPARE/EXECUTE          session-scoped
     portals and cursors                transaction-scoped, or session if WITH HOLD
     advisory locks                     pg_advisory_lock (session) vs _xact_lock
     LISTEN registrations               session-scoped
     temp tables and the pg_temp schema created lazily on first temp object
     SET ROLE / SET SESSION AUTHORIZATION
     search_path                        security-relevant
     row_security                       security-relevant
     currval/lastval                    session-local sequence state
     large-object descriptors           backend-local
```

Returning a backend without a reset means the next client inherits all of it. That is not
a performance bug; it is a correctness and tenant-isolation bug. `DISCARD ALL` is the blunt
reset — and it is precisely why prepared statements stop working under transaction pooling.

The two ways to get this wrong, both shipped in production by others:

```
   OVER-SHARE      return the backend with state intact     -> leak between clients
   UNDER-SHARE     pin the backend to the client indefinitely -> no multiplexing
                   and report nothing about it
```

---

## 5. Why passive observation cannot work

The obvious design is: watch the `ParameterStatus` messages the server sends, and mirror
whatever changed onto the next backend. It does not work, and not for want of effort.

```
   GUC_REPORT is the flag that makes the server push a value to the client.
   In PG18 exactly 15 GUCs carry it.  Five of those are server facts
   (server_version, server_encoding, integer_datetimes, in_hot_standby,
   is_superuser), leaving 10 that a client can set.

     154 client-settable GUCs
   -  10 that the server reports
   ------
     144 that are invisible to any proxy forever
```

`search_path` is one of them, and only became reportable in **PG18**. On PG14–17 there is
no protocol mechanism to observe a client's `search_path` at all — which is exactly the
mechanism behind the documented cross-tenant schema leak where `postgres_fdw` leaves
`search_path` modified and a transaction-mode pooler then resolves unqualified queries in
the wrong schema.

PgBouncer's `track_extra_parameters` is bounded by this same channel. It is not a
limitation of PgBouncer's implementation; the information is not on the wire.

**Therefore the proxy must derive session state from the client's own statements**, which
requires a real PostgreSQL parser (libpg_query — the server's own grammar), not a
pass-through and not a heuristic.

---

## 6. The design: a per-client session ledger

```
   For each client connection, maintain an explicit session state model.

   On checkout of a backend:
     diff the model against the backend's current state
     apply the difference as ONE batched round trip
       (a pipelined sequence of SET, or SET LOCAL where scope permits)

   On checkin:
     if the client owns state on that backend, either restore the previous
     owner's state or reset to a known-empty state
     record the delta
```

State is classified, and the classification is the design:

```
   A  virtualisable    record from the wire, replay on checkout
                       e.g. SET, search_path, SET ROLE, application_name
                       sub-flags:
                         parser-affecting  (9 GUCs)  mirror in our own parser
                         planner-affecting (63 GUCs) include in the plan-cache key

   B  emulatable       provide the semantics at the proxy, not the mechanism
                       advisory locks  -> lease with heartbeats, routed by lock key
                       LISTEN/NOTIFY   -> fan-out from few long-lived listeners
                       WITH HOLD       -> backend ownership for the cursor's lifetime
                       temp tables     -> per-client schema namespace where possible

   C  refuse           detect, report, and fail closed
                       currval/lastval, large-object descriptors,
                       PREPARE TRANSACTION, unknown extension GUCs
```

The invariant that makes it sound:

```
   A backend connection may carry session state across a transaction boundary
   only if the ledger says a specific client owns it. Otherwise it is reset.
```

**Why the taxonomy is not optional:** `standard_conforming_strings` and `backslash_quote`
change how SQL text tokenises. If a client sets one and the proxy does not mirror it in its
own parser, the proxy mis-parses the client's statements — a correctness bug now, and a
policy bypass once enforcement exists. libpg_query exposes exactly these switches, and
fingerprints change with them.

### Dependencies the ledger creates

```
   prepared statement registry
     keyed on (fingerprint, parameter type OIDs, relation OID set, rowtype version)
     invalidated by a DDL event stream
     anonymous Parse must be handled too: it is the driver default, and it is
     destroyed by the next Parse or by any simple Query

   DDL event stream
     logical decoding does NOT carry DDL, only row changes
     so it is synthesised from: the wire stream (we see every statement),
     server-side ddl_command_end event triggers, and catalog-fingerprint polling

   plan invalidation
     without it, ALTER TABLE produces
       ERROR: cached plan must not change result type
     whose only remedy today is draining the pooler
```

DDL-safe plan invalidation and zero-pinning multiplexing are the two capabilities no
shipping proxy has.

---

## 7. Authentication

A proxy authenticates in one of two ways, and the choice determines whether it works
against managed PostgreSQL.

### Passthrough (session mode)

The proxy relays the exchange opaquely.

```
   client                proxy                 backend
     |-- StartupMsg ---->|                      |
     |                   |-- StartupMsg ------->|
     |                   |<-- AuthenticationSASL|
     |<-- AuthenticationSASL                     |
     |-- SASLResponse -->|-- SASLResponse ----->|
     |                   |<-- AuthenticationOk --|
     |<-- AuthenticationOk                      |
     |=== relay everything thereafter ==========|
```

The proxy never holds a credential, because it never computes a proof. The SCRAM exchange
is bound to a server-generated nonce and salt, so relaying it verbatim means the client
authenticates **to the backend** through the proxy.

This is the answer to a documented problem: PgBouncer's own documentation records that
against providers which block `pg_authid`, it requires either a plaintext password or a
stored SCRAM verifier whose salt and iteration count match the server's exactly — because
a SCRAM verifier cannot be used to authenticate elsewhere by construction.

### Terminate (required for transaction pooling)

Transaction mode cannot relay authentication: the backend connection serving a query is
not the one the client logged in on. The proxy must hold **already-authenticated**
connections, so it must authenticate to the backend itself:

```
   client -- StartupMsg --> proxy
                             proxy authenticates to the backend
                             (trust | MD5 | SCRAM-SHA-256, with a credential)
                             proxy sends to the client:
                               AuthenticationOk
                               ParameterStatus x N   (the backend's real values)
                               BackendKeyData        (the proxy's own pid + key)
                               ReadyForQuery 'I'
```

The proxy is the server to the client and a client to the backend. This is a real
trade-off, and it is stated in the error rather than left for an operator to discover.

Cancellation is affected: `CancelRequest` arrives on a **separate connection** carrying the
`BackendKeyData` the client was issued. In transaction mode the proxy issues its own key
and must route the cancellation to whichever backend is bound at that moment. Protocol 3.2
(PG18) makes the key variable-length up to 256 bits, which breaks the fixed 12-byte
assumption every current implementation makes.

---

## 8. Policy enforcement

Application-layer allowlists are not a security boundary. CVE-2026-85620 (CVSS 9.2)
demonstrated it: a restricted-mode validator checked `FuncCall` AST nodes, so

```
   SELECT pg_read_file('/etc/passwd')           blocked
   SELECT * FROM pg_read_file('/etc/passwd')    executed, returned the file
```

because a function in a `FROM` clause parses as a `RangeFunction` node.

The proxy is the correct enforcement point because it observes plaintext SQL **below**
anything the client controls, with no privileges required — unlike eBPF, which sees
ciphertext at the socket layer and needs uprobes inside the server binary to recover query
text.

Enforcement operates on the parse tree, deny-by-default, covering `FROM`-clause functions,
CTEs, `DO` blocks, dynamic SQL in PL/pgSQL, and the file/network escape hatches
(`COPY … FROM PROGRAM`, `lo_import`, `dblink`, `postgres_fdw`).

---

## 9. Parsing strategy

Full parsing costs real time and most traffic does not need it, so the decision is per
message, in tiers:

```
   T0  no parse       ~18 ns     protocol state alone
                                 BEGIN/COMMIT/ROLLBACK by first keyword
   T1  classify       low        read vs write, pinning risk; prefix scan
   T2  full parse     2.5 us     policy, fingerprints, statement keys
                      to 333 us  libpg_query, cached by SQL hash
```

Measured: a T0 decision is **142×** cheaper than a full parse for a small statement, and
6 KB statements cost 333 µs each. So a parsed statement is parsed once and cached by
fingerprint, never per `Bind`/`Execute`.

Two findings from the spike worth recording because they contradict common assumptions:

```
   * libpg_query's protobuf API is 2-5x SLOWER than its JSON API
     (hand-written writer vs protobuf-c). Neither is the fast path: both
     serialise the tree. Direct access to the raw C tree needs a shim, which
     is why PgDog maintains a separate crate for it.

   * Tree size amplifies ~8.5x over query size
     (a 1.3 MB statement produced a 10.9 MB tree), so parse-cache memory must
     be budgeted per principal rather than assumed proportional to input.
```

---

## 10. Threading and state ownership

```
   one thread per core, each owning:
     its own SO_REUSEPORT listener
     its own slice of pooled backend connections
     its own parse and fingerprint caches
   one thread per connection for the data path
   cross-core coordination only in the control plane:
     metrics aggregation, config reload, admin surface
```

Chosen on measurement, not preference. A pass-through relay against PgBouncer:

```
   TPS                      c=1     c=4    c=16     c=64
   --------------------------------------------------------
   PgBouncer              9,486  34,347  70,253   71,183   single-threaded ceiling
   Tokio, work-stealing   9,563  33,919  91,013   93,625   plateaus
   thread-per-core        9,678  33,049 107,599  215,827   scales
   splice(2) bypass       9,808  32,518 109,345  217,867   no gain over copying
```

Two conclusions: the **runtime**, not the language, was the variable; and zero-copy bought
nothing, so the data path stays simple userspace copying.

One consequence must be handled deliberately: because each core owns its own pool, pool
limits are per-core. PgBouncer's `so_reuseport` workaround has exactly this weakness — its
pool limits are not shared across processes. Admission control here must therefore be a
global decision enforced per core.

---

## 11. Current status

```
   implemented
     wire protocol: framing, startup, SSLRequest, v3.0/v3.2, CancelRequest parsing
     authentication: SCRAM-SHA-256 both directions, MD5, passthrough validated
                     against real libpq
     session mode: relay, one backend per client, 17/17 conformance scenarios
     backend connector: proxy as a protocol client (trust, MD5, SCRAM)
     connection pool: RAII checkout, LIFO reuse, bounded wait, dead-connection eviction

   implemented but incomplete
     transaction pooling: correct for self-contained requests, but the relay is
     request/response and therefore deadlocks on the extended query protocol and COPY.
     Fix is a concurrent bidirectional relay with the transaction boundary detected on
     the backend-to-client direction.

   not started
     session-state ledger      <- the differentiator
     policy enforcement
     per-principal fairness and attribution
     TLS
     cancellation routing (needs ADR-0007)
```

The honest summary: everything implemented so far is substrate that PgBouncer also has.
The ledger is where the product begins.
