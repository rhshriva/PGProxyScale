# The Design, Explained

A guide to explaining what this is, why it is shaped this way, and what is different about
it. Diagrams are plain ASCII so they survive any medium: a terminal, a slide, a PR, a
README.

---

## 1. The sixty-second version

> PostgreSQL connection poolers solved the easy problem in 2007. They multiplex
> connections, they are free, and they are fast enough. What they did not solve is
> **correctness**: in transaction mode they silently break prepared statements, `LISTEN`,
> advisory locks, cursors and `search_path`; one of them even leaks session state between
> tenants. The managed answer is to pin sessions invisibly, which defeats the pooling and
> cannot be measured.
>
> We are building a proxy that fixes the correctness problem instead of documenting it,
> enforces security policy at the wire where it cannot be bypassed, and tells you which
> tenant or agent caused a query.

Three differentiators, in the order we build them:

| | What it is | Status |
|---|---|---|
| 1 | **Session-State Ledger** — make transaction pooling safe for stateful apps | not started |
| 2 | **Protocol-enforced policy** — unbypassable SQL policy | not started |
| 3 | **Per-principal fairness and attribution** | not started |

Everything built so far is the substrate these sit on.

---

## 2. The problem: what actually breaks today

### 2.1 Multiplexing is solved

```
   WITHOUT A POOLER                       WITH A POOLER
   1000 app connections                   1000 app connections
     |  |  |  |  ...                        |  |  |  |  ...
     v  v  v  v                             v  v  v  v
   +----------------+                    +---------------+
   |   PostgreSQL   |                    |    pgproxy    |
   | max_connections|                    +-------+-------+
   |     = 100      |                            |  20 real connections
   |                |                            v
   | 900 clients    |                    +----------------+
   | get "too many  |                    |   PostgreSQL   |
   |  clients"      |                    +----------------+
   +----------------+
```

This part is a solved, commodity problem. We are not trying to win here.

### 2.2 The pooling that fixes it breaks your application

```
   TRANSACTION MODE: the connection is given back after every transaction
   =====================================================================

     client                          pgproxy                   backends
       |                                |                    [B1] [B2] [B3]
       |-- PREPARE find AS ... -------->|                         |
       |                                |  ...transaction ends...  |
       |                                |---------- return B1 ---->|
       |                                |                          |
       |-- EXECUTE find(42) ----------->|                          |
       |                                |<-- check out B3 ---------|
       |                                |                          |
       |<-- ERROR: prepared statement "find" does not exist -------|
```

The session state that the client believed it owned was destroyed by the thing that made
the connection reusable. Every pooler's feature matrix lists these as unsupported:

```
   session mode      transaction mode
   ------------      ----------------
   SET           ✓        ✗
   LISTEN        ✓        ✗
   advisory lock ✓        ✗
   temp table    ✓        ✗
   WITH HOLD     ✓        ✗
   PREPARE       ✓        ✗  (or "works" until a schema change)
```

So the choice every operator faces is: **multiplex, or be correct.** We think that is a
false choice, and removing it is the product.

### 2.3 The managed answer is worse

```
   PINNING (AWS RDS Proxy, and PgDog for advisory locks)
   =====================================================

     A ---\
     B ----\
     C -----+--> pgproxy --> [B1][B2][B3] ... [B10] --> PostgreSQL
     D ----/                     ^
     Z ---/                      |
                                +-- client C ran:  SET search_path = tenant_c;
                                    the proxy can no longer reuse this connection
                                    for anyone else. It is C's until C disconnects.

   Ten tenants do this  ->  the pool is gone.
   Nobody is told. There is no "pinned" metric. The only symptom is
   "sorry, too many clients already", with nothing in the logs explaining why.
```

That last paragraph is the single most-repeated complaint in our research. Our own
transaction-mode bug reproduced the same signature — `total=20 idle=0`, no explanation —
which is why pool-state logging is now permanent.

---

## 3. Where we sit

```
   LAYER                          WHO                          STATUS
   ---------------------------------------------------------------------------
   L4  agent / MCP gateways       postgres-mcp, ORMs           security collapsed
                                                                 (CVE-2026-85620)
   L3  managed data-access edge   RDS Proxy, Hyperdrive,       locked to clouds,
                                  Neon, Supabase               deliberately shallow
   L2  routing / sharding         PgDog, Multigres, SPQR,       contested by two
                                  Citus                        funded teams
   L1  wire-protocol pooling      PgBouncer, pg_doorman,       commodity
                                  Odyssey, pgagroal, PgCat
   ---------------------------------------------------------------------------
   >> we sit across L1-L2 with the correctness and policy that L3
      will not build and L1 cannot
```

We deliberately do **not** lead with L2 (sharding): it is the hardest correctness problem
in the space and two funded teams are already fighting there.

---

## 4. The architecture

```
   clients:  psycopg · pgx · JDBC · node-postgres · Rails · agents
      |
      |   PostgreSQL wire protocol  (v3 / v3.2)
      v
   ==========================================================================
    pgproxy                                       one process, one binary
   --------------------------------------------------------------------------
      one thread per CPU   (SO_REUSEPORT, per-core state, no shared accept lock)

        worker 0            worker 1            worker N
            \                   |                   /
             +------------------+------------------+
                                |
                       one thread per connection
                                |
        +-----------+-----------+-----------+-----------+
        |           |           |           |           |
      wire       parser      session      policy       pool
      codec      T0/T1/T2    LEDGER       engine     checkout
      +state     classify    (Phase 1)   (Phase 2)   (W4)
        |           |           |           |           |
      built     built        NEXT        Phase 2     built
                                ^
                                |
                       this is the differentiator
   ==========================================================================
      |
      v
   PostgreSQL 14 · 15 · 16 · 17 · 18
```

### Why thread-per-core and thread-per-connection

Not a preference — a measurement. Spike S1 put a pass-through relay against PgBouncer and
against a work-stealing async runtime:

```
   TPS, higher is better            c=1      c=4     c=16     c=64
   ---------------------------------------------------------------------
   PgBouncer (single process)      9,486   34,347   70,253   71,183   <- flat
   Rust + Tokio (work-stealing)    9,563   33,919   91,013   93,625   <- plateaus
   Rust + thread-per-core          9,678   33,049  107,599  215,827   <- scales
   Rust + splice(2) zero-copy      9,808   32,518  109,345  217,867   <- no gain
```

Two conclusions that shaped everything:

1. **The runtime, not the language, was the variable.** Tokio flattened at ~92k while
   thread-per-core kept scaling under an identical harness.
2. **The zero-copy bypass earns nothing.** `splice(2)` tied with plain userspace copying,
   so the data path stays simple and auditable. The most exciting item on the roadmap was
   dropped on evidence.

---

## 5. Authentication: the design decision that matters most

A proxy can authenticate in two ways, and the choice decides whether it works against
managed PostgreSQL at all.

### Mode A — passthrough (session pooling)

The proxy relays the exchange without understanding it. It never learns the password or
the verifier, because it never computes anything.

```
     client                    pgproxy                   postgres
        |                         |                         |
        |-- Startup(user, db) --->|                         |
        |                         |-- Startup(user, db) --->|
        |                         |                         |
        |                         |<-- AuthenticationSASL --|
        |<-- AuthenticationSASL --|                         |
        |                         |                         |
        |-- SASLResponse(proof) ->|-- SASLResponse(proof) ->|
        |                         |                         |
        |                         |<-- AuthenticationOk ----|
        |<-- AuthenticationOk ----|                         |
        |                         |                         |
        |== now relay everything, both directions ==========|

     The proxy sees a proof it cannot use and a challenge it did not create.
     It needs no secret. Verified end to end against real libpq.
```

**Why this matters:** PgBouncer's own documentation records the alternative's cost —
against providers that block `pg_authid`, it needs the password in plaintext, and a SCRAM
verifier cannot be reused because it is bound to the server's salt and iteration count.
Passthrough sidesteps that entirely.

### Mode B — terminate (required for transaction pooling)

```
     client                    pgproxy                   postgres
        |                         |                         |
        |-- Startup ------------> |                         |
        |                         |== proxy authenticates ==|
        |<-- AuthenticationOk ----|    with its own        |
        |<-- ParameterStatus x15 -|    credential           |
        |<-- BackendKeyData ------|                         |
        |<-- ReadyForQuery -------|                         |
        |                         |                         |
        |== client now talks to the proxy, which talks to a pool ==|
```

Transaction pooling **cannot** relay authentication, because the connection serving a
query is not the one the client logged in on. The proxy must hold connections that are
*already authenticated*, so it must authenticate to the backend itself — which means a
credential. That is a genuine trade-off, and the error message says so rather than
confusing the operator:

```
   the backend requires a password for role "postgres" but none is configured;
   transaction pooling needs a backend credential, unlike session-mode passthrough
```

---

## 6. The connection lifecycle

```
   accept
     |
     v
   +----------------+   SSLRequest? --> reply 'N' (TLS not implemented) --> retry
   |    STARTUP     |
   |  read packet   |   CancelRequest? --> not routed yet (ADR-0007) --> close
   +--------+-------+
            |  Startup(user, db, options...)
            v
   +----------------+   lookup db in config
   |     ROUTE      |   absent `database` means "the username"  (PostgreSQL's rule)
   +--------+-------+   unknown db --> FATAL 3D000, close
            |
            v
   +----------------+----------------+
   |  SESSION MODE  |  TRANSACTION   |
   |                |     MODE       |
   +--------+-------+--------+-------+
            |                |
   connect, forward     check out a pooled connection
   startup, relay       handshake with the client as server
   both directions      then bind a backend per transaction
            |                |
            v                v
   +--------------------------------+
   |            RELAY               |
   |  client --> backend            |
   |  backend --> client            |   ReadyForQuery tells us the
   |  read transaction state from   |   transaction boundary: 'I' 'T' 'E'
   |  the ReadyForQuery status byte |
   +--------------------------------+
```

Every phase has a deliberate refusal path. TLS answers `N` honestly rather than
pretending; an unroutable database gets a real PostgreSQL error; cancellation is refused
rather than silently doing nothing, because a no-op cancellation is worse than a reported
one.

---

## 7. The data path: not every message needs parsing

A proxy that parses every statement loses the benchmark. Ours decides per message:

```
   T0  no parse        ~18 ns      transaction control, protocol plumbing
       |                            (BEGIN/COMMIT/ROLLBACK by first keyword,
       |                             everything else by protocol state alone)
       |
   T1  classify        very low    read vs write, pinning risk
       |                            prefix scan, no AST
       |
   T2  full parse      2.5 us      policy, fingerprinting, statement keys
       |                to 333 us     (libpg_query, cached by hash)
       |
       +-- parsed ONCE per unique statement, never per Bind/Execute
```

Measured: a T0 decision is **142x cheaper** than a full parse for a small statement, and
`libpg_query`'s own JSON API is 4x faster than its protobuf one — which corrected an
assumption in our own ADR.

---

## 8. The differentiator: the Session-State Ledger

This is the part nobody has built. It is why the product exists.

### 8.1 The idea

```
   WITHOUT A SESSION-STATE LEDGER
   ==============================

     client                 pgproxy                 backends
       |                       |                [B1] search_path = public
       |-- SET search_path --->|                [B2] search_path = public
       |     = tenant_a        |
       |                       |   (the proxy has nowhere to put this)
       |-- SELECT * FROM ----->|
       |      orders           |------------------> [B2]
       |                       |                    resolves to public.orders
       |<-- rows from public.orders ---------------|
       |                                            WRONG SCHEMA. Silent. Possibly
       |                                            another tenant's data.


   WITH A SESSION-STATE LEDGER
   ===========================

     client                 pgproxy                 backends
       |                       |                [B1] search_path = public
       |-- SET search_path --->|                [B2] search_path = public
       |     = tenant_a        |
       |                       +--> ledger[this client] = { search_path: tenant_a }
       |                       |
       |-- SELECT * FROM ----->|
       |      orders           |-- SET LOCAL search_path = tenant_a;
       |                       |   SELECT * FROM orders;  ----------> [B2]
       |                       |                    resolves to tenant_a.orders
       |<-- correct rows ------|
```

### 8.2 The insight that makes it tractable

Every pooler asks the server what changed. That cannot work:

```
   PG18 has 406 GUCs.  154 are client-settable.  Only 15 are ever REPORTED
   back to the client.  So 144 of them are invisible to a pooler forever.

   PgBouncer's `track_extra_parameters` can only track what PostgreSQL
   volunteers. That is not a bug in PgBouncer. The channel does not carry
   the information. No configuration fixes it.
```

So the ledger records **what the client asked for**, parsed from the wire — not what the
server chose to report. That inversion is the whole trick, and it is why the proxy needs a
real PostgreSQL parser rather than a relay.

### 8.3 One primitive, six symptoms

Each of these looks like a separate bug in every pooler's issue tracker. They are the same
missing thing:

```
     SYMPTOM                          SAME PRIMITIVE: per-client state, replayed
     ---------------------------------------------------------------------------
     prepared statements fail      ->  statement registry, re-prepared on demand
     "cached plan must not         ->  invalidate on DDL, re-Parse transparently
       change result type"
     search_path leaks             ->  replay the client's value onto the backend
     advisory locks die            ->  a lease, routed by lock key
     LISTEN never fires            ->  fan-out from a few long-lived listeners
     temp tables vanish            ->  per-client namespace, or reported pinning
     DISCARD ALL costs a trip      ->  replay only the diff, in one batched round trip
     per-tenant unfairness         ->  the same ledger tells you who holds what
```

### 8.4 The safety property

```
   A server connection may carry session state across a transaction boundary
   ONLY IF the ledger says one specific client owns it.

   Otherwise it is returned to a fully reset state.

   Unclassifiable state is REFUSED with a specific error — never guessed,
   never silently leaked. (pgagroal leaks; that is the anti-pattern.)
```

---

## 9. Policy enforcement: why a proxy, not middleware

```
   CVE-2026-85620   CVSS 9.2
   =========================
     A "safe mode" allowlist in an MCP server checked FuncCall AST nodes.
     A function in a FROM clause parses as a RangeFunction node.

        SELECT pg_read_file('/etc/passwd')          -> blocked
        SELECT * FROM pg_read_file('/etc/passwd')   -> returned the file

     The lesson is architectural, not a coding error:

        middleware an attacker can influence is not a security boundary.

                  app-layer allowlist            wire-level enforcement
                  ------------------             ---------------------
                  sits above the thing           sits below everything
                  being untrusted                the client controls
                  parser gaps = bypass           deny by default
                  can be prompt-injected         cannot be talked around
```

A protocol-aware proxy sees plaintext SQL with no extra privileges — which is also why
eBPF cannot replace it (socket-level tracing sees ciphertext and needs root uprobes in the
server binary).

---

## 10. Invariants worth quoting

These are the sentences that carry the design. They are testable, which is why they are
the gates:

```
   * A checked-out connection always comes back.
     (RAII. A panicking session must not starve the pool.)

   * A dead connection is never handed out.

   * A client never observes another client's session state.

   * Unclassifiable session state is refused, never guessed.
     (Fail closed. A wrong answer is worse than an error.)

   * Nothing is dropped: a startup parameter we do not understand is
     still the client's state.

   * Never pin silently. Pinning that cannot be measured is
     indistinguishable from a bug.
```

---

## 11. How to explain it at three lengths

### 60 seconds
Use §1 verbatim.

### 5 minutes
§1, then §2.2 (the `PREPARE` break) and §2.3 (pinning), then §8.1 (the ledger diagram).
The arc is: *pooling is solved; the pooling that works breaks your app; the managed fix is
invisible and unmeasurable; here is the mechanism that makes it correct instead.*

### 30 minutes
Add §4 (architecture and why thread-per-core), §5 (passthrough — the design decision that
makes managed PostgreSQL work at all), §8.2 (why the server cannot tell you what changed),
and §9 (why enforcement belongs at the wire).

### Questions you will be asked

**"Isn't this just PgBouncer?"**
PgBouncer multiplexes and is excellent at it. It documents session breakage as "Never
supported". We treat that as the bug to fix. Roughly 90% of what we have built so far *is*
PgBouncer-shaped — that is the substrate; the ledger is the product.

**"Why not fix PgBouncer?"**
Its model asks the server what changed, and the server cannot answer for 144 of the 154
client-settable GUCs. The fix is an inversion, not a patch: track what the client asked
for, which needs a real parser and a state model threaded through the data path.

**"Won't the database vendors just bundle this?"**
They have so far shipped the shallow version — pinning, TTL caches that never invalidate.
The research also shows the risk is real: PolyScale sold transparent Postgres caching and
was absorbed. That is why the ledger is a *feature of a product whose core is policy and
correctness*, not a standalone caching proxy.

**"Why not just use session mode?"**
It does not multiplex, which is the entire reason to run a pooler.

**"What is the moat?"**
Correctness that is measurable (pinning ratio → 0), a parser-and-policy engine that
compounds into policy libraries per framework, and attribution data that becomes the
system of record for database spend.

**"What is the biggest risk?"**
That we rebuild PgBouncer and never reach the ledger. The mitigation is sequencing: the
relay is the last substrate item, and the ledger is next.
