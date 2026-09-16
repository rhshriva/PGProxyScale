# Conformance harness

Validates that a PostgreSQL endpoint behaves correctly at the wire-protocol level, using
real client drivers rather than hand-rolled messages.

**Run it against direct PostgreSQL first.** If the harness cannot pass against a correct
server, its verdict on the proxy means nothing — so the control run is the first thing CI
does.

```sh
./run.sh                        # control: direct PostgreSQL 18
TARGET=pgproxy:6432 ./run.sh    # against the proxy
PG_VERSION=17 ./run.sh          # a different server major
ONLY=cursor ./run.sh            # one scenario
```

## Why these scenarios

Every scenario targets something the research identified as fragile under connection
pooling. They are not a general SQL test suite; they are the specific behaviours that
poolers are known to break.

| Scenario | What it guards |
|---|---|
| `connect_and_select` | Baseline connectivity |
| `simple_protocol_multi_statement` | The simple-query path, which PgBouncer can only disable wholesale |
| `extended_protocol_params` | Server-side parameter binding |
| `unnamed_prepared_reuse` | The driver-default `Parse` path — destroyed by the next `Parse` or any simple `Query`, and cached by only one pooler today |
| `named_prepared_server_side` | The `cached plan must not change result type` failure class |
| `sql_level_prepare_execute` | Session state PgBouncer forwards blind |
| `transaction_commit` / `transaction_rollback` | Transaction boundaries survive multiplexing |
| `error_then_continue` | Error → skip-to-`Sync` recovery |
| `session_guc_roundtrip` | The *easy* session-state case (a reported GUC) |
| `search_path_roundtrip` | The *hard* case — unreportable before PostgreSQL 18, and the mechanism behind the cross-tenant schema leak |
| `cursor_with_hold` | Session-scoped cursors |
| `advisory_lock` | Session advisory locks |
| `listen_notify` | Persistent `LISTEN` registration |
| `large_result_set` | Buffering far beyond one packet |
| `copy_from_stdin` | `CopyData` framing passthrough |
| `concurrent_clients` | Correctness under 16 parallel clients |

Several of these are **expected to fail under transaction pooling until Phase 1 lands**.
That is the point: they are the Phase 1 acceptance tests, written before the
implementation so that "done" is defined by behaviour rather than by opinion.

## Scope and limits

- One driver so far (**psycopg3**). The M0 milestone calls for a second
  (node-postgres); `drivers/` is structured so adding one is a new file plus a line in
  `run.sh`.
- Scenarios assert on correctness, not performance. Latency and percentiles belong to the
  benchmark suite (`benches/`), not here.
- PostgreSQL 18 is the primary target. The matrix is driven by `PG_VERSION`, and the
  plan is to run 16–18 in CI once a second driver lands.
