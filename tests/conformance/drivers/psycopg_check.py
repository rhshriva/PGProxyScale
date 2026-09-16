#!/usr/bin/env python3
"""PostgreSQL wire-protocol conformance scenarios, driven by psycopg3.

Design intent
-------------
This harness must pass against a *correct* server before it is pointed at anything
else. A harness that fails against direct PostgreSQL cannot distinguish "the proxy
broke this" from "this scenario was written wrong", so the control run is the first
thing CI does.

Every scenario is a deliberate test of something the research identified as fragile
under connection pooling. Where a scenario is expected to break once transaction
pooling arrives, the docstring says so — those are the Phase 1 acceptance tests, not
bugs in the harness.
"""

from __future__ import annotations

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

import psycopg
from psycopg import pq

SCENARIOS: list[tuple[str, Callable[[argparse.Namespace], None]]] = []


def scenario(fn: Callable[[argparse.Namespace], None]) -> Callable[[argparse.Namespace], None]:
    SCENARIOS.append((fn.__name__, fn))
    return fn


def connect(args: argparse.Namespace, **kwargs):
    """Open a connection to the target under test."""
    kwargs.setdefault("connect_timeout", 10)
    if args.password:
        kwargs.setdefault("password", args.password)
    return psycopg.connect(
        host=args.host,
        port=args.port,
        user=args.user,
        dbname=args.dbname,
        **kwargs,
    )


# --------------------------------------------------------------------------- basics


@scenario
def connect_and_select(args):
    """A connection can be established and a trivial query executed."""
    with connect(args, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            assert cur.fetchone() == (1,), "SELECT 1 did not return 1"


@scenario
def simple_protocol_multi_statement(args):
    """The simple query protocol accepts several statements in one message.

    Exercises the simple-query path directly, which a proxy must support and which
    PgBouncer can only disable wholesale (`disable_pqexec`).
    """
    with connect(args, autocommit=True) as conn:
        res = conn.pgconn.exec_(b"SELECT 1; SELECT 2;")
        assert res.status == pq.ExecStatus.TUPLES_OK, f"unexpected status {res.status}"
        assert res.get_value(0, 0) == b"2", f"expected the last result, got {res.get_value(0, 0)!r}"


@scenario
def extended_protocol_params(args):
    """The extended query protocol binds parameters server-side."""
    with connect(args, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT %s::int + %s::int", (2, 3))
            assert cur.fetchone() == (5,), "parameter binding produced the wrong result"


@scenario
def unnamed_prepared_reuse(args):
    """The same unnamed statement is executed repeatedly with different parameters.

    Unnamed `Parse` is the driver-default path. It is destroyed by the next `Parse` and
    by any simple `Query`, and only pg_doorman caches it today.
    """
    with connect(args, autocommit=True) as conn:
        with conn.cursor() as cur:
            for i in range(5):
                cur.execute("SELECT %s::int * 2", (i,), prepare=False)
                assert cur.fetchone() == (i * 2,), f"iteration {i} returned the wrong value"


@scenario
def named_prepared_server_side(args):
    """A named server-side prepared statement is reused across executions.

    This is the scenario behind `ERROR: cached plan must not change result type`: the
    same statement text is prepared once and executed with different parameters, so a
    pooler must make the prepared statement available on whichever backend is attached.
    """
    with connect(args, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT %s::int + 1", (1,), prepare=True)
            assert cur.fetchone() == (2,)
            cur.execute("SELECT %s::int + 1", (41,), prepare=True)
            assert cur.fetchone() == (42,), "reusing the prepared statement gave a wrong result"


@scenario
def sql_level_prepare_execute(args):
    """SQL-level `PREPARE` / `EXECUTE` within one session.

    Session state. PgBouncer forwards these blind — it tracks only protocol-level
    prepared statements.
    """
    with connect(args, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("PREPARE conf_p1 AS SELECT $1::int * 2")
            cur.execute("EXECUTE conf_p1(21)")
            assert cur.fetchone() == (42,), "EXECUTE returned the wrong value"
            cur.execute("DEALLOCATE conf_p1")


# ---------------------------------------------------------------------- transactions


@scenario
def transaction_commit(args):
    """A committed write is visible to a later statement on the same connection."""
    with connect(args) as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO conformance_probe(id) VALUES (1)")
            conn.commit()
            cur.execute("SELECT count(*) FROM conformance_probe WHERE id = 1")
            assert cur.fetchone()[0] == 1, "committed row is not visible"
            cur.execute("DELETE FROM conformance_probe WHERE id = 1")
            conn.commit()


@scenario
def transaction_rollback(args):
    """A rolled-back write is not visible."""
    with connect(args) as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO conformance_probe(id) VALUES (999)")
            conn.rollback()
            cur.execute("SELECT count(*) FROM conformance_probe WHERE id = 999")
            assert cur.fetchone()[0] == 0, "rolled-back row is visible"


@scenario
def error_then_continue(args):
    """After a statement error the session recovers and serves the next query.

    Exercises the error -> skip-to-`Sync` recovery path, which a proxy must reproduce
    exactly rather than resynchronising incorrectly.
    """
    with connect(args) as conn:
        with conn.cursor() as cur:
            try:
                cur.execute("SELECT 1/0")
                raise AssertionError("expected a division-by-zero error")
            except psycopg.errors.DivisionByZero:
                conn.rollback()
            cur.execute("SELECT 7")
            assert cur.fetchone() == (7,), "session did not recover after an error"


# -------------------------------------------------------------------- session state


@scenario
def session_guc_roundtrip(args):
    """`SET` then `SHOW` on the same connection.

    The canonical class-A session-state test. `application_name` is one of the ten
    client-settable GUCs PostgreSQL actually reports, so this is the *easy* case.
    """
    with connect(args, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SET application_name = 'conformance-guc'")
            cur.execute("SHOW application_name")
            assert cur.fetchone()[0] == "conformance-guc", "application_name did not stick"


@scenario
def search_path_roundtrip(args):
    """`SET search_path` then `SHOW search_path`.

    The hard case. `search_path` only became reportable in PostgreSQL 18, so on 14-17 a
    pooler has no protocol mechanism to observe it at all — which is the mechanism
    behind the documented cross-tenant schema leak.
    """
    with connect(args, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SET search_path TO pg_catalog, public")
            cur.execute("SHOW search_path")
            value = cur.fetchone()[0]
            assert "pg_catalog" in value, f"search_path did not stick: {value!r}"


@scenario
def cursor_with_hold(args):
    """A `WITH HOLD` cursor survives `COMMIT`.

    Session-scoped by definition, and listed as session-pooling-only by every pooler
    feature matrix.
    """
    with connect(args) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DECLARE conf_c CURSOR WITH HOLD FOR SELECT g FROM generate_series(1, 10) g"
            )
            conn.commit()
            cur.execute("FETCH 3 FROM conf_c")
            rows = cur.fetchall()
            assert len(rows) == 3, f"expected 3 rows from the held cursor, got {len(rows)}"
            cur.execute("CLOSE conf_c")
            conn.commit()


@scenario
def advisory_lock(args):
    """Session advisory locks acquire and release."""
    with connect(args, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(4242)")
            cur.execute("SELECT pg_advisory_unlock(4242)")
            assert cur.fetchone() == (True,), "advisory lock was not held by this session"


@scenario
def listen_notify(args):
    """`LISTEN` on one connection receives a `NOTIFY` from another.

    Requires a persistent `LISTEN` registration, which transaction pooling drops. Today
    the documented answer is a second, session-mode pool.
    """
    with connect(args, autocommit=True) as listener, connect(args, autocommit=True) as sender:
        with listener.cursor() as lcur:
            lcur.execute("LISTEN conf_chan")
        with sender.cursor() as scur:
            scur.execute("NOTIFY conf_chan, 'payload-1'")
        notification = next(listener.notifies(timeout=10, stop_after=1))
        assert notification.payload == "payload-1", f"got payload {notification.payload!r}"


# ------------------------------------------------------------------------- bulk paths


@scenario
def large_result_set(args):
    """A result set far larger than any single buffer is delivered intact."""
    with connect(args, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT g, repeat('x', 100) FROM generate_series(1, 50000) g")
            rows = cur.fetchall()
            assert len(rows) == 50000, f"expected 50000 rows, got {len(rows)}"
            assert rows[-1][0] == 50000, "last row is wrong"


@scenario
def copy_from_stdin(args):
    """`COPY ... FROM STDIN` round-trips.

    Uses `CopyData` framing, which a proxy should pass through without buffering the
    whole stream.
    """
    with connect(args) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE TEMP TABLE conf_copy(id int, name text)")
            with cur.copy("COPY conf_copy (id, name) FROM STDIN") as copy:
                for i in range(1000):
                    copy.write_row((i, f"row{i}"))
            cur.execute("SELECT count(*), max(id) FROM conf_copy")
            count, max_id = cur.fetchone()
            assert count == 1000, f"expected 1000 copied rows, got {count}"
            assert max_id == 999, f"expected max id 999, got {max_id}"
        conn.rollback()


@scenario
def concurrent_clients(args):
    """Sixteen clients querying in parallel all get correct answers."""
    def worker(n: int) -> None:
        with connect(args, autocommit=True) as conn:
            with conn.cursor() as cur:
                for _ in range(20):
                    cur.execute("SELECT %s::int", (n,))
                    assert cur.fetchone() == (n,), f"client {n} got a wrong result"

    with ThreadPoolExecutor(max_workers=16) as pool:
        # Raises the first worker exception, if any.
        list(pool.map(worker, range(16)))


# --------------------------------------------------------------------------- runner


def bootstrap(args: argparse.Namespace) -> None:
    """Create the probe table used by the transaction scenarios."""
    with connect(args, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS conformance_probe(id int)")
            cur.execute("DELETE FROM conformance_probe")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--dbname", default="conformance")
    parser.add_argument("--label", default="target")
    parser.add_argument(
        "--password",
        default=None,
        help="password to authenticate with, if the endpoint requires one",
    )
    parser.add_argument("--only", default=None, help="substring filter on scenario name")
    args = parser.parse_args()

    try:
        bootstrap(args)
    except Exception as exc:  # noqa: BLE001 - report and fail, do not traceback-spam
        print(f"FATAL: cannot reach {args.host}:{args.port} ({type(exc).__name__}: {exc})")
        return 2

    results: list[tuple[str, str, float, str]] = []
    for name, fn in SCENARIOS:
        if args.only and args.only not in name:
            continue
        started = time.perf_counter()
        try:
            fn(args)
            results.append((name, "PASS", time.perf_counter() - started, ""))
        except Exception as exc:  # noqa: BLE001 - a scenario failure is data, not a crash
            detail = f"{type(exc).__name__}: {exc}".replace("\n", " ")[:160]
            results.append((name, "FAIL", time.perf_counter() - started, detail))

    print(f"\n=== conformance: {args.label} ({args.host}:{args.port}) ===")
    print(f"{'scenario':<32} {'result':<6} {'ms':>8}  detail")
    print(f"{'-' * 32} {'-' * 6} {'-' * 8}  {'-' * 40}")
    for name, result, elapsed, detail in results:
        print(f"{name:<32} {result:<6} {elapsed * 1000:>8.1f}  {detail}")

    passed = sum(1 for r in results if r[1] == "PASS")
    failed = len(results) - passed
    print(f"\n{passed} passed, {failed} failed, {len(results)} total")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
