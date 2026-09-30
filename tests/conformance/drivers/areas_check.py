#!/usr/bin/env python3
"""Live acceptance for authentication, cancellation and ledger backend handoff.

Requires transaction route pool_size=1, a session route and a SCRAM route.
Runs against an isolated test database. Passwords come from the environment.
"""
import argparse
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import psycopg


def connect(args, database, **kwargs):
    return psycopg.connect(host=args.host, port=args.port, user=args.user,
                           dbname=database, sslmode="disable", connect_timeout=5,
                           autocommit=True, **kwargs)


def scalar(conn, sql, params=None, **kwargs):
    return conn.execute(sql, params, **kwargs).fetchone()[0]


def handoff(args):
    # Alternation over a size-one pool proves reuse while both clients stay open.
    with connect(args, args.transaction) as a, connect(args, args.transaction) as b:
        pid = scalar(a, "SELECT pg_catalog.pg_backend_pid()")
        assert scalar(b, "SELECT pg_catalog.pg_backend_pid()") == pid
        a.execute("SET application_name = 'ledger-a'")
        b.execute("SET application_name = 'ledger-b'")
        for _ in range(8):
            for conn, label in [(a, "ledger-a"), (b, "ledger-b")]:
                assert scalar(conn, "SELECT pg_catalog.current_setting('application_name')") == label
                assert scalar(conn, "SELECT pg_catalog.pg_backend_pid()") == pid
                assert scalar(conn, "SELECT %s::int + 1", (41,), prepare=True) == 42
        a.execute("PREPARE area_sql(int) AS SELECT $1 + 2")
        assert scalar(b, "SELECT pg_catalog.pg_backend_pid()") == pid
        assert scalar(a, "EXECUTE area_sql(40)") == 42
        try:
            b.execute("EXECUTE area_sql(40)")
        except psycopg.errors.InvalidSqlStatementName:
            pass
        else:
            raise AssertionError("prepared statement leaked into the other client")


def cancellation(args, route):
    with connect(args, route) as conn:
        started = threading.Event()

        def sleeping_query():
            started.set()
            try:
                conn.execute("SELECT pg_catalog.pg_sleep(8)")
            except psycopg.errors.QueryCanceled as error:
                assert error.sqlstate == "57014"
                return
            raise AssertionError("query did not cancel")

        with ThreadPoolExecutor(max_workers=1) as executor:
            before = time.monotonic()
            job = executor.submit(sleeping_query)
            assert started.wait(2)
            time.sleep(0.25)
            conn.cancel()
            job.result(timeout=4)
            assert time.monotonic() - before < 5
        assert scalar(conn, "SELECT 42") == 42
        # An idle cancellation must not affect the next client to reuse the pool.
        conn.cancel()
        with connect(args, args.transaction) as other:
            assert scalar(other, "SELECT 42") == 42


def startup_options(args):
    with connect(args, args.transaction, options=r"-c application_name=hello\ world") as conn:
        assert scalar(conn, "SELECT pg_catalog.current_setting('application_name')") == "hello world"
    try:
        connect(args, args.transaction, options="-c application_name=ok nonsense")
    except psycopg.OperationalError:
        pass
    else:
        raise AssertionError("partially invalid startup options were accepted")


def ddl_reprepare(args):
    name = "pgproxy_area_" + uuid.uuid4().hex
    relation = psycopg.sql.Identifier(name)
    with connect(args, args.transaction) as a, connect(args, args.transaction) as b:
        b.execute(psycopg.sql.SQL("CREATE TABLE {} (value integer)").format(relation))
        try:
            b.execute(psycopg.sql.SQL("INSERT INTO {} VALUES (42)").format(relation))
            query = psycopg.sql.SQL("SELECT value FROM {}").format(relation)
            assert scalar(a, query, prepare=True) == 42
            b.execute(psycopg.sql.SQL("ALTER TABLE {} ALTER value TYPE bigint").format(relation))
            assert scalar(a, query, prepare=True) == 42
            assert scalar(b, "SELECT pg_catalog.pg_backend_pid()") == scalar(a, "SELECT pg_catalog.pg_backend_pid()")
        finally:
            b.execute(psycopg.sql.SQL("DROP TABLE {}").format(relation))


def authentication(args):
    password = os.environ["PGPROXY_AREA_PASSWORD"]
    with connect(args, args.scram, password=password) as conn:
        assert scalar(conn, "SELECT 42") == 42
    for supplied in [password + "-wrong", ""]:
        try:
            connect(args, args.scram, password=supplied)
        except psycopg.OperationalError:
            pass
        else:
            raise AssertionError("SCRAM accepted an invalid password")


def backend_failure(args):
    with connect(args, args.transaction) as client:
        old_pid = scalar(client, "SELECT pg_catalog.pg_backend_pid()")
        with psycopg.connect(host=args.host, port=args.backend_port, user=args.user,
                             dbname="conformance", sslmode="disable", autocommit=True) as control:
            assert scalar(control, "SELECT pg_catalog.pg_terminate_backend(%s)", (old_pid,))
        time.sleep(0.1)
        # No user query was in flight. A dead idle connection must be discarded.
        assert scalar(client, "SELECT 42") == 42
        assert scalar(client, "SELECT pg_catalog.pg_backend_pid()") != old_pid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=6439, type=int)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--transaction", default="areas_transaction")
    parser.add_argument("--session", default="conformance_session")
    parser.add_argument("--scram", default="areas_scram")
    parser.add_argument("--backend-port", default=55439, type=int)
    parser.add_argument("--readonly", help="optional read-only route with require_primary=true")
    args = parser.parse_args()
    cases = [("single-backend handoff and isolation", lambda: handoff(args)),
             ("transaction cancellation and recovery", lambda: cancellation(args, args.transaction)),
             ("session cancellation and recovery", lambda: cancellation(args, args.session)),
             ("startup options", lambda: startup_options(args)),
             ("DDL reprepare across handoff", lambda: ddl_reprepare(args)),
             ("idle backend failure and reconnect", lambda: backend_failure(args)),
             ("SCRAM authentication", lambda: authentication(args))]
    if args.readonly:
        def reject_readonly():
            try:
                with connect(args, args.readonly) as conn:
                    scalar(conn, "SELECT 42")
            except psycopg.OperationalError:
                return
            raise AssertionError("read-only backend accepted by writable-primary route")
        cases.append(("writable-primary enforcement", reject_readonly))
    failures = []
    for name, run in cases:
        try:
            run()
            print(f"PASS {name}", flush=True)
        except Exception as error:
            failures.append(name)
            # Avoid credentials or full connection strings in failure output.
            print(f"FAIL {name}: {type(error).__name__}", flush=True)
    print(f"{len(cases) - len(failures)}/{len(cases)} passed", flush=True)
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
