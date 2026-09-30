#!/usr/bin/env python3
"""Session ledger system checks against an isolated database.

The route must use transaction pooling with pool_size=1 and explicit trust or
password authentication. RESET ALL startup emulation requires PostgreSQL's normal
trusted plpgsql language. Specify --backend-port for independent DDL control.
"""
import argparse
import uuid
import psycopg


def connect(args, **kwargs):
    tls = {"sslmode": args.sslmode}
    if args.sslrootcert is not None:
        tls["sslrootcert"] = args.sslrootcert
    return psycopg.connect(host=args.host, port=args.port, dbname=args.database,
                          user=args.user, autocommit=True, connect_timeout=5,
                          **tls, **kwargs)


def scalar(conn, sql, **kwargs):
    return conn.execute(sql, **kwargs).fetchone()[0]


def startup_reset(args):
    with connect(args, options="-c application_name=ledger-startup") as a, connect(args) as b:
        pid = scalar(a, "SELECT pg_catalog.pg_backend_pid()")
        for sql, prepared in [("RESET application_name", False),
                              ("SET application_name TO DEFAULT", True),
                              ("RESET ALL", False), ("RESET ALL", True)]:
            a.execute("SET application_name='changed'")
            cursor = a.execute(sql, prepare=prepared)
            expected = "SET" if sql.startswith("SET ") else "RESET"
            assert cursor.statusmessage == expected, (sql, cursor.statusmessage)
            assert scalar(a, "SHOW application_name") == "ledger-startup", sql
            assert scalar(b, "SELECT pg_catalog.pg_backend_pid()") == pid
            assert scalar(a, "SELECT pg_catalog.pg_backend_pid()") == pid
        for prepared in [False, True]:
            a.execute("SET application_name='changed'")
            a.execute("DISCARD ALL", prepare=prepared)
            assert scalar(a, "SHOW application_name") == "ledger-startup"
            assert scalar(b, "SHOW application_name") != "ledger-startup"
            assert scalar(a, "SELECT pg_catalog.pg_backend_pid()") == pid


def rollback_context(args):
    with connect(args, options="-c application_name=ledger-startup") as a:
        a.execute("SET application_name='base'")
        a.execute("BEGIN")
        a.execute("SET application_name='changed'")
        a.execute("SAVEPOINT checkpoint")
        a.execute("RESET ALL", prepare=True)
        assert scalar(a, "SHOW application_name") == "ledger-startup"
        a.execute("ROLLBACK TO checkpoint")
        assert scalar(a, "SHOW application_name") == "changed"
        a.execute("ROLLBACK")
        assert scalar(a, "SHOW application_name") == "base"
        a.execute("BEGIN")
        a.execute("PREPARE rollback_p AS SELECT 42")
        a.execute("ROLLBACK")
        assert scalar(a, "EXECUTE rollback_p") == 42
        a.execute("DEALLOCATE rollback_p")


def resources(args):
    name = "ledger_" + uuid.uuid4().hex
    ident = psycopg.sql.Identifier(name)
    with connect(args) as a:
        pid = scalar(a, "SELECT pg_catalog.pg_backend_pid()")
        a.execute(psycopg.sql.SQL("CREATE TEMP TABLE {} (v int)").format(ident))
        a.execute(psycopg.sql.SQL("INSERT INTO {} VALUES (42)").format(ident))
        assert scalar(a, psycopg.sql.SQL("SELECT v FROM {}").format(ident)) == 42
        a.execute("BEGIN")
        a.execute("DECLARE held CURSOR WITH HOLD FOR SELECT 42")
        a.execute("COMMIT")
        assert scalar(a, "FETCH held") == 42
        a.execute("CLOSE held")
        a.execute("LISTEN ledger_notifications")
        a.execute("NOTIFY ledger_notifications, 'payload'")
        notifications = list(a.notifies(timeout=1, stop_after=1))
        assert notifications and notifications[0].payload == "payload"
        a.execute("UNLISTEN *")
        a.execute("SELECT pg_catalog.pg_advisory_lock(7301923)")
        assert scalar(a, "SELECT pg_catalog.pg_backend_pid()") == pid
        a.execute("SELECT pg_catalog.pg_advisory_unlock_all()")
        a.execute(psycopg.sql.SQL("DROP TABLE pg_temp.{}").format(ident))
        with connect(args) as b:
            assert scalar(b, "SELECT pg_catalog.pg_backend_pid()") == pid


def retained_ddl(args):
    name = "ledger_ddl_" + uuid.uuid4().hex
    ident = psycopg.sql.Identifier(name)
    with connect(args) as a, psycopg.connect(host=args.host, port=args.backend_port,
              dbname=args.backend_database, user=args.user, autocommit=True,
              sslmode="disable", connect_timeout=5) as control:
        control.execute(psycopg.sql.SQL("CREATE TABLE {} (v int)").format(ident))
        try:
            control.execute(psycopg.sql.SQL("INSERT INTO {} VALUES (42)").format(ident))
            a.execute("LISTEN retain_backend")
            query = psycopg.sql.SQL("SELECT v FROM {}").format(ident)
            pid = scalar(a, "SELECT pg_catalog.pg_backend_pid()")
            assert scalar(a, query, prepare=True) == 42
            control.execute(psycopg.sql.SQL("ALTER TABLE {} ADD COLUMN other int").format(ident))
            assert scalar(a, query, prepare=True) == 42
            assert scalar(a, "SELECT pg_catalog.pg_backend_pid()") == pid
            a.execute("UNLISTEN *")
        finally:
            control.execute(psycopg.sql.SQL("DROP TABLE {}").format(ident))



def nontransactional_failure(args):
    name = "ledger_lock_fail_" + uuid.uuid4().hex
    function = psycopg.sql.Identifier(name)
    with psycopg.connect(host=args.host, port=args.backend_port,
              dbname=args.backend_database, user=args.user, autocommit=True,
              sslmode="disable", connect_timeout=5) as control:
        control.execute(psycopg.sql.SQL("""CREATE FUNCTION {}() RETURNS void LANGUAGE plpgsql AS
            $function$ BEGIN PERFORM pg_catalog.pg_advisory_lock(7301924);
            RAISE EXCEPTION 'intentional ledger failure'; END $function$""").format(function))
        try:
            with connect(args) as client:
                pid = scalar(client, "SELECT pg_catalog.pg_backend_pid()")
                try:
                    client.execute(psycopg.sql.SQL("SELECT {}()").format(function))
                except psycopg.errors.RaiseException:
                    pass
                else:
                    raise AssertionError("function did not fail")
                assert scalar(client, "SELECT pg_catalog.pg_backend_pid()") == pid
                assert scalar(control, "SELECT pg_catalog.pg_try_advisory_lock(7301924)") is False
                client.execute("DISCARD ALL")
                assert scalar(control, "SELECT pg_catalog.pg_try_advisory_lock(7301924)") is True
                control.execute("SELECT pg_catalog.pg_advisory_unlock(7301924)")
        finally:
            control.execute(psycopg.sql.SQL("DROP FUNCTION {}()").format(function))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="host.docker.internal")
    parser.add_argument("--port", type=int, default=6439)
    parser.add_argument("--database", default="areas_transaction")
    parser.add_argument("--backend-port", type=int, default=55439)
    parser.add_argument("--backend-database", default="conformance")
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--sslmode", default="disable")
    parser.add_argument("--sslrootcert")
    args = parser.parse_args()
    checks = [("startup RESET/default/DISCARD and pool handoff", startup_reset),
              ("rollback and prepared ownership", rollback_context),
              ("temp/cursor/listener/advisory resource lifecycle", resources),
              ("DDL with retained prepared statements", retained_ddl),
              ("failed function retains nontransactional session effects", nontransactional_failure)]
    failures = 0
    for title, check in checks:
        try:
            check(args)
            print("PASS", title, flush=True)
        except Exception as error:
            failures += 1
            print("FAIL", title, repr(error), flush=True)
    print(f"{len(checks)-failures}/{len(checks)} ledger checks passed", flush=True)
    raise SystemExit(bool(failures))


if __name__ == "__main__":
    main()
