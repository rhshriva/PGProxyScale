#!/usr/bin/env python3
"""Native PostgreSQL TLS, SCRAM-PLUS and client certificate acceptance.

Requires isolated certificate fixtures, a TLS-required listener and configured
SCRAM transaction/session and certificate routes. Never uses production credentials.
"""
import argparse
import os
from pathlib import Path
import psycopg


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="host.docker.internal")
    p.add_argument("--port", type=int, default=6440)
    p.add_argument("--fixtures", default="/fixtures")
    args = p.parse_args()
    root = Path(args.fixtures)
    defaults = dict(host=args.host, port=args.port, user="postgres", connect_timeout=5,
                    sslmode="verify-full", sslrootcert=str(root / "server.pem"))
    secret = os.environ["PGPROXY_AREA_PASSWORD"]

    def connect(db="areas_scram", **kwargs):
        return psycopg.connect(**(defaults | dict(dbname=db, autocommit=True) | kwargs))

    def rejected(**kwargs):
        try:
            with connect(**kwargs):
                pass
        except psycopg.OperationalError:
            return
        raise AssertionError("expected connection rejection")

    def plus():
        for route in ["areas_scram", "areas_scram_session"]:
            with connect(route, password=secret, channel_binding="require") as conn:
                assert conn.pgconn.ssl_in_use
                assert conn.execute("SELECT 42").fetchone() == (42,)
                pid = conn.execute("SELECT pg_catalog.pg_backend_pid()").fetchone()[0]
                conn.execute("DISCARD ALL")
                if route.endswith("session"):
                    assert conn.execute("SELECT pg_catalog.pg_backend_pid()").fetchone()[0] == pid
                assert conn.execute("SELECT %s::int + 1", (41,), prepare=True).fetchone() == (42,)

    def certificate():
        with connect("areas_certificate", sslcert=str(root / "client.pem"),
                     sslkey=str(root / "client-key.pem")) as conn:
            assert conn.execute("SELECT 42").fetchone() == (42,)
        rejected(db="areas_certificate")
        rejected(db="areas_certificate", sslcert=str(root / "other.pem"), sslkey=str(root / "other-key.pem"))

    cases = [
        ("SCRAM-PLUS transaction and session", plus),
        ("required TLS rejects plaintext", lambda: rejected(password=secret, sslmode="disable")),
        ("wrong password over TLS", lambda: rejected(password=secret + "-wrong", channel_binding="require")),
        ("server certificate verification", lambda: rejected(password=secret, sslrootcert=str(root / "ca.pem"))),
        ("verified certificate identity mapping", certificate),
    ]
    failures = 0
    for label, test in cases:
        try:
            test()
            print("PASS", label, flush=True)
        except Exception as error:
            failures += 1
            print("FAIL", label, type(error).__name__, flush=True)
    print(f"{len(cases)-failures}/{len(cases)} passed", flush=True)
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
