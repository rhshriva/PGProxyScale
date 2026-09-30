#!/usr/bin/env python3
"""Backend verify-full TLS, SCRAM-PLUS, cancellation and fail-closed live checks."""
import argparse
import threading
import time
import psycopg


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="host.docker.internal")
    parser.add_argument("--port", type=int, default=6441)
    args = parser.parse_args()

    def connect(route="verified"):
        return psycopg.connect(host=args.host, port=args.port, dbname=route,
                               user="postgres", sslmode="disable", autocommit=True,
                               connect_timeout=5)

    def verified():
        with connect() as connection:
            assert connection.execute("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone() == (True,)
            assert connection.execute("SELECT %s::int + 1", (41,), prepare=True).fetchone() == (42,)

    def reject(route):
        try:
            with connect(route):
                pass
        except psycopg.OperationalError:
            return
        raise AssertionError("invalid TLS peer accepted")

    def cancellation():
        with connect() as connection:
            outcomes = []
            def query():
                try:
                    connection.execute("SELECT pg_sleep(10)")
                    outcomes.append("completed")
                except psycopg.errors.QueryCanceled:
                    outcomes.append("cancelled")
            worker = threading.Thread(target=query)
            worker.start()
            time.sleep(0.3)
            connection.cancel()
            worker.join(timeout=5)
            assert outcomes == ["cancelled"], outcomes
            assert connection.execute("SELECT 42").fetchone() == (42,)

    def certificate_identity():
        with connect("mtls") as connection:
            assert connection.execute("SELECT current_user").fetchone() == ("certuser",)
            assert connection.execute("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone() == (True,)

    def unicode_password():
        with connect("unicode") as connection:
            assert connection.execute("SELECT current_user").fetchone() == ("unicodeuser",)
            assert connection.execute("SELECT 42").fetchone() == (42,)

    cases = [("verified encrypted backend and bound SCRAM", verified),
             ("hostname mismatch rejected", lambda: reject("wrong_host")),
             ("untrusted CA rejected", lambda: reject("wrong_ca")),
             ("encrypted cancellation and recovery", cancellation),
             ("verified backend client certificate", certificate_identity),
             ("missing backend client certificate rejected", lambda: reject("mtls_missing")),
             ("wrong backend certificate identity rejected", lambda: reject("mtls_wrong_identity")),
             ("Unicode SCRAM SASLprep password", unicode_password)]
    failed = 0
    for label, run in cases:
        try:
            run()
            print("PASS", label, flush=True)
        except Exception as error:
            failed += 1
            print("FAIL", label, type(error).__name__, str(error), flush=True)
    print(f"{len(cases)-failed}/{len(cases)} passed", flush=True)
    return bool(failed)


if __name__ == "__main__":
    raise SystemExit(main())
