#!/usr/bin/env python3
"""Protected-column composite/alias regression against an isolated configured route.

The backend fixture is public.pgproxy_masked_review(id integer, secret text).
Its governed route grants SELECT but denies column 'secret'. Both simple and
extended protocols must reject requests before any private data is returned.
"""
import argparse
import psycopg


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--database", default="masked_review")
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--password", default="pgproxy-test-password")
    args = parser.parse_args()
    settings = dict(host=args.host, port=args.port, dbname=args.database,
                    user=args.user, password=args.password, connect_timeout=5,
                    sslmode="disable", autocommit=True)
    blocked = [
        "SELECT secret FROM public.pgproxy_masked_review",
        "SELECT * FROM public.pgproxy_masked_review",
        "SELECT a FROM public.pgproxy_masked_review AS a",
        "SELECT pgproxy_masked_review FROM public.pgproxy_masked_review",
        "SELECT public.pgproxy_masked_review FROM public.pgproxy_masked_review",
        "SELECT safe FROM public.pgproxy_masked_review AS a(id,safe)",
        'SELECT "Hidden" FROM public.pgproxy_masked_review AS "Hidden"',
    ]
    count = 0
    for prepared in (False, True):
        # Each rejected protocol exchange may close its connection deliberately.
        for sql in blocked:
            with psycopg.connect(**settings) as connection:
                try:
                    connection.execute(sql, prepare=prepared).fetchall()
                except psycopg.Error as error:
                    assert error.sqlstate == "42501", error
                else:
                    raise AssertionError(f"protected-column bypass accepted: {sql}")
            count += 1
        with psycopg.connect(**settings) as connection:
            assert connection.execute(
                "SELECT a.id FROM public.pgproxy_masked_review AS a",
                prepare=prepared).fetchall() == [(42,)]
        count += 1
    print(f"PASS {count} protected-column simple/extended checks")


if __name__ == "__main__":
    main()
