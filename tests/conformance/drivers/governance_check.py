#!/usr/bin/env python3
"""Live policy acceptance against an explicitly configured governed route.

Run with psycopg 3. The backend user should be able to read the denied relation,
so these checks demonstrate proxy denial rather than PostgreSQL permissions.
"""
import argparse
import psycopg


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='host.docker.internal')
    parser.add_argument('--port', type=int, default=6442)
    parser.add_argument('--database', default='areas_policy')
    parser.add_argument('--user', default='postgres')
    parser.add_argument('--password', default='')
    args = parser.parse_args()
    settings = dict(host=args.host, port=args.port, dbname=args.database,
                    user=args.user, password=args.password, connect_timeout=5,
                    sslmode='disable', autocommit=True)
    cases = [
        ('plain permitted query', 'SELECT 42', False, True),
        ('prepared permitted query', 'SELECT 42', True, True),
        ('forbidden relation', 'SELECT * FROM pg_catalog.pg_authid', False, False),
        ('forbidden scalar function', "SELECT pg_catalog.pg_read_file('/etc/passwd')", False, False),
        ('forbidden FROM function', "SELECT * FROM pg_catalog.pg_read_file('/etc/passwd')", True, False),
        ('dynamic SQL', "DO $$ BEGIN EXECUTE 'SELECT 1'; END $$", False, False),
        ('custom operator', 'SELECT 1 OPERATOR(public.+) 2', False, False),
        ('simple multi statement', 'SELECT 1; SELECT 2', False, False),
        ('role escalation', 'SET ROLE postgres', False, False),
    ]
    failures = []
    for name, sql, prepared, allowed in cases:
        try:
            with psycopg.connect(**settings) as connection:
                result = connection.execute(sql, prepare=prepared).fetchone()
                if not allowed or result != (42,):
                    raise AssertionError(f'unexpected result: {result!r}')
            print(f'PASS {name}')
        except psycopg.Error as error:
            if allowed or error.sqlstate != '42501':
                failures.append(f'{name}: {error}')
                print(f'FAIL {name}: {error}')
            else:
                print(f'PASS {name}')
        except Exception as error:
            failures.append(f'{name}: {error}')
            print(f'FAIL {name}: {error}')
    print(f'{len(cases)-len(failures)}/{len(cases)} policy checks passed')
    if failures:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
