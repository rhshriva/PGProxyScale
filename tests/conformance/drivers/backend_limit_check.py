#!/usr/bin/env python3
"""Bound physical backends across transaction/session modes and reload generations.

Requires reload_fixtures.py config with --backend-limit 2. The operations control
surface reloads only the fixed disposable config path; no untrusted config body.
"""
import argparse
import http.client
import json
from pathlib import Path
import time
import psycopg


def reload(args):
    conn = http.client.HTTPConnection(args.host, args.operations_port, timeout=5)
    conn.request('POST', '/reload', headers={'Authorization': 'Bearer ' + args.token})
    response = conn.getresponse()
    body = json.loads(response.read())
    conn.close()
    assert response.status == 200, body
    return body


def connect(args, database):
    return psycopg.connect(host=args.host, port=args.port, user='postgres',
          dbname=database, sslmode='verify-full', sslrootcert=str(args.fixtures / 'ca.pem'),
          autocommit=True, connect_timeout=5)


def run(args):
    transaction = session = None
    try:
        transaction = connect(args, 'reload_transaction')
        transaction.execute('BEGIN')
        first = transaction.execute('SELECT pg_catalog.pg_backend_pid()').fetchone()[0]
        session = connect(args, 'reload_session')
        second = session.execute('SELECT pg_catalog.pg_backend_pid()').fetchone()[0]
        assert first != second
        state = reload(args)
        assert state['backend_connections'] == state['backend_capacity'] == 2, state
        before = time.monotonic()
        try:
            connect(args, 'reload_transaction')
        except psycopg.OperationalError as error:
            assert 'admission timed out' in str(error), str(error)
        else:
            raise AssertionError('new generation exceeded the global physical backend cap')
        assert time.monotonic() - before < 4
        assert transaction.execute('SELECT 42').fetchone()[0] == 42
        assert session.execute('SELECT 42').fetchone()[0] == 42
        print('PASS shared backend cap across transaction/session modes and service generations', flush=True)
        transaction.close()
        session.close()
        transaction = session = None
        deadline = time.monotonic() + 5
        while True:
            try:
                fresh = connect(args, 'reload_transaction')
                break
            except psycopg.OperationalError:
                assert time.monotonic() < deadline
                time.sleep(.05)
        with fresh:
            assert fresh.execute('SELECT 42').fetchone()[0] == 42
        print('PASS capacity reclaimed after retired generation closes', flush=True)
        print('2/2 backend-cap checks passed', flush=True)
    finally:
        if transaction is not None:
            transaction.close()
        if session is not None:
            session.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='host.docker.internal')
    parser.add_argument('--port', type=int, default=6444)
    parser.add_argument('--operations-port', type=int, default=6452)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--token', default='pgproxy-reload-test-token-0000000000')
    run(parser.parse_args())
