#!/usr/bin/env python3
"""Live role/RLS backend handoff and two-principal containment acceptance."""
import argparse
import threading
import time
import psycopg

FIXTURE_SQL = """
DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='pgproxy_rls_owner') THEN CREATE ROLE pgproxy_rls_owner NOLOGIN; END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='pgproxy_rls_reader') THEN CREATE ROLE pgproxy_rls_reader NOLOGIN; END IF;
END $$;
CREATE TABLE IF NOT EXISTS public.pgproxy_rls_tenants (tenant text, id integer, secret text);
ALTER TABLE public.pgproxy_rls_tenants OWNER TO pgproxy_rls_owner;
ALTER TABLE public.pgproxy_rls_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.pgproxy_rls_tenants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pgproxy_test_isolation ON public.pgproxy_rls_tenants;
CREATE POLICY pgproxy_test_isolation ON public.pgproxy_rls_tenants TO pgproxy_rls_reader
 USING (tenant = pg_catalog.current_setting('pgproxy.tenant', true));
GRANT USAGE ON SCHEMA public TO pgproxy_rls_reader;
GRANT SELECT ON public.pgproxy_rls_tenants TO pgproxy_rls_reader;
TRUNCATE public.pgproxy_rls_tenants;
INSERT INTO public.pgproxy_rls_tenants VALUES ('noisy',42,'private-noisy'),('victim',84,'private-victim');
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='host.docker.internal')
    parser.add_argument('--port', type=int, default=6446)
    parser.add_argument('--backend-port', type=int, default=55439)
    parser.add_argument('--database', default='policy_rls')
    parser.add_argument('--password', default='pgproxy-test-password')
    parser.add_argument('--setup-only', action='store_true')
    args = parser.parse_args()
    direct = psycopg.connect(host=args.host, port=args.backend_port, user='postgres', dbname='conformance', autocommit=True)
    direct.execute(FIXTURE_SQL)
    if args.setup_only:
        print('RLS fixtures prepared')
        return
    def connect(user):
        return psycopg.connect(host=args.host, port=args.port, user=user, password=args.password,
                              dbname=args.database, autocommit=True, sslmode='disable', connect_timeout=5)
    with connect('postgres') as noisy, connect('other') as victim:
        for _ in range(20):
            assert noisy.execute('SELECT id FROM public.pgproxy_rls_tenants', prepare=True).fetchall() == [(42,)]
            assert victim.execute('SELECT id FROM public.pgproxy_rls_tenants', prepare=True).fetchall() == [(84,)]
        print('PASS tenant RLS isolation across prepared backend handoffs')
        errors = []
        def saturate():
            try:
                noisy.execute('SELECT pg_catalog.pg_sleep(0.4)').fetchone()
            except Exception as error:
                errors.append(error)
        worker = threading.Thread(target=saturate)
        worker.start()
        deadline = time.monotonic() + 2
        while not direct.execute("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE state='active' AND query='SELECT pg_catalog.pg_sleep(0.4)'").fetchone()[0]:
            if time.monotonic() > deadline:
                raise AssertionError('noisy query did not reach PostgreSQL')
            time.sleep(0.005)
        started = time.monotonic()
        assert victim.execute('SELECT id FROM public.pgproxy_rls_tenants').fetchall() == [(84,)]
        latency = time.monotonic() - started
        assert latency < 0.2, f'victim delayed by noisy tenant: {latency:.3f}s'
        print(f'PASS noisy-neighbor containment: victim {latency*1000:.1f}ms during 400ms noisy query')
        try:
            with connect('postgres') as excess:
                excess.execute('SELECT 1')
            raise AssertionError('noisy tenant exceeded concurrency quota')
        except psycopg.Error as error:
            assert error.sqlstate == '53300', error
        worker.join(timeout=3)
        assert not worker.is_alive() and not errors, errors
        print('PASS typed per-principal concurrency shedding')
        noisy.execute('BEGIN')
        assert noisy.execute('SELECT id FROM public.pgproxy_rls_tenants').fetchall() == [(42,)]
        try:
            with connect('postgres') as excess:
                excess.execute('BEGIN')
            raise AssertionError('idle transaction exceeded principal scheduler cap')
        except psycopg.Error as error:
            assert error.sqlstate == '53300', error
        assert victim.execute('SELECT id FROM public.pgproxy_rls_tenants').fetchall() == [(84,)]
        noisy.execute('COMMIT')
        print('PASS idle transaction cannot consume victim slot')
    direct.close()
    print('4/4 RLS and fairness checks passed')


if __name__ == '__main__':
    main()
