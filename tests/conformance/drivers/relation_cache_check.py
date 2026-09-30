#!/usr/bin/env python3
"""Falsification of the real MCP relation cache using direct outside writers."""
import argparse
import json
import select
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--container', default='pgproxy-area-tests')
    parser.add_argument('--database', default='cache_app')
    parser.add_argument('--usage-report', default='/tmp/pgproxy-relation-cache-usage.json')
    args = parser.parse_args()
    command = ['docker', 'exec', args.container, 'psql', '-U', 'postgres', '-d', 'conformance', '-Atq']
    def db(sql):
        result = subprocess.run(command + ['-c', sql], text=True, capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()
    db("""DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='pgproxy_cache_service') THEN CREATE ROLE pgproxy_cache_service LOGIN; END IF; END $$;
ALTER ROLE pgproxy_cache_service LOGIN;
GRANT pg_monitor TO pgproxy_cache_service;
CREATE TABLE IF NOT EXISTS public.pgproxy_cache_table(id integer,val text);
DROP VIEW IF EXISTS public.pgproxy_cache_view;
ALTER TABLE public.pgproxy_cache_table DROP COLUMN IF EXISTS extra;
TRUNCATE public.pgproxy_cache_table;
INSERT INTO public.pgproxy_cache_table VALUES(1,'initial');
CREATE VIEW public.pgproxy_cache_view AS SELECT id,val FROM public.pgproxy_cache_table;
CREATE TABLE IF NOT EXISTS public.pgproxy_cache_rls(id integer);
ALTER TABLE public.pgproxy_cache_rls ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.pgproxy_cache_rls FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cache_test_policy ON public.pgproxy_cache_rls;
CREATE POLICY cache_test_policy ON public.pgproxy_cache_rls USING(true);
TRUNCATE public.pgproxy_cache_rls;
INSERT INTO public.pgproxy_cache_rls VALUES(7);
GRANT USAGE ON SCHEMA public TO pgproxy_cache_service;
GRANT SELECT ON public.pgproxy_cache_table,public.pgproxy_cache_view,public.pgproxy_cache_rls TO pgproxy_cache_service;
""")
    process = subprocess.Popen([args.binary, '--config', args.config, '--mcp-stdio', '--mcp-database', args.database, '--mcp-user', 'postgres', '--mcp-usage-report', args.usage_report], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=open("/tmp/pgproxy-relation-cache-mcp.log", "w"), text=True, bufsize=1)
    request_id = 0
    observed_rows = observed_bytes = observed_hits = observed_errors = 0
    def query(sql='SELECT id,val FROM public.pgproxy_cache_table', error=False):
        nonlocal request_id, observed_rows, observed_bytes, observed_hits, observed_errors
        request_id += 1
        request = dict(jsonrpc='2.0', id=request_id, method='tools/call', params=dict(name='query', arguments=dict(sql=sql)))
        process.stdin.write(json.dumps(request)+'\n')
        process.stdin.flush()
        assert select.select([process.stdout], [], [], 15)[0], 'MCP timed out'
        line = process.stdout.readline()
        assert line, 'MCP closed: inspect /tmp/pgproxy-relation-cache-mcp.log'
        result = json.loads(line)['result']
        assert result['isError'] == error, result
        if error:
            observed_errors += 1
            return [], False
        rows = json.loads(result['content'][0]['text'])
        hit = result.get('_meta', {}).get('pgproxy/cache_hit', False)
        observed_rows += len(rows)
        observed_bytes += len(result['content'][0]['text'].encode('utf-8'))
        observed_hits += int(hit)
        return [row['values'] for row in rows], hit
    def warm(value):
        for _ in range(30):
            rows, hit = query()
            assert rows == [['1', value]], rows
            if hit:
                return
        raise AssertionError('no snapshot cache hit in 30 attempts; concurrent fixture writes may prevent reuse')
    try:
        warm('initial')
        print('PASS validated relation cache hit')
        db("UPDATE public.pgproxy_cache_table SET val='external'")
        rows, hit = query()
        assert rows == [['1', 'external']] and not hit, (rows, hit)
        print('PASS external committed DML invalidation')
        warm('external')
        writer_command = command.copy()
        writer_command.insert(2, '-i')
        writer = subprocess.Popen(writer_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        writer.stdin.write("BEGIN; UPDATE public.pgproxy_cache_table SET val='uncommitted'; SELECT 'writer-ready';\n")
        writer.stdin.flush()
        assert select.select([writer.stdout], [], [], 15)[0]
        assert writer.stdout.readline().strip() == 'writer-ready'
        assert query()[0] == [['1', 'external']]
        writer.stdin.write('COMMIT;\n')
        writer.stdin.close()
        writer.wait(timeout=15)
        assert query()[0] == [['1', 'uncommitted']]
        print('PASS active external writer snapshot and commit visibility')
        db("BEGIN;UPDATE public.pgproxy_cache_table SET val='rolled-back';ROLLBACK")
        assert query()[0] == [['1', 'uncommitted']]
        print('PASS rollback does not publish speculative data')
        db("ALTER TABLE public.pgproxy_cache_table ADD COLUMN extra text DEFAULT 'ddl'")
        rows, hit = query('SELECT * FROM public.pgproxy_cache_table')
        assert rows == [['1', 'uncommitted', 'ddl']] and not hit, (rows, hit)
        print('PASS DDL column shape invalidation')
        db("TRUNCATE public.pgproxy_cache_table;INSERT INTO public.pgproxy_cache_table VALUES(1,'truncated','ddl')")
        assert query()[0] == [['1', 'truncated']]
        print('PASS TRUNCATE invalidation')
        for sql in ['SELECT id,val FROM public.pgproxy_cache_view', 'SELECT id FROM public.pgproxy_cache_rls', 'SELECT pg_catalog.random()']:
            assert not query(sql)[1]
            assert not query(sql)[1]
        print('PASS views RLS and volatile expressions bypass relation cache')
        warm('truncated')
        db('ALTER ROLE pgproxy_cache_service NOLOGIN')
        query(error=True)
        db('ALTER ROLE pgproxy_cache_service LOGIN')
        rows, hit = query()
        assert rows == [['1', 'truncated']] and not hit, (rows, hit)
        print('PASS failed authentication validation never serves stale cache')
        db("REVOKE SELECT ON public.pgproxy_cache_table FROM pgproxy_cache_service")
        query(error=True)
        db('GRANT SELECT ON public.pgproxy_cache_table TO pgproxy_cache_service')
        assert query()[0] == [['1', 'truncated']]
        print('PASS permission revocation cannot reuse cached data')
    finally:
        db('ALTER ROLE pgproxy_cache_service LOGIN;GRANT SELECT ON public.pgproxy_cache_table TO pgproxy_cache_service')
        process.stdin.close()
        process.wait(timeout=15)
    with open(args.usage_report) as report_file:
        report = json.load(report_file)
    accounts = report['accounts']
    assert report['dropped_samples'] == 0, report
    for field, expected in [('exchanges', request_id), ('rows', observed_rows), ('result_bytes', observed_bytes), ('cache_hits', observed_hits), ('errors', observed_errors)]:
        assert sum(account[field] for account in accounts) == expected, (field, expected, report)
    assert observed_hits > 0 and observed_errors == 2
    assert all(account['identity'] == dict(user='postgres', tenant='cache-test', agent='cache-agent') for account in accounts), report
    assert all(account['cpu_us'] is None and account['buffers'] is None and account['wal_bytes'] is None for account in accounts), report
    assert sum(account['elapsed_us'] for account in accounts) > 0
    print('PASS exact measured MCP cost attribution, cache hits and errors')
    print('10/10 relation cache and attribution checks passed')


if __name__ == '__main__':
    main()
