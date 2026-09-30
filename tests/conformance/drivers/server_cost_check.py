#!/usr/bin/env python3
"""Reconcile real server extension counters; never assume exclusive tenant cost."""
import argparse
import json
import pathlib
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--container', default='pgproxy-server-cost-tests')
    parser.add_argument('--port', default=55447, type=int)
    parser.add_argument('--require-cpu', action='store_true')
    args = parser.parse_args()
    binary = str(pathlib.Path(args.binary).resolve())
    base = ['docker', 'exec', args.container, 'psql', '-U', 'postgres', '-d', 'conformance', '-Atq', '-v', 'ON_ERROR_STOP=1']
    def sql(statement):
        process = subprocess.run(base + ['-c', statement], capture_output=True, text=True, timeout=30)
        assert process.returncode == 0, process.stderr
        return process.stdout.strip()
    sql("""CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='pgproxy_cost_a') THEN CREATE ROLE pgproxy_cost_a; END IF; IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='pgproxy_cost_b') THEN CREATE ROLE pgproxy_cost_b; END IF; END $$;
DROP TABLE IF EXISTS public.pgproxy_cost_measure;
CREATE TABLE public.pgproxy_cost_measure(id integer, value text);
GRANT SELECT,INSERT ON public.pgproxy_cost_measure TO pgproxy_cost_a,pgproxy_cost_b;
SELECT pg_stat_statements_reset();
SET ROLE pgproxy_cost_a; INSERT INTO public.pgproxy_cost_measure SELECT g, repeat('a',64) FROM generate_series(1,1000) g; RESET ROLE;
SET ROLE pgproxy_cost_b; INSERT INTO public.pgproxy_cost_measure SELECT g, repeat('b',64) FROM generate_series(1,1000) g; RESET ROLE;""")
    if args.require_cpu:
        sql('CREATE EXTENSION IF NOT EXISTS pg_stat_kcache')
        # Extension creates counters only after installation; run a CPU-heavy
        # SELECT with the same role, distinct from the WAL-producing workload.
        sql("SET ROLE pgproxy_cost_a; SELECT sum(g::numeric*g::numeric) FROM generate_series(1,500000) g; RESET ROLE")
    with tempfile.TemporaryDirectory(prefix='pgproxy-server-cost-') as directory:
        config = pathlib.Path(directory)/'config.toml'
        report = pathlib.Path(directory)/'report.json'
        config.write_text(f'''[general]
listen_addr = "127.0.0.1"
listen_port = 6477
workers = 1
[[databases]]
name = "cost_app"
host = "127.0.0.1"
port = {args.port}
dbname = "conformance"
user = "postgres"
password = "pgproxy-test-password"
pool_mode = "transaction"
client_auth = "trust"
pool_size = 2
require_primary = true
''')
        def collect(error=False):
            result = subprocess.run([binary,'--config',str(config),'--server-cost-database','cost_app','--server-cost-user','postgres','--server-cost-report',str(report)],capture_output=True,text=True,timeout=30)
            assert (result.returncode != 0) == error, (result.returncode,result.stderr)
            if error:
                assert 'pgproxy-test-password' not in result.stderr
                return None
            return json.loads(report.read_text())
        measured = collect()
        assert measured['scope'] == 'cumulative_database_role_query_aggregate'
        rows = [r for r in measured['statements'] if r['role'] in ('pgproxy_cost_a','pgproxy_cost_b') and int(r['wal_bytes']) > 0]
        assert len(rows) == 2, measured
        assert {r['role'] for r in rows} == {'pgproxy_cost_a','pgproxy_cost_b'}
        for row in rows:
            expected = json.loads(sql(f"SELECT json_build_object('calls',calls,'rows',rows,'wal_bytes',wal_bytes::text,'shared_blocks_hit',shared_blks_hit,'shared_blocks_dirtied',shared_blks_dirtied) FROM pg_stat_statements(false) WHERE dbid={row['database_oid']} AND userid={row['role_oid']} AND queryid={row['query_id']} AND toplevel"))
            for field in expected:
                assert row[field] == expected[field], (field,row,expected)
            assert row['rows'] == 1000
            assert 'query' not in row and 'identity' not in row
        print('PASS actual WAL/buffer/call/row counters reconcile exact database-role-query IDs')
        # Same role, different client execution: intentionally cumulative, not an
        # exclusive inferred tenant delta or proxy-only measurement.
        sql("SET ROLE pgproxy_cost_a; INSERT INTO public.pgproxy_cost_measure SELECT g, repeat('a',64) FROM generate_series(1,1000) g; RESET ROLE")
        after = collect()
        first = next(r for r in rows if r['role']=='pgproxy_cost_a')
        same = next(r for r in after['statements'] if r['role_oid']==first['role_oid'] and r['query_id']==first['query_id'])
        assert same['calls']==first['calls']+1 and same['rows']==first['rows']+1000
        assert int(same['wal_bytes'])>int(first['wal_bytes'])
        print('PASS outside writer measured as shared PostgreSQL role aggregate')
        if args.require_cpu:
            cpu = [r for r in after['statements'] if r['role']=='pgproxy_cost_a' and r['execution_user_cpu_seconds'] is not None]
            assert cpu and sum(r['execution_user_cpu_seconds']+r['execution_system_cpu_seconds'] for r in cpu)>0
            assert after['cpu_source']=='pg_stat_kcache_execution_rusage'
            for row in cpu:
                actual = json.loads(sql(f"SELECT json_build_object('user',exec_user_time,'system',exec_system_time) FROM pg_stat_kcache() WHERE dbid={row['database_oid']} AND userid={row['role_oid']} AND queryid={row['query_id']} AND top"))
                assert row['execution_user_cpu_seconds']==actual['user'] and row['execution_system_cpu_seconds']==actual['system'], (row,actual)
            print('PASS measured user/system CPU reconciles pg_stat_kcache, never elapsed time')
        else:
            assert all(r['execution_user_cpu_seconds'] is None and r['execution_system_cpu_seconds'] is None for r in after['statements'])
            print('PASS absent CPU instrumentation explicitly unavailable')
        # Monitoring permissions are explicit, never silently replaced by fake
        # zeros. Use a non-superuser so denied extension access is observable.
        sql("DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='pgproxy_cost_monitor') THEN CREATE ROLE pgproxy_cost_monitor LOGIN PASSWORD 'pgproxy-test-password'; END IF; END $$; REVOKE pg_monitor FROM pgproxy_cost_monitor")
        original_config=config.read_text()
        config.write_text(original_config.replace('user = "postgres"','user = "pgproxy_cost_monitor"'))
        collect(error=True)
        sql('GRANT pg_monitor TO pgproxy_cost_monitor')
        monitored=collect()
        assert any(r['role']=='pgproxy_cost_a' for r in monitored['statements'])
        if args.require_cpu:
            sql('REVOKE EXECUTE ON FUNCTION pg_stat_kcache() FROM PUBLIC')
            collect(error=True)
            sql('GRANT EXECUTE ON FUNCTION pg_stat_kcache() TO PUBLIC')
            assert collect()['cpu_source']=='pg_stat_kcache_execution_rusage'
        config.write_text(original_config)
        print('PASS missing monitoring/CPU permissions fail closed, grants restore measured results')
        prior_entry=next(r for r in after['statements'] if r['role_oid']==first['role_oid'] and r['query_id']==first['query_id'])
        sql(f"SELECT pg_stat_statements_reset({first['role_oid']}, {first['database_oid']}, {first['query_id']})")
        sql("SET ROLE pgproxy_cost_a; INSERT INTO public.pgproxy_cost_measure SELECT g, repeat('a',64) FROM generate_series(1,1000) g; RESET ROLE")
        targeted=collect()
        reset_entry=next(r for r in targeted['statements'] if r['role_oid']==first['role_oid'] and r['query_id']==first['query_id'])
        assert reset_entry['calls']==1 and reset_entry['rows']==1000
        actual_since=sql(f"SELECT COALESCE(to_jsonb(s)->>'stats_since','<unsupported>') FROM pg_stat_statements(false) s WHERE s.userid={first['role_oid']} AND s.dbid={first['database_oid']} AND s.queryid={first['query_id']} AND s.toplevel")
        if targeted['server_major']>=17:
            assert reset_entry['statistics_since']==actual_since
            assert reset_entry['statistics_since']!=prior_entry['statistics_since']
        else:
            assert reset_entry['statistics_since'] is None and actual_since=='<unsupported>'
        print('PASS targeted query reset reported with per-entry epoch when supported, no inferred deltas')
        old_reset=after['statistics_reset_at']
        sql('SELECT pg_stat_statements_reset()')
        reset=collect()
        assert reset['statistics_reset_at']!=old_reset
        assert not any(r['role'] in ('pgproxy_cost_a','pgproxy_cost_b') for r in reset['statements'])
        print('PASS reset metadata exposes counter discontinuity without inferred deltas')
        sql('DROP EXTENSION pg_stat_statements CASCADE')
        collect(error=True)
        sql('CREATE EXTENSION pg_stat_statements')
        print('PASS missing instrumentation fails closed without leaked credentials')
    print('7/7 server cost checks passed')


if __name__ == '__main__':
    main()
