#!/usr/bin/env python3
"""Live late-bound credential expiry/rotation/refusal and measured wire usage checks."""
import argparse,json,pathlib,time,urllib.request
import psycopg
p=argparse.ArgumentParser();p.add_argument('--host',default='host.docker.internal');p.add_argument('--port',type=int,default=6447);p.add_argument('--fixtures',type=pathlib.Path,default=pathlib.Path('/fixtures'));a=p.parse_args()
def connection(route,user='postgres'):
    return psycopg.connect(host=a.host,port=a.port,dbname=route,user=user,password='pgproxy-client-test',sslmode='disable',autocommit=True,connect_timeout=4)
def values(route,user='postgres'):
    with connection(route,user) as c:return c.execute('SELECT current_user, pg_catalog.pg_backend_pid()').fetchone()
def lease(role,remaining):
    password='pgproxy-credential-test-'+role[-1]
    (a.fixtures/'lease.json').write_text(json.dumps({'user':role,'password':password,'expires_at':int(time.time())+remaining}))
lease('pgproxy_credential_a',2)
old=values('credential_file');assert old[0]=='pgproxy_credential_a'
time.sleep(2.1);lease('pgproxy_credential_b',2)
new=values('credential_file');assert new[0]=='pgproxy_credential_b' and old[1]!=new[1]
print('PASS file lease expiry rotates physical backend role',flush=True)
old=values('credential_command');assert old[0]=='pgproxy_credential_b'
time.sleep(2.1);lease('pgproxy_credential_a',2)
new=values('credential_command');assert new[0]=='pgproxy_credential_a' and old[1]!=new[1]
print('PASS bounded command broker issues rotated backend identity',flush=True)
old=values('credential_environment');time.sleep(2.1);new=values('credential_environment');assert old[0]==new[0]=='pgproxy_credential_a' and old[1]!=new[1]
print('PASS environment lease retires expired idle socket',flush=True)
time.sleep(2.1);(a.fixtures/'lease.json').write_text('{"user":"pgproxy_credential_a","password":"do-not-log-this","expires_at":1}')
try:values('credential_file')
except psycopg.OperationalError as e:assert 'do-not-log-this' not in str(e)
else:raise AssertionError('expired credential reused')
print('PASS expired issuer output fails closed without stale reuse or secret errors',flush=True)
for user in ['postgres','other']:
    with connection('credential_environment',user) as c:
        for _ in range(3):assert c.execute('SELECT %s::int',(42,),prepare=True).fetchone()==(42,)
        assert c.execute('SELECT 42').fetchone()==(42,)
request=urllib.request.Request(f'http://{a.host}:6455/usage',headers={'Authorization':'Bearer pgproxy-credential-usage-test-token-123456789'})
with urllib.request.urlopen(request,timeout=4) as response:report=json.load(response)
for user in ['postgres','other']:
    records=[r for r in report['accounts'] if r['identity']['user']==user]
    assert sum(r['rows'] for r in records)>=4
    assert sum(r['result_bytes'] for r in records)>0
    assert all(r['cpu_us'] is None and r['buffers'] is None and r['wal_bytes'] is None for r in records)
assert 'SELECT' not in json.dumps(report) and 'do-not-log-this' not in json.dumps(report)
print('PASS usage report accounts for both protocol paths/principals; unmeasured server costs remain unknown',flush=True)
print('5/5 credentials/usage checks passed')
