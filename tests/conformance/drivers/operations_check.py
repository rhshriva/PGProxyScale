#!/usr/bin/env python3
"""Operations acceptance with a real PostgreSQL protocol client (stdlib only)."""
import argparse
import json
import os
import socket
import struct
import time
import urllib.error
import urllib.request

p=argparse.ArgumentParser()
p.add_argument('--port',type=int,default=6439)
p.add_argument('--operations',default='http://127.0.0.1:6450')
a=p.parse_args()
token=os.environ['PGPROXY_OPERATIONS_TOKEN']
def http(path,authenticated=True):
    headers={'Authorization':'Bearer '+token} if authenticated else {}
    with urllib.request.urlopen(urllib.request.Request(a.operations+path,headers=headers),timeout=2) as response:
        return response.read().decode()
def exact(s,n):
    out=b''
    while len(out)<n:
        data=s.recv(n-len(out))
        if not data:raise RuntimeError('unexpected EOF')
        out+=data
    return out
def ready(s):
    while True:
        tag=exact(s,1);length=struct.unpack('!I',exact(s,4))[0]
        payload=exact(s,length-4)
        if tag==b'E':raise RuntimeError('database error')
        if tag==b'Z':return payload
with socket.create_connection(('127.0.0.1',a.port),timeout=3) as client:
    body=struct.pack('!I',196608)+b'user\0postgres\0database\0areas_transaction\0application_name\0operations-acceptance\0\0'
    client.sendall(struct.pack('!I',len(body)+4)+body);ready(client)
    assert json.loads(http('/health',False))['alive']
    assert json.loads(http('/ready',False))['accepting']
    try:http('/clients',False)
    except urllib.error.HTTPError as error:assert error.code==401
    else:raise AssertionError('unauthenticated diagnostics exposed')
    def query(sql):
        body=sql.encode()+b'\0';client.sendall(b'Q'+struct.pack('!I',len(body)+4)+body);return ready(client)
    assert query('BEGIN')==b'T'
    clients=json.loads(http('/clients'))['clients']
    matching=[c for c in clients if c['principal']=='postgres' and c['database']=='areas_transaction']
    assert any(c['transaction']=='transaction' and c['bytes_in']>0 for c in matching)
    assert query('ROLLBACK')==b'I'
    query('SELECT 42')
    metrics=http('/metrics')
    assert 'pgproxy_exchange_duration_seconds_bucket' in metrics
    assert 'pgproxy_exchange_duration_seconds_count 0\n' not in metrics
    pools=json.loads(http('/pools'))
    assert pools and all('password' not in str(pool).lower() for pool in pools)
    assert 'operations-acceptance' not in metrics
    client.sendall(b'X'+struct.pack('!I',4))
print('PASS authenticated metrics, health/readiness, client transaction/traffic diagnostics and pool stats')
