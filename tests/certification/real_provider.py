#!/usr/bin/env python3
"""Authorized real AWS RDS/Vault acceptance. No secrets in evidence or command arguments."""
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time
from urllib.parse import urlsplit
from evidence import source_identity

OBSERVATIONS={'authenticated','backend_tls_verified','lease_expiry_rotation','expired_lease_rejected','provider_failure_closed'}

def cli(command):
    result=subprocess.run(command,capture_output=True,timeout=30,stdin=subprocess.DEVNULL)
    if result.returncode or len(result.stdout)>65536:raise RuntimeError('provider CLI failed or output exceeded bound')
    return result.stdout

def identity(connection):
    row=connection.execute("SELECT current_user, pg_catalog.pg_backend_pid(), ssl FROM pg_catalog.pg_stat_ssl WHERE pid=pg_catalog.pg_backend_pid()").fetchone()
    if not row or row[2] is not True:raise RuntimeError('encrypted backend identity probe failed')
    return {'user':row[0],'pid':row[1],'backend_ssl':True}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--authorize-live',action='store_true',help='explicit authorization for provider issuance and read-only database probes; Vault issuance creates dynamic credentials')
    p.add_argument('--kind',choices=['aws_rds','vault'],required=True)
    p.add_argument('--host',required=True);p.add_argument('--port',type=int,default=5432)
    p.add_argument('--database',required=True);p.add_argument('--user',required=True)
    p.add_argument('--region');p.add_argument('--vault-role-path')
    p.add_argument('--backend-ca',required=True,type=pathlib.Path)
    p.add_argument('--proxy-dsn-env',required=True)
    p.add_argument('--failure-proxy-dsn-env',help='operator-preconfigured issuer-failure route on the same authorized proxy; never disable a production provider here')
    p.add_argument('--deployment-id',required=True);p.add_argument('--release-binary',required=True,type=pathlib.Path)
    p.add_argument('--wait-for-expiry',action='store_true',help='wait actual lease TTL plus 30 seconds, up to two hours')
    p.add_argument('--output',required=True,type=pathlib.Path)
    a=p.parse_args()
    if not a.authorize_live:p.error('live provider authorization is required; no requests were made')
    if not 1<=a.port<=65535 or not a.host or a.host.startswith('-'):p.error('invalid endpoint')
    if a.proxy_dsn_env not in os.environ:p.error('proxy DSN environment is missing')
    if a.kind=='aws_rds' and not a.region:p.error('AWS region required')
    if a.kind=='vault' and (not a.vault_role_path or '/creds/' not in a.vault_role_path or a.vault_role_path.startswith('-') or '..' in a.vault_role_path):p.error('valid Vault dynamic-role path required')
    if a.kind=='vault':
        address=urlsplit(os.environ.get('VAULT_ADDR',''))
        if address.scheme!='https' or not address.hostname or address.username or address.password or os.environ.get('VAULT_SKIP_VERIFY','').lower() not in {'','false','0'}:p.error('Vault acceptance requires HTTPS and certificate verification')
    import psycopg
    parameters=psycopg.conninfo.conninfo_to_dict(os.environ[a.proxy_dsn_env])
    if parameters.get('sslmode')!='verify-full' or not parameters.get('sslrootcert'):p.error('proxy DSN requires explicit verify-full and trusted CA')
    report={'kind':a.kind,'deployment_id':a.deployment_id,'endpoint':a.host+':'+str(a.port),'identity':a.user,'source_sha256':source_identity(pathlib.Path(__file__).resolve().parents[2]),'release_binary_sha256':hashlib.sha256(a.release_binary.read_bytes()).hexdigest(),'created_at':dt.datetime.now(dt.timezone.utc).isoformat(),'production_certified':False,'observations':[],'remote_binary_identity_verified':False,'limitations':['Remote deployed binary/configuration identity must be independently verified by the attesting operator. This runner does not sign its own output or perform infrastructure failover.']}
    def issue():
        if a.kind=='aws_rds':
            return a.user,cli(['aws','rds','generate-db-auth-token','--hostname',a.host,'--port',str(a.port),'--username',a.user,'--region',a.region]).decode().strip(),900
        value=json.loads(cli(['vault','read','-format=json',a.vault_role_path]))
        return value['data']['username'],value['data']['password'],value['lease_duration']
    def connect(user,password):
        return psycopg.connect(host=a.host,port=a.port,dbname=a.database,user=user,password=password,sslmode='verify-full',sslrootcert=str(a.backend_ca),connect_timeout=5,autocommit=True,options='-cstatement_timeout=5000')
    try:
        user,password,ttl=issue()
        if not 1<=ttl<=7200 or not password:raise RuntimeError('unsupported or empty provider lease')
        with connect(user,password) as direct:report['direct_initial']=identity(direct)
        report['observations']+=['authenticated','backend_tls_verified']
        with psycopg.connect(os.environ[a.proxy_dsn_env],autocommit=True,connect_timeout=5) as proxy:
            report['proxy_initial']=identity(proxy)
            if a.kind=='aws_rds' and report['proxy_initial']['user']!=report['direct_initial']['user']:raise RuntimeError('proxy backend principal differs from authentic IAM principal')
            if a.wait_for_expiry:
                deadline=time.monotonic()+ttl+30
                while time.monotonic()<deadline:time.sleep(min(30,deadline-time.monotonic()))
                try:
                    with connect(user,password) as expired:identity(expired)
                except psycopg.Error as error:
                    if error.sqlstate in {'28000','28P01'}:report['observations'].append('expired_lease_rejected')
                fresh_user,fresh_password,_=issue()
                with connect(fresh_user,fresh_password) as fresh:report['direct_after_expiry']=identity(fresh)
                try:report['proxy_after_expiry']=identity(proxy)
                except psycopg.Error:
                    with psycopg.connect(os.environ[a.proxy_dsn_env],autocommit=True,connect_timeout=5) as replacement:report['proxy_after_expiry']=identity(replacement)
                    report['observations'].append('frontend_reconnected_after_lease_retirement')
                if report['proxy_initial']['pid']!=report['proxy_after_expiry']['pid'] and (a.kind=='aws_rds' or report['proxy_initial']['user']!=report['proxy_after_expiry']['user']):report['observations'].append('lease_expiry_rotation')
        if a.failure_proxy_dsn_env:
            if a.failure_proxy_dsn_env not in os.environ:raise RuntimeError('failure-route DSN missing')
            try:
                with psycopg.connect(os.environ[a.failure_proxy_dsn_env],autocommit=True,connect_timeout=5) as failure:failure.execute('SELECT 1').fetchone()
            except psycopg.Error as error:
                if error.sqlstate in {'08006','08001','57P03','XX000'}:report['observations'].append('provider_failure_closed')
        report['complete']=OBSERVATIONS<=set(report['observations'])
    except Exception as error:
        report['complete']=False;report['failure_type']=type(error).__name__
    report['source_sha256_after']=source_identity(pathlib.Path(__file__).resolve().parents[2])
    report['release_binary_sha256_after']=hashlib.sha256(a.release_binary.read_bytes()).hexdigest()
    report['complete']=report['complete'] and report['source_sha256']==report['source_sha256_after'] and report['release_binary_sha256']==report['release_binary_sha256_after']
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
    print('Real provider lifecycle observations complete.' if report['complete'] else 'Provider acceptance incomplete; see redacted report.')
    return 0 if report['complete'] else 2

if __name__=='__main__':sys.exit(main())
