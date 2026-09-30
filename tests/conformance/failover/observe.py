#!/usr/bin/env python3
"""Read-only multi-endpoint topology observer; does not fence/promote or certify infrastructure."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import sys
import time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]/'certification'))
from evidence import source_identity, strict_json

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--authorize-live',action='store_true')
    p.add_argument('--manifest',required=True,type=pathlib.Path,help='deployment_id, vantage_id, endpoints {server_id,dsn_env}')
    p.add_argument('--release-binary',required=True,type=pathlib.Path)
    p.add_argument('--duration-secs',type=float,default=30)
    p.add_argument('--output',required=True,type=pathlib.Path)
    a=p.parse_args()
    if not a.authorize_live:p.error('explicit authorization required; no connections made')
    if not math.isfinite(a.duration_secs) or not 1<=a.duration_secs<=3600:p.error('duration outside bounded limits')
    manifest=strict_json(a.manifest)
    endpoints=manifest['endpoints']
    if not 2<=len(endpoints)<=8 or len({e['server_id'] for e in endpoints})!=len(endpoints):p.error('distinct endpoint identities required')
    import psycopg
    for endpoint in endpoints:
        options=psycopg.conninfo.conninfo_to_dict(os.environ[endpoint["dsn_env"]])
        if options.get("sslmode")!="verify-full" or not options.get("sslrootcert"):
            p.error("every observer DSN requires sslmode=verify-full and sslrootcert")
    def probe(endpoint):
        observed={'server_id':endpoint['server_id']}
        try:
            with psycopg.connect(os.environ[endpoint['dsn_env']],autocommit=True,connect_timeout=3,options='-cstatement_timeout=1000') as connection:
                row=connection.execute("SELECT pg_catalog.pg_is_in_recovery(), pg_catalog.current_setting('transaction_read_only'), ssl FROM pg_catalog.pg_stat_ssl WHERE pid=pg_catalog.pg_backend_pid()").fetchone()
                if not row or row[2] is not True:raise RuntimeError('encrypted probe required')
                observed.update(recovery=row[0],transaction_read_only=row[1],writable=not row[0] and row[1]=='off',reachable=True)
        except Exception as error:observed.update(reachable=False,failure_type=type(error).__name__)
        return observed
    root=pathlib.Path(__file__).resolve().parents[3]
    report={'deployment_id':manifest['deployment_id'],'vantage_id':manifest['vantage_id'],'source_sha256':source_identity(root),'release_binary_sha256':hashlib.sha256(a.release_binary.read_bytes()).hexdigest(),'production_certified':False,'scope':'sampled read-only role observations; authoritative fencing audit and write probes remain required','samples':[]}
    deadline=time.monotonic()+a.duration_secs
    with ThreadPoolExecutor(max_workers=len(endpoints)) as workers:
        while time.monotonic()<deadline:
            observations=list(workers.map(probe,endpoints))
            report['samples'].append({'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),'endpoints':observations,'writable_count':sum(bool(e.get('writable')) for e in observations)})
            time.sleep(min(.5,max(0,deadline-time.monotonic())))
    report['dual_writable_observed']=any(sample['writable_count']>1 for sample in report['samples'])
    report['unknown_endpoints_observed']=any(not e['reachable'] for sample in report['samples'] for e in sample['endpoints'])
    report["source_sha256_after"]=source_identity(root)
    report["release_binary_sha256_after"]=hashlib.sha256(a.release_binary.read_bytes()).hexdigest()
    report["identity_stable"]=report["source_sha256"]==report["source_sha256_after"] and report["release_binary_sha256"]==report["release_binary_sha256_after"]
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
    print('Dual writable endpoints detected.' if report['dual_writable_observed'] else 'No dual writable state sampled; this does not prove fencing.')
    return 1 if report['dual_writable_observed'] or not report['identity_stable'] else 0

if __name__=='__main__':sys.exit(main())
