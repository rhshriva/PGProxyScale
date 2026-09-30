#!/usr/bin/env python3
"""Source-bound actual SQL workloads and operator-declared SLOs; never self-certifies."""
import argparse
from array import array
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
import pathlib
import platform
import subprocess
import sys
import threading
import time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'tests/certification'))
from evidence import source_identity, strict_json

WORKLOADS={'simple_select','prepared_select','transaction_rollback'}
HISTOGRAM_RATIO=1.001
HISTOGRAM_BINS=40000
def bucket_upper(index):return math.ceil(math.exp(index*math.log(HISTOGRAM_RATIO)))

def hardware():
    detected=None
    if platform.system()=='Linux':
        try:
            result=subprocess.run(['systemd-detect-virt'],capture_output=True,text=True,timeout=5)
            if result.returncode in {0,1}:detected=result.stdout.strip()!='none'
        except (OSError,subprocess.TimeoutExpired):pass
    identity='unidentified'
    for path in ['/sys/class/dmi/id/product_uuid','/etc/machine-id']:
        try:identity=pathlib.Path(path).read_text().strip();break
        except OSError:pass
    return {'hardware_id':hashlib.sha256((platform.platform()+identity).encode()).hexdigest(),'platform':platform.platform(),'cpu_count':os.cpu_count(),'platform_class':'bare_metal' if detected is False else 'virtualized' if detected else 'unknown','virtualization_detected':detected}

def run_workload(dsn,name,limit,metadata):
    import psycopg
    clients=limit['clients'];seconds=limit['duration_secs']
    if not 1<=clients<=64 or not math.isfinite(seconds) or not 0<seconds<=172800:raise ValueError('invalid workload bounds')
    clock=[None]
    barrier=threading.Barrier(clients,action=lambda:clock.__setitem__(0,time.perf_counter_ns()))
    def execute(connection,index,operation):
        if name=='simple_select':
            if connection.execute('SELECT 42',prepare=False).fetchone() != (42,):raise RuntimeError('simple SELECT result mismatch')
        elif name=='prepared_select':
            if connection.execute('SELECT %s::int',(42,),prepare=True).fetchone() != (42,):raise RuntimeError('prepared SELECT result mismatch')
        else:
            connection.execute('BEGIN',prepare=False)
            try:connection.execute('INSERT INTO pgproxy_perf_probe VALUES (%s,%s)',(index,operation),prepare=True)
            finally:connection.execute('ROLLBACK',prepare=False)
    def worker(index):
        histogram=array('Q',[0])*HISTOGRAM_BINS;overflow=0;errors=0;finished=0
        try:
            with psycopg.connect(dsn,autocommit=True,connect_timeout=5,options='-cstatement_timeout=5000') as connection:
                for operation in range(5):execute(connection,index,operation)
                barrier.wait(timeout=30)
                end=clock[0]+int(seconds*1e9);operation=5
                while time.perf_counter_ns()<end:
                    before=time.perf_counter_ns();success=True
                    try:execute(connection,index,operation)
                    except Exception:success=False;errors+=1
                    elapsed=time.perf_counter_ns()-before;operation+=1
                    bucket=max(0,math.ceil(math.log(max(1,elapsed))/math.log(HISTOGRAM_RATIO)))
                    while bucket<HISTOGRAM_BINS and bucket_upper(bucket)<elapsed:bucket+=1
                    if bucket<HISTOGRAM_BINS:histogram[bucket]+=1
                    else:overflow+=1
                    if not success:break
                finished=time.perf_counter_ns()
        except Exception:
            barrier.abort();errors+=1;finished=time.perf_counter_ns()
        return histogram,overflow,errors,finished
    with ThreadPoolExecutor(max_workers=clients) as pool:results=list(pool.map(worker,range(clients)))
    histogram=array('Q',[0])*HISTOGRAM_BINS
    for result in results:
        for index,count in enumerate(result[0]):histogram[index]+=count
    started=clock[0] or time.perf_counter_ns()
    finished=max(result[3] for result in results)
    duration=max(0,(finished-started)/1e9)
    count=sum(histogram)
    def percentile(percent):
        if not count:return None
        target=math.ceil(count*percent);observed=0
        for index,bucket_count in enumerate(histogram):
            observed+=bucket_count
            if observed>=target:return bucket_upper(index)/1e6
    overflow=sum(result[1] for result in results);errors=sum(result[2] for result in results)
    summary={'name':name,'clients':clients,'requested_duration_secs':seconds,'duration_secs':duration,'sample_count':count,'dropped_samples':overflow,'errors':errors,'p50_ms':percentile(.5),'p95_ms':percentile(.95),'p99_ms':percentile(.99),'throughput_ops_per_sec':count/duration if duration else 0}
    passed=errors==0 and overflow==0 and count>=limit['min_samples'] and count>0 and summary['p99_ms']<=limit['max_p99_ms'] and summary['throughput_ops_per_sec']>=limit['min_throughput_ops_per_sec']
    raw={**metadata,'name':name,'clients':clients,'started_ns':started,'finished_ns':finished,'dropped_samples':overflow,'errors':errors,'format':'log_histogram_v1','ratio':HISTOGRAM_RATIO,'max_bins':HISTOGRAM_BINS,'counts':[[index,value] for index,value in enumerate(histogram) if value]}
    return {**summary,'slo_passed':passed},raw

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--physical-inventory-reference',help='external lab physical asset registry reference; must be independently verified')
    p.add_argument('--authorize-probe-writes',action='store_true',help='authorize rolled-back INSERT probes on a dedicated, precreated test table')
    p.add_argument('--rollback-observer-dsn-env',required=True,help='direct independent connection to dedicated probe database')
    p.add_argument('--slo-file',required=True,type=pathlib.Path)
    p.add_argument('--target',action='append',required=True,help='label=DSN_ENV_VARIABLE; credentials never enter command arguments or output')
    p.add_argument('--release-binary',required=True,type=pathlib.Path)
    p.add_argument('--output-directory',required=True,type=pathlib.Path)
    a=p.parse_args();policy=strict_json(a.slo_file)
    if not a.authorize_probe_writes:p.error('rolled-back probe authorization required')
    if a.rollback_observer_dsn_env not in os.environ:p.error('rollback observer DSN missing')
    import psycopg
    def probe_rows():
        with psycopg.connect(os.environ[a.rollback_observer_dsn_env],autocommit=True,connect_timeout=5) as observer:
            return observer.execute('SELECT count(*) FROM pgproxy_perf_probe').fetchone()[0]
    if probe_rows()!=0:p.error('dedicated probe table must start empty')
    if set(policy['workloads'])!=WORKLOADS:p.error('all three declared workloads are required')
    root=pathlib.Path(__file__).resolve().parents[1];source=source_identity(root)
    inventory=hardware();inventory['physical_inventory_ref']=a.physical_inventory_reference;inventory['scope']='load_generator_only';binary=hashlib.sha256(a.release_binary.read_bytes()).hexdigest()
    a.output_directory.mkdir(parents=True,exist_ok=True)
    (a.output_directory/'hardware.json').write_text(json.dumps(inventory,indent=2)+'\n')
    metadata={'source_sha256':source,'release_binary_sha256':binary,'hardware_id':inventory['hardware_id']}
    report={**metadata,'hardware':inventory,'purpose':policy['purpose'],'production_certified':False,'deployed_endpoint_binary_identity_verified':False,'sample_policy':'complete bounded logarithmic histogram; latency quantiles are conservative upper bounds with ratio1.001 plus1ns rounding; any overflow fails','results':[]}
    for target in a.target:
        label,variable=target.split('=',1)
        if not label.isidentifier() or variable not in os.environ:p.error('target label/environment invalid')
        for name,limit in policy['workloads'].items():
            summary,raw=run_workload(os.environ[variable],name,limit,metadata)
            path=a.output_directory/(label+'-'+name+'.json');path.write_text(json.dumps(raw,separators=(',',':'))+'\n')
            report['results'].append({'target':label,**summary,'measurement_file':path.name,'measurement_sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    report['rollback_table_empty']=probe_rows()==0
    report['source_sha256_after']=source_identity(root)
    report['source_stable']=source==report['source_sha256_after']
    report['gate_passed']=report['source_stable'] and report['rollback_table_empty'] and all(result['slo_passed'] for result in report['results'])
    (a.output_directory/'performance.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Workload SLO gates passed.' if report['gate_passed'] else 'Workload SLO gates failed; see performance report.')
    return 0 if report['gate_passed'] else 1

if __name__=='__main__':sys.exit(main())
