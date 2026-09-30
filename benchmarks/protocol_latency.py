#!/usr/bin/env python3
"""Reproducible client latency/TPS comparison on isolated trust-auth test routes.

Example: --target direct=postgresql://postgres@localhost:5432/bench \
         --target proxy=postgresql://postgres@localhost:6432/bench --clients 4,64
Use a release build and run on bare-metal Linux before assessing production gates.
This harness measures end-to-end SELECT exchanges; it is not the full hard-case suite.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import math
import platform
import random
import socket
import struct
import threading
import time
from urllib.parse import urlsplit, unquote


def exact(stream, n):
    result=bytearray()
    while len(result)<n:
        data=stream.recv(n-len(result))
        if not data:raise RuntimeError('endpoint closed connection')
        result.extend(data)
    return bytes(result)


def ready(stream):
    while True:
        tag=exact(stream,1)
        length=struct.unpack('!I',exact(stream,4))[0]
        if length<4 or length>16*1024*1024:raise RuntimeError('invalid frame size')
        payload=exact(stream,length-4)
        if tag==b'E':raise RuntimeError('query/authentication failed')
        if tag==b'R' and payload!=b'\0\0\0\0':raise RuntimeError('benchmark needs isolated trust authentication')
        if tag==b'Z':return


def frame(tag,payload):return tag+struct.pack('!I',len(payload)+4)+payload


def session(endpoint,workload):
    url=urlsplit(endpoint)
    stream=socket.create_connection((url.hostname,url.port or 5432),timeout=5)
    stream.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    body=struct.pack('!I',196608)
    for name,value in [('user',unquote(url.username or 'postgres')),('database',unquote(url.path.lstrip('/'))),('application_name','pgproxy-latency-harness')]:
        body+=name.encode()+b'\0'+value.encode()+b'\0'
    body+=b'\0';stream.sendall(struct.pack('!I',len(body)+4)+body);ready(stream)
    if workload=='prepared':
        stream.sendall(frame(b'P',b'bench\0SELECT 42\0\0\0')+frame(b'S',b''));ready(stream)
        exchange=frame(b'B',b'\0bench\0\0\0\0\0\0\0')+frame(b'E',b'\0\0\0\0\0')+frame(b'S',b'')
    else:exchange=frame(b'Q',b'SELECT 42\0')
    return stream,exchange


MAX_SAMPLE_BUDGET=250000

def run(endpoint,clients,seconds,workload):
    if not math.isfinite(seconds) or not 0 < seconds <= 3600 or not 1 <= clients <= 256:
        raise ValueError("invalid duration/concurrency")
    sample_cap=min(100000,MAX_SAMPLE_BUDGET//clients)
    start=[None]
    barrier=threading.Barrier(clients+1, action=lambda: start.__setitem__(0, time.perf_counter()))
    def worker(index):
        rng=random.Random(index)
        samples=[];count=0
        try:
            stream,exchange=session(endpoint,workload)
            with stream:
                for _ in range(5):stream.sendall(exchange);ready(stream)
                barrier.wait(timeout=15)
                while time.perf_counter()<start[0]+seconds:
                    before=time.perf_counter_ns();stream.sendall(exchange);ready(stream)
                    elapsed=(time.perf_counter_ns()-before)/1000
                    count+=1
                    if len(samples)<sample_cap:samples.append(elapsed)
                    else:
                        candidate=rng.randrange(count)
                        if candidate<sample_cap:samples[candidate]=elapsed
                finished=time.perf_counter()
                stream.sendall(frame(b'X',b''))
            return count,samples,None,finished
        except Exception as error:
            barrier.abort()
            return count,samples,type(error).__name__,time.perf_counter()
    with ThreadPoolExecutor(max_workers=clients) as pool:
        futures=[pool.submit(worker,index) for index in range(clients)]
        try:barrier.wait(timeout=15)
        except threading.BrokenBarrierError:pass
        results=[future.result(timeout=seconds+20) for future in futures]
    # Each client's unbiased reservoir has weight count/sample_count. This
    # avoids over-representing slow clients when only fast clients hit the cap.
    samples=sorted((value,count/len(values)) for count,values,_,_ in results if values for value in values)
    total=sum(count for count,_,_,_ in results)
    elapsed=max(finished for _,_,_,finished in results)-start[0] if start[0] is not None else 0
    def percentile(percent):
        if not samples:return None
        target=sum(weight for _,weight in samples)*percent
        cumulative=0
        for value,weight in samples:
            cumulative+=weight
            if cumulative>=target:return value
        return samples[-1][0]
    return {'clients':clients,'workload':workload,'requested_seconds':seconds,'actual_elapsed_seconds':elapsed,'queries':total,
            'tps':total/elapsed if elapsed>0 else 0,'samples':len(samples),
            'p50_us':percentile(.5),'p95_us':percentile(.95),'p99_us':percentile(.99),
            'sample_cap_per_client':sample_cap,'global_sample_budget':MAX_SAMPLE_BUDGET,'sample_policy':'deterministic per-client Algorithm R reservoir, weighted by completed count; estimated percentiles',
            'truncated_samples':total-len(samples),'errors':[error for _,_,error,_ in results if error]}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target',action='append',required=True,help='label=postgresql://user@host:port/database')
    p.add_argument('--clients',default='4,64')
    p.add_argument('--seconds',type=float,default=10)
    p.add_argument('--workload',choices=['simple','prepared'],default='simple')
    p.add_argument('--profile',choices=['debug','release','external'],required=True)
    args=p.parse_args()
    counts=[int(c) for c in args.clients.split(',')]
    if not math.isfinite(args.seconds) or args.seconds<=0 or args.seconds>3600 or any(c<1 or c>256 for c in counts):p.error('invalid duration/concurrency')
    output={'platform':platform.platform(),'python':platform.python_version(),'profile':args.profile,
            'gate_certified':False,'measurement':'client protocol exchange latency; unbiased per-client reservoirs, weighted percentile estimates', 'results':[]}
    for target in args.target:
        label,endpoint=target.split('=',1)
        url=urlsplit(endpoint)
        if url.password or url.scheme!='postgresql' or not url.hostname or not url.path:p.error('use isolated trust routes without passwords')
        for clients in counts:
            result=run(endpoint,clients,args.seconds,args.workload)
            output['results'].append({'target':label,**result})
    print(json.dumps(output,indent=2))
    return any(r['errors'] for r in output['results'])

if __name__=='__main__':raise SystemExit(main())
