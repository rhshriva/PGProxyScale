#!/usr/bin/env python3
"""Reproducible SELECT42 workload, latency percentiles and explicit reference gates."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import math
import platform
import time
import psycopg


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--database", required=True)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--queries-per-client", type=int, default=1000)
    parser.add_argument("--label", default="candidate")
    parser.add_argument("--output")
    parser.add_argument("--baseline", help="JSON from the same workload and hardware")
    parser.add_argument("--max-p99-ratio", type=float, default=1.5)
    parser.add_argument("--min-throughput-ratio", type=float, default=0.8)
    args = parser.parse_args()
    if not 1 <= args.clients <= 1000 or not 1 <= args.queries_per_client <= 1_000_000:
        parser.error("client/query count outside bounded benchmark limits")

    def worker(_):
        measurements = []
        with psycopg.connect(host=args.host, port=args.port, dbname=args.database,
                            user="postgres", sslmode="disable", connect_timeout=5,
                            autocommit=True, options="-cstatement_timeout=5000") as connection:
            for _ in range(10):
                assert connection.execute("SELECT 42").fetchone() == (42,)
            for _ in range(args.queries_per_client):
                started = time.perf_counter_ns()
                assert connection.execute("SELECT 42").fetchone() == (42,)
                measurements.append((time.perf_counter_ns() - started) / 1_000_000)
        return measurements

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.clients) as workers:
        samples = sorted(value for result in workers.map(worker, range(args.clients)) for value in result)
    elapsed = time.perf_counter() - started
    def percentile(percent):
        return samples[max(0, math.ceil(len(samples) * percent) - 1)]
    result = dict(label=args.label, workload="SELECT 42", clients=args.clients,
                  queries_per_client=args.queries_per_client, queries=len(samples),
                  elapsed_seconds=elapsed, throughput_qps=len(samples) / elapsed,
                  p50_ms=percentile(.50), p95_ms=percentile(.95), p99_ms=percentile(.99),
                  driver="psycopg-" + psycopg.__version__, platform=platform.platform())
    if args.baseline:
        with open(args.baseline, encoding="utf-8") as handle:
            baseline = json.load(handle)
        for name in ("workload", "clients", "queries_per_client", "driver", "platform"):
            if baseline[name] != result[name]:
                raise ValueError("baseline workload/environment differs: " + name)
        result["gate_passed"] = (result["p99_ms"] <= baseline["p99_ms"] * args.max_p99_ratio
                                 and result["throughput_qps"] >= baseline["throughput_qps"] * args.min_throughput_ratio)
    encoded = json.dumps(result, indent=2, sort_keys=True)
    print(encoded, flush=True)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(encoded + "\n")
    return not result.get("gate_passed", True)


if __name__ == "__main__":
    raise SystemExit(main())
