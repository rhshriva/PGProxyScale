import importlib.util
import math
import pathlib
import time
import unittest
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
latency=load('protocol_latency',ROOT/'benchmarks/protocol_latency.py')
acceptance=load('performance_acceptance',ROOT/'benchmarks/acceptance.py')

class Stream:
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def sendall(self,data):pass

class BenchmarkTests(unittest.TestCase):
    def test_warmup_is_excluded_from_measurement_start_and_denominator(self):
        started=time.perf_counter()
        with patch.object(latency,'session',return_value=(Stream(),b'x')),patch.object(latency,'ready',side_effect=lambda stream:time.sleep(.01)):
            result=latency.run('unused',2,.03,'simple')
        self.assertGreater(time.perf_counter()-started,.07)
        self.assertGreater(result['queries'],0)
        self.assertGreaterEqual(result['actual_elapsed_seconds'],.03)
        self.assertLess(result['actual_elapsed_seconds'],.07)
        self.assertAlmostEqual(result['tps'],result['queries']/result['actual_elapsed_seconds'])

    def test_nonfinite_duration_rejected_before_network(self):
        for value in [float('nan'),float('inf'),-1,0]:
            with self.assertRaises(ValueError):latency.run('unused',1,value,'simple')

    def test_histogram_upper_bounds_are_conservative(self):
        for nanoseconds in [1,2,999,1000,999999,1000000,10**9,5*10**9]:
            index=max(0,math.ceil(math.log(nanoseconds)/math.log(acceptance.HISTOGRAM_RATIO)))
            while acceptance.bucket_upper(index)<nanoseconds:index+=1
            upper=acceptance.bucket_upper(index)
            self.assertGreaterEqual(upper,nanoseconds)
            self.assertLessEqual(upper,nanoseconds*acceptance.HISTOGRAM_RATIO+1)

    def test_sample_budget_is_global_and_capped(self):
        self.assertLessEqual(latency.MAX_SAMPLE_BUDGET,250000)
        self.assertEqual(acceptance.HISTOGRAM_BINS*8*64,20480000)

if __name__=='__main__':unittest.main()
