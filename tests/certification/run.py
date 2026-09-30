#!/usr/bin/env python3
"""Reproducible release evidence; external deployment certification stays explicit."""
import argparse, datetime, hashlib, json, pathlib, platform, re, subprocess, sys, time
ROOT = pathlib.Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=pathlib.Path, default=ROOT / 'target/certification/report.json')
p.add_argument('--live', action='store_true', help='run disposable replication acceptance (Docker required)')
p.add_argument('--linux', action='store_true', help='run isolated Linux workspace tests and strict lint')
a = p.parse_args()
a.output.parent.mkdir(parents=True, exist_ok=True)
from evidence import source_identity as identify_source
def source_identity():
    return identify_source(ROOT)
source_start = source_identity()
environment = {'platform': platform.platform(), 'rustc': subprocess.check_output(['rustc','-Vv'], cwd=ROOT, text=True).strip(), 'cargo': subprocess.check_output(['cargo','--version'], cwd=ROOT, text=True).strip()}
gates = []
def gate(name, command, timeout):
    log = a.output.parent / (name + '.log')
    start = time.monotonic()
    try:
        with log.open('w') as handle:
            result = subprocess.run(command, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT, timeout=timeout)
        status = 'pass' if result.returncode == 0 else 'fail'
    except subprocess.TimeoutExpired:
        status = 'fail'
    log_text = log.read_text(errors='replace')
    counts = re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed;', log_text)
    gates.append({'name': name, 'status': status, 'seconds': round(time.monotonic()-start, 2), 'log': str(log), 'tests_passed': sum(int(item[0]) for item in counts), 'tests_failed': sum(int(item[1]) for item in counts)})
    return status == 'pass'
gate('certification-evidence-tests', ['python3', '-m', 'unittest', 'discover', '-s', 'tests/certification', '-p', 'test_*.py'], 120)
gate('workspace-tests', ['cargo', 'test', '--workspace'], 300)
gate('strict-lint', ['cargo', 'clippy', '--workspace', '--all-targets', '--', '-D', 'warnings'], 300)
gate('release-build', ['cargo', 'build', '--workspace', '--release'], 600)
if a.live:
    if gate('build', ['cargo', 'build', '--workspace'], 300):
        gate('replicated-failover', ['bash', 'tests/conformance/failover/run.sh'], 300)
        gate('fenced-local-fixture', ['env', 'PGPROXY_FAILOVER_FENCE_MODE=power_off', 'bash', 'tests/conformance/failover/run.sh'], 300)
    else:
        gates.append({'name': 'replicated-failover', 'status': 'blocked-by-build'})
else:
    gates.append({'name': 'replicated-failover', 'status': 'not-run'})
if a.linux:
    gate('linux-tests-lint', ['docker', 'run', '--rm', '-v', str(ROOT)+':/app', '-v', 'pgproxy-conformance-target:/target', '-v', 'pgproxy-linux-cargo:/usr/local/cargo', '-v', 'pgproxy-linux-rustup:/usr/local/rustup', '-w', '/app', '-e', 'CARGO_TARGET_DIR=/target', 'rust:1.91-slim-bookworm', 'sh', '-c', 'apt-get update -qq && apt-get install -y -qq --no-install-recommends make >/dev/null && cargo test --workspace && cargo build --workspace --release && cargo clippy --workspace --all-targets -- -D warnings'], 900)
else:
    gates.append({'name': 'linux-tests-lint', 'status': 'not-run'})
for name in ['independent-security-review', 'deployment-fencing-and-split-brain-review', 'bare-metal-performance-and-soak', 'real-credential-provider-integration']:
    gates.append({'name': name, 'status': 'external-evidence-required'})
try:
    revision = subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip()
except subprocess.CalledProcessError:
    revision = None
source_end = source_identity()
gates.append({'name': 'source-stability', 'status': 'pass' if source_start == source_end else 'fail'})
binaries = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in [ROOT/'target/debug/pgproxy', ROOT/'target/release/pgproxy'] if path.is_file()}
report = {'binary_sha256': binaries, 'source_sha256_start': source_start, 'source_sha256_end': source_end, 'environment': environment, 'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'git_revision': revision, 'working_tree_included': True, 'working_tree_status': subprocess.check_output(['git','status','--porcelain'], cwd=ROOT, text=True), 'production_certified': False, 'gates': gates}
a.output.write_text(json.dumps(report, indent=2)+'\n')
print(f'Evidence report: {a.output}. Production certification requires external gates.')
sys.exit(1 if any(item['status']=='fail' for item in gates) else 0)
