#!/usr/bin/env bash
# Disposable local diagnostic performance, never bare-metal certification.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUTPUT=${PGPROXY_PERF_OUTPUT:-$ROOT/deliverables/verification-next/performance}
BIN=${PGPROXY_BINARY:-$ROOT/target/release/pgproxy}
TAG=pgproxy-perf-$$
TMP=$(mktemp -d)
PID=''
cleanup() { if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; docker rm -f -v "$TAG" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT
mkdir -p "$OUTPUT"
NET=()
if [[ "$(uname -s)" == Linux ]]; then NET=(--network host --add-host host.docker.internal:127.0.0.1); fi
docker run -d --name "$TAG" -p 127.0.0.1:55444:5432 -e POSTGRES_DB=performance -e POSTGRES_HOST_AUTH_METHOD=trust postgres:18-alpine >/dev/null
for n in $(seq 1 60); do docker exec "$TAG" pg_isready -h 127.0.0.1 -U postgres -d performance >/dev/null 2>&1 && break; sleep .2; done
docker exec "$TAG" psql -U postgres -d performance -v ON_ERROR_STOP=1 -c 'CREATE TABLE pgproxy_perf_probe(client_id int, operation_id bigint)' >/dev/null
cat > "$TMP/proxy.toml" <<CONFIG
[general]
listen_addr = "0.0.0.0"
listen_port = 6449
workers = 2
[[databases]]
name = "performance"
host = "127.0.0.1"
port = 55444
dbname = "performance"
user = "postgres"
client_auth = "trust"
pool_mode = "transaction"
pool_size = 2
CONFIG
"$BIN" --config "$TMP/proxy.toml" > "$OUTPUT/proxy.log" 2>&1 &
PID=$!
for n in $(seq 1 50); do docker run --rm "${NET[@]}" postgres:18-alpine pg_isready -h host.docker.internal -p 6449 -U postgres -d performance >/dev/null 2>&1 && break; sleep .2; done
# Runtime provenance is local: the owned PID was launched from the exact passed executable.
python3 - "$BIN" "$PID" "$OUTPUT" <<'PY'
import hashlib,json,pathlib,sys
pathlib.Path(sys.argv[3],'local-process-provenance.json').write_text(json.dumps({'owned_proxy_pid':int(sys.argv[2]),'release_binary_sha256':hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest(),'scope':'owned local release process; not remote deployment or bare-metal proof'},indent=2)+'\n')
PY
docker run --rm "${NET[@]}" -v "$ROOT:/app:ro" -v "$OUTPUT:/evidence" -v "$BIN:/measured-release:ro" -w /app -e PGPROXY_PERF_DIRECT='host=host.docker.internal port=55444 user=postgres dbname=performance sslmode=disable' -e PGPROXY_PERF_PROXY='host=host.docker.internal port=6449 user=postgres dbname=performance sslmode=disable' python:3.12-slim sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends git >/dev/null && git config --global --add safe.directory /app && pip install --quiet "psycopg[binary]" && python benchmarks/acceptance.py --authorize-probe-writes --rollback-observer-dsn-env PGPROXY_PERF_DIRECT --slo-file benchmarks/local-smoke-slo.json --target direct=PGPROXY_PERF_DIRECT --target proxy=PGPROXY_PERF_PROXY --release-binary /measured-release --output-directory /evidence'
[[ "$(docker exec "$TAG" psql -U postgres -d performance -Atc 'SELECT count(*) FROM pgproxy_perf_probe')" == 0 ]]
echo 'PASS: independent direct database check confirms all transaction probes rolled back'
