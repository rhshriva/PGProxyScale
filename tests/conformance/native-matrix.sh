#!/usr/bin/env bash
# Native binary + disposable PostgreSQL containers; direct control and both modes.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
FIXTURE=$(mktemp -d "${TMPDIR:-/tmp}/pgproxy-matrix.XXXXXX")
CONTAINER="pgproxy-native-matrix-$$"
BACKEND_PORT=${PGPROXY_MATRIX_BACKEND_PORT:-55441}
PROXY_PORT=${PGPROXY_MATRIX_PROXY_PORT:-6442}
PROXY_PID=""
DRIVER_NETWORK_ARGS=()
if [[ "$(uname -s)" == Linux ]]; then DRIVER_NETWORK_ARGS=(--network host --add-host host.docker.internal:127.0.0.1); fi
cleanup_server() {
  if [[ -n "$PROXY_PID" ]]; then kill "$PROXY_PID" 2>/dev/null || true; wait "$PROXY_PID" 2>/dev/null || true; PROXY_PID=""; fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
cleanup() { cleanup_server; rm -rf "$FIXTURE"; }
trap cleanup EXIT
for MAJOR in ${PGPROXY_MATRIX_VERSIONS:-14 15 16 17 18}; do
  cleanup_server
  docker run -d --name "$CONTAINER" -p "127.0.0.1:$BACKEND_PORT:5432" -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=conformance "postgres:$MAJOR-alpine" >/dev/null
  for _ in $(seq 1 60); do if docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U postgres -d conformance >/dev/null 2>&1; then break; fi; sleep 1; done
  docker exec "$CONTAINER" psql -U postgres -d conformance -q -c "ALTER DATABASE conformance SET statement_timeout='10s'"
  cat > "$FIXTURE/config.toml" <<CONFIG
[general]
listen_addr = "0.0.0.0"
listen_port = $PROXY_PORT
workers = 2
[[databases]]
name = "conformance_session"
host = "127.0.0.1"
port = $BACKEND_PORT
dbname = "conformance"
pool_mode = "session"
[[databases]]
name = "conformance_transaction"
host = "127.0.0.1"
port = $BACKEND_PORT
dbname = "conformance"
user = "postgres"
pool_mode = "transaction"
client_auth = "trust"
pool_size = 2
CONFIG
  "$ROOT/target/debug/pgproxy" --log-level "${PGPROXY_MATRIX_LOG_LEVEL:-info}" --config "$FIXTURE/config.toml" > "$FIXTURE/proxy.log" 2>&1 &
  PROXY_PID=$!
  sleep 1
  for MODE in direct session transaction; do
    PORT=$PROXY_PORT; DATABASE="conformance_$MODE"
    if [[ "$MODE" == direct ]]; then PORT=$BACKEND_PORT; DATABASE=conformance; fi
    echo "PostgreSQL $MAJOR: $MODE"
    docker run --rm "${DRIVER_NETWORK_ARGS[@]}" -v "$ROOT/tests/conformance/drivers:/app:ro" -v pgproxy-conformance-pip:/root/.cache/pip python:3.12-slim sh -c 'pip install --quiet --root-user-action=ignore "psycopg[binary]" && python /app/psycopg_check.py --host host.docker.internal --port "$1" --dbname "$2" --user postgres --label "$3"' sh "$PORT" "$DATABASE" "pg$MAJOR-$MODE" || { cat "$FIXTURE/proxy.log"; exit 1; }
  done
  echo "PostgreSQL $MAJOR: asyncpg transaction"
  docker run --rm "${DRIVER_NETWORK_ARGS[@]}" -v "$ROOT/tests/conformance/drivers:/app:ro" -v pgproxy-conformance-pip:/root/.cache/pip python:3.12-slim sh -c 'pip install --quiet --root-user-action=ignore asyncpg && python /app/asyncpg_check.py --port "$1" --database conformance_transaction' sh "$PROXY_PORT" || { cat "$FIXTURE/proxy.log"; exit 1; }
done
