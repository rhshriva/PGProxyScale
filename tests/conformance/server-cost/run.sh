#!/usr/bin/env bash
# Exact server-counter verification on disposable supported PostgreSQL versions.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
CONTAINER="pgproxy-server-cost-matrix-$$"
PORT=${PGPROXY_COST_BACKEND_PORT:-55448}
cleanup() { docker rm -f -v "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
for MAJOR in ${PGPROXY_COST_VERSIONS:-14 15 16 17 18}; do
  cleanup
  IMAGE=${PGPROXY_COST_POSTGRES_IMAGE:-postgres:$MAJOR-alpine}
  PRELOAD=pg_stat_statements
  DRIVER_ARGS=()
  if [[ "${PGPROXY_COST_REQUIRE_CPU:-0}" == 1 ]]; then
    PRELOAD=pg_stat_statements,pg_stat_kcache
    DRIVER_ARGS=(--require-cpu)
  fi
  docker run -d --name "$CONTAINER" -p "127.0.0.1:$PORT:5432" -e POSTGRES_PASSWORD=pgproxy-test-password -e POSTGRES_DB=conformance "$IMAGE" -c "shared_preload_libraries=$PRELOAD" -c compute_query_id=on >/dev/null
  READY=0
  for _ in $(seq 1 60); do
    if docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U postgres -d conformance >/dev/null 2>&1; then READY=1; break; fi
    sleep 1
  done
  [[ "$READY" == 1 ]] || { docker logs "$CONTAINER"; exit 1; }
  echo "PostgreSQL $MAJOR: measured server cost"
  python3 "$ROOT/tests/conformance/drivers/server_cost_check.py" --binary "$ROOT/target/debug/pgproxy" --container "$CONTAINER" --port "$PORT" "${DRIVER_ARGS[@]}"
done
