#!/usr/bin/env bash
# PostgreSQL wire-protocol conformance harness.
#
# Everything runs in containers on one bridge network, so the harness behaves the same
# on a laptop and in CI.
#
#   ./run.sh                        # control run against direct PostgreSQL 18
#   TARGET=pgproxy:6432 ./run.sh    # run against the proxy instead
#   PG_VERSION=17 ./run.sh          # against a different server major
#   ONLY=cursor ./run.sh            # a single scenario
#
# The control run is the important one: if the harness cannot pass against a correct
# server, its verdict on the proxy means nothing.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
NET=pgproxy-conformance
PG_NAME=conformance-pg
PG_IMAGE="postgres:${PG_VERSION:-18}-alpine"
PY_IMAGE="python:3.12-slim"
DB=conformance
TARGET="${TARGET:-}"
ONLY="${ONLY:-}"

cleanup() {
  docker rm -f "$PG_NAME" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

docker network create "$NET" >/dev/null

echo "== starting PostgreSQL (${PG_IMAGE}) =="
docker run -d --name "$PG_NAME" --network "$NET" --network-alias pg \
  -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB="$DB" \
  "$PG_IMAGE" -c max_connections=200 >/dev/null
for _ in $(seq 1 60); do
  docker exec "$PG_NAME" pg_isready -U postgres -d "$DB" >/dev/null 2>&1 && break
  sleep 1
done

if [ -n "$TARGET" ]; then
  HOST="${TARGET%%:*}"
  PORT="${TARGET##*:}"
  LABEL="target($TARGET)"
else
  HOST=pg
  PORT=5432
  LABEL="direct-control"
fi

echo "== running conformance against ${HOST}:${PORT} =="
# A named volume keeps the pip cache warm across runs.
docker run --rm --network "$NET" \
  -v "$ROOT:/work" -w /work \
  -v pgproxy-conformance-pip:/root/.cache/pip \
  "$PY_IMAGE" bash -c "
    pip install --quiet 'psycopg[binary]' >/dev/null 2>&1 || { echo 'pip install failed'; exit 3; }
    python3 drivers/psycopg_check.py \
      --host '$HOST' --port '$PORT' --user postgres --dbname '$DB' \
      --label '$LABEL' ${ONLY:+--only '$ONLY'}
  "
status=$?

if [ $status -eq 0 ]; then
  echo "conformance: PASS"
else
  echo "conformance: FAIL (exit $status)"
fi
exit $status
