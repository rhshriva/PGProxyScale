#!/usr/bin/env bash
# PostgreSQL wire-protocol conformance harness.
#
# Everything runs in containers on one bridge network, so the harness behaves the same
# on a laptop and in CI.
#
#   ./run.sh                        # control run against direct PostgreSQL 18
#   PROXY=1 ./run.sh                # build pgproxy, run it in-network, test through it
#   TARGET=host:port ./run.sh       # test any other endpoint
#   PG_VERSION=17 ./run.sh          # against a different server major
#   ONLY=cursor ./run.sh            # a single scenario
#
# The control run is the important one: if the harness cannot pass against a correct
# server, its verdict on the proxy means nothing.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
NET=pgproxy-conformance
PG_NAME=conformance-pg
PROXY_NAME=conformance-pgproxy
PIP_VOLUME=pgproxy-conformance-pip
# A separate target directory inside a named volume. The repository's own `target/` is
# built by the host toolchain; letting a Linux container write there would collide with
# the macOS artefacts.
TARGET_VOLUME=pgproxy-conformance-target

PG_IMAGE="postgres:${PG_VERSION:-18}-alpine"
PY_IMAGE="python:3.12-slim"
RUST_IMAGE="rust:1-slim-bookworm"
DB=conformance
TARGET="${TARGET:-}"
PROXY="${PROXY:-}"
ONLY="${ONLY:-}"

cleanup() {
  docker rm -f "$PG_NAME" "$PROXY_NAME" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

docker network create "$NET" >/dev/null

echo "== starting PostgreSQL (${PG_IMAGE}) =="
docker run -d --name "$PG_NAME" --network "$NET" --network-alias pg \
  -e POSTGRES_HOST_AUTH_METHOD="${PG_AUTH:-trust}" \
  -e POSTGRES_DB="$DB" \
  -e POSTGRES_PASSWORD="${PG_PASSWORD:-conformance}" \
  "$PG_IMAGE" -c max_connections=200 >/dev/null
for _ in $(seq 1 60); do
  docker exec "$PG_NAME" pg_isready -U postgres -d "$DB" >/dev/null 2>&1 && break
  sleep 1
done

if [ -n "$PROXY" ]; then
  echo "== building pgproxy for linux =="
  docker run --rm -v "$REPO:/app" -v "$TARGET_VOLUME:/target" -w /app \
    -e CARGO_TARGET_DIR=/target \
    "$RUST_IMAGE" bash -c \
    'export PATH=/usr/local/cargo/bin:$PATH; cargo build --release -p pgproxy-cli' \
    || { echo "pgproxy build failed"; exit 4; }

  echo "== starting pgproxy =="
  docker run -d --name "$PROXY_NAME" --network "$NET" \
    -v "$REPO:/app" -v "$TARGET_VOLUME:/target" -w /app \
    -e CARGO_TARGET_DIR=/target \
    "$RUST_IMAGE" /target/release/pgproxy --config tests/conformance/pgproxy.toml >/dev/null

  # Wait for the listener, then surface its log if it never comes up.
  ready=0
  for _ in $(seq 1 30); do
    # Ask for the database the proxy actually serves: a probe for an unconfigured one
    # gets a correct FATAL and would look like a dead listener.
    if docker exec "$PG_NAME" pg_isready -h "$PROXY_NAME" -p 6432 -U postgres -d "$DB" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [ "$ready" != "1" ]; then
    echo "pgproxy did not come up; log follows:"
    docker logs "$PROXY_NAME" 2>&1 | sed 's/^/  /'
    exit 4
  fi
  echo "  pgproxy is listening"
  TARGET="$PROXY_NAME:6432"
fi

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
docker run --rm --network "$NET" \
  -v "$ROOT:/work" -w /work \
  -v "$PIP_VOLUME:/root/.cache/pip" \
  "$PY_IMAGE" bash -c "
    pip install --quiet 'psycopg[binary]' >/dev/null 2>&1 || { echo 'pip install failed'; exit 3; }
    python3 drivers/psycopg_check.py \
      --host '$HOST' --port '$PORT' --user postgres --dbname '$DB' \
      --password '${PG_PASSWORD:-conformance}' \
      --label '$LABEL' ${ONLY:+--only '$ONLY'}
  "
status=$?

if [ -n "$PROXY" ]; then
  echo
  echo "== pgproxy log =="
  docker logs "$PROXY_NAME" 2>&1 | tail -20 | sed 's/^/  /'
fi

if [ $status -eq 0 ]; then
  echo "conformance: PASS"
else
  echo "conformance: FAIL (exit $status)"
fi
exit $status
