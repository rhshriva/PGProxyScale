#!/usr/bin/env bash
# Spike S1 — where is the Rust proxy's data-path overhead?
#
# Everything runs inside containers on one Docker network so that no target gets a
# different network path: Postgres, PgBouncer, each proxy variant, and pgbench itself.
#
# Note: no `docker build` is used. Docker's buildx wants to write outside the
# workspace, and building via a bind mount is both simpler and more reproducible.
#
#   ./run.sh
#   WORKERS=2 CONNS="1 4 16 64" ./run.sh
set -uo pipefail

NET=spike-s1
RUST_IMG=rust:1-slim-bookworm
WORKERS="${WORKERS:-2}"
SCALE="${SCALE:-100}"
CONNS="${CONNS:-1 4 16 64}"
DUR="${DUR:-10}"
WARM="${WARM:-5}"
OUT="${OUT:-s1-report.md}"
ROOT="$PWD"

cleanup() {
  docker rm -f s1-pg s1-pgbouncer s1-proxy-thread s1-proxy-tokio s1-proxy-splice \
    >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

echo "== building proxy (linux, release) =="
docker run --rm -v "$ROOT:/app" -w /app "$RUST_IMG" bash -c \
  'export PATH=/usr/local/cargo/bin:$PATH; cargo build --release' >/dev/null 2>&1 \
  || { echo "build failed"; exit 1; }
[ -x target/release/spike-s1 ] || { echo "binary missing"; exit 1; }

docker network create "$NET" >/dev/null

echo "== starting postgres =="
docker run -d --name s1-pg --network "$NET" \
  -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=pgbench \
  postgres:18-alpine \
  -c max_connections=400 -c shared_buffers=1GB -c fsync=off \
  -c synchronous_commit=off -c full_page_writes=off -c autovacuum=off \
  >/dev/null
for _ in $(seq 1 60); do
  docker exec s1-pg pg_isready -U postgres -d pgbench >/dev/null 2>&1 && break
  sleep 1
done

echo "== initialising pgbench (scale $SCALE) =="
docker exec s1-pg pgbench -i -q -s "$SCALE" -U postgres pgbench >/dev/null 2>&1

echo "== starting pgbouncer (installed in-container; no docker build) =="
docker run -d --name s1-pgbouncer --network "$NET" \
  -v "$ROOT/pgbouncer.ini:/etc/pgbouncer/pgbouncer.ini:ro" \
  -v "$ROOT/userlist.txt:/etc/pgbouncer/userlist.txt:ro" \
  debian:bookworm-slim bash -c \
  'apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq --no-install-recommends pgbouncer >/dev/null 2>&1; exec pgbouncer /etc/pgbouncer/pgbouncer.ini' \
  >/dev/null

echo "== starting proxies (workers=$WORKERS) =="
for mode in thread tokio splice; do
  docker run -d --name "s1-proxy-$mode" --network "$NET" \
    -v "$ROOT:/app" -w /app "$RUST_IMG" \
    ./target/release/spike-s1 --mode "$mode" --workers "$WORKERS" \
    --listen 0.0.0.0:6432 --backend pg:5432 >/dev/null
done

echo "== waiting for targets =="
for _ in $(seq 1 90); do
  docker exec s1-pg pg_isready -h s1-pgbouncer -p 6432 -U postgres >/dev/null 2>&1 && break
  sleep 2
done
for t in s1-pgbouncer s1-proxy-thread s1-proxy-tokio s1-proxy-splice; do
  if docker exec s1-pg pg_isready -h "$t" -p 6432 -U postgres >/dev/null 2>&1; then
    echo "  ok   $t"
  else
    echo "  FAIL $t"
  fi
done

TARGETS=(
  "direct:pg:5432"
  "pgbouncer-session:s1-pgbouncer:6432"
  "rust-thread:s1-proxy-thread:6432"
  "rust-tokio:s1-proxy-tokio:6432"
  "rust-splice:s1-proxy-splice:6432"
)

run_pgbench() { # host port conns
  local host="$1" port="$2" c="$3"
  docker exec s1-pg pgbench -S -n -U postgres -h "$host" -p "$port" \
    -c "$c" -j "$c" -T "$WARM" pgbench >/dev/null 2>&1
  docker exec s1-pg pgbench -S -n -U postgres -h "$host" -p "$port" \
    -c "$c" -j "$c" -T "$DUR" pgbench 2>&1
}

{
  echo "# Spike S1 — data-path overhead report"
  echo
  echo "- pgbench scale $SCALE, \`-S -n\`, ${DUR}s measured after ${WARM}s warmup"
  echo "- all containers on one Docker bridge network (no host-network variance)"
  echo "- Rust proxies: release build, $WORKERS worker(s), SO_REUSEPORT, TCP_NODELAY"
  echo "- PgBouncer: single process, session mode, \`default_pool_size=100\`"
  echo "- PostgreSQL 18, \`fsync=off\`, \`synchronous_commit=off\`, \`shared_buffers=1GB\`"
  echo
  echo "| target | conns | TPS | latency avg (ms) |"
  echo "|---|---|---|---|"
} > "$OUT"

for entry in "${TARGETS[@]}"; do
  label="${entry%%:*}"; rest="${entry#*:}"; host="${rest%%:*}"; port="${rest##*:}"
  for c in $CONNS; do
    out="$(run_pgbench "$host" "$port" "$c")"
    tps="$(printf '%s\n' "$out" | sed -n 's/^tps = \([0-9.]*\).*/\1/p' | head -1)"
    lat="$(printf '%s\n' "$out" | sed -n 's/^latency average = \([0-9.]*\).*/\1/p' | head -1)"
    [ -z "$tps" ] && tps="FAILED"
    [ -z "$lat" ] && lat="-"
    printf '| %s | %s | %s | %s |\n' "$label" "$c" "$tps" "$lat" | tee -a "$OUT"
  done
done

echo
echo "wrote $OUT"
