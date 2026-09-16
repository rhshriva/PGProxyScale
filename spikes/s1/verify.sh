#!/usr/bin/env bash
# Spike S1 follow-up: falsify (or explain) the c=64 anomaly.
#
# The main run showed the pass-through proxies beating DIRECT postgres at c=64
# (215k vs 122k TPS, and *lower* latency). A pass-through relay cannot make a round
# trip faster, so one of the two measurements is wrong. This script A/Bs them under
# controlled conditions and cross-checks server-side work.
set -uo pipefail

NET=spike-s1v
RUST_IMG=rust:1-slim-bookworm
PG_IMG=postgres:18-alpine
ROOT="$PWD"

cleanup() {
  docker rm -f v-pg v-proxy-thread >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

docker network create "$NET" >/dev/null
docker run --rm -v "$ROOT:/app" -w /app "$RUST_IMG" bash -c \
  'export PATH=/usr/local/cargo/bin:$PATH; cargo build --release' >/dev/null 2>&1

docker run -d --name v-pg --network "$NET" --network-alias pg \
  -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=pgbench "$PG_IMG" \
  -c max_connections=400 -c shared_buffers=1GB -c fsync=off \
  -c synchronous_commit=off -c full_page_writes=off -c autovacuum=off >/dev/null
for _ in $(seq 1 60); do docker exec v-pg pg_isready -U postgres -d pgbench >/dev/null 2>&1 && break; sleep 1; done
docker exec v-pg pgbench -i -q -s 100 -U postgres pgbench >/dev/null 2>&1

# One worker so the proxy is not given more parallelism than postgres gets.
docker run -d --name v-proxy-thread --network "$NET" -v "$ROOT:/app" -w /app "$RUST_IMG" \
  ./target/release/spike-s1 --mode thread --workers 1 --listen 0.0.0.0:6432 --backend pg:5432 >/dev/null
sleep 3

bench() { # host port clients threads label
  local host="$1" port="$2" c="$3" j="$4" label="$5"
  docker exec v-pg psql -U postgres -d pgbench -tAc \
    "SELECT xact_commit FROM pg_stat_database WHERE datname='pgbench'" > /tmp/before 2>/dev/null
  # warmup
  docker run --rm --network "$NET" "$PG_IMG" pgbench -S -n -U postgres -h "$host" -p "$port" \
    -c "$c" -j "$j" -T 4 pgbench >/dev/null 2>&1
  local out
  out="$(docker run --rm --network "$NET" "$PG_IMG" pgbench -S -n -U postgres -h "$host" -p "$port" \
    -c "$c" -j "$j" -T 10 pgbench 2>&1)"
  docker exec v-pg psql -U postgres -d pgbench -tAc \
    "SELECT xact_commit FROM pg_stat_database WHERE datname='pgbench'" > /tmp/after 2>/dev/null
  local tps lat ntx xdelta
  tps="$(printf '%s\n' "$out" | sed -n 's/^tps = \([0-9.]*\).*/\1/p' | head -1)"
  lat="$(printf '%s\n' "$out" | sed -n 's/^latency average = \([0-9.]*\).*/\1/p' | head -1)"
  ntx="$(printf '%s\n' "$out" | sed -n 's/^number of transactions actually processed: \([0-9]*\).*/\1/p' | head -1)"
  xdelta=$(( $(cat /tmp/after) - $(cat /tmp/before) ))
  printf '%-34s c=%-3s j=%-3s tps=%-14s lat=%-8s pgbench_ntx=%-9s pg_xact_commit_delta=%s\n' \
    "$label" "$c" "$j" "$tps" "$lat" "$ntx" "$xdelta"
}

echo "--- repeat A/B at c=64, one proxy worker, single client thread set ---"
for rep in 1 2 3; do
  bench pg 5432 64 8 "rep$rep direct        j=8"
  bench v-proxy-thread 6432 64 8 "rep$rep via-proxy     j=8"
done

echo
echo "--- does giving pgbench more client threads change the picture? ---"
bench pg 5432 64 64 "direct        j=64"
bench v-proxy-thread 6432 64 64 "via-proxy     j=64"

echo
echo "--- mid concurrency for reference ---"
bench pg 5432 16 8 "direct        c=16"
bench v-proxy-thread 6432 16 8 "via-proxy     c=16"

echo
echo "--- postgres backend count seen for each path (sampled during a run) ---"
docker exec v-pg psql -U postgres -d pgbench -tAc \
  "SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend'" 2>/dev/null
