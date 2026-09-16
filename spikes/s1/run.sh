#!/usr/bin/env bash
# Spike S1 — where is the Rust proxy's data-path overhead?
#
# Method (corrected after a first run showed classic first-run cache bias):
#   * everything runs in containers on one Docker bridge network
#   * pgbench runs in its OWN container, so its CPU does not compete with postgres
#   * a global warmup brings the whole dataset into shared_buffers before measuring
#   * targets are interleaved inside the concurrency loop, so any drift affects all
#     targets equally rather than penalising whichever ran first
#   * two full passes, best TPS per cell
#
# Caveat to state in any write-up: pgbench reports *average* latency, not percentiles.
#
#   ./run.sh
set -uo pipefail

NET=spike-s1
RUST_IMG=rust:1-slim-bookworm
PG_IMG=postgres:18-alpine
WORKERS="${WORKERS:-2}"
SCALE="${SCALE:-100}"
CONNS="${CONNS:-1 4 16 64}"
DUR="${DUR:-8}"
WARM="${WARM:-4}"
PASSES="${PASSES:-2}"
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
docker run -d --name s1-pg --network "$NET" --network-alias pg \
  -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=pgbench \
  "$PG_IMG" \
  -c max_connections=400 -c shared_buffers=1GB -c fsync=off \
  -c synchronous_commit=off -c full_page_writes=off -c autovacuum=off \
  >/dev/null
for _ in $(seq 1 60); do
  docker exec s1-pg pg_isready -U postgres -d pgbench >/dev/null 2>&1 && break
  sleep 1
done

echo "== initialising pgbench (scale $SCALE) =="
docker exec s1-pg pgbench -i -q -s "$SCALE" -U postgres pgbench >/dev/null 2>&1

echo "== starting pgbouncer (1.18, Debian; must not run as root) =="
docker run -d --name s1-pgbouncer --network "$NET" \
  -v "$ROOT/pgbouncer.ini:/etc/pgbouncer/pgbouncer.ini:ro" \
  -v "$ROOT/userlist.txt:/etc/pgbouncer/userlist.txt:ro" \
  debian:bookworm-slim bash -c \
  'apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq --no-install-recommends pgbouncer >/dev/null 2>&1; exec runuser -u postgres -- pgbouncer /etc/pgbouncer/pgbouncer.ini' \
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
    echo "  FAIL $t -- last 15 log lines:"
    docker logs --tail 15 "$t" 2>&1 | sed 's/^/      /'
  fi
done

TARGETS=(
  "direct:pg:5432"
  "pgbouncer-session:s1-pgbouncer:6432"
  "rust-thread:s1-proxy-thread:6432"
  "rust-tokio:s1-proxy-tokio:6432"
  "rust-splice:s1-proxy-splice:6432"
)

# pgbench runs in its own container on the same network.
run_pgbench() { # host port conns seconds
  local host="$1" port="$2" c="$3" secs="$4"
  local j=$(( c < 8 ? c : 8 ))
  docker run --rm --network "$NET" "$PG_IMG" \
    pgbench -S -n -U postgres -h "$host" -p "$port" \
    -c "$c" -j "$j" -T "$secs" pgbench 2>&1
}

echo "== global warmup (dataset into shared_buffers) =="
run_pgbench pg 5432 8 20 >/dev/null 2>&1

declare -A BEST_TPS BEST_LAT
RAW="$OUT.raw.tsv"
: > "$RAW"

for pass in $(seq 1 "$PASSES"); do
  for c in $CONNS; do
    for entry in "${TARGETS[@]}"; do
      label="${entry%%:*}"; rest="${entry#*:}"; host="${rest%%:*}"; port="${rest##*:}"
      run_pgbench "$host" "$port" "$c" "$WARM" >/dev/null 2>&1
      out="$(run_pgbench "$host" "$port" "$c" "$DUR")"
      tps="$(printf '%s\n' "$out" | sed -n 's/^tps = \([0-9.]*\).*/\1/p' | head -1)"
      lat="$(printf '%s\n' "$out" | sed -n 's/^latency average = \([0-9.]*\).*/\1/p' | head -1)"
      sd="$(printf '%s\n' "$out" | sed -n 's/^latency stddev = \([0-9.]*\).*/\1/p' | head -1)"
      if [ -z "$tps" ]; then
        echo "  ! pgbench failed: $label c=$c" >&2
        printf '%s\n' "$out" | tail -4 | sed 's/^/      /' >&2
        continue
      fi
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$pass" "$c" "$label" "$tps" "$lat" "${sd:--}" >> "$RAW"
      key="$label|$c"
      if [ -z "${BEST_TPS[$key]:-}" ] || awk "BEGIN{exit !($tps > ${BEST_TPS[$key]})}"; then
        BEST_TPS[$key]="$tps"; BEST_LAT[$key]="$lat"
      fi
      printf '  pass %s  c=%-3s %-18s %10s tps  %s ms\n' "$pass" "$c" "$label" "$tps" "$lat"
    done
  done
done

{
  echo "# Spike S1 — data-path overhead report"
  echo
  echo "- pgbench scale $SCALE, \`-S -n\`, ${DUR}s measured after ${WARM}s warmup, best of $PASSES passes"
  echo "- pgbench in its own container; global warmup before measuring; targets interleaved"
  echo "- all containers on one Docker bridge network"
  echo "- Rust proxies: release, $WORKERS worker(s), SO_REUSEPORT, TCP_NODELAY, pure pass-through"
  echo "- PgBouncer 1.18 single process, session mode, \`default_pool_size=100\`"
  echo "- PostgreSQL 18, \`fsync=off\`, \`synchronous_commit=off\`, \`shared_buffers=1GB\`, 16 CPUs"
  echo
  echo "**Raw TPS** (best of $PASSES passes):"
  echo
  printf '| target |'
  for c in $CONNS; do printf ' c=%s |' "$c"; done
  echo
  printf -- '---|'
  for c in $CONNS; do printf -- '---|'; done
  echo
  for entry in "${TARGETS[@]}"; do
    label="${entry%%:*}"
    printf '| %s |' "$label"
    for c in $CONNS; do
      v="${BEST_TPS[$label|$c]:-FAILED}"
      printf ' %s |' "$v"
    done
    echo
  done
  echo
  echo "**Average latency (ms)** — best-of-pass latency for the fastest TPS run:"
  echo
  printf '| target |'
  for c in $CONNS; do printf ' c=%s |' "$c"; done
  echo
  printf -- '---|'
  for c in $CONNS; do printf -- '---|'; done
  echo
  for entry in "${TARGETS[@]}"; do
    label="${entry%%:*}"
    printf '| %s |' "$label"
    for c in $CONNS; do
      printf ' %s |' "${BEST_LAT[$label|$c]:--}"
    done
    echo
  done
  echo
  echo "**Overhead versus direct**, as (direct ÷ proxy) latency ratio at the same concurrency:"
  echo
  printf '| target |'
  for c in $CONNS; do printf ' c=%s |' "$c"; done
  echo
  printf -- '---|'
  for c in $CONNS; do printf -- '---|'; done
  echo
  for entry in "${TARGETS[@]}"; do
    label="${entry%%:*}"
    [ "$label" = "direct" ] && continue
    printf '| %s |' "$label"
    for c in $CONNS; do
      d="${BEST_LAT[direct|$c]:-}"; p="${BEST_LAT[$label|$c]:-}"
      if [ -n "$d" ] && [ -n "$p" ]; then
        printf ' %s |' "$(awk "BEGIN{printf \"%.2fx\", $p/$d}")"
      else
        printf ' - |'
      fi
    done
    echo
  done
  echo
  echo "Raw per-pass data: \`$(basename "$RAW")\`."
} > "$OUT"

echo
echo "wrote $OUT"
cat "$OUT"
