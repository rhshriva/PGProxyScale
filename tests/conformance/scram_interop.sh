#!/usr/bin/env bash
# SCRAM-SHA-256 interop: does a real PostgreSQL driver accept our handshake?
#
# The unit tests pin the RFC 7677 vectors, which proves our SCRAM agrees with the
# specification. This proves something different and stronger: that libpq, as driven by
# psycopg, accepts the messages our server actually emits — including the
# AuthenticationOk / ParameterStatus / BackendKeyData / ReadyForQuery sequence a driver
# needs before it will call a connection established.
#
#   ./scram_interop.sh
#
# Exits non-zero if either case behaves unexpectedly.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${PORT:-6544}"
PASSWORD="probe-secret"
PY_IMAGE="python:3.12-slim"

cd "$ROOT"
echo "== building scram_probe =="
cargo build -q -p pgproxy-wire --example scram_probe || { echo "build failed"; exit 3; }

failures=0

# run_case <password> <expected-probe-exit> <expected-client-verdict>
run_case() {
  local password="$1" expected_exit="$2" expect="$3" label="$4"

  ./target/debug/examples/scram_probe "0.0.0.0:$PORT" "$PASSWORD" > "/tmp/scram-$label.log" 2>&1 &
  local pid=$!
  sleep 1

  local client_out
  client_out="$(docker run --rm -v scapip:/root/.cache/pip "$PY_IMAGE" bash -c "
    pip install -q 'psycopg[binary]' >/dev/null 2>&1
    python3 -c \"
import psycopg
try:
    c = psycopg.connect(host='host.docker.internal', port=$PORT, user='probe',
                        password='$password', dbname='probe', connect_timeout=10)
    print('VERDICT=accepted version=' + str(c.info.server_version))
    c.close()
except Exception as e:
    print('VERDICT=rejected ' + type(e).__name__)
\"
  " 2>&1 | grep -E '^VERDICT=' || echo "VERDICT=error")"

  sleep 1
  wait "$pid" 2>/dev/null
  local probe_exit=$?

  echo "--- $label"
  echo "    client: $client_out"
  echo "    probe exit: $probe_exit (expected $expected_exit)"

  if [ "$probe_exit" != "$expected_exit" ]; then
    echo "    MISMATCH: probe exit"
    sed 's/^/      /' "/tmp/scram-$label.log"
    failures=$((failures + 1))
  fi
  case "$client_out" in
    *"VERDICT=$expect"*) ;;
    *)
      echo "    MISMATCH: expected the client to report '$expect'"
      sed 's/^/      /' "/tmp/scram-$label.log"
      failures=$((failures + 1))
      ;;
  esac
}

run_case "$PASSWORD"        0 accepted "correct-password"
run_case "definitely-wrong" 1 rejected "wrong-password"

echo
if [ "$failures" -eq 0 ]; then
  echo "scram interop: PASS"
  exit 0
fi
echo "scram interop: FAIL ($failures checks)"
exit 1
