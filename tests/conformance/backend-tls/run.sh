#!/usr/bin/env bash
# Isolated, disposable backend TLS + SCRAM-PLUS + cancellation verification.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
FIXTURE=$(mktemp -d "${TMPDIR:-/tmp}/pgproxy-backend-tls.XXXXXX")
CONTAINER="pgproxy-backend-tls-$$"
BACKEND_PORT=${PGPROXY_TLS_BACKEND_PORT:-55440}
PROXY_PORT=${PGPROXY_TLS_PROXY_PORT:-6441}
POSTGRES_IMAGE=${PGPROXY_TLS_POSTGRES_IMAGE:-postgres:18-alpine}
PROXY_PID=""
DRIVER_NETWORK_ARGS=()
if [[ "$(uname -s)" == Linux ]]; then DRIVER_NETWORK_ARGS=(--network host --add-host host.docker.internal:127.0.0.1); fi
cleanup() {
  STATUS=$?
  if [[ "$STATUS" != 0 ]]; then
    if [[ -f "$FIXTURE/proxy.log" ]]; then cat "$FIXTURE/proxy.log" >&2; fi
    docker logs "$CONTAINER" >&2 2>/dev/null || true
  fi
  if [[ -n "$PROXY_PID" ]]; then kill "$PROXY_PID" 2>/dev/null || true; wait "$PROXY_PID" 2>/dev/null || true; fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$FIXTURE"
}
trap cleanup EXIT
SERVER_SIGNATURE_ARGS=()
if [[ "${PGPROXY_TLS_SERVER_SIGNATURE:-default}" == pss ]]; then SERVER_SIGNATURE_ARGS=(-sha384 -sigopt rsa_padding_mode:pss); fi
openssl req -x509 "${SERVER_SIGNATURE_ARGS[@]}" -newkey rsa:2048 -nodes -keyout "$FIXTURE/server-key.pem" -out "$FIXTURE/server.pem" -days 1 -subj /CN=localhost -addext 'subjectAltName=DNS:localhost' -addext 'basicConstraints=critical,CA:FALSE' -addext 'keyUsage=critical,digitalSignature,keyEncipherment' >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$FIXTURE/wrong-key.pem" -out "$FIXTURE/wrong.pem" -days 1 -subj /CN=wrong >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$FIXTURE/ca-key.pem" -out "$FIXTURE/ca.pem" -days 1 -subj /CN=FixtureClientCA -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n' > "$FIXTURE/client.ext"
for IDENTITY in certuser other; do
  openssl req -newkey rsa:2048 -nodes -keyout "$FIXTURE/$IDENTITY-key.pem" -out "$FIXTURE/$IDENTITY.csr" -subj "/CN=$IDENTITY" >/dev/null 2>&1
  openssl x509 -req -in "$FIXTURE/$IDENTITY.csr" -CA "$FIXTURE/ca.pem" -CAkey "$FIXTURE/ca-key.pem" -CAcreateserial -out "$FIXTURE/$IDENTITY.pem" -days 1 -extfile "$FIXTURE/client.ext" >/dev/null 2>&1
done
chmod 755 "$FIXTURE"
chmod 644 "$FIXTURE"/*.pem
docker run -d --name "$CONTAINER" -p "127.0.0.1:$BACKEND_PORT:5432" -e POSTGRES_PASSWORD=public-fixture-password -e POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 -v "$FIXTURE:/fixtures:ro" "$POSTGRES_IMAGE" sh -c 'cp /fixtures/server-key.pem /tmp/server-key.pem; cp /fixtures/server.pem /tmp/server.pem; chown postgres:postgres /tmp/server-key.pem /tmp/server.pem; chmod 600 /tmp/server-key.pem; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.pem -c ssl_key_file=/tmp/server-key.pem -c ssl_ca_file=/fixtures/ca.pem' >/dev/null
READY=0
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then READY=1; break; fi
  sleep 1
done
[[ "$READY" == 1 ]] || { echo "PostgreSQL TLS fixture failed to start" >&2; exit 1; }
docker exec "$CONTAINER" psql -U postgres -d postgres -v ON_ERROR_STOP=1 -c "CREATE ROLE certuser LOGIN; CREATE ROLE unicodeuser LOGIN PASSWORD U&'I\\00ADX';" >/dev/null
docker exec "$CONTAINER" sh -c 'printf "hostssl all certuser all cert\n" > "$PGDATA/pg_hba.conf.new"; cat "$PGDATA/pg_hba.conf" >> "$PGDATA/pg_hba.conf.new"; mv "$PGDATA/pg_hba.conf.new" "$PGDATA/pg_hba.conf"; chown postgres:postgres "$PGDATA/pg_hba.conf"'
docker exec "$CONTAINER" psql -U postgres -d postgres -c 'SELECT pg_reload_conf()' >/dev/null
for ROUTE in verified wrong_host wrong_ca; do
  SERVER_NAME=localhost
  ROOT_CERT="$FIXTURE/server.pem"
  [[ "$ROUTE" != wrong_host ]] || SERVER_NAME=wrong.example
  [[ "$ROUTE" != wrong_ca ]] || ROOT_CERT="$FIXTURE/wrong.pem"
  cat >> "$FIXTURE/proxy.toml" <<CONFIG
[[databases]]
name = "$ROUTE"
host = "127.0.0.1"
port = $BACKEND_PORT
dbname = "postgres"
user = "postgres"
password = "public-fixture-password"
pool_mode = "transaction"
client_auth = "trust"
pool_size = 1
backend_tls = { root_certificate = "$ROOT_CERT", server_name = "$SERVER_NAME", require_channel_binding = true }
CONFIG
done
for ROUTE in mtls mtls_missing mtls_wrong_identity unicode; do
  BACKEND_USER=certuser
  CERT="certuser"
  BINDING=false
  IDENTITY_CONFIG=""
  if [[ "$ROUTE" == unicode ]]; then BACKEND_USER=unicodeuser; BINDING=true; fi
  if [[ "$ROUTE" == mtls_wrong_identity ]]; then CERT=other; fi
  if [[ "$ROUTE" == mtls || "$ROUTE" == mtls_wrong_identity ]]; then IDENTITY_CONFIG=", client_certificate = \"$FIXTURE/$CERT.pem\", private_key = \"$FIXTURE/$CERT-key.pem\""; fi
  cat >> "$FIXTURE/proxy.toml" <<CONFIG
[[databases]]
name = "$ROUTE"
host = "127.0.0.1"
port = $BACKEND_PORT
dbname = "postgres"
user = "$BACKEND_USER"
password = "I\\u00ADX"
pool_mode = "transaction"
client_auth = "trust"
pool_size = 1
backend_tls = { root_certificate = "$FIXTURE/server.pem", server_name = "localhost", require_channel_binding = $BINDING$IDENTITY_CONFIG }
CONFIG
done
{ printf '[general]\nlisten_addr = "0.0.0.0"\nlisten_port = %s\nworkers = 2\n' "$PROXY_PORT"; cat "$FIXTURE/proxy.toml"; } > "$FIXTURE/config.toml"
"$ROOT/target/debug/pgproxy" --config "$FIXTURE/config.toml" > "$FIXTURE/proxy.log" 2>&1 &
PROXY_PID=$!
sleep 1
# Driver is in a disposable container: no developer Python installation required.
docker run --rm "${DRIVER_NETWORK_ARGS[@]}" -v "$ROOT/tests/conformance/drivers:/app:ro" -v pgproxy-conformance-pip:/root/.cache/pip python:3.12-slim sh -c 'pip install --quiet --root-user-action=ignore "psycopg[binary]" && python /app/backend_tls_check.py --port "$1"' sh "$PROXY_PORT"
