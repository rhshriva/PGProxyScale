#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
BIN=${PGPROXY_BINARY:-$ROOT/target/debug/pgproxy}
IMAGE=${PGPROXY_FAILOVER_IMAGE:-postgres:18}
TAG=pgproxy-failover-$$
DOCKER_HOST_ARGS=()
if [[ "$(uname -s)" == Linux ]]; then DOCKER_HOST_ARGS=(--network host --add-host host.docker.internal:127.0.0.1); fi
TMP=$(mktemp -d)
cleanup() { [[ -f "$TMP/proxy.log" ]] && cat "$TMP/proxy.log"; kill "${PROXY_PID:-99999999}" 2>/dev/null || true; docker rm -f -v "$TAG-primary" "$TAG-standby" >/dev/null 2>&1 || true; docker volume rm "$TAG-data" >/dev/null 2>&1 || true; docker network rm "$TAG-net" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT
# Do not use kill 0 if startup fails.
PROXY_PID=99999999
docker network create "$TAG-net" >/dev/null
docker volume create "$TAG-data" >/dev/null
echo "Fixture image: $IMAGE"
docker run -d --name "$TAG-primary" --network "$TAG-net" --network-alias primary -p 55442:5432 -e POSTGRES_PASSWORD=fixture-password "$IMAGE" -c wal_level=replica -c max_wal_senders=5 >/dev/null
docker image inspect "$IMAGE" --format 'Image identity: {{.Id}} {{json .RepoDigests}}'
for n in $(seq 1 90); do docker exec "$TAG-primary" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break; sleep 1; done
docker exec "$TAG-primary" psql -U postgres -v ON_ERROR_STOP=1 -c "CREATE ROLE replicator REPLICATION LOGIN PASSWORD 'fixture-replication';" >/dev/null
docker exec "$TAG-primary" createdb -U postgres failover
docker exec "$TAG-primary" sh -c "echo 'host replication replicator 0.0.0.0/0 scram-sha-256' >> \"\$PGDATA/pg_hba.conf\""
docker exec "$TAG-primary" psql -U postgres -c 'SELECT pg_reload_conf()' >/dev/null
docker run --rm --network "$TAG-net" -v "$TAG-data:/standby" -e PGPASSWORD=fixture-replication "$IMAGE" sh -c 'chown postgres:postgres /standby; chmod 700 /standby; gosu postgres pg_basebackup -h primary -U replicator -D /standby -R -X stream --checkpoint=fast'
docker run -d --name "$TAG-standby" --network "$TAG-net" -p 55443:5432 -v "$TAG-data:/standby" -e PGDATA=/standby "$IMAGE" >/dev/null
for n in $(seq 1 90); do docker exec "$TAG-standby" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break; sleep 1; done
cat > "$TMP/proxy.toml" <<CONFIG
[general]
listen_addr = "0.0.0.0"
listen_port = 6443
workers = 1
[[databases]]
name = "failover"
host = "127.0.0.1"
port = 55442
dbname = "failover"
user = "postgres"
password = "fixture-password"
client_auth = "trust"
pool_mode = "transaction"
pool_size = 2
connect_timeout_secs = 3
checkout_timeout_secs = 3
[[databases.failover]]
host = "127.0.0.1"
port = 55443
CONFIG
"$BIN" --config "$TMP/proxy.toml" > "$TMP/proxy.log" 2>&1 &
PROXY_PID=$!
for n in $(seq 1 50); do docker run --rm "${DOCKER_HOST_ARGS[@]}" "$IMAGE" pg_isready -h host.docker.internal -p 6443 -U postgres -d failover >/dev/null 2>&1 && break; sleep .2; done
psql_proxy() { docker run --rm "${DOCKER_HOST_ARGS[@]}" "$IMAGE" psql -d "host=host.docker.internal port=6443 user=postgres dbname=failover connect_timeout=5" -v ON_ERROR_STOP=1 "$@"; }
psql_proxy -c 'CREATE TABLE failover_marker (id int PRIMARY KEY); INSERT INTO failover_marker VALUES (1)' >/dev/null
# Wait until the physical replica contains committed data before fencing the primary.
for n in $(seq 1 50); do docker exec "$TAG-standby" psql -U postgres -d failover -Atc 'SELECT count(*) FROM failover_marker' 2>/dev/null | rg -q '^1$' && break; sleep .2; done
docker stop -t 1 "$TAG-primary" >/dev/null
if psql_proxy -Atc 'SELECT 1' > "$TMP/read-only-query.log" 2>&1; then echo 'FAIL: unpromoted standby accepted user SQL'; exit 1; fi
if psql_proxy -c 'INSERT INTO failover_marker VALUES (2)' > "$TMP/read-only.log" 2>&1; then echo 'FAIL: read-only replica accepted user write'; exit 1; fi
echo 'PASS: unavailable primary does not route user writes to unpromoted standby'
if [[ "${PGPROXY_FAILOVER_FENCE_MODE:-read_only_demotion}" == power_off ]]; then
    [[ "$(docker inspect "$TAG-primary" --format '{{.State.Running}}')" == false ]]
    echo 'PASS: authoritative Docker power fence confirmed before standby promotion'
else
# Recover the old primary and populate TWO idle sockets. Demote it while its
# sockets remain reachable; retry must retire the entire old generation.
docker start "$TAG-primary" >/dev/null
for n in $(seq 1 50); do docker exec "$TAG-primary" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break; sleep .1; done
psql_proxy -c 'SELECT pg_sleep(1)' > "$TMP/warm-one.log" 2>&1 &
WARM_PID=$!
sleep .2
psql_proxy -Atc 'SELECT 1' >/dev/null
wait "$WARM_PID"
IDLE_SOCKETS=$(docker exec "$TAG-primary" psql -U postgres -d failover -Atc "SELECT count(*) FROM pg_stat_activity WHERE application_name='pgproxy' AND state='idle'")
[[ "$IDLE_SOCKETS" == 2 ]] || { echo "FAIL: expected two old idle pool sockets, observed $IDLE_SOCKETS"; exit 1; }
docker exec "$TAG-primary" psql -U postgres -c "ALTER SYSTEM SET default_transaction_read_only = on" >/dev/null
docker exec "$TAG-primary" psql -U postgres -c 'SELECT pg_reload_conf()' >/dev/null
fi
# This fixture's operator changes the old primary to read-only before promotion.
# Production deployments need proper distributed fencing, not merely a GUC.
docker exec -u postgres "$TAG-standby" pg_ctl -D /standby promote -w >/dev/null
psql_proxy -c 'INSERT INTO failover_marker VALUES (2)' >/dev/null
COUNT=$(psql_proxy -Atc 'SELECT count(*) FROM failover_marker')
[[ "$COUNT" == 2 ]]
if [[ "${PGPROXY_FAILOVER_FENCE_MODE:-read_only_demotion}" != power_off ]]; then echo 'PASS: reachable demoted primary with two idle sockets is retired before user SQL'; fi
echo 'PASS: externally promoted replica receives new connections and committed writes'
docker stop -t 1 "$TAG-primary" >/dev/null
echo 'PASS: pre-failover committed row preserved and post-failover write appears once'
# Kill the selected server while an explicit transaction has executed a write.
# Its client must fail; after recovery its uncommitted write must remain absent.
psql_proxy -c 'BEGIN; INSERT INTO failover_marker VALUES (3); SELECT pg_sleep(30); COMMIT' > "$TMP/inflight.log" 2>&1 &
INFLIGHT_PID=$!
SLEEPING=false
for n in $(seq 1 50); do
    if docker exec "$TAG-standby" psql -U postgres -d failover -Atc "SELECT count(*) FROM pg_stat_activity WHERE wait_event='PgSleep'" | rg -q '^1$'; then SLEEPING=true; break; fi
    sleep .1
done
[[ "$SLEEPING" == true ]]
docker stop -t 1 "$TAG-standby" >/dev/null
if wait "$INFLIGHT_PID"; then echo 'FAIL: in-flight transaction was reported successful after backend failure'; exit 1; fi
docker start "$TAG-standby" >/dev/null
for n in $(seq 1 50); do docker exec "$TAG-standby" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break; sleep .1; done
COUNT=$(psql_proxy -Atc 'SELECT count(*) FROM failover_marker')
[[ "$COUNT" == 2 ]]
echo 'PASS: in-flight write fails and is never replayed after backend recovery'
