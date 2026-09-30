# Reload, planned endpoint changes and physical backend limits

The runtime uses `ManagedService` generations. A replacement first validates the
configuration, compiles SQL policy, loads frontend certificate/key/client trust,
and loads backend trust. Only a fully staged service can replace the current
service. A staging failure leaves the current service and generation unchanged.
New clients use the new routing, TLS and policy configuration; existing clients
keep their original generation, settings, pools and policy until disconnecting.
Policy reload therefore does not revoke the privileges of already connected
clients. Cancellation ownership is shared across generations so old clients can
still cancel work after a certificate or configuration reload.

The authenticated loopback operations interface accepts bodyless POST controls:

- `/reload`: replace routes, certificates, policy and per-session protocol limits.
- `/switchover/prepare`: pause new logins and readiness while existing sessions run.
- `/switchover/commit`: read the same configured file and install its validated
  endpoint configuration only after all old client sessions have disconnected.
- `/switchover/abort`: resume the original generation.

Cancellation control connections remain available during a drain. Prepare does
not forcibly migrate or kill clients. An idle client keeping its connection open
can delay commit. The proxy does not promote a PostgreSQL server; promotion and
configuration of the target endpoint remain operator actions. Enable
`require_primary` to reject backend handoff to a recovery/read-only target. These
controls do not establish the roadmap's zero-errors planned-switchover gate.

Listener addresses, worker counts, process admission caps, shutdown settings,
logging and the operations endpoint require a restart. Reload refuses a change
rather than silently ignoring it. Control epochs prevent a slowly staged request
from committing after a concurrent abort/reprepare or replacement.

`general.max_backend_connections` bounds physical backend sockets across users,
transaction pools, passthrough sessions and reload generations. A backend owns a
permit for its entire socket lifetime, including idle pooling. FIFO admission
uses bounded waits and bounded waiter storage; closure wakes waiters without
revoking already active sockets. Separate generation pools can overlap, but their
combined physical sockets stay within this shared process cap. Retired idle pools
are released when the last client owning that service generation disconnects.

The durable tests use disposable certificates, configurations and an isolated
PostgreSQL database. Create a fresh fixture directory:

```sh
python tests/conformance/reload_fixtures.py /tmp/pgproxy-reload-check \
  --port 6444 --operations-port 6452 --backend-port 55439 --backend-limit 2
./target/debug/pgproxy --config /tmp/pgproxy-reload-check/proxy.toml
```

From another terminal with psycopg installed, run:

```sh
python tests/conformance/drivers/reload_check.py --host localhost \
  --fixtures /tmp/pgproxy-reload-check
python tests/conformance/drivers/backend_limit_check.py --host localhost \
  --fixtures /tmp/pgproxy-reload-check
```

The reload driver checks actual TLS certificate fingerprint rotation under a
trusted CA, cancellation by an old generation, invalid configuration/certificate
atomicity, login quiescence, cancellation during draining, early commit refusal,
resume and abort. The capacity driver holds a transaction backend and a
passthrough session simultaneously, reloads, checks that a third physical backend
is refused within its deadline, and verifies reclamation after the old generation
closes. Unit checks exercise failed staging, lease lifetimes, drain wakeups,
concurrent-control epochs, shared budgets and FIFO admission.
