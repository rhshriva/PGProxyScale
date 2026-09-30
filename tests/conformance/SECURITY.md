# Frontend security acceptance

These tests use disposable certificates and an isolated PostgreSQL database named
`conformance`, with trust authentication for the local test backend. They never need
production credentials. The default backend port is 55439; TLS listener is 6440.

Generate fixtures in a new empty directory (OpenSSL and Python 3 required):

```sh
export PGPROXY_AREA_PASSWORD=pgproxy-test-password
python3 tests/conformance/security_fixtures.py /tmp/pgproxy-security
cargo build -p pgproxy-cli
./target/debug/pgproxy --config /tmp/pgproxy-security/proxy.toml --check
./target/debug/pgproxy --config /tmp/pgproxy-security/proxy.toml
```

In another terminal with the same test password, install `psycopg[binary]` in a test
Python environment and run:

```sh
python tests/conformance/drivers/security_check.py \
  --host localhost --fixtures /tmp/pgproxy-security
```

The generator configures transaction and dedicated-session SCRAM routes and a
certificate route. Certificates expire after one day. The five acceptance cases
require PLUS channel binding, prove session backend affinity across DISCARD ALL,
reject plaintext and wrong passwords, verify the server certificate, and reject
missing or mismatched client certificates even when signed by the trusted CA.

The system suite `drivers/areas_check.py` separately checks size-one pool handoff,
settings/prepared isolation, cancellation in both modes, startup options, DDL
reprepare, idle backend termination/reconnection and password rejection. Supply
`--readonly` to test a route with `require_primary=true` pointing to a database
with `default_transaction_read_only=on`. Normal handoff routes can also enable
`require_primary` to exercise role checks before every checkout.

Unit tests cover binding proof substitution/downgrade, transport backpressure and
handshake deadlines, idle EOF/pending-data detection, writable-primary changes,
independent cancellation locks, admission limits and shutdown waiting for clients.
The separate backend TLS, reload and version-matrix drivers cover backend encryption,
certificate reload, SASLprep and PostgreSQL 14–18 compatibility; see `VERIFICATION.md`.
Frontend checks alone do not establish full state virtualization or performance gates.
