# Backend TLS acceptance

Build `cargo build -p pgproxy-cli`, then run `tests/conformance/backend-tls/run.sh`.
Requires Docker and OpenSSL; uses PostgreSQL 18 and a disposable Python driver
container. Default ports are 55440 (backend) and 6441 (proxy), configurable with
`PGPROXY_TLS_BACKEND_PORT` and `PGPROXY_TLS_PROXY_PORT`.

The runner creates temporary certificates and public fixture credentials, uses
SCRAM-SHA-256-PLUS with a mandatory channel binding, verifies encryption through
`pg_stat_ssl`, exercises prepared queries and encrypted cancellation/recovery,
and rejects both a wrong server name and an untrusted CA. Its cleanup trap
removes only its own container and files. Frontend connections deliberately use
plaintext loopback so the test isolates backend TLS; frontend TLS has a separate
security acceptance driver.

Backend TLS is strict verify-full: no plaintext fallback and no insecure
certificate verifier. A supplied server name can be a DNS name or an IP address
and must match the certificate. CA files are explicitly configured. Platform trust store discovery,
certificate hot reload, and direct-TLS negotiation are separate features.

The runner also verifies mutual TLS with a CA-issued client certificate whose
common name matches the backend role, and rejects missing or wrong certificate
identities. A separate role uses a Unicode password containing a soft hyphen;
PostgreSQL and the proxy must normalize it with SASLprep before SCRAM proof
verification. Unit vectors cover RFC mappings and PostgreSQL's raw-byte fallback
for prohibited or invalid UTF-8 input.

Unsupported certificate signature digest algorithms cannot satisfy mandatory
endpoint channel binding and fail closed.

Set `PGPROXY_TLS_SERVER_SIGNATURE=pss` to generate an RSA-PSS SHA384 server
certificate and verify its parameter-specific endpoint digest with PostgreSQL.
