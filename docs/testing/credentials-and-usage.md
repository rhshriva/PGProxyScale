# Credential adapters and measured usage

Backend credentials can be acquired at physical connection creation using an optional
`[databases.credential_provider]`. It replaces `password` and requires terminated client
authentication. Provider configuration and output are never accepted from client SQL/MCP arguments.
Existing configured principal/policy identities remain independent of dynamic backend roles.

Supported adapters:

| Kind | Configuration | Lease behavior |
|---|---|---|
| `environment` | `password_variable`, optional `user_variable`, `ttl_secs` (1–3600) | Reread on connection creation; physical socket retired at configured TTL |
| `file` | `path` | Bounded JSON `{user?,password,expires_at}`; expiry is Unix seconds, required and at most 24 hours away |
| `command` | Absolute `program`, bounded `args`, `timeout_secs` (1–30) | Same JSON lease; no implicit shell; bounded process timeout/output |
| `aws_rds` | `region`, optional AWS CLI `program` | Generates endpoint-specific IAM token; conservatively retires sockets after 14 minutes |
| `vault` | `role_path` such as `database/creds/app`, optional Vault CLI `program` | Uses dynamic username/password and issuer lease duration; does not silently renew revoked grants |

Cloud adapters require verified backend TLS. AWS IAM token acquisition is performed separately
for each failover candidate because the token is bound to the endpoint. The AWS CLI's ambient
credential chain supplies cloud identity. Vault requires explicit HTTPS `VAULT_ADDR`, refuses
`VAULT_SKIP_VERIFY=true`, and delegates Vault authentication/CA configuration to the CLI.
Only dynamic database leases are accepted. Renewal and revocation of upstream identities remain
provider/operator responsibilities; no client is migrated within an open transaction when a lease
expires. Pooled expired sockets are discarded; retained expired ownership closes before another
user request. External revocation is not instantly detected on an already authenticated socket.

Provider stdout is captured in a private 0600 temporary file unlinked before the child starts.
Only regular credential files are accepted; nonblocking open rejects FIFO/device traps. Issuers
run in private process groups, and direct signal cleanup terminates ordinary descendants on
timeout, failure and completion without requiring an external kill executable.
Output memory is limited to 64 KiB and oversized/failed/timed-out providers fail closed. The
operator-selected executable is trusted code; it can spawn children and affect its own environment.
Errors discard stdout/stderr, and credentials are redacted from backend/router Debug output.
No credentials are written to repository artifacts.

AWS token duration and invocation follow the
[AWS RDS authentication documentation](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.Connecting.html)
and [CLI reference](https://docs.aws.amazon.com/cli/latest/reference/rds/generate-db-auth-token.html).
Vault lease handling follows the
[database secrets engine documentation](https://developer.hashicorp.com/vault/docs/secrets/databases).
Local tests verify response/expiry parsing and command contracts, and file/environment/broker
leases through actual PostgreSQL SCRAM. They do **not** certify a live AWS account or Vault deployment.
OAuth/SASL OAUTHBEARER and RFC 8693 vending remain outside these adapters.

## Cost attribution

Enable `general.session.cost_attribution = true` to record wire usage. Authenticated operations
`GET /usage` returns bounded accounts keyed by full principal and versioned normalized fingerprint.
Simple/extended protocol rows, DataRow frame bytes, elapsed client exchange time, errors and
partial aborted exchanges are measured. A multi-statement or mixed pipelined cycle is an exchange
aggregate, not invented individual statement CPU timing. Prepared SQL/bind values are not retained;
only bounded name/fingerprint provenance is kept. Cardinality is limited to 4096 accounts, with
explicit dropped-sample reporting. Tracker overflow is unmeasured and contributes to `dropped_samples`, while response alignment
stays correct. Instrumentation adds parser/locking overhead and is opt-in.

MCP observer records authorized tool execution, serialized result rows/UTF-8 bytes, failures and
both literal/relation cache hits. `--mcp-usage-report /path/report.json` exports on clean input EOF.
It does not checkpoint on process crash. Cache hits remain authorized and quota charged.
CLI reports are published atomically using a new private file (0600 on Unix),
including when replacing an existing report. A destination symlink is replaced
without writing through it; a failed publication preserves the prior destination.

**CPU time, buffers and WAL bytes remain null in client usage reports** because PostgreSQL's wire protocol does not report
per-statement values. Delivered rows are not server rows scanned. Elapsed client time is not CPU.
Actual server measurements are available separately through an operator-requested export:

```sh
pgproxy --config pgproxy.toml --server-cost-database app \
  --server-cost-user monitor --server-cost-report /private/path/server-cost.json
```

The configured route requires monitoring privileges and `pg_stat_statements`.
WAL and buffer measurements are cumulative database/role/PostgreSQL-queryid
aggregates. Optional `pg_stat_kcache` supplies actual execution CPU measurements.
Shared roles include activity outside the proxy; no exclusive tenant allocation
or mapping to proxy parser fingerprints is invented. Reset, eviction and CPU
instrumentation limitations are explicit. See
[server cost acceptance](../../tests/conformance/governance/README.md#measured-server-cost)
for exact counter semantics and reproduction.

MCP metadata/context/cache validation/query/commit share a single query deadline;
checked partial reads prevent trickling frames or notices from extending it.
The statement timeout is reduced to the remaining budget before user SQL.

## Durable local acceptance

`tests/conformance/credentials/setup.sql` creates two isolated LOGIN roles; require SCRAM for
those roles in the disposable PostgreSQL instance. Run `credentials/fixture.py <directory>` and
start the resulting config with `PGPROXY_CREDENTIAL_TEST_PASSWORD=pgproxy-credential-test-a`.
Then run `drivers/credentials_usage_check.py --fixtures <directory>` from a psycopg environment.
The five cases prove expiry, role rotation, fresh broker acquisition, refusal and both protocol paths.
`relation_cache_check.py` additionally reconciles all MCP rows/bytes/cache/errors with its usage report.
All listed passwords/tokens are public test values for disposable fixtures only.
