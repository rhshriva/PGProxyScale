# Operations and governance acceptance

Operations is opt-in. Configure `[operations]` with `listen = "127.0.0.1:6433"`
and a private random bearer token of at least 32 bytes. Non-loopback addresses
are rejected. `/health` and `/ready` are public on loopback; `/metrics`, `/clients`
and `/pools` require `Authorization: Bearer <token>`. Diagnostics omit SQL,
passwords and certificate material. Client output is bounded to 256 entries.
Read/write deadlines and header size are bounded; request bodies are refused.

Authenticated bodyless POST endpoints `/reload`, `/switchover/prepare`,
`/switchover/commit` and `/switchover/abort` operate on the original configured
file. They never accept an arbitrary path or new configuration in the request.
See `reload-and-capacity.md` for generation/drain behavior.

Latency metrics measure client exchange completion (including pool wait and
relay), with bounded histograms and approximate bucket-upper-bound percentiles.
They are not separate server execution timings for each SQL statement. Unbounded
pipelining cannot allocate an unbounded clock queue; overflow is unmeasured while
response alignment remains preserved. Structured decision tracing records identity,
fingerprint and outcome without raw SQL.

Run `drivers/operations_check.py` against an isolated native proxy with the
`areas_transaction` route. Supply `PGPROXY_OPERATIONS_TOKEN`, `--port` and
`--operations` as appropriate. `protocol_negotiation_check.py` uses the same route
and checks negotiation, GSS fallback and unknown major rejection.

## Governed routes

`tests/conformance/governance/pgproxy.toml` and its README provide a durable
isolated fixture. Grants bind authenticated usernames to configured user/tenant/
agent identities. The client cannot override the identity via SQL or MCP arguments.
SQL capabilities are parsed and deny by default. Only reviewed constructs and
explicitly granted tables/functions are accepted. Unknown casts/operators and
opaque constructs are conservatively refused. Protected columns and associated
wildcards are denied rather than masked.

Trusted transaction context selects the backend role, tenant setting, read-only
state and timeout independently of client SQL. Context is applied before restored
prepared statements and reinstated after restoration resets. Roles, RLS policies,
custom functions and database objects must be reviewed together: granting a custom
function does not prove that its internal dynamic SQL is safe. `pg_catalog.set_config`
cannot be granted to clients because it could mutate the trusted context.

Weighted bounded scheduling applies to leases held through protocol/transaction
completion. Both waiting and active work have per-principal limits. Quotas cover
concurrency, token rate/burst and optional lifetime queries. Resource consumption
is not CPU/WAL chargeback.

## MCP stdio

Start the binary with `--mcp-stdio --mcp-database <route> --mcp-user <user>`.
The selected route must have a configured agent principal. Stdio/config access is
the trust boundary; this command does not expose an unauthenticated network MCP
listener. Logging goes to stderr and JSON-RPC responses to stdout.

Query, non-ANALYZE explain and filtered schema tools share policy and budgets.
Execution uses fresh authenticated backend connections, BEGIN READ ONLY,
trusted context/search path and timeout. Request, row and byte ceilings are checked.
Cache hits remain budgeted; only immutable relation-free literals can be cached.

Drivers `governance_check.py`, `mcp_check.py`, `rls_fairness_check.py` and
`mcp_rls_check.py` exercise wire enforcement, prepared provenance, adversarial
requests, real resource ceilings, tenant RLS and contention. The fixture creates
its own roles/table in a disposable test database, not a user database.
