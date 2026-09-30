//! Configuration: file, environment, then CLI overrides — in that order of precedence.
//!
//! Configuration is a validated plain-data struct, not a pile of argv. The binary is a
//! thin adapter over this loader, so an embedder can construct the same struct
//! programmatically (ADR-0005).

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};

/// Default bind address.
pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0";
/// Default bind port. IANA assigned 6432 to PgBouncer; we match it so evaluation is drop-in.
pub const DEFAULT_LISTEN_PORT: u16 = 6432;
/// Default server connections per database.
pub const DEFAULT_POOL_SIZE: usize = 20;
/// Default wait for a pooled backend connection.
pub const DEFAULT_CHECKOUT_TIMEOUT_SECS: u64 = 5;
/// Default wait for a backend TCP connection.
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Default graceful-shutdown budget.
pub const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 30;
/// Upper bound on worker threads. Above this, per-core state stops being a sane model.
pub const MAX_WORKERS: usize = 1024;

fn default_backend_limit() -> usize {
    200
}
fn default_client_limit() -> usize {
    1024
}
fn default_connection_rate() -> u32 {
    1000
}
fn default_listen_addr() -> String {
    DEFAULT_LISTEN_ADDR.to_string()
}
fn default_listen_port() -> u16 {
    DEFAULT_LISTEN_PORT
}
fn default_pg_port() -> u16 {
    5432
}
fn default_pool_size() -> usize {
    DEFAULT_POOL_SIZE
}
fn default_checkout_timeout() -> u64 {
    DEFAULT_CHECKOUT_TIMEOUT_SECS
}
fn default_connect_timeout() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_SECS
}
fn default_shutdown_timeout() -> u64 {
    DEFAULT_SHUTDOWN_TIMEOUT_SECS
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> LogFormat {
    LogFormat::Text
}

/// Protocol and ledger limits, shared by all routes in this process.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionLimits {
    pub virtualize_hold_cursors: bool,
    pub cost_attribution: bool,
    pub startup_timeout_secs: u64,
    pub query_timeout_secs: u64,
    pub idle_in_transaction_secs: u64,
    pub client_write_timeout_secs: u64,
    pub max_message_bytes: usize,
    pub max_sql_bytes: usize,
    pub memory_bytes: usize,
}
impl Default for SessionLimits {
    fn default() -> Self {
        let options = pgproxy_wire::SessionOptions::default();
        Self {
            virtualize_hold_cursors: false,
            cost_attribution: false,
            startup_timeout_secs: options.connect_timeout.as_secs(),
            query_timeout_secs: options.query_timeout.as_secs(),
            idle_in_transaction_secs: options.idle_in_transaction.as_secs(),
            client_write_timeout_secs: options.client_write_timeout.as_secs(),
            max_message_bytes: options.max_message_len,
            max_sql_bytes: options.max_sql_bytes,
            memory_bytes: options.session_memory_bytes,
        }
    }
}

/// Frontend TLS certificate and key. Relative paths resolve against the process working directory.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendTlsConfig {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub client_ca: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendTlsConfig {
    #[serde(default)]
    pub client_certificate: Option<PathBuf>,
    #[serde(default)]
    pub private_key: Option<PathBuf>,
    pub root_certificate: PathBuf,
    pub server_name: String,
    #[serde(default)]
    pub require_channel_binding: bool,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationsConfig {
    pub listen: SocketAddr,
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyGrant {
    pub principal: pgproxy_policy::Principal,
    pub capabilities: pgproxy_policy::Capabilities,
    pub quota: pgproxy_policy::admission::Quota,
    #[serde(default = "default_policy_weight")]
    pub weight: u32,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub context: Option<pgproxy_policy::context::TransactionContext>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub grants: Vec<PolicyGrant>,
    #[serde(default)]
    pub scheduler: Option<pgproxy_policy::shared_scheduler::SchedulerConfig>,
    #[serde(default = "default_queue_timeout")]
    pub queue_timeout_ms: u64,
}
fn default_policy_weight() -> u32 {
    1
}
fn default_queue_timeout() -> u64 {
    50
}
impl PolicyConfig {
    pub fn compile(&self) -> Result<std::sync::Arc<pgproxy_wire::governance::RouteGovernance>> {
        let mut contexts = std::collections::BTreeMap::new();
        let mut weights = std::collections::BTreeMap::new();
        let mut grants = std::collections::BTreeMap::new();
        let mut quotas = std::collections::BTreeMap::new();
        let mut principals = std::collections::BTreeMap::new();
        for grant in &self.grants {
            if grant.principal.user.is_empty()
                || grant.principal.tenant.is_empty()
                || principals
                    .insert(grant.principal.user.clone(), grant.principal.clone())
                    .is_some()
            {
                return Err(Error::Config(
                    "policy principal usernames must be unique and identities nonempty".into(),
                ));
            }
            let priority = match grant.priority.as_deref().unwrap_or("interactive") {
                "interactive" => pgproxy_policy::scheduler::Priority::Interactive,
                "batch" => pgproxy_policy::scheduler::Priority::Batch,
                "analytics" => pgproxy_policy::scheduler::Priority::Analytics,
                "migration" => pgproxy_policy::scheduler::Priority::Migration,
                _ => return Err(Error::Config("invalid scheduling priority".into())),
            };
            weights.insert(grant.principal.clone(), (grant.weight, priority));
            if let Some(context) = &grant.context {
                context
                    .session_commands()
                    .map_err(|e| Error::Config(e.to_string()))?;
                if context.tenant != grant.principal.tenant {
                    return Err(Error::Config(
                        "policy context tenant must match principal identity".into(),
                    ));
                }
                contexts.insert(grant.principal.clone(), context.clone());
            }
            grants.insert(grant.principal.clone(), grant.capabilities.clone());
            quotas.insert(grant.principal.clone(), grant.quota.clone());
        }
        if self.queue_timeout_ms > 10000 {
            return Err(Error::Config(
                "policy queue timeout exceeds 10 seconds".into(),
            ));
        }
        let scheduler = self
            .scheduler
            .clone()
            .map(|cfg| {
                pgproxy_policy::shared_scheduler::SharedScheduler::new(weights, cfg)
                    .map(|scheduler| {
                        (
                            scheduler,
                            std::time::Duration::from_millis(self.queue_timeout_ms),
                        )
                    })
                    .map_err(|e| Error::Config(e.to_string()))
            })
            .transpose()?;
        Ok(std::sync::Arc::new(
            pgproxy_wire::governance::RouteGovernance {
                policy: pgproxy_policy::Policy::new(grants)
                    .map_err(|e| Error::Config(e.to_string()))?,
                admission: pgproxy_policy::admission::Admission::new(quotas)
                    .map_err(|e| Error::Config(e.to_string()))?,
                principals,
                scheduler,
                contexts,
            },
        ))
    }
}

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Process-level settings.
    #[serde(default)]
    pub general: General,
    /// Logging settings.
    #[serde(default)]
    pub logging: Logging,
    #[serde(default)]
    pub operations: Option<OperationsConfig>,
    /// Databases that clients may connect to through the proxy.
    #[serde(default)]
    pub databases: Vec<Database>,
}

/// Process-level settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct General {
    /// Address to listen on. Must be an IP literal; hostname binding is deliberately
    /// not supported (a proxy that resolves its own bind name is a footgun).
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// Port to listen on.
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Worker threads. `0` means one per available CPU.
    #[serde(default)]
    pub workers: usize,
    #[serde(default = "default_client_limit")]
    pub max_client_connections: usize,
    #[serde(default = "default_backend_limit")]
    pub max_backend_connections: usize,
    #[serde(default = "default_connection_rate")]
    pub connection_rate_per_second: u32,
    /// Users permitted to use the admin surface. Empty disables it.
    #[serde(default)]
    pub admin_users: Vec<String>,
    /// How long to wait for in-flight work during shutdown.
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
    /// Startup/query bounds and per-client memory caps.
    #[serde(default)]
    pub session: SessionLimits,
    #[serde(default)]
    pub tls: Option<FrontendTlsConfig>,
}

impl Default for General {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: default_listen_port(),
            workers: 0,
            max_client_connections: default_client_limit(),
            max_backend_connections: default_backend_limit(),
            connection_rate_per_second: default_connection_rate(),
            admin_users: Vec::new(),
            shutdown_timeout_secs: default_shutdown_timeout(),
            session: SessionLimits::default(),
            tls: None,
        }
    }
}

/// Logging settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Logging {
    /// `tracing` filter directive, e.g. `info` or `pgproxy_wire=debug,info`.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Output format.
    #[serde(default = "default_log_format")]
    pub format: LogFormat,
}

impl Default for Logging {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

/// How connections are pooled for a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PoolMode {
    /// One backend per client, held for the whole session.
    ///
    /// Authentication is relayed, so the proxy needs no backend credential. This is the
    /// default because it is the only mode that cannot corrupt a session.
    #[default]
    Session,
    /// One backend per transaction, returned to the pool at each transaction boundary.
    ///
    /// Requires a backend credential: authentication cannot be relayed because the
    /// connection serving a query is not the one the client logged in on.
    Transaction,
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable, for terminals.
    Text,
    /// Structured, for log shippers.
    Json,
}

/// Client-side authentication is separate from the backend credential.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientAuthMethod {
    /// Backend authentication exchange, session mode only.
    #[default]
    Passthrough,
    /// Explicitly unauthenticated clients.
    Trust,
    /// Stored MD5 hashes.
    Md5,
    /// Stored SCRAM verifiers.
    ScramSha256,
    /// SHA256 fingerprints of certificates verified against general.tls.client_ca.
    Certificate,
}

/// A backend database reachable through the proxy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
    #[serde(default)]
    pub failover: Vec<FailoverEndpointConfig>,
    #[serde(default)]
    pub credential_provider: Option<crate::credentials::CredentialConfig>,
    /// Name clients use to reach this database.
    pub name: String,
    /// Backend host.
    pub host: String,
    /// Backend port.
    #[serde(default = "default_pg_port")]
    pub port: u16,
    /// Backend database name. Defaults to the client-supplied name.
    #[serde(default)]
    pub dbname: Option<String>,
    /// Maximum server connections for this database.
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    /// How connections to this database are pooled.
    #[serde(default)]
    pub pool_mode: PoolMode,
    /// Client authentication selection; transaction mode requires explicit selection.
    #[serde(default)]
    pub client_auth: ClientAuthMethod,
    /// Username to stored PostgreSQL verifier. Never a plaintext password.
    #[serde(default)]
    pub auth_users: std::collections::HashMap<String, String>,
    /// Role to connect to the backend as, ignoring the client's choice.
    ///
    /// Unset means each client's own role is used, which gives one pool per
    /// `(database, user)` as PgBouncer does.
    #[serde(default)]
    pub user: Option<String>,
    /// Password for the backend role.
    ///
    /// Only needed when the backend challenges the proxy, which transaction pooling
    /// requires and session mode does not. Note that this stores a secret in the
    /// configuration file, exactly as PgBouncer's `auth_file` does — a deliberate,
    /// documented trade-off rather than an oversight.
    #[serde(default)]
    pub password: Option<String>,
    /// How long a session waits for a pooled backend before being told there are too many
    /// clients.
    #[serde(default = "default_checkout_timeout")]
    pub checkout_timeout_secs: u64,
    /// How long to wait for the backend TCP connection.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    /// Verify that each transaction-pooled backend is a writable primary.
    #[serde(default)]
    pub require_primary: bool,
    #[serde(default)]
    pub backend_tls: Option<BackendTlsConfig>,
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
}

/// Ordered alternate endpoints; omitted TLS inherits the primary configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailoverEndpointConfig {
    pub host: String,
    #[serde(default = "default_pg_port")]
    pub port: u16,
    #[serde(default)]
    pub backend_tls: Option<BackendTlsConfig>,
}

/// Overrides applied after the file is read, from the CLI or an embedder.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    /// Replace `general.workers`.
    pub workers: Option<usize>,
    /// Replace `logging.level`.
    pub log_level: Option<String>,
    /// Replace `general.listen_port`.
    pub listen_port: Option<u16>,
}

impl Config {
    /// Read and parse a configuration file, applying no environment overrides.
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|source| Error::ConfigRead {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| Error::ConfigParse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })
    }

    /// Read a configuration file, then apply `PGPROXY_*` environment overrides.
    ///
    /// Recognised variables: `PGPROXY_LISTEN_ADDR`, `PGPROXY_LISTEN_PORT`,
    /// `PGPROXY_WORKERS`, `PGPROXY_LOG_LEVEL`, `PGPROXY_LOG_FORMAT`.
    pub fn from_file_with_env(path: &Path) -> Result<Self> {
        let mut cfg = Self::from_file(path)?;
        cfg.apply_env(std::env::vars())?;
        Ok(cfg)
    }

    /// Apply environment overrides. Takes an iterator so it is testable without
    /// mutating the process environment.
    pub fn apply_env<I, K, V>(&mut self, vars: I) -> Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (k, v) in vars {
            let v = v.as_ref();
            match k.as_ref() {
                "PGPROXY_LISTEN_ADDR" => self.general.listen_addr = v.to_string(),
                "PGPROXY_LISTEN_PORT" => {
                    self.general.listen_port = v.parse().map_err(|_| {
                        Error::Config(format!("PGPROXY_LISTEN_PORT={v:?} is not a port"))
                    })?
                }
                "PGPROXY_WORKERS" => {
                    self.general.workers = v.parse().map_err(|_| {
                        Error::Config(format!("PGPROXY_WORKERS={v:?} is not a number"))
                    })?
                }
                "PGPROXY_LOG_LEVEL" => self.logging.level = v.to_string(),
                "PGPROXY_LOG_FORMAT" => {
                    self.logging.format = match v {
                        "text" => LogFormat::Text,
                        "json" => LogFormat::Json,
                        other => {
                            return Err(Error::Config(format!(
                                "PGPROXY_LOG_FORMAT={other:?} must be 'text' or 'json'"
                            )));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Apply CLI/embedder overrides. Highest precedence.
    pub fn apply_overrides(&mut self, o: &Overrides) {
        if let Some(w) = o.workers {
            self.general.workers = w;
        }
        if let Some(p) = o.listen_port {
            self.general.listen_port = p;
        }
        if let Some(l) = &o.log_level {
            self.logging.level = l.clone();
        }
    }

    /// Reject configurations that would fail confusingly at runtime.
    pub fn validate(&self) -> Result<()> {
        if self.databases.is_empty() {
            return Err(Error::Config(
                "no [[databases]] entries: the proxy would accept connections it cannot route"
                    .to_string(),
            ));
        }

        if !(1..=1_000_000).contains(&self.general.max_backend_connections)
            || !(1..=1_000_000).contains(&self.general.max_client_connections)
            || !(1..=1_000_000).contains(&self.general.connection_rate_per_second)
        {
            return Err(Error::Config("invalid connection admission limits".into()));
        }
        if let Some(ops) = &self.operations
            && (!ops.listen.ip().is_loopback() || ops.token.len() < 32)
        {
            return Err(Error::Config(
                "operations requires a loopback listener and token of at least 32 bytes".into(),
            ));
        }
        let limits = &self.general.session;
        if [
            limits.startup_timeout_secs,
            limits.query_timeout_secs,
            limits.idle_in_transaction_secs,
            limits.client_write_timeout_secs,
        ]
        .iter()
        .any(|seconds| !(1..=86400).contains(seconds))
            || limits.max_message_bytes < 5
            || limits.max_message_bytes > 64 * 1024 * 1024
            || limits.max_sql_bytes == 0
            || limits.max_sql_bytes > 1024 * 1024
            || limits.memory_bytes < 65536
            || limits.memory_bytes > 64 * 1024 * 1024
        {
            return Err(Error::Config(
                "invalid general.session timeout or memory limits".into(),
            ));
        }

        for db in &self.databases {
            if let Some(policy) = &db.policy {
                if matches!(
                    db.client_auth,
                    ClientAuthMethod::Passthrough | ClientAuthMethod::Trust
                ) {
                    return Err(Error::Config(
                        "SQL policy requires verified client authentication".into(),
                    ));
                }
                if policy
                    .scheduler
                    .as_ref()
                    .is_some_and(|scheduler| scheduler.maximum > db.pool_size)
                {
                    return Err(Error::Config(
                        "scheduler maximum must not exceed route pool size".into(),
                    ));
                }
                policy.compile()?;
            }
            if !db.failover.is_empty() {
                if db.failover.len() > 7 || db.client_auth == ClientAuthMethod::Passthrough {
                    return Err(Error::Config("failover requires terminated authentication and at most seven alternate endpoints".into()));
                }
                let mut endpoints = std::collections::BTreeSet::new();
                endpoints.insert((db.host.as_str(), db.port));
                for endpoint in &db.failover {
                    if endpoint.host.is_empty()
                        || endpoint.host.len() > 256
                        || endpoint.port == 0
                        || !endpoints.insert((endpoint.host.as_str(), endpoint.port))
                    {
                        return Err(Error::Config(
                            "failover endpoints must be valid and distinct".into(),
                        ));
                    }
                    if let Some(tls) = &endpoint.backend_tls
                        && (tls.server_name.is_empty()
                            || tls.root_certificate.as_os_str().is_empty()
                            || tls.client_certificate.is_some() != tls.private_key.is_some()
                            || tls
                                .client_certificate
                                .as_ref()
                                .is_some_and(|p| p.as_os_str().is_empty())
                            || tls
                                .private_key
                                .as_ref()
                                .is_some_and(|p| p.as_os_str().is_empty()))
                    {
                        return Err(Error::Config(
                            "invalid alternate backend TLS identity".into(),
                        ));
                    }
                }
            }
            if let Some(provider) = &db.credential_provider {
                provider.validate().map_err(Error::Config)?;
                if db.password.is_some() || db.client_auth == ClientAuthMethod::Passthrough {
                    return Err(Error::Config("credential adapters require terminated authentication and replace static backend passwords".into()));
                }
                if matches!(
                    provider,
                    crate::credentials::CredentialConfig::AwsRds { .. }
                        | crate::credentials::CredentialConfig::Vault { .. }
                ) && db.backend_tls.is_none()
                {
                    return Err(Error::Config(
                        "cloud credential adapters require verified backend TLS".into(),
                    ));
                }
            }
            if let Some(tls) = &db.backend_tls
                && (tls.server_name.is_empty()
                    || tls.root_certificate.as_os_str().is_empty()
                    || (db.pool_mode == PoolMode::Session
                        && db.client_auth == ClientAuthMethod::Passthrough))
            {
                return Err(Error::Config("backend TLS requires a root certificate, server name and terminated authentication".into()));
            }
            if let Some(tls) = &db.backend_tls {
                if tls.client_certificate.is_some() != tls.private_key.is_some() {
                    return Err(Error::Config(
                        "backend TLS client certificate and private key must be paired".into(),
                    ));
                }
                if tls
                    .client_certificate
                    .as_ref()
                    .is_some_and(|path| path.as_os_str().is_empty())
                    || tls
                        .private_key
                        .as_ref()
                        .is_some_and(|path| path.as_os_str().is_empty())
                {
                    return Err(Error::Config(
                        "backend TLS client identity paths cannot be empty".into(),
                    ));
                }
            }
            if db.name.is_empty() {
                return Err(Error::Config(
                    "a [[databases]] entry has an empty name".to_string(),
                ));
            }
            if db.name == "pgbouncer" || db.name == "pgproxy" {
                return Err(Error::Config(format!(
                    "database name {:?} is reserved for the admin console",
                    db.name
                )));
            }
            if db.host.is_empty() {
                return Err(Error::Config(format!(
                    "database {:?} has an empty host",
                    db.name
                )));
            }
            if !(1..=86400).contains(&db.checkout_timeout_secs) {
                return Err(Error::Config(format!(
                    "database {:?} checkout_timeout_secs must be between 1 and 86400",
                    db.name
                )));
            }
            if !(1..=86400).contains(&db.connect_timeout_secs) {
                return Err(Error::Config(format!(
                    "database {:?} connect_timeout_secs must be between 1 and 86400",
                    db.name
                )));
            }
            if db.pool_mode == PoolMode::Session
                && db.client_auth == ClientAuthMethod::Passthrough
                && db.password.is_some()
            {
                // Not an error - a session-mode database may still want a credential for
                // future use - but it is almost always a mistake worth naming.
                tracing::warn!(
                    database = %db.name,
                    "a password is configured for a session-mode database; session mode \
                     relays authentication and does not need one"
                );
            }
            if db.pool_mode == PoolMode::Transaction
                && db.client_auth == ClientAuthMethod::Passthrough
            {
                return Err(Error::Config(format!(
                    "database {:?}: transaction mode requires client_auth = trust, md5, scram-sha256, or certificate",
                    db.name
                )));
            }
            if db.require_primary
                && db.pool_mode == PoolMode::Session
                && db.client_auth == ClientAuthMethod::Passthrough
            {
                return Err(Error::Config(
                    "require_primary needs terminated authentication or transaction mode".into(),
                ));
            }
            if db.client_auth == ClientAuthMethod::Certificate
                && self
                    .general
                    .tls
                    .as_ref()
                    .and_then(|tls| tls.client_ca.as_ref())
                    .is_none()
            {
                return Err(Error::Config(
                    "certificate authentication requires general.tls.client_ca".into(),
                ));
            }
            if matches!(
                db.client_auth,
                ClientAuthMethod::Md5
                    | ClientAuthMethod::ScramSha256
                    | ClientAuthMethod::Certificate
            ) && db.auth_users.is_empty()
            {
                return Err(Error::Config(format!(
                    "database {:?}: auth_users must contain stored verifiers",
                    db.name
                )));
            }
            for (user, verifier) in &db.auth_users {
                let valid = !user.is_empty()
                    && match db.client_auth {
                        ClientAuthMethod::Md5 => pgproxy_wire::auth::md5::is_md5_hash(verifier),
                        ClientAuthMethod::ScramSha256 => {
                            pgproxy_wire::auth::scram::ScramVerifier::parse(verifier).is_ok()
                        }
                        ClientAuthMethod::Certificate => {
                            pgproxy_wire::tls::decode_fingerprint(verifier).is_some()
                        }
                        _ => false,
                    };
                if !valid {
                    return Err(Error::Config(format!(
                        "database {:?}: invalid auth_users verifier for user {:?}",
                        db.name, user
                    )));
                }
            }
            if db.pool_size == 0 {
                return Err(Error::Config(format!(
                    "database {:?} has pool_size = 0, which would never serve a query",
                    db.name
                )));
            }
        }

        let mut seen: Vec<&str> = self.databases.iter().map(|d| d.name.as_str()).collect();
        seen.sort_unstable();
        for pair in seen.windows(2) {
            if pair[0] == pair[1] {
                return Err(Error::Config(format!(
                    "database {:?} is defined more than once",
                    pair[0]
                )));
            }
        }

        // Parsed here so the error names the bad value rather than failing at bind time.
        self.socket_addr()?;

        if self.effective_workers() > MAX_WORKERS {
            return Err(Error::Config(format!(
                "workers = {} exceeds the maximum of {MAX_WORKERS}",
                self.effective_workers()
            )));
        }

        if !(1..=86400).contains(&self.general.shutdown_timeout_secs) {
            return Err(Error::Config(
                "shutdown_timeout_secs must be between 1 and 86400".to_string(),
            ));
        }

        Ok(())
    }

    /// Resolve operator limits into the protocol service's settings.
    pub fn session_options(&self) -> pgproxy_wire::SessionOptions {
        let limits = &self.general.session;
        pgproxy_wire::SessionOptions {
            connect_timeout: std::time::Duration::from_secs(limits.startup_timeout_secs),
            query_timeout: std::time::Duration::from_secs(limits.query_timeout_secs),
            idle_in_transaction: std::time::Duration::from_secs(limits.idle_in_transaction_secs),
            client_write_timeout: std::time::Duration::from_secs(limits.client_write_timeout_secs),
            max_message_len: limits.max_message_bytes,
            max_sql_bytes: limits.max_sql_bytes,
            session_memory_bytes: limits.memory_bytes,
            virtualize_hold_cursors: limits.virtualize_hold_cursors,
            cost_attribution: limits.cost_attribution,
            backend_capacity: pgproxy_pool::ConnectionLimit::new(
                self.general.max_backend_connections,
            ),
            ..Default::default()
        }
    }

    /// The address to bind, as a parsed socket address.
    pub fn socket_addr(&self) -> Result<SocketAddr> {
        let ip: IpAddr = self
            .general
            .listen_addr
            .parse()
            .map_err(|source| Error::ListenAddr {
                addr: self.general.listen_addr.clone(),
                source,
            })?;
        Ok(SocketAddr::new(ip, self.general.listen_port))
    }

    /// Worker count, resolving `0` to one per available CPU.
    pub fn effective_workers(&self) -> usize {
        if self.general.workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        } else {
            self.general.workers
        }
    }

    /// Look up a database by the name a client asked for.
    pub fn database(&self, name: &str) -> Option<&Database> {
        self.databases.iter().find(|d| d.name == name)
    }

    /// Canonical path used in log lines.
    pub fn display_path(path: &Path) -> PathBuf {
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        Config {
            databases: vec![Database {
                name: "app".into(),
                host: "127.0.0.1".into(),
                port: 5432,
                dbname: None,
                pool_size: 10,
                pool_mode: PoolMode::Session,
                client_auth: ClientAuthMethod::Passthrough,
                auth_users: Default::default(),
                user: None,
                password: None,
                checkout_timeout_secs: DEFAULT_CHECKOUT_TIMEOUT_SECS,
                connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
                require_primary: false,
                backend_tls: None,
                policy: None,
                failover: Vec::new(),
                credential_provider: None,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn alternate_endpoints_and_credential_adapters_are_fail_closed() {
        let mut config = base();
        config.databases[0].failover.push(FailoverEndpointConfig {
            host: "alternate".into(),
            port: 5432,
            backend_tls: None,
        });
        assert!(config.validate().is_err());
        config.databases[0].client_auth = ClientAuthMethod::Trust;
        config.validate().unwrap();
        let duplicate = config.databases[0].failover[0].clone();
        config.databases[0].failover.push(duplicate);
        assert!(config.validate().is_err());
        config.databases[0].failover.pop();
        config.databases[0].credential_provider =
            Some(crate::credentials::CredentialConfig::AwsRds {
                region: "us-west-2".into(),
                program: "aws".into(),
            });
        assert!(config.validate().is_err());
        config.databases[0].credential_provider =
            Some(crate::credentials::CredentialConfig::Environment {
                password_variable: "PGPROXY_BACKEND_SECRET".into(),
                user_variable: None,
                ttl_secs: 30,
            });
        config.validate().unwrap();
        config.databases[0].password = Some("conflicting".into());
        assert!(config.validate().is_err());
    }

    #[test]
    fn operator_limits_are_validated_and_reach_the_service() {
        let mut config = base();
        config.general.session.query_timeout_secs = 7;
        config.general.session.memory_bytes = 131072;
        config.validate().unwrap();
        assert_eq!(config.session_options().query_timeout.as_secs(), 7);
        assert_eq!(config.session_options().session_memory_bytes, 131072);
        config.general.session.max_sql_bytes = 0;
        assert!(config.validate().is_err());
        config.general.session.max_sql_bytes = 65536;
        config.general.session.startup_timeout_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn unbounded_operator_timeouts_are_rejected_before_deadline_construction() {
        for field in 0..7 {
            let mut config = base();
            let seconds = match field {
                0 => &mut config.general.session.startup_timeout_secs,
                1 => &mut config.general.session.query_timeout_secs,
                2 => &mut config.general.session.idle_in_transaction_secs,
                3 => &mut config.general.session.client_write_timeout_secs,
                4 => &mut config.general.shutdown_timeout_secs,
                5 => &mut config.databases[0].connect_timeout_secs,
                _ => &mut config.databases[0].checkout_timeout_secs,
            };
            *seconds = u64::MAX;
            assert!(config.validate().is_err(), "timeout field {field}");
        }
        let mut config = base();
        config.general.session.query_timeout_secs = 86400;
        config.validate().unwrap();
    }

    #[test]
    fn transaction_authentication_must_be_explicit() {
        let mut c = base();
        c.databases[0].pool_mode = PoolMode::Transaction;
        assert!(
            c.validate()
                .unwrap_err()
                .to_string()
                .contains("requires client_auth")
        );
        c.databases[0].client_auth = ClientAuthMethod::Trust;
        c.validate().unwrap();
        c.databases[0].client_auth = ClientAuthMethod::ScramSha256;
        assert!(c.validate().is_err());
        c.databases[0].auth_users.insert(
            "alice".into(),
            pgproxy_wire::auth::scram::ScramVerifier::generate(b"secret").to_secret(),
        );
        c.validate().unwrap();
        c.databases[0]
            .auth_users
            .insert("alice".into(), "plaintext-is-not-a-verifier".into());
        assert!(c.validate().is_err());
    }

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert_eq!(c.general.listen_port, DEFAULT_LISTEN_PORT);
        assert_eq!(c.general.listen_addr, DEFAULT_LISTEN_ADDR);
        assert_eq!(c.logging.format, LogFormat::Text);
    }

    #[test]
    fn workers_zero_resolves_to_cpus() {
        let c = Config::default();
        assert!(c.effective_workers() >= 1);
    }

    #[test]
    fn validate_rejects_no_databases() {
        let err = Config::default().validate().unwrap_err();
        assert!(err.to_string().contains("no [[databases]]"), "{err}");
    }

    #[test]
    fn validate_rejects_duplicate_database_names() {
        let mut c = base();
        c.databases.push(c.databases[0].clone());
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("more than once"), "{err}");
    }

    #[test]
    fn validate_rejects_reserved_database_name() {
        let mut c = base();
        c.databases[0].name = "pgproxy".into();
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");
    }

    #[test]
    fn validate_rejects_zero_pool_size() {
        let mut c = base();
        c.databases[0].pool_size = 0;
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("pool_size"), "{err}");
    }

    #[test]
    fn validate_rejects_bad_listen_address() {
        let mut c = base();
        c.general.listen_addr = "not-an-ip".into();
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("listen address"), "{err}");
    }

    #[test]
    fn validate_accepts_a_good_config() {
        base().validate().unwrap();
    }

    #[test]
    fn env_overrides_apply() {
        let mut c = base();
        c.apply_env([
            ("PGPROXY_LISTEN_PORT", "7000"),
            ("PGPROXY_WORKERS", "3"),
            ("PGPROXY_LOG_LEVEL", "debug"),
            ("PGPROXY_LOG_FORMAT", "json"),
            ("UNRELATED", "ignored"),
        ])
        .unwrap();
        assert_eq!(c.general.listen_port, 7000);
        assert_eq!(c.effective_workers(), 3);
        assert_eq!(c.logging.level, "debug");
        assert_eq!(c.logging.format, LogFormat::Json);
    }

    #[test]
    fn env_rejects_non_numeric_port() {
        let mut c = base();
        let err = c.apply_env([("PGPROXY_LISTEN_PORT", "abc")]).unwrap_err();
        assert!(err.to_string().contains("not a port"), "{err}");
    }

    #[test]
    fn cli_overrides_beat_env() {
        let mut c = base();
        c.apply_env([("PGPROXY_WORKERS", "3")]).unwrap();
        c.apply_overrides(&Overrides {
            workers: Some(8),
            ..Default::default()
        });
        assert_eq!(c.effective_workers(), 8);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let err = toml::from_str::<Config>(
            r#"
            [general]
            listen_port = 6432
            typo_field = true
            [[databases]]
            name = "app"
            host = "127.0.0.1"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("typo_field"), "{err}");
    }
    #[test]
    fn certificate_authentication_needs_a_trust_root_and_exact_fingerprints() {
        let mut config = base();
        config.databases[0].client_auth = ClientAuthMethod::Certificate;
        config.databases[0]
            .auth_users
            .insert("alice".into(), "11".repeat(32));
        assert!(config.validate().is_err());
        config.general.tls = Some(FrontendTlsConfig {
            certificate: "cert.pem".into(),
            private_key: "key.pem".into(),
            required: true,
            client_ca: Some("ca.pem".into()),
        });
        config.validate().unwrap();
        config.databases[0]
            .auth_users
            .insert("alice".into(), "bad fingerprint".into());
        assert!(config.validate().is_err());
    }
    #[test]
    fn backend_client_identity_requires_paired_nonempty_paths() {
        let mut config = base();
        config.databases[0].pool_mode = PoolMode::Transaction;
        config.databases[0].client_auth = ClientAuthMethod::Trust;
        config.databases[0].backend_tls = Some(BackendTlsConfig {
            root_certificate: "ca.pem".into(),
            server_name: "localhost".into(),
            require_channel_binding: false,
            client_certificate: Some("client.pem".into()),
            private_key: None,
        });
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("paired")
        );
        config.databases[0]
            .backend_tls
            .as_mut()
            .unwrap()
            .private_key = Some("key.pem".into());
        assert!(config.validate().is_ok());
        config.databases[0]
            .backend_tls
            .as_mut()
            .unwrap()
            .private_key = Some("".into());
        assert!(config.validate().unwrap_err().to_string().contains("empty"));
    }
}
