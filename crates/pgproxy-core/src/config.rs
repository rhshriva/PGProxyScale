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
    /// Users permitted to use the admin surface. Empty disables it.
    #[serde(default)]
    pub admin_users: Vec<String>,
    /// How long to wait for in-flight work during shutdown.
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
}

impl Default for General {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: default_listen_port(),
            workers: 0,
            admin_users: Vec::new(),
            shutdown_timeout_secs: default_shutdown_timeout(),
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

/// A backend database reachable through the proxy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
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

        for db in &self.databases {
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
            if db.checkout_timeout_secs == 0 {
                return Err(Error::Config(format!(
                    "database {:?} has checkout_timeout_secs = 0, which would refuse every \
                     connection the moment the pool is busy",
                    db.name
                )));
            }
            if db.connect_timeout_secs == 0 {
                return Err(Error::Config(format!(
                    "database {:?} has connect_timeout_secs = 0",
                    db.name
                )));
            }
            if db.pool_mode == PoolMode::Session && db.password.is_some() {
                // Not an error - a session-mode database may still want a credential for
                // future use - but it is almost always a mistake worth naming.
                tracing::warn!(
                    database = %db.name,
                    "a password is configured for a session-mode database; session mode \
                     relays authentication and does not need one"
                );
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

        if self.general.shutdown_timeout_secs == 0 {
            return Err(Error::Config(
                "shutdown_timeout_secs = 0 would abandon in-flight work immediately".to_string(),
            ));
        }

        Ok(())
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
                user: None,
                password: None,
                checkout_timeout_secs: DEFAULT_CHECKOUT_TIMEOUT_SECS,
                connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            }],
            ..Default::default()
        }
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
}
