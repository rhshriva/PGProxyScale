//! Routing a client's startup request to a configured backend.
//!
//! This lives in `pgproxy-core` rather than `pgproxy-wire` because it is the one place
//! that needs both: the protocol's view of a startup packet, and the proxy's
//! configuration. `pgproxy-wire` defines the [`DatabaseRouter`] trait and stays ignorant
//! of configuration; this implements it.

use std::collections::HashMap;
use std::time::Duration;

use pgproxy_wire::BackendCredentials;
use pgproxy_wire::StartupParams;
use pgproxy_wire::{
    BackendTarget, DatabaseRouter, PoolMode, PoolSettings, ResolvedBackend, RouteError,
};

use crate::config::{Config, PoolMode as ConfigPoolMode};

/// Resolves database names from configuration.
#[derive(Debug, Clone)]
pub struct ConfigRouter {
    databases: HashMap<String, Route>,
    /// Used when a client names no database and no user-derived name matches.
    default_database: Option<String>,
}

#[derive(Clone)]
struct Route {
    host: String,
    port: u16,
    dbname: Option<String>,
    pool_mode: ConfigPoolMode,
    client_auth: crate::config::ClientAuthMethod,
    auth_users: HashMap<String, String>,
    user: Option<String>,
    password: Option<String>,
    checkout_timeout_secs: u64,
    connect_timeout_secs: u64,
    pool_size: usize,
    require_primary: bool,
    tls: Option<pgproxy_wire::backend_tls::BackendTls>,
    failover: Option<std::sync::Arc<pgproxy_wire::failover::FailoverPlan>>,
    credential_provider: Option<std::sync::Arc<dyn pgproxy_wire::credentials::CredentialProvider>>,
    governance: Option<std::sync::Arc<pgproxy_wire::governance::RouteGovernance>>,
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("dbname", &self.dbname)
            .field("pool_mode", &self.pool_mode)
            .field("user", &self.user)
            .field("failover", &self.failover)
            .field("credential_provider", &self.credential_provider)
            .finish_non_exhaustive()
    }
}

impl ConfigRouter {
    /// Build a router from a validated configuration.
    pub fn new(config: &Config) -> Self {
        Self::try_new(config).expect("valid backend TLS configuration")
    }
    pub fn try_new(config: &Config) -> std::io::Result<Self> {
        let databases = config
            .databases
            .iter()
            .map(|db| {
                let tls = db
                    .backend_tls
                    .as_ref()
                    .map(|tls| {
                        pgproxy_wire::backend_tls::BackendTls::from_pem_with_identity(
                            &tls.root_certificate,
                            &tls.server_name,
                            tls.require_channel_binding,
                            tls.client_certificate.as_deref(),
                            tls.private_key.as_deref(),
                        )
                    })
                    .transpose()?;
                let failover = if db.failover.is_empty() {
                    None
                } else {
                    let mut candidates = vec![pgproxy_wire::failover::BackendCandidate {
                        target: BackendTarget {
                            host: db.host.clone(),
                            port: db.port,
                            database: db.dbname.clone(),
                            user: db.user.clone(),
                        },
                        tls: tls.clone(),
                    }];
                    for endpoint in &db.failover {
                        let alternate_tls = endpoint
                            .backend_tls
                            .as_ref()
                            .map(|value| {
                                pgproxy_wire::backend_tls::BackendTls::from_pem_with_identity(
                                    &value.root_certificate,
                                    &value.server_name,
                                    value.require_channel_binding,
                                    value.client_certificate.as_deref(),
                                    value.private_key.as_deref(),
                                )
                            })
                            .transpose()?
                            .or_else(|| tls.clone());
                        candidates.push(pgproxy_wire::failover::BackendCandidate {
                            target: BackendTarget {
                                host: endpoint.host.clone(),
                                port: endpoint.port,
                                database: db.dbname.clone(),
                                user: db.user.clone(),
                            },
                            tls: alternate_tls,
                        });
                    }
                    Some(std::sync::Arc::new(
                        pgproxy_wire::failover::FailoverPlan::new(candidates)?,
                    ))
                };
                Ok((
                    db.name.clone(),
                    Route {
                        host: db.host.clone(),
                        port: db.port,
                        dbname: db.dbname.clone(),
                        pool_mode: db.pool_mode,
                        client_auth: db.client_auth,
                        auth_users: db.auth_users.clone(),
                        user: db.user.clone(),
                        password: db.password.clone(),
                        checkout_timeout_secs: db.checkout_timeout_secs,
                        connect_timeout_secs: db.connect_timeout_secs,
                        pool_size: db.pool_size,
                        require_primary: db.require_primary,
                        governance: db
                            .policy
                            .as_ref()
                            .map(|policy| policy.compile().map_err(std::io::Error::other))
                            .transpose()?,
                        tls,
                        failover,
                        credential_provider: db
                            .credential_provider
                            .as_ref()
                            .map(|provider| provider.provider())
                            .transpose()?,
                    },
                ))
            })
            .collect::<std::io::Result<HashMap<_, _>>>()?;

        Ok(Self {
            databases,
            default_database: None,
        })
    }

    /// Name to use when the client asks for nothing at all.
    ///
    /// Only meaningful for single-database deployments, where being strict would reject
    /// clients that rely on the PostgreSQL default.
    pub fn with_default_database(mut self, name: impl Into<String>) -> Self {
        self.default_database = Some(name.into());
        self
    }

    /// Names this router can serve, for diagnostics.
    pub fn database_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.databases.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }
}

impl DatabaseRouter for ConfigRouter {
    fn route(&self, params: &StartupParams) -> Result<ResolvedBackend, RouteError> {
        // PostgreSQL's own rule: an absent `database` means "the username". Reproducing
        // it matters for drop-in compatibility -- libpq omits `database` whenever the
        // caller did not set it, which is common in scripts and ORMs.
        let requested = params
            .get("database")
            .map(str::to_string)
            .or_else(|| params.get("user").map(str::to_string))
            .or_else(|| self.default_database.clone())
            .ok_or(RouteError::NoDatabase)?;

        let route = self
            .databases
            .get(&requested)
            .ok_or_else(|| RouteError::UnknownDatabase(requested.clone()))?;

        let client_user = params.get("user").unwrap_or("").to_string();
        // A configured user replaces the client's; otherwise the client's own role is
        // used, which yields one pool per (database, user) as PgBouncer does.
        let backend_user = route.user.clone().unwrap_or_else(|| client_user.clone());

        Ok(ResolvedBackend {
            target: BackendTarget {
                host: route.host.clone(),
                port: route.port,
                // The backend may know the database by a different name.
                database: Some(route.dbname.clone().unwrap_or_else(|| requested.clone())),
                // Session mode forwards the client's user, so per-user backend
                // authentication keeps working. Transaction mode uses the resolved user,
                // because the connection is not the one the client logged in on.
                user: match route.pool_mode {
                    ConfigPoolMode::Session => None,
                    ConfigPoolMode::Transaction => route.user.clone(),
                },
            },
            mode: match route.pool_mode {
                ConfigPoolMode::Session => PoolMode::Session,
                ConfigPoolMode::Transaction => PoolMode::Transaction,
            },
            credentials: Some(BackendCredentials {
                user: backend_user,
                password: route.password.clone(),
                database: Some(route.dbname.clone().unwrap_or_else(|| requested.clone())),
                application_name: Some("pgproxy".to_string()),
            }),
            client_auth: match route.client_auth {
                crate::config::ClientAuthMethod::Passthrough => {
                    pgproxy_wire::auth::client::ClientAuth::Passthrough
                }
                crate::config::ClientAuthMethod::Trust => {
                    pgproxy_wire::auth::client::ClientAuth::Trust
                }
                crate::config::ClientAuthMethod::Md5 => {
                    pgproxy_wire::auth::client::ClientAuth::Md5(route.auth_users.clone())
                }
                crate::config::ClientAuthMethod::Certificate => {
                    let fingerprints = route
                        .auth_users
                        .iter()
                        .map(|(user, value)| {
                            pgproxy_wire::tls::decode_fingerprint(value)
                                .map(|fingerprint| (user.clone(), fingerprint))
                                .ok_or_else(|| {
                                    RouteError::Internal(
                                        "invalid certificate authentication configuration".into(),
                                    )
                                })
                        })
                        .collect::<Result<HashMap<_, _>, _>>()?;
                    pgproxy_wire::auth::client::ClientAuth::Certificate(fingerprints)
                }
                crate::config::ClientAuthMethod::ScramSha256 => {
                    let users = route
                        .auth_users
                        .iter()
                        .map(|(user, secret)| {
                            pgproxy_wire::auth::scram::ScramVerifier::parse(secret)
                                .map(|verifier| (user.clone(), verifier))
                        })
                        .collect::<Result<HashMap<_, _>, _>>()
                        .map_err(|_| {
                            RouteError::Internal("invalid authentication configuration".into())
                        })?;
                    pgproxy_wire::auth::client::ClientAuth::Scram(users)
                }
            },
            pool: PoolSettings {
                max_size: route.pool_size,
                checkout_timeout: Duration::from_secs(route.checkout_timeout_secs),
                require_primary: route.require_primary || route.failover.is_some(),
            },
            connect_timeout: Duration::from_secs(route.connect_timeout_secs),
            tls: route.tls.clone(),
            failover: route.failover.clone(),
            credential_provider: route.credential_provider.clone(),
            governance: route.governance.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Database, PoolMode as ConfigPoolMode};
    use pgproxy_wire::protocol::{PROTOCOL_3_0, StartupRequest, parse_startup};

    fn database(name: &str, host: &str, port: u16, dbname: Option<&str>) -> Database {
        Database {
            name: name.to_string(),
            host: host.to_string(),
            port,
            dbname: dbname.map(str::to_string),
            pool_size: 10,
            pool_mode: ConfigPoolMode::Session,
            client_auth: crate::config::ClientAuthMethod::Passthrough,
            auth_users: Default::default(),
            user: None,
            password: None,
            checkout_timeout_secs: 5,
            connect_timeout_secs: 10,
            require_primary: false,
            backend_tls: None,
            policy: None,
            failover: Vec::new(),
            credential_provider: None,
        }
    }

    fn config() -> Config {
        let mut analytics = database("analytics", "10.0.0.2", 5433, None);
        analytics.pool_size = 5;
        Config {
            databases: vec![
                database("app", "10.0.0.1", 5432, Some("app_production")),
                analytics,
            ],
            ..Default::default()
        }
    }

    fn params(entries: &[(&str, &str)]) -> StartupParams {
        let mut body = PROTOCOL_3_0.to_be_bytes().to_vec();
        for (k, v) in entries {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }
        body.push(0);
        match parse_startup(&body).expect("valid startup") {
            StartupRequest::Startup(p) => p,
            other => panic!("expected Startup, got {other:?}"),
        }
    }

    #[test]
    fn routes_a_named_database_and_rewrites_its_name() {
        let router = ConfigRouter::new(&config());
        let resolved = router
            .route(&params(&[("user", "alice"), ("database", "app")]))
            .unwrap();

        assert_eq!(resolved.target.host, "10.0.0.1");
        assert_eq!(resolved.target.port, 5432);
        assert_eq!(resolved.target.database.as_deref(), Some("app_production"));
    }

    #[test]
    fn session_mode_forwards_the_clients_user_so_relayed_auth_still_works() {
        // The client authenticates to the backend through the proxy, so the backend must
        // see the client's own role.
        let router = ConfigRouter::new(&config());
        let resolved = router
            .route(&params(&[("user", "alice"), ("database", "app")]))
            .unwrap();

        assert_eq!(resolved.mode, PoolMode::Session);
        assert_eq!(
            resolved.target.user, None,
            "session mode must not override the user"
        );
        assert_eq!(resolved.credentials.as_ref().unwrap().user, "alice");
    }

    #[test]
    fn transaction_mode_uses_the_configured_user_for_the_backend() {
        let mut cfg = config();
        cfg.databases[0].pool_mode = ConfigPoolMode::Transaction;
        cfg.databases[0].user = Some("pool_role".to_string());
        cfg.databases[0].password = Some("secret".to_string());
        let router = ConfigRouter::new(&cfg);

        let resolved = router
            .route(&params(&[("user", "alice"), ("database", "app")]))
            .unwrap();

        assert_eq!(resolved.mode, PoolMode::Transaction);
        assert_eq!(resolved.target.user.as_deref(), Some("pool_role"));
        let credentials = resolved.credentials.unwrap();
        assert_eq!(credentials.user, "pool_role");
        assert_eq!(credentials.password.as_deref(), Some("secret"));
    }

    #[test]
    fn transaction_mode_without_a_configured_user_pools_per_client_role() {
        let mut cfg = config();
        cfg.databases[0].pool_mode = ConfigPoolMode::Transaction;
        let router = ConfigRouter::new(&cfg);

        let alice = router
            .route(&params(&[("user", "alice"), ("database", "app")]))
            .unwrap();
        let bob = router
            .route(&params(&[("user", "bob"), ("database", "app")]))
            .unwrap();

        assert_eq!(alice.credentials.as_ref().unwrap().user, "alice");
        assert_eq!(bob.credentials.as_ref().unwrap().user, "bob");
        assert_ne!(
            alice.pool_key(),
            bob.pool_key(),
            "different roles must never share a pooled backend connection"
        );
    }

    #[test]
    fn a_database_without_an_explicit_dbname_keeps_the_client_name() {
        let router = ConfigRouter::new(&config());
        let resolved = router
            .route(&params(&[("user", "alice"), ("database", "analytics")]))
            .unwrap();
        assert_eq!(resolved.target.database.as_deref(), Some("analytics"));
        assert_eq!(resolved.pool.max_size, 5);
    }

    #[test]
    fn an_absent_database_falls_back_to_the_username() {
        // PostgreSQL's rule. libpq omits `database` whenever the caller did not set it,
        // so rejecting this would break drop-in use.
        let mut cfg = config();
        cfg.databases[0].name = "alice".to_string();
        let router = ConfigRouter::new(&cfg);

        let resolved = router.route(&params(&[("user", "alice")])).unwrap();
        assert_eq!(resolved.target.database.as_deref(), Some("app_production"));
    }

    #[test]
    fn an_unknown_database_is_refused_by_name() {
        let router = ConfigRouter::new(&config());
        let err = router
            .route(&params(&[("user", "alice"), ("database", "nope")]))
            .unwrap_err();
        match err {
            RouteError::UnknownDatabase(name) => assert_eq!(name, "nope"),
            other => panic!("expected UnknownDatabase, got {other:?}"),
        }
    }

    #[test]
    fn a_startup_with_no_database_and_no_user_is_refused() {
        let router = ConfigRouter::new(&config());
        let err = router.route(&params(&[])).unwrap_err();
        assert!(matches!(err, RouteError::NoDatabase));
    }

    #[test]
    fn a_default_database_can_be_configured() {
        let router = ConfigRouter::new(&config()).with_default_database("app");
        let resolved = router.route(&params(&[])).unwrap();
        assert_eq!(resolved.target.database.as_deref(), Some("app_production"));
    }

    #[test]
    fn the_explicit_database_beats_the_default() {
        let router = ConfigRouter::new(&config()).with_default_database("app");
        let resolved = router
            .route(&params(&[("user", "x"), ("database", "analytics")]))
            .unwrap();
        assert_eq!(resolved.target.database.as_deref(), Some("analytics"));
    }

    #[test]
    fn database_names_are_listed_for_diagnostics() {
        let router = ConfigRouter::new(&config());
        assert_eq!(router.database_names(), vec!["analytics", "app"]);
    }
}
