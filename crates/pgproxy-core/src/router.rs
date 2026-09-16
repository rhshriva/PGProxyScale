//! Routing a client's startup request to a configured backend.
//!
//! This lives in `pgproxy-core` rather than `pgproxy-wire` because it is the one place
//! that needs both: the protocol's view of a startup packet, and the proxy's
//! configuration. `pgproxy-wire` defines the [`DatabaseRouter`] trait and stays ignorant
//! of configuration; this implements it.

use std::collections::HashMap;

use pgproxy_wire::StartupParams;
use pgproxy_wire::{BackendTarget, DatabaseRouter, RouteError};

use crate::config::Config;

/// Resolves database names from configuration.
#[derive(Debug, Clone)]
pub struct ConfigRouter {
    databases: HashMap<String, Route>,
    /// Used when a client names no database and no user-derived name matches.
    default_database: Option<String>,
}

#[derive(Debug, Clone)]
struct Route {
    host: String,
    port: u16,
    dbname: Option<String>,
}

impl ConfigRouter {
    /// Build a router from a validated configuration.
    pub fn new(config: &Config) -> Self {
        let databases = config
            .databases
            .iter()
            .map(|db| {
                (
                    db.name.clone(),
                    Route {
                        host: db.host.clone(),
                        port: db.port,
                        dbname: db.dbname.clone(),
                    },
                )
            })
            .collect();

        Self {
            databases,
            default_database: None,
        }
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
    fn route(&self, params: &StartupParams) -> Result<BackendTarget, RouteError> {
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

        Ok(BackendTarget {
            host: route.host.clone(),
            port: route.port,
            // The backend may know the database by a different name.
            database: Some(route.dbname.clone().unwrap_or_else(|| requested.clone())),
            // Deliberately not overridden: forwarding the client's user is what makes
            // per-user authentication and per-user pools possible.
            user: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Database};
    use pgproxy_wire::protocol::{PROTOCOL_3_0, StartupRequest, parse_startup};

    fn config() -> Config {
        Config {
            databases: vec![
                Database {
                    name: "app".to_string(),
                    host: "10.0.0.1".to_string(),
                    port: 5432,
                    dbname: Some("app_production".to_string()),
                    pool_size: 10,
                },
                Database {
                    name: "analytics".to_string(),
                    host: "10.0.0.2".to_string(),
                    port: 5433,
                    dbname: None,
                    pool_size: 5,
                },
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
        let target = router
            .route(&params(&[("user", "alice"), ("database", "app")]))
            .unwrap();

        assert_eq!(target.host, "10.0.0.1");
        assert_eq!(target.port, 5432);
        assert_eq!(target.database.as_deref(), Some("app_production"));
        assert_eq!(target.user, None, "the client's user must be forwarded");
    }

    #[test]
    fn a_database_without_an_explicit_dbname_keeps_the_client_name() {
        let router = ConfigRouter::new(&config());
        let target = router
            .route(&params(&[("user", "alice"), ("database", "analytics")]))
            .unwrap();
        assert_eq!(target.database.as_deref(), Some("analytics"));
    }

    #[test]
    fn an_absent_database_falls_back_to_the_username() {
        // PostgreSQL's rule. libpq omits `database` whenever the caller did not set it,
        // so rejecting this would break drop-in use.
        let mut cfg = config();
        cfg.databases[0].name = "alice".to_string();
        let router = ConfigRouter::new(&cfg);

        let target = router.route(&params(&[("user", "alice")])).unwrap();
        assert_eq!(target.database.as_deref(), Some("app_production"));
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
        let target = router.route(&params(&[])).unwrap();
        assert_eq!(target.database.as_deref(), Some("app_production"));
    }

    #[test]
    fn the_explicit_database_beats_the_default() {
        let router = ConfigRouter::new(&config()).with_default_database("app");
        let target = router
            .route(&params(&[("user", "x"), ("database", "analytics")]))
            .unwrap();
        assert_eq!(target.database.as_deref(), Some("analytics"));
    }

    #[test]
    fn database_names_are_listed_for_diagnostics() {
        let router = ConfigRouter::new(&config());
        assert_eq!(router.database_names(), vec!["analytics", "app"]);
    }
}
