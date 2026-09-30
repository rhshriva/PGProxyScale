//! Validated service generations and conservative planned endpoint changes.
//!
//! Reload affects new connections. Existing clients keep their original routing,
//! policy, pools and TLS generation. Planned changes quiesce new admissions and
//! wait for whole client sessions, not only transactions; they never replay work.
use crate::{Config, ConfigRouter};
use pgproxy_admin::Operations;
use pgproxy_wire::{Connection, Service, SessionOptions, SessionService};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Running,
    Draining,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct Snapshot {
    pub generation: u64,
    pub active_sessions: usize,
    pub backend_connections: usize,
    pub backend_capacity: usize,
    pub phase: Phase,
    pub databases: Vec<String>,
}
struct Generation {
    id: u64,
    config: Config,
    service: Arc<SessionService>,
    databases: Vec<String>,
}
struct State {
    current: Arc<Generation>,
    retired: Vec<Weak<Generation>>,
    active: usize,
    phase: Phase,
    control_epoch: u64,
}
struct Shared {
    state: Mutex<State>,
    drained: Condvar,
}
/// One validated SessionService per generation, with a shared operations registry.
/// Every replacement loads certificates and compiles policy before taking the
/// admission lock; a failure leaves the current service untouched.
pub struct ManagedService {
    shared: Arc<Shared>,
    operations: Arc<Operations>,
    login_gate: Arc<AtomicBool>,
    backend_capacity: Arc<pgproxy_pool::ConnectionLimit>,
}
struct Lease {
    shared: Arc<Shared>,
    generation: Arc<Generation>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock().unwrap();
        state.active -= 1;
        if state.active == 0 {
            self.shared.drained.notify_all();
        }
    }
}
impl ManagedService {
    pub fn new(config: &Config, operations: Arc<Operations>) -> io::Result<Self> {
        let login_gate = Arc::new(AtomicBool::new(true));
        let backend_capacity =
            pgproxy_pool::ConnectionLimit::new(config.general.max_backend_connections);
        let generation = build(
            config,
            Arc::clone(&operations),
            Arc::clone(&backend_capacity),
            Arc::clone(&login_gate),
            None,
            1,
        )?;
        Ok(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    current: Arc::new(generation),
                    retired: Vec::new(),
                    active: 0,
                    phase: Phase::Running,
                    control_epoch: 0,
                }),
                drained: Condvar::new(),
            }),
            operations,
            login_gate,
            backend_capacity,
        })
    }
    #[cfg(test)]
    fn enter(&self) -> io::Result<Lease> {
        let mut state = self.shared.state.lock().unwrap();
        if state.phase != Phase::Running {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "planned switchover is draining; new connections are paused",
            ));
        }
        state.active += 1;
        Ok(Lease {
            shared: Arc::clone(&self.shared),
            generation: Arc::clone(&state.current),
        })
    }
    pub fn backend_capacity(&self) -> Arc<pgproxy_pool::ConnectionLimit> {
        Arc::clone(&self.backend_capacity)
    }
    pub fn snapshot(&self) -> Snapshot {
        let state = self.shared.state.lock().unwrap();
        Snapshot {
            generation: state.current.id,
            active_sessions: state.active,
            backend_connections: self.backend_capacity.used(),
            backend_capacity: self.backend_capacity.capacity(),
            phase: state.phase,
            databases: state.current.databases.clone(),
        }
    }
    /// Rotate routes, policy, certificates and session limits for future clients.
    pub fn reload(&self, config: &Config) -> io::Result<u64> {
        let (staged, epoch) = self.stage(config)?;
        let mut state = self.shared.state.lock().unwrap();
        ensure_epoch(&state, epoch)?;
        if state.phase != Phase::Running {
            return Err(io::Error::other(
                "cannot reload while switchover is draining",
            ));
        }
        replace(&mut state, staged)
    }
    fn stage(&self, config: &Config) -> io::Result<(Generation, u64)> {
        let (current, epoch) = {
            let state = self.shared.state.lock().unwrap();
            (Arc::clone(&state.current), state.control_epoch)
        };
        check_runtime_settings(&current.config, config)?;
        let generation = build(
            config,
            Arc::clone(&self.operations),
            Arc::clone(&self.backend_capacity),
            Arc::clone(&self.login_gate),
            Some(&current.service),
            0,
        )?;
        Ok((generation, epoch))
    }
    /// Stop admitting new sessions. Already admitted sessions finish normally.
    pub fn prepare_switchover(&self) -> io::Result<()> {
        let mut state = self.shared.state.lock().unwrap();
        if state.phase != Phase::Running {
            return Err(io::Error::other("switchover is already prepared"));
        }
        state.control_epoch = next_epoch(&state)?;
        state.phase = Phase::Draining;
        self.login_gate.store(false, Ordering::Release);
        self.operations.set_paused(true);
        Ok(())
    }
    /// Bounded wait for all client sessions. A timeout leaves admission paused;
    /// the operator can wait again or explicitly abort. No session is killed.
    pub fn wait_drained(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.shared.state.lock().unwrap();
        if state.phase != Phase::Draining {
            return false;
        }
        let epoch = state.control_epoch;
        while state.active != 0 {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (next, _) = self
                .shared
                .drained
                .wait_timeout(state, deadline - now)
                .unwrap();
            state = next;
            if state.phase != Phase::Draining || state.control_epoch != epoch {
                return false;
            }
        }
        true
    }
    /// Install a validated endpoint configuration only after every old session
    /// has drained. External promotion and writable-primary verification remain
    /// operator responsibilities; this API does not promote a PostgreSQL server.
    pub fn commit_if_idle(&self, config: &Config) -> io::Result<u64> {
        let (staged, epoch) = self.stage(config)?;
        self.commit_staged(staged, epoch)
    }
    fn commit_staged(&self, staged: Generation, epoch: u64) -> io::Result<u64> {
        let mut state = self.shared.state.lock().unwrap();
        ensure_epoch(&state, epoch)?;
        if state.phase != Phase::Draining {
            return Err(io::Error::other("prepare switchover before commit"));
        }
        if state.active != 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "active sessions have not drained",
            ));
        }
        let id = replace(&mut state, staged)?;
        state.phase = Phase::Running;
        self.login_gate.store(true, Ordering::Release);
        self.operations.set_paused(false);
        self.shared.drained.notify_all();
        Ok(id)
    }
    /// Resume the original generation, retaining all existing sessions.
    pub fn abort_switchover(&self) -> io::Result<()> {
        let mut state = self.shared.state.lock().unwrap();
        if state.phase != Phase::Draining {
            return Err(io::Error::other("no switchover is prepared"));
        }
        state.control_epoch = next_epoch(&state)?;
        state.phase = Phase::Running;
        self.login_gate.store(true, Ordering::Release);
        self.operations.set_paused(false);
        self.shared.drained.notify_all();
        Ok(())
    }
    /// Includes old service generations while clients still own them. No secrets
    /// from configuration or SQL text are returned by this diagnostic method.
    pub fn pool_stats(&self) -> Vec<(String, pgproxy_pool::PoolStats)> {
        let generations = {
            let mut state = self.shared.state.lock().unwrap();
            state
                .retired
                .retain(|generation| generation.strong_count() != 0);
            let mut generations = vec![Arc::clone(&state.current)];
            generations.extend(state.retired.iter().filter_map(Weak::upgrade));
            generations
        };
        let mut pools = Vec::new();
        for generation in generations {
            pools.extend(
                generation
                    .service
                    .pool_stats()
                    .into_iter()
                    .map(|(key, stats)| (format!("generation={} {key}", generation.id), stats)),
            );
        }
        pools.sort_by(|a, b| a.0.cmp(&b.0));
        pools
    }
}
impl Service for ManagedService {
    fn handle(&self, connection: Connection) -> io::Result<()> {
        // Protocol-level admission rejects new logins but still decodes cancellation
        // requests during a drain. Count the entire brief control connection too.
        let lease = {
            let mut state = self.shared.state.lock().unwrap();
            state.active += 1;
            Lease {
                shared: Arc::clone(&self.shared),
                generation: Arc::clone(&state.current),
            }
        };
        lease.generation.service.handle(connection)
    }
}
fn next_epoch(state: &State) -> io::Result<u64> {
    state
        .control_epoch
        .checked_add(1)
        .ok_or_else(|| io::Error::other("control epoch exhausted"))
}
fn ensure_epoch(state: &State, epoch: u64) -> io::Result<()> {
    if state.control_epoch == epoch {
        Ok(())
    } else {
        Err(io::Error::other(
            "service changed while replacement was being validated; retry the operation",
        ))
    }
}
fn replace(state: &mut State, mut staged: Generation) -> io::Result<u64> {
    let id = state
        .current
        .id
        .checked_add(1)
        .ok_or_else(|| io::Error::other("service generation exhausted"))?;
    let epoch = next_epoch(state)?;
    staged.id = id;
    state.control_epoch = epoch;
    let old = std::mem::replace(&mut state.current, Arc::new(staged));
    state.retired.push(Arc::downgrade(&old));
    state
        .retired
        .retain(|generation| generation.strong_count() != 0);
    Ok(id)
}
fn build(
    config: &Config,
    operations: Arc<Operations>,
    backend_capacity: Arc<pgproxy_pool::ConnectionLimit>,
    login_gate: Arc<AtomicBool>,
    previous: Option<&SessionService>,
    id: u64,
) -> io::Result<Generation> {
    config.validate().map_err(io::Error::other)?;
    let router = ConfigRouter::try_new(config)?;
    let databases = router
        .database_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let limits = &config.general.session;
    let options = SessionOptions {
        virtualize_hold_cursors: limits.virtualize_hold_cursors,
        cost_attribution: limits.cost_attribution,
        connect_timeout: Duration::from_secs(limits.startup_timeout_secs),
        max_message_len: limits.max_message_bytes,
        session_memory_bytes: limits.memory_bytes,
        max_sql_bytes: limits.max_sql_bytes,
        idle_in_transaction: Duration::from_secs(limits.idle_in_transaction_secs),
        query_timeout: Duration::from_secs(limits.query_timeout_secs),
        client_write_timeout: Duration::from_secs(limits.client_write_timeout_secs),
        operations,
        backend_capacity,
    };
    let mut service =
        SessionService::with_options(Arc::new(router), options).with_login_gate(login_gate);
    if let Some(previous) = previous {
        service = service.with_cancellation_from(previous);
    }
    if let Some(tls) = &config.general.tls {
        service = service.with_frontend_tls(pgproxy_wire::tls::FrontendTls::from_pem_with_ca(
            &tls.certificate,
            &tls.private_key,
            tls.required,
            tls.client_ca.as_deref(),
        )?);
    }
    Ok(Generation {
        id,
        config: config.clone(),
        service: Arc::new(service),
        databases,
    })
}
fn check_runtime_settings(old: &Config, new: &Config) -> io::Result<()> {
    let a = &old.general;
    let b = &new.general;
    if a.listen_addr != b.listen_addr
        || a.listen_port != b.listen_port
        || a.workers != b.workers
        || a.max_backend_connections != b.max_backend_connections
        || a.max_client_connections != b.max_client_connections
        || a.connection_rate_per_second != b.connection_rate_per_second
        || a.shutdown_timeout_secs != b.shutdown_timeout_secs
        || a.admin_users != b.admin_users
        || format!("{:?}", old.operations) != format!("{:?}", new.operations)
        || format!("{:?}", old.logging) != format!("{:?}", new.logging)
    {
        return Err(io::Error::other(
            "listener, workers, process admission, shutdown, operations and logging changes require restart",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(host: &str) -> Config {
        toml::from_str(&format!("[[databases]]\nname='app'\nhost='{host}'\npool_mode='transaction'\nclient_auth='trust'\n")).unwrap()
    }
    fn manager() -> ManagedService {
        ManagedService::new(&config("127.0.0.1"), Arc::default()).unwrap()
    }
    #[test]
    fn invalid_reload_and_changed_runtime_settings_leave_generation_unchanged() {
        let m = manager();
        let mut invalid = config("127.0.0.2");
        invalid.databases.clear();
        assert!(m.reload(&invalid).is_err());
        let mut restart = config("127.0.0.2");
        restart.general.listen_port += 1;
        assert!(m.reload(&restart).is_err());
        assert_eq!(m.snapshot().generation, 1);
        assert_eq!(m.snapshot().phase, Phase::Running);
    }
    #[test]
    fn old_clients_keep_original_generation_on_atomic_reload() {
        let m = manager();
        let client = m.enter().unwrap();
        assert_eq!(m.reload(&config("127.0.0.2")).unwrap(), 2);
        assert_eq!(client.generation.config.databases[0].host, "127.0.0.1");
        assert_eq!(
            m.enter().unwrap().generation.config.databases[0].host,
            "127.0.0.2"
        );
        assert_eq!(m.snapshot().active_sessions, 1);
        drop(client);
        assert_eq!(m.snapshot().active_sessions, 0);
    }
    #[test]
    fn planned_change_waits_for_sessions_and_never_forces_replay() {
        let m = manager();
        let client = m.enter().unwrap();
        m.prepare_switchover().unwrap();
        assert!(m.enter().is_err());
        assert!(!m.wait_drained(Duration::from_millis(1)));
        assert!(m.commit_if_idle(&config("127.0.0.2")).is_err());
        drop(client);
        assert!(m.wait_drained(Duration::from_millis(1)));
        assert_eq!(m.commit_if_idle(&config("127.0.0.2")).unwrap(), 2);
        assert!(m.enter().is_ok());
    }
    #[test]
    fn abort_preserves_generation_and_resumes_admission() {
        let m = manager();
        m.prepare_switchover().unwrap();
        m.abort_switchover().unwrap();
        assert_eq!(m.snapshot().generation, 1);
        assert!(m.enter().is_ok());
        assert!(m.abort_switchover().is_err());
        assert!(m.commit_if_idle(&config("127.0.0.2")).is_err());
    }
    #[test]
    fn missing_tls_material_fails_before_generation_replacement() {
        let m = manager();
        let mut next = config("127.0.0.2");
        next.general.tls = Some(crate::config::FrontendTlsConfig {
            certificate: "/no-such-certificate".into(),
            private_key: "/no-such-key".into(),
            required: true,
            client_ca: None,
        });
        assert!(m.reload(&next).is_err());
        assert_eq!(m.snapshot().generation, 1);
    }
    #[test]
    fn wait_is_woken_by_last_client_drop() {
        let m = Arc::new(manager());
        let client = m.enter().unwrap();
        m.prepare_switchover().unwrap();
        let waiting = Arc::clone(&m);
        let task = std::thread::spawn(move || waiting.wait_drained(Duration::from_secs(1)));
        drop(client);
        assert!(task.join().unwrap());
    }
    #[test]
    fn stale_staged_configuration_cannot_commit_after_abort_and_reprepare() {
        let m = manager();
        m.prepare_switchover().unwrap();
        let (staged, epoch) = m.stage(&config("127.0.0.2")).unwrap();
        m.abort_switchover().unwrap();
        m.prepare_switchover().unwrap();
        assert!(m.commit_staged(staged, epoch).is_err());
        assert_eq!(m.snapshot().generation, 1);
        assert_eq!(m.snapshot().phase, Phase::Draining);
    }
    #[test]
    fn every_reload_generation_shares_the_physical_backend_budget() {
        let m = manager();
        let budget = m.backend_capacity();
        let permit = budget.acquire(Duration::ZERO).unwrap();
        m.reload(&config("127.0.0.2")).unwrap();
        assert!(Arc::ptr_eq(&budget, &m.backend_capacity()));
        assert_eq!(m.backend_capacity().used(), 1);
        let mut resized = config("127.0.0.2");
        resized.general.max_backend_connections += 1;
        assert!(m.reload(&resized).is_err());
        drop(permit);
        assert_eq!(m.backend_capacity().used(), 0);
    }
}
