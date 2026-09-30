//! Backend acquisition failover. This never sends or retries user SQL and never promotes a server.
use crate::{
    BackendConnection, BackendCredentials, BackendTarget, backend_tls::BackendTls,
    credentials::CredentialProvider,
};
use sha2::{Digest, Sha256};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct BackendCandidate {
    pub target: BackendTarget,
    pub tls: Option<BackendTls>,
}
#[derive(Debug)]
struct Selection {
    preferred: usize,
    generation: u64,
}
#[derive(Debug)]
pub struct FailoverPlan {
    candidates: Vec<BackendCandidate>,
    selection: Arc<Mutex<Selection>>,
    epoch: Arc<AtomicU64>,
    identity: String,
}
impl FailoverPlan {
    pub fn new(candidates: Vec<BackendCandidate>) -> io::Result<Self> {
        if candidates.is_empty() || candidates.len() > 8 {
            return Err(io::Error::other("failover requires one to eight endpoints"));
        }
        let mut identity = Sha256::new();
        for candidate in &candidates {
            for value in [
                candidate.target.host.as_str(),
                candidate
                    .tls
                    .as_ref()
                    .map_or("plaintext", |tls| tls.pool_identity()),
            ] {
                identity.update((value.len() as u64).to_be_bytes());
                identity.update(value.as_bytes());
            }
            identity.update(candidate.target.port.to_be_bytes());
        }
        Ok(Self {
            candidates,
            selection: Arc::new(Mutex::new(Selection {
                preferred: 0,
                generation: 1,
            })),
            epoch: Arc::new(AtomicU64::new(1)),
            identity: format!("{:x}", identity.finalize()),
        })
    }
    pub fn pool_identity(&self) -> &str {
        &self.identity
    }
    pub fn generation(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }
    pub fn active_index(&self) -> usize {
        self.selection.lock().map_or(0, |value| value.preferred)
    }
    /// Resolve endpoint-specific credentials and establish a writable-primary connection
    /// within the acquisition budget. Database failover/fencing is an external responsibility.
    pub fn connect(
        &self,
        credentials: &BackendCredentials,
        timeout: Duration,
        max_message_len: usize,
        provider: Option<&dyn CredentialProvider>,
    ) -> io::Result<BackendConnection> {
        let deadline = Instant::now() + timeout;
        // A concurrent route change may require one restart against the new preferred
        // endpoint. This bounded retry is still before any user SQL has been sent.
        for _ in 0..2 {
            let (preferred, generation) = {
                let selection = self
                    .selection
                    .lock()
                    .map_err(|_| io::Error::other("failover selection poisoned"))?;
                (selection.preferred, selection.generation)
            };
            let mut changed = false;
            for offset in 0..self.candidates.len() {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "backend failover acquisition deadline",
                    ));
                };
                let index = (preferred + offset) % self.candidates.len();
                let candidate = &self.candidates[index];
                let slice = remaining / (self.candidates.len() - offset) as u32;
                let attempt_deadline = Instant::now() + slice;
                let outcome = (|| {
                    let lease = provider
                        .map(|provider| {
                            provider.resolve(&candidate.target, credentials, attempt_deadline)
                        })
                        .transpose()?;
                    let resolved = lease
                        .as_ref()
                        .map_or(credentials, |lease| &lease.credentials);
                    let budget = attempt_deadline
                        .checked_duration_since(Instant::now())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "credential acquisition deadline",
                            )
                        })?;
                    let mut connection = BackendConnection::connect_with_tls(
                        &candidate.target,
                        resolved,
                        budget,
                        max_message_len,
                        candidate.tls.as_ref(),
                    )?
                    .with_credential_expiry(lease.and_then(|lease| lease.expires_at));
                    connection.require_primary(true);
                    connection.verify_primary_with_deadline(attempt_deadline)?;
                    Ok::<_, io::Error>(connection)
                })();
                let mut connection = match outcome {
                    Ok(connection) => connection,
                    Err(error) => {
                        tracing::debug!(index,error_kind=?error.kind(),"backend failover candidate unavailable");
                        continue;
                    }
                };
                let mut selection = self
                    .selection
                    .lock()
                    .map_err(|_| io::Error::other("failover selection poisoned"))?;
                if selection.generation != generation && selection.preferred != index {
                    changed = true;
                    break;
                }
                if selection.preferred != index {
                    selection.generation = selection
                        .generation
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("failover generation exhausted"))?;
                    selection.preferred = index;
                    self.epoch.store(selection.generation, Ordering::Release);
                    tracing::warn!(
                        index,
                        generation = selection.generation,
                        "backend route changed to verified writable endpoint"
                    );
                }
                let selection_owner = Arc::clone(&self.selection);
                let epoch_owner = Arc::clone(&self.epoch);
                connection = connection
                    .with_failover_generation(Arc::clone(&self.epoch), selection.generation)
                    .with_failover_invalidation(Arc::new(move |observed| {
                        let Ok(mut selected) = selection_owner.lock() else {
                            return false;
                        };
                        if selected.generation != observed {
                            return false;
                        }
                        let Some(next) = selected.generation.checked_add(1) else {
                            epoch_owner.store(0, Ordering::Release);
                            return false;
                        };
                        selected.generation = next;
                        epoch_owner.store(next, Ordering::Release);
                        true
                    }));
                return Ok(connection);
            }
            if !changed {
                break;
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "no verified writable failover backend is available",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };
    fn mock(writable: bool) -> (BackendCandidate, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut length = [0; 4];
            socket.read_exact(&mut length).unwrap();
            let mut startup = vec![0; u32::from_be_bytes(length) as usize - 4];
            socket.read_exact(&mut startup).unwrap();
            // AuthenticationOk, BackendKeyData, ReadyForQuery.
            socket
                .write_all(b"R\0\0\0\x08\0\0\0\0K\0\0\0\x0c\0\0\0\x07\0\0\0\x09Z\0\0\0\x05I")
                .unwrap();
            let mut header = [0; 5];
            socket.read_exact(&mut header).unwrap();
            assert_eq!(header[0], b'Q');
            let mut sql = vec![0; u32::from_be_bytes(header[1..].try_into().unwrap()) as usize - 4];
            socket.read_exact(&mut sql).unwrap();
            assert!(
                std::str::from_utf8(&sql)
                    .unwrap()
                    .starts_with("SELECT NOT pg_catalog.pg_is_in_recovery()")
            );
            let mut row = b"D\0\0\0\x0b\0\x01\0\0\0\x01tZ\0\0\0\x05I".to_vec();
            row[11] = if writable { b't' } else { b'f' };
            socket.write_all(&row).unwrap();
            // No test ever authorizes user SQL or retries it.
            let mut byte = [0];
            match socket.read(&mut byte) {
                Ok(0) | Err(_) => {}
                Ok(_) => panic!("unexpected user SQL"),
            }
        });
        (
            BackendCandidate {
                target: BackendTarget {
                    host: "127.0.0.1".into(),
                    port,
                    database: Some("test".into()),
                    user: Some("test".into()),
                },
                tls: None,
            },
            task,
        )
    }
    fn credentials() -> BackendCredentials {
        BackendCredentials {
            user: "test".into(),
            password: None,
            database: Some("test".into()),
            application_name: None,
        }
    }
    #[test]
    fn skips_read_only_endpoint_and_records_actual_cancel_owner() {
        let (read_only, first) = mock(false);
        let (primary, second) = mock(true);
        let primary_port = primary.target.port;
        let plan = FailoverPlan::new(vec![read_only, primary]).unwrap();
        let connection = plan
            .connect(&credentials(), Duration::from_secs(3), 1024, None)
            .unwrap();
        assert_eq!(plan.active_index(), 1);
        assert_eq!(plan.generation(), 2);
        assert_eq!(connection.backend_address().port(), primary_port);
        assert!(connection.generation_is_current());
        assert!(connection.invalidate_generation_if_current());
        assert_eq!(plan.generation(), 3);
        assert!(!connection.generation_is_current());
        assert!(!connection.invalidate_generation_if_current());
        drop(connection);
        first.join().unwrap();
        second.join().unwrap();
    }
    #[test]
    fn provider_is_resolved_for_each_physical_endpoint() {
        #[derive(Debug)]
        struct Provider(Mutex<Vec<u16>>);
        impl CredentialProvider for Provider {
            fn resolve(
                &self,
                target: &BackendTarget,
                seed: &BackendCredentials,
                _: Instant,
            ) -> io::Result<crate::credentials::CredentialLease> {
                self.0.lock().unwrap().push(target.port);
                Ok(crate::credentials::CredentialLease {
                    credentials: seed.clone(),
                    expires_at: Some(Instant::now() + Duration::from_secs(30)),
                })
            }
            fn pool_identity(&self) -> String {
                "mock".into()
            }
        }
        let (read_only, first) = mock(false);
        let (primary, second) = mock(true);
        let expected = vec![read_only.target.port, primary.target.port];
        let plan = FailoverPlan::new(vec![read_only, primary]).unwrap();
        let provider = Provider(Mutex::new(Vec::new()));
        let connection = plan
            .connect(
                &credentials(),
                Duration::from_secs(3),
                1024,
                Some(&provider),
            )
            .unwrap();
        assert_eq!(*provider.0.lock().unwrap(), expected);
        drop(connection);
        first.join().unwrap();
        second.join().unwrap();
    }

    #[test]
    fn rejects_empty_and_oversized_candidates() {
        assert!(FailoverPlan::new(vec![]).is_err());
        let target = BackendCandidate {
            target: BackendTarget {
                host: "127.0.0.1".into(),
                port: 1,
                database: None,
                user: None,
            },
            tls: None,
        };
        assert!(FailoverPlan::new(vec![target; 9]).is_err());
    }
}
