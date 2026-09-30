//! Cancellation keys belong to client sessions; backend ownership is temporary.
use crate::{CancelRequest, auth::ct_eq, protocol::CANCEL_REQUEST_CODE};
use rand::{RngCore, rngs::OsRng};
use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicI32, Ordering},
    },
    time::Duration,
};

#[derive(Clone)]
struct Target {
    address: SocketAddr,
    tls: Option<crate::backend_tls::BackendTls>,
    process_id: i32,
    key: Vec<u8>,
}
struct Entry {
    key: Vec<u8>,
    target: Option<Target>,
    uncertain: bool,
}
/// Shared by every worker: cancellation may arrive on a different listener.
#[derive(Default)]
pub struct CancelRegistry {
    entries: Mutex<HashMap<i32, Arc<Mutex<Entry>>>>,
    next: AtomicI32,
}
/// Owns the public key for the lifetime of one client.
pub struct CancelSession {
    registry: Arc<CancelRegistry>,
    pub process_id: i32,
    pub key: Vec<u8>,
    entry: Arc<Mutex<Entry>>,
}
/// Removing a binding synchronises with any cancel already being dispatched.
pub struct CancelBinding {
    entry: Arc<Mutex<Entry>>,
    active: bool,
}
impl CancelRegistry {
    pub fn session(self: &Arc<Self>) -> io::Result<CancelSession> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| io::Error::other("cancel registry poisoned"))?;
        let process_id = loop {
            let id = self.next.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            if id > 0 && !entries.contains_key(&id) {
                break id;
            }
            if id <= 0 {
                self.next.store(0, Ordering::Relaxed);
            }
        };
        let mut key = vec![0; 4];
        OsRng.fill_bytes(&mut key);
        let entry = Arc::new(Mutex::new(Entry {
            key: key.clone(),
            target: None,
            uncertain: false,
        }));
        entries.insert(process_id, Arc::clone(&entry));
        Ok(CancelSession {
            registry: Arc::clone(self),
            process_id,
            key,
            entry,
        })
    }
    /// Hold ownership until PostgreSQL closes the cancellation connection. Reset/checkin
    /// cannot overlap this exchange. Unknown/stale keys have PostgreSQL's silent behavior.
    pub fn dispatch(&self, request: &CancelRequest, timeout: Duration) -> io::Result<()> {
        // Registry lookup never holds the global lock during network I/O.
        let entry = self
            .entries
            .lock()
            .map_err(|_| io::Error::other("cancel registry poisoned"))?
            .get(&request.process_id)
            .cloned();
        let Some(entry) = entry else {
            return Ok(());
        };
        let mut entry = entry
            .lock()
            .map_err(|_| io::Error::other("cancel ownership poisoned"))?;
        if !ct_eq(&entry.key, &request.key) {
            return Ok(());
        }
        let Some(target) = &entry.target else {
            return Ok(());
        };
        let outcome = (|| {
            let mut stream = TcpStream::connect_timeout(&target.address, timeout)?;
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;
            let bridge = target
                .tls
                .as_ref()
                .map(|tls| tls.connect(stream.try_clone()?, timeout))
                .transpose()?;
            if let Some(bridge) = &bridge {
                stream = bridge.stream.try_clone()?;
            }
            let length = 12 + target.key.len();
            let mut packet = Vec::with_capacity(length);
            packet.extend_from_slice(&(length as i32).to_be_bytes());
            packet.extend_from_slice(&CANCEL_REQUEST_CODE.to_be_bytes());
            packet.extend_from_slice(&target.process_id.to_be_bytes());
            packet.extend_from_slice(&target.key);
            stream.write_all(&packet)?;
            let mut response = [0; 1];
            if stream.read(&mut response)? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected cancellation response",
                ));
            }
            Ok(())
        })();
        if outcome.is_err() {
            entry.uncertain = true;
        }
        outcome
    }
}
impl CancelSession {
    pub fn bind(
        &self,
        address: SocketAddr,
        process_id: i32,
        key: &[u8],
    ) -> io::Result<CancelBinding> {
        self.bind_with_tls(address, process_id, key, None)
    }
    pub fn bind_with_tls(
        &self,
        address: SocketAddr,
        process_id: i32,
        key: &[u8],
        tls: Option<crate::backend_tls::BackendTls>,
    ) -> io::Result<CancelBinding> {
        let mut entry = self
            .entry
            .lock()
            .map_err(|_| io::Error::other("cancel ownership poisoned"))?;
        if entry.target.is_some() {
            return Err(io::Error::other("cancel session already owns a backend"));
        }
        entry.uncertain = false;
        entry.target = Some(Target {
            address,
            tls,
            process_id,
            key: key.to_vec(),
        });
        Ok(CancelBinding {
            entry: Arc::clone(&self.entry),
            active: true,
        })
    }
}
impl CancelBinding {
    /// Revoke ownership atomically, waiting for active dispatch. A timed-out dispatch
    /// leaves cancellation delivery uncertain; its backend must be discarded.
    pub fn finish(mut self) -> io::Result<bool> {
        let mut entry = self
            .entry
            .lock()
            .map_err(|_| io::Error::other("cancel ownership poisoned"))?;
        entry.target = None;
        self.active = false;
        Ok(!entry.uncertain)
    }
}
impl Drop for CancelBinding {
    fn drop(&mut self) {
        if self.active
            && let Ok(mut entry) = self.entry.lock()
        {
            entry.target = None;
        }
    }
}
impl Drop for CancelSession {
    fn drop(&mut self) {
        // Invalidate a lookup cloned before removal, synchronising with dispatch.
        if let Ok(mut entry) = self.entry.lock() {
            entry.target = None;
        }
        if let Ok(mut entries) = self.registry.entries.lock() {
            entries.remove(&self.process_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread};
    #[test]
    fn authenticated_cancel_rewrites_variable_length_backend_key_and_cleanup_revokes_it() {
        let registry = Arc::new(CancelRegistry::default());
        let session = registry.session().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let key = vec![7; 32];
        let binding = session
            .bind(listener.local_addr().unwrap(), 123, &key)
            .unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = crate::FrameReader::new(stream);
            let crate::StartupRequest::CancelRequest(request) = reader.read_startup().unwrap()
            else {
                panic!("expected cancel");
            };
            assert_eq!(request.process_id, 123);
            assert_eq!(request.key, vec![7; 32]);
        });
        registry
            .dispatch(
                &CancelRequest {
                    process_id: session.process_id,
                    key: session.key.clone(),
                },
                Duration::from_secs(1),
            )
            .unwrap();
        server.join().unwrap();
        drop(binding);
        registry
            .dispatch(
                &CancelRequest {
                    process_id: session.process_id,
                    key: session.key.clone(),
                },
                Duration::from_secs(1),
            )
            .unwrap();
        let id = session.process_id;
        let key = session.key.clone();
        drop(session);
        registry
            .dispatch(
                &CancelRequest {
                    process_id: id,
                    key,
                },
                Duration::from_secs(1),
            )
            .unwrap();
        assert!(registry.entries.lock().unwrap().is_empty());
    }
    #[test]
    fn uncertain_dispatch_prevents_backend_reuse() {
        let registry = Arc::new(CancelRegistry::default());
        let session = registry.session().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let binding = session.bind(address, 123, &[7; 4]).unwrap();
        assert!(
            registry
                .dispatch(
                    &CancelRequest {
                        process_id: session.process_id,
                        key: session.key.clone()
                    },
                    Duration::from_secs(1)
                )
                .is_err()
        );
        assert!(!binding.finish().unwrap());
    }

    #[test]
    fn wrong_key_never_touches_a_backend() {
        let registry = Arc::new(CancelRegistry::default());
        let session = registry.session().unwrap();
        let _binding = session
            .bind("127.0.0.1:1".parse().unwrap(), 10, &[1; 4])
            .unwrap();
        registry
            .dispatch(
                &CancelRequest {
                    process_id: session.process_id,
                    key: vec![0; 32],
                },
                Duration::from_secs(1),
            )
            .unwrap();
    }
    #[test]
    fn slow_cancellation_does_not_block_unrelated_sessions() {
        use std::sync::mpsc;
        let registry = Arc::new(CancelRegistry::default());
        let session = registry.session().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let binding = session
            .bind(listener.local_addr().unwrap(), 123, &[7; 4])
            .unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = crate::FrameReader::new(stream);
            reader.read_startup().unwrap();
            accepted_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        let request = CancelRequest {
            process_id: session.process_id,
            key: session.key.clone(),
        };
        let dispatch_registry = Arc::clone(&registry);
        let dispatch =
            thread::spawn(move || dispatch_registry.dispatch(&request, Duration::from_secs(5)));
        accepted_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (other_tx, other_rx) = mpsc::channel();
        let other_registry = Arc::clone(&registry);
        let unrelated = thread::spawn(move || {
            let other = other_registry.session().unwrap();
            let binding = other
                .bind("127.0.0.1:1".parse().unwrap(), 321, &[1; 4])
                .unwrap();
            assert!(binding.finish().unwrap());
            other_tx.send(()).unwrap();
        });
        let progressed = other_rx.recv_timeout(Duration::from_secs(1));
        release_tx.send(()).unwrap();
        server.join().unwrap();
        dispatch.join().unwrap().unwrap();
        unrelated.join().unwrap();
        assert!(
            progressed.is_ok(),
            "unrelated ownership must not wait for network cancellation"
        );
        assert!(binding.finish().unwrap());
    }

    #[test]
    fn binding_cannot_replace_active_ownership() {
        let registry = Arc::new(CancelRegistry::default());
        let session = registry.session().unwrap();
        let binding = session
            .bind("127.0.0.1:1".parse().unwrap(), 1, &[1; 4])
            .unwrap();
        assert!(
            session
                .bind("127.0.0.1:2".parse().unwrap(), 2, &[2; 4])
                .is_err()
        );
        drop(binding);
        assert!(
            session
                .bind("127.0.0.1:2".parse().unwrap(), 2, &[2; 4])
                .is_ok()
        );
    }
}
