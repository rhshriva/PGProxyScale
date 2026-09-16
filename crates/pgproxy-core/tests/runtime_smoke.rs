//! End-to-end proof that the Phase 0 runtime works: bind, accept, dispatch, drain.
//!
//! This does not test the PostgreSQL protocol — that is workstream W2 — but it does prove
//! the pieces the protocol will be built on: per-worker `SO_REUSEPORT` listeners, the
//! accept path, per-connection dispatch, and a bounded shutdown.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use pgproxy_core::Runtime;
use pgproxy_core::config::{Config, Database};
use pgproxy_wire::{Connection, Service, ShutdownToken};

/// A service that records connections and immediately closes them.
struct ClosingService {
    seen: Arc<AtomicUsize>,
}

impl Service for ClosingService {
    fn handle(&self, conn: Connection) -> std::io::Result<()> {
        self.seen.fetch_add(1, Ordering::SeqCst);
        let _ = conn.stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }
}

fn test_config(workers: usize) -> Config {
    Config {
        general: pgproxy_core::config::General {
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 0, // any free port; the runtime reports which
            workers,
            admin_users: Vec::new(),
            shutdown_timeout_secs: 5,
        },
        databases: vec![Database {
            name: "app".to_string(),
            host: "127.0.0.1".to_string(),
            port: 5432,
            dbname: None,
            pool_size: 4,
        }],
        ..Default::default()
    }
}

fn start(
    workers: usize,
) -> (
    std::net::SocketAddr,
    ShutdownToken,
    thread::JoinHandle<()>,
    Arc<AtomicUsize>,
) {
    let cfg = test_config(workers);
    cfg.validate().expect("test config must be valid");

    let seen = Arc::new(AtomicUsize::new(0));
    let service = ClosingService {
        seen: Arc::clone(&seen),
    };

    let token = ShutdownToken::new();
    let (tx, rx) = mpsc::channel();
    let runtime = Runtime::new(cfg, Arc::new(service))
        .with_ready_signal(tx)
        .with_shutdown_token(token.clone());

    let handle = thread::spawn(move || {
        runtime.run().expect("runtime must exit cleanly");
    });

    let addr = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("runtime must report its bound address");
    (addr, token, handle, seen)
}

/// Trigger shutdown and assert it completes well inside the configured budget.
///
/// This is the regression guard for a blocked accept loop. Workers that park inside
/// `accept()` never observe the shutdown token, so the runtime only returns when the
/// *drain budget* expires. Without a timing assertion that failure mode passes
/// silently, because the timeout branch returns `Ok(())` and every test still goes
/// green — which is exactly what happened before this assertion existed.
fn shutdown_promptly(token: ShutdownToken, handle: thread::JoinHandle<()>) {
    let started = std::time::Instant::now();
    token.trigger();
    handle.join().expect("runtime thread must join");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(1500),
        "shutdown took {elapsed:?}: workers never observed the token, so only the drain \
         budget ended them (blocked accept loop?)"
    );
}

/// A service that performs a blocking read of a fixed number of bytes.
///
/// If accepted sockets were left non-blocking, this read would fail with `WouldBlock`
/// instead of waiting — which is exactly how a working proxy can look alive while closing
/// every connection on arrival.
struct BlockingReadService {
    expected: usize,
    got: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
}

impl Service for BlockingReadService {
    fn handle(&self, conn: Connection) -> std::io::Result<()> {
        let mut stream = conn.stream;
        let mut buf = vec![0u8; self.expected];
        stream.read_exact(&mut buf)?;
        *self.got.lock().unwrap() = Some(buf);
        Ok(())
    }
}

#[test]
fn accepted_sockets_support_blocking_reads() {
    // Regression guard: mio requires a non-blocking listener and an accepted socket
    // inherits that flag, so the runtime must switch it back.
    let payload = b"startup-bytes-here";

    let got = Arc::new(std::sync::Mutex::new(None));
    let service = BlockingReadService {
        expected: payload.len(),
        got: Arc::clone(&got),
    };

    let cfg = test_config(1);
    let token = ShutdownToken::new();
    let (tx, rx) = mpsc::channel();
    let runtime = Runtime::new(cfg, Arc::new(service))
        .with_ready_signal(tx)
        .with_shutdown_token(token.clone());
    let handle = thread::spawn(move || runtime.run().expect("runtime exits cleanly"));
    let addr = rx.recv_timeout(Duration::from_secs(10)).expect("ready");

    let mut client = TcpStream::connect(addr).expect("connect");
    client.write_all(payload).expect("write");
    client.flush().expect("flush");

    // The service must receive all of it; a non-blocking socket would have returned
    // WouldBlock and left `got` empty.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if got.lock().unwrap().is_some() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the service never received the payload, so the accepted socket was not readable in blocking mode"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(got.lock().unwrap().as_deref(), Some(payload.as_slice()));

    shutdown_promptly(token, handle);
}

#[test]
fn binds_reports_address_and_serves_a_connection() {
    let (addr, token, handle, seen) = start(1);

    let mut stream = TcpStream::connect(addr).expect("must connect to the reported address");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    // The service closes the connection, so a read returns EOF rather than blocking.
    let mut buf = [0u8; 1];
    let n = stream.read(&mut buf).expect("read must not error");
    assert_eq!(n, 0, "service should have closed the connection");

    // The handler runs on its own thread, so allow a moment for the counter.
    for _ in 0..50 {
        if seen.load(Ordering::SeqCst) == 1 {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "service must see exactly one connection"
    );

    shutdown_promptly(token, handle);
}

#[test]
fn multiple_workers_share_one_port_and_shutdown_drains() {
    let (addr, token, handle, seen) = start(4);

    // Several concurrent connections must all be accepted across the worker set.
    let mut streams = Vec::new();
    for _ in 0..16 {
        let s = TcpStream::connect(addr).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        streams.push(s);
    }
    for s in &mut streams {
        let mut buf = [0u8; 1];
        assert_eq!(s.read(&mut buf).expect("read"), 0);
    }

    for _ in 0..100 {
        if seen.load(Ordering::SeqCst) == 16 {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        seen.load(Ordering::SeqCst),
        16,
        "all 16 connections must be handled across workers sharing one port"
    );

    shutdown_promptly(token, handle);
}
