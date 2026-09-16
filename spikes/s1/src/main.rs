//! Spike S1 — where does the Rust proxy's data-path overhead actually come from?
//!
//! This is a deliberately dumb pass-through proxy: it speaks no PostgreSQL, parses no SQL and
//! pools nothing. It exists only to measure the *floor* — the cost of moving bytes — so it can
//! be compared against PgBouncer's libevent loop and against no proxy at all.
//!
//! Three data paths, same binary:
//!   thread  — blocking std::io::copy on a thread per connection
//!   tokio   — copy_bidirectional on per-core current-thread runtimes
//!   splice  — zero-copy pipe splice (Linux), blocking, thread per connection
//!
//! All modes use SO_REUSEPORT so each worker owns a listener and there is no shared
//! accept mutex — the model PgBouncer's multi-process workaround approximates.

use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

fn usage() -> ! {
    eprintln!(
        "usage: spike-s1 --mode <thread|tokio|splice> [--workers N] --listen ADDR --backend ADDR"
    );
    std::process::exit(2);
}

struct Args {
    mode: String,
    workers: usize,
    listen: String,
    backend: String,
}

fn parse_args() -> Args {
    let mut mode = None;
    let mut workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mut listen = None;
    let mut backend = None;

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--mode" => mode = it.next(),
            "--workers" => {
                workers = it.next().and_then(|v| v.parse().ok()).unwrap_or(workers);
            }
            "--listen" => listen = it.next(),
            "--backend" => backend = it.next(),
            _ => usage(),
        }
    }
    Args {
        mode: mode.unwrap_or_else(|| usage()),
        workers,
        listen: listen.unwrap_or_else(|| usage()),
        backend: backend.unwrap_or_else(|| usage()),
    }
}

/// Bind a listener with SO_REUSEPORT so every worker can own one.
fn reuseport_listener(addr: &str) -> io::Result<TcpListener> {
    let sa: SocketAddr = addr
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{addr}: {e}")))?;
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(sa),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.bind(&sa.into())?;
    sock.listen(4096)?;
    sock.set_nonblocking(false)?;
    Ok(sock.into())
}

fn set_nodelay(s: &TcpStream) {
    let _ = s.set_nodelay(true);
}

// ------------------------------------------------------------------ thread

fn run_thread(workers: usize, listen: &str, backend: &str, splice: bool) {
    let backend: Arc<str> = Arc::from(backend);
    let mut handles = Vec::new();
    for _ in 0..workers {
        let l = reuseport_listener(listen).expect("bind");
        let backend = Arc::clone(&backend);
        handles.push(std::thread::spawn(move || {
            for stream in l.incoming() {
                let client = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let backend = Arc::clone(&backend);
                std::thread::spawn(move || {
                    let server = match TcpStream::connect(&*backend) {
                        Ok(s) => s,
                        Err(_) => {
                            let _ = client.shutdown(Shutdown::Both);
                            return;
                        }
                    };
                    set_nodelay(&client);
                    set_nodelay(&server);
                    if splice {
                        splice_bidirectional(&client, &server);
                    } else {
                        copy_bidirectional_threads(client, server);
                    }
                });
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

fn copy_bidirectional_threads(client: TcpStream, server: TcpStream) {
    let c2 = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let s2 = match server.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };

    let up = std::thread::spawn(move || {
        let (mut c, mut s) = (c2, s2);
        let _ = io::copy(&mut c, &mut s);
        let _ = s.shutdown(Shutdown::Write);
    });

    let (mut s, mut c) = (server, client);
    let _ = io::copy(&mut s, &mut c);
    let _ = c.shutdown(Shutdown::Write);
    let _ = up.join();
}

// ------------------------------------------------------------------ splice

/// Zero-copy socket-to-socket relay through a pipe, using splice(2).
///
/// This is the "bypass" hypothesis: once a connection is assigned, the proxy should stop
/// touching payload bytes. Runs on blocking fds, one thread per direction-set.
fn splice_loop(fd_in: RawFd, fd_out: RawFd) -> io::Result<()> {
    const CAP: usize = 1 << 16;
    let mut fds = [0i32; 2];
    // SAFETY: fds points at two valid i32 slots.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (rd, wr) = (fds[0], fds[1]);

    // Best effort: a bigger pipe means fewer syscalls per byte.
    // SAFETY: wr is a valid fd; F_SETPIPE_SZ takes an int argument.
    unsafe { libc::fcntl(wr, libc::F_SETPIPE_SZ, 1 << 20) };

    let result = (|| -> io::Result<()> {
        loop {
            // SAFETY: both fds are valid and owned by this thread for the call duration.
            let n = unsafe {
                libc::splice(
                    fd_in,
                    std::ptr::null_mut(),
                    wr,
                    std::ptr::null_mut(),
                    CAP,
                    0,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if n == 0 {
                return Ok(()); // EOF
            }
            let mut left = n as usize;
            while left > 0 {
                // SAFETY: as above; left is the remaining byte count in the pipe.
                let w = unsafe {
                    libc::splice(
                        rd,
                        std::ptr::null_mut(),
                        fd_out,
                        std::ptr::null_mut(),
                        left,
                        0,
                    )
                };
                if w < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                if w == 0 {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "splice peer closed"));
                }
                left -= w as usize;
            }
        }
    })();

    // SAFETY: both fds were created by pipe() above and are not used afterwards.
    unsafe {
        libc::close(rd);
        libc::close(wr);
    }
    result
}

fn splice_bidirectional(client: &TcpStream, server: &TcpStream) {
    let (cfd, sfd) = (client.as_raw_fd(), server.as_raw_fd());
    // Two independent directions; each needs its own pipe and thread.
    let c2 = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let s2 = match server.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let (c2fd, s2fd) = (c2.as_raw_fd(), s2.as_raw_fd());

    let up = std::thread::spawn(move || {
        let _ = splice_loop(c2fd, s2fd);
        let _ = c2.shutdown(Shutdown::Read);
        let _ = s2.shutdown(Shutdown::Write);
        // Keep the clones alive until the relay finishes.
        drop(c2);
        drop(s2);
    });
    let _ = splice_loop(sfd, cfd);
    let _ = client.shutdown(Shutdown::Read);
    let _ = server.shutdown(Shutdown::Write);
    let _ = up.join();
}

// ------------------------------------------------------------------ tokio

fn run_tokio(workers: usize, listen: &str, backend: &str) {
    let listen: Arc<str> = Arc::from(listen);
    let backend: Arc<str> = Arc::from(backend);
    let mut handles = Vec::new();

    for _ in 0..workers {
        let listen = Arc::clone(&listen);
        let backend = Arc::clone(&backend);
        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async move {
                let std_listener = reuseport_listener(&listen).expect("bind");
                std_listener.set_nonblocking(true).expect("nonblocking");
                let listener =
                    tokio::net::TcpListener::from_std(std_listener).expect("tokio listener");
                loop {
                    let (mut client, _) = match listener.accept().await {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let backend = Arc::clone(&backend);
                    tokio::spawn(async move {
                        let mut server = match tokio::net::TcpStream::connect(&*backend).await {
                            Ok(s) => s,
                            Err(_) => return,
                        };
                        let _ = client.set_nodelay(true);
                        let _ = server.set_nodelay(true);
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                    });
                }
            });
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

fn main() {
    let args = parse_args();
    eprintln!(
        "spike-s1 mode={} workers={} listen={} backend={}",
        args.mode, args.workers, args.listen, args.backend
    );
    match args.mode.as_str() {
        "thread" => run_thread(args.workers, &args.listen, &args.backend, false),
        "splice" => run_thread(args.workers, &args.listen, &args.backend, true),
        "tokio" => run_tokio(args.workers, &args.listen, &args.backend),
        _ => usage(),
    }
}
