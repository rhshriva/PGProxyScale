//! Listening sockets.
//!
//! Every worker binds its own listener with `SO_REUSEPORT`, so the kernel distributes
//! incoming connections across cores and there is no shared accept mutex. This is the
//! model spike S1 measured as scaling to 3.0x PgBouncer at 64 clients, and it is the
//! reason pool accounting must be coordinated globally rather than per listener — see
//! `docs/architecture/overview.md` §2.

use std::net::{SocketAddr, TcpListener};

use socket2::{Domain, Protocol, Socket, Type};

use crate::error::{Error, Result};

/// Backlog for `listen(2)`. Deep enough that a burst of serverless clients is queued
/// rather than refused, matching what the research showed is the common failure mode.
pub const LISTEN_BACKLOG: i32 = 4096;

/// Bind a listener with `SO_REUSEPORT` and `SO_REUSEADDR` set.
///
/// Safe to call once per worker with the same address.
pub fn reuseport_listener(addr: SocketAddr) -> Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
        .map_err(|source| Error::Bind { addr, source })?;

    socket
        .set_reuse_address(true)
        .map_err(|source| Error::Bind { addr, source })?;
    // The whole point: without this, N workers cannot share one port.
    socket
        .set_reuse_port(true)
        .map_err(|source| Error::Bind { addr, source })?;

    socket
        .bind(&addr.into())
        .map_err(|source| Error::Bind { addr, source })?;
    socket
        .listen(LISTEN_BACKLOG)
        .map_err(|source| Error::Bind { addr, source })?;

    let listener: TcpListener = socket.into();
    Ok(listener)
}

/// Disable Nagle on a stream.
///
/// Set on both sides of every relayed connection. PostgreSQL's own protocol is
/// request/response, so Nagle only ever adds latency here.
pub fn set_nodelay(stream: &std::net::TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, "could not set TCP_NODELAY");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_and_rebinds_the_same_port() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let first = reuseport_listener(addr).expect("first bind");
        let port = first.local_addr().unwrap().port();

        // A second listener on the *same concrete port* is the property that matters.
        let addr2: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let second = reuseport_listener(addr2).expect("second bind with SO_REUSEPORT");
        assert_eq!(second.local_addr().unwrap().port(), port);

        // And a third, to prove it is not a two-listener special case.
        reuseport_listener(addr2).expect("third bind with SO_REUSEPORT");
    }
}
