//! Small bounded, loopback-only HTTP control surface. No SQL text or credentials in diagnostics.
use super::Operations;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

pub type Control = Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>;
pub type PoolDiagnostics = Arc<dyn Fn() -> String + Send + Sync>;
pub struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    pub address: SocketAddr,
}
impl Server {
    pub fn start(
        address: SocketAddr,
        token: String,
        ops: Arc<Operations>,
        pools: PoolDiagnostics,
    ) -> io::Result<Self> {
        Self::start_with_control(address, token, ops, pools, None)
    }
    pub fn start_with_control(
        address: SocketAddr,
        token: String,
        ops: Arc<Operations>,
        pools: PoolDiagnostics,
        control: Option<Control>,
    ) -> io::Result<Self> {
        if !address.ip().is_loopback() {
            return Err(io::Error::other("operations listener must bind loopback"));
        }
        if token.len() < 32 {
            return Err(io::Error::other(
                "operations token must have at least 32 bytes",
            ));
        }
        let listener = TcpListener::bind(address)?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("pgproxy-operations".into())
            .spawn(move || {
                while !flag.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = serve(&mut stream, &token, &ops, &pools, control.as_ref());
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10))
                        }
                        Err(_) => break,
                    }
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(handle),
            address,
        })
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}
fn serve(
    stream: &mut TcpStream,
    token: &str,
    ops: &Operations,
    pools: &PoolDiagnostics,
    control: Option<&Control>,
) -> io::Result<()> {
    // Accepted sockets may inherit the listener's nonblocking flag on macOS.
    // Each bounded HTTP exchange uses deadline-controlled blocking I/O.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut bytes = Vec::new();
    let mut chunk = [0; 1024];
    while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        stream.set_read_timeout(Some(remaining))?;
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() > 8192 {
            return respond(stream, 431, "text/plain", "request too large");
        }
    }
    let text = match std::str::from_utf8(&bytes) {
        Ok(t) => t,
        Err(_) => return respond(stream, 400, "text/plain", "invalid request"),
    };
    let mut lines = text.split("\r\n");
    let request = lines.next().unwrap_or("");
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if !matches!(method, "GET" | "POST") {
        return respond(stream, 405, "text/plain", "GET required");
    }
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || parts.next().is_some() {
        return respond(stream, 400, "text/plain", "invalid request");
    }
    let mut authorization = None;
    let mut body_refused = false;
    for line in lines.take_while(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return respond(stream, 400, "text/plain", "invalid header");
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
        {
            body_refused = true;
        }
        if name.eq_ignore_ascii_case("authorization") {
            if authorization.is_some() {
                return respond(stream, 400, "text/plain", "duplicate authorization");
            }
            authorization = Some(value.trim());
        }
    }
    if body_refused {
        return respond(stream, 400, "text/plain", "request body refused");
    }
    if method == "GET" && path == "/health" {
        return respond(stream, 200, "application/json", "{\"alive\":true}");
    }
    if method == "GET" && path == "/ready" {
        return respond(
            stream,
            if ops.ready() { 200 } else { 503 },
            "application/json",
            if ops.ready() {
                "{\"accepting\":true}"
            } else {
                "{\"accepting\":false}"
            },
        );
    }
    let supplied = authorization
        .unwrap_or("")
        .strip_prefix("Bearer ")
        .unwrap_or("");
    if supplied.as_bytes().ct_eq(token.as_bytes()).unwrap_u8() != 1 {
        return respond(stream, 401, "text/plain", "unauthorized");
    }
    if method == "POST" {
        if !matches!(
            path,
            "/reload" | "/switchover/prepare" | "/switchover/commit" | "/switchover/abort"
        ) {
            return respond(stream, 404, "text/plain", "not found");
        }
        return match control {
            Some(control) => match control(path) {
                Ok(body) => respond(stream, 200, "application/json", &body),
                Err(message) => respond(
                    stream,
                    409,
                    "application/json",
                    &serde_json::json!({"error":message}).to_string(),
                ),
            },
            None => respond(stream, 404, "text/plain", "control disabled"),
        };
    }
    match path {
        "/usage" => respond(stream,200,"application/json",&serde_json::json!({"accounts":ops.usage_report(),"dropped_samples":ops.usage_dropped(),"measurement":"client exchanges and delivered results; server CPU/buffer/WAL unavailable"}).to_string()),
        "/metrics" => respond(stream, 200, "text/plain; version=0.0.4", &ops.prometheus()),
        "/clients" => {
            let clients = ops.clients();
            let body=serde_json::json!({"total":clients.len(),"clients":clients.into_iter().take(256).collect::<Vec<_>>()}).to_string();
            respond(stream, 200, "application/json", &body)
        }
        "/pools" => respond(stream, 200, "application/json", &pools()),
        _ => respond(stream, 404, "text/plain", "not found"),
    }
}
fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &str) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        match status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            431 => "Request Header Fields Too Large",
            409 => "Conflict",
            _ => "Service Unavailable",
        },
        body.len()
    );
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut bytes = response.as_bytes();
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        stream.set_write_timeout(Some(remaining))?;
        let n = stream.write(bytes)?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        bytes = &bytes[n..];
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request(server: &Server, request: &str) -> String {
        let mut stream = TcpStream::connect(server.address).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }
    #[test]
    fn endpoints_require_auth_and_track_readiness() {
        let ops = Arc::new(Operations::default());
        let token = "x".repeat(32);
        let server = Server::start(
            "127.0.0.1:0".parse().unwrap(),
            token.clone(),
            ops.clone(),
            Arc::new(|| "[]".into()),
        )
        .unwrap();
        assert!(request(&server, "GET /health HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 200"));
        assert!(request(&server, "GET /ready HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 503"));
        ops.set_ready(true);
        assert!(request(&server, "GET /ready HTTP/1.1\r\n\r\n").contains("\"accepting\":true"));
        assert!(request(&server, "GET /clients HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 401"));
        let response = request(
            &server,
            &format!("GET /metrics HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n"),
        );
        assert!(response.contains("pgproxy_ready 1"));
        assert!(request(&server,&format!("GET /clients HTTP/1.1\r\nAuthorization: Bearer {token}\r\nAuthorization: Bearer {token}\r\n\r\n")).starts_with("HTTP/1.1 400"));
    }
    #[test]
    fn external_bind_and_short_secret_fail() {
        assert!(
            Server::start(
                "0.0.0.0:0".parse().unwrap(),
                "x".repeat(32),
                Arc::default(),
                Arc::new(|| "[]".into())
            )
            .is_err()
        );
        assert!(
            Server::start(
                "127.0.0.1:0".parse().unwrap(),
                "short".into(),
                Arc::default(),
                Arc::new(|| "[]".into())
            )
            .is_err()
        );
    }

    #[test]
    fn control_requires_authenticated_bodyless_post() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let token = "z".repeat(32);
        let server = Server::start_with_control(
            "127.0.0.1:0".parse().unwrap(),
            token.clone(),
            Arc::default(),
            Arc::new(|| "[]".into()),
            Some(Arc::new(move |_| {
                observed.fetch_add(1, Ordering::Relaxed);
                Ok("{}".into())
            })),
        )
        .unwrap();
        assert!(request(&server, "POST /reload HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 401"));
        assert!(
            request(
                &server,
                &format!("GET /reload HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n")
            )
            .starts_with("HTTP/1.1 404")
        );
        assert!(request(&server, &format!("POST /reload HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: 1\r\n\r\nx")).starts_with("HTTP/1.1 400"));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(
            request(
                &server,
                &format!("POST /reload HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n")
            )
            .starts_with("HTTP/1.1 200")
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
