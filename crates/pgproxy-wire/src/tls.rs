//! Native frontend TLS. A bounded bridge keeps the existing protocol relay's sockets
//! independent of TLS record boundaries. One thread owns all rustls state, avoiding
//! a blocking read mutex that would deadlock full-duplex PostgreSQL exchanges.
use crate::ShutdownToken;
use rustls::{ServerConfig, ServerConnection};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{
    fs::File,
    io::{self, BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub struct FrontendTls {
    config: Arc<ServerConfig>,
    pub required: bool,
    endpoint: Option<Vec<u8>>,
}
impl FrontendTls {
    pub fn from_pem(certificate: &Path, key: &Path, required: bool) -> io::Result<Self> {
        Self::from_pem_with_ca(certificate, key, required, None)
    }
    pub fn from_pem_with_ca(
        certificate: &Path,
        key: &Path,
        required: bool,
        client_ca: Option<&Path>,
    ) -> io::Result<Self> {
        let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(certificate)?))
            .collect::<Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key)?))?
            .ok_or_else(|| io::Error::other("TLS private key is missing"))?;
        let endpoint = certs
            .first()
            .and_then(|cert| endpoint_digest(cert.as_ref()));
        let builder = ServerConfig::builder();
        let builder = if let Some(ca) = client_ca {
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(ca)?)) {
                roots.add(cert?).map_err(io::Error::other)?;
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .allow_unauthenticated()
                .build()
                .map_err(io::Error::other)?;
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };
        let config = builder
            .with_single_cert(certs, key)
            .map_err(io::Error::other)?;
        Ok(Self {
            config: Arc::new(config),
            required,
            endpoint,
        })
    }

    /// Complete the TLS handshake within the socket's existing startup deadline.
    pub fn accept(&self, mut network: TcpStream, shutdown: ShutdownToken) -> io::Result<TlsBridge> {
        let mut tls = ServerConnection::new(Arc::clone(&self.config)).map_err(io::Error::other)?;
        tls.set_buffer_limit(Some(64 * 1024));
        let deadline = Instant::now() + network.read_timeout()?.unwrap_or(Duration::from_secs(10));
        network.set_nonblocking(true)?;
        while tls.is_handshaking() {
            if shutdown.is_shutdown() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "TLS shutdown"));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TLS handshake timeout",
                ));
            }
            let mut progressed = false;
            if tls.wants_write() {
                match tls.write_tls(&mut network) {
                    Ok(n) => progressed |= n != 0,
                    Err(e) if transient(&e) => {}
                    Err(e) => return Err(e),
                }
            }
            if tls.wants_read() {
                match tls.read_tls(&mut network) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "TLS handshake closed",
                        ));
                    }
                    Ok(_) => {
                        tls.process_new_packets().map_err(io::Error::other)?;
                        progressed = true;
                    }
                    Err(e) if transient(&e) => {}
                    Err(e) => return Err(e),
                }
            }
            if !progressed {
                thread::sleep(Duration::from_millis(1));
            }
        }
        let peer_certificate = tls
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| Sha256::digest(cert.as_ref()).to_vec());
        // The protocol layer continues over a private loopback pair. Verify the peer
        // so another local connection cannot win the accept race and receive plaintext.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let local = TcpStream::connect(listener.local_addr()?)?;
        let expected = local.local_addr()?;
        let bridge = loop {
            let (candidate, peer) = listener.accept()?;
            if peer == expected {
                break candidate;
            }
        };
        drop(listener);
        network.set_nonblocking(true)?;
        bridge.set_nonblocking(true)?;
        network.set_nodelay(true)?;
        bridge.set_nodelay(true)?;
        local.set_nodelay(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&stop);
        let abort_network = network.try_clone()?;
        let worker = thread::Builder::new()
            .name("pgproxy-tls".into())
            .spawn(move || {
                let mut tls = rustls::Connection::Server(tls);
                let result = pump(&mut tls, &mut network, &mut &bridge, &signal, &shutdown);
                let _ = bridge.shutdown(Shutdown::Both);
                let _ = network.shutdown(Shutdown::Both);
                result
            })?;
        Ok(TlsBridge {
            stream: local,
            channel_binding: self.endpoint.clone(),
            peer_certificate,
            stop,
            abort_network,
            worker: Some(worker),
        })
    }
}

pub struct TlsBridge {
    pub stream: TcpStream,
    pub channel_binding: Option<Vec<u8>>,
    pub peer_certificate: Option<Vec<u8>>,
    pub(crate) stop: Arc<AtomicBool>,
    pub(crate) abort_network: TcpStream,
    pub(crate) worker: Option<JoinHandle<io::Result<()>>>,
}
impl Drop for TlsBridge {
    fn drop(&mut self) {
        // Half-close the application side first. Queued PostgreSQL errors and final
        // responses must reach the TLS pump before the encrypted socket is aborted.
        let _ = self.stream.shutdown(Shutdown::Write);
        if let Some(worker) = self.worker.take() {
            let deadline = Instant::now() + Duration::from_millis(250);
            while !worker.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            if !worker.is_finished() {
                self.stop.store(true, Ordering::Release);
                let _ = self.stream.shutdown(Shutdown::Both);
                let _ = self.abort_network.shutdown(Shutdown::Both);
            }
            let _ = worker.join();
        }
    }
}

/// Canonical hexadecimal SHA256 certificate fingerprint. Accept no ambiguous encodings.
pub fn decode_fingerprint(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..32)
        .map(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// RFC 5929: use the certificate signature hash, upgrading MD5/SHA1 to SHA256.
/// Unsupported algorithms disable PLUS advertisement rather than guessing a digest.
pub(crate) fn endpoint_digest(der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    if cert.signature_algorithm.algorithm.to_id_string() == "1.2.840.113549.1.1.10" {
        let x509_parser::signature_algorithm::SignatureAlgorithm::RSASSA_PSS(parameters) =
            x509_parser::signature_algorithm::SignatureAlgorithm::try_from(
                &cert.signature_algorithm,
            )
            .ok()?
        else {
            return None;
        };
        return match parameters.hash_algorithm_oid().to_id_string().as_str() {
            "1.3.14.3.2.26" | "2.16.840.1.101.3.4.2.1" => Some(Sha256::digest(der).to_vec()),
            "2.16.840.1.101.3.4.2.2" => Some(Sha384::digest(der).to_vec()),
            "2.16.840.1.101.3.4.2.3" => Some(Sha512::digest(der).to_vec()),
            _ => None,
        };
    }
    match cert.signature_algorithm.algorithm.to_id_string().as_str() {
        "1.2.840.113549.1.1.4"
        | "1.2.840.113549.1.1.5"
        | "1.2.840.113549.1.1.11"
        | "1.2.840.10045.4.1"
        | "1.2.840.10045.4.3.2"
        | "1.2.840.10040.4.3" => Some(Sha256::digest(der).to_vec()),
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => Some(Sha384::digest(der).to_vec()),
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => Some(Sha512::digest(der).to_vec()),
        _ => None,
    }
}

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
pub(crate) fn pump(
    tls: &mut rustls::Connection,
    network: &mut TcpStream,
    local: &mut &TcpStream,
    stop: &AtomicBool,
    shutdown: &ShutdownToken,
) -> io::Result<()> {
    let mut poll = mio::Poll::new()?;
    let mut events = mio::Events::with_capacity(8);
    let mut network_source = mio::net::TcpStream::from_std(network.try_clone()?);
    let mut local_source = mio::net::TcpStream::from_std(local.try_clone()?);
    let mut network_interest = None;
    let mut local_interest = None;
    let mut to_local = [0u8; 16384];
    let mut start = 0;
    let mut end = 0;
    let mut to_tls = [0u8; 16384];
    let mut tls_start = 0;
    let mut tls_end = 0;
    let mut local_closed = false;
    loop {
        if stop.load(Ordering::Acquire) || shutdown.is_shutdown() {
            return Ok(());
        }
        let mut progressed = false;
        if start < end {
            match local.write(&to_local[start..end]) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    start += n;
                    progressed = true;
                }
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e),
            }
        }
        if start == end {
            start = 0;
            end = 0;
            match tls.reader().read(&mut to_local) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    end = n;
                    progressed = true;
                }
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e),
            }
        }
        if tls.wants_write() {
            match tls.write_tls(network) {
                Ok(n) => progressed |= n != 0,
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e),
            }
        }
        if tls_start < tls_end {
            match tls.writer().write(&to_tls[tls_start..tls_end]) {
                Ok(n) => {
                    tls_start += n;
                    progressed |= n != 0;
                }
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e),
            }
        }
        if local_closed && tls_start == tls_end && !tls.wants_write() {
            return Ok(());
        }
        if !local_closed && tls_start == tls_end && !tls.wants_write() {
            tls_start = 0;
            tls_end = 0;
            match local.read(&mut to_tls) {
                Ok(0) => {
                    local_closed = true;
                    tls.send_close_notify();
                    progressed = true;
                }
                Ok(n) => {
                    tls_end = n;
                    progressed = true;
                }
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e),
            }
        }
        if start == end && tls.wants_read() {
            match tls.read_tls(network) {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    tls.process_new_packets().map_err(io::Error::other)?;
                    progressed = true;
                }
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e),
            }
        }
        if !progressed {
            update_interest(
                &poll,
                &mut network_source,
                mio::Token(0),
                &mut network_interest,
                interests(
                    !local_closed && start == end && tls.wants_read(),
                    tls.wants_write(),
                ),
            )?;
            update_interest(
                &poll,
                &mut local_source,
                mio::Token(1),
                &mut local_interest,
                interests(
                    !local_closed && tls_start == tls_end && !tls.wants_write(),
                    start < end,
                ),
            )?;
            // Socket readiness removes artificial per-message sleeps. The timeout
            // remains a watchdog for shutdown tokens that do not own a socket waker.
            match poll.poll(&mut events, Some(Duration::from_millis(50))) {
                Ok(()) => {}
                Err(error) if transient(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }
}
fn interests(read: bool, write: bool) -> Option<mio::Interest> {
    match (read, write) {
        (true, true) => Some(mio::Interest::READABLE | mio::Interest::WRITABLE),
        (true, false) => Some(mio::Interest::READABLE),
        (false, true) => Some(mio::Interest::WRITABLE),
        (false, false) => None,
    }
}
fn update_interest(
    poll: &mio::Poll,
    source: &mut mio::net::TcpStream,
    token: mio::Token,
    current: &mut Option<mio::Interest>,
    desired: Option<mio::Interest>,
) -> io::Result<()> {
    if *current == desired {
        return Ok(());
    }
    match (*current, desired) {
        (None, Some(interest)) => poll.registry().register(source, token, interest)?,
        (Some(_), Some(interest)) => poll.registry().reregister(source, token, interest)?,
        (Some(_), None) => poll.registry().deregister(source)?,
        (None, None) => {}
    }
    *current = desired;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    fn configs() -> (FrontendTls, Arc<ClientConfig>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key.into())
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let client = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (
            FrontendTls {
                config: Arc::new(server),
                required: true,
                endpoint: endpoint_digest(der.as_ref()),
            },
            Arc::new(client),
        )
    }
    #[test]
    fn encrypted_bridge_handles_full_duplex_and_large_payloads() {
        let (server, config) = configs();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (network, _) = listener.accept().unwrap();
            network
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            network
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let bridge = server.accept(network, ShutdownToken::new()).unwrap();
            let mut local = &bridge.stream;
            local.write_all(b"server-first").unwrap();
            let mut received = vec![0; 256 * 1024];
            local.read_exact(&mut received).unwrap();
            assert!(received.iter().all(|byte| *byte == 42));
            local.write_all(b"verified").unwrap();
            // Let the peer consume the response before the bridge closes.
            let mut ack = [0; 1];
            local.read_exact(&mut ack).unwrap();
        });
        let stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let client = ClientConnection::new(config, "localhost".try_into().unwrap()).unwrap();
        let mut encrypted = StreamOwned::new(client, stream);
        let mut first = [0; 12];
        encrypted.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"server-first");
        encrypted.write_all(&vec![42; 256 * 1024]).unwrap();
        encrypted.flush().unwrap();
        let mut response = [0; 8];
        encrypted.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"verified");
        encrypted.write_all(b"!").unwrap();
        encrypted.flush().unwrap();
        worker.join().unwrap();
    }
    #[test]
    fn untrusted_server_certificate_fails_handshake() {
        let (server, _) = configs();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert!(server.accept(stream, ShutdownToken::new()).is_err());
        });
        let config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let client =
            ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
        let mut encrypted = StreamOwned::new(client, TcpStream::connect(address).unwrap());
        assert!(encrypted.write_all(b"never accepted").is_err());
        drop(encrypted);
        worker.join().unwrap();
    }
    #[test]
    fn stalled_handshake_obeys_the_overall_deadline() {
        let (server, _) = configs();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        let began = Instant::now();
        let error = server.accept(stream, ShutdownToken::new()).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(began.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn fingerprint_encoding_is_unambiguous() {
        assert_eq!(decode_fingerprint(&"aF".repeat(32)), Some(vec![0xaf; 32]));
        for invalid in ["", "ab", &"zz".repeat(32), &"é".repeat(32)] {
            assert!(decode_fingerprint(invalid).is_none());
        }
    }
    #[test]
    fn rsa_pss_binding_uses_the_certificate_parameter_hash() {
        let der = include_bytes!("../tests/fixtures/tls/rsa-pss-sha384.der");
        assert_eq!(endpoint_digest(der), Some(Sha384::digest(der).to_vec()));
        assert_ne!(endpoint_digest(der), Some(Sha256::digest(der).to_vec()));
    }
    #[test]
    fn dropping_bridge_drains_the_final_postgres_fatal_response() {
        let (server, client) = configs();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (network, _) = listener.accept().unwrap();
            let bridge = server.accept(network, ShutdownToken::new()).unwrap();
            let mut writer = crate::FrameWriter::new(bridge.stream.try_clone().unwrap());
            crate::protocol::messages::send_error(
                &mut writer,
                crate::protocol::messages::Severity::Fatal,
                "28000",
                "fatal-fixture",
            )
            .unwrap();
            // Return immediately: a socket write into the private bridge is not yet
            // evidence that the encrypted response reached the remote client.
        });
        let network = TcpStream::connect(address).unwrap();
        network
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let client = ClientConnection::new(client, "localhost".try_into().unwrap()).unwrap();
        let mut reader = crate::FrameReader::new(StreamOwned::new(client, network));
        let frame = reader.read_message().unwrap().expect("FATAL response");
        assert_eq!(frame.tag, crate::protocol::backend::ERROR_RESPONSE);
        assert!(
            frame
                .payload
                .windows(b"fatal-fixture".len())
                .any(|value| value == b"fatal-fixture")
        );
        worker.join().unwrap();
    }
}
