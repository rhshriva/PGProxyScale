//! Verified backend TLS. There is deliberately no opportunistic plaintext fallback.
use crate::{
    ShutdownToken,
    tls::{TlsBridge, endpoint_digest, pump},
};
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct BackendTls {
    identity: String,
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    pub require_channel_binding: bool,
}
impl BackendTls {
    pub fn from_pem(
        ca: &Path,
        server_name: &str,
        require_channel_binding: bool,
    ) -> io::Result<Self> {
        Self::from_pem_with_identity(ca, server_name, require_channel_binding, None, None)
    }
    pub fn from_pem_with_identity(
        ca: &Path,
        server_name: &str,
        require_channel_binding: bool,
        certificate: Option<&Path>,
        private_key: Option<&Path>,
    ) -> io::Result<Self> {
        let mut roots = RootCertStore::empty();
        let mut identity = Sha256::new();
        identity.update(server_name.as_bytes());
        identity.update([u8::from(require_channel_binding)]);
        for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(ca)?)) {
            let cert = cert?;
            identity.update(cert.as_ref());
            roots.add(cert).map_err(io::Error::other)?;
        }
        if roots.is_empty() {
            return Err(io::Error::other("backend TLS CA contains no certificates"));
        }
        let builder = ClientConfig::builder().with_root_certificates(roots);
        let config = match (certificate, private_key) {
            (None, None) => builder.with_no_client_auth(),
            (Some(certificate), Some(private_key)) => {
                let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(certificate)?))
                    .collect::<Result<Vec<_>, _>>()?;
                if certs.is_empty() {
                    return Err(io::Error::other(
                        "backend TLS client certificate is missing",
                    ));
                }
                for certificate in &certs {
                    identity.update(certificate.as_ref());
                }
                let key =
                    rustls_pemfile::private_key(&mut BufReader::new(File::open(private_key)?))?
                        .ok_or_else(|| {
                            io::Error::other("backend TLS client private key is missing")
                        })?;
                builder
                    .with_client_auth_cert(certs, key)
                    .map_err(io::Error::other)?
            }
            _ => {
                return Err(io::Error::other(
                    "backend TLS client certificate and private key must be paired",
                ));
            }
        };
        Ok(Self {
            identity: format!("{:x}", identity.finalize()),
            config: Arc::new(config),
            server_name: ServerName::try_from(server_name.to_owned()).map_err(io::Error::other)?,
            require_channel_binding,
        })
    }
    pub fn pool_identity(&self) -> &str {
        &self.identity
    }
    pub fn connect(&self, mut network: TcpStream, timeout: Duration) -> io::Result<TlsBridge> {
        network.set_read_timeout(Some(timeout))?;
        network.set_write_timeout(Some(timeout))?;
        network.write_all(&[0, 0, 0, 8, 4, 210, 22, 47])?;
        let mut reply = [0];
        network.read_exact(&mut reply)?;
        if reply != [b'S'] {
            return Err(io::Error::other("backend refused required TLS"));
        }
        let mut tls = ClientConnection::new(Arc::clone(&self.config), self.server_name.clone())
            .map_err(io::Error::other)?;
        tls.set_buffer_limit(Some(64 * 1024));
        // One absolute deadline prevents a peer from extending startup with trickled records.
        let deadline = std::time::Instant::now() + timeout;
        network.set_nonblocking(true)?;
        while tls.is_handshaking() {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "backend TLS handshake timeout",
                ));
            }
            let mut progressed = false;
            if tls.wants_write() {
                match tls.write_tls(&mut network) {
                    Ok(n) => progressed |= n != 0,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => return Err(e),
                }
            }
            if tls.wants_read() {
                match tls.read_tls(&mut network) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "backend TLS handshake closed",
                        ));
                    }
                    Ok(_) => {
                        tls.process_new_packets().map_err(io::Error::other)?;
                        progressed = true;
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => return Err(e),
                }
            }
            if !progressed {
                thread::sleep(Duration::from_millis(1));
            }
        }
        let channel_binding = tls
            .peer_certificates()
            .and_then(|c| c.first())
            .and_then(|c| endpoint_digest(c.as_ref()));
        if self.require_channel_binding && channel_binding.is_none() {
            return Err(io::Error::other(
                "backend certificate cannot provide channel binding",
            ));
        }
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let local = TcpStream::connect(listener.local_addr()?)?;
        let expected = local.local_addr()?;
        let bridge = loop {
            let (candidate, peer) = listener.accept()?;
            if peer == expected {
                break candidate;
            }
        };
        network.set_nonblocking(true)?;
        bridge.set_nonblocking(true)?;
        network.set_nodelay(true)?;
        bridge.set_nodelay(true)?;
        local.set_nodelay(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&stop);
        let abort_network = network.try_clone()?;
        let worker = thread::Builder::new()
            .name("pgproxy-backend-tls".into())
            .spawn(move || {
                let mut tls = rustls::Connection::Client(tls);
                let result = pump(
                    &mut tls,
                    &mut network,
                    &mut &bridge,
                    &signal,
                    &ShutdownToken::new(),
                );
                let _ = bridge.shutdown(Shutdown::Both);
                let _ = network.shutdown(Shutdown::Both);
                result
            })?;
        local.set_read_timeout(Some(timeout))?;
        local.set_write_timeout(Some(timeout))?;
        Ok(TlsBridge {
            stream: local,
            channel_binding,
            peer_certificate: None,
            stop,
            abort_network,
            worker: Some(worker),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ServerConfig, ServerConnection, StreamOwned};
    fn fixture(
        name: &str,
        accept: bool,
    ) -> (
        BackendTls,
        TcpStream,
        thread::JoinHandle<()>,
        std::path::PathBuf,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let path = std::env::temp_dir().join(format!(
            "pgproxy-backend-ca-{}-{}.pem",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, cert.cert.pem()).unwrap();
        let client = BackendTls::from_pem(&path, name, false).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let server = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert.cert.der().clone()], key.into())
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let network = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let worker = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0; 8];
            socket.read_exact(&mut request).unwrap();
            assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47]);
            socket.write_all(if accept { b"S" } else { b"N" }).unwrap();
            if !accept {
                return;
            }
            let tls = ServerConnection::new(server).unwrap();
            let mut stream = StreamOwned::new(tls, socket);
            let mut data = [0; 4];
            if stream.read_exact(&mut data).is_ok() {
                assert_eq!(&data, b"ping");
                stream.write_all(b"pong").unwrap();
                stream.flush().unwrap();
                let _ = stream.read(&mut data);
            }
        });
        (client, network, worker, path)
    }
    #[test]
    fn verified_hostname_tls_transports_bytes_and_binding() {
        let (tls, network, worker, path) = fixture("localhost", true);
        let bridge = tls.connect(network, Duration::from_secs(2)).unwrap();
        assert!(bridge.channel_binding.is_some());
        let mut stream = &bridge.stream;
        stream.write_all(b"ping").unwrap();
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"pong");
        drop(bridge);
        worker.join().unwrap();
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn hostname_mismatch_fails_closed() {
        let (tls, network, worker, path) = fixture("wrong.example", true);
        assert!(tls.connect(network, Duration::from_secs(2)).is_err());
        worker.join().unwrap();
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn refusal_never_falls_back_to_plaintext() {
        let (tls, network, worker, path) = fixture("localhost", false);
        assert!(
            tls.connect(network, Duration::from_secs(2))
                .err()
                .unwrap()
                .to_string()
                .contains("refused")
        );
        worker.join().unwrap();
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn stalled_handshake_is_bounded() {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let path =
            std::env::temp_dir().join(format!("pgproxy-timeout-ca-{}.pem", rand::random::<u64>()));
        std::fs::write(&path, certificate.cert.pem()).unwrap();
        let tls = BackendTls::from_pem(&path, "localhost", false).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let network = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 8];
            stream.read_exact(&mut request).unwrap();
            stream.write_all(b"S").unwrap();
            thread::sleep(Duration::from_millis(150));
        });
        let started = std::time::Instant::now();
        let error = tls
            .connect(network, Duration::from_millis(25))
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(125));
        worker.join().unwrap();
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn backend_mutual_tls_requires_the_verified_client_identity() {
        for present in [true, false] {
            let directory =
                std::env::temp_dir().join(format!("pgproxy-mtls-{}", rand::random::<u64>()));
            std::fs::create_dir(&directory).unwrap();
            let server_cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            std::fs::write(directory.join("server.pem"), server_cert.cert.pem()).unwrap();
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca = ca_params.self_signed(&ca_key).unwrap();
            let client_key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            let client_cert = params.signed_by(&client_key, &ca, &ca_key).unwrap();
            std::fs::write(directory.join("client.pem"), client_cert.pem()).unwrap();
            std::fs::write(directory.join("client-key.pem"), client_key.serialize_pem()).unwrap();
            let cert_path = directory.join("client.pem");
            let key_path = directory.join("client-key.pem");
            let tls = BackendTls::from_pem_with_identity(
                &directory.join("server.pem"),
                "localhost",
                false,
                present.then_some(cert_path.as_path()),
                present.then_some(key_path.as_path()),
            )
            .unwrap();
            let mut roots = RootCertStore::empty();
            roots.add(ca.der().clone()).unwrap();
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap();
            let config = Arc::new(
                ServerConfig::builder()
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(
                        vec![server_cert.cert.der().clone()],
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            server_cert.key_pair.serialize_der(),
                        )
                        .into(),
                    )
                    .unwrap(),
            );
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let network = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let worker = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0; 8];
                stream.read_exact(&mut request).unwrap();
                stream.write_all(b"S").unwrap();
                let mut encrypted =
                    StreamOwned::new(ServerConnection::new(config).unwrap(), stream);
                let mut bytes = [0; 4];
                if present {
                    encrypted.read_exact(&mut bytes).unwrap();
                    assert_eq!(&bytes, b"ping");
                    encrypted.write_all(b"pong").unwrap();
                    encrypted.flush().unwrap();
                    let _ = encrypted.read(&mut bytes);
                } else {
                    assert!(encrypted.read_exact(&mut bytes).is_err());
                }
            });
            let outcome = tls.connect(network, Duration::from_secs(2));
            if present {
                let bridge = outcome.unwrap();
                let mut stream = &bridge.stream;
                stream.write_all(b"ping").unwrap();
                let mut reply = [0; 4];
                stream.read_exact(&mut reply).unwrap();
                assert_eq!(&reply, b"pong");
            } else if let Ok(bridge) = outcome {
                let mut stream = &bridge.stream;
                let _ = stream.write_all(b"ping");
                let mut reply = [0; 4];
                assert!(stream.read_exact(&mut reply).is_err());
            }
            worker.join().unwrap();
            std::fs::remove_dir_all(directory).unwrap();
        }
    }
    #[test]
    fn client_identity_configuration_rejects_partial_and_mismatched_pairs() {
        let directory =
            std::env::temp_dir().join(format!("pgproxy-mtls-config-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other = rcgen::KeyPair::generate().unwrap();
        let certificate = directory.join("cert.pem");
        let key = directory.join("key.pem");
        std::fs::write(&certificate, cert.cert.pem()).unwrap();
        std::fs::write(&key, other.serialize_pem()).unwrap();
        assert!(
            BackendTls::from_pem_with_identity(
                &certificate,
                "localhost",
                false,
                Some(&certificate),
                None
            )
            .is_err()
        );
        assert!(
            BackendTls::from_pem_with_identity(
                &certificate,
                "localhost",
                false,
                Some(&certificate),
                Some(&key)
            )
            .is_err()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
