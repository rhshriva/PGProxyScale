//! Client authentication before any backend is opened.
use super::{
    AuthError, md5,
    messages::{self, AuthenticationRequest},
    scram::{MECHANISM, MECHANISM_PLUS, ScramServer, ScramVerifier},
};
use crate::{
    FrameReader, FrameWriter,
    protocol::{backend, frontend},
};
use rand::{RngCore, rngs::OsRng};
use std::collections::HashMap;
use std::io;

/// Stored verifier authentication. Trust must be explicitly selected by the operator.
#[derive(Clone, Default)]
pub enum ClientAuth {
    /// Authentication relayed to PostgreSQL (session mode only).
    #[default]
    Passthrough,
    /// No client password check.
    Trust,
    /// PostgreSQL MD5 hashes indexed by startup username.
    Md5(HashMap<String, String>),
    /// PostgreSQL SCRAM verifiers indexed by startup username.
    Scram(HashMap<String, ScramVerifier>),
    /// SHA256 fingerprints of CA-verified client certificates, indexed by username.
    Certificate(HashMap<String, Vec<u8>>),
}
impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Passthrough => "Passthrough",
            Self::Trust => "Trust",
            Self::Md5(_) => "Md5(<redacted>)",
            Self::Scram(_) => "Scram(<redacted>)",
            Self::Certificate(_) => "Certificate(<redacted>)",
        })
    }
}

fn failed() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "password authentication failed",
    )
}
fn auth_error(_: AuthError) -> io::Error {
    failed()
}
fn challenge<W: io::Write>(
    writer: &mut FrameWriter<W>,
    request: AuthenticationRequest,
) -> io::Result<()> {
    writer.write_message(backend::AUTHENTICATION, &request.to_payload())?;
    writer.flush()
}
fn password<R: io::Read>(reader: &mut FrameReader<R>) -> io::Result<Vec<u8>> {
    let frame = reader.read_message()?.ok_or_else(failed)?;
    if frame.tag != frontend::PASSWORD || frame.payload.len() > 8192 {
        return Err(failed());
    }
    Ok(frame.payload.to_vec())
}

/// Does not send AuthenticationOk: the caller completes startup after backend acquisition.
pub fn authenticate<R: io::Read, W: io::Write>(
    method: &ClientAuth,
    user: &str,
    reader: &mut FrameReader<R>,
    writer: &mut FrameWriter<W>,
) -> io::Result<()> {
    authenticate_secure(method, user, reader, writer, None, None)
}

pub fn authenticate_secure<R: io::Read, W: io::Write>(
    method: &ClientAuth,
    user: &str,
    reader: &mut FrameReader<R>,
    writer: &mut FrameWriter<W>,
    channel_binding: Option<&[u8]>,
    certificate: Option<&[u8]>,
) -> io::Result<()> {
    if user.is_empty() {
        return Err(failed());
    }
    match method {
        ClientAuth::Passthrough => Err(failed()),
        ClientAuth::Trust => Ok(()),
        ClientAuth::Certificate(users) => {
            if let (Some(expected), Some(actual)) = (users.get(user), certificate)
                && super::ct_eq(expected, actual)
            {
                Ok(())
            } else {
                Err(failed())
            }
        }
        ClientAuth::Md5(users) => {
            let mut salt = [0; 4];
            OsRng.fill_bytes(&mut salt);
            challenge(writer, AuthenticationRequest::Md5Password { salt })?;
            let response =
                messages::parse_password_message(&password(reader)?).map_err(auth_error)?;
            let dummy = md5::hash_password(b"nonexistent-user", user);
            let stored = users.get(user).unwrap_or(&dummy);
            if md5::verify(&response, stored, &salt).map_err(auth_error)?
                && users.contains_key(user)
            {
                Ok(())
            } else {
                Err(failed())
            }
        }
        ClientAuth::Scram(users) => {
            // Unknown users get the same protocol exchange, with a random, unusable secret.
            let verifier = match users.get(user) {
                Some(verifier) => verifier.clone(),
                None => {
                    let mut random = [0; 32];
                    OsRng.fill_bytes(&mut random);
                    ScramVerifier::generate(&random)
                }
            };
            challenge(
                writer,
                AuthenticationRequest::Sasl {
                    mechanisms: if channel_binding.is_some() {
                        vec![MECHANISM_PLUS.into(), MECHANISM.into()]
                    } else {
                        vec![MECHANISM.into()]
                    },
                },
            )?;
            let (mechanism, first) =
                messages::parse_sasl_response(&password(reader)?).map_err(auth_error)?;
            let plus = mechanism.as_deref() == Some(MECHANISM_PLUS);
            if mechanism.as_deref() != Some(MECHANISM) && !(plus && channel_binding.is_some()) {
                return Err(failed());
            }
            let mut server = ScramServer::new(verifier);
            if plus {
                server = server.with_channel_binding(channel_binding.unwrap().to_vec());
            }
            let first = std::str::from_utf8(&first).map_err(|_| failed())?;
            if channel_binding.is_some() && !plus && first.starts_with("y,,") {
                return Err(failed());
            }
            let server_first = server.handle_client_first(first).map_err(auth_error)?;
            challenge(
                writer,
                AuthenticationRequest::SaslContinue(server_first.into_bytes()),
            )?;
            let final_bytes = password(reader)?;
            let final_text = std::str::from_utf8(&final_bytes).map_err(|_| failed())?;
            let final_message = server.handle_client_final(final_text).map_err(auth_error)?;
            if !users.contains_key(user) {
                return Err(failed());
            }
            challenge(
                writer,
                AuthenticationRequest::SaslFinal(final_message.into_bytes()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::scram::ScramClient;
    use std::{
        net::{TcpListener, TcpStream},
        thread,
        time::Duration,
    };

    fn exchange(method: ClientAuth, user: &str, secret: &str, scram: bool) -> bool {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        server_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let user_owned = user.to_owned();
        let server = thread::spawn(move || {
            authenticate(
                &method,
                &user_owned,
                &mut FrameReader::new(server_stream.try_clone().unwrap()),
                &mut FrameWriter::new(server_stream),
            )
            .is_ok()
        });
        let mut reader = FrameReader::new(stream.try_clone().unwrap());
        let mut writer = FrameWriter::new(stream);
        let first =
            AuthenticationRequest::parse(reader.read_message().unwrap().unwrap().payload).unwrap();
        if scram {
            assert!(matches!(first, AuthenticationRequest::Sasl { .. }));
            let mut client = ScramClient::new(secret.as_bytes());
            let first = client.client_first();
            writer
                .write_message(
                    frontend::PASSWORD,
                    &messages::sasl_initial_response(MECHANISM, first.as_bytes()),
                )
                .unwrap();
            if let AuthenticationRequest::SaslContinue(data) =
                AuthenticationRequest::parse(reader.read_message().unwrap().unwrap().payload)
                    .unwrap()
            {
                let response = client
                    .handle_server_first(std::str::from_utf8(&data).unwrap())
                    .unwrap();
                writer
                    .write_message(frontend::PASSWORD, response.as_bytes())
                    .unwrap();
                if let Some(frame) = reader.read_message().unwrap() {
                    if let AuthenticationRequest::SaslFinal(data) =
                        AuthenticationRequest::parse(frame.payload).unwrap()
                    {
                        client
                            .handle_server_final(std::str::from_utf8(&data).unwrap())
                            .unwrap();
                    } else {
                        panic!("unexpected authentication message");
                    }
                }
            } else {
                panic!("missing SCRAM challenge");
            }
        } else if let AuthenticationRequest::Md5Password { salt } = first {
            let response =
                md5::response(&md5::hash_password(secret.as_bytes(), user), &salt).unwrap();
            writer
                .write_message(frontend::PASSWORD, &messages::password_message(&response))
                .unwrap();
        } else {
            panic!("missing MD5 challenge");
        }
        server.join().unwrap()
    }
    #[test]
    fn scram_accepts_only_the_configured_user_and_password() {
        let auth = ClientAuth::Scram(HashMap::from([(
            "alice".into(),
            ScramVerifier::generate(b"secret"),
        )]));
        assert!(exchange(auth.clone(), "alice", "secret", true));
        assert!(!exchange(auth.clone(), "alice", "wrong", true));
        assert!(!exchange(auth, "missing", "secret", true));
    }
    #[test]
    fn md5_accepts_only_the_configured_user_and_password() {
        let auth = ClientAuth::Md5(HashMap::from([(
            "alice".into(),
            md5::hash_password(b"secret", "alice"),
        )]));
        assert!(exchange(auth.clone(), "alice", "secret", false));
        assert!(!exchange(auth.clone(), "alice", "wrong", false));
        assert!(!exchange(auth, "missing", "secret", false));
    }
    #[test]
    fn secrets_are_redacted_and_passthrough_cannot_authenticate_locally() {
        let auth = ClientAuth::Md5(HashMap::from([("alice".into(), "secret".into())]));
        assert!(!format!("{auth:?}").contains("secret"));
        assert!(
            authenticate(
                &ClientAuth::Passthrough,
                "alice",
                &mut FrameReader::new(io::empty()),
                &mut FrameWriter::new(io::sink())
            )
            .is_err()
        );
    }
    #[test]
    fn certificate_auth_requires_the_verified_identity_of_the_startup_user() {
        let auth = ClientAuth::Certificate(HashMap::from([("alice".into(), vec![1; 32])]));
        for (user, certificate, expected) in [
            ("alice", Some(vec![1; 32]), true),
            ("alice", Some(vec![2; 32]), false),
            ("bob", Some(vec![1; 32]), false),
            ("alice", None, false),
        ] {
            assert_eq!(
                authenticate_secure(
                    &auth,
                    user,
                    &mut FrameReader::new(io::empty()),
                    &mut FrameWriter::new(io::sink()),
                    None,
                    certificate.as_deref()
                )
                .is_ok(),
                expected
            );
        }
    }
}
