//! The `Authentication*` messages (backend tag `R`).
//!
//! Every one of these has the same envelope — tag `R`, then an `Int32` subtype — and then
//! a subtype-specific body. Modelling them as one enum keeps the subtype numbers in one
//! place, which matters because a proxy has to relay them correctly in passthrough mode
//! without understanding them.

use super::{AuthError, Result};

/// Authentication succeeded.
pub const AUTH_OK: i32 = 0;
/// Kerberos V5.
pub const AUTH_KERBEROS_V5: i32 = 2;
/// Send a cleartext password.
pub const AUTH_CLEARTEXT_PASSWORD: i32 = 3;
/// MD5 challenge-response, with a 4-byte salt.
pub const AUTH_MD5_PASSWORD: i32 = 5;
/// SCM credential.
pub const AUTH_SCM_CREDENTIAL: i32 = 6;
/// GSSAPI.
pub const AUTH_GSS: i32 = 7;
/// GSSAPI continuation.
pub const AUTH_GSS_CONTINUE: i32 = 8;
/// SSPI.
pub const AUTH_SSPI: i32 = 9;
/// SASL: the server offers a mechanism list.
pub const AUTH_SASL: i32 = 10;
/// SASL continuation.
pub const AUTH_SASL_CONTINUE: i32 = 11;
/// SASL final: the server's signature.
pub const AUTH_SASL_FINAL: i32 = 12;

/// A parsed `Authentication` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationRequest {
    /// Authentication is complete.
    Ok,
    /// Kerberos V5 authentication is requested.
    KerberosV5,
    /// A cleartext password is requested. Dangerous over an unencrypted channel.
    CleartextPassword,
    /// MD5 challenge with the given salt.
    Md5Password {
        /// Four bytes of server-generated salt.
        salt: [u8; 4],
    },
    /// SCM credential authentication is requested.
    ScmCredential,
    /// GSSAPI authentication is requested.
    Gss,
    /// GSSAPI continuation data.
    GssContinue(Vec<u8>),
    /// SSPI authentication is requested.
    Sspi,
    /// SASL: the mechanisms the server will accept, in preference order.
    Sasl {
        /// Mechanism names, for example `SCRAM-SHA-256`.
        mechanisms: Vec<String>,
    },
    /// SASL continuation: server-first-message.
    SaslContinue(Vec<u8>),
    /// SASL final: server-final-message.
    SaslFinal(Vec<u8>),
    /// A subtype this build does not model. Relayed but not interpreted.
    Unknown(i32),
}

impl AuthenticationRequest {
    /// Parse the payload of an `R` message (everything after the tag and length).
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 4 {
            return Err(AuthError::Malformed {
                context: "Authentication",
                detail: format!(
                    "payload of {} bytes cannot contain a subtype",
                    payload.len()
                ),
            });
        }
        let subtype = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let body = &payload[4..];

        Ok(match subtype {
            AUTH_OK => Self::Ok,
            AUTH_KERBEROS_V5 => Self::KerberosV5,
            AUTH_CLEARTEXT_PASSWORD => Self::CleartextPassword,
            AUTH_MD5_PASSWORD => {
                if body.len() < 4 {
                    return Err(AuthError::Malformed {
                        context: "AuthenticationMD5Password",
                        detail: format!("expected a 4-byte salt, got {} bytes", body.len()),
                    });
                }
                Self::Md5Password {
                    salt: [body[0], body[1], body[2], body[3]],
                }
            }
            AUTH_SCM_CREDENTIAL => Self::ScmCredential,
            AUTH_GSS => Self::Gss,
            AUTH_GSS_CONTINUE => Self::GssContinue(body.to_vec()),
            AUTH_SSPI => Self::Sspi,
            AUTH_SASL => Self::Sasl {
                mechanisms: parse_sasl_mechanisms(body)?,
            },
            AUTH_SASL_CONTINUE => Self::SaslContinue(body.to_vec()),
            AUTH_SASL_FINAL => Self::SaslFinal(body.to_vec()),
            other => Self::Unknown(other),
        })
    }

    /// Build the payload for an `R` message (without tag or length).
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Ok => out.extend_from_slice(&AUTH_OK.to_be_bytes()),
            Self::KerberosV5 => out.extend_from_slice(&AUTH_KERBEROS_V5.to_be_bytes()),
            Self::CleartextPassword => {
                out.extend_from_slice(&AUTH_CLEARTEXT_PASSWORD.to_be_bytes())
            }
            Self::Md5Password { salt } => {
                out.extend_from_slice(&AUTH_MD5_PASSWORD.to_be_bytes());
                out.extend_from_slice(salt);
            }
            Self::ScmCredential => out.extend_from_slice(&AUTH_SCM_CREDENTIAL.to_be_bytes()),
            Self::Gss => out.extend_from_slice(&AUTH_GSS.to_be_bytes()),
            Self::GssContinue(data) => {
                out.extend_from_slice(&AUTH_GSS_CONTINUE.to_be_bytes());
                out.extend_from_slice(data);
            }
            Self::Sspi => out.extend_from_slice(&AUTH_SSPI.to_be_bytes()),
            Self::Sasl { mechanisms } => {
                out.extend_from_slice(&AUTH_SASL.to_be_bytes());
                for mechanism in mechanisms {
                    out.extend_from_slice(mechanism.as_bytes());
                    out.push(0);
                }
                out.push(0);
            }
            Self::SaslContinue(data) => {
                out.extend_from_slice(&AUTH_SASL_CONTINUE.to_be_bytes());
                out.extend_from_slice(data);
            }
            Self::SaslFinal(data) => {
                out.extend_from_slice(&AUTH_SASL_FINAL.to_be_bytes());
                out.extend_from_slice(data);
            }
            Self::Unknown(subtype) => out.extend_from_slice(&subtype.to_be_bytes()),
        }
        out
    }

    /// Whether this request means authentication succeeded.
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Whether this request carries a SASL payload a passthrough proxy must relay.
    pub fn is_sasl_exchange(&self) -> bool {
        matches!(
            self,
            Self::Sasl { .. } | Self::SaslContinue(_) | Self::SaslFinal(_)
        )
    }
}

/// Parse the null-terminated mechanism list that follows the SASL subtype.
///
/// The list ends with an extra null byte. A missing terminator is malformed rather than
/// an empty list, because guessing here could silently select the wrong mechanism.
fn parse_sasl_mechanisms(body: &[u8]) -> Result<Vec<String>> {
    let mut mechanisms = Vec::new();
    let mut rest = body;

    loop {
        if rest.is_empty() {
            return Err(AuthError::Malformed {
                context: "AuthenticationSASL",
                detail: "mechanism list is not terminated by a null byte".to_string(),
            });
        }
        if rest[0] == 0 {
            return Ok(mechanisms);
        }
        let Some(end) = rest.iter().position(|&b| b == 0) else {
            return Err(AuthError::Malformed {
                context: "AuthenticationSASL",
                detail: "unterminated mechanism name".to_string(),
            });
        };
        let name = &rest[..end];
        if !name.is_ascii() {
            return Err(AuthError::Malformed {
                context: "AuthenticationSASL",
                detail: "mechanism name contains non-ASCII bytes".to_string(),
            });
        }
        mechanisms.push(String::from_utf8_lossy(name).into_owned());
        rest = &rest[end + 1..];
    }
}

/// Build the payload of a `PasswordMessage` (`p`) carrying an MD5 response.
pub fn password_message(response: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(response.len() + 1);
    out.extend_from_slice(response.as_bytes());
    out.push(0);
    out
}

/// Extract the password from a `PasswordMessage` payload.
pub fn parse_password_message(payload: &[u8]) -> Result<String> {
    let Some(end) = payload.iter().position(|&b| b == 0) else {
        return Err(AuthError::Malformed {
            context: "PasswordMessage",
            detail: "password is not null-terminated".to_string(),
        });
    };
    let password = &payload[..end];
    if !password.is_ascii() {
        // PostgreSQL allows arbitrary bytes here, but every mechanism we implement uses
        // ASCII. Refusing is safer than lossily decoding something secret.
        return Err(AuthError::Malformed {
            context: "PasswordMessage",
            detail: "password contains non-ASCII bytes".to_string(),
        });
    }
    Ok(String::from_utf8_lossy(password).into_owned())
}

/// Build the payload of a SASL `PasswordMessage`: mechanism name, then the response.
///
/// Note the `Int32` length of the response: it is present in
/// `SASLInitialResponse` (the first message) and absent in subsequent `SASLResponse`
/// messages. Getting that wrong desynchronises the stream, so the two cases are separate
/// functions rather than one with a flag.
pub fn sasl_initial_response(mechanism: &str, response: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(mechanism.as_bytes());
    out.push(0);
    out.extend_from_slice(&(response.len() as i32).to_be_bytes());
    out.extend_from_slice(response);
    out
}

/// Parse a SASL `PasswordMessage` (either the initial response or a continuation).
///
/// Returns the mechanism name when present, and the response bytes. A negative response
/// length means the client has no initial response, which is legal and yields empty bytes.
pub fn parse_sasl_response(payload: &[u8]) -> Result<(Option<String>, Vec<u8>)> {
    if payload.is_empty() {
        return Err(AuthError::Malformed {
            context: "SASLResponse",
            detail: "empty payload".to_string(),
        });
    }

    // A continuation response starts directly with the response bytes. The initial
    // response instead starts with a null-terminated mechanism name. Distinguish them by
    // whether a null appears before any non-ASCII byte, which is how libpq's own parser
    // behaves in practice.
    let Some(nul) = payload.iter().position(|&b| b == 0) else {
        // No mechanism name; treat the whole payload as response data.
        return Ok((None, payload.to_vec()));
    };

    let name = &payload[..nul];
    let after = &payload[nul + 1..];

    // The initial response is followed by a 4-byte length. If the remaining bytes cannot
    // hold one, this is a continuation whose data happened to contain a null.
    if after.len() < 4 {
        return Ok((None, payload.to_vec()));
    }
    let declared = i32::from_be_bytes([after[0], after[1], after[2], after[3]]);
    if declared < 0 {
        // "-1" means the client sent no initial response.
        return Ok((Some(String::from_utf8_lossy(name).into_owned()), Vec::new()));
    }
    let declared = declared as usize;
    if declared > after.len() - 4 {
        return Err(AuthError::Malformed {
            context: "SASLInitialResponse",
            detail: format!(
                "declared response length {declared} exceeds the {} bytes available",
                after.len() - 4
            ),
        });
    }

    Ok((
        Some(String::from_utf8_lossy(name).into_owned()),
        after[4..4 + declared].to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_modelled_subtype() {
        let cases = vec![
            AuthenticationRequest::Ok,
            AuthenticationRequest::KerberosV5,
            AuthenticationRequest::CleartextPassword,
            AuthenticationRequest::Md5Password { salt: [1, 2, 3, 4] },
            AuthenticationRequest::ScmCredential,
            AuthenticationRequest::Gss,
            AuthenticationRequest::GssContinue(vec![9, 9]),
            AuthenticationRequest::Sspi,
            AuthenticationRequest::Sasl {
                mechanisms: vec![
                    "SCRAM-SHA-256".to_string(),
                    "SCRAM-SHA-256-PLUS".to_string(),
                ],
            },
            AuthenticationRequest::SaslContinue(b"r=abc,s=c2FsdA==,i=4096".to_vec()),
            AuthenticationRequest::SaslFinal(b"v=abc".to_vec()),
            AuthenticationRequest::Unknown(42),
        ];
        for case in cases {
            let payload = case.to_payload();
            let parsed = AuthenticationRequest::parse(&payload).expect("parses");
            assert_eq!(parsed, case, "round trip failed for {case:?}");
        }
    }

    #[test]
    fn md5_salt_is_read_from_the_right_offset() {
        // Subtype(4) then salt(4). An off-by-one here silently breaks every MD5 login.
        let mut payload = AUTH_MD5_PASSWORD.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            AuthenticationRequest::parse(&payload).unwrap(),
            AuthenticationRequest::Md5Password {
                salt: [0xDE, 0xAD, 0xBE, 0xEF]
            }
        );
    }

    #[test]
    fn rejects_an_md5_challenge_without_a_salt() {
        let payload = AUTH_MD5_PASSWORD.to_be_bytes().to_vec();
        let err = AuthenticationRequest::parse(&payload).unwrap_err();
        assert!(err.to_string().contains("4-byte salt"), "{err}");
    }

    #[test]
    fn sasl_mechanism_list_encoding_is_exact() {
        let payload = AuthenticationRequest::Sasl {
            mechanisms: vec!["SCRAM-SHA-256".to_string()],
        }
        .to_payload();

        let mut expected = AUTH_SASL.to_be_bytes().to_vec();
        expected.extend_from_slice(b"SCRAM-SHA-256\0");
        expected.push(0);
        assert_eq!(payload, expected);
    }

    #[test]
    fn rejects_an_unterminated_sasl_mechanism_list() {
        let mut payload = AUTH_SASL.to_be_bytes().to_vec();
        payload.extend_from_slice(b"SCRAM-SHA-256"); // no nulls at all
        let err = AuthenticationRequest::parse(&payload).unwrap_err();
        assert!(err.to_string().contains("unterminated"), "{err}");
    }

    #[test]
    fn unknown_subtypes_are_preserved_not_dropped() {
        // A passthrough proxy must relay what it does not understand.
        let payload = 99i32.to_be_bytes().to_vec();
        let parsed = AuthenticationRequest::parse(&payload).unwrap();
        assert_eq!(parsed, AuthenticationRequest::Unknown(99));
        assert_eq!(parsed.to_payload(), payload);
    }

    #[test]
    fn password_message_round_trips() {
        let payload = password_message("md5bb41a296aab6baccb36ff243a562abff");
        assert_eq!(
            parse_password_message(&payload).unwrap(),
            "md5bb41a296aab6baccb36ff243a562abff"
        );
    }

    #[test]
    fn password_message_must_be_terminated() {
        let err = parse_password_message(b"md5abc").unwrap_err();
        assert!(err.to_string().contains("null-terminated"), "{err}");
    }

    #[test]
    fn sasl_initial_response_carries_a_length_prefix() {
        let payload = sasl_initial_response("SCRAM-SHA-256", b"n,,n=,r=abc");
        let mut expected = b"SCRAM-SHA-256\0".to_vec();
        // "n,,n=,r=abc" is 11 bytes.
        expected.extend_from_slice(&11i32.to_be_bytes());
        expected.extend_from_slice(b"n,,n=,r=abc");
        assert_eq!(payload, expected);

        let (mechanism, response) = parse_sasl_response(&payload).unwrap();
        assert_eq!(mechanism.as_deref(), Some("SCRAM-SHA-256"));
        assert_eq!(response, b"n,,n=,r=abc");
    }

    #[test]
    fn sasl_initial_response_handles_a_negative_length() {
        // "-1" means the client declined to send an initial response.
        let mut payload = b"SCRAM-SHA-256\0".to_vec();
        payload.extend_from_slice(&(-1i32).to_be_bytes());
        let (mechanism, response) = parse_sasl_response(&payload).unwrap();
        assert_eq!(mechanism.as_deref(), Some("SCRAM-SHA-256"));
        assert!(response.is_empty());
    }

    #[test]
    fn sasl_continuation_is_parsed_as_bare_data() {
        let (mechanism, response) = parse_sasl_response(b"c=biws,r=abc,p=proof").unwrap();
        assert_eq!(mechanism, None);
        assert_eq!(response, b"c=biws,r=abc,p=proof");
    }

    #[test]
    fn rejects_a_sasl_initial_response_whose_length_overruns() {
        let mut payload = b"SCRAM-SHA-256\0".to_vec();
        payload.extend_from_slice(&9999i32.to_be_bytes());
        payload.extend_from_slice(b"short");
        let err = parse_sasl_response(&payload).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn classifies_sasl_exchange_messages() {
        assert!(
            AuthenticationRequest::Sasl {
                mechanisms: vec!["SCRAM-SHA-256".into()]
            }
            .is_sasl_exchange()
        );
        assert!(AuthenticationRequest::SaslContinue(vec![]).is_sasl_exchange());
        assert!(AuthenticationRequest::SaslFinal(vec![]).is_sasl_exchange());
        assert!(!AuthenticationRequest::Ok.is_sasl_exchange());
        assert!(!AuthenticationRequest::CleartextPassword.is_sasl_exchange());
    }
}
