//! The startup phase: the one untyped message in the protocol.
//!
//! Shape: `Int32 length`, `Int32 code`, then either a list of null-terminated
//! key/value pairs (a normal startup) or nothing further (the special requests).
//!
//! Two details matter more than they look:
//!
//! * **`CancelRequest` keys are variable length as of protocol 3.2 (PostgreSQL 18).**
//!   In 3.0 the key is a fixed 4-byte integer, giving a 16-byte message. Every current
//!   proxy assumes the fixed size, which is why PgBouncer's `[peers]` cancellation
//!   forwarding is version-sensitive. [`CancelRequest::key`] is therefore a byte slice,
//!   not an integer.
//! * **`options` smuggles GUCs into the startup packet** (`PGOPTIONS`, or libpq's
//!   `options`). Spike S2 found 144 client-settable GUCs that the server never reports
//!   back, so anything arriving here must be captured rather than dropped — which is
//!   exactly what PgBouncer's `ignore_startup_parameters` does. [`StartupParams::options`]
//!   parses it.

use std::io;

use super::{CANCEL_REQUEST_CODE, GSSENC_REQUEST_CODE, PROTOCOL_3_0, SSL_REQUEST_CODE};

/// Prefix PostgreSQL uses for future protocol negotiation ("protocol grease").
///
/// A startup packet beginning with this is not a version we can parse. Detecting it
/// produces a clear error instead of a confusing parse failure.
pub const PROTOCOL_GREASE_PREFIX: &[u8] = b"_pq_.";

/// What the client sent in place of a normal startup message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupRequest {
    /// A normal startup: protocol version plus connection parameters.
    Startup(StartupParams),
    /// The client wants to negotiate TLS. Reply with a single byte, `S` or `N`.
    SslRequest,
    /// The client wants to negotiate GSSAPI encryption.
    GssEncRequest,
    /// The client wants to cancel a running query.
    CancelRequest(CancelRequest),
}

/// A parsed normal startup message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupParams {
    /// Protocol version the client asked for, encoded as `major << 16 | minor`.
    pub protocol_version: i32,
    /// Parameters in the order the client sent them. Values stay as bytes: the protocol
    /// does not guarantee UTF-8, and comparing a database name must be exact.
    entries: Vec<(String, Vec<u8>)>,
}

impl StartupParams {
    /// Look up a parameter, returning it only if it is valid UTF-8.
    ///
    /// Suitable for parameters the protocol defines as text (`user`, `database`, ...).
    pub fn get(&self, key: &str) -> Option<&str> {
        self.get_bytes(key)
            .and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Look up a parameter as raw bytes.
    ///
    /// Use this for anything used in a security decision, so that a non-UTF-8 value
    /// cannot be silently normalised into something that compares equal.
    pub fn get_bytes(&self, key: &str) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }

    /// All parameters, in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    /// Number of parameters.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no parameters.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Parse startup GUC switches, returning no settings on malformed input.
    /// Use `checked_options` when the proxy terminates startup instead of forwarding it.
    pub fn options(&self) -> Vec<(String, String)> {
        self.checked_options().unwrap_or_default()
    }

    /// Parse every startup option or reject the entire string. PostgreSQL splits
    /// ASCII whitespace and permits backslash escapes, not shell quote syntax.
    /// Only GUC switches can be represented safely by the transaction ledger.
    pub fn checked_options(&self) -> io::Result<Vec<(String, String)>> {
        let Some(raw) = self.get_bytes("options") else {
            return Ok(Vec::new());
        };
        let text = std::str::from_utf8(raw)
            .map_err(|_| invalid_data("startup options require UTF8".to_string()))?;
        let mut tokens = Vec::new();
        let mut token = String::new();
        let mut escaped = false;
        for ch in text.chars() {
            if escaped {
                token.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch.is_ascii_whitespace() {
                if !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            } else {
                token.push(ch);
            }
        }
        // PostgreSQL drops a trailing escape when splitting an option.
        if !token.is_empty() {
            tokens.push(token);
        }
        let mut tokens = tokens.into_iter();
        let mut out = Vec::new();
        while let Some(token) = tokens.next() {
            let setting = if token == "-c" {
                tokens
                    .next()
                    .ok_or_else(|| invalid_data("missing startup setting".to_string()))?
            } else if let Some(rest) = token
                .strip_prefix("-c")
                .or_else(|| token.strip_prefix("--"))
            {
                rest.to_string()
            } else {
                return Err(invalid_data("unsupported startup option".to_string()));
            };
            let (name, value) = setting
                .split_once('=')
                .filter(|(name, _)| !name.is_empty())
                .ok_or_else(|| invalid_data("invalid startup setting".to_string()))?;
            out.push((name.to_string(), value.to_string()));
        }
        Ok(out)
    }

    /// Whether the client negotiated protocol 3.0 exactly.
    pub fn is_protocol_3_0(&self) -> bool {
        self.protocol_version == PROTOCOL_3_0
    }
}

/// A request to cancel whichever query belongs to a given backend key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelRequest {
    /// Backend process id the client wants to cancel.
    pub process_id: i32,
    /// Key material.
    ///
    /// Four bytes in protocol 3.0. Variable length, up to 256 bits, as of protocol 3.2
    /// (PostgreSQL 18) — which is why this is bytes rather than an `i32`.
    pub key: Vec<u8>,
}

impl CancelRequest {
    /// The 3.0 secret key, when the key is the historical 4-byte form.
    pub fn secret_v3_0(&self) -> Option<i32> {
        if self.key.len() == 4 {
            Some(i32::from_be_bytes([
                self.key[0],
                self.key[1],
                self.key[2],
                self.key[3],
            ]))
        } else {
            None
        }
    }
}

/// Parse the body of a startup message (everything after the 4-byte length).
pub fn parse_startup(body: &[u8]) -> io::Result<StartupRequest> {
    if body.len() < 4 {
        return Err(invalid_data(format!(
            "startup body of {} bytes cannot contain a code",
            body.len()
        )));
    }

    if body.starts_with(PROTOCOL_GREASE_PREFIX) {
        return Err(invalid_data(
            "client attempted protocol negotiation (_pq_.), which is not supported".to_string(),
        ));
    }

    let code = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    match code {
        SSL_REQUEST_CODE => {
            require_length(body, 4, "SSLRequest")?;
            Ok(StartupRequest::SslRequest)
        }
        GSSENC_REQUEST_CODE => {
            require_length(body, 4, "GSSENCRequest")?;
            Ok(StartupRequest::GssEncRequest)
        }
        CANCEL_REQUEST_CODE => {
            let rest = &body[4..];
            if rest.len() < 8 {
                return Err(invalid_data(format!(
                    "CancelRequest body of {} bytes is too short for a process id and key",
                    rest.len()
                )));
            }
            let process_id = i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            Ok(StartupRequest::CancelRequest(CancelRequest {
                process_id,
                key: rest[4..].to_vec(),
            }))
        }
        version if (version >> 16) == 3 => Ok(StartupRequest::Startup(StartupParams {
            protocol_version: version,
            entries: parse_parameters(&body[4..])?,
        })),
        version => Err(invalid_data(format!(
            "unsupported frontend protocol {}.{}: this proxy requires 3.0 or later",
            version >> 16,
            version & 0xffff
        ))),
    }
}

fn require_length(body: &[u8], expected: usize, name: &str) -> io::Result<()> {
    if body.len() != expected {
        return Err(invalid_data(format!(
            "{name} body must be exactly {expected} bytes, got {}",
            body.len()
        )));
    }
    Ok(())
}

/// Parse the null-terminated key/value list that ends with an extra null.
fn parse_parameters(mut rest: &[u8]) -> io::Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();

    loop {
        if rest.is_empty() {
            return Err(invalid_data(
                "startup parameters are not terminated by a null byte".to_string(),
            ));
        }
        if rest[0] == 0 {
            if rest.len() != 1 {
                return Err(invalid_data(format!(
                    "{} trailing bytes after the startup terminator",
                    rest.len() - 1
                )));
            }
            return Ok(out);
        }

        let (key_bytes, after_key) = split_nul(rest, "parameter name")?;
        let (value, after_value) = split_nul(after_key, "parameter value")?;

        // Keys are ASCII identifiers by protocol; rejecting non-ASCII keeps the exact
        // byte comparison above meaningful.
        if !key_bytes.is_ascii() {
            return Err(invalid_data(
                "startup parameter name contains non-ASCII bytes".to_string(),
            ));
        }
        out.push((
            String::from_utf8_lossy(key_bytes).into_owned(),
            value.to_vec(),
        ));

        rest = after_value;
    }
}

/// Split at the first null byte, returning the part before it and the part after it.
fn split_nul<'a>(bytes: &'a [u8], what: &str) -> io::Result<(&'a [u8], &'a [u8])> {
    match bytes.iter().position(|&b| b == 0) {
        Some(index) => Ok((&bytes[..index], &bytes[index + 1..])),
        None => Err(invalid_data(format!(
            "unterminated {what} in startup packet"
        ))),
    }
}

fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{PROTOCOL_3_0, PROTOCOL_3_2};

    fn startup_body(version: i32, params: &[(&str, &str)]) -> Vec<u8> {
        let mut body = version.to_be_bytes().to_vec();
        for (k, v) in params {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }
        body.push(0);
        body
    }

    #[test]
    fn parses_a_normal_startup() {
        let body = startup_body(PROTOCOL_3_0, &[("user", "postgres"), ("database", "app")]);
        match parse_startup(&body).unwrap() {
            StartupRequest::Startup(p) => {
                assert!(p.is_protocol_3_0());
                assert_eq!(p.get("user"), Some("postgres"));
                assert_eq!(p.get("database"), Some("app"));
                assert_eq!(p.len(), 2);
                assert!(p.get("absent").is_none());
            }
            other => panic!("expected Startup, got {other:?}"),
        }
    }

    #[test]
    fn parses_protocol_3_2() {
        let body = startup_body(PROTOCOL_3_2, &[("user", "postgres")]);
        match parse_startup(&body).unwrap() {
            StartupRequest::Startup(p) => {
                assert_eq!(p.protocol_version, PROTOCOL_3_2);
                assert!(!p.is_protocol_3_0());
            }
            other => panic!("expected Startup, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_protocol_major() {
        let body = startup_body(4 << 16, &[("user", "postgres")]);
        assert!(parse_startup(&body).is_err());
    }

    #[test]
    fn accepts_a_startup_with_no_parameters() {
        // length 8: version then the single terminator null.
        let body = startup_body(PROTOCOL_3_0, &[]);
        match parse_startup(&body).unwrap() {
            StartupRequest::Startup(p) => assert!(p.is_empty()),
            other => panic!("expected Startup, got {other:?}"),
        }
    }

    #[test]
    fn recognises_ssl_and_gssenc_requests() {
        assert_eq!(
            parse_startup(&SSL_REQUEST_CODE.to_be_bytes()).unwrap(),
            StartupRequest::SslRequest
        );
        assert_eq!(
            parse_startup(&GSSENC_REQUEST_CODE.to_be_bytes()).unwrap(),
            StartupRequest::GssEncRequest
        );
    }

    #[test]
    fn rejects_ssl_request_with_trailing_bytes() {
        let mut body = SSL_REQUEST_CODE.to_be_bytes().to_vec();
        body.push(0);
        let err = parse_startup(&body).unwrap_err();
        assert!(err.to_string().contains("exactly 4 bytes"), "{err}");
    }

    #[test]
    fn parses_a_protocol_3_0_cancel_request() {
        // The 3.0 secret is an opaque 32-bit value, not a signed quantity.
        const SECRET: u32 = 0xDEAD_BEEF;

        // code, process id, 4-byte secret
        let mut body = CANCEL_REQUEST_CODE.to_be_bytes().to_vec();
        body.extend_from_slice(&4242i32.to_be_bytes());
        body.extend_from_slice(&SECRET.to_be_bytes());

        match parse_startup(&body).unwrap() {
            StartupRequest::CancelRequest(c) => {
                assert_eq!(c.process_id, 4242);
                assert_eq!(c.key.len(), 4);
                assert_eq!(c.secret_v3_0().map(|s| s as u32), Some(SECRET));
            }
            other => panic!("expected CancelRequest, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_protocol_3_2_cancel_request_with_a_variable_length_key() {
        // PostgreSQL 18 allows keys up to 256 bits. A proxy that assumes 4 bytes here
        // will mis-parse the message and drop the cancellation.
        let mut body = CANCEL_REQUEST_CODE.to_be_bytes().to_vec();
        body.extend_from_slice(&7i32.to_be_bytes());
        let key: Vec<u8> = (0..32).collect();
        body.extend_from_slice(&key);

        match parse_startup(&body).unwrap() {
            StartupRequest::CancelRequest(c) => {
                assert_eq!(c.process_id, 7);
                assert_eq!(c.key, key);
                assert_eq!(c.secret_v3_0(), None, "a 32-byte key is not a 3.0 secret");
            }
            other => panic!("expected CancelRequest, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_cancel_request_without_a_key() {
        let mut body = CANCEL_REQUEST_CODE.to_be_bytes().to_vec();
        body.extend_from_slice(&7i32.to_be_bytes());
        let err = parse_startup(&body).unwrap_err();
        assert!(err.to_string().contains("too short"), "{err}");
    }

    #[test]
    fn rejects_pre_3_0_protocols() {
        // Protocol 2.0.
        let body = startup_body(2 << 16, &[("user", "postgres")]);
        let err = parse_startup(&body).unwrap_err();
        assert!(
            err.to_string().contains("unsupported frontend protocol"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unterminated_parameters() {
        let mut body = PROTOCOL_3_0.to_be_bytes().to_vec();
        body.extend_from_slice(b"user\0postgres\0"); // no final terminator
        let err = parse_startup(&body).unwrap_err();
        assert!(err.to_string().contains("not terminated"), "{err}");
    }

    #[test]
    fn rejects_trailing_bytes_after_the_terminator() {
        let mut body = startup_body(PROTOCOL_3_0, &[("user", "postgres")]);
        body.push(0xFF);
        let err = parse_startup(&body).unwrap_err();
        assert!(err.to_string().contains("trailing bytes"), "{err}");
    }

    #[test]
    fn rejects_an_empty_parameter_name() {
        // A zero-length key is malformed; the leading null is the terminator, so this
        // actually parses as an empty parameter list only if the next byte is null too.
        let mut body = PROTOCOL_3_0.to_be_bytes().to_vec();
        body.extend_from_slice(b"\0");
        // This is a legal empty parameter list, not an error.
        match parse_startup(&body).unwrap() {
            StartupRequest::Startup(p) => assert!(p.is_empty()),
            other => panic!("expected Startup, got {other:?}"),
        }
    }

    #[test]
    fn rejects_protocol_negotiation_prefix() {
        let mut body = PROTOCOL_GREASE_PREFIX.to_vec();
        body.extend_from_slice(b"3.0\0");
        let err = parse_startup(&body).unwrap_err();
        assert!(err.to_string().contains("protocol negotiation"), "{err}");
    }

    #[test]
    fn rejects_a_truncated_body() {
        let err = parse_startup(&[0, 0]).unwrap_err();
        assert!(err.to_string().contains("cannot contain a code"), "{err}");
    }

    #[test]
    fn non_utf8_values_are_preserved_exactly_but_not_returned_as_str() {
        let mut body = PROTOCOL_3_0.to_be_bytes().to_vec();
        body.extend_from_slice(b"database\0");
        body.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        body.push(0);
        body.push(0);

        match parse_startup(&body).unwrap() {
            StartupRequest::Startup(p) => {
                assert_eq!(
                    p.get("database"),
                    None,
                    "invalid UTF-8 must not be lossily decoded"
                );
                assert_eq!(p.get_bytes("database"), Some(&[0xFF, 0xFE][..]));
            }
            other => panic!("expected Startup, got {other:?}"),
        }
    }

    #[test]
    fn parses_gucs_out_of_the_options_parameter() {
        // The case PgBouncer's ignore_startup_parameters silently drops.
        let body = startup_body(
            PROTOCOL_3_0,
            &[
                ("user", "postgres"),
                (
                    "options",
                    "-c statement_timeout=5000 -c search_path=tenant_a",
                ),
            ],
        );
        match parse_startup(&body).unwrap() {
            StartupRequest::Startup(p) => {
                let opts = p.options();
                assert_eq!(
                    opts,
                    vec![
                        ("statement_timeout".to_string(), "5000".to_string()),
                        ("search_path".to_string(), "tenant_a".to_string()),
                    ]
                );
            }
            other => panic!("expected Startup, got {other:?}"),
        }
    }

    #[test]
    fn parses_options_in_all_supported_shapes() {
        for (input, expected) in [
            ("-c a=1", vec![("a", "1")]),
            ("-ca=1", vec![("a", "1")]),
            ("--a=1", vec![("a", "1")]),
            ("-c a=1 -c b=2", vec![("a", "1"), ("b", "2")]),
            ("--a=1 --b=2", vec![("a", "1"), ("b", "2")]),
            ("-c", vec![]),
            ("nonsense", vec![]),
        ] {
            let body = startup_body(PROTOCOL_3_0, &[("options", input)]);
            let StartupRequest::Startup(p) = parse_startup(&body).unwrap() else {
                panic!("expected Startup");
            };
            let opts = p.options();
            let got: Vec<(&str, &str)> =
                opts.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            assert_eq!(got, expected, "input {input:?}");
        }
    }

    #[test]
    fn options_is_empty_when_absent() {
        let body = startup_body(PROTOCOL_3_0, &[("user", "postgres")]);
        let StartupRequest::Startup(p) = parse_startup(&body).unwrap() else {
            panic!("expected Startup");
        };
        assert!(p.options().is_empty());
    }
    #[test]
    fn startup_options_are_atomic_and_preserve_escapes() {
        for (input, expected) in [
            (r"-c application_name=hello\ world", "hello world"),
            (r"-c application_name=hello\\world", r"hello\world"),
            (r"-c application_name='hello'", "'hello'"),
            ("-c application_name=", ""),
        ] {
            let body = startup_body(PROTOCOL_3_0, &[("options", input)]);
            let StartupRequest::Startup(p) = parse_startup(&body).unwrap() else {
                panic!()
            };
            assert_eq!(
                p.checked_options().unwrap(),
                vec![("application_name".to_string(), expected.to_string())]
            );
        }
        for input in [
            "-c application_name=ok nonsense",
            "-c application_name=ok -c",
            "--",
            "-c =value",
            "-c missing",
        ] {
            let body = startup_body(PROTOCOL_3_0, &[("options", input)]);
            let StartupRequest::Startup(p) = parse_startup(&body).unwrap() else {
                panic!()
            };
            assert!(p.checked_options().is_err(), "{input}");
            assert!(p.options().is_empty(), "must not partially apply {input}");
        }
    }
}
