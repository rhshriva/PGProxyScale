//! SCRAM-SHA-256 (RFC 5802, RFC 7677), both directions.
//!
//! Why both: a proxy must be able to *terminate* authentication (verify the client
//! itself) and to *originate* it (authenticate to the backend). Passthrough relays these
//! messages without interpreting them, but the moment the policy engine wants to reject a
//! client before touching a backend, or the proxy needs a verified principal, it must
//! speak the protocol rather than forward it.
//!
//! ## The exchange
//!
//! ```text
//! S: AuthenticationSASL          mechanisms: SCRAM-SHA-256
//! C: SASLInitialResponse         n,,n=,r=<client nonce>
//! S: AuthenticationSASLContinue  r=<client nonce><server nonce>,s=<salt>,i=<iterations>
//! C: SASLResponse                c=<gs2 header>,r=<combined nonce>,p=<client proof>
//! S: AuthenticationSASLFinal     v=<server signature>
//! S: AuthenticationOk
//! ```
//!
//! ## Known-answer tests
//!
//! The tests pin the exact `p=` and `v=` values from RFC 7677's worked example, not just
//! self-consistency. A client and server that agree with each other but not with the RFC
//! would pass a round-trip test and fail against every real PostgreSQL.
//!
//! ## Deliberate gaps
//!
//! * **Channel binding** (`SCRAM-SHA-256-PLUS`) is not implemented. A client that demands
//!   it is rejected, never silently downgraded.
//! * **SASLprep** (RFC 4013) normalisation is not applied to passwords. PostgreSQL applies
//!   it and falls back to the raw bytes when it fails; we always use the raw bytes. For
//!   the ASCII passwords that account for essentially all deployments this is identical,
//!   but a password containing characters SASLprep would normalise will not authenticate.
//!   Recorded here rather than left implicit.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use super::{AuthError, Result, ct_eq};

type HmacSha256 = Hmac<Sha256>;

/// The mechanism this module implements.
pub const MECHANISM: &str = "SCRAM-SHA-256";
/// The channel-binding variant, recognised only so it can be refused explicitly.
pub const MECHANISM_PLUS: &str = "SCRAM-SHA-256-PLUS";
/// PostgreSQL's default iteration count.
pub const DEFAULT_ITERATIONS: u32 = 4096;
/// Length of every derived key, in bytes.
pub const KEY_LEN: usize = 32;
/// Default salt length, matching PostgreSQL's 16 bytes.
pub const DEFAULT_SALT_LEN: usize = 16;
/// Raw nonce length, matching PostgreSQL's 18 bytes (24 base64 characters).
pub const NONCE_LEN: usize = 18;

/// Upper bound on the iteration count we will honour from a server or a verifier.
///
/// The iteration count is attacker-controlled in the client case (it comes from the
/// server). Without a cap, a malicious or misconfigured server can make the proxy burn
/// unbounded CPU per connection attempt.
pub const MAX_ITERATIONS: u32 = 1_000_000;

const CLIENT_KEY: &[u8] = b"Client Key";
const SERVER_KEY: &[u8] = b"Server Key";
const GS2_HEADER_NO_CHANNEL_BINDING: &str = "n,,";

// ---------------------------------------------------------------- primitives

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; KEY_LEN] {
    // HMAC accepts keys of any length, so this cannot fail for any input.
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 accepts a key of any length");
    mac.update(data);
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn sha256(data: &[u8]) -> [u8; KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn salted_password(password: &[u8], salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
    out
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

fn random_nonce() -> String {
    BASE64.encode(random_bytes(NONCE_LEN))
}

fn xor(a: &[u8; KEY_LEN], b: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    for i in 0..KEY_LEN {
        out[i] = a[i] ^ b[i];
    }
    out
}

// ---------------------------------------------------------------- attributes

fn parse_attributes(message: &str, context: &'static str) -> Result<Vec<(char, String)>> {
    let mut out = Vec::with_capacity(4);
    for part in message.split(',') {
        let Some((key, value)) = part.split_once('=') else {
            return Err(AuthError::Malformed {
                context,
                detail: format!("attribute {part:?} has no '='"),
            });
        };
        let mut chars = key.chars();
        let (Some(k), None) = (chars.next(), chars.next()) else {
            return Err(AuthError::Malformed {
                context,
                detail: format!("attribute key {key:?} is not a single character"),
            });
        };
        out.push((k, value.to_string()));
    }
    Ok(out)
}

fn require<'a>(
    attributes: &'a [(char, String)],
    key: char,
    context: &'static str,
) -> Result<&'a str> {
    attributes
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_str())
        .ok_or(AuthError::Malformed {
            context,
            detail: format!("missing required '{key}' attribute"),
        })
}

// ---------------------------------------------------------------- verifier

/// A stored SCRAM secret.
///
/// This is what PostgreSQL keeps in `pg_authid.rolpassword`, and it is enough to verify a
/// client without knowing the password. Two consequences matter for a proxy: a leaked
/// verifier does not reveal the password, and *a verifier cannot be used to log in to
/// another server* — which is exactly why PgBouncer cannot reuse a managed provider's
/// SCRAM secret unless the salt and iteration count match exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScramVerifier {
    /// PBKDF2 iteration count.
    pub iterations: u32,
    /// Salt, as raw bytes.
    pub salt: Vec<u8>,
    /// `SHA256(HMAC(SaltedPassword, "Client Key"))`.
    pub stored_key: [u8; KEY_LEN],
    /// `HMAC(SaltedPassword, "Server Key")`.
    pub server_key: [u8; KEY_LEN],
}

impl ScramVerifier {
    /// Derive a verifier from a password.
    pub fn derive(password: &[u8], iterations: u32, salt: &[u8]) -> Self {
        let salted = salted_password(password, salt, iterations);
        let client_key = hmac_sha256(&salted, CLIENT_KEY);
        Self {
            iterations,
            salt: salt.to_vec(),
            stored_key: sha256(&client_key),
            server_key: hmac_sha256(&salted, SERVER_KEY),
        }
    }

    /// Derive a verifier with a fresh random salt.
    pub fn generate(password: &[u8]) -> Self {
        Self::derive(
            password,
            DEFAULT_ITERATIONS,
            &random_bytes(DEFAULT_SALT_LEN),
        )
    }

    /// Parse the `SCRAM-SHA-256$<iterations>:<salt>$<stored key>:<server key>` form.
    pub fn parse(secret: &str) -> Result<Self> {
        let invalid = |detail: &str| AuthError::InvalidVerifier(detail.to_string());

        let rest = secret
            .strip_prefix("SCRAM-SHA-256$")
            .ok_or_else(|| invalid("must start with 'SCRAM-SHA-256$'"))?;
        let (parameters, keys) = rest
            .split_once('$')
            .ok_or_else(|| invalid("missing '$' before the key material"))?;
        let (iterations, salt) = parameters
            .split_once(':')
            .ok_or_else(|| invalid("missing ':' between iterations and salt"))?;
        let (stored_key, server_key) = keys
            .split_once(':')
            .ok_or_else(|| invalid("missing ':' between the stored key and server key"))?;

        let iterations: u32 = iterations
            .parse()
            .map_err(|_| invalid("iteration count is not a number"))?;
        if iterations == 0 || iterations > MAX_ITERATIONS {
            return Err(invalid("iteration count is out of range"));
        }

        let decode = |value: &str, what: &str| -> Result<[u8; KEY_LEN]> {
            let bytes = BASE64
                .decode(value)
                .map_err(|_| invalid(&format!("{what} is not valid base64")))?;
            if bytes.len() != KEY_LEN {
                return Err(invalid(&format!("{what} must be {KEY_LEN} bytes")));
            }
            let mut out = [0u8; KEY_LEN];
            out.copy_from_slice(&bytes);
            Ok(out)
        };

        Ok(Self {
            iterations,
            salt: BASE64
                .decode(salt)
                .map_err(|_| invalid("salt is not valid base64"))?,
            stored_key: decode(stored_key, "stored key")?,
            server_key: decode(server_key, "server key")?,
        })
    }

    /// Render back to PostgreSQL's stored form.
    pub fn to_secret(&self) -> String {
        format!(
            "SCRAM-SHA-256${}:{}${}:{}",
            self.iterations,
            BASE64.encode(&self.salt),
            BASE64.encode(self.stored_key),
            BASE64.encode(self.server_key),
        )
    }
}

// ---------------------------------------------------------------- server

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerState {
    AwaitingClientFirst,
    AwaitingClientFinal,
    Complete,
}

/// Verifies a client's SCRAM exchange.
#[derive(Debug)]
pub struct ScramServer {
    verifier: ScramVerifier,
    server_nonce: String,
    state: ServerState,
    client_first_bare: String,
    server_first: String,
    combined_nonce: String,
    gs2_header: String,
    client_username: String,
}

impl ScramServer {
    /// Start an exchange, generating a fresh server nonce.
    pub fn new(verifier: ScramVerifier) -> Self {
        Self::with_nonce(verifier, random_nonce())
    }

    /// Start an exchange with a fixed server nonce. For tests and vectors only.
    pub fn with_nonce(verifier: ScramVerifier, server_nonce: impl Into<String>) -> Self {
        Self {
            verifier,
            server_nonce: server_nonce.into(),
            state: ServerState::AwaitingClientFirst,
            client_first_bare: String::new(),
            server_first: String::new(),
            combined_nonce: String::new(),
            gs2_header: String::new(),
            client_username: String::new(),
        }
    }

    /// The username the client claimed. Informational only.
    ///
    /// PostgreSQL ignores this field and uses the startup packet's user instead; so do we.
    /// A proxy that trusted it would let a client authenticate as an arbitrary name.
    pub fn client_username(&self) -> &str {
        &self.client_username
    }

    /// The mechanism name a server must advertise.
    pub fn mechanism(&self) -> &'static str {
        MECHANISM
    }

    /// Consume the client-first-message, returning the server-first-message.
    pub fn handle_client_first(&mut self, message: &str) -> Result<String> {
        if self.state != ServerState::AwaitingClientFirst {
            return Err(AuthError::Protocol(
                "client-first-message sent out of order",
            ));
        }

        // The GS2 header ends at the first ",,". Searching for that rather than splitting
        // on ',' matters because the channel-binding form contains an '='.
        let Some(header_end) = message.find(",,") else {
            return Err(AuthError::Malformed {
                context: "SCRAM client-first-message",
                detail: "missing the GS2 header terminator \",,\"".to_string(),
            });
        };
        let gs2_header = &message[..header_end + 2];
        let bare = &message[header_end + 2..];

        match gs2_header.chars().next() {
            // 'n': client does not support channel binding. 'y': it supports it but
            // believes we do not. Both are fine to continue without channel binding.
            Some('n') | Some('y') => {}
            Some('p') => return Err(AuthError::ChannelBindingRequired),
            _ => {
                return Err(AuthError::Malformed {
                    context: "SCRAM client-first-message",
                    detail: format!("unrecognised GS2 channel-binding flag in {gs2_header:?}"),
                });
            }
        }

        let attributes = parse_attributes(bare, "SCRAM client-first-message")?;
        let client_nonce = require(&attributes, 'r', "SCRAM client-first-message")?;
        if client_nonce.is_empty() {
            return Err(AuthError::Protocol("client nonce is empty"));
        }
        let username = attributes
            .iter()
            .find(|(k, _)| *k == 'n')
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        self.client_username = username.to_string();
        self.combined_nonce = format!("{client_nonce}{}", self.server_nonce);
        self.gs2_header = gs2_header.to_string();
        self.client_first_bare = bare.to_string();
        self.server_first = format!(
            "r={},s={},i={}",
            self.combined_nonce,
            BASE64.encode(&self.verifier.salt),
            self.verifier.iterations
        );
        self.state = ServerState::AwaitingClientFinal;

        Ok(self.server_first.clone())
    }

    /// Consume the client-final-message, returning the server-final-message.
    pub fn handle_client_final(&mut self, message: &str) -> Result<String> {
        if self.state != ServerState::AwaitingClientFinal {
            return Err(AuthError::Protocol(
                "client-final-message sent out of order",
            ));
        }

        // The proof is always last, and its base64 may contain '='. Splitting on the
        // final ",p=" avoids truncating a padded proof.
        let Some(proof_at) = message.rfind(",p=") else {
            return Err(AuthError::Malformed {
                context: "SCRAM client-final-message",
                detail: "missing the 'p' proof attribute".to_string(),
            });
        };
        let without_proof = &message[..proof_at];
        let proof_b64 = &message[proof_at + 3..];

        let attributes = parse_attributes(without_proof, "SCRAM client-final-message")?;
        let channel_binding = require(&attributes, 'c', "SCRAM client-final-message")?;
        let nonce = require(&attributes, 'r', "SCRAM client-final-message")?;

        let expected_binding = BASE64.encode(self.gs2_header.as_bytes());
        if channel_binding != expected_binding {
            return Err(AuthError::Protocol(
                "channel-binding attribute does not match the GS2 header",
            ));
        }
        if nonce != self.combined_nonce {
            return Err(AuthError::NonceMismatch);
        }

        let proof = BASE64
            .decode(proof_b64)
            .map_err(|_| AuthError::Base64("SCRAM client proof"))?;
        if proof.len() != KEY_LEN {
            return Err(AuthError::Failed);
        }
        let mut proof_bytes = [0u8; KEY_LEN];
        proof_bytes.copy_from_slice(&proof);

        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, self.server_first, without_proof
        );
        let client_signature = hmac_sha256(&self.verifier.stored_key, auth_message.as_bytes());
        let client_key = xor(&proof_bytes, &client_signature);

        // The whole point of the exchange: prove the client knows the password without
        // revealing it. Constant-time, because this is the comparison an attacker probes.
        if !ct_eq(&sha256(&client_key), &self.verifier.stored_key) {
            return Err(AuthError::Failed);
        }

        let server_signature = hmac_sha256(&self.verifier.server_key, auth_message.as_bytes());
        self.state = ServerState::Complete;

        Ok(format!("v={}", BASE64.encode(server_signature)))
    }
}

// ---------------------------------------------------------------- client

/// Performs a SCRAM exchange against a server.
#[derive(Debug)]
pub struct ScramClient {
    password: Vec<u8>,
    /// The `n` field of the client-first-message.
    ///
    /// Empty by default, because that is what PostgreSQL clients send: the real username
    /// travels in the startup packet and PostgreSQL ignores this field. It is configurable
    /// so the RFC test vectors, which use a non-empty value, can be reproduced exactly.
    username: String,
    client_nonce: String,
    client_first_bare: String,
    server_first: String,
    auth_message: String,
    server_key: [u8; KEY_LEN],
    state: ServerState,
}

impl ScramClient {
    /// Start an exchange, generating a fresh client nonce.
    pub fn new(password: &[u8]) -> Self {
        Self::with_nonce(password, random_nonce())
    }

    /// Start an exchange with a fixed nonce. For tests and vectors only.
    pub fn with_nonce(password: &[u8], client_nonce: impl Into<String>) -> Self {
        Self {
            password: password.to_vec(),
            username: String::new(),
            client_nonce: client_nonce.into(),
            client_first_bare: String::new(),
            server_first: String::new(),
            auth_message: String::new(),
            server_key: [0u8; KEY_LEN],
            state: ServerState::AwaitingClientFirst,
        }
    }

    /// Set the username field of the client-first-message.
    ///
    /// Only needed to reproduce non-PostgreSQL test vectors; real clients leave it empty.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    /// The mechanism name to request.
    pub fn mechanism(&self) -> &'static str {
        MECHANISM
    }

    /// Build the client-first-message.
    pub fn client_first(&mut self) -> String {
        // PostgreSQL clients send an empty username here; the real one travels in the
        // startup packet and PostgreSQL ignores this field.
        self.client_first_bare = format!("n={},r={}", self.username, self.client_nonce);
        format!("{GS2_HEADER_NO_CHANNEL_BINDING}{}", self.client_first_bare)
    }

    /// Consume the server-first-message, returning the client-final-message.
    pub fn handle_server_first(&mut self, message: &str) -> Result<String> {
        let attributes = parse_attributes(message, "SCRAM server-first-message")?;

        // A server may report a failure in place of a challenge.
        if let Some(error) = attributes.iter().find(|(k, _)| *k == 'e') {
            let _ = error;
            return Err(AuthError::Failed);
        }

        let nonce = require(&attributes, 'r', "SCRAM server-first-message")?;
        let salt = require(&attributes, 's', "SCRAM server-first-message")?;
        let iterations = require(&attributes, 'i', "SCRAM server-first-message")?;

        if !nonce.starts_with(&self.client_nonce) || nonce.len() == self.client_nonce.len() {
            return Err(AuthError::NonceMismatch);
        }

        let iterations: u32 = iterations.parse().map_err(|_| AuthError::Malformed {
            context: "SCRAM server-first-message",
            detail: "iteration count is not a number".to_string(),
        })?;
        if iterations == 0 || iterations > MAX_ITERATIONS {
            return Err(AuthError::Malformed {
                context: "SCRAM server-first-message",
                detail: format!("iteration count {iterations} is out of range"),
            });
        }

        let salt = BASE64
            .decode(salt)
            .map_err(|_| AuthError::Base64("SCRAM salt"))?;

        let salted = salted_password(&self.password, &salt, iterations);
        let client_key = hmac_sha256(&salted, CLIENT_KEY);
        let stored_key = sha256(&client_key);
        self.server_key = hmac_sha256(&salted, SERVER_KEY);

        let without_proof = format!(
            "c={},r={}",
            BASE64.encode(GS2_HEADER_NO_CHANNEL_BINDING),
            nonce
        );
        self.server_first = message.to_string();
        self.auth_message = format!(
            "{},{},{}",
            self.client_first_bare, self.server_first, without_proof
        );

        let client_signature = hmac_sha256(&stored_key, self.auth_message.as_bytes());
        let proof = xor(&client_key, &client_signature);

        self.state = ServerState::AwaitingClientFinal;
        Ok(format!("{without_proof},p={}", BASE64.encode(proof)))
    }

    /// Verify the server-final-message.
    ///
    /// Skipping this check authenticates the *client* to a server that may be an impostor.
    /// A proxy that relays SCRAM without verifying lets an attacker who can intercept the
    /// exchange capture a proof and replay it — so this is not optional.
    pub fn handle_server_final(&mut self, message: &str) -> Result<()> {
        if self.state != ServerState::AwaitingClientFinal {
            return Err(AuthError::Protocol(
                "server-final-message sent out of order",
            ));
        }

        let attributes = parse_attributes(message, "SCRAM server-final-message")?;
        if attributes.iter().any(|(k, _)| *k == 'e') {
            return Err(AuthError::Failed);
        }

        let signature = require(&attributes, 'v', "SCRAM server-final-message")?;
        let signature = BASE64
            .decode(signature)
            .map_err(|_| AuthError::Base64("SCRAM server signature"))?;

        let expected = hmac_sha256(&self.server_key, self.auth_message.as_bytes());
        if !ct_eq(&signature, &expected) {
            return Err(AuthError::ServerSignatureMismatch);
        }

        self.state = ServerState::Complete;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------ RFC 7677 vectors
    //
    // The worked example from RFC 7677 section 3. Everything below is copied from the
    // RFC, so a self-consistent-but-wrong implementation cannot pass.

    const RFC_PASSWORD: &[u8] = b"pencil";
    const RFC_CLIENT_NONCE: &str = "rOprNGfwEbeRWgbNEkqO";
    const RFC_SERVER_NONCE: &str = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    const RFC_SALT_B64: &str = "W22ZaJ0SNY7soEsUEjb6gQ==";
    const RFC_ITERATIONS: u32 = 4096;
    const RFC_CLIENT_FIRST: &str = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
    const RFC_SERVER_FIRST: &str =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const RFC_CLIENT_FINAL: &str = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const RFC_SERVER_FINAL: &str = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    fn rfc_verifier() -> ScramVerifier {
        let salt = BASE64.decode(RFC_SALT_B64).unwrap();
        ScramVerifier::derive(RFC_PASSWORD, RFC_ITERATIONS, &salt)
    }

    #[test]
    fn verifier_derivation_matches_the_rfc() {
        let verifier = rfc_verifier();
        assert_eq!(
            BASE64.encode(verifier.stored_key),
            "WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY="
        );
        assert_eq!(
            BASE64.encode(verifier.server_key),
            "wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="
        );
    }

    #[test]
    fn client_produces_the_rfc_client_final_message() {
        let mut client =
            ScramClient::with_nonce(RFC_PASSWORD, RFC_CLIENT_NONCE).with_username("user");
        assert_eq!(client.client_first(), RFC_CLIENT_FIRST);
        assert_eq!(
            client.handle_server_first(RFC_SERVER_FIRST).unwrap(),
            RFC_CLIENT_FINAL
        );
        client.handle_server_final(RFC_SERVER_FINAL).unwrap();
    }

    #[test]
    fn server_produces_the_rfc_server_first_message() {
        let mut server = ScramServer::with_nonce(rfc_verifier(), RFC_SERVER_NONCE);
        assert_eq!(
            server.handle_client_first(RFC_CLIENT_FIRST).unwrap(),
            RFC_SERVER_FIRST
        );
    }

    #[test]
    fn server_produces_the_rfc_server_final_message() {
        let mut server = ScramServer::with_nonce(rfc_verifier(), RFC_SERVER_NONCE);
        server.handle_client_first(RFC_CLIENT_FIRST).unwrap();
        assert_eq!(
            server.handle_client_final(RFC_CLIENT_FINAL).unwrap(),
            RFC_SERVER_FINAL
        );
    }

    #[test]
    fn server_records_the_claimed_username() {
        let mut server = ScramServer::with_nonce(rfc_verifier(), RFC_SERVER_NONCE);
        server.handle_client_first(RFC_CLIENT_FIRST).unwrap();
        assert_eq!(server.client_username(), "user");
    }

    // ------------------------------------------------------------------ full exchanges

    #[test]
    fn client_and_server_complete_a_random_exchange() {
        let verifier = ScramVerifier::generate(b"correct horse battery staple");
        let mut server = ScramServer::new(verifier);
        let mut client = ScramClient::new(b"correct horse battery staple");

        let client_first = client.client_first();
        let server_first = server.handle_client_first(&client_first).unwrap();
        let client_final = client.handle_server_first(&server_first).unwrap();
        let server_final = server.handle_client_final(&client_final).unwrap();
        client.handle_server_final(&server_final).unwrap();
    }

    #[test]
    fn a_wrong_password_is_rejected() {
        let verifier = ScramVerifier::generate(b"the-right-one");
        let mut server = ScramServer::new(verifier);
        let mut client = ScramClient::new(b"the-wrong-one");

        let client_first = client.client_first();
        let server_first = server.handle_client_first(&client_first).unwrap();
        let client_final = client.handle_server_first(&server_first).unwrap();

        let err = server.handle_client_final(&client_final).unwrap_err();
        assert!(matches!(err, AuthError::Failed));
        // And the message must not say why.
        assert_eq!(err.to_string(), "authentication failed");
    }

    #[test]
    fn a_tampered_proof_is_rejected() {
        let verifier = ScramVerifier::generate(b"password");
        let mut server = ScramServer::new(verifier);
        let mut client = ScramClient::new(b"password");

        let server_first = server.handle_client_first(&client.client_first()).unwrap();
        let client_final = client.handle_server_first(&server_first).unwrap();

        // Flip one character of the base64 proof.
        let mut tampered = client_final.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });

        assert!(matches!(
            server.handle_client_final(&tampered).unwrap_err(),
            AuthError::Failed
        ));
    }

    #[test]
    fn a_forged_server_signature_is_rejected() {
        // The check that stops a man-in-the-middle relaying a captured exchange.
        let verifier = ScramVerifier::generate(b"password");
        let mut server = ScramServer::new(verifier);
        let mut client = ScramClient::new(b"password");

        let server_first = server.handle_client_first(&client.client_first()).unwrap();
        let client_final = client.handle_server_first(&server_first).unwrap();
        server.handle_client_final(&client_final).unwrap();

        let forged = format!("v={}", BASE64.encode([0u8; KEY_LEN]));
        assert!(matches!(
            client.handle_server_final(&forged).unwrap_err(),
            AuthError::ServerSignatureMismatch
        ));
    }

    // ------------------------------------------------------------------ protocol abuses

    #[test]
    fn a_replayed_client_final_message_fails_on_a_second_exchange() {
        // The server nonce is fresh each time, so a captured proof cannot be replayed.
        let verifier = ScramVerifier::generate(b"password");

        let mut first = ScramServer::new(verifier.clone());
        let mut client = ScramClient::new(b"password");
        let server_first = first.handle_client_first(&client.client_first()).unwrap();
        let client_final = client.handle_server_first(&server_first).unwrap();
        first.handle_client_final(&client_final).unwrap();

        let mut second = ScramServer::new(verifier);
        second.handle_client_first(&client.client_first()).unwrap();
        assert!(
            second.handle_client_final(&client_final).is_err(),
            "a captured client-final-message must not be replayable"
        );
    }

    #[test]
    fn channel_binding_is_refused_rather_than_downgraded() {
        // Silently ignoring a client's channel-binding demand would remove the protection
        // it asked for, so this must be a hard failure.
        let mut server = ScramServer::new(ScramVerifier::generate(b"password"));
        let err = server
            .handle_client_first("p=tls-server-end-point,,n=,r=abcdef")
            .unwrap_err();
        assert!(matches!(err, AuthError::ChannelBindingRequired));
    }

    #[test]
    fn the_y_flag_is_accepted() {
        // 'y' means the client supports channel binding but thinks the server does not.
        let mut server = ScramServer::with_nonce(rfc_verifier(), RFC_SERVER_NONCE);
        assert!(server.handle_client_first("y,,n=,r=abcdef").is_ok());
    }

    #[test]
    fn a_missing_gs2_terminator_is_rejected() {
        let mut server = ScramServer::new(ScramVerifier::generate(b"password"));
        let err = server.handle_client_first("n=,r=abcdef").unwrap_err();
        assert!(err.to_string().contains("GS2 header"), "{err}");
    }

    #[test]
    fn out_of_order_messages_are_rejected() {
        let mut server = ScramServer::new(ScramVerifier::generate(b"password"));
        assert!(matches!(
            server.handle_client_final("c=biws,r=x,p=y").unwrap_err(),
            AuthError::Protocol(_)
        ));
    }

    #[test]
    fn a_client_final_without_a_proof_is_rejected() {
        let mut server = ScramServer::with_nonce(rfc_verifier(), RFC_SERVER_NONCE);
        server.handle_client_first(RFC_CLIENT_FIRST).unwrap();
        let err = server
            .handle_client_final("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0")
            .unwrap_err();
        assert!(err.to_string().contains("proof"), "{err}");
    }

    #[test]
    fn a_wrong_nonce_is_rejected() {
        let mut server = ScramServer::with_nonce(rfc_verifier(), RFC_SERVER_NONCE);
        server.handle_client_first(RFC_CLIENT_FIRST).unwrap();
        let tampered = RFC_CLIENT_FINAL.replace(
            "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
            "wrong",
        );
        assert!(matches!(
            server.handle_client_final(&tampered).unwrap_err(),
            AuthError::NonceMismatch | AuthError::Protocol(_)
        ));
    }

    #[test]
    fn a_client_rejects_a_server_nonce_that_does_not_extend_its_own() {
        let mut client = ScramClient::with_nonce(b"password", "clientnonce");
        client.client_first();
        let err = client
            .handle_server_first("r=completely-different,s=c2FsdA==,i=4096")
            .unwrap_err();
        assert!(matches!(err, AuthError::NonceMismatch));
    }

    #[test]
    fn a_client_rejects_a_server_nonce_that_only_echoes_its_own() {
        // The server must contribute entropy; echoing the client's nonce back would make
        // the exchange replayable.
        let mut client = ScramClient::with_nonce(b"password", "clientnonce");
        client.client_first();
        let err = client
            .handle_server_first("r=clientnonce,s=c2FsdA==,i=4096")
            .unwrap_err();
        assert!(matches!(err, AuthError::NonceMismatch));
    }

    #[test]
    fn an_absurd_iteration_count_is_refused() {
        // Otherwise a hostile server makes the proxy burn CPU per connection attempt.
        let mut client = ScramClient::with_nonce(b"password", "clientnonce");
        client.client_first();
        let err = client
            .handle_server_first("r=clientnonceEXTRA,s=c2FsdA==,i=4000000000")
            .unwrap_err();
        assert!(err.to_string().contains("out of range"), "{err}");
    }

    #[test]
    fn a_server_error_attribute_is_surfaced_as_failure() {
        let mut client = ScramClient::with_nonce(b"password", "clientnonce");
        client.client_first();
        assert!(matches!(
            client.handle_server_first("e=invalid-proof").unwrap_err(),
            AuthError::Failed
        ));
    }

    // ------------------------------------------------------------------ verifier storage

    #[test]
    fn verifier_round_trips_through_its_stored_form() {
        let verifier = ScramVerifier::generate(b"password");
        let secret = verifier.to_secret();
        assert!(secret.starts_with("SCRAM-SHA-256$"));
        assert_eq!(ScramVerifier::parse(&secret).unwrap(), verifier);
    }

    #[test]
    fn verifier_stored_form_matches_postgresqls_shape() {
        // The exact value PostgreSQL's ALTER USER ... PASSWORD would produce for this
        // salt and iteration count.
        let salt = BASE64.decode(RFC_SALT_B64).unwrap();
        let verifier = ScramVerifier::derive(RFC_PASSWORD, RFC_ITERATIONS, &salt);
        assert_eq!(
            verifier.to_secret(),
            "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="
        );
    }

    #[test]
    fn a_parsed_verifier_can_verify_a_client() {
        // The property that matters: no plaintext is needed to authenticate a client.
        let secret = ScramVerifier::generate(b"password").to_secret();
        let mut server = ScramServer::new(ScramVerifier::parse(&secret).unwrap());
        let mut client = ScramClient::new(b"password");

        let server_first = server.handle_client_first(&client.client_first()).unwrap();
        let client_final = client.handle_server_first(&server_first).unwrap();
        client
            .handle_server_final(&server.handle_client_final(&client_final).unwrap())
            .unwrap();
    }

    #[test]
    fn malformed_verifiers_are_rejected() {
        for bad in [
            "",
            "SCRAM-SHA-256$",
            "SCRAM-SHA-256$4096",
            "SCRAM-SHA-256$4096:c2FsdA==",
            "SCRAM-SHA-256$4096:c2FsdA==$c2hvcnQ=",
            "SCRAM-SHA-256$notanumber:c2FsdA==$AAAA:AAAA",
            "SCRAM-SHA-256$0:c2FsdA==$AAAA:AAAA",
            "SCRAM-SHA-256$99999999:c2FsdA==$AAAA:AAAA",
            "MD5$4096:c2FsdA==$AAAA:AAAA",
        ] {
            assert!(
                ScramVerifier::parse(bad).is_err(),
                "should have rejected {bad:?}"
            );
        }
    }

    #[test]
    fn iteration_counts_above_the_cap_are_rejected_when_parsed() {
        let err = ScramVerifier::parse(&format!(
            "SCRAM-SHA-256${}:c2FsdA==$AAAA:AAAA",
            MAX_ITERATIONS + 1
        ))
        .unwrap_err();
        assert!(err.to_string().contains("out of range"), "{err}");
    }

    #[test]
    fn nonces_are_unique_and_unpredictable_length() {
        let a = random_nonce();
        let b = random_nonce();
        assert_ne!(a, b, "two nonces must not collide");
        // 18 raw bytes base64-encode to 24 characters.
        assert_eq!(a.len(), 24);
    }

    #[test]
    fn mechanism_names_are_stable() {
        // Advertised over the wire; changing them silently would break every client.
        assert_eq!(MECHANISM, "SCRAM-SHA-256");
        assert_eq!(MECHANISM_PLUS, "SCRAM-SHA-256-PLUS");
    }
}
