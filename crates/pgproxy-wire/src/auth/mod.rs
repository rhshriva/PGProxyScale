//! Authentication: the `Authentication*` messages, SCRAM-SHA-256 and MD5.
//!
//! ## The design question this module exists to answer
//!
//! A proxy can authenticate in one of two ways, and the choice is the difference between
//! working and not working against managed PostgreSQL:
//!
//! 1. **Terminate** — the proxy verifies the client itself, then authenticates to the
//!    backend separately. This needs a secret: either a plaintext password, or the stored
//!    SCRAM verifier.
//! 2. **Passthrough** — the proxy relays the authentication exchange verbatim, so the
//!    client authenticates *to the backend* through the proxy. No secret is required.
//!
//! PgBouncer does (1), and its documentation records the consequence: against managed
//! providers that block `pg_authid`, it needs the password in plaintext, and a SCRAM
//! secret can only be reused if the salt and iteration count match exactly. Passthrough
//! avoids the problem entirely.
//!
//! Both are implemented here, because passthrough does not cover every case — the policy
//! engine will want to reject a client before a backend is touched, which requires
//! terminating. Which one runs is a per-database decision made by the connection state
//! machine, not by this module.
//!
//! ## Scope note
//!
//! Channel binding (`SCRAM-SHA-256-PLUS`, `p=tls-server-end-point`) is **not** implemented.
//! A client that demands it is rejected with a specific error rather than silently
//! downgraded, because silently downgrading is how channel binding stops protecting
//! anyone. This is a known gap against PgBouncer, which does support it.

pub mod md5;
pub mod messages;
pub mod scram;

use subtle::ConstantTimeEq;

/// Everything that can go wrong during authentication.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// A message did not match the grammar it claimed.
    #[error("malformed {context}: {detail}")]
    Malformed {
        /// Which message or field was malformed.
        context: &'static str,
        /// What was wrong with it.
        detail: String,
    },

    /// The client asked for a mechanism we do not implement.
    #[error("unsupported authentication mechanism: {0}")]
    UnsupportedMechanism(String),

    /// The client requires channel binding, which we do not offer.
    #[error(
        "client requires channel binding (SCRAM-SHA-256-PLUS), which this proxy does not support"
    )]
    ChannelBindingRequired,

    /// The client completed a SCRAM exchange with an incorrect proof.
    ///
    /// Deliberately carries no detail: the wire response must not distinguish "wrong
    /// password" from "unknown user", or it becomes a user-enumeration oracle.
    #[error("authentication failed")]
    Failed,

    /// The exchange broke its own rules (missing attribute, wrong order).
    #[error("SCRAM protocol violation: {0}")]
    Protocol(&'static str),

    /// The server's signature did not verify, so the server is not who it claims.
    #[error("server signature did not verify")]
    ServerSignatureMismatch,

    /// The nonce the server returned does not extend the client's nonce.
    #[error("server nonce does not extend the client nonce")]
    NonceMismatch,

    /// A stored verifier was not in the expected format.
    #[error("invalid stored verifier: {0}")]
    InvalidVerifier(String),

    /// A base64 field did not decode.
    #[error("base64 decode failed in {0}")]
    Base64(&'static str),

    /// A stored hash was not in the expected format.
    #[error("invalid stored hash: {0}")]
    InvalidHash(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, AuthError>;

/// Constant-time byte comparison.
///
/// Used for every MAC, proof and hash comparison in this module. A variable-time
/// comparison against a secret is a timing oracle, and hand-rolling one is a classic way
/// to introduce exactly the bug the timing-safe version exists to prevent.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// How a database authenticates clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// No authentication. Only sane on a trusted unix socket.
    Trust,
    /// Legacy MD5 challenge-response. Broken by design against offline attack; supported
    /// because existing deployments still use it.
    Md5,
    /// SCRAM-SHA-256, the current default.
    ScramSha256,
}

impl AuthMethod {
    /// Parse a configuration value.
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "trust" => Ok(AuthMethod::Trust),
            "md5" => Ok(AuthMethod::Md5),
            "scram-sha-256" | "scram" => Ok(AuthMethod::ScramSha256),
            other => Err(AuthError::UnsupportedMechanism(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"a"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn auth_method_parsing_accepts_documented_names() {
        assert_eq!(AuthMethod::parse("trust").unwrap(), AuthMethod::Trust);
        assert_eq!(AuthMethod::parse("MD5").unwrap(), AuthMethod::Md5);
        assert_eq!(
            AuthMethod::parse("scram-sha-256").unwrap(),
            AuthMethod::ScramSha256
        );
        assert!(AuthMethod::parse("ldap").is_err());
    }

    #[test]
    fn the_failure_error_leaks_nothing() {
        // Guards against someone later adding detail to this variant for debugging.
        assert_eq!(AuthError::Failed.to_string(), "authentication failed");
    }
}
