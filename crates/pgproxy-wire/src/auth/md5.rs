//! MD5 password authentication.
//!
//! PostgreSQL's scheme, for compatibility with existing deployments:
//!
//! ```text
//! inner    = md5(password || username)
//! outer    = md5(hex(inner) || salt)
//! response = "md5" || hex(outer)
//! ```
//!
//! The server stores `"md5" || hex(inner)` in `pg_authid.rolpassword`, so verifying needs
//! no plaintext — only the stored hash and the salt the server generated.
//!
//! MD5 is cryptographically broken and this scheme is vulnerable to offline attack by
//! anyone who observes the exchange, which is why SCRAM-SHA-256 exists. It is supported
//! because real deployments still use it, and because refusing would make the proxy
//! unusable as a drop-in replacement. It is **not** the default.

use md5::{Digest, Md5};

use super::{AuthError, Result, ct_eq};

/// Length of an MD5 digest in bytes.
const DIGEST_LEN: usize = 16;

/// Lowercase hex encoding.
///
/// Hand-rolled rather than pulling in a `hex` dependency for one call site.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn md5_of(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Md5::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Compute the stored hash for a password, as PostgreSQL would store it.
///
/// Returns `"md5" || hex(md5(password || username))`.
pub fn hash_password(password: &[u8], username: &str) -> String {
    let mut material = Vec::with_capacity(password.len() + username.len());
    material.extend_from_slice(password);
    material.extend_from_slice(username.as_bytes());
    format!("md5{}", hex(&md5_of(&material)))
}

/// Whether a string looks like a stored MD5 hash.
pub fn is_md5_hash(value: &str) -> bool {
    value.len() == 3 + DIGEST_LEN * 2
        && value.starts_with("md5")
        && value[3..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// Produce the response a client must send for a given stored hash and salt.
pub fn response(stored_hash: &str, salt: &[u8; 4]) -> Result<String> {
    if !is_md5_hash(stored_hash) {
        return Err(AuthError::InvalidHash(
            "expected a stored hash of the form md5<32 hex digits>".to_string(),
        ));
    }
    // The stored hash already contains hex(md5(password || username)), so the outer
    // round hashes that hex string with the salt rather than re-deriving it.
    let mut material = Vec::with_capacity(32 + 4);
    material.extend_from_slice(&stored_hash.as_bytes()[3..]);
    material.extend_from_slice(salt);
    Ok(format!("md5{}", hex(&md5_of(&material))))
}

/// Verify a client's response against a stored hash and the salt we issued.
///
/// Comparison is constant-time: this is the check an attacker can otherwise use as a
/// timing oracle to recover the hash byte by byte.
pub fn verify(client_response: &str, stored_hash: &str, salt: &[u8; 4]) -> Result<bool> {
    let expected = response(stored_hash, salt)?;
    Ok(ct_eq(client_response.as_bytes(), expected.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vector, computed independently:
    //   password "secret", username "postgres", salt 01 02 03 04
    const STORED: &str = "md553f48b7c4b76a86ce72276c5755f217d";
    const EXPECTED_RESPONSE: &str = "md5bb41a296aab6baccb36ff243a562abff";

    #[test]
    fn matches_a_known_answer_vector() {
        // If this breaks, every MD5 login breaks, so pin the exact bytes.
        assert_eq!(hash_password(b"secret", "postgres"), STORED);
        assert_eq!(
            response(STORED, &[0x01, 0x02, 0x03, 0x04]).unwrap(),
            EXPECTED_RESPONSE
        );
    }

    #[test]
    fn verifies_a_correct_response() {
        assert!(verify(EXPECTED_RESPONSE, STORED, &[0x01, 0x02, 0x03, 0x04]).unwrap());
    }

    #[test]
    fn rejects_a_wrong_password() {
        let wrong = hash_password(b"hunter2", "postgres");
        assert!(!verify(EXPECTED_RESPONSE, &wrong, &[0x01, 0x02, 0x03, 0x04]).unwrap());
    }

    #[test]
    fn rejects_a_different_salt() {
        // The salt binds the response to this exchange; replaying an old response must fail.
        assert!(!verify(EXPECTED_RESPONSE, STORED, &[0x04, 0x03, 0x02, 0x01]).unwrap());
    }

    #[test]
    fn hex_is_lowercase_and_zero_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn recognises_valid_and_invalid_stored_hashes() {
        assert!(is_md5_hash(STORED));
        // Wrong length.
        assert!(!is_md5_hash("md5123"));
        // Missing prefix.
        assert!(!is_md5_hash("53f48b7c4b76a86ce72276c5755f217d"));
        // Non-hex characters.
        assert!(!is_md5_hash("md5zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
        // A SCRAM secret is not an MD5 hash.
        assert!(!is_md5_hash(
            "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy"
        ));
    }

    #[test]
    fn response_rejects_a_malformed_stored_hash() {
        let err = response("not-a-hash", &[0, 0, 0, 0]).unwrap_err();
        assert!(err.to_string().contains("invalid stored hash"), "{err}");
    }

    #[test]
    fn the_same_password_and_user_differ_for_different_users() {
        // A per-user salt would be better, but PostgreSQL does not do that: this test
        // documents the property rather than endorsing it.
        assert_ne!(
            hash_password(b"secret", "alice"),
            hash_password(b"secret", "bob")
        );
    }
}
