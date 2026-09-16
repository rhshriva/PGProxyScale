//! Rebuilding a client's startup packet for the backend.
//!
//! Passthrough needs one piece of surgery: the client asks for a database by the name it
//! configured in the proxy, and the backend may know it by a different name. Everything
//! else must be forwarded byte-for-byte.
//!
//! Two rules this module exists to enforce:
//!
//! * **Values are bytes, not strings.** The protocol does not promise UTF-8, and a
//!   database or user name that goes through a lossy decode can come out changed — or
//!   come out equal to something it was not.
//! * **Nothing is dropped.** A parameter we do not understand is still the client's
//!   session state. Spike S2 found 144 client-settable GUCs the server never reports
//!   back, so silently discarding a startup parameter is exactly the failure mode we are
//!   trying to avoid.

use super::StartupOverrides;
use crate::protocol::startup::StartupParams;

/// The parameter names the proxy may rewrite.
const DATABASE: &str = "database";
const USER: &str = "user";

/// Build a complete startup packet, including its length prefix.
///
/// Parameter order is preserved so the packet is byte-identical to the client's whenever
/// no override applies.
pub fn build_startup<'a>(params: &'a StartupParams, overrides: &StartupOverrides<'a>) -> Vec<u8> {
    let mut entries: Vec<(&'a str, &'a [u8])> = params.iter().collect();

    apply(&mut entries, DATABASE, overrides.database);
    apply(&mut entries, USER, overrides.user);

    // version(4) + for each entry: key + NUL + value + NUL + final NUL
    let mut body_len = 4 + 1;
    for (key, value) in &entries {
        body_len += key.len() + 1 + value.len() + 1;
    }

    let mut packet = Vec::with_capacity(4 + body_len);
    // The startup length field covers the whole packet *including itself* - the same
    // convention as the length field of every typed message, and the detail S3's golden
    // vectors pin. Writing `body_len` alone is an off-by-four that desynchronises the
    // backend immediately.
    packet.extend_from_slice(&((body_len + 4) as i32).to_be_bytes());
    packet.extend_from_slice(&params.protocol_version.to_be_bytes());

    for (key, value) in &entries {
        packet.extend_from_slice(key.as_bytes());
        packet.push(0);
        packet.extend_from_slice(value);
        packet.push(0);
    }
    packet.push(0);

    packet
}

/// Replace an existing entry, or append it when the client did not send one.
///
/// Both borrows share the function's single lifetime, so the override's bytes live exactly
/// as long as the parameter entries it is spliced into. Getting this wrong is what tempts
/// people into extending a lifetime by hand.
fn apply<'a>(entries: &mut Vec<(&'a str, &'a [u8])>, key: &'a str, replacement: Option<&'a str>) {
    let Some(value) = replacement else {
        return;
    };
    let value_bytes = value.as_bytes();

    if let Some(slot) = entries.iter_mut().find(|(k, _)| *k == key) {
        *slot = (key, value_bytes);
    } else {
        entries.push((key, value_bytes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::startup::parse_startup;
    use crate::protocol::{PROTOCOL_3_0, PROTOCOL_3_2, StartupRequest};

    fn params(version: i32, entries: &[(&str, &str)]) -> StartupParams {
        let mut body = version.to_be_bytes().to_vec();
        for (k, v) in entries {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }
        body.push(0);
        match parse_startup(&body).expect("valid startup body") {
            StartupRequest::Startup(p) => p,
            other => panic!("expected Startup, got {other:?}"),
        }
    }

    /// Parse a built packet back through the real startup parser.
    fn round_trip(packet: &[u8]) -> StartupParams {
        let mut reader = crate::FrameReader::new(std::io::Cursor::new(packet.to_vec()));
        match reader.read_startup().expect("parses") {
            StartupRequest::Startup(p) => p,
            other => panic!("expected Startup, got {other:?}"),
        }
    }

    fn no_overrides() -> StartupOverrides<'static> {
        StartupOverrides {
            database: None,
            user: None,
        }
    }

    #[test]
    fn without_overrides_the_packet_is_unchanged() {
        let original = params(PROTOCOL_3_0, &[("user", "alice"), ("database", "app")]);
        let built = build_startup(&original, &no_overrides());
        let reparsed = round_trip(&built);

        assert_eq!(reparsed.protocol_version, original.protocol_version);
        assert_eq!(reparsed.get("user"), Some("alice"));
        assert_eq!(reparsed.get("database"), Some("app"));
        assert_eq!(reparsed.len(), original.len());
        assert_eq!(reparsed.options(), original.options());
    }

    #[test]
    fn the_length_prefix_is_correct() {
        let original = params(PROTOCOL_3_0, &[("user", "alice"), ("database", "app")]);
        let built = build_startup(&original, &no_overrides());
        let declared = i32::from_be_bytes(built[0..4].try_into().unwrap());
        assert_eq!(declared as usize, built.len());
    }

    #[test]
    fn the_database_can_be_rewritten() {
        let original = params(PROTOCOL_3_0, &[("user", "alice"), ("database", "app")]);
        let built = build_startup(
            &original,
            &StartupOverrides {
                database: Some("app_production"),
                user: None,
            },
        );
        let reparsed = round_trip(&built);
        assert_eq!(reparsed.get("database"), Some("app_production"));
        assert_eq!(
            reparsed.get("user"),
            Some("alice"),
            "other params must survive"
        );
    }

    #[test]
    fn a_database_can_be_supplied_when_the_client_sent_none() {
        // libpq omits `database` when it defaults to the username.
        let original = params(PROTOCOL_3_0, &[("user", "alice")]);
        let built = build_startup(
            &original,
            &StartupOverrides {
                database: Some("app"),
                user: None,
            },
        );
        assert_eq!(round_trip(&built).get("database"), Some("app"));
    }

    #[test]
    fn the_user_can_be_rewritten_for_a_forced_user_backend() {
        let original = params(PROTOCOL_3_0, &[("user", "alice"), ("database", "app")]);
        let built = build_startup(
            &original,
            &StartupOverrides {
                database: None,
                user: Some("pool_role"),
            },
        );
        assert_eq!(round_trip(&built).get("user"), Some("pool_role"));
    }

    #[test]
    fn protocol_3_2_is_preserved() {
        // Dropping the minor version would silently downgrade a client that negotiated
        // 3.2 - and with it, the variable-length cancel keys.
        let original = params(PROTOCOL_3_2, &[("user", "alice")]);
        let built = build_startup(&original, &no_overrides());
        assert_eq!(round_trip(&built).protocol_version, PROTOCOL_3_2);
    }

    #[test]
    fn parameters_are_preserved_in_order() {
        let original = params(
            PROTOCOL_3_0,
            &[
                ("user", "alice"),
                ("database", "app"),
                ("application_name", "worker"),
                ("client_encoding", "UTF8"),
                ("options", "-c statement_timeout=5000"),
            ],
        );
        let built = build_startup(&original, &no_overrides());
        let reparsed = round_trip(&built);

        let before: Vec<&str> = original.iter().map(|(k, _)| k).collect();
        let after: Vec<&str> = reparsed.iter().map(|(k, _)| k).collect();
        assert_eq!(before, after, "parameter order must not change");

        assert_eq!(
            reparsed.options(),
            vec![("statement_timeout".to_string(), "5000".to_string())],
            "GUCs in `options` must survive the round trip"
        );
    }

    #[test]
    fn a_rewritten_database_stays_in_place() {
        // Replacing rather than appending matters: a client that sent `database` twice,
        // or a server that reads the first occurrence, must see the override.
        let original = params(PROTOCOL_3_0, &[("user", "alice"), ("database", "app")]);
        let built = build_startup(
            &original,
            &StartupOverrides {
                database: Some("other"),
                user: None,
            },
        );
        let reparsed = round_trip(&built);
        let keys: Vec<&str> = reparsed.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["user", "database"]);
    }

    #[test]
    fn non_utf8_values_survive_byte_for_byte() {
        // A lossy decode here could make two different database names compare equal.
        let mut body = PROTOCOL_3_0.to_be_bytes().to_vec();
        body.extend_from_slice(b"user\0alice\0database\0");
        body.extend_from_slice(&[0xFF, 0xFE]);
        body.push(0);
        body.push(0);

        let StartupRequest::Startup(original) = parse_startup(&body).unwrap() else {
            panic!("expected Startup");
        };
        let built = build_startup(&original, &no_overrides());
        let reparsed = round_trip(&built);

        assert_eq!(reparsed.get_bytes("database"), Some(&[0xFF, 0xFE][..]));
        assert_eq!(reparsed.get("database"), None);
    }

    #[test]
    fn an_empty_parameter_list_is_handled() {
        let original = params(PROTOCOL_3_0, &[]);
        let built = build_startup(
            &original,
            &StartupOverrides {
                database: Some("app"),
                user: None,
            },
        );
        assert_eq!(round_trip(&built).get("database"), Some("app"));
    }
}
