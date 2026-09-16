//! Golden vectors captured from a real client.
//!
//! Synthetic test vectors only prove the parser agrees with its author. These are the
//! actual bytes psycopg3 (libpq) put on the wire, captured on 2026-09-16 with:
//!
//! ```sh
//! cargo run -p pgproxy-wire --example capture_startup 0.0.0.0:6543
//! # then, from a container:
//! #   psycopg.connect(host='host.docker.internal', port=6543, user='probe_user',
//! #                   dbname='probe_db')
//! ```
//!
//! The capture deliberately answers the `SSLRequest` with `N` first, so it also pins our
//! handling of the TLS negotiation that precedes every real connection.

use std::io::Cursor;

use pgproxy_wire::protocol::{SSL_REQUEST_CODE, startup::StartupRequest};
use pgproxy_wire::{FrameReader, parse_startup};

/// `SSLRequest`: length 8, code 80877103.
const REAL_SSL_REQUEST: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];

/// The full startup packet: length 43, version 3.0, then `user` and `database`.
const REAL_STARTUP_PACKET: &[u8] = &[
    0x00, 0x00, 0x00, 0x2b, // length = 43
    0x00, 0x03, 0x00, 0x00, // protocol 3.0
    b'u', b's', b'e', b'r', 0x00, //
    b'p', b'r', b'o', b'b', b'e', b'_', b'u', b's', b'e', b'r', 0x00, //
    b'd', b'a', b't', b'a', b'b', b'a', b's', b'e', 0x00, //
    b'p', b'r', b'o', b'b', b'e', b'_', b'd', b'b', 0x00, //
    0x00, // terminator
];

#[test]
fn the_captured_ssl_request_decodes_to_the_known_code() {
    assert_eq!(REAL_SSL_REQUEST.len(), 8);
    let length = i32::from_be_bytes(REAL_SSL_REQUEST[0..4].try_into().unwrap());
    let code = i32::from_be_bytes(REAL_SSL_REQUEST[4..8].try_into().unwrap());
    assert_eq!(length, 8);
    assert_eq!(code, SSL_REQUEST_CODE);
}

#[test]
fn the_captured_startup_packet_has_a_consistent_length_field() {
    // The length advertised must equal the actual packet size - the framing rule most
    // often got wrong.
    let advertised = i32::from_be_bytes(REAL_STARTUP_PACKET[0..4].try_into().unwrap());
    assert_eq!(advertised as usize, REAL_STARTUP_PACKET.len());
}

#[test]
fn parses_the_captured_startup_body() {
    // `parse_startup` takes the body, i.e. everything after the 4-byte length.
    let body = &REAL_STARTUP_PACKET[4..];
    match parse_startup(body).expect("a real client's startup must parse") {
        StartupRequest::Startup(params) => {
            assert_eq!(params.protocol_version, 3 << 16);
            assert_eq!(params.get("user"), Some("probe_user"));
            assert_eq!(params.get("database"), Some("probe_db"));
            assert_eq!(params.len(), 2);
            assert!(params.options().is_empty(), "psycopg sent no options here");
        }
        other => panic!("expected a Startup, got {other:?}"),
    }
}

#[test]
fn reads_the_real_handshake_as_a_sequence() {
    // The actual order on the wire: SSLRequest first, then the startup packet on the
    // same connection once TLS is declined.
    let mut stream = Vec::new();
    stream.extend_from_slice(REAL_SSL_REQUEST);
    stream.extend_from_slice(REAL_STARTUP_PACKET);

    let mut reader = FrameReader::new(Cursor::new(stream));

    assert_eq!(
        reader.read_startup().expect("ssl request"),
        StartupRequest::SslRequest
    );

    match reader.read_startup().expect("startup packet") {
        StartupRequest::Startup(params) => {
            assert_eq!(params.get("user"), Some("probe_user"));
            assert_eq!(params.get("database"), Some("probe_db"));
        }
        other => panic!("expected a Startup, got {other:?}"),
    }
}

#[test]
fn parses_a_typical_orm_style_startup_with_many_parameters() {
    // Real drivers (and ORMs) send considerably more than libpq's minimal set. This is
    // synthesised rather than captured, and exists to check we do not assume a small
    // parameter list or a particular order.
    let params: &[(&str, &str)] = &[
        ("user", "app_rw"),
        ("database", "app"),
        ("application_name", "rails"),
        ("client_encoding", "UTF8"),
        ("DateStyle", "ISO, MDY"),
        ("TimeZone", "UTC"),
        ("extra_float_digits", "3"),
        (
            "options",
            "-c statement_timeout=5000 -c search_path=tenant_42",
        ),
    ];

    let mut body = pgproxy_wire::protocol::PROTOCOL_3_0.to_be_bytes().to_vec();
    for (k, v) in params {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);

    let mut packet = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    packet.extend_from_slice(&body);

    let mut reader = FrameReader::new(Cursor::new(packet));
    let StartupRequest::Startup(parsed) = reader.read_startup().expect("startup") else {
        panic!("expected Startup");
    };

    assert_eq!(parsed.get("application_name"), Some("rails"));
    assert_eq!(parsed.get("DateStyle"), Some("ISO, MDY"));
    assert_eq!(
        parsed.options(),
        vec![
            ("statement_timeout".to_string(), "5000".to_string()),
            ("search_path".to_string(), "tenant_42".to_string()),
        ],
        "GUCs smuggled through `options` must be recoverable, not dropped"
    );
}
