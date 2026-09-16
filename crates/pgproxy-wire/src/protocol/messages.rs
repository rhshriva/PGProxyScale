//! Building backend (server-to-client) messages.
//!
//! The proxy has to speak first in several places: rejecting a connection before a
//! backend exists, failing closed when policy cannot be evaluated, and answering the
//! startup handshake. Each of those is a chance to get a byte layout wrong that no
//! client will forgive, so the builders are pure functions over byte buffers with
//! golden-vector tests.

use std::io::{self, Write};

use super::codec::FrameWriter;
use super::{MIN_MESSAGE_LEN, backend};

/// SQLSTATE codes the proxy emits itself.
///
/// Chosen to match what PostgreSQL would send in the equivalent situation, so clients
/// and drivers route them through their existing error handling rather than inventing
/// a new path.
pub mod sqlstate {
    /// `08P01` — protocol violation.
    pub const PROTOCOL_VIOLATION: &str = "08P01";
    /// `28000` — invalid authorization specification.
    pub const INVALID_AUTHORIZATION: &str = "28000";
    /// `28P01` — invalid password.
    pub const INVALID_PASSWORD: &str = "28P01";
    /// `3D000` — database does not exist.
    pub const INVALID_CATALOG: &str = "3D000";
    /// `53300` — too many connections.
    pub const TOO_MANY_CONNECTIONS: &str = "53300";
    /// `57P03` — cannot connect now (starting up or shutting down).
    pub const CANNOT_CONNECT_NOW: &str = "57P03";
    /// `0A000` — feature not supported.
    pub const FEATURE_NOT_SUPPORTED: &str = "0A000";
    /// `42501` — insufficient privilege.
    pub const INSUFFICIENT_PRIVILEGE: &str = "42501";
    /// `XX000` — internal error.
    pub const INTERNAL_ERROR: &str = "XX000";
}

/// Error severity, as it appears in the `S` and `V` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// A recoverable error; the session continues.
    Error,
    /// The session is being terminated.
    Fatal,
    /// The server is in an inconsistent state.
    Panic,
}

impl Severity {
    /// The wire representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "ERROR",
            Severity::Fatal => "FATAL",
            Severity::Panic => "PANIC",
        }
    }
}

/// Transaction status reported by `ReadyForQuery`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    /// Not in a transaction block.
    Idle,
    /// Inside a transaction block.
    InTransaction,
    /// Inside a failed transaction block; only `ROLLBACK` is accepted.
    Failed,
}

impl TransactionStatus {
    /// The single-byte wire representation.
    pub fn as_byte(self) -> u8 {
        match self {
            TransactionStatus::Idle => b'I',
            TransactionStatus::InTransaction => b'T',
            TransactionStatus::Failed => b'E',
        }
    }
}

/// Build the payload of an `ErrorResponse` or `NoticeResponse`.
///
/// Layout: repeated `u8 field code` + null-terminated value, ended by a zero byte.
/// Always includes severity (`S`), non-localised severity (`V`), SQLSTATE (`C`) and
/// message (`M`) — the four fields every driver expects to find.
pub fn error_fields(severity: Severity, sqlstate: &str, message: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + sqlstate.len() + 16);
    for (code, value) in [
        (b'S', severity.as_str()),
        (b'V', severity.as_str()),
        (b'C', sqlstate),
        (b'M', message),
    ] {
        out.push(code);
        out.extend_from_slice(value.as_bytes());
        out.push(0);
    }
    // Terminator.
    out.push(0);
    out
}

/// Write an `ErrorResponse`.
pub fn send_error<W: Write>(
    writer: &mut FrameWriter<W>,
    severity: Severity,
    sqlstate: &str,
    message: &str,
) -> io::Result<()> {
    writer.write_message(
        backend::ERROR_RESPONSE,
        &error_fields(severity, sqlstate, message),
    )
}

/// Write a `NoticeResponse`, which uses the same field layout as an error.
pub fn send_notice<W: Write>(
    writer: &mut FrameWriter<W>,
    severity: Severity,
    sqlstate: &str,
    message: &str,
) -> io::Result<()> {
    writer.write_message(
        backend::NOTICE_RESPONSE,
        &error_fields(severity, sqlstate, message),
    )
}

/// Build the payload of `ReadyForQuery`: a single status byte.
pub fn ready_for_query_payload(status: TransactionStatus) -> Vec<u8> {
    vec![status.as_byte()]
}

/// Write `ReadyForQuery`.
pub fn send_ready<W: Write>(
    writer: &mut FrameWriter<W>,
    status: TransactionStatus,
) -> io::Result<()> {
    writer.write_message(backend::READY_FOR_QUERY, &ready_for_query_payload(status))
}

/// Build the payload of `ParameterStatus`: name and value, each null-terminated.
pub fn parameter_status_payload(name: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + value.len() + 2);
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    out.extend_from_slice(value.as_bytes());
    out.push(0);
    out
}

/// Write `ParameterStatus`.
pub fn send_parameter_status<W: Write>(
    writer: &mut FrameWriter<W>,
    name: &str,
    value: &str,
) -> io::Result<()> {
    writer.write_message(
        backend::PARAMETER_STATUS,
        &parameter_status_payload(name, value),
    )
}

/// Write `AuthenticationOk`, the final step of a successful handshake.
///
/// Payload is a single `Int32` with value zero.
pub fn send_authentication_ok<W: Write>(writer: &mut FrameWriter<W>) -> io::Result<()> {
    writer.write_message(backend::AUTHENTICATION, &0i32.to_be_bytes())
}

/// Build the payload of `BackendKeyData`.
///
/// The key is bytes rather than an integer on purpose: protocol 3.2 (PostgreSQL 18)
/// allows keys up to 256 bits, so the historical fixed 4-byte form is not the only
/// legal shape. A proxy that virtualises cancellation must be able to issue any length.
pub fn backend_key_data_payload(process_id: i32, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + key.len());
    out.extend_from_slice(&process_id.to_be_bytes());
    out.extend_from_slice(key);
    out
}

/// Write `BackendKeyData`.
pub fn send_backend_key_data<W: Write>(
    writer: &mut FrameWriter<W>,
    process_id: i32,
    key: &[u8],
) -> io::Result<()> {
    writer.write_message(
        backend::BACKEND_KEY_DATA,
        &backend_key_data_payload(process_id, key),
    )
}

/// Write a `CommandComplete` carrying a command tag.
pub fn send_command_complete<W: Write>(writer: &mut FrameWriter<W>, tag: &str) -> io::Result<()> {
    let mut payload = Vec::with_capacity(tag.len() + 1);
    payload.extend_from_slice(tag.as_bytes());
    payload.push(0);
    writer.write_message(backend::COMMAND_COMPLETE, &payload)
}

/// The framed length of a message with the given payload size.
///
/// Exposed because tests and callers reasonably want to assert framing without
/// duplicating the off-by-one that this module exists to prevent.
pub fn framed_len(payload_len: usize) -> usize {
    1 + MIN_MESSAGE_LEN as usize + payload_len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::codec::FrameReader;
    use std::io::Cursor;

    fn parse_one(bytes: &[u8]) -> (u8, Vec<u8>) {
        let mut reader = FrameReader::new(Cursor::new(bytes.to_vec()));
        let frame = reader.read_message().unwrap().expect("a message");
        (frame.tag, frame.payload.to_vec())
    }

    #[test]
    fn error_response_field_layout_is_exact() {
        let payload = error_fields(Severity::Fatal, "3D000", "no such db");
        // S<VALUE>\0 V<VALUE>\0 C<VALUE>\0 M<VALUE>\0 \0
        let expected: Vec<u8> = [
            b"S".as_slice(),
            b"FATAL\0",
            b"V",
            b"FATAL\0",
            b"C",
            b"3D000\0",
            b"M",
            b"no such db\0",
            b"\0",
        ]
        .concat();
        assert_eq!(payload, expected);
    }

    #[test]
    fn error_response_always_carries_the_four_required_fields() {
        let payload = error_fields(Severity::Error, "XX000", "boom");
        let text = String::from_utf8_lossy(&payload);
        for required in ["S", "V", "C", "M"] {
            assert!(
                text.contains(required),
                "missing field {required} in {text:?}"
            );
        }
        assert_eq!(*payload.last().unwrap(), 0, "must end with a terminator");
    }

    #[test]
    fn ready_for_query_is_exactly_one_status_byte() {
        for (status, byte) in [
            (TransactionStatus::Idle, b'I'),
            (TransactionStatus::InTransaction, b'T'),
            (TransactionStatus::Failed, b'E'),
        ] {
            let payload = ready_for_query_payload(status);
            assert_eq!(payload, vec![byte]);
        }
    }

    #[test]
    fn parameter_status_is_two_null_terminated_strings() {
        assert_eq!(
            parameter_status_payload("client_encoding", "UTF8"),
            b"client_encoding\0UTF8\0".to_vec()
        );
    }

    #[test]
    fn authentication_ok_is_a_zero_int32() {
        let mut writer = FrameWriter::new(Vec::new());
        send_authentication_ok(&mut writer).unwrap();
        let (tag, payload) = parse_one(&writer.into_inner());
        assert_eq!(tag, backend::AUTHENTICATION);
        assert_eq!(payload, vec![0, 0, 0, 0]);
    }

    #[test]
    fn backend_key_data_supports_a_variable_length_key() {
        // 3.0 shape: 4-byte pid + 4-byte secret = 8-byte payload.
        let short = backend_key_data_payload(1, &[0xAA; 4]);
        assert_eq!(short.len(), 8);

        // 3.2 shape: a 32-byte key must be representable.
        let long = backend_key_data_payload(1, &[0xBB; 32]);
        assert_eq!(long.len(), 36);
    }

    #[test]
    fn command_complete_carries_a_null_terminated_tag() {
        let mut writer = FrameWriter::new(Vec::new());
        send_command_complete(&mut writer, "SELECT 1").unwrap();
        let (tag, payload) = parse_one(&writer.into_inner());
        assert_eq!(tag, backend::COMMAND_COMPLETE);
        assert_eq!(payload, b"SELECT 1\0".to_vec());
    }

    #[test]
    fn framed_len_matches_what_the_writer_produces() {
        for payload_len in [0usize, 1, 7, 1000] {
            let payload = vec![0u8; payload_len];
            let mut writer = FrameWriter::new(Vec::new());
            writer.write_message(backend::DATA_ROW, &payload).unwrap();
            assert_eq!(writer.into_inner().len(), framed_len(payload_len));
        }
    }

    #[test]
    fn every_builder_produces_a_message_our_own_reader_accepts() {
        // Round-tripping through our reader is a weak check on its own, but it does
        // catch framing mistakes, which is the failure mode that matters here.
        let mut writer = FrameWriter::new(Vec::new());
        send_error(&mut writer, Severity::Fatal, "53300", "too many").unwrap();
        send_notice(&mut writer, Severity::Error, "01000", "heads up").unwrap();
        send_ready(&mut writer, TransactionStatus::Idle).unwrap();
        send_parameter_status(&mut writer, "server_version", "18.0").unwrap();
        send_backend_key_data(&mut writer, 99, &[1, 2, 3, 4]).unwrap();

        let bytes = writer.into_inner();
        let mut reader = FrameReader::new(Cursor::new(bytes));
        let tags: Vec<u8> =
            std::iter::from_fn(|| reader.read_message().unwrap().map(|f| f.tag)).collect();

        assert_eq!(
            tags,
            vec![
                backend::ERROR_RESPONSE,
                backend::NOTICE_RESPONSE,
                backend::READY_FOR_QUERY,
                backend::PARAMETER_STATUS,
                backend::BACKEND_KEY_DATA,
            ]
        );
    }
}
