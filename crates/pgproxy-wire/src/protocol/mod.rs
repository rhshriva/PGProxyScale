//! PostgreSQL wire protocol, version 3.
//!
//! Two phases, two shapes:
//!
//! * **Startup** — an untyped message: `Int32 length`, `Int32 code`, then either a list
//!   of null-terminated key/value pairs (a normal startup) or nothing (the special
//!   `SSLRequest` / `GSSENCRequest` / `CancelRequest` forms).
//! * **Everything after** — typed messages: `u8 tag`, `Int32 length`, payload. The length
//!   **includes the four length bytes but excludes the tag**, which is the single most
//!   commonly mis-implemented detail in this protocol.
//!
//! This module is pure: it parses and builds byte buffers and never touches a socket it
//! does not own, so the whole protocol surface is unit-testable without a server.

pub mod codec;
pub mod messages;
pub mod startup;

/// Protocol 3.0: `major << 16 | minor`.
pub const PROTOCOL_3_0: i32 = 3 << 16;
/// Protocol 3.2, introduced in PostgreSQL 18.
///
/// Relevant to us because it makes cancellation keys variable-length, breaking the fixed
/// 12-byte assumption every current proxy makes. See [`startup::CancelRequest`].
pub const PROTOCOL_3_2: i32 = (3 << 16) | 2;

/// `SSLRequest` code, sent in place of a protocol version.
pub const SSL_REQUEST_CODE: i32 = 80_877_103;
/// `GSSENCRequest` code, sent in place of a protocol version.
pub const GSSENC_REQUEST_CODE: i32 = 80_877_104;
/// `CancelRequest` code, sent in place of a protocol version.
pub const CANCEL_REQUEST_CODE: i32 = 80_877_102;

/// Smallest legal value of a typed message's length field: it must at least cover itself.
pub const MIN_MESSAGE_LEN: i32 = 4;

/// Default cap on a single message.
///
/// Matches PostgreSQL's own 1 GiB limit on a message (`MaxAllocSize` is 1 GiB - 1, and
/// `PQ_LARGE_MESSAGE_LIMIT` is below that), rather than the 2 GiB-1 that PgBouncer allows
/// by default — an unbounded frame is a trivial memory-exhaustion vector from an
/// untrusted client, which matters once agents are on the other end.
pub const DEFAULT_MAX_MESSAGE_LEN: usize = 1 << 30;

/// Frontend (client to server) message tags.
pub mod frontend {
    /// `Bind`
    pub const BIND: u8 = b'B';
    /// `Close`
    pub const CLOSE: u8 = b'C';
    /// `CopyData`
    pub const COPY_DATA: u8 = b'd';
    /// `CopyDone`
    pub const COPY_DONE: u8 = b'c';
    /// `CopyFail`
    pub const COPY_FAIL: u8 = b'f';
    /// `Describe`
    pub const DESCRIBE: u8 = b'D';
    /// `Execute`
    pub const EXECUTE: u8 = b'E';
    /// `Flush`
    pub const FLUSH: u8 = b'H';
    /// `FunctionCall`
    pub const FUNCTION_CALL: u8 = b'F';
    /// `Parse`
    pub const PARSE: u8 = b'P';
    /// `PasswordMessage`, also used for SASL responses.
    pub const PASSWORD: u8 = b'p';
    /// `Query` — the simple query protocol.
    pub const QUERY: u8 = b'Q';
    /// `Sync`
    pub const SYNC: u8 = b'S';
    /// `Terminate`
    pub const TERMINATE: u8 = b'X';

    /// Whether a tag is a message a *client* may send after startup.
    pub fn is_valid(tag: u8) -> bool {
        matches!(
            tag,
            BIND | CLOSE
                | COPY_DATA
                | COPY_DONE
                | COPY_FAIL
                | DESCRIBE
                | EXECUTE
                | FLUSH
                | FUNCTION_CALL
                | PARSE
                | PASSWORD
                | QUERY
                | SYNC
                | TERMINATE
        )
    }
}

/// Backend (server to client) message tags.
pub mod backend {
    /// `Authentication`
    pub const AUTHENTICATION: u8 = b'R';
    /// `BackendKeyData`
    pub const BACKEND_KEY_DATA: u8 = b'K';
    /// `BindComplete`
    pub const BIND_COMPLETE: u8 = b'2';
    /// `CloseComplete`
    pub const CLOSE_COMPLETE: u8 = b'3';
    /// `CommandComplete`
    pub const COMMAND_COMPLETE: u8 = b'C';
    /// `CopyData`
    pub const COPY_DATA: u8 = b'd';
    /// `CopyDone`
    pub const COPY_DONE: u8 = b'c';
    /// `CopyInResponse`
    pub const COPY_IN_RESPONSE: u8 = b'G';
    /// `CopyOutResponse`
    pub const COPY_OUT_RESPONSE: u8 = b'H';
    /// `CopyBothResponse`
    pub const COPY_BOTH_RESPONSE: u8 = b'W';
    /// `DataRow`
    pub const DATA_ROW: u8 = b'D';
    /// `EmptyQueryResponse`
    pub const EMPTY_QUERY_RESPONSE: u8 = b'I';
    /// `ErrorResponse`
    pub const ERROR_RESPONSE: u8 = b'E';
    /// `FunctionCallResponse`
    pub const FUNCTION_CALL_RESPONSE: u8 = b'V';
    /// `NegotiateProtocolVersion`
    pub const NEGOTIATE_PROTOCOL_VERSION: u8 = b'v';
    /// `NoData`
    pub const NO_DATA: u8 = b'n';
    /// `NoticeResponse`
    pub const NOTICE_RESPONSE: u8 = b'N';
    /// `NotificationResponse`
    pub const NOTIFICATION_RESPONSE: u8 = b'A';
    /// `ParameterDescription`
    pub const PARAMETER_DESCRIPTION: u8 = b't';
    /// `ParameterStatus`
    pub const PARAMETER_STATUS: u8 = b'S';
    /// `ParseComplete`
    pub const PARSE_COMPLETE: u8 = b'1';
    /// `PortalSuspended`
    pub const PORTAL_SUSPENDED: u8 = b's';
    /// `ReadyForQuery`
    pub const READY_FOR_QUERY: u8 = b'Z';
    /// `RowDescription`
    pub const ROW_DESCRIPTION: u8 = b'T';
}

/// Human-readable name for a message tag, for logs and error messages.
///
/// Tag values collide between directions (for example `S` is `Sync` from a client and
/// `ParameterStatus` from a server), so names are resolved per direction.
pub fn frontend_name(tag: u8) -> &'static str {
    match tag {
        frontend::BIND => "Bind",
        frontend::CLOSE => "Close",
        frontend::COPY_DATA => "CopyData",
        frontend::COPY_DONE => "CopyDone",
        frontend::COPY_FAIL => "CopyFail",
        frontend::DESCRIBE => "Describe",
        frontend::EXECUTE => "Execute",
        frontend::FLUSH => "Flush",
        frontend::FUNCTION_CALL => "FunctionCall",
        frontend::PARSE => "Parse",
        frontend::PASSWORD => "PasswordMessage",
        frontend::QUERY => "Query",
        frontend::SYNC => "Sync",
        frontend::TERMINATE => "Terminate",
        _ => "Unknown",
    }
}

/// Human-readable name for a backend message tag.
pub fn backend_name(tag: u8) -> &'static str {
    match tag {
        backend::AUTHENTICATION => "Authentication",
        backend::BACKEND_KEY_DATA => "BackendKeyData",
        backend::BIND_COMPLETE => "BindComplete",
        backend::CLOSE_COMPLETE => "CloseComplete",
        backend::COMMAND_COMPLETE => "CommandComplete",
        backend::COPY_DATA => "CopyData",
        backend::COPY_DONE => "CopyDone",
        backend::COPY_IN_RESPONSE => "CopyInResponse",
        backend::COPY_OUT_RESPONSE => "CopyOutResponse",
        backend::COPY_BOTH_RESPONSE => "CopyBothResponse",
        backend::DATA_ROW => "DataRow",
        backend::EMPTY_QUERY_RESPONSE => "EmptyQueryResponse",
        backend::ERROR_RESPONSE => "ErrorResponse",
        backend::FUNCTION_CALL_RESPONSE => "FunctionCallResponse",
        backend::NEGOTIATE_PROTOCOL_VERSION => "NegotiateProtocolVersion",
        backend::NO_DATA => "NoData",
        backend::NOTICE_RESPONSE => "NoticeResponse",
        backend::NOTIFICATION_RESPONSE => "NotificationResponse",
        backend::PARAMETER_DESCRIPTION => "ParameterDescription",
        backend::PARAMETER_STATUS => "ParameterStatus",
        backend::PARSE_COMPLETE => "ParseComplete",
        backend::PORTAL_SUSPENDED => "PortalSuspended",
        backend::READY_FOR_QUERY => "ReadyForQuery",
        backend::ROW_DESCRIPTION => "RowDescription",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_encoding() {
        // The encoding is major << 16 | minor, which is why 3.0 is 196608.
        assert_eq!(PROTOCOL_3_0, 196_608);
        assert_eq!(PROTOCOL_3_2, 196_610);
        assert_eq!(PROTOCOL_3_0 >> 16, 3);
        assert_eq!(PROTOCOL_3_2 & 0xffff, 2);
    }

    #[test]
    fn frontend_tag_validation_rejects_backend_only_tags() {
        assert!(frontend::is_valid(frontend::QUERY));
        assert!(frontend::is_valid(frontend::PARSE));
        // 'R' is Authentication, server-to-client only.
        assert!(!frontend::is_valid(backend::AUTHENTICATION));
        assert!(!frontend::is_valid(0));
    }

    #[test]
    fn names_are_direction_specific() {
        // 'S' collides by design between the two directions.
        assert_eq!(frontend_name(b'S'), "Sync");
        assert_eq!(backend_name(b'S'), "ParameterStatus");
    }
}
