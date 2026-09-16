//! PostgreSQL wire protocol codec and connection state machine.
//!
//! Phase 0 status: framing, startup parsing and the authentication primitives are
//! implemented and tested. What remains of workstream W2 is the connection state machine
//! that drives them — the simple and extended query flows, `COPY`, cancellation routing —
//! plus TLS (`docs/plans/phase-0-foundations.md`).
//!
//! [`Service`] is the contract the runtime drives; it lives here rather than in
//! `pgproxy-core` so that the runtime can depend on the protocol layer without a cycle.
// `unsafe` is permitted in this crate only, per ADR-0001. Every block requires a
// written safety justification. See docs/adr/0001-language-and-runtime.md.
#![warn(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod auth;
pub mod protocol;
pub mod service;
pub mod session;

pub use auth::{AuthError, AuthMethod};
pub use protocol::codec::{Frame, FrameReader, FrameWriter};
pub use protocol::startup::{CancelRequest, StartupParams, StartupRequest, parse_startup};
pub use service::{Connection, Service, ShutdownToken};
pub use session::{
    BackendTarget, DatabaseRouter, RouteError, SessionOptions, SessionService, SessionStats,
};
