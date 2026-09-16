//! PostgreSQL wire protocol codec and connection state machine.
//!
//! Phase 0 status: the framing layer and startup parsing are implemented and tested.
//! Authentication, the simple and extended query state machines, `COPY` and cancellation
//! routing are workstream W2 (`docs/plans/phase-0-foundations.md`).
//!
//! [`Service`] is the contract the runtime drives; it lives here rather than in
//! `pgproxy-core` so that the runtime can depend on the protocol layer without a cycle,
//! and so an embedder can implement it directly.
// `unsafe` is permitted in this crate only, per ADR-0001. Every block requires a
// written safety justification. See docs/adr/0001-language-and-runtime.md.
#![warn(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod protocol;
pub mod service;

pub use protocol::codec::{Frame, FrameReader, FrameWriter};
pub use protocol::startup::{CancelRequest, StartupParams, StartupRequest, parse_startup};
pub use service::{Connection, Service, ShutdownToken};
