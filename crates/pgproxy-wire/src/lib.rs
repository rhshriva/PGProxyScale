//! PostgreSQL wire protocol codec and connection state machine.
//!
//! Phase 0 status: this crate currently defines only the [`Service`] contract that the
//! runtime drives. The protocol itself — message codec, startup, authentication,
//! simple and extended query flows, `COPY`, cancellation — is workstream W2
//! (`docs/plans/phase-0-foundations.md`).
// `unsafe` is permitted in this crate only, per ADR-0001. Every block requires a
// written safety justification. See docs/adr/0001-language-and-runtime.md.
#![warn(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod service;

pub use service::{Connection, Service, ShutdownToken};
