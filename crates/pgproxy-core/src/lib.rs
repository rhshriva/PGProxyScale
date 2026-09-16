//! Runtime bootstrap, configuration and supervision.
//!
//! This crate owns the process-level concerns: loading and validating configuration,
//! binding listeners, running the thread-per-core accept loop, and shutting down.
//!
//! It deliberately does **not** own the PostgreSQL wire protocol — that is
//! [`pgproxy_wire`] — nor the data path. The service to run is supplied by the caller
//! as a [`pgproxy_wire::Service`], which keeps this crate usable by a future sidecar or
//! embedded host without redesign (ADR-0005).
//!
//! Concurrency model: one OS thread per core, each owning its own `SO_REUSEPORT`
//! listener and its own state, with one thread per connection for the data path. Chosen
//! on measurement, not preference — see `docs/plans/spike-findings.md` (spike S1).
#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod listener;
pub mod router;
pub mod runtime;
pub mod telemetry;

pub use config::Config;
pub use error::{Error, Result};
pub use router::ConfigRouter;
pub use runtime::Runtime;
