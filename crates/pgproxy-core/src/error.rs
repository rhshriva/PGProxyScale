//! Error taxonomy for startup, configuration and supervision.
//!
//! Rule: nothing on a protocol path may `unwrap`/`expect`. Errors are typed and carry
//! the address, path or worker that produced them, because the first question an
//! operator asks is always "which one?".

use std::path::PathBuf;

/// Errors produced while loading configuration, binding, or running.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The configuration was syntactically valid but semantically wrong.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// The configuration file could not be read.
    #[error("cannot read config file {path}: {source}")]
    ConfigRead {
        /// Path that was attempted.
        path: PathBuf,
        /// Underlying I/O failure.
        source: std::io::Error,
    },

    /// The configuration file was not valid TOML, or had unknown/missing fields.
    #[error("cannot parse config file {path}: {source}")]
    ConfigParse {
        /// Path that was attempted.
        path: PathBuf,
        /// Underlying parse failure.
        source: Box<toml::de::Error>,
    },

    /// `listen_addr` is not a valid IP address.
    #[error("invalid listen address {addr:?}: {source}")]
    ListenAddr {
        /// The offending value.
        addr: String,
        /// Underlying parse failure.
        source: std::net::AddrParseError,
    },

    /// Binding a listener failed.
    #[error("cannot bind {addr}: {source}")]
    Bind {
        /// Address that could not be bound.
        addr: std::net::SocketAddr,
        /// Underlying I/O failure.
        source: std::io::Error,
    },

    /// Installing a signal handler failed.
    #[error("cannot install signal handler: {0}")]
    Signal(std::io::Error),

    /// The polling facility failed.
    #[error("poll failed: {0}")]
    Poll(std::io::Error),

    /// A worker thread could not be spawned.
    #[error("cannot spawn worker thread {worker}: {source}")]
    Spawn {
        /// Index of the worker.
        worker: usize,
        /// Underlying I/O failure.
        source: std::io::Error,
    },

    /// A worker thread panicked. The process is not safe to continue.
    #[error("worker thread {worker} panicked")]
    WorkerPanic {
        /// Index of the worker.
        worker: usize,
    },

    /// Logging could not be initialised.
    #[error("cannot initialise logging: {0}")]
    Telemetry(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
