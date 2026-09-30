//! Logging initialisation.

use tracing_subscriber::EnvFilter;

use crate::config::{LogFormat, Logging};
use crate::error::{Error, Result};

/// Install the global tracing subscriber.
///
/// Called once, from the host process, before anything logs. An embedder that already
/// has a subscriber should skip this and keep its own.
pub fn init(logging: &Logging) -> Result<()> {
    // An invalid directive should not stop the proxy from starting with a usable
    // default; but it must be visible, so it is reported after init.
    let (filter, filter_error) = match EnvFilter::try_new(&logging.level) {
        Ok(f) => (f, None),
        Err(e) => (EnvFilter::new("info"), Some(e.to_string())),
    };

    let result = match logging.format {
        LogFormat::Text => tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .with_target(false)
            .try_init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .with_target(false)
            .try_init(),
    };

    result.map_err(|e| Error::Telemetry(e.to_string()))?;

    if let Some(err) = filter_error {
        tracing::warn!(
            directive = %logging.level,
            error = %err,
            "invalid log filter directive; falling back to 'info'"
        );
    }

    Ok(())
}
