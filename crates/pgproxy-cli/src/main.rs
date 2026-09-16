//! The `pgproxy` binary.
//!
//! A thin adapter: parse arguments, load and validate configuration, install logging,
//! hand a [`Service`] to the runtime. All the interesting behaviour lives in
//! `pgproxy-core` and, from workstream W2, `pgproxy-wire`.
//!
//! Keeping this file thin is deliberate — an embedded or sidecar host must be able to
//! reuse everything below it without dragging along CLI concerns (ADR-0005).

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use pgproxy_core::config::{Config, Overrides};
use pgproxy_core::{Runtime, telemetry};
use pgproxy_wire::{Connection, Service};

/// Protocol-aware PostgreSQL gateway.
#[derive(Debug, Parser)]
#[command(name = "pgproxy", version, about, long_about = None)]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, value_name = "PATH", default_value = "pgproxy.toml")]
    config: PathBuf,

    /// Worker threads. 0 means one per available CPU.
    #[arg(long, value_name = "N")]
    workers: Option<usize>,

    /// Listen port, overriding the configuration file.
    #[arg(long, value_name = "PORT")]
    port: Option<u16>,

    /// Log filter directive, e.g. "info" or "pgproxy_wire=debug,info".
    #[arg(long, value_name = "DIRECTIVE")]
    log_level: Option<String>,

    /// Validate the configuration and exit without serving.
    #[arg(long)]
    check: bool,
}

/// Placeholder until workstream W2 lands the protocol state machine.
///
/// It accepts the connection so that listener, accept-path and shutdown behaviour are
/// exercisable, then closes it with a log line explaining why.
struct ProtocolNotImplemented;

impl Service for ProtocolNotImplemented {
    fn handle(&self, conn: Connection) -> std::io::Result<()> {
        tracing::warn!(
            id = conn.id,
            worker = conn.worker,
            peer = %conn.peer,
            "accepted a connection, but the PostgreSQL wire protocol is not implemented yet \
             (Phase 0 workstream W2) - closing"
        );
        let _ = conn.stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Errors here are startup errors: config, bind, signals. There is no logging
            // subscriber yet in the failure path, so write to stderr directly.
            eprintln!("pgproxy: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::from_file_with_env(&cli.config)?;
    config.apply_overrides(&Overrides {
        workers: cli.workers,
        log_level: cli.log_level.clone(),
        listen_port: cli.port,
    });
    config.validate()?;

    telemetry::init(&config.logging)?;

    let path = Config::display_path(&cli.config);
    tracing::debug!(config = %path.display(), "configuration loaded and validated");

    if cli.check {
        tracing::info!(config = %path.display(), "configuration is valid");
        return Ok(());
    }

    Runtime::new(config, Arc::new(ProtocolNotImplemented)).run()?;
    Ok(())
}
