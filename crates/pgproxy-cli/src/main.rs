//! The `pgproxy` binary.
//!
//! A thin adapter: parse arguments, load and validate configuration, install logging,
//! hand a [`Service`] to the runtime. All the interesting behaviour lives in
//! `pgproxy-core` and `pgproxy-wire`.
//!
//! Keeping this file thin is deliberate — an embedded or sidecar host must be able to
//! reuse everything below it without dragging along CLI concerns (ADR-0005).

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use pgproxy_core::config::{Config, Overrides};
use pgproxy_core::router::ConfigRouter;
use pgproxy_core::{Runtime, telemetry};
mod report;

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
    /// Serve bounded MCP JSON-RPC on stdin/stdout as an explicitly configured agent.
    #[arg(long, requires_all=["mcp_database","mcp_user"])]
    mcp_stdio: bool,
    #[arg(long, requires = "mcp_stdio")]
    mcp_database: Option<String>,
    #[arg(long, requires = "mcp_stdio")]
    mcp_user: Option<String>,
    /// Export measured MCP usage on clean EOF; unavailable server counters remain null.
    #[arg(long, requires = "mcp_stdio")]
    mcp_usage_report: Option<PathBuf>,
    /// Export actual PostgreSQL role/queryid cost counters and exit.
    #[arg(long, requires_all=["server_cost_user", "server_cost_report"], conflicts_with_all=["mcp_stdio", "check"])]
    server_cost_database: Option<String>,
    #[arg(long, requires = "server_cost_database")]
    server_cost_user: Option<String>,
    #[arg(long, requires = "server_cost_database")]
    server_cost_report: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Startup errors: config, bind, signals. There may be no logging subscriber
            // yet on this path, so write to stderr directly.
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

    // Validate certificate/key material even for --check, before binding a listener.
    let _frontend_tls = config
        .general
        .tls
        .as_ref()
        .map(|tls| {
            pgproxy_wire::tls::FrontendTls::from_pem_with_ca(
                &tls.certificate,
                &tls.private_key,
                tls.required,
                tls.client_ca.as_deref(),
            )
        })
        .transpose()?;

    let router = ConfigRouter::try_new(&config)?;
    if cli.check {
        tracing::info!(config = %path.display(), "configuration is valid");
        return Ok(());
    }

    if let Some(database) = cli.server_cost_database.as_deref() {
        let resolved = selected_route(&router, database, cli.server_cost_user.as_deref().unwrap())?;
        let cost =
            pgproxy_core::attribution::collect_server_cost(&resolved, &config.session_options())?;
        report::write(
            cli.server_cost_report.as_deref().unwrap(),
            &serde_json::to_value(cost)?,
        )?;
        return Ok(());
    }

    if cli.mcp_stdio {
        return serve_mcp(
            &config,
            &router,
            cli.mcp_database.as_deref().unwrap(),
            cli.mcp_user.as_deref().unwrap(),
            cli.mcp_usage_report.as_deref(),
        );
    }
    tracing::info!(databases = ?router.database_names(), "routing table");

    let operations = config.session_options().operations;
    let service = Arc::new(pgproxy_core::reload::ManagedService::new(
        &config,
        Arc::clone(&operations),
    )?);
    let observed = Arc::clone(&service);
    let diagnostics = Arc::new(move || {
        let pools=observed.pool_stats().into_iter().take(256).map(|(name,s)|serde_json::json!({"pool":name,"total":s.total,"idle":s.idle,"waiters":s.waiters,"created":s.created,"reused":s.reused,"discarded":s.discarded,"timeouts":s.timeouts})).collect::<Vec<_>>();
        serde_json::to_string(&pools).unwrap_or_else(|_| "[]".into())
    });
    let controlled = Arc::clone(&service);
    let config_path = cli.config.clone();
    let overrides = Overrides {
        workers: cli.workers,
        log_level: cli.log_level,
        listen_port: cli.port,
    };
    let control = Arc::new(move |path: &str| -> Result<String, String> {
        let load = || {
            let mut cfg = Config::from_file_with_env(&config_path).map_err(|e| e.to_string())?;
            cfg.apply_overrides(&overrides);
            Ok::<_, String>(cfg)
        };
        match path {
            "/reload" => {
                controlled.reload(&load()?).map_err(|e| e.to_string())?;
            }
            "/switchover/prepare" => controlled.prepare_switchover().map_err(|e| e.to_string())?,
            "/switchover/commit" => {
                controlled
                    .commit_if_idle(&load()?)
                    .map_err(|e| e.to_string())?;
            }
            "/switchover/abort" => controlled.abort_switchover().map_err(|e| e.to_string())?,
            _ => return Err("unknown control action".into()),
        }
        serde_json::to_string(&controlled.snapshot()).map_err(|e| e.to_string())
    });
    Runtime::new(config, service)
        .with_operations(operations, diagnostics)
        .with_control(control)
        .run()?;
    Ok(())
}

/// Local stdio transport: process/config access authorizes the selected immutable agent.
/// Exposing this process remotely requires authentication in the supervising transport.
fn serve_mcp(
    config: &Config,
    router: &ConfigRouter,
    database: &str,
    user: &str,
    usage_report: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufRead, Read, Write};
    let resolved = selected_route(router, database, user)?;
    let route = resolved
        .governance
        .as_ref()
        .ok_or("MCP requires configured SQL policy")?;
    let principal = route
        .principals
        .get(user)
        .ok_or("unknown MCP principal")?
        .clone();
    let mut gateway = pgproxy_policy::agent::AgentGateway::new(
        route.policy.clone(),
        route.admission.clone(),
        1000,
        1024 * 1024,
    )?;
    if let Some((scheduler, wait)) = &route.scheduler {
        gateway = gateway.with_scheduler(Arc::clone(scheduler), *wait);
    }
    let context = route.contexts.get(&principal).cloned();
    let executor = pgproxy_core::mcp_executor::PgExecutor::new(resolved, config.session_options())?
        .with_context(context)
        .with_principal(principal.clone());
    let usage_operations = Arc::clone(&config.session_options().operations);
    let mut server = pgproxy_policy::mcp::McpServer::new(gateway, principal, executor, 65536)?
        .with_observer(Arc::new(pgproxy_core::usage::UsageObserver(Arc::clone(
            &usage_operations,
        ))));
    let input = std::io::stdin();
    let mut input = input.lock();
    let output = std::io::stdout();
    let mut output = output.lock();
    loop {
        let mut line = Vec::new();
        let n = Read::take(&mut input, 65537).read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        if line.len() > 65536 {
            return Err("MCP request exceeds size limit".into());
        }
        if let Some(response) = server.dispatch(&line) {
            serde_json::to_writer(&mut output, &response)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
    if let Some(path) = usage_report {
        report::write(
            path,
            &serde_json::json!({"accounts":usage_operations.usage_report(),"dropped_samples":usage_operations.usage_dropped(),"measurement":"authorized MCP tools; client elapsed time, rows and serialized result bytes; server CPU/buffer/WAL unavailable"}),
        )?;
    }
    Ok(())
}

fn selected_route(
    router: &ConfigRouter,
    database: &str,
    user: &str,
) -> Result<pgproxy_wire::ResolvedBackend, Box<dyn std::error::Error>> {
    use pgproxy_wire::DatabaseRouter;
    if database.is_empty() || user.is_empty() || database.contains('\0') || user.contains('\0') {
        return Err("invalid configured route identity".into());
    }
    let mut body = pgproxy_wire::protocol::PROTOCOL_3_0.to_be_bytes().to_vec();
    for (key, value) in [("user", user), ("database", database)] {
        body.extend_from_slice(key.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    let pgproxy_wire::protocol::StartupRequest::Startup(params) =
        pgproxy_wire::protocol::parse_startup(&body)?
    else {
        return Err("invalid configured route identity".into());
    };
    Ok(router.route(&params)?)
}
