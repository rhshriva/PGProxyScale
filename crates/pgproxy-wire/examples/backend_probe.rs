//! Connect to a live PostgreSQL as a client, to validate [`BackendConnection`].
//!
//! The unit tests cover payload parsing; this covers the parts only a real server can
//! exercise: the startup exchange, the SCRAM client flow, and `ReadyForQuery` handling.
//! Transaction pooling depends on all three.
//!
//! ```sh
//! cargo run -p pgproxy-wire --example backend_probe -- 127.0.0.1 5432 conformance postgres [password]
//! ```

use std::time::Duration;

use pgproxy_wire::backend::{BackendConnection, BackendCredentials};
use pgproxy_wire::session::BackendTarget;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "127.0.0.1".to_string());
    let port: u16 = args.next().unwrap_or_else(|| "5432".to_string()).parse()?;
    let database = args.next().unwrap_or_else(|| "conformance".to_string());
    let user = args.next().unwrap_or_else(|| "postgres".to_string());
    let password = args.next();

    let target = BackendTarget {
        host,
        port,
        database: Some(database.clone()),
        user: None,
    };
    let credentials = BackendCredentials {
        user: user.clone(),
        password,
        database: Some(database.clone()),
        application_name: Some("pgproxy-backend-probe".to_string()),
    };

    let started = std::time::Instant::now();
    let mut connection =
        BackendConnection::connect(&target, &credentials, Duration::from_secs(10), 1 << 30)?;
    println!(
        "CONNECTED in {:?}: user={} database={} backend_pid={} parameters={}",
        started.elapsed(),
        connection.user(),
        connection.database(),
        connection.process_id(),
        connection.parameters().len(),
    );
    if let Some(version) = connection.parameter("server_version") {
        println!("  server_version = {version}");
    }
    println!("  cancel_key length = {}", connection.cancel_key().len());

    let status = connection.simple_query("SELECT 1")?;
    println!("SIMPLE QUERY ok, transaction status = {} ", status as char);

    // The reset every transaction-pooled connection gets before reuse.
    let status = connection.simple_query("DISCARD ALL")?;
    println!("DISCARD ALL ok, transaction status = {}", status as char);

    // A statement that must fail, to prove error responses are parsed and surfaced.
    match connection.simple_query("SELECT * FROM definitely_not_a_table") {
        Ok(_) => {
            println!("UNEXPECTED: a bad query succeeded");
            std::process::exit(1);
        }
        Err(e) => {
            let text = e.to_string();
            println!("BAD QUERY rejected as expected: {}", &text[..text.len().min(90)]);
            if !text.contains("SQLSTATE") {
                println!("  WARNING: the error carried no SQLSTATE");
            }
        }
    }

    // DISCARD ALL dropped the failed-transaction state, so the connection is reusable.
    let status = connection.simple_query("SELECT 1")?;
    println!("RECOVERED, transaction status = {}", status as char);

    connection.terminate();
    println!("OK");
    Ok(())
}
