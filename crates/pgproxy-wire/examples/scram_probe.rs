//! A minimal authentication server, to test our SCRAM implementation against a real client.
//!
//! This answers the question the unit tests cannot: does a real PostgreSQL driver accept
//! our handshake? It performs exactly the authentication phase — startup, `SSLRequest`,
//! SASL exchange — then reports success or failure and closes. It deliberately does not
//! implement the query path, because the point is to isolate authentication.
//!
//! ```sh
//! cargo run -p pgproxy-wire --example scram_probe -- 0.0.0.0:6544 probe-secret
//! # then, from a container:
//! #   psycopg.connect(host='host.docker.internal', port=6544, user='probe',
//! #                   password='probe-secret', dbname='probe')
//! ```
//!
//! Exit code 0 means the client authenticated; 1 means it did not.

use std::io::Write;
use std::net::{TcpListener, TcpStream};

use pgproxy_wire::auth::messages::{self as auth, AuthenticationRequest};
use pgproxy_wire::auth::scram::{ScramServer, ScramVerifier};
use pgproxy_wire::protocol::backend;
use pgproxy_wire::protocol::messages as backend_messages;
use pgproxy_wire::{FrameReader, FrameWriter, StartupRequest};

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "0.0.0.0:6544".to_string());
    let password = args.next().unwrap_or_else(|| "probe-secret".to_string());
    let expect_user = args.next();

    let listener = TcpListener::bind(&addr)?;
    println!("listening on {addr}");

    // A fresh salt per run: the verifier is generated here, so nothing is stored.
    let verifier = ScramVerifier::generate(password.as_bytes());

    let (stream, peer) = listener.accept()?;
    println!("connection from {peer}");

    match authenticate(stream, verifier, expect_user.as_deref()) {
        Ok(()) => {
            println!("AUTH OK");
            std::process::exit(0);
        }
        Err(e) => {
            println!("AUTH FAILED: {e}");
            std::process::exit(1);
        }
    }
}

fn authenticate(
    stream: TcpStream,
    verifier: ScramVerifier,
    expect_user: Option<&str>,
) -> std::io::Result<()> {
    let read_stream = stream.try_clone()?;
    let mut reader = FrameReader::new(read_stream);
    let mut writer = FrameWriter::new(stream);

    // Startup, possibly preceded by an SSL negotiation we decline.
    let mut startup = reader.read_startup()?;
    if matches!(startup, StartupRequest::SslRequest) {
        println!("  client requested TLS; declining with 'N'");
        writer.get_ref().write_all(b"N")?;
        writer.flush()?;
        startup = reader.read_startup()?;
    }

    let StartupRequest::Startup(params) = startup else {
        return Err(std::io::Error::other(format!(
            "expected a startup message, got {startup:?}"
        )));
    };
    let user = params
        .get("user")
        .ok_or_else(|| std::io::Error::other("startup packet had no user"))?
        .to_string();
    println!(
        "  user={user} database={:?} protocol={}",
        params.get("database"),
        params.protocol_version
    );

    if let Some(expected) = expect_user
        && expected != user
    {
        let _ = backend_messages::send_error(
            &mut writer,
            backend_messages::Severity::Fatal,
            backend_messages::sqlstate::INVALID_AUTHORIZATION,
            "probe: unexpected user",
        );
        return Err(std::io::Error::other(format!(
            "expected user {expected:?}, got {user:?}"
        )));
    }

    // Offer SCRAM-SHA-256.
    let offer = AuthenticationRequest::Sasl {
        mechanisms: vec![ScramServer::new(verifier.clone()).mechanism().to_string()],
    };
    writer.write_message(backend::AUTHENTICATION, &offer.to_payload())?;
    writer.flush()?;

    // client-first-message
    let frame = reader
        .read_message()?
        .ok_or_else(|| std::io::Error::other("client closed before responding"))?;
    let (mechanism, client_first) = auth::parse_sasl_response(frame.payload)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mechanism = mechanism.unwrap_or_default();
    println!("  client chose mechanism {mechanism:?}");

    let mut server = ScramServer::new(verifier);

    let client_first = String::from_utf8_lossy(&client_first).into_owned();
    let server_first = match server.handle_client_first(&client_first) {
        Ok(m) => m,
        Err(e) => return fail(&mut writer, &format!("{e}")),
    };
    println!(
        "  username in SCRAM message: {:?}",
        server.client_username()
    );

    writer.write_message(
        backend::AUTHENTICATION,
        &AuthenticationRequest::SaslContinue(server_first.into_bytes()).to_payload(),
    )?;
    writer.flush()?;

    // client-final-message
    let frame = reader
        .read_message()?
        .ok_or_else(|| std::io::Error::other("client closed before the final message"))?;
    let (_, client_final) = auth::parse_sasl_response(frame.payload)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let client_final = String::from_utf8_lossy(&client_final).into_owned();
    let server_final = match server.handle_client_final(&client_final) {
        Ok(m) => m,
        // Deliberately generic: the client learns only that authentication failed.
        Err(_) => return fail(&mut writer, "password authentication failed"),
    };

    writer.write_message(
        backend::AUTHENTICATION,
        &AuthenticationRequest::SaslFinal(server_final.into_bytes()).to_payload(),
    )?;
    writer.write_message(
        backend::AUTHENTICATION,
        &AuthenticationRequest::Ok.to_payload(),
    )?;

    // The parameter set a real backend sends, so drivers finish their setup.
    for (name, value) in [
        ("server_version", "18.0"),
        ("server_encoding", "UTF8"),
        ("client_encoding", "UTF8"),
        ("DateStyle", "ISO, MDY"),
        ("TimeZone", "UTC"),
        ("integer_datetimes", "on"),
        ("standard_conforming_strings", "on"),
    ] {
        backend_messages::send_parameter_status(&mut writer, name, value)?;
    }
    backend_messages::send_backend_key_data(&mut writer, std::process::id() as i32, &[0u8; 4])?;
    backend_messages::send_ready(&mut writer, backend_messages::TransactionStatus::Idle)?;
    writer.flush()?;
    println!("  handshake complete; authentication succeeded");

    // Read whatever the client sends next, purely to confirm it is happy. A driver that
    // rejected our handshake would have closed instead.
    match reader.read_message()? {
        Some(frame) => println!(
            "  client sent {:?} (tag {}) after ReadyForQuery",
            pgproxy_wire::protocol::frontend_name(frame.tag),
            frame.tag as char
        ),
        None => println!("  client disconnected cleanly after ReadyForQuery"),
    }
    Ok(())
}

fn fail<W: Write>(writer: &mut FrameWriter<W>, message: &str) -> std::io::Result<()> {
    backend_messages::send_error(
        writer,
        backend_messages::Severity::Fatal,
        backend_messages::sqlstate::INVALID_PASSWORD,
        message,
    )?;
    writer.flush()?;
    Err(std::io::Error::other(message.to_string()))
}
