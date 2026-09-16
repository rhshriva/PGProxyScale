//! Capture a real client's startup bytes, for use as golden test vectors.
//!
//! Run this, then point a real driver at it:
//!
//! ```sh
//! cargo run -p pgproxy-wire --example capture_startup
//! # in another shell, from a container:
//! docker run --rm python:3.12-slim bash -c \
//!   "pip install -q 'psycopg[binary]' && python -c \
//!    \"import psycopg; psycopg.connect(host='host.docker.internal', port=6543, user='u', dbname='d')\""
//! ```
//!
//! It answers an `SSLRequest` with `N` (decline) so the plaintext startup packet that
//! follows can be captured. Keeping this as an example rather than a test means the
//! vectors are captured deliberately and pasted in with provenance, instead of the tests
//! depending on a live driver.

use std::io::{Read, Write};
use std::net::TcpListener;

const SSL_REQUEST_CODE: i32 = 80_877_103;

fn hexdump(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> std::io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:6543".to_string());
    let listener = TcpListener::bind(&addr)?;
    println!("listening on {addr}; point a client at it");

    let (mut stream, peer) = listener.accept()?;
    println!("connection from {peer}");

    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf)?;
    println!("first read: {n} bytes");
    println!("  hex: {}", hexdump(&buf[..n]));

    // Decode just enough to know whether TLS is being requested.
    if n >= 8 {
        let code = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if code == SSL_REQUEST_CODE {
            println!("  -> SSLRequest; replying 'N' to force plaintext");
            stream.write_all(b"N")?;
            stream.flush()?;

            let n2 = stream.read(&mut buf)?;
            println!("startup read: {n2} bytes");
            println!("  hex: {}", hexdump(&buf[..n2]));

            // Decode the parameter list so the capture is self-documenting.
            let body = &buf[4..n2];
            let version = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            println!("  protocol version: {} ({version})", version >> 16);
            let mut rest = &body[4..];
            while !rest.is_empty() && rest[0] != 0 {
                let k_end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
                let key = String::from_utf8_lossy(&rest[..k_end]).into_owned();
                rest = &rest[k_end + 1..];
                let v_end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
                let value = String::from_utf8_lossy(&rest[..v_end]).into_owned();
                rest = &rest[v_end + 1..];
                println!("    {key} = {value}");
            }
        }
    }

    Ok(())
}
