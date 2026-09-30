#![no_main]
use libfuzzer_sys::fuzz_target;
use pgproxy_wire::FrameReader;
use std::io::Cursor;
fuzz_target!(|data: &[u8]| {
    let mut reader = FrameReader::with_max_message_len(Cursor::new(data), 64 * 1024);
    // Exercise the startup path independently: all errors are legitimate outcomes.
    let _ = reader.read_startup();
    let mut reader = FrameReader::with_max_message_len(Cursor::new(data), 64 * 1024);
    for _ in 0..128 {
        match reader.read_message() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    // The limit bounds payload bytes; storage includes a five-byte wire header
    // and Vec may reserve up to twice the requested size during reuse.
    assert!(reader.buffer_capacity() <= 2 * (64 * 1024 + 5));
});
