#![no_main]
use libfuzzer_sys::fuzz_target;
use pgproxy_parser::{ParseOptions, parse};
fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let Ok(sql) = std::str::from_utf8(data) else {
        return;
    };
    let options = ParseOptions {
        backend_major: 14 + data.first().copied().unwrap_or(0) as u16 % 5,
        standard_conforming_strings: data.len() % 2 == 0,
        backslash_quote: data.len() % 3 != 0,
    };
    let _ = parse(sql, options, 64 * 1024, 256 * 1024);
});
