# Bounded fuzz targets

Use a nightly Rust toolchain and cargo-fuzz:

```
cargo +nightly fuzz run codec -- -max_len=65536 -max_total_time=60
cargo +nightly fuzz run parser -- -max_len=65536 -max_total_time=60
```

The codec target independently probes startup and regular framing with a bounded
message size and iteration count. The parser target exercises the vendored C FFI
with valid UTF-8, version tags 14–18 and parser-affecting options; SQL and output
limits remain active. Seeds cover startup, a simple query, settings and PREPARE.

These are fuzzing entry points and a reproducible bounded smoke campaign, not
proof of memory safety or exhaustive protocol/parser validation. Preserve a
found crashing input as a regression fixture before changing the implementation.
The separate workspace keeps fuzz tooling outside production dependencies.
