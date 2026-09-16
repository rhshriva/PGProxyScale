// Links the vendored libpg_query build.
//
// libpg_query is built by `make build` in ../libpg_query, which produces a static
// archive. We intentionally link whatever is present rather than hard-coding a name,
// because the artefact name has changed across libpg_query releases.
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let libdir = manifest
        .parent()
        .expect("harness/ has a parent")
        .join("libpg_query");

    println!("cargo:rustc-link-search=native={}", libdir.display());
    println!("cargo:rustc-link-lib=static=pg_query");
    // libpg_query pulls in libm and pthreads; protobuf-c is vendored and compiled in.
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rerun-if-changed=build.rs");
}
