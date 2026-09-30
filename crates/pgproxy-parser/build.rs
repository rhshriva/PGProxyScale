use std::{env, path::PathBuf, process::Command};
fn main() {
    let source = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("build directory"));
    let archive = source.join("vendor/libpg-query-18.0.0.tar.gz");
    println!("cargo:rerun-if-changed={}", archive.display());
    println!("cargo:rerun-if-env-changed=CC");
    assert_eq!(
        env::var("HOST").unwrap(),
        env::var("TARGET").unwrap(),
        "cross compilation requires an explicit target C toolchain"
    );
    assert!(
        Command::new("tar")
            .args(["-xzf"])
            .arg(&archive)
            .arg("-C")
            .arg(&out)
            .status()
            .expect("tar is required to unpack vendored parser")
            .success()
    );
    let build = out.join("libpg-query");
    let mut make = Command::new("make");
    make.current_dir(&build)
        .args(["build", "-j"])
        .arg(env::var("NUM_JOBS").unwrap_or_else(|_| "2".into()));
    if let Ok(cc) = env::var("CC") {
        make.arg(format!("CC={cc}"));
    }
    assert!(
        make.status()
            .expect("make and a C compiler are required")
            .success(),
        "vendored PostgreSQL parser compilation failed"
    );
    println!("cargo:rustc-link-search=native={}", build.display());
    println!("cargo:rustc-link-lib=static=pg_query");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=pthread");
}
