//! Generates the Rust modules of silica.block.Device and silica.block.Partitions into OUT_DIR.
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../../idl/protocols/silica/block");
    let files = [dir.join("device.idl"), dir.join("partitions.idl")];
    for f in &files {
        println!("cargo::rerun-if-changed={}", f.display());
    }
    let protocols = idlc::load(&files).unwrap_or_else(|errs| {
        for e in errs {
            println!("cargo::warning=ERROR: {e}");
        }
        std::process::exit(1)
    });
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    for p in &protocols {
        let code = idlc::rustgen::rust(p).unwrap_or_else(|errs| {
            for e in errs {
                println!("cargo::warning=ERROR: {e}");
            }
            std::process::exit(1)
        });
        std::fs::write(out.join(idlc::rustgen::file_name(p)), code).unwrap();
    }
}
