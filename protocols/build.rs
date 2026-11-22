//! Generates the Rust modules of the system's protocols into OUT_DIR.
use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../idl/protocols/silica");
    let files: Vec<PathBuf> =
        ["device/manager.idl", "system/manager.idl", "input/device.idl", "display/device.idl", "console/terminal.idl", "log/reader.idl"]
            .iter()
            .map(|f| root.join(f))
            .collect();
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
