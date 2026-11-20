//! Generates the Rust module of the sample.Echo protocol into OUT_DIR.
use std::path::PathBuf;

fn main() {
    let idl = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../idl/protocols/sample/echo.idl");
    println!("cargo::rerun-if-changed={}", idl.display());
    let protocols = idlc::load(&[idl]).unwrap_or_else(|errs| {
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
