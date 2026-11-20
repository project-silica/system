//! Generates the Rust module of the protocol `sample.Echo` into `OUT_DIR`.

use std::path::PathBuf;

fn main() {
    let idl = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../idl/protocols/sample/echo.idl");
    println!("cargo::rerun-if-changed={}", idl.display());
    let protocols = idlc::load(&[idl]).expect("the protocol does not compile");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    for p in &protocols {
        std::fs::write(
            out.join(idlc::rustgen::file_name(p)),
            idlc::rustgen::rust(p).expect("code generation"),
        )
        .unwrap();
    }
}
