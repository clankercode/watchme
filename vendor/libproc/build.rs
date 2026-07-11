use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").expect("TARGET is defined by Cargo");
    if !target.contains("apple-darwin") {
        return;
    }
    let output = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is defined by Cargo"))
        .join("osx_libproc_bindings.rs");
    let host = env::var("HOST").expect("HOST is defined by Cargo");
    if host.contains("apple-darwin") {
        generate_native_bindings(&output);
    } else {
        fs::copy("docs_rs/osx_libproc_bindings.rs", output)
            .expect("copy shipped macOS bindings for cross-target checking");
    }
}

fn generate_native_bindings(output: &std::path::Path) {
    use bindgen::{RustEdition, RustTarget};
    let rust_target = RustTarget::stable(72, 0).expect("supported Rust target");
    bindgen::builder()
        .header_contents("libproc_rs.h", "#include <libproc.h>")
        .rust_target(rust_target)
        .rust_edition(RustEdition::Edition2018)
        .layout_tests(false)
        .generate()
        .expect("generate libproc bindings")
        .write_to_file(output)
        .expect("write libproc bindings");
}
