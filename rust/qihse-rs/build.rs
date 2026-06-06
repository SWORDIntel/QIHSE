use std::env;
use std::path::PathBuf;

fn main() {
    let qihse_path = "/home/john/Documents/QIHSE";

    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-search=native={}", qihse_path);
    // Tell cargo to tell rustc to link the qihse shared library.
    println!("cargo:rustc-link-lib=dylib=qihse");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        // Add include path
        .clang_arg(format!("-I{}/include", qihse_path))
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
