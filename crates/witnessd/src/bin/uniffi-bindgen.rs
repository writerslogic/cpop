// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

/// UniFFI binding generator for cpop_engine.
///
/// Usage: cargo run --features ffi --bin uniffi-bindgen -- generate \
///          --library target/release/libcpop_engine.dylib \
///          --language swift --out-dir <output-dir>
fn main() {
    #[cfg(feature = "ffi")]
    uniffi::uniffi_bindgen_main();

    #[cfg(not(feature = "ffi"))]
    {
        eprintln!("uniffi-bindgen requires the 'ffi' feature.");
        eprintln!("Run with: cargo run --features ffi --bin uniffi-bindgen -- <args>");
        std::process::exit(1);
    }
}
