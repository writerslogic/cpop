fn main() {
    eprintln!("uniffi-bindgen requires the 'ffi' feature and uniffi_bindgen dependency.");
    eprintln!("Install with: cargo install uniffi_bindgen");
    eprintln!("Or run the uniffi-bindgen CLI directly.");
    std::process::exit(1);
}
