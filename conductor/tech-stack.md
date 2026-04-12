# Tech Stack

## Core Engine & CLI (Native)
- **Language:** Rust (Edition 2021, MSRV 1.75.0)
- **Runtime:** Tokio (Full features, for async/multithreaded operations)
- **CLI Framework:** Clap (v4.4, with derive macros)
- **Cryptography:** Ed25519-Dalek (v2.1), SHA-2 (v0.10), HMAC (v0.12), HKDF (v0.12)
- **Protocol & Formats:** Serde (with derive/JSON), Ciborium (CBOR), Coset (COSE)
- **Platform APIs:** CGEventTap (macOS), TPM 2.0 / Secure Enclave (Platform-specific), UniFFI (for FFI bindings)

## Protocol & Timing (Library)
- **cpoe-protocol:** Native + WASM32 support (for web/browser verification)
- **cpoe-jitter:** Native + no_std support (for embedded/timing entropy)

## Atlassian/Web Integrations
- **Framework:** Atlassian Forge (TypeScript)
- **API/Storage:** @forge/api, @forge/ui, @forge/storage
- **Testing:** Jest, ts-jest

## Build & CI/CD
- **Dependency Management:** Cargo (Rust), NPM/Forge (TypeScript)
- **CI:** GitHub Actions (Linux, macOS, Windows, Security/Audit)
- **Packaging:** Homebrew (macOS), Scoop (Windows), Linux package workflows
- **Security Tools:** cargo-audit, cargo-deny
