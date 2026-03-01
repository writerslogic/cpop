<p align="center">
  <img src="assets/logo.png" alt="witnessd_engine" width="200">
</p>

<h1 align="center">witnessd_engine</h1>

<p align="center">
  <strong>High-performance cryptographic engine for authorship witnessing</strong>
</p>

<p align="center">
  <a href="https://github.com/writerslogic/witnessd/actions"><img src="https://github.com/writerslogic/witnessd/workflows/CI/badge.svg" alt="Build Status"></a>
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange" alt="Rust">
  <a href="https://github.com/writerslogic/witnessd/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
</p>

---

## Overview

**witnessd_engine** is the core cryptographic engine of the [witnessd](https://github.com/writerslogic/witnessd) monorepo. It produces independently verifiable, tamper-evident process evidence constraining when and how a document could have been created.

## Features

| Feature | Description |
|:--------|:------------|
| `default` | Core library without optional features |
| `witnessd_jitter` | Hardware entropy via witnessd_jitter |
| `secure-enclave` | macOS Secure Enclave support |
| `x11` | X11 focus detection on Linux |
| `ffi` | UniFFI bindings for Swift/Kotlin |

## Usage

```toml
[dependencies]
witnessd_engine = { git = "https://github.com/writerslogic/witnessd", branch = "main" }
```

## Key Modules

| Module | Description |
|:-------|:------------|
| `analysis/` | Signal analysis and behavioral metrics |
| `anchors/` | Blockchain and timestamp anchoring |
| `crypto/` | Cryptographic primitives (SHA-256, Ed25519, AES-256-GCM) |
| `evidence/` | Evidence packet export and verification |
| `forensics/` | Authorship analysis and scoring |
| `ipc/` | Inter-process communication (daemon <-> clients) |
| `keyhierarchy/` | Ratchet key derivation and management |
| `mmr/` | Merkle Mountain Range append-only structure |
| `platform/` | OS-specific code (macOS, Linux, Windows) |
| `rfc/` | RFC/IETF-compliant wire format types |
| `sentinel/` | Real-time file monitoring and session management |
| `tpm/` | TPM 2.0 attestation integration |
| `vdf/` | Verifiable Delay Functions for time proofs |

## Development

```bash
cargo test --all-features      # Run tests
cargo clippy -- -D warnings    # Lint
cargo fmt --all                # Format
```

## Related Crates

- [`witnessd_protocol`](../witnessd_protocol) - PoP wire format and forensic models
- [`witnessd_jitter`](../witnessd_jitter) - Hardware timing entropy primitive

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
