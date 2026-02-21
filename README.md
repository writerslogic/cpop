<p align="center">
  <strong>witnessd-core</strong><br>
  Cryptographic authorship witnessing for writers and creators
</p>

<p align="center">
  <a href="https://doi.org/10.5281/zenodo.18480372"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.18480372.svg" alt="DOI"></a>
  <a href="https://arxiv.org/abs/2602.01663"><img src="https://img.shields.io/badge/arXiv-2602.01663-b31b1b.svg" alt="arXiv"></a>
  <a href="https://orcid.org/0009-0003-1849-2963"><img src="https://img.shields.io/badge/ORCID-0009--0003--1849--2963-green.svg" alt="ORCID"></a>
</p>

<p align="center">
  <a href="https://github.com/writerslogic/witnessd/actions"><img src="https://github.com/writerslogic/witnessd/workflows/CI/badge.svg" alt="Build Status"></a>
  <a href="https://slsa.dev/spec/v1.0/levels#build-l3"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA Level 3"></a>
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange" alt="Rust">
  <a href="https://github.com/writerslogic/witnessd/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/Patent-US%2019%2F460%2C364%20Pending-blue" alt="Patent Pending">
</p>

---

> [!NOTE]
> **Patent Pending:** USPTO Application No. 19/460,364 — *"Falsifiable Process Evidence via Cryptographic Causality Locks and Behavioral Attestation"*

---

## Overview

**witnessd-core** is the cryptographic core library that produces independently verifiable, tamper-evident process evidence constraining when and how a document could have been created.

This repository contains only the core Rust library. For the full witnessd ecosystem:

| Repository | Description |
|:-----------|:------------|
| **[witnessd](https://github.com/writerslogic/witnessd)** | Core cryptographic library (this repo) |
| **[witnessd-cli](https://github.com/writerslogic/witnessd-cli)** | Command-line interface + Linux packaging (GPL-3.0) |
| **[witnessd-docs](https://github.com/writerslogic/witnessd-docs)** | Documentation, schemas, and specifications |

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
witnessd-core = { git = "https://github.com/writerslogic/witnessd", branch = "main" }
```

## Features

| Feature | Description |
|:--------|:------------|
| `default` | Core library without optional features |
| `physjitter` | Hardware entropy via PhysJitter |
| `secure-enclave` | macOS Secure Enclave support |
| `x11` | X11 focus detection on Linux |
| `ffi` | UniFFI bindings for Swift/Kotlin |

## Architecture

```
src/
├── analysis/       Signal analysis and behavioral metrics
├── anchors/        Blockchain and timestamp anchoring
├── calibration/    VDF calibration
├── codec/          CBOR/encoding
├── crypto/         Cryptographic primitives
├── fingerprint/    Device fingerprinting
├── identity/       Identity and key management
├── ipc/            Inter-process communication
├── mmr/            Merkle Mountain Range
├── physics/        Physical measurements (PUF)
├── platform/       OS-specific code (macOS, Linux, Windows)
├── rfc/            RFC implementations
├── tpm/            TPM 2.0 integration
├── vdf/            Verifiable Delay Functions
├── checkpoint.rs   Document checkpointing
├── evidence.rs     Evidence export/verify
├── forensics.rs    Authorship analysis
├── sentinel.rs     Real-time monitoring
├── store.rs        Persistent storage
├── wal.rs          Write-Ahead Log
└── war.rs          Write-Ahead Recovery
```

## Development

```bash
cargo test --all-features      # Run tests
cargo clippy -- -D warnings    # Lint
cargo fmt --all                # Format
cargo audit && cargo deny check # Security audit
```

## Security

> [!IMPORTANT]
> witnessd provides **independently verifiable, tamper-evident process evidence**, not absolute proof. The value lies in converting unsubstantiated doubt into testable claims across independent trust boundaries.

See [SECURITY.md](SECURITY.md) for the security policy.

## Citation

```bibtex
@article{condrey2026witnessd,
  title={Witnessd: Proof-of-process via Adversarial Collapse},
  author={Condrey, David},
  journal={arXiv preprint arXiv:2602.01663},
  year={2026},
  doi={10.48550/arXiv.2602.01663}
}
```

> **Abstract:** Digital signatures prove key possession but not authorship. We introduce *proof-of-process* — a mechanism combining jitter seals, Verifiable Delay Functions, timestamp anchors, keystroke validation, and optional hardware attestation.
>
> — [arXiv:2602.01663](https://arxiv.org/abs/2602.01663) [cs.CR]

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
