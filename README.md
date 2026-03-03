<p align="center">
  <strong>writerslogic-core</strong><br>
  Cryptographic authorship witnessing for writers and creators
</p>

<p align="center">
  <a href="https://doi.org/10.5281/zenodo.18480372"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.18480372.svg" alt="DOI"></a>
  <a href="https://arxiv.org/abs/2602.01663"><img src="https://img.shields.io/badge/arXiv-2602.01663-b31b1b.svg" alt="arXiv"></a>
  <a href="https://orcid.org/0009-0003-1849-2963"><img src="https://img.shields.io/badge/ORCID-0009--0003--1849--2963-green.svg" alt="ORCID"></a>
</p>

<p align="center">
  <a href="https://github.com/writerslogic/writerslogic/actions"><img src="https://github.com/writerslogic/writerslogic/workflows/CI/badge.svg" alt="Build Status"></a>
  <a href="https://slsa.dev/spec/v1.0/levels#build-l3"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA Level 3"></a>
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange" alt="Rust">
  <a href="https://github.com/writerslogic/writerslogic/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/Patent-US%2019%2F460%2C364%20Pending-blue" alt="Patent Pending">
</p>

---

> [!NOTE]
> **Patent Pending:** USPTO Application No. 19/460,364 — *"Falsifiable Process Evidence via Cryptographic Causality Locks and Behavioral Attestation"*

---

## Overview

**writerslogic-core** is the cryptographic core library that produces independently verifiable, tamper-evident process evidence constraining when and how a document could have been created.

This monorepo contains the full WritersLogic ecosystem:

| Component | Path | Description | License |
|:----------|:-----|:------------|:--------|
| **wld_engine** | [`crates/wld_engine`](crates/wld_engine) | Cryptographic engine | AGPL-3.0-only |
| **wld_protocol** | [`crates/wld_protocol`](crates/wld_protocol) | PoP wire format & forensic models | AGPL-3.0-only |
| **wld_jitter** | [`crates/wld_jitter`](crates/wld_jitter) | Hardware timing entropy | AGPL-3.0-only |
| **wld_cli** | [`apps/wld_cli`](apps/wld_cli) | CLI & Linux packaging | AGPL-3.0-only |
| **wld_macos** | [`apps/wld_macos`](apps/wld_macos) | macOS desktop app | Proprietary |
| **wld_windows** | [`apps/wld_windows`](apps/wld_windows) | Windows desktop app | Proprietary |

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
writerslogic-core = { git = "https://github.com/writerslogic/writerslogic", branch = "main" }
```

## Features

| Feature | Description |
|:--------|:------------|
| `default` | Core library without optional features |
| `wld_jitter` | Hardware entropy via PhysJitter |
| `secure-enclave` | macOS Secure Enclave support |
| `x11` | X11 focus detection on Linux |
| `ffi` | UniFFI bindings for Swift/Kotlin |

## Architecture

```
writerslogic/
├── crates/
│   ├── wld_engine/    High-performance cryptographic engine
│   │   └── src/
│   │       ├── analysis/   Signal analysis and behavioral metrics
│   │       ├── anchors/    Blockchain and timestamp anchoring
│   │       ├── crypto/     Cryptographic primitives
│   │       ├── evidence/   Evidence export/verify
│   │       ├── forensics/  Authorship analysis
│   │       ├── ipc/        Inter-process communication
│   │       ├── keyhierarchy/ Key derivation and ratcheting
│   │       ├── platform/   OS-specific code (macOS, Linux, Windows)
│   │       ├── sentinel/   Real-time monitoring
│   │       ├── rfc/        RFC implementations
│   │       ├── tpm/        TPM 2.0 integration
│   │       └── vdf/        Verifiable Delay Functions
│   ├── wld_protocol/  PoP wire format (CBOR/COSE)
│   └── wld_jitter/    Hardware timing entropy
├── apps/
│   ├── wld_cli/       Command-line interface
│   ├── wld_macos/     Native macOS app (submodule)
│   └── wld_windows/   Native Windows app (submodule)
├── docs/                   Schemas, specs, and user guides
└── wiki/                   GitHub Wiki pages
```

## Development

```bash
cargo test --all-features      # Run tests
cargo clippy -- -D warnings    # Lint
cargo fmt --all                # Format
cargo audit && cargo deny check # Security audit
```

## Security & Privacy

> [!IMPORTANT]
> WritersLogic provides **independently verifiable, tamper-evident process evidence**, not absolute proof. The value lies in converting unsubstantiated doubt into testable claims across independent trust boundaries.

### Privacy & External Interactions

WritersLogic is designed with a strictly **offline-first and privacy-preserving** architecture. Core witnessing, keystroke capture, and evidence generation occur entirely on your local machine.

However, the applications interact with the following external domains for specific enhanced features:

*   **Verification Portal (`writersproof.com/verify`):** Provides a browser-based tool for verifying `.wpkt` evidence packets. This process runs client-side in your browser; evidence data is never uploaded to our servers.
*   **Attestation API (`writerslogic.com/api`):** Used for "Tier 3" and "Tier 4" evidence to request anti-replay nonces and receive cloud-signed attestation certificates.
*   **Schema Registry (`protocol.writersproof.com`):** Hosts the JSON schemas and DID (Decentralized Identifier) resolution data used for protocol compliance.

For a detailed breakdown of our privacy model, see the **[Privacy & External Interactions Wiki](https://github.com/writerslogic/writerslogic/wiki/Privacy-&-External-Interactions)**.

See [SECURITY.md](SECURITY.md) for the security policy.

## Citation

```bibtex
@article{condrey2026writerslogic,
  title={WritersLogic: Proof-of-process via Adversarial Collapse},
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
