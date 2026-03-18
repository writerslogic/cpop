<p align="center">
  <strong>CPOP</strong><br>
  Cryptographic authorship witnessing for writers and creators
</p>

<p align="center">
  <a href="https://doi.org/10.5281/zenodo.18480372"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.18480372.svg" alt="DOI"></a>
  <a href="https://arxiv.org/abs/2602.01663"><img src="https://img.shields.io/badge/arXiv-2602.01663-b31b1b.svg" alt="arXiv"></a>
  <a href="https://orcid.org/0009-0003-1849-2963"><img src="https://img.shields.io/badge/ORCID-0009--0003--1849--2963-green.svg" alt="ORCID"></a>
</p>

<p align="center">
  <a href="https://github.com/writerslogic/cpop/actions"><img src="https://github.com/writerslogic/cpop/workflows/CI/badge.svg" alt="Build Status"></a>
  <a href="https://github.com/writerslogic/cpop/attestations"><img src="https://img.shields.io/badge/SLSA-Build_Provenance-blue" alt="SLSA Build Provenance"></a>
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange" alt="Rust">
  <a href="https://github.com/writerslogic/cpop/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0--only-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/Patent-US%2019%2F460%2C364%20Pending-blue" alt="Patent Pending">
</p>

---

> [!NOTE]
> **Patent Pending:** USPTO Application No. 19/460,364 — *"Falsifiable Process Evidence via Cryptographic Causality Locks and Behavioral Attestation"*

---

## Overview

**CPOP** is a cryptographic engine and CLI that produces independently verifiable, tamper-evident process evidence constraining when and how a document could have been created. It implements the [draft-condrey-rats-pop](https://datatracker.ietf.org/doc/draft-condrey-rats-pop/) IETF protocol specification.

This monorepo contains the full CPOP ecosystem:

| Component | Path | Description | License |
|:----------|:-----|:------------|:--------|
| **cpop_engine** | [`crates/cpop_engine`](crates/cpop_engine) | Cryptographic engine | AGPL-3.0-only |
| **cpop_protocol** | [`crates/cpop_protocol`](crates/cpop_protocol) | PoP wire format & forensic models | AGPL-3.0-only |
| **cpop_jitter** | [`crates/cpop_jitter`](crates/cpop_jitter) | Hardware timing entropy | AGPL-3.0-only |
| **cpop_cli** | [`apps/cpop_cli`](apps/cpop_cli) | CLI (`cpop`) | AGPL-3.0-only |
| **cpop_macos** | [`apps/cpop_macos`](apps/cpop_macos) | macOS desktop app | Proprietary |
| **cpop_windows** | [`apps/cpop_windows`](apps/cpop_windows) | Windows desktop app | Proprietary |

## Install

**macOS (Homebrew):**
```bash
brew install writerslogic/tap/writerslogic
```

**Windows (Scoop):**
```powershell
scoop bucket add writerslogic https://github.com/writerslogic/scoop-bucket
scoop install writerslogic
```

**Linux / macOS (script):**
```bash
curl -sSf https://raw.githubusercontent.com/writerslogic/cpop/main/apps/cpop_cli/install.sh | sh
```

**From source:**
```bash
cargo install --git https://github.com/writerslogic/cpop --bin cpop
```

## Quick Start

```bash
# Start tracking a document
cpop essay.md

# Create a checkpoint
cpop commit essay.md -m "first draft complete"

# View history
cpop log essay.md

# Export cryptographic evidence (.cpop)
cpop export essay.md -t 2

# Verify evidence
cpop verify essay.cpop
```

Run `cpop` with no arguments for an interactive menu, or `cpop --help` for full command reference.

## CLI Commands

| Command | Description |
|:--------|:------------|
| `cpop <path>` | Start tracking a file or directory |
| `cpop commit` | Create a checkpoint (alias: `checkpoint`) |
| `cpop log` | View history or list tracked documents (alias: `history`, `ls`) |
| `cpop export` | Export evidence packet (alias: `prove`) |
| `cpop verify` | Verify evidence packet (alias: `check`) |
| `cpop status` | Show current tracking status |
| `cpop track` | Session management (start/stop/status/list/show/export) |
| `cpop identity` | Identity management (alias: `id`) |
| `cpop config` | Configuration (alias: `cfg`) |
| `cpop fingerprint` | Behavioral fingerprinting (alias: `fp`) |
| `cpop presence` | Physical presence verification |

All commands support `--json` for machine-readable output and `--quiet` for silent operation.

## Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
cpop_engine = { git = "https://github.com/writerslogic/cpop", branch = "main" }
```

## Features

| Feature | Description |
|:--------|:------------|
| `default` | Core library without optional features |
| `cpop_jitter` | Hardware entropy via PhysJitter |
| `secure-enclave` | macOS Secure Enclave support |
| `x11` | X11 focus detection on Linux |
| `ffi` | UniFFI bindings for Swift/Kotlin |

## Architecture

```
writerslogic/
├── crates/
│   ├── cpop_engine/    High-performance cryptographic engine
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
│   │       ├── rfc/        RFC wire types
│   │       ├── tpm/        TPM 2.0 / Secure Enclave
│   │       └── vdf/        Verifiable Delay Functions
│   ├── cpop_protocol/  PoP wire format (CBOR/COSE)
│   └── cpop_jitter/    Hardware timing entropy
├── apps/
│   ├── cpop_cli/       Command-line interface
│   ├── cpop_macos/     Native macOS app (submodule)
│   └── cpop_windows/   Native Windows app (submodule)
└── docs/              Schemas, specs, and user guides
```

## Development

```bash
cargo test --workspace           # Run all tests
cargo test -p cpop_engine --lib   # Fast engine tests (~915 tests)
cargo clippy --workspace -- -D warnings  # Lint (zero warnings maintained)
cargo fmt --all -- --check       # Format check
cargo audit && cargo deny check  # Security audit
```

## Verifying Evidence

Anyone can verify `.cpop` evidence packets — no account or software required:

- **Web**: Upload at [writerslogic.com/verify](https://writerslogic.com/verify)
- **CLI**: `cpop verify proof.cpop`

Verification checks the checkpoint chain, Ed25519 signatures, VDF timing proofs, and behavioral consistency. It runs entirely client-side — your evidence is never uploaded to our servers.

## Security & Privacy

> [!IMPORTANT]
> CPOP provides **independently verifiable, tamper-evident process evidence**, not absolute proof. The value lies in converting unsubstantiated doubt into testable claims across independent trust boundaries.

### Privacy & External Interactions

CPOP is designed with a strictly **offline-first and privacy-preserving** architecture. Core witnessing, keystroke capture, and evidence generation occur entirely on your local machine.

The applications interact with the following external domains for specific enhanced features:

*   **Verification Portal (`writersproof.com/verify`):** Browser-based tool for verifying `.cpop` evidence packets. Runs client-side; evidence data is never uploaded.
*   **Attestation API (`writerslogic.com/api`):** Used for Tier 3 and Tier 4 evidence to request anti-replay nonces and receive cloud-signed attestation certificates.
*   **Schema Registry (`protocol.writersproof.com`):** Hosts JSON schemas and DID resolution data for protocol compliance.

For a detailed breakdown, see the **[Privacy & External Interactions Wiki](https://github.com/writerslogic/cpop/wiki/Privacy-&-External-Interactions)**.

See [SECURITY.md](SECURITY.md) for the security policy.

## Citation

```bibtex
@article{condrey2026writerslogic,
  title={CPOP: Proof-of-process via Adversarial Collapse},
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

Licensed under [AGPL-3.0-only](LICENSE). See individual component licenses in the table above.
