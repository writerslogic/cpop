<p align="center">
  <img src="assets/logo.svg" alt="witnessd" width="400">
</p>

<p align="center">
  <strong>Cryptographic authorship witnessing for writers and creators</strong>
</p>

<p align="center">
  <a href="https://github.com/writerslogic/witnessd-rust/actions/workflows/ci.yml"><img src="https://github.com/writerslogic/witnessd-rust/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/writerslogic/witnessd-rust/actions/workflows/release.yml"><img src="https://github.com/writerslogic/witnessd-rust/actions/workflows/release.yml/badge.svg" alt="Release"></a>
  <a href="https://slsa.dev/spec/v1.0/levels#build-l3"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA Level 3"></a>
  <a href="https://github.com/writerslogic/witnessd-rust/releases/latest"><img src="https://img.shields.io/github/v/release/writerslogic/witnessd-rust?label=release" alt="Release"></a>
  <a href="https://crates.io/crates/witnessd-core"><img src="https://img.shields.io/crates/v/witnessd-core" alt="Crates.io"></a>
  <a href="https://docs.rs/witnessd-core"><img src="https://docs.rs/witnessd-core/badge.svg" alt="docs.rs"></a>
  <a href="https://github.com/writerslogic/witnessd-rust/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-dual-blue" alt="License"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#features">Features</a> •
  <a href="#verification">Verification</a>
</p>

---

> **Patent Pending:** USPTO Application No. 19/460,364 — "Falsifiable Process Evidence via Cryptographic Causality Locks and Behavioral Attestation"

---

## Overview

**witnessd** creates tamper-evident cryptographic records of document authorship through commit-based temporal witnessing. It provides irrefutable proof that you wrote what you wrote, when you wrote it.

### Key Benefits

- **Prove authorship** — Cryptographic evidence chain linking you to your work
- **Detect AI content** — Forensic analysis identifies non-human writing patterns
- **Hardware-backed** — TPM 2.0 and Secure Enclave integration for device binding
- **Verify independently** — Evidence can be verified by anyone, anywhere

## Installation

### macOS

**Homebrew (recommended):**
```bash
brew install writerslogic/tap/witnessd
```

**Or install via script:**
```bash
curl -sSf https://raw.githubusercontent.com/writerslogic/witnessd/main/install.sh | sh
```

### Linux

**Homebrew:**
```bash
brew install writerslogic/tap/witnessd
```

**Or install via script:**
```bash
curl -sSf https://raw.githubusercontent.com/writerslogic/witnessd/main/install.sh | sh
```

**Or download directly:**
```bash
# x86_64
curl -LO https://github.com/writerslogic/witnessd/releases/latest/download/witnessd_v0.1.1_x86_64-unknown-linux-gnu.tar.gz
tar -xzf witnessd_v0.1.1_x86_64-unknown-linux-gnu.tar.gz
sudo mv witnessd-cli /usr/local/bin/witnessd

# ARM64
curl -LO https://github.com/writerslogic/witnessd/releases/latest/download/witnessd_v0.1.1_aarch64-unknown-linux-gnu.tar.gz
tar -xzf witnessd_v0.1.1_aarch64-unknown-linux-gnu.tar.gz
sudo mv witnessd-cli /usr/local/bin/witnessd
```

### Windows

**Download from releases:**
1. Download [witnessd_v0.1.1_x86_64-pc-windows-msvc.zip](https://github.com/writerslogic/witnessd/releases/latest)
2. Extract and add to your PATH

**Or using PowerShell:**
```powershell
# Download and extract
Invoke-WebRequest -Uri "https://github.com/writerslogic/witnessd/releases/latest/download/witnessd_v0.1.1_x86_64-pc-windows-msvc.zip" -OutFile "witnessd.zip"
Expand-Archive -Path "witnessd.zip" -DestinationPath "$env:LOCALAPPDATA\witnessd"

# Add to PATH (current session)
$env:PATH += ";$env:LOCALAPPDATA\witnessd"
```

### From Source

```bash
# Clone the repository
git clone https://github.com/writerslogic/witnessd-rust
cd witnessd-rust

# Build and install the CLI
cd rust/witnessd-cli
cargo build --release
sudo cp target/release/witnessd-cli /usr/local/bin/witnessd
```

### Binary Releases

Download from [GitHub Releases](https://github.com/writerslogic/witnessd-rust/releases)

All releases include:
- SHA256 checksums
- SLSA Level 3 provenance attestations
- SBOM (SPDX and CycloneDX)

## Quick Start

```bash
# Initialize witnessd
witnessd init

# Calibrate VDF for your machine
witnessd calibrate

# Create checkpoints as you write
witnessd commit document.md -m "First draft"

# View history
witnessd log document.md

# Export evidence
witnessd export document.md --tier enhanced

# Verify evidence
witnessd verify evidence-packet.json
```

## Architecture

```
witnessd-rust/
├── rust/
│   ├── witnessd-core/     # Cryptographic core library
│   │   ├── src/
│   │   │   ├── crypto.rs      # HMAC, hashing primitives
│   │   │   ├── checkpoint.rs  # Document checkpointing
│   │   │   ├── vdf/           # Verifiable delay functions
│   │   │   ├── forensics.rs   # Authorship analysis
│   │   │   ├── presence.rs    # Human verification
│   │   │   ├── tpm/           # Hardware security (TPM/Secure Enclave)
│   │   │   └── evidence.rs    # Evidence export
│   │   └── Cargo.toml
│   │
│   └── witnessd-cli/      # Command-line interface
│
└── platforms/             # Platform-specific code
    ├── macos/             # SwiftUI app (coming soon)
    ├── windows/           # Windows packaging
    └── linux/             # Linux packaging
```

## Features

### Cryptographic Checkpointing
- SHA-256 content hashing
- HMAC chain integrity
- Unbreakable checkpoint chain

### Verifiable Delay Functions (VDF)
- Pietrzak VDF implementation
- Proves minimum elapsed time
- Hardware-calibrated iterations

### Forensic Analysis
- Edit topology analysis
- Keystroke cadence patterns
- Monotonic append detection (AI indicator)
- Session gap analysis

### Presence Verification
- Random cryptographic challenges
- Multiple challenge types
- Response time tracking

### Hardware Security
- TPM 2.0 support (Windows/Linux)
- macOS Secure Enclave integration
- Device identity binding

### Evidence Tiers

| Tier | Contents |
|------|----------|
| **Basic** | Checkpoint chain, VDF proof, declaration |
| **Standard** | + Presence verification |
| **Enhanced** | + Forensic analysis, keystroke patterns |
| **Maximum** | + Hardware attestation, external anchors |

## Verification

### Verify Release Artifacts

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Verify SLSA provenance
slsa-verifier verify-artifact witnessd-rust_v1.0.0_x86_64-unknown-linux-gnu.tar.gz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/writerslogic/witnessd-rust
```

### Verify Evidence Packets

```bash
# Using the CLI
witnessd verify evidence-packet.json

# Outputs verification report with:
# - Chain integrity status
# - VDF proof verification
# - Declaration signature check
# - Forensic analysis summary
```

## Security

- **SLSA Level 3** compliant builds
- **SBOM** included with every release
- Automated security scanning (cargo-audit, Trivy, Semgrep)
- See [SECURITY.md](SECURITY.md) and [docs/SLSA.md](docs/SLSA.md)

## Supply Chain Security

| Artifact | Attestation |
|----------|-------------|
| Binaries | SLSA v1.0 provenance |
| Dependencies | Vendored + Cargo.lock |
| SBOMs | SPDX + CycloneDX |

## Development

```bash
# Run tests
cd rust/witnessd-core
cargo test --all-features

# Run lints
cargo clippy --all-targets --all-features -- -D warnings

# Format code
cargo fmt --all

# Security audit
cargo audit
cargo deny check
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

Dual licensed:
- **Non-Commercial**: Free for personal, academic, research, and open-source projects
- **Commercial**: Requires a commercial license — contact licensing@writerslogic.com

## Related Projects

- [witnessd (Go)](https://github.com/writerslogic/witnessd/tree/legacy-go-v1) — Original Go implementation (archived)
- [C2PA](https://c2pa.org/) — Content Authenticity Initiative (interoperability planned)

## Links

- [Documentation](https://docs.writerslogic.com/witnessd)
- [SLSA Compliance](docs/SLSA.md)
- [Evidence Format Specification](specs/evidence-format.md)
