<p align="center">
  <strong>wld_cli</strong><br>
  Command-line interface for cryptographic authorship witnessing
</p>

<p align="center">
  <a href="https://doi.org/10.5281/zenodo.18480372"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.18480372.svg" alt="DOI"></a>
  <a href="https://arxiv.org/abs/2602.01663"><img src="https://img.shields.io/badge/arXiv-2602.01663-b31b1b.svg" alt="arXiv"></a>
  <a href="https://orcid.org/0009-0003-1849-2963"><img src="https://img.shields.io/badge/ORCID-0009--0003--1849--2963-green.svg" alt="ORCID"></a>
</p>

<p align="center">
  <a href="https://github.com/writerslogic/writerslogic/actions"><img src="https://github.com/writerslogic/writerslogic/workflows/CI/badge.svg" alt="Build Status"></a>
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange" alt="Rust">
  <a href="https://github.com/writerslogic/writerslogic/blob/main/apps/wld_cli/LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/Patent-US%2019%2F460%2C364%20Pending-blue" alt="Patent Pending">
</p>

---

> [!NOTE]
> **Patent Pending:** USPTO Application No. 19/460,364 — *"Falsifiable Process Evidence via Cryptographic Causality Locks and Behavioral Attestation"*

---

## Overview

**wld_cli** is the command-line interface for [wld_engine](https://github.com/writerslogic/writerslogic) — producing independently verifiable, tamper-evident process evidence constraining when and how a document could have been created.

This repository contains the CLI tool and Linux packaging. For the full WritersLogic ecosystem:

| Component | Path | Description |
|:----------|:-----|:------------|
| **wld_engine** | [`crates/wld_engine`](../../crates/wld_engine) | Core cryptographic engine (AGPL-3.0-only) |
| **wld_protocol** | [`crates/wld_protocol`](../../crates/wld_protocol) | PoP wire format (AGPL-3.0-only) |
| **wld_jitter** | [`crates/wld_jitter`](../../crates/wld_jitter) | Hardware timing entropy (AGPL-3.0-only) |
| **wld_cli** | [`apps/wld_cli`](.) | CLI & Linux packaging (this directory, AGPL-3.0-only) |

## Installation

### Package Managers

| Platform | Command |
|:---------|:--------|
| **macOS** | `brew install writerslogic/tap/wld` |
| **Linux** | `brew install writerslogic/tap/wld` |
| **Windows** | `scoop bucket add writerslogic https://github.com/writerslogic/scoop-bucket && scoop install wld` |

### Quick Install Script

```bash
curl -sSf https://raw.githubusercontent.com/writerslogic/writerslogic/main/apps/wld_cli/install.sh | sh
```

### Build from Source

```bash
git clone https://github.com/writerslogic/writerslogic.git && cd writerslogic
cargo build --release
sudo cp target/release/wld /usr/local/bin/wld
```

## Usage

### Getting Started

```bash
wld init                              # Initialize keys, identity, and database
wld calibrate                         # Calibrate VDF for your machine
wld commit document.md -m "Draft"     # Create checkpoint with time proof
wld log document.md                   # View checkpoint history
```

### Evidence Export and Verification

```bash
wld export document.md -t core        # Export as JSON evidence packet
wld export document.md -f war -o proof.war  # Export as WAR block
wld verify evidence.json              # Verify JSON evidence packet
wld verify proof.war                  # Verify WAR block
```

### Evidence Collection

```bash
wld track start                       # Start keystroke timing collection
wld track status                      # Check tracking status
wld track stop                        # Stop tracking
wld presence start                    # Start presence verification session
wld fingerprint status                # Show fingerprint collection status
```

### Daemon and Folder Watching

```bash
wld start                             # Start background daemon
wld stop                              # Stop background daemon
wld watch add ~/Documents             # Auto-checkpoint a folder
wld status                            # Show system status
```

## Evidence Tiers

Per [draft-condrey-rats-pop](https://github.com/writerslogic/draft-condrey-rats-pop) CDDL: `content-tier = core(1) / enhanced(2) / maximum(3)`

| Tier | Value | Content | Use Case |
|:-----|:------|:--------|:---------|
| `core` | 1 | Checkpoint chain + VDF proofs + keystroke jitter evidence | Default — recommended for most workflows |
| `enhanced` | 2 | + TPM/hardware attestation | Stronger claims with hardware backing |
| `maximum` | 3 | + behavioral analysis + external anchors | Maximum assurance |

## Commands

| Command | Aliases | Description |
|:--------|:--------|:------------|
| `init` | | Initialize WritersLogic (keys, database, identity) |
| `calibrate` | | Calibrate VDF performance for this machine |
| `commit` | `checkpoint` | Create a checkpoint with VDF time proof |
| `log` | `history` | Show checkpoint history for a file |
| `export` | | Export evidence packet (JSON or WAR format) |
| `verify` | | Verify evidence packet or database integrity |
| `track` | | Manage keystroke timing collection |
| `presence` | | Manage presence verification sessions |
| `fingerprint` | `fp` | Manage author fingerprints |
| `watch` | | Auto-checkpoint watched folders |
| `start` / `stop` | | Manage the WritersLogic daemon |
| `session` | | Manage document sessions |
| `config` | `cfg` | View and edit configuration |
| `status` | | Show system status and configuration |
| `list` | `ls` | List all tracked documents |

## Architecture

```
wld_cli/
├── src/
│   ├── main.rs              # CLI entry point and command dispatch
│   └── smart_defaults.rs    # Platform-aware default configuration
├── tests/
│   └── cli_e2e.rs           # End-to-end CLI integration tests
├── packaging/
│   └── linux/               # Linux distribution packaging
│       ├── debian/           # .deb package config
│       ├── rpm/              # .rpm package config
│       ├── appimage/         # AppImage config
│       ├── systemd/          # systemd service units
│       └── scripts/          # Build and install scripts
├── install.sh               # Quick install script
├── Cargo.toml               # Dependencies (wld_engine via git)
└── CITATION.cff             # Citation metadata
```

## Security

> [!IMPORTANT]
> WritersLogic provides **independently verifiable, tamper-evident process evidence**, not absolute proof. The value lies in converting unsubstantiated doubt into testable claims across independent trust boundaries.

**Privacy-first design:**
- Keystroke tracking captures **timing only** — never the keys you press
- Voice fingerprinting is **off by default** and requires explicit consent
- All keys are stored with restrictive file permissions (0600)
- Database uses HMAC-based tamper detection

## Development

```bash
cargo test                        # Run tests
cargo clippy -- -D warnings       # Lint
cargo fmt --all                   # Format
```

## Linux Packaging

Linux packaging configs (Debian, RPM, AppImage, systemd) are in the [`packaging/linux/`](packaging/linux/) directory. See the [Linux Packaging README](packaging/linux/README-LINUX-PACKAGING.md) for details.

## Citation

```bibtex
@article{condrey2026wld,
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

Licensed under the [GNU General Public License v3.0](LICENSE).

For commercial licensing inquiries (embedding WritersLogic in proprietary software), contact: licensing@writerslogic.com
