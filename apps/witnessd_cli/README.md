<p align="center">
  <strong>witnessd_cli</strong><br>
  Command-line interface for cryptographic authorship witnessing
</p>

<p align="center">
  <a href="https://doi.org/10.5281/zenodo.18480372"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.18480372.svg" alt="DOI"></a>
  <a href="https://arxiv.org/abs/2602.01663"><img src="https://img.shields.io/badge/arXiv-2602.01663-b31b1b.svg" alt="arXiv"></a>
  <a href="https://orcid.org/0009-0003-1849-2963"><img src="https://img.shields.io/badge/ORCID-0009--0003--1849--2963-green.svg" alt="ORCID"></a>
</p>

<p align="center">
  <a href="https://github.com/writerslogic/witnessd_cli/actions"><img src="https://github.com/writerslogic/witnessd_cli/workflows/CI/badge.svg" alt="Build Status"></a>
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange" alt="Rust">
  <a href="https://github.com/writerslogic/witnessd_cli/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/Patent-US%2019%2F460%2C364%20Pending-blue" alt="Patent Pending">
</p>

---

> [!NOTE]
> **Patent Pending:** USPTO Application No. 19/460,364 — *"Falsifiable Process Evidence via Cryptographic Causality Locks and Behavioral Attestation"*

---

## Overview

**witnessd_cli** is the command-line interface for [witnessd_engine](https://github.com/writerslogic/witnessd) — producing independently verifiable, tamper-evident process evidence constraining when and how a document could have been created.

This repository contains the CLI tool and Linux packaging. For the full witnessd ecosystem:

| Repository | Description |
|:-----------|:------------|
| **[witnessd](https://github.com/writerslogic/witnessd)** | Core cryptographic library (Apache-2.0) |
| **[witnessd_cli](https://github.com/writerslogic/witnessd_cli)** | Command-line interface + Linux packaging (this repo, GPL-3.0) |
| **[witnessd-docs](https://github.com/writerslogic/witnessd-docs)** | Documentation, schemas, and specifications |

## Installation

### Package Managers

| Platform | Command |
|:---------|:--------|
| **macOS** | `brew install writerslogic/tap/witnessd` |
| **Linux** | `brew install writerslogic/tap/witnessd` |
| **Windows** | `scoop bucket add witnessd https://github.com/writerslogic/scoop-bucket && scoop install witnessd` |

### Quick Install Script

```bash
curl -sSf https://raw.githubusercontent.com/writerslogic/witnessd_cli/main/install.sh | sh
```

### Build from Source

```bash
git clone https://github.com/writerslogic/witnessd_cli && cd witnessd_cli
cargo build --release
sudo cp target/release/witnessd_cli /usr/local/bin/witnessd
```

## Usage

### Getting Started

```bash
witnessd init                              # Initialize keys, identity, and database
witnessd calibrate                         # Calibrate VDF for your machine
witnessd commit document.md -m "Draft"     # Create checkpoint with time proof
witnessd log document.md                   # View checkpoint history
```

### Evidence Export and Verification

```bash
witnessd export document.md -t core        # Export as JSON evidence packet
witnessd export document.md -f war -o proof.war  # Export as WAR block
witnessd verify evidence.json              # Verify JSON evidence packet
witnessd verify proof.war                  # Verify WAR block
```

### Evidence Collection

```bash
witnessd track start                       # Start keystroke timing collection
witnessd track status                      # Check tracking status
witnessd track stop                        # Stop tracking
witnessd presence start                    # Start presence verification session
witnessd fingerprint status                # Show fingerprint collection status
```

### Daemon and Folder Watching

```bash
witnessd start                             # Start background daemon
witnessd stop                              # Stop background daemon
witnessd watch add ~/Documents             # Auto-checkpoint a folder
witnessd status                            # Show system status
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
| `init` | | Initialize witnessd (keys, database, identity) |
| `calibrate` | | Calibrate VDF performance for this machine |
| `commit` | `checkpoint` | Create a checkpoint with VDF time proof |
| `log` | `history` | Show checkpoint history for a file |
| `export` | | Export evidence packet (JSON or WAR format) |
| `verify` | | Verify evidence packet or database integrity |
| `track` | | Manage keystroke timing collection |
| `presence` | | Manage presence verification sessions |
| `fingerprint` | `fp` | Manage author fingerprints |
| `watch` | | Auto-checkpoint watched folders |
| `start` / `stop` | | Manage the witnessd daemon |
| `session` | | Manage document sessions |
| `config` | `cfg` | View and edit configuration |
| `status` | | Show system status and configuration |
| `list` | `ls` | List all tracked documents |

## Architecture

```
witnessd_cli/
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
├── Cargo.toml               # Dependencies (witnessd_engine via git)
└── CITATION.cff             # Citation metadata
```

## Security

> [!IMPORTANT]
> witnessd provides **independently verifiable, tamper-evident process evidence**, not absolute proof. The value lies in converting unsubstantiated doubt into testable claims across independent trust boundaries.

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

Licensed under the [GNU General Public License v3.0](LICENSE).

For commercial licensing inquiries (embedding witnessd in proprietary software), contact: licensing@writerslogic.com
