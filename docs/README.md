<p align="center">
  <strong>CPoE</strong><br>
  Documentation, schemas, and specifications for CPoE
</p>

<p align="center">
  <a href="https://doi.org/10.5281/zenodo.18480372"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.18480372.svg" alt="DOI"></a>
  <a href="https://arxiv.org/abs/2602.01663"><img src="https://img.shields.io/badge/arXiv-2602.01663-b31b1b.svg" alt="arXiv"></a>
  <a href="https://orcid.org/0009-0003-1849-2963"><img src="https://img.shields.io/badge/ORCID-0009--0003--1849--2963-green.svg" alt="ORCID"></a>
  <a href="https://github.com/writerslogic/cpoe/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/Patent-US%2019%2F460%2C364%20Pending-blue" alt="Patent Pending">
</p>

---

> [!NOTE]
> **Patent Pending:** USPTO Application No. 19/460,364 — *"Falsifiable Process Evidence via Cryptographic Causality Locks and Behavioral Attestation"*

---

## Overview

**CPoE** is a unified protocol suite for high-integrity authorship witnessing based on the **Proof-of-Process (PoP)** protocol. This repository contains the core implementation, reference applications, and technical documentation.

| Component | Path | Description | License |
|:----------|:-----|:------------|:--------|
| **cpoe_engine** | [`crates/cpoe_engine`](../crates/cpoe_engine) | High-performance cryptographic engine | AGPL-3.0-only |
| **cpoe_protocol** | [`crates/cpoe_protocol`](../crates/cpoe_protocol) | PoP protocol wire format & forensic models | AGPL-3.0-only |
| **cpoe_jitter** | [`crates/cpoe_jitter`](../crates/cpoe_jitter) | Hardware timing entropy foundation | AGPL-3.0-only |
| **cpoe_cli** | [`apps/cpoe_cli`](../apps/cpoe_cli) | Command-line interface & Linux packaging | AGPL-3.0-only |
| **cpoe_macos** | [`apps/cpoe_macos`](../apps/cpoe_macos) | Native macOS desktop application | Proprietary |
| **cpoe_windows** | [`apps/cpoe_windows`](../apps/cpoe_windows) | Native Windows desktop application | Proprietary |

## Technical Implementation

CPoE is built on a high-integrity cryptographic stack:

- **Streaming Evidence Engine:** Optimized for massive files via chunked SHA-256 hashing.
- **Adversarial Hardening:** Tier 4 protections including RAM-locking (`mlock`) and anti-debugging.
- **The Labyrinth:** Machine-wide Merkle Mountain Range (MMR) entanglement for global integrity.
- **Forensic Suite:** Real-time authorship scoring ($PS = 0.3R + 0.3S + 0.4B$) and robotic cadence detection.

## Documentation Index

### 🚀 Getting Started
- [Installation](user/getting-started.md#installation) - Homebrew, DMG, and Linux scripts.
- [Initial Setup](user/getting-started.md#initial-setup) - Creating your cryptographic identity.
- [First Checkpoint](user/getting-started.md#your-first-checkpoint) - Proving your creative process.

### 📘 User & Vendor Guides
- [CLI Reference](user/cli-reference.md) - Detailed command documentation.
- [GUI Guide](user/gui-guide.md) - macOS and Windows application walkthroughs.
- [Vendor Integration](integrations/integration-guide.md) - Integrating into 3rd-party apps.
- [Evidence Interpretation](integrations/evidence-interpretation.md) - Criteria for verifying reports.
- [Philosophy & Ethics](philosophy/authorship-ethics.md) - Moral framework for PoP.
- [Configuration](user/configuration.md) - Tuning the Sentinel and VDF parameters.
- [Troubleshooting](user/troubleshooting.md) - Common issues and solutions.

### 🛠 Technical Specifications
- [Evidence Format](specs/evidence-format.md) - PoP wire format (CBOR/JSON).
- [Ratchet Key Hierarchy](specs/ratchet-key-hierarchy.md) - Forward-secure key management.
- [Architectural Hardening](specs/architectural-hardening.md) - Tier 4 protection mechanisms.
- [Behavioral Metrics](specs/behavioral-metrics.md) - Forensic authorship analysis.
- [Persistence & Fault Tolerance](specs/persistence-fault-tolerance.md) - WAL and global integrity.

## Citations

```bibtex
@article{condrey2026writerslogic,
  title={CPoE: Proof-of-process via Adversarial Collapse},
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
