<p align="center">
  <img src="assets/logo.svg" alt="witnessd" width="400">
</p>

<p align="center">
  <strong>Cryptographic proof of human authorship through continuous temporal witnessing</strong>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#commands">Commands</a> •
  <a href="#forensic-analysis">Forensic Analysis</a>
</p>

---

## Overview

**witnessd** generates irrefutable cryptographic evidence of document authorship by capturing the "kinetic signature" of human creative work—the natural rhythm of edits, pauses, and revisions. Unlike AI-generated content which appears atomically, human writing exhibits distinctive temporal patterns that are computationally infeasible to forge retroactively.

### Key Features

- **Merkle Mountain Range (MMR)** — Append-only authenticated data structure with O(log n) inclusion proofs
- **Edit Topology Tracking** — Captures *where* edits occur, not just *when*, defeating drip-script attacks
- **Cryptographic Binding** — Content, metadata, and edit regions bound in tamper-evident chain
- **External Trust Anchors** — OpenTimestamps (Bitcoin) and RFC 3161 TSA integration
- **Forensic Analysis** — Statistical detection of anomalous authorship patterns
- **Multi-Device Support** — Federated witness chains with weave synchronization

## Installation

```bash
go install witnessd/cmd/witnessd@latest
go install witnessd/cmd/witnessctl@latest
```

Or build from source:

```bash
git clone https://github.com/yourusername/witnessd
cd witnessd
go build -o witnessd ./cmd/witnessd
go build -o witnessctl ./cmd/witnessctl
```

## Quick Start

1. **Generate a signing key:**
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/witnessd_signing_key -N ""
   ```

2. **Create configuration:**
   ```bash
   mkdir -p ~/.witnessd
   cat > ~/.witnessd/config.toml << EOF
   watch_paths = ["~/Documents/writing"]
   interval = 5
   EOF
   ```

3. **Start the daemon:**
   ```bash
   witnessd -v
   ```

4. **Check status:**
   ```bash
   witnessctl status
   ```

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    File Change Detected                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Shadow Cache (Previous State)                   │
│         Compare with Myers diff → Extract topology           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Cryptographic Commitment                        │
│    LeafHash = SHA256(ContentHash || MetadataHash ||         │
│                      RegionsRoot)                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Merkle Mountain Range                           │
│         Append leaf → Update peaks → Compute root            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              SQLite Event Store                              │
│    Full metadata for forensic queries and verification       │
└─────────────────────────────────────────────────────────────┘
```

## Commands

### Daemon

```bash
witnessd [options]
  -config <path>    Path to config file
  -v                Verbose logging
```

### Control CLI

```bash
# Check daemon status and statistics
witnessctl status

# View witness history
witnessctl history

# Verify a file against the witness database
witnessctl verify <file>

# Export self-contained evidence packet
witnessctl export <file> [output.json]

# Analyze authorship patterns
witnessctl forensics <file>

# Manage editing context declarations
witnessctl context begin <type> [note]   # types: external, assisted, review
witnessctl context end
witnessctl context status
```

## Forensic Analysis

The `forensics` command analyzes authorship patterns across five primary metrics:

| Metric | Human Range | Drip Attack | Description |
|--------|-------------|-------------|-------------|
| Monotonic Append Ratio | 40-60% | >95% | Fraction of edits at document end |
| Edit Entropy | 2.5-4.0 | <1.0 | Shannon entropy of edit positions |
| Median Interval | Variable | Regular | Time between edits |
| Positive/Negative Ratio | 60-75% | >98% | Insertions vs deletions |
| Deletion Clustering | <1.0 | ≈1.0 | Spatial clustering of deletions |

Example output:

```
══════════════════════════════════════════════════════════════════════
                     AUTHORSHIP ANALYSIS: manuscript.md
══════════════════════════════════════════════════════════════════════

Overview
  Events:        1,847 witnesses across 89 sessions
  Time span:     2025-09-14 → 2026-01-24 (132 days)

EDIT TOPOLOGY                                              [KEY METRIC]
  Monotonic append:   47.3%    ✓ (human: 40-60%, drip: >95%)
  Edit entropy:       3.21     ✓ (human: 2.5-4.0, drip: <1.0)

  ✓ CONSISTENT WITH HUMAN AUTHORSHIP
```

## Context Declarations

Annotate editing sessions to explain anomalous patterns:

```bash
# Before pasting a block quote
witnessctl context begin external "Block quote from source"

# When using AI assistance
witnessctl context begin assisted "Outline generated with Claude"

# During a revision pass
witnessctl context begin review "Final proofreading"

# End the context
witnessctl context end
```

## Evidence Export

Export a self-contained cryptographic proof:

```bash
witnessctl export manuscript.md evidence.json
```

The evidence packet includes:
- File hash and MMR inclusion proof
- All peak hashes for root verification
- Ed25519 signature
- Optional external anchor proofs (OpenTimestamps, RFC 3161)

## Configuration

`~/.witnessd/config.toml`:

```toml
# Paths to watch for changes
watch_paths = ["~/Documents", "~/Projects/novel.md"]

# Debounce interval in seconds
interval = 5

# Database paths (defaults shown)
database_path = "~/.witnessd/mmr.db"
event_store_path = "~/.witnessd/events.db"
log_path = "~/.witnessd/witnessd.log"
signing_key_path = "~/.ssh/witnessd_signing_key"
signatures_path = "~/.witnessd/signatures.sigs"
```

## Security Model

**Threat Model:**
- Adversary controls filesystem after the fact
- Adversary cannot break SHA-256 or Ed25519
- Adversary cannot retroactively modify Bitcoin blockchain
- External timestamp authorities are trusted

**Attack Resistance:**
- *Backdating*: Cannot produce valid MMR proofs without knowing historical state
- *Drip Scripts*: Edit topology analysis detects monotonic append patterns
- *Fabrication*: External anchors pin timeline; statistical analysis reveals artificial patterns

## License

MIT

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
