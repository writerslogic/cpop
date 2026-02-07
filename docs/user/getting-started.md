# Getting Started with Witnessd

Witnessd is a cryptographic authorship witnessing system that creates tamper-evident records of your creative process. This guide will help you install and configure witnessd for first use.

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Initial Setup](#initial-setup)
- [Your First Checkpoint](#your-first-checkpoint)
- [Exporting Evidence](#exporting-evidence)
- [Next Steps](#next-steps)

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|------------|
| Operating System | macOS 13.0+ or Linux (kernel 5.0+) |
| CPU | 64-bit processor (x86_64 or ARM64) |
| RAM | 512 MB available |
| Storage | 100 MB for installation, plus space for evidence data |
| Go | 1.21+ (for building from source) |

### Optional Hardware

- **TPM 2.0**: Enables hardware-backed attestation (Tier 3 evidence)
- **Secure Enclave**: On Apple Silicon Macs, provides enhanced device binding

## Installation

### macOS (Recommended)

#### Using Homebrew

```bash
brew tap writerslogic/witnessd
brew install witnessd
```

#### Using the macOS App

1. Download `Witnessd.dmg` from the [releases page](https://github.com/writerslogic/witnessd/releases)
2. Open the DMG file
3. Drag **Witnessd** to your Applications folder
4. Launch the app from Applications or Spotlight

The macOS app includes:
- Menu bar integration for quick access
- Automatic keystroke tracking
- Visual checkpoint history
- One-click evidence export

### Linux

#### Using the Install Script

```bash
curl -fsSL https://witnessd.io/install.sh | bash
```

#### Building from Source

```bash
git clone https://github.com/writerslogic/witnessd.git
cd witnessd
make build
sudo make install
```

### Verifying Installation

```bash
witnessd version
```

Expected output:
```
witnessd v1.0.0
  Build:    2026-01-15T10:00:00Z
  Commit:   abc1234
  Platform: darwin/arm64
  Go:       go1.21.5
```

## Initial Setup

### Initialize Witnessd

Before creating checkpoints, you must initialize witnessd:

```bash
witnessd init
```

This creates:
- `~/.witnessd/` directory structure
- Ed25519 signing key pair (your cryptographic identity)
- Master identity from device PUF (hardware binding)
- Secure SQLite database for events
- Default configuration

Sample output:
```
Generating Ed25519 signing key...
  Public key: a1b2c3d4...
Initializing master identity from PUF...
  Master Identity: 5f8e2a9c
  Device ID: device-mac-m1-001
Creating secure event database...
  Database: events.db (tamper-evident)

witnessd initialized!

Next steps:
  1. Run 'witnessd calibrate' to calibrate VDF for your machine
  2. Create checkpoints with 'witnessd commit <file> -m "message"'
  3. Export evidence with 'witnessd export <file>'
```

### Calibrate VDF

The Verifiable Delay Function (VDF) provides timing proofs. Calibration measures your CPU speed:

```bash
witnessd calibrate
```

This takes about 30 seconds and only needs to be done once per machine.

### Configuration (Optional)

Edit `~/.witnessd/config.json` to customize behavior:

```json
{
  "version": 4,
  "storage": {
    "type": "sqlite",
    "path": "events.db",
    "secure": true
  },
  "vdf": {
    "iterations_per_second": 15000000,
    "min_iterations": 100000,
    "max_iterations": 3600000000,
    "calibrated": true
  },
  "sentinel": {
    "auto_start": false,
    "heartbeat_seconds": 60,
    "checkpoint_seconds": 60
  }
}
```

See [Configuration Guide](configuration.md) for detailed options.

## Your First Checkpoint

### Basic Checkpoint

Create a checkpoint for any file:

```bash
# Create or edit a document
echo "My first witnessed document" > mydoc.txt

# Create a checkpoint
witnessd commit mydoc.txt -m "Initial version"
```

Output:
```
Computing checkpoint... done (1.2s)

Checkpoint #1 created
  File: /Users/you/mydoc.txt
  Hash: 8f14e45f...
  VDF:  1500000 iterations
  Time: 2026-01-15T10:30:00Z
```

### View Checkpoint History

```bash
witnessd log mydoc.txt
```

Output:
```
Checkpoint History for mydoc.txt

#  Time                  Size     Message
1  2026-01-15 10:30:00  28 B     Initial version
2  2026-01-15 10:45:00  156 B    Added introduction
3  2026-01-15 11:00:00  892 B    Completed first draft
```

### Enhanced Workflow with Keystroke Tracking

For stronger evidence, track keystrokes during writing:

```bash
# Start tracking
witnessd track start mydoc.txt

# ... write your document ...
# The system counts keystrokes (not content!) in the background

# Check progress
witnessd track status

# Create checkpoint with keystroke evidence
witnessd commit mydoc.txt -m "Draft with tracked keystrokes"

# Stop tracking
witnessd track stop
```

## Exporting Evidence

### Export Evidence Packet

When you need to prove authorship:

```bash
witnessd export mydoc.txt
```

This creates `mydoc.wpkt` containing:
- Complete checkpoint chain with VDF proofs
- Key hierarchy with session certificates
- Signed declaration of creative process
- Verification instructions

### Verify Evidence

Anyone can verify the evidence:

```bash
witnessd verify mydoc.wpkt
```

Output:
```
Evidence Packet Verification

Document: mydoc.txt
Author Identity: 5f8e2a9c
Checkpoints: 15
Time Span: 2026-01-15 10:30:00 to 2026-01-15 18:45:00

Verification Results:
  [PASS] Checkpoint chain integrity
  [PASS] VDF timing proofs (minimum 8 hours proven)
  [PASS] Key hierarchy valid
  [PASS] Session certificate authentic
  [PASS] Signatures valid

Evidence Class: Tier 2 (Software-Attested)
Overall: VERIFIED
```

## Next Steps

1. **Read the [CLI Reference](cli-reference.md)** for all available commands
2. **Configure [automatic tracking](configuration.md#sentinel)** with the sentinel daemon
3. **Try the [macOS app](gui-guide.md)** for a visual interface
4. **Understand [evidence tiers](../protocol/evidence-format.md#evidence-tiers)** for stronger proofs
5. **Review [privacy considerations](../security/privacy-analysis.md)** to understand data handling

## Getting Help

- **Documentation**: https://docs.witnessd.io
- **Issues**: https://github.com/writerslogic/witnessd/issues
- **Community**: https://discord.gg/witnessd

---

*Patent Pending: USPTO Application No. 19/460,364*
