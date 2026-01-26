<p align="center">
  <img src="assets/logo.svg" alt="witnessd" width="400">
</p>

<p align="center">
  <strong>Cryptographic proof of authorship through documented process attestation</strong>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#commands">Commands</a> •
  <a href="#evidence-tiers">Evidence Tiers</a>
</p>

---

## Overview

**witnessd** generates irrefutable cryptographic evidence of document authorship through commit-based temporal witnessing. Unlike detection-based approaches that attempt to distinguish human from AI content, witnessd provides a **documentation framework** where authors commit to content states over time and declare their creative process.

### Philosophy

The system makes three categories of claims:

1. **Cryptographic (strong)**: Content states form an unbroken hash chain; VDFs prove minimum elapsed time between states
2. **Attestation (legal)**: Authors sign declarations describing their process, including any AI tool usage
3. **Presence (optional)**: Random challenge-response protocols verify author presence during sessions

### Key Features

- **Verifiable Delay Functions (VDF)** — Prove minimum elapsed time between commits (unforgeable)
- **Process Declarations** — Structured documentation of AI usage, collaboration, and input modalities
- **Presence Verification** — Optional random challenges proving human presence
- **Evidence Strength Tiers** — Basic → Standard → Enhanced → Maximum
- **External Trust Anchors** — OpenTimestamps (Bitcoin) and RFC 3161 TSA integration
- **TPM Integration** — Optional hardware attestation for enhanced security

## Installation

```bash
go install witnessd@latest
```

Or build from source:

```bash
git clone https://github.com/davidcondrey/witnessd
cd witnessd
go build -o witnessd ./cmd/witnessd
```

## Quick Start

```bash
# 1. Initialize witnessd
witnessd init

# 2. Calibrate VDF for your machine (one-time)
witnessd calibrate

# 3. Write your document, then commit checkpoints
witnessd commit manuscript.md -m "Completed chapter 1"
# ... continue writing ...
witnessd commit manuscript.md -m "Finished draft"

# 4. View checkpoint history
witnessd log manuscript.md

# 5. Export evidence when done
witnessd export manuscript.md
```

## How It Works

```
CREATION:
┌─────────────────────────────────────────────────────────────────┐
│  Author writes in any application                               │
│                    ↓                                            │
│  Author runs `witnessd commit` at chosen intervals              │
│                    ↓                                            │
│  Checkpoint created: content_hash + VDF proof + chain link      │
│                    ↓                                            │
│  Chain grows over days/weeks/months                             │
└─────────────────────────────────────────────────────────────────┘

EXPORT:
┌─────────────────────────────────────────────────────────────────┐
│  Author requests evidence export                                │
│                    ↓                                            │
│  System prompts for Process Declaration                         │
│                    ↓                                            │
│  Author declares modalities, AI usage, collaboration            │
│                    ↓                                            │
│  Declaration signed, bound to chain                             │
│                    ↓                                            │
│  Evidence packet generated at requested tier                    │
└─────────────────────────────────────────────────────────────────┘

VERIFICATION:
┌─────────────────────────────────────────────────────────────────┐
│  Verifier receives evidence packet                              │
│                    ↓                                            │
│  Verify chain integrity (hash links)                            │
│                    ↓                                            │
│  Verify VDF proofs (time elapsed)                               │
│                    ↓                                            │
│  Evaluate declaration plausibility against evidence             │
│                    ↓                                            │
│  Decision: Accept, investigate further, or reject               │
└─────────────────────────────────────────────────────────────────┘
```

## Commands

```bash
witnessd init                    # Initialize witnessd
witnessd calibrate               # Calibrate VDF for your machine
witnessd commit <file> [-m msg]  # Create checkpoint
witnessd log <file>              # Show checkpoint history
witnessd export <file> [-tier T] # Export evidence packet
witnessd verify <file|json>      # Verify chain or evidence
witnessd presence <action>       # Manage presence verification
witnessd status                  # Show status
```

### Creating Checkpoints

```bash
# Basic commit
witnessd commit essay.md

# With message
witnessd commit essay.md -m "Added methodology section"
```

### Presence Verification (Optional)

For stronger evidence, run presence verification during writing sessions:

```bash
# Start a presence session
witnessd presence start

# Periodically verify your presence
witnessd presence challenge

# End the session
witnessd presence stop
```

### Exporting Evidence

```bash
# Basic tier (commits + declaration)
witnessd export essay.md

# Standard tier (+ presence verification)
witnessd export essay.md -tier standard

# Enhanced tier (+ TPM attestation)
witnessd export essay.md -tier enhanced
```

## Evidence Tiers

| Tier | Components | Claims |
|------|------------|--------|
| **Basic** | Commits + Declaration | Chain integrity, time elapsed, process declared |
| **Standard** | + Presence Verification | Author was physically present during sessions |
| **Enhanced** | + Hardware Attestation | TPM attests chain was not modified |
| **Maximum** | + Behavioral + External | Full forensic analysis + blockchain anchors |

## Process Declaration

When exporting evidence, you must declare your creative process:

```
=== Process Declaration ===
You must declare how this document was created.

Input modality (how was this written?):
  1. Keyboard (typing)
  2. Dictation (voice)
  3. Mixed
Choice [1]: 1

Did you use any AI tools? (y/n)
Choice [n]: y

Which AI tool? (e.g., Claude, ChatGPT, Copilot): Claude
How was it used?
  1. Research/ideation only
  2. Feedback on drafts
  3. Editing assistance
  4. Drafting assistance
Choice [1]: 2

Provide a brief statement about your process:
> I wrote this essay over two weeks, using Claude for feedback on early drafts.
```

The declaration is cryptographically signed and bound to your evidence.

## What This Proves

The evidence packet makes explicit claims:

**Cryptographic (cannot be faked):**
- "Content states form an unbroken cryptographic chain"
- "At least 12h 34m elapsed during documented composition"
- "Author was present 89% of challenged sessions"

**Attestation (legal accountability):**
- "Author signed declaration of creative process"
- "No AI tools declared" or "AI assistance declared: moderate extent"

**Limitations (explicitly stated):**
- "Cannot prove cognitive origin of ideas"
- "Cannot prove absence of AI involvement in ideation"

## Why Documentation Over Detection

Traditional approaches try to **detect** AI involvement through behavioral analysis. This creates an arms race: as AI improves, detection becomes harder.

witnessd takes a different approach:
- **Prove what's provable**: Time elapsed (VDF), chain integrity (hashes)
- **Declare what's not**: AI usage, collaboration, input modalities
- **Let institutions handle false declarations**: This is how affidavits, notarization, and signatures work

False declarations are the author's legal risk, not a technical detection problem.

## Security Model

**Threat Model:**
- Adversary controls filesystem after the fact
- Adversary cannot break SHA-256, Ed25519, or VDF
- Adversary cannot retroactively modify Bitcoin blockchain

**The "Drip Attack" Problem:**
An adversary could generate AI content and slowly feed it through the system. Under witnessd:
1. They must spend real wall-clock time (VDF proves it)
2. They must sign a false declaration (legal risk)
3. The economic cost approaches honest work

## Configuration

Configuration is stored in `~/.witnessd/config.json`:

```json
{
  "version": 2,
  "vdf": {
    "iterations_per_second": 1500000,
    "calibrated": true
  },
  "presence": {
    "challenge_interval_seconds": 600,
    "response_window_seconds": 60
  }
}
```

## License

Apache License 2.0

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
