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

- **Hardened Keystroke Capture** — CGEventTap-based counting with multi-layer security
- **Tamper Detection** — HMAC integrity verification, cryptographic chaining, timing anomaly detection
- **Script/USB-HID Protection** — Detects automated input from scripts and hardware spoofing devices
- **Jitter Evidence** — Cryptographic proof of real-time typing through zone-based keystroke timing
- **Verifiable Delay Functions (VDF)** — Prove minimum elapsed time between commits (unforgeable)
- **Process Declarations** — Structured documentation of AI usage, collaboration, and input modalities
- **Presence Verification** — Optional random challenges proving human presence
- **Secure Storage** — Tamper-evident SQLite database with HMAC integrity verification
- **Evidence Strength Tiers** — Basic → Standard → Enhanced → Maximum
- **External Trust Anchors** — OpenTimestamps (Bitcoin) and RFC 3161 TSA integration
- **TPM Integration** — Hardware-backed security with monotonic counters and attestation

## Installation

**Homebrew (macOS/Linux):**
```bash
brew install writerslogic/tap/witnessd
```

**From source:**
```bash
git clone https://github.com/writerslogic/witnessd
cd witnessd
make install
```

**Binary releases:**
Download from [GitHub Releases](https://github.com/writerslogic/witnessd/releases)

## Configuration

By default, witnessd reads `~/.witnessd/config.toml`. If it doesn't exist,
defaults are used.

Example config:

```bash
cp configs/config.example.toml ~/.witnessd/config.toml
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

## Enhanced Workflow (with Keystroke Tracking)

For stronger evidence, enable real-time keystroke tracking during writing:

```bash
# 1. Initialize and calibrate (one-time)
witnessd init && witnessd calibrate

# 2. Start keystroke tracking for your document
witnessd track start manuscript.md

# 3. Write your document (keystrokes are counted, NOT captured)
#    - Only keystroke counts and timing are recorded
#    - Zone transitions (which finger) are tracked
#    - This is NOT a keylogger

# 4. Check tracking status
witnessd track status

# 5. Create checkpoints as you write
witnessd commit manuscript.md -m "Draft complete"

# 6. Stop tracking when done
witnessd track stop

# 7. Export with jitter evidence
witnessd export manuscript.md -tier standard
```

**Privacy Guarantee:** Keystroke tracking records ONLY:
- Event counts and timing (not which keys)
- Zone transitions (which finger typed each key)
- Jitter samples (cryptographic proof of real typing)

No actual keystrokes or text content is captured.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         WITNESSD SYSTEM                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐        │
│   │  witnessd   │     │  witnessctl │     │   IME       │        │
│   │  (daemon)   │     │   (query)   │     │  (future)   │        │
│   └──────┬──────┘     └──────┬──────┘     └──────┬──────┘        │
│          │                   │                   │                │
│          ▼                   ▼                   ▼                │
│   ┌──────────────────────────────────────────────────────┐       │
│   │               Secure SQLite Storage                   │       │
│   │  • HMAC integrity verification                        │       │
│   │  • Chain-linked events                                │       │
│   │  • Tamper detection                                   │       │
│   └──────────────────────────────────────────────────────┘       │
│          │                                                        │
│          ▼                                                        │
│   ┌──────────────────────────────────────────────────────┐       │
│   │                 Evidence Layers                       │       │
│   │  • VDF proofs (temporal)                              │       │
│   │  • Jitter evidence (behavioral)                       │       │
│   │  • Presence verification                              │       │
│   │  • TPM attestation                                    │       │
│   │  • External anchors (Bitcoin, RFC 3161)               │       │
│   └──────────────────────────────────────────────────────┘       │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **witnessd** commands create events (init, commit, track)
2. Events are stored in tamper-evident SQLite database
3. **witnessctl** reads events for status, verification, forensics
4. **Export** bundles events into portable evidence packets
5. **Verify** validates evidence packets independently

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
# Core workflow
witnessd init                    # Initialize witnessd
witnessd calibrate               # Calibrate VDF for your machine
witnessd commit <file> [-m msg]  # Create checkpoint
witnessd log <file>              # Show checkpoint history
witnessd export <file> [-tier T] # Export evidence packet
witnessd verify <file|json>      # Verify chain or evidence
witnessd status                  # Show status

# Keystroke tracking (for jitter evidence)
witnessd track start <file>      # Start tracking keystrokes
witnessd track status            # Show tracking status
witnessd track stop              # Stop tracking and save evidence
witnessd track list              # List saved tracking sessions
witnessd track export <id>       # Export jitter evidence

# Presence verification (optional)
witnessd presence start          # Start presence session
witnessd presence challenge      # Take a presence challenge
witnessd presence stop           # End presence session

# Status
witnessctl status                # Show full system status
witnessctl history               # Show witness history
witnessctl verify <file>         # Verify a file
witnessctl forensics <file>      # Analyze authorship patterns
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

## Jitter Evidence

The keystroke tracking system builds cryptographic proof of real-time typing:

```
┌─────────────────────────────────────────────────────────────────┐
│                     JITTER EVIDENCE CHAIN                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  For each keystroke:                                            │
│    1. Zone detected (which finger: 0-7 from pinky to pinky)     │
│    2. Document hash computed (current content state)             │
│    3. Jitter delay calculated (zone-dependent, entropy-based)    │
│    4. Sample added to chain: zone + delay + doc_hash + prev_hash │
│                                                                  │
│  The chain proves:                                               │
│    • Real keystrokes occurred (zone transitions are realistic)   │
│    • Document evolved over time (hash progression)               │
│    • Timing is consistent with human typing                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Zone Layout (QWERTY):**
```
Zone 0 (left pinky):  Q A Z
Zone 1 (left ring):   W S X
Zone 2 (left middle): E D C
Zone 3 (left index):  R T F G V B
Zone 4 (right index): Y U H J N M
Zone 5 (right middle): I K ,
Zone 6 (right ring):  O L .
Zone 7 (right pinky): P ; /
```

Human typing has characteristic patterns between zones. The jitter evidence proves
these patterns occurred over the documented time period.

## Keystroke Security

The keystroke tracking system uses multiple layers of protection to prevent tampering:

### Primary: CGEventTap (macOS) / evdev (Linux)

```
┌─────────────────────────────────────────────────────────────────┐
│                    HARDENED KEYSTROKE CAPTURE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. DUAL-LAYER VALIDATION (macOS)                               │
│     • CGEventTap captures keyboard events at system level        │
│     • IOKit HID monitors hardware-level input below CGEventTap   │
│     • Cross-validation detects synthetic events                  │
│                                                                  │
│  2. SYNTHETIC EVENT DETECTION                                    │
│     • Source state ID verification                               │
│     • Keyboard type checking                                     │
│     • Source PID validation                                      │
│     • Timestamp monotonicity                                     │
│                                                                  │
│  3. TIMING ANOMALY DETECTION                                     │
│     • Superhuman speed detection (<20ms intervals)               │
│     • Consecutive identical intervals (scripted)                 │
│     • Low variance detection (robotic typing)                    │
│     • Repeating pattern detection                                │
│                                                                  │
│  4. INTEGRITY PROTECTION                                         │
│     • HMAC on all counter state                                  │
│     • Cryptographic chaining of updates                          │
│     • Tamper-evident sealed checkpoints                          │
│                                                                  │
│  5. TPM BINDING (when available)                                 │
│     • Hardware monotonic counter (prevents rollback)             │
│     • TPM attestation quotes                                     │
│     • Key sealing to platform state (PCRs)                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Legitimate Copy/Paste Handling

The system properly handles legitimate copy/paste operations:
- **Detection**: Large content changes with few keystrokes are flagged as paste events
- **Transparency**: Paste events are recorded and included in evidence export
- **No Penalty**: Copy/paste from your own content or citations is legitimate authorship

```bash
# Check tracking status including paste detection
witnessd track status

# Example output:
# Keystrokes: 15234
# Paste events: 3 (legitimate copy/paste detected)
```

### Backup: IME Integration (Future)

For users who decline accessibility permissions or on mobile platforms, an optional
Input Method Engine (IME) provides keystroke counting without system-level access:
- Requires installing witnessd as a keyboard
- Privacy-focused: counts only, no text capture
- Lower security tier (cannot detect synthetic events)

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

**Storage Security:**

The event database (`~/.witnessd/events.db`) is tamper-evident:

```
┌────────────────────────────────────────────────────────────────┐
│                    SECURE SQLITE STORAGE                        │
├────────────────────────────────────────────────────────────────┤
│  • HMAC Integrity: Each record has HMAC derived from signing   │
│    key - modifications are detectable                          │
│                                                                │
│  • Chain Linking: Each event references previous event hash    │
│    - insertions/deletions break the chain                      │
│                                                                │
│  • Append-Only: Events cannot be modified after insertion      │
│                                                                │
│  • File Permissions: Database has 0600 permissions (owner      │
│    read/write only)                                            │
│                                                                │
│  • Integrity Verification: Full chain verified on every open   │
└────────────────────────────────────────────────────────────────┘
```

Check integrity status:
```bash
witnessctl status  # Shows "Integrity: VERIFIED" or "FAILED"
```

**The "Drip Attack" Problem:**
An adversary could generate AI content and slowly feed it through the system. Under witnessd:
1. They must spend real wall-clock time (VDF proves it)
2. They must sign a false declaration (legal risk)
3. The economic cost approaches honest work
4. With keystroke tracking: Multiple layers of protection:
   - **Timing anomaly detection**: Scripts show low variance, identical intervals, or superhuman speed
   - **Synthetic event detection**: CGEventPost injections are flagged by source state validation
   - **Dual-layer validation**: IOKit HID cross-validates CGEventTap counts
   - **USB-HID spoofing detection**: Hardware keyboard type checking
   - **TPM binding**: Hardware counters prevent replay attacks
5. Copy/paste is tracked: Large content changes with few keystrokes are recorded

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

## Citation

If you use witnessd in academic work, please cite:

```bibtex
@article{condrey2025witnessd,
  title={Kinetic Proof of Provenance: Cryptographic Authorship Witnessing Through Temporal Attestation},
  author={Condrey, David},
  journal={arXiv preprint},
  year={2025},
  note={Paper forthcoming}
}
```

<!-- TODO: Update with arXiv ID once published -->

## License

Apache License 2.0

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
