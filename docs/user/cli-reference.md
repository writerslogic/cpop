# CLI Reference

Complete reference for the witnessd command-line interface.

## Table of Contents

- [Global Options](#global-options)
- [Commands](#commands)
  - [init](#init)
  - [commit](#commit)
  - [log](#log)
  - [export](#export)
  - [verify](#verify)
  - [track](#track)
  - [sentinel](#sentinel)
  - [presence](#presence)
  - [calibrate](#calibrate)
  - [status](#status)
  - [daemon](#daemon)
  - [help](#help)
  - [version](#version)
- [Interactive Menu](#interactive-menu)
- [Exit Codes](#exit-codes)

## Global Options

These options can be used with any command:

| Option | Description |
|--------|-------------|
| `--config <path>` | Use custom configuration file |
| `-h`, `--help` | Show help for command |
| `-v`, `--version` | Show version information |

## Commands

### init

Initialize witnessd in the current directory.

```bash
witnessd init
```

**What it does:**
1. Creates `~/.witnessd/` directory structure
2. Generates Ed25519 signing key pair
3. Initializes master identity from device PUF
4. Creates secure SQLite database
5. Writes default configuration

**Example:**
```bash
$ witnessd init

Generating Ed25519 signing key...
  Public key: a1b2c3d4...
Initializing master identity from PUF...
  Master Identity: 5f8e2a9c
  Device ID: device-mac-m1-001
Creating secure event database...
  Database: events.db (tamper-evident)

witnessd initialized!
```

**Notes:**
- Safe to run multiple times (idempotent)
- Preserves existing keys and identity
- Run `witnessd calibrate` after initialization

---

### commit

Create a checkpoint for a file.

```bash
witnessd commit <file> [-m <message>]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-m <message>` | Commit message describing the checkpoint |

**Example:**
```bash
$ witnessd commit manuscript.md -m "Completed chapter 3"

Computing checkpoint... done (1.2s)

Checkpoint #5 created
  File: /Users/you/manuscript.md
  Hash: 8f14e45f...
  VDF:  1500000 iterations
  Time: 2026-01-15T14:30:00Z
```

**What is captured:**
- SHA-256 hash of file content
- File size and size delta
- VDF timing proof
- Ratcheting key signature
- Link to previous checkpoint

**With tracking active:**
```bash
$ witnessd commit manuscript.md -m "Draft with tracking"

Computing checkpoint... done (1.2s)

Checkpoint #6 created (tracking: 1523 keystrokes, 45 samples)
  File: /Users/you/manuscript.md
  Hash: 9a7b3c2d...
```

---

### log

Show checkpoint history for a file.

```bash
witnessd log <file> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--json` | Output in JSON format |
| `--limit <n>` | Show only last n checkpoints |
| `--since <date>` | Show checkpoints since date |

**Example:**
```bash
$ witnessd log manuscript.md

Checkpoint History for manuscript.md

#   Time                  Size      Delta    Message
1   2026-01-15 10:30:00   1.2 KB    +1.2 KB  Initial outline
2   2026-01-15 11:15:00   3.4 KB    +2.2 KB  Added introduction
3   2026-01-15 14:00:00   8.7 KB    +5.3 KB  Chapter 1 complete
4   2026-01-15 16:30:00   15.2 KB   +6.5 KB  Chapter 2 draft
5   2026-01-15 18:00:00   18.9 KB   +3.7 KB  Completed chapter 3

Total: 5 checkpoints over 7h 30m
```

**JSON output:**
```bash
$ witnessd log manuscript.md --json --limit 1
```
```json
{
  "file": "/Users/you/manuscript.md",
  "checkpoints": [
    {
      "number": 5,
      "timestamp": "2026-01-15T18:00:00Z",
      "content_hash": "8f14e45f...",
      "file_size": 19353,
      "size_delta": 3788,
      "message": "Completed chapter 3",
      "vdf_iterations": 1500000
    }
  ]
}
```

---

### export

Export evidence packet for a file.

```bash
witnessd export <file> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-o <path>` | Output file path |
| `--format <fmt>` | Format: `json` or `cbor` |
| `--tier <n>` | Evidence tier: `1`, `2`, or `3` |
| `--include-content` | Include file content in packet |

**Example:**
```bash
$ witnessd export manuscript.md

Exporting evidence packet...

Evidence Packet: manuscript.wpkt
  Checkpoints: 15
  Time span: 2026-01-15 to 2026-01-20
  Evidence tier: 2 (Software-Attested)
  Size: 24.5 KB

Packet ready for verification.
```

**Custom output:**
```bash
$ witnessd export manuscript.md -o evidence.json --format json --tier 3
```

**Evidence packet contents:**
- Protocol version and metadata
- Complete checkpoint chain
- VDF proofs for each checkpoint
- Key hierarchy with session certificates
- Signed author declaration
- Verification instructions

---

### verify

Verify a checkpoint chain or evidence packet.

```bash
witnessd verify <file|packet> [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--verbose` | Show detailed verification steps |
| `--strict` | Fail on any warning |

**Verify evidence packet:**
```bash
$ witnessd verify manuscript.wpkt

Evidence Packet Verification

Document: manuscript.md
Author Identity: 5f8e2a9c
Checkpoints: 15
Time Span: 2026-01-15 10:30:00 to 2026-01-20 18:45:00

Verification Results:
  [PASS] Checkpoint chain integrity
  [PASS] VDF timing proofs (minimum 48 hours proven)
  [PASS] Key hierarchy valid
  [PASS] Session certificate authentic
  [PASS] All 15 signatures valid

Evidence Class: Tier 2 (Software-Attested)
Overall: VERIFIED
```

**Verify file against local checkpoints:**
```bash
$ witnessd verify manuscript.md

Verifying manuscript.md against local checkpoints...

Current file matches checkpoint #15
  Hash: 8f14e45f...
  Time: 2026-01-20T18:45:00Z

Chain integrity: VALID (15 checkpoints)
```

---

### track

Track keyboard activity for a document.

```bash
witnessd track <action> [options]
```

**Actions:**

| Action | Description |
|--------|-------------|
| `start <file>` | Start tracking for a document |
| `stop` | Stop current tracking session |
| `status` | Show tracking status |

**Privacy Note:** Tracking counts keystrokes only - it does NOT capture which keys are pressed. This is NOT a keylogger.

**Start tracking:**
```bash
$ witnessd track start manuscript.md

Tracking started for manuscript.md
  Session ID: sess_abc123
  WAL: ~/.witnessd/tracking/manuscript.md.wal

Press Ctrl+C or run 'witnessd track stop' to end.
```

**Check status:**
```bash
$ witnessd track status

Tracking Status
  Document: manuscript.md
  Duration: 2h 15m
  Keystrokes: 4,523
  Jitter samples: 127
  Last activity: 30s ago
```

**Stop tracking:**
```bash
$ witnessd track stop

Tracking stopped
  Total keystrokes: 4,523
  Jitter samples: 127
  Session saved to events.db
```

---

### sentinel

Manage the background sentinel daemon for automatic tracking.

```bash
witnessd sentinel <action>
```

**Actions:**

| Action | Description |
|--------|-------------|
| `start` | Start the sentinel daemon |
| `stop` | Stop the sentinel daemon |
| `status` | Show sentinel status and tracked documents |

**Start sentinel:**
```bash
$ witnessd sentinel start

Sentinel daemon started
  PID: 12345
  Heartbeat: every 60s
  Auto-checkpoint: every 60s
  WAL: enabled
```

**Check status:**
```bash
$ witnessd sentinel status

Sentinel Status: Running (PID 12345)
  Uptime: 4h 23m
  Heartbeats: 263

Tracked Documents:
  manuscript.md     12,456 keystrokes  Last: 2m ago
  notes.txt         1,234 keystrokes   Last: 15m ago

Auto-checkpoints: 47 created
```

**Stop sentinel:**
```bash
$ witnessd sentinel stop

Sentinel stopped
  Final checkpoint created for all tracked documents
```

---

### presence

Manage presence verification sessions.

```bash
witnessd presence <action>
```

**Actions:**

| Action | Description |
|--------|-------------|
| `start` | Start a presence verification session |
| `stop` | End the current presence session |
| `status` | Show presence session status |

**Start presence session:**
```bash
$ witnessd presence start

Presence verification session started
  Challenge interval: 10m
  Response window: 60s

You will be prompted to respond to periodic challenges.
This proves you are actively present during document creation.
```

**Respond to challenge:**
```
[PRESENCE CHALLENGE] Please type the following code: 7X4M9
> 7X4M9
Challenge accepted! Next challenge in 10 minutes.
```

---

### calibrate

Calibrate VDF performance for this machine.

```bash
witnessd calibrate
```

**Example:**
```bash
$ witnessd calibrate

Calibrating VDF performance...

Running benchmark (30 seconds)...
  [################] 100%

Results:
  Iterations per second: 15,234,567
  Estimated 1-second proof: 15,234,567 iterations
  Estimated 1-minute proof: 914,074,020 iterations

Configuration updated.
```

**Notes:**
- Takes approximately 30 seconds
- Only needs to be run once per machine
- Re-run after significant hardware changes
- Results stored in config.json

---

### status

Show witnessd status and configuration.

```bash
witnessd status
```

**Example:**
```bash
$ witnessd status

Witnessd Status
  Version: 1.0.0
  Data directory: ~/.witnessd
  Initialized: Yes

Identity:
  Master: 5f8e2a9c
  Device: device-mac-m1-001

Configuration:
  VDF calibrated: Yes (15.2M iter/sec)
  Key hierarchy: Enabled (v1)
  Secure storage: Enabled

Storage:
  Database: events.db (2.4 MB)
  Checkpoints: 156
  Documents: 12

Sentinel: Not running
Tracking: Not active
```

---

### daemon

(Legacy) Run background monitoring daemon.

```bash
witnessd daemon [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--foreground` | Run in foreground (don't daemonize) |

**Note:** The `daemon` command is legacy. Use `sentinel` for background monitoring with the modern workflow.

---

### help

Show help information.

```bash
witnessd help [command]
```

**Examples:**
```bash
witnessd help          # Show all commands
witnessd help commit   # Show help for commit command
witnessd commit --help # Same as above
```

---

### version

Show version information.

```bash
witnessd version
```

**Example:**
```bash
$ witnessd version

witnessd v1.0.0
  Build:    2026-01-15T10:00:00Z
  Commit:   abc12345
  Platform: darwin/arm64
  Go:       go1.21.5
```

---

## Interactive Menu

Running `witnessd` without arguments launches the interactive menu:

```bash
$ witnessd

░█░░░█░░▀░░▀█▀░█▀▀▄░█▀▀░█▀▀░█▀▀░░░░█▀▄
░▀▄█▄▀░░█▀░░█░░█░▒█░█▀▀░▀▀▄░▀▀▄░▀▀░█░█
░░▀░▀░░▀▀▀░░▀░░▀░░▀░▀▀▀░▀▀▀░▀▀▀░░░░▀▀░

witnessd v1.0.0

? Select an action:
  > Initialize
    Create Checkpoint
    View History
    Export Evidence
    Verify
    Track Document
    Settings
    Quit
```

Navigate with arrow keys and press Enter to select.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | File not found |
| 4 | Verification failed |
| 5 | Database error |
| 6 | Key error |
| 7 | VDF error |

---

See also:
- [Getting Started](getting-started.md) for initial setup
- [Configuration](configuration.md) for all options
- [Troubleshooting](troubleshooting.md) for common issues
