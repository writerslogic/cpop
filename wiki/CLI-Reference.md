# CLI Reference

The `cpop` command-line tool is the primary interface for managing authorship evidence.

## Global Options

| Option | Description |
|--------|-------------|
| `--config <path>` | Use custom configuration directory (default: `~/.writerslogic`) |
| `-h`, `--help` | Show help for a command |
| `-v`, `--version` | Show version information |

---

## Core Commands

### `init`
Initialize CPOP and generate your cryptographic identity.
```bash
cpop init
```

### `calibrate`
Measure your CPU performance for VDF timing proofs. Run this once after installation.
```bash
cpop calibrate
```

### `commit`
Create a checkpoint for a file.
```bash
cpop commit <file> [-m "message"]
```

### `log`
Show the checkpoint history for a file.
```bash
cpop log <file>
```

### `status`
Show the current status of CPOP, including your identity and configuration.
```bash
cpop status
```

---

## Evidence Commands

### `export`
Export a `.cpop` evidence packet containing the full chain of authorship proof.
```bash
cpop export <file> [-o output.cpop]
```

### `verify`
Verify an evidence packet or a local file's checkpoint chain.
```bash
cpop verify <file_or_packet>
```

---

## Tracking Commands

### `track`
Manage real-time activity tracking for a document.
```bash
cpop track start <file>
cpop track status
cpop track stop
```

### `sentinel`
Manage the background daemon that handles automatic tracking and checkpoints.
```bash
CPOP sentinel start
CPOP sentinel status
CPOP sentinel stop
```

---

## Additional Commands

- `list`: List all files that have checkpoints in the database.
- `watch`: Automatically checkpoint files in specific folders.
- `presence`: Start a presence verification session (periodic challenges).
- `fingerprint`: Manage behavioral fingerprinting settings.

---

## Interactive Menu

If you run `cpop` without any arguments, it will launch an interactive TUI menu for easy navigation.

---

*For detailed troubleshooting, see the **[[Troubleshooting]]** guide.*
