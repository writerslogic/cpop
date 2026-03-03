# CLI Reference

The `wld` command-line tool is the primary interface for managing authorship evidence.

## Global Options

| Option | Description |
|--------|-------------|
| `--config <path>` | Use custom configuration directory (default: `~/.writerslogic`) |
| `-h`, `--help` | Show help for a command |
| `-v`, `--version` | Show version information |

---

## Core Commands

### `init`
Initialize WritersLogic and generate your cryptographic identity.
```bash
wld init
```

### `calibrate`
Measure your CPU performance for VDF timing proofs. Run this once after installation.
```bash
wld calibrate
```

### `commit`
Create a checkpoint for a file.
```bash
wld commit <file> [-m "message"]
```

### `log`
Show the checkpoint history for a file.
```bash
wld log <file>
```

### `status`
Show the current status of WritersLogic, including your identity and configuration.
```bash
wld status
```

---

## Evidence Commands

### `export`
Export a `.wpkt` evidence packet containing the full chain of authorship proof.
```bash
wld export <file> [-o output.wpkt]
```

### `verify`
Verify an evidence packet or a local file's checkpoint chain.
```bash
wld verify <file_or_packet>
```

---

## Tracking Commands

### `track`
Manage real-time activity tracking for a document.
```bash
wld track start <file>
wld track status
wld track stop
```

### `sentinel`
Manage the background daemon that handles automatic tracking and checkpoints.
```bash
WritersLogic sentinel start
WritersLogic sentinel status
WritersLogic sentinel stop
```

---

## Additional Commands

- `list`: List all files that have checkpoints in the database.
- `watch`: Automatically checkpoint files in specific folders.
- `presence`: Start a presence verification session (periodic challenges).
- `fingerprint`: Manage behavioral fingerprinting settings.

---

## Interactive Menu

If you run `wld` without any arguments, it will launch an interactive TUI menu for easy navigation.

---

*For detailed troubleshooting, see the **[[Troubleshooting]]** guide.*
