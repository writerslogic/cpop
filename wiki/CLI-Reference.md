# CLI Reference

The `witnessd` command-line tool is the primary interface for managing authorship evidence.

## Global Options

| Option | Description |
|--------|-------------|
| `--config <path>` | Use custom configuration directory (default: `~/.witnessd`) |
| `-h`, `--help` | Show help for a command |
| `-v`, `--version` | Show version information |

---

## Core Commands

### `init`
Initialize witnessd and generate your cryptographic identity.
```bash
witnessd init
```

### `calibrate`
Measure your CPU performance for VDF timing proofs. Run this once after installation.
```bash
witnessd calibrate
```

### `commit`
Create a checkpoint for a file.
```bash
witnessd commit <file> [-m "message"]
```

### `log`
Show the checkpoint history for a file.
```bash
witnessd log <file>
```

### `status`
Show the current status of witnessd, including your identity and configuration.
```bash
witnessd status
```

---

## Evidence Commands

### `export`
Export a `.wpkt` evidence packet containing the full chain of authorship proof.
```bash
witnessd export <file> [-o output.wpkt]
```

### `verify`
Verify an evidence packet or a local file's checkpoint chain.
```bash
witnessd verify <file_or_packet>
```

---

## Tracking Commands

### `track`
Manage real-time activity tracking for a document.
```bash
witnessd track start <file>
witnessd track status
witnessd track stop
```

### `sentinel`
Manage the background daemon that handles automatic tracking and checkpoints.
```bash
witnessd sentinel start
witnessd sentinel status
witnessd sentinel stop
```

---

## Additional Commands

- `list`: List all files that have checkpoints in the database.
- `watch`: Automatically checkpoint files in specific folders.
- `presence`: Start a presence verification session (periodic challenges).
- `fingerprint`: Manage behavioral fingerprinting settings.

---

## Interactive Menu

If you run `witnessd` without any arguments, it will launch an interactive TUI menu for easy navigation.

---

*For detailed troubleshooting, see the **[[Troubleshooting]]** guide.*
