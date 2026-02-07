# Configuration Guide

Witnessd can be configured through configuration files, environment variables, and command-line flags. This guide covers all available options.

## Table of Contents

- [Configuration File Location](#configuration-file-location)
- [Configuration File Format](#configuration-file-format)
- [Core Settings](#core-settings)
- [Storage Settings](#storage-settings)
- [VDF Settings](#vdf-settings)
- [Key Hierarchy Settings](#key-hierarchy-settings)
- [Presence Settings](#presence-settings)
- [Sentinel Settings](#sentinel-settings)
- [Environment Variables](#environment-variables)
- [macOS App Settings](#macos-app-settings)
- [Configuration Examples](#configuration-examples)

## Configuration File Location

### Default Locations

| Platform | Path |
|----------|------|
| macOS/Linux | `~/.witnessd/config.json` |
| macOS App | `~/Library/Application Support/Witnessd/config.json` |

### Custom Location

Use the `--config` flag or `WITNESSD_CONFIG` environment variable:

```bash
witnessd --config /path/to/config.json status
```

## Configuration File Format

Witnessd uses JSON configuration with the following structure:

```json
{
  "version": 4,
  "storage": { ... },
  "vdf": { ... },
  "key_hierarchy": { ... },
  "presence": { ... },
  "sentinel": { ... }
}
```

### TOML Alternative

For the legacy daemon mode, TOML configuration is also supported at `~/.witnessd/config.toml`:

```toml
watch_paths = ["~/Documents"]
interval = 5
database_path = "~/.witnessd/mmr.db"
log_path = "~/.witnessd/witnessd.log"
signing_key_path = "~/.witnessd/signing_key"
signatures_path = "~/.witnessd/signatures.sigs"
event_store_path = "~/.witnessd/events.db"
```

## Core Settings

### version

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `version` | integer | `4` | Configuration schema version |

## Storage Settings

Configure how witnessd stores evidence data.

```json
{
  "storage": {
    "type": "sqlite",
    "path": "events.db",
    "secure": true
  }
}
```

### Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | string | `"sqlite"` | Storage backend: `sqlite` or `memory` |
| `path` | string | `"events.db"` | Database file path (relative to data directory) |
| `secure` | boolean | `true` | Enable HMAC integrity checking on all records |

### Secure Mode

When `secure` is enabled:
- All database records include HMAC-SHA256 integrity tags
- Tampering is detected on read
- Slight performance overhead (~5%)

## VDF Settings

Configure the Verifiable Delay Function for timing proofs.

```json
{
  "vdf": {
    "iterations_per_second": 15000000,
    "min_iterations": 100000,
    "max_iterations": 3600000000,
    "calibrated": true
  }
}
```

### Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `iterations_per_second` | integer | `1000000` | Calibrated VDF speed for this machine |
| `min_iterations` | integer | `100000` | Minimum iterations per checkpoint |
| `max_iterations` | integer | `3600000000` | Maximum iterations (caps proof time) |
| `calibrated` | boolean | `false` | Whether VDF has been calibrated |

### Calibration

Run calibration to measure your CPU's VDF performance:

```bash
witnessd calibrate
```

This updates `iterations_per_second` to reflect actual performance, ensuring accurate timing proofs.

### Timing Implications

| Iterations | Approximate Time | Use Case |
|------------|-----------------|----------|
| 100,000 | ~10ms | Minimum checkpoint delay |
| 15,000,000 | ~1 second | Default checkpoint |
| 900,000,000 | ~1 minute | Extended proof |
| 3,600,000,000 | ~4 minutes | Maximum single proof |

## Key Hierarchy Settings

Configure the three-tier key hierarchy for identity and forward secrecy.

```json
{
  "key_hierarchy": {
    "enabled": true,
    "version": 1
  }
}
```

### Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `true` | Enable ratcheting key hierarchy |
| `version` | integer | `1` | Key hierarchy protocol version |

### Key Hierarchy Tiers

1. **Tier 0 (Identity)**: Master key derived from device PUF
2. **Tier 1 (Session)**: Per-session keys certified by master
3. **Tier 2 (Ratchet)**: Forward-secret keys per checkpoint

See [Key Management](../security/key-management.md) for details.

## Presence Settings

Configure presence verification for real-time author presence proofs.

```json
{
  "presence": {
    "challenge_interval_seconds": 600,
    "response_window_seconds": 60
  }
}
```

### Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `challenge_interval_seconds` | integer | `600` | Time between presence challenges |
| `response_window_seconds` | integer | `60` | Time allowed to respond to challenge |

### Presence Verification

Presence sessions create additional proof that the author was actively present:

```bash
# Start a presence session
witnessd presence start

# Respond to challenges when prompted
# ...

# End session
witnessd presence stop
```

## Sentinel Settings

Configure the background sentinel daemon for automatic document tracking.

```json
{
  "sentinel": {
    "auto_start": false,
    "heartbeat_seconds": 60,
    "checkpoint_seconds": 60,
    "wal_enabled": true
  }
}
```

### Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `auto_start` | boolean | `false` | Start sentinel automatically on init |
| `heartbeat_seconds` | integer | `60` | Frequency of sentinel heartbeat |
| `checkpoint_seconds` | integer | `60` | Auto-checkpoint interval when tracking |
| `wal_enabled` | boolean | `true` | Enable write-ahead log for crash recovery |

### Managing Sentinel

```bash
# Start sentinel daemon
witnessd sentinel start

# Check status
witnessd sentinel status

# Stop sentinel
witnessd sentinel stop
```

## Environment Variables

Override configuration with environment variables:

| Variable | Description |
|----------|-------------|
| `WITNESSD_DATA_DIR` | Override data directory path |
| `WITNESSD_CONFIG` | Path to configuration file |
| `WITNESSD_LOG_LEVEL` | Logging verbosity: `debug`, `info`, `warn`, `error` |
| `WITNESSD_NO_COLOR` | Disable colored output |

### Example

```bash
export WITNESSD_DATA_DIR=/custom/path
export WITNESSD_LOG_LEVEL=debug
witnessd status
```

## macOS App Settings

The macOS app provides a graphical settings interface with additional options:

### General Tab

| Setting | Description |
|---------|-------------|
| Open at Login | Launch Witnessd when you log in |
| Auto-create checkpoints | Automatically save checkpoints at intervals |
| Checkpoint Interval | Time between auto-checkpoints (5min to 2hr) |
| Debounce Interval | Wait time after last keystroke (100-2000ms) |

### Watch Paths Tab

Configure directories for automatic file tracking:
- Add/remove watched directories
- Enable/disable individual paths
- Paths are monitored for document changes

### Patterns Tab

Filter which files are tracked:
- Include patterns: `.md`, `.txt`, `.rtf`, etc.
- Presets for common use cases (Text Files, Documents, Code)

### Security Tab

| Setting | Description |
|---------|-------------|
| Signing Key | Path to Ed25519 private key |
| TPM Attestation | Enable hardware attestation (if available) |
| VDF Calibration | Recalibrate timing proofs |

### Notifications Tab

Configure notification preferences:
- Enable/disable notifications
- Notifications for tracking start/stop
- Notifications for checkpoint creation

### Advanced Tab

| Setting | Description |
|---------|-------------|
| Data Location | Path to evidence storage |
| Default Export Format | JSON or CBOR |
| Default Export Tier | Evidence tier for exports |
| Reset | Delete all data and start fresh |

## Configuration Examples

### Minimal Configuration

```json
{
  "version": 4,
  "storage": {
    "type": "sqlite",
    "path": "events.db"
  }
}
```

### Writer Configuration

Optimized for creative writing with automatic tracking:

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
    "min_iterations": 500000,
    "calibrated": true
  },
  "sentinel": {
    "auto_start": true,
    "checkpoint_seconds": 300,
    "wal_enabled": true
  }
}
```

### High-Security Configuration

Maximum evidence strength for legal/compliance use:

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
    "min_iterations": 1000000,
    "calibrated": true
  },
  "key_hierarchy": {
    "enabled": true,
    "version": 1
  },
  "presence": {
    "challenge_interval_seconds": 300,
    "response_window_seconds": 30
  },
  "sentinel": {
    "auto_start": true,
    "heartbeat_seconds": 30,
    "checkpoint_seconds": 60,
    "wal_enabled": true
  }
}
```

### Development Configuration

For testing and development:

```json
{
  "version": 4,
  "storage": {
    "type": "memory",
    "secure": false
  },
  "vdf": {
    "min_iterations": 1000,
    "max_iterations": 10000,
    "calibrated": true
  }
}
```

---

See also:
- [CLI Reference](cli-reference.md) for command-line options
- [Getting Started](getting-started.md) for initial setup
- [Troubleshooting](troubleshooting.md) for common issues
