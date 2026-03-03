# Configuration

WritersLogic can be customized via a JSON configuration file. By default, this file is located at:
- **Linux/macOS (CLI)**: `~/.writerslogic/config.json`
- **macOS App**: `~/Library/Application Support/WritersLogic/config.json`

## Configuration Structure

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
  },
  "identity": {
    "puf_type": "auto",
    "key_rotation_days": 30
  }
}
```

## Settings Categories

### Storage

- `type`: Only `sqlite` is currently supported.
- `path`: Path to the event database.
- `secure`: If true, enables additional database integrity checks.

### [[Glossary#VDF|VDF (Verifiable Delay Function)]]

- `iterations_per_second`: Calibrated speed of your CPU.
- `min_iterations`: Minimum delay for any single checkpoint.
- `max_iterations`: Maximum allowable delay (safety limit).
- `calibrated`: Whether `wld calibrate` has been run.

### [[Glossary#Sentinel|Sentinel (Background Daemon)]]

- `auto_start`: Whether to start the sentinel on login.
- `heartbeat_seconds`: Frequency of background "alive" signals.
- `checkpoint_seconds`: Frequency of automatic checkpoints for tracked files.

---

## Environment Variables

You can override certain settings using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `WLD_DIR` | Base directory for WritersLogic data | `~/.writerslogic` |
| `WLD_LOG_LEVEL` | Logging verbosity (debug, info, warn, error) | `info` |
| `WLD_CONFIG` | Path to a specific config file | `$WLD_DIR/config.json` |

---

## Command Line Overrides

Most CLI commands accept a `--config` flag to use an alternative configuration directory:

```bash
WritersLogic --config /path/to/alt/dir commit myfile.txt
```

---

*For more details, see the **[[CLI Reference]]**.*
