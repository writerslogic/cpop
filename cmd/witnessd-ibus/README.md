# Witnessd IBus Engine

Linux IBus input method implementation for witnessd cryptographic authorship witnessing.

## Overview

The witnessd IBus engine is a transparent input method that monitors keystrokes for cryptographic proof of authorship. It operates in pass-through mode - observing and recording typing patterns without modifying any input.

## Features

- **Transparent Monitoring**: All keystrokes pass through unchanged
- **Focus Tracking**: Correlates keystrokes with applications and documents
- **X11 and Wayland Support**: Works on both display protocols
- **IPC Communication**: Connects to witnessd daemon for centralized evidence storage
- **Systemd Integration**: User service for automatic startup

## Requirements

- Linux with IBus
- Go 1.21 or later
- D-Bus session bus
- Optional: xdotool (for enhanced X11 focus tracking)

## Installation

### User Installation (Recommended)

```bash
# Build and install to ~/.local
make install
```

This will:
1. Build the witnessd-ibus binary
2. Install to `~/.local/bin/witnessd-ibus`
3. Create IBus component in `~/.local/share/ibus/component/`
4. Install systemd user service
5. Create desktop file for settings

### System Installation

```bash
# Build and install system-wide (requires sudo)
make install-system
```

### After Installation

1. Restart IBus:
   ```bash
   ibus restart
   ```

2. Enable the engine via:
   - IBus preferences: `ibus-setup`
   - GNOME: Settings > Keyboard > Input Sources
   - KDE: System Settings > Input Devices > Input Methods

3. Optionally start the systemd service:
   ```bash
   systemctl --user enable witnessd-ibus
   systemctl --user start witnessd-ibus
   ```

## Usage

### Command-Line Options

```bash
witnessd-ibus [options]

Options:
  --ibus        Run as IBus engine (started by IBus)
  --install     Install component files
  --uninstall   Remove component files
  --status      Show status information
  --configure   Open configuration
  --debug       Enable debug logging
  --version     Show version information
  --socket      Override daemon socket path
  --data-dir    Override data directory
```

### Status Check

```bash
witnessd-ibus --status
```

### View Logs

```bash
# Using journalctl (if systemd service is used)
journalctl --user -u witnessd-ibus -f

# Or directly from log file
tail -f ~/.local/share/witnessd/logs/ibus.log
```

## Configuration

Configuration file: `~/.config/witnessd/config.json`

```json
{
  "engine": {
    "batch_size": 50,
    "flush_interval": "5s",
    "debug": false
  },
  "storage": {
    "evidence_dir": "~/.local/share/witnessd/evidence",
    "retention_days": 90,
    "compress": true
  }
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Application                              │
└──────────────────────────────┬──────────────────────────────────┘
                               │ Key events (unchanged)
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                          IBus Daemon                            │
│                  (org.freedesktop.IBus)                         │
└──────────────────────────────┬──────────────────────────────────┘
                               │ D-Bus
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   witnessd-ibus Engine                          │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐ │
│  │ Key Handler    │  │ Focus Tracker  │  │ Evidence Storage   │ │
│  │ (ProcessKey)   │  │ (X11/Wayland)  │  │ (Local JSON)       │ │
│  └───────┬────────┘  └───────┬────────┘  └─────────┬──────────┘ │
│          │                   │                     │            │
│          └───────────────────┴─────────────────────┤            │
│                         │                          │            │
│                         ▼                          ▼            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    IME Engine Core                       │   │
│  │  - Jitter fingerprinting                                │   │
│  │  - Zone-based keystroke analysis                        │   │
│  │  - Document hash tracking                               │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────────────────────────┬────────────────────────────────┘
                                 │ Unix Socket (optional)
                                 ▼
                    ┌─────────────────────────┐
                    │   witnessd Daemon       │
                    │   (centralized store)   │
                    └─────────────────────────┘
```

## Focus Tracking

### X11

On X11, focus tracking uses:
1. `xdotool getactivewindow` (primary)
2. `xprop _NET_ACTIVE_WINDOW` (fallback)

### Wayland

On Wayland, due to security restrictions:
1. GNOME Shell D-Bus interface (if available)
2. IBus client properties
3. Environment variables

## Files

```
Installation:
  ~/.local/bin/witnessd-ibus           # Engine binary
  ~/.local/share/ibus/component/witnessd.xml  # IBus component
  ~/.config/systemd/user/witnessd-ibus.service  # Systemd service
  ~/.local/share/applications/witnessd-ibus-setup.desktop  # Desktop file

Data:
  ~/.local/share/witnessd/evidence/    # Evidence JSON files
  ~/.local/share/witnessd/logs/        # Log files
  ~/.config/witnessd/config.json       # Configuration
```

## Uninstallation

```bash
make uninstall
```

To also remove data:
```bash
rm -rf ~/.local/share/witnessd
rm -rf ~/.config/witnessd
```

## Development

### Building

```bash
make build           # Build binary
make build-debug     # Build with debug symbols
```

### Testing

```bash
make test            # Run unit tests
make test-race       # Run with race detector
make test-coverage   # Generate coverage report
```

### Running

```bash
make run             # Run in foreground
make debug           # Run with debug logging
```

## Troubleshooting

### Engine not appearing in IBus

1. Check if the component file exists:
   ```bash
   ls ~/.local/share/ibus/component/witnessd.xml
   ```

2. Restart IBus:
   ```bash
   ibus restart
   ```

3. Check IBus logs:
   ```bash
   journalctl --user -u ibus -f
   ```

### No keystrokes being captured

1. Ensure the engine is selected as the active input method
2. Check engine status:
   ```bash
   witnessd-ibus --status
   ```

3. View engine logs:
   ```bash
   tail -f ~/.local/share/witnessd/logs/ibus.log
   ```

### Wayland focus tracking not working

Focus tracking on Wayland is limited due to security restrictions. The engine will still capture keystrokes but may not accurately identify the application.

## License

MIT License - see main witnessd project.
