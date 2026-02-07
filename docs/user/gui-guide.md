# macOS App User Guide

The Witnessd macOS app provides a graphical interface for cryptographic authorship witnessing. This guide covers all features of the menu bar application.

## Table of Contents

- [Installation](#installation)
- [First Launch](#first-launch)
- [Menu Bar Interface](#menu-bar-interface)
- [Tracking Documents](#tracking-documents)
- [Creating Checkpoints](#creating-checkpoints)
- [Viewing History](#viewing-history)
- [Exporting Evidence](#exporting-evidence)
- [Settings](#settings)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Permissions](#permissions)

## Installation

### Requirements

- macOS 13.0 (Ventura) or later
- Apple Silicon or Intel processor
- 50 MB disk space

### Install from DMG

1. Download `Witnessd.dmg` from the [releases page](https://github.com/writerslogic/witnessd/releases)
2. Open the DMG file
3. Drag **Witnessd** to your **Applications** folder
4. Eject the DMG

### Launch

- Open from **Applications** folder, or
- Search "Witnessd" in **Spotlight** (Cmd+Space)

The app runs as a menu bar application - look for the eye icon in your menu bar.

## First Launch

### Onboarding

On first launch, you'll see the onboarding screen:

1. **Welcome**: Overview of witnessd features
2. **Permissions**: Grant accessibility permissions (required for keystroke counting)
3. **Initialize**: Creates your cryptographic identity
4. **Calibrate**: Measures VDF performance for your Mac

### Accessibility Permissions

Witnessd requires accessibility permissions to count keystrokes (not capture content):

1. Click **Open System Settings** when prompted
2. Navigate to **Privacy & Security > Accessibility**
3. Enable the toggle next to **Witnessd**
4. Return to the app

**Privacy Note:** Witnessd only counts keystroke events - it does NOT record which keys you press.

### Initialization

The app automatically initializes on first launch:
- Creates Ed25519 signing key pair
- Derives master identity from device
- Sets up secure database
- Calibrates VDF timing

## Menu Bar Interface

### Status Icon

The menu bar icon indicates current state:

| Icon | Color | Meaning |
|------|-------|---------|
| Eye circle (filled) | Green | Tracking active |
| Eye circle | Gray | Ready (not tracking) |
| Eye slash | Light gray | Not initialized |

### Quick Menu

Click the menu bar icon to open the quick menu:

**When not tracking:**
```
○ Ready to Track
──────────────────
▶ Start Global Tracking    ⌘G
  Start Tracking Document…
──────────────────
  View Details…
  Settings…                ⌘,
──────────────────
  Quit Witnessd           ⌘Q
```

**When tracking:**
```
● Tracking: manuscript.md (1,234 keystrokes)
──────────────────
  Stop Tracking
  Create Checkpoint Now
──────────────────
  View Details…
  Settings…                ⌘,
──────────────────
  Quit Witnessd           ⌘Q
```

## Tracking Documents

### Global Tracking

Start tracking all keystrokes without specifying a document:

1. Click the menu bar icon
2. Select **Start Global Tracking**

This creates a session file in `~/Library/Application Support/Witnessd/sessions/` named with the current date.

### Document-Specific Tracking

Track keystrokes for a specific document:

1. Click the menu bar icon
2. Select **Start Tracking Document...**
3. Choose the file you're working on
4. Click **Start Tracking**

### What Gets Tracked

| Data | Description |
|------|-------------|
| Keystroke count | Total number of key presses |
| Timing jitter | Nanosecond-precision timing variations |
| Session duration | Start and end times |
| File associations | Which document the session is for |

**Not tracked:** Actual keys pressed, clipboard content, screen content, or any identifying information about your writing.

### Stopping Tracking

1. Click the menu bar icon
2. Select **Stop Tracking**

This automatically:
- Creates a final checkpoint
- Saves the session to the database
- Shows a confirmation notification

## Creating Checkpoints

### Manual Checkpoint

Create a checkpoint at any time:

1. Click the menu bar icon
2. Select **Create Checkpoint Now**

The checkpoint includes:
- Current file content hash
- VDF timing proof
- Keystroke count (if tracking)
- Jitter samples (if tracking)

### Auto-Checkpoints

Enable automatic checkpoints in Settings:

1. Open **Settings** > **General**
2. Enable **Auto-create checkpoints**
3. Set the interval (5 min to 2 hours)

Checkpoints are created automatically at the specified interval while tracking is active.

## Viewing History

### Details Popover

Click **View Details...** to see:

- Current tracking status
- Total keystrokes in session
- Recent checkpoints
- Quick actions

### Checkpoint History

The popover shows recent checkpoints:

```
Recent Checkpoints

#15  Today 2:30 PM      +1.2 KB  Chapter complete
#14  Today 1:15 PM      +856 B   Added section
#13  Today 11:00 AM     +2.1 KB  Morning writing
```

Click any checkpoint to see details:
- Full content hash
- VDF iterations
- Associated keystroke count
- Size delta

## Exporting Evidence

### Export from Details

1. Click **View Details...**
2. Select a document
3. Click **Export Evidence**
4. Choose save location

### Export Options

| Option | Description |
|--------|-------------|
| Format | JSON (readable) or CBOR (compact) |
| Tier | Evidence tier level |
| Include Content | Embed file content in packet |

### Evidence Tiers

| Tier | Name | Description |
|------|------|-------------|
| 1 | Basic | Checkpoints with VDF proofs |
| 2 | Software-Attested | + Key hierarchy and declaration |
| 3 | Hardware-Attested | + TPM/Secure Enclave attestation |

## Settings

Access settings via menu bar > **Settings...** or **Cmd+,**

### General Tab

| Setting | Description |
|---------|-------------|
| Open at Login | Auto-start Witnessd on login |
| Auto-create checkpoints | Enable automatic checkpoints |
| Checkpoint Interval | Time between auto-checkpoints |
| Debounce Interval | Wait after last keystroke (100-2000ms) |

### Watch Paths Tab

Configure directories for automatic tracking:

1. Click **Add Directory...**
2. Select a folder to watch
3. Toggle paths on/off as needed

When you edit files in watched directories, Witnessd can automatically start tracking.

### Patterns Tab

Filter which files to track:

- **File Extensions**: Only track files matching patterns (e.g., `.md`, `.txt`)
- **Presets**: Quick-add common patterns:
  - Text Files: `.txt`, `.md`, `.rtf`
  - Documents: `.doc`, `.docx`, `.odt`, `.pdf`
  - Code: `.swift`, `.go`, `.py`, `.js`, `.ts`

### Security Tab

| Setting | Description |
|---------|-------------|
| Signing Key | Path to custom Ed25519 key |
| TPM Attestation | Enable hardware attestation (if available) |
| VDF Calibration | Recalibrate timing proofs |

**VDF Status:**
- Green checkmark: Calibrated
- Yellow warning: Not calibrated (click **Recalibrate VDF**)

### Notifications Tab

| Setting | Description |
|---------|-------------|
| Show notifications | Enable/disable all notifications |

Notification types:
- Tracking started/stopped
- Checkpoint created
- Auto-checkpoint created

### Advanced Tab

| Setting | Description |
|---------|-------------|
| Data Location | Path to evidence storage |
| Default Export Format | JSON or CBOR |
| Default Export Tier | Tier for new exports |

**Reveal**: Opens the data folder in Finder

**Reset Witnessd**: Deletes all data and keys (irreversible!)

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| ⌘G | Start global tracking |
| ⌘, | Open Settings |
| ⌘Q | Quit Witnessd |

## Permissions

### Required Permissions

| Permission | Purpose |
|------------|---------|
| Accessibility | Count keystroke events (not content) |
| Notifications | Show tracking and checkpoint alerts |

### Granting Permissions

**Accessibility:**
1. System Settings > Privacy & Security > Accessibility
2. Enable Witnessd

**Notifications:**
1. System Settings > Notifications
2. Find Witnessd
3. Enable notifications

### Revoking Permissions

If you revoke accessibility permissions:
- Keystroke counting will be disabled
- Basic checkpointing still works
- Evidence will be Tier 1 instead of Tier 2

## Data Storage

All data is stored in:
```
~/Library/Application Support/Witnessd/
```

Contents:
```
Witnessd/
├── config.json        # Configuration
├── events.db          # Checkpoint database
├── identity.json      # Public identity info
├── puf_seed           # Device binding seed
├── signing_key        # Private key (protected)
├── signing_key.pub    # Public key
├── sessions/          # Global tracking sessions
├── chains/            # Checkpoint chains
└── tracking/          # WAL files
```

### Backup

To backup your evidence:
1. Quit Witnessd
2. Copy the entire `Witnessd` folder
3. Store backup securely

**Important:** The `signing_key` file is your cryptographic identity. Keep backups secure!

## Troubleshooting

### Menu Bar Icon Missing

1. Check if app is running in Activity Monitor
2. Try quitting and relaunching
3. Check menu bar overflow (click >> in menu bar)

### Keystroke Counting Not Working

1. Verify accessibility permissions are granted
2. Try toggling the permission off and on
3. Restart the app after granting permission

### VDF Not Calibrated

1. Open Settings > Security
2. Click **Recalibrate VDF**
3. Wait for calibration to complete (~30 seconds)

### High CPU Usage

Normal CPU usage during:
- VDF computation (brief spike during checkpoint)
- Calibration (sustained ~30 seconds)

If CPU stays high:
1. Check sentinel status
2. Reduce checkpoint frequency
3. Increase debounce interval

See also: [Troubleshooting Guide](troubleshooting.md)

---

*For command-line usage, see [CLI Reference](cli-reference.md)*
