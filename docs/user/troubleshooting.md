# Troubleshooting Guide

Solutions to common issues with witnessd.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Initialization Issues](#initialization-issues)
- [Tracking Issues](#tracking-issues)
- [Checkpoint Issues](#checkpoint-issues)
- [Verification Issues](#verification-issues)
- [Performance Issues](#performance-issues)
- [macOS App Issues](#macos-app-issues)
- [Data Recovery](#data-recovery)
- [Getting Help](#getting-help)

## Installation Issues

### "Command not found: witnessd"

**Cause:** witnessd is not in your PATH.

**Solutions:**

1. **Verify installation:**
   ```bash
   which witnessd
   ls -la /usr/local/bin/witnessd
   ```

2. **Add to PATH (if installed elsewhere):**
   ```bash
   export PATH="$PATH:$HOME/.local/bin"
   ```

3. **Reinstall:**
   ```bash
   make install
   # or
   brew reinstall witnessd
   ```

### Build Fails with Rust Errors

**Cause:** Incompatible Rust version or missing dependencies.

**Solution:**
```bash
# Check Rust version (requires 1.75+)
rustc --version

# Update Rust
rustup update stable

# Clean and rebuild
cargo clean
cargo build --release
```

### Permission Denied During Install

**Cause:** Insufficient permissions for /usr/local/bin.

**Solution:**
```bash
# Option 1: Use sudo
sudo make install

# Option 2: Install to user directory
make install PREFIX=$HOME/.local
```

## Initialization Issues

### "Error creating directory: permission denied"

**Cause:** Cannot create ~/.witnessd directory.

**Solutions:**

1. **Check home directory permissions:**
   ```bash
   ls -la ~/
   ```

2. **Create directory manually:**
   ```bash
   mkdir -p ~/.witnessd
   chmod 700 ~/.witnessd
   witnessd init
   ```

### "Error generating key"

**Cause:** Insufficient entropy or crypto subsystem issue.

**Solutions:**

1. **Check entropy (Linux):**
   ```bash
   cat /proc/sys/kernel/random/entropy_avail
   # Should be > 256
   ```

2. **Regenerate key manually:**
   ```bash
   rm ~/.witnessd/signing_key*
   witnessd init
   ```

### "Error deriving master identity"

**Cause:** PUF initialization failed.

**Solutions:**

1. **Remove PUF seed and reinitialize:**
   ```bash
   rm ~/.witnessd/puf_seed
   witnessd init
   ```

2. **Check file permissions:**
   ```bash
   chmod 600 ~/.witnessd/puf_seed
   ```

## Tracking Issues

### "Tracking not starting"

**Cause:** Various possible causes.

**Solutions:**

1. **Check if witnessd is initialized:**
   ```bash
   witnessd status
   ```

2. **Verify file exists:**
   ```bash
   ls -la /path/to/document.md
   ```

3. **Check for existing tracking session:**
   ```bash
   witnessd track status
   # If stuck, stop and restart
   witnessd track stop
   witnessd track start document.md
   ```

### "Keystroke count always zero"

**Cause:** Accessibility permissions not granted (macOS) or event capture not working.

**Solutions (macOS):**

1. **Grant accessibility permissions:**
   - System Settings > Privacy & Security > Accessibility
   - Enable Witnessd

2. **Restart the app after granting permissions**

3. **Check if permissions are actually granted:**
   ```bash
   sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
     "SELECT * FROM access WHERE service='kTCCServiceAccessibility'"
   ```

**Solutions (Linux):**

1. **Check if running in terminal with input:**
   ```bash
   # Must run in terminal that receives keyboard input
   witnessd track start document.md
   ```

2. **Verify input group membership:**
   ```bash
   groups | grep input
   # If not present:
   sudo usermod -a -G input $USER
   # Log out and back in
   ```

### "WAL file corrupted"

**Cause:** System crash during tracking or disk issue.

**Solutions:**

1. **Stop tracking and check WAL:**
   ```bash
   witnessd track stop
   ls -la ~/.witnessd/tracking/
   ```

2. **Remove corrupted WAL:**
   ```bash
   rm ~/.witnessd/tracking/*.wal
   ```

3. **Existing checkpoints are preserved in the database**

## Checkpoint Issues

### "Error opening database"

**Cause:** Database file corrupted or locked.

**Solutions:**

1. **Check database status:**
   ```bash
   sqlite3 ~/.witnessd/events.db "PRAGMA integrity_check;"
   ```

2. **If locked, find process holding lock:**
   ```bash
   lsof ~/.witnessd/events.db
   ```

3. **If corrupted, attempt recovery:**
   ```bash
   sqlite3 ~/.witnessd/events.db ".recover" | sqlite3 events_recovered.db
   mv events_recovered.db ~/.witnessd/events.db
   ```

### "VDF computation timeout"

**Cause:** VDF taking too long, possibly uncalibrated.

**Solutions:**

1. **Calibrate VDF:**
   ```bash
   witnessd calibrate
   ```

2. **Check VDF settings:**
   ```bash
   cat ~/.witnessd/config.json | grep -A5 '"vdf"'
   ```

3. **Reduce max iterations if needed:**
   ```json
   {
     "vdf": {
       "max_iterations": 900000000
     }
   }
   ```

### "Checkpoint failed: HMAC verification error"

**Cause:** Database integrity check failed (possible tampering).

**Solutions:**

1. **This is a security feature - investigate cause**

2. **Check if signing key changed:**
   ```bash
   sha256sum ~/.witnessd/signing_key
   ```

3. **If key was regenerated, previous checkpoints cannot be verified**

## Verification Issues

### "Invalid checkpoint chain"

**Cause:** Checkpoints don't form valid chain.

**Solutions:**

1. **Verify with verbose output:**
   ```bash
   witnessd verify document.md --verbose
   ```

2. **Check for gaps in sequence:**
   ```bash
   witnessd log document.md --json | jq '.[].number'
   ```

### "VDF proof invalid"

**Cause:** VDF proof doesn't verify.

**Solutions:**

1. **Re-verify with current VDF parameters:**
   ```bash
   witnessd calibrate
   witnessd verify document.wpkt
   ```

2. **VDF proofs are deterministic - if fails, evidence may be invalid**

### "Key hierarchy verification failed"

**Cause:** Session certificate or signature invalid.

**Solutions:**

1. **Check certificate chain:**
   ```bash
   witnessd verify document.wpkt --verbose 2>&1 | grep -i cert
   ```

2. **Verify master identity matches:**
   ```bash
   cat ~/.witnessd/identity.json | jq '.fingerprint'
   ```

## Performance Issues

### High CPU Usage

**Cause:** VDF computation or sentinel running.

**Solutions:**

1. **Check what's running:**
   ```bash
   witnessd status
   witnessd sentinel status
   ```

2. **VDF computation is intentionally CPU-intensive (brief)**

3. **Reduce checkpoint frequency:**
   ```json
   {
     "sentinel": {
       "checkpoint_seconds": 300
     }
   }
   ```

### High Disk Usage

**Cause:** Many checkpoints or large WAL files.

**Solutions:**

1. **Check disk usage:**
   ```bash
   du -sh ~/.witnessd/*
   ```

2. **WAL files can be cleaned after tracking stops:**
   ```bash
   rm ~/.witnessd/tracking/*.wal
   ```

3. **Database compaction:**
   ```bash
   sqlite3 ~/.witnessd/events.db "VACUUM;"
   ```

### Slow Checkpoints

**Cause:** Large file or uncalibrated VDF.

**Solutions:**

1. **Calibrate VDF:**
   ```bash
   witnessd calibrate
   ```

2. **For large files, checkpointing takes longer due to hashing**

3. **Check file size:**
   ```bash
   ls -lh /path/to/document
   ```

## macOS App Issues

### Menu Bar Icon Missing

**Solutions:**

1. **Check if app is running:**
   ```bash
   pgrep -l Witnessd
   ```

2. **Check menu bar overflow** (click >> on right side of menu bar)

3. **Restart the app:**
   ```bash
   pkill Witnessd
   open /Applications/Witnessd.app
   ```

### App Crashes on Launch

**Solutions:**

1. **Check Console for crash logs:**
   - Open Console.app
   - Filter for "Witnessd"

2. **Reset app state:**
   ```bash
   rm -rf ~/Library/Application\ Support/Witnessd/
   open /Applications/Witnessd.app
   ```

3. **Check macOS version compatibility**

### Notifications Not Working

**Solutions:**

1. **Check notification permissions:**
   - System Settings > Notifications > Witnessd

2. **Check Focus mode** isn't blocking notifications

3. **Toggle notifications off and on in app settings**

### Accessibility Permission Issues

**Solutions:**

1. **Remove and re-add permission:**
   - System Settings > Privacy & Security > Accessibility
   - Remove Witnessd
   - Quit and relaunch app
   - Grant permission when prompted

2. **Full disk access may be required for some features:**
   - System Settings > Privacy & Security > Full Disk Access

## Data Recovery

### Lost Signing Key

**Impact:** Cannot sign new checkpoints with same identity.

**Solutions:**

1. **Check for backups:**
   ```bash
   ls ~/.witnessd/signing_key*
   ```

2. **If no backup, generate new key:**
   ```bash
   witnessd init
   ```

3. **Previous evidence remains valid but new evidence will have different identity**

### Database Corruption

**Solutions:**

1. **Attempt recovery:**
   ```bash
   cp ~/.witnessd/events.db events.backup
   sqlite3 events.backup ".recover" | sqlite3 events.recovered.db
   ```

2. **Check recovered data:**
   ```bash
   sqlite3 events.recovered.db "SELECT COUNT(*) FROM secure_events;"
   ```

3. **Replace if recovery successful:**
   ```bash
   mv events.recovered.db ~/.witnessd/events.db
   ```

### Export Existing Data

Before complete reset:

```bash
# Export all evidence packets
for file in $(witnessd log --all --files); do
  witnessd export "$file" -o "backup_${file}.wpkt"
done
```

## Getting Help

### Diagnostic Information

Collect this before reporting issues:

```bash
# System info
uname -a
witnessd version

# Configuration
cat ~/.witnessd/config.json

# Status
witnessd status

# Recent logs (if available)
tail -100 ~/.witnessd/witnessd.log
```

### Reporting Issues

1. Search [existing issues](https://github.com/writerslogic/witnessd/issues)
2. Create new issue with:
   - Witnessd version
   - Operating system and version
   - Steps to reproduce
   - Expected vs actual behavior
   - Diagnostic information

### Community Support

- GitHub Discussions: https://github.com/writerslogic/witnessd/discussions
- Discord: https://discord.gg/witnessd

---

See also:
- [Getting Started](getting-started.md)
- [Configuration](configuration.md)
- [CLI Reference](cli-reference.md)
