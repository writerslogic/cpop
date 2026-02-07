# Persistence Logic and Fault Tolerance Specification

**Version:** 1.0.0
**Status:** Draft
**Last Updated:** 2026-01-27

## Overview

This specification defines how `witnessd` transitions ephemeral keystroke/timing data from volatile buffers to permanent cryptographic records. The critical requirements are:

1. **Zero data loss** on expected shutdown (user closes app, system restart)
2. **Minimal data loss** on unexpected failure (power loss, crash)
3. **Tamper evidence** for all persisted records
4. **Invisible operation** to the user during normal writing flow

## Design Goals

### The Temporary-to-Permanent Transition

Most evidence systems fail at the boundary between capture and persistence:
- Systems that record everything create privacy nightmares and storage bloat
- Systems that only record final saves produce weak evidence ("could have been generated")

`witnessd` captures the *process* of creation through high-frequency sampling, then commits **signed hashes and VDF proofs** (not raw content) to permanent storage. This provides strong evidence while respecting privacy and storage constraints.

### Evidence Strength vs. Friction

| State | Purpose | Storage | Falsifiability | User Visibility |
|-------|---------|---------|----------------|-----------------|
| **RAM Buffer** | Capture high-frequency data | Volatile memory | None (lost on crash) | Invisible |
| **Write-Ahead Log** | Crash recovery | fsync'd file | Medium (recoverable) | Invisible |
| **MMR Checkpoint** | Permanent record | SQLite/MMR | Extreme (cryptographic) | Optional notification |

## Architecture

### Three-Layer Persistence Stack

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            LAYER 1: RAM BUFFER                              │
│                                                                             │
│  High-frequency capture (every keystroke)                                   │
│  - Keystroke counter                                                        │
│  - Timing intervals                                                         │
│  - Document hash snapshots                                                  │
│  - Zone transitions (jitter)                                                │
│                                                                             │
│  Flush trigger: 100ms idle OR buffer full (1000 entries)                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ Atomic append (100ms)
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LAYER 2: WRITE-AHEAD LOG                            │
│                                                                             │
│  Durable but uncommitted data                                               │
│  - WAL entries with sequence numbers                                        │
│  - HMAC integrity on each entry                                             │
│  - Mini hash-chain within WAL                                               │
│                                                                             │
│  Commit trigger: 60s heartbeat OR semantic milestone (Cmd+S, file close)    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ VDF + Sign + Append (60s)
┌─────────────────────────────────────────────────────────────────────────────┐
│                       LAYER 3: MMR (PERMANENT RECORD)                       │
│                                                                             │
│  Immutable, cryptographically sealed                                        │
│  - VDF-locked checkpoint                                                    │
│  - PUF-bound session key signature                                          │
│  - Appended to Merkle Mountain Range                                        │
│                                                                             │
│  Once here: Cannot be altered without breaking hash chain                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Write-Ahead Log (WAL)

### Purpose

The WAL bridges the gap between high-frequency RAM capture and the 60-second commit cycle. On crash:
- RAM buffer is lost (max 100ms of data)
- WAL entries survive and are replayed on recovery
- User loses at most one heartbeat interval (60s) of *uncommitted* data, but the WAL preserves it for reconstruction

### WAL Entry Format

```go
type WALEntry struct {
    // Monotonic sequence number (survives crash, detects gaps)
    Sequence    uint64

    // Entry timestamp (UnixNano)
    Timestamp   int64

    // Entry type discriminator
    Type        WALEntryType

    // Type-specific payload (see below)
    Payload     []byte

    // Hash of previous entry (mini hash-chain)
    PrevHash    [32]byte

    // HMAC-SHA256(session_key, sequence || timestamp || type || payload || prev_hash)
    HMAC        [32]byte
}

type WALEntryType uint8

const (
    WALEntryKeystrokeBatch  WALEntryType = 1  // Batch of keystroke events
    WALEntryDocumentHash    WALEntryType = 2  // Document state snapshot
    WALEntryJitterSample    WALEntryType = 3  // Jitter seal sample
    WALEntryHeartbeat       WALEntryType = 4  // Periodic heartbeat marker
    WALEntrySessionStart    WALEntryType = 5  // Session initialization
    WALEntrySessionEnd      WALEntryType = 6  // Clean session termination
    WALEntryCheckpoint      WALEntryType = 7  // Checkpoint committed to MMR
)
```

### WAL Entry Payloads

**KeystrokeBatch (Type 1):**
```go
type KeystrokeBatchPayload struct {
    StartSequence   uint64    // First keystroke in batch
    EndSequence     uint64    // Last keystroke in batch
    Count           uint32    // Number of keystrokes
    StartTime       int64     // First keystroke timestamp
    EndTime         int64     // Last keystroke timestamp
    DocumentHash    [32]byte  // Document state at batch end
    ZoneHistogram   [8]uint16 // Zone transition counts (privacy-preserving)
}
```

**DocumentHash (Type 2):**
```go
type DocumentHashPayload struct {
    Hash        [32]byte
    Size        uint64
    ModTime     int64
}
```

**JitterSample (Type 3):**
```go
type JitterSamplePayload struct {
    Ordinal         uint64
    KeystrokeCount  uint64
    DocumentHash    [32]byte
    ZoneTransition  uint8
    IntervalBucket  uint8
    JitterMicros    uint32
    SampleHash      [32]byte
}
```

**Checkpoint (Type 7):**
```go
type CheckpointPayload struct {
    MMRIndex        uint64    // Index in MMR
    CheckpointHash  [32]byte  // Hash of committed checkpoint
    WALSequence     uint64    // Last WAL sequence included in checkpoint
}
```

### WAL File Format

```
┌────────────────────────────────────────────────────────────────┐
│ WAL Header (64 bytes)                                          │
├────────────────────────────────────────────────────────────────┤
│ Magic: "WWAL" (4 bytes)                                        │
│ Version: uint32 (4 bytes)                                      │
│ SessionID: [32]byte                                            │
│ CreatedAt: int64 (8 bytes)                                     │
│ LastCheckpointSeq: uint64 (8 bytes)                            │
│ Reserved: [8]byte                                              │
└────────────────────────────────────────────────────────────────┘
│ Entry 0 (variable length)                                      │
├────────────────────────────────────────────────────────────────┤
│ EntryLength: uint32 (4 bytes, big-endian)                      │
│ Sequence: uint64 (8 bytes)                                     │
│ Timestamp: int64 (8 bytes)                                     │
│ Type: uint8 (1 byte)                                           │
│ PayloadLength: uint32 (4 bytes)                                │
│ Payload: [PayloadLength]byte                                   │
│ PrevHash: [32]byte                                             │
│ HMAC: [32]byte                                                 │
│ CRC32: uint32 (4 bytes, entry integrity)                       │
└────────────────────────────────────────────────────────────────┘
│ Entry 1 ...                                                    │
│ Entry N ...                                                    │
└────────────────────────────────────────────────────────────────┘
```

### WAL Operations

**Append:**
```go
func (w *WAL) Append(entryType WALEntryType, payload []byte) error {
    w.mu.Lock()
    defer w.mu.Unlock()

    entry := &WALEntry{
        Sequence:  w.nextSequence,
        Timestamp: time.Now().UnixNano(),
        Type:      entryType,
        Payload:   payload,
        PrevHash:  w.lastHash,
    }

    // Compute HMAC
    entry.HMAC = w.computeHMAC(entry)

    // Serialize and write
    data := entry.Serialize()
    if _, err := w.file.Write(data); err != nil {
        return err
    }

    // fsync to ensure durability
    if err := w.file.Sync(); err != nil {
        return err
    }

    // Update state
    w.lastHash = entry.Hash()
    w.nextSequence++

    return nil
}
```

**Truncate (after checkpoint):**
```go
func (w *WAL) TruncateBeforeCheckpoint(checkpointSeq uint64) error {
    // Keep entries after the checkpoint for crash recovery
    // Delete entries that have been committed to MMR

    w.mu.Lock()
    defer w.mu.Unlock()

    // Create new WAL file with only entries >= checkpointSeq
    newPath := w.path + ".new"
    newFile, err := os.Create(newPath)
    if err != nil {
        return err
    }

    // Write header
    w.writeHeader(newFile, checkpointSeq)

    // Copy entries after checkpoint
    for _, entry := range w.entriesAfter(checkpointSeq) {
        data := entry.Serialize()
        newFile.Write(data)
    }

    newFile.Sync()
    newFile.Close()

    // Atomic rename
    return os.Rename(newPath, w.path)
}
```

## Commit Triggers

### 1. Temporal Heartbeat (Primary)

Every 60 seconds (configurable), the daemon commits accumulated WAL entries to the MMR:

```go
func (s *Sentinel) startHeartbeat() {
    ticker := time.NewTicker(s.config.HeartbeatInterval) // Default: 60s

    go func() {
        for {
            select {
            case <-ticker.C:
                s.commitCheckpoint("heartbeat")
            case <-s.ctx.Done():
                ticker.Stop()
                return
            }
        }
    }()
}
```

### 2. Semantic Milestones (Secondary)

Certain user actions trigger immediate commits:

| Event | Detection Method | Commit Type |
|-------|------------------|-------------|
| Cmd+S (Save) | CGEventTap key monitoring | `"user-save"` |
| File close | FSEvents + accessibility | `"file-close"` |
| App switch | NSWorkspace notification | `"app-switch"` |
| Session end | User-initiated stop | `"session-end"` |

```go
func (s *Sentinel) onSaveDetected(path string) {
    // Debounce rapid saves (500ms)
    if time.Since(s.lastSaveCommit) < 500*time.Millisecond {
        return
    }

    s.commitCheckpoint("user-save")
    s.lastSaveCommit = time.Now()
}
```

### 3. WAL Size Threshold (Safety)

If WAL grows beyond threshold, force commit to prevent unbounded growth:

```go
const (
    WALSoftLimit = 10 * 1024 * 1024  // 10 MB: trigger commit
    WALHardLimit = 50 * 1024 * 1024  // 50 MB: force commit, warn user
)

func (s *Sentinel) checkWALSize() {
    size := s.wal.Size()

    if size > WALHardLimit {
        log.Warn("WAL exceeded hard limit, forcing checkpoint")
        s.commitCheckpoint("wal-overflow")
    } else if size > WALSoftLimit {
        s.commitCheckpoint("wal-threshold")
    }
}
```

## Checkpoint Commit Protocol

When a commit is triggered, the following sequence executes:

```go
func (s *Sentinel) commitCheckpoint(trigger string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    // 1. Snapshot current state
    snapshot := s.captureSnapshot()
    if snapshot.IsEmpty() {
        return nil // Nothing to commit
    }

    // 2. Compute VDF proof (locks time)
    vdfInput := s.computeVDFInput(snapshot)
    vdfProof, err := vdf.Compute(vdfInput, s.config.VDFDuration, s.vdfParams)
    if err != nil {
        return fmt.Errorf("VDF computation failed: %w", err)
    }

    // 3. Create checkpoint structure
    checkpoint := &Checkpoint{
        Ordinal:       s.nextOrdinal,
        ContentHash:   snapshot.DocumentHash,
        ContentSize:   snapshot.DocumentSize,
        Timestamp:     time.Now(),
        Message:       trigger,
        VDFInput:      vdfInput,
        VDFOutput:     vdfProof.Output,
        VDFIterations: vdfProof.Iterations,
        PreviousHash:  s.lastCheckpointHash,

        // Aggregate keystroke data
        KeystrokeCount:  snapshot.KeystrokeCount,
        JitterSamples:   snapshot.JitterSamples,
        ZoneProfile:     snapshot.ZoneProfile,
    }

    // 4. Sign with session key (ratchet forward after)
    checkpoint.Signature = s.signWithSessionKey(checkpoint)
    s.ratchetSessionKey()

    // 5. Compute checkpoint hash
    checkpoint.Hash = checkpoint.ComputeHash()

    // 6. Append to MMR
    mmrIndex, err := s.mmr.Append(checkpoint.Hash[:])
    if err != nil {
        return fmt.Errorf("MMR append failed: %w", err)
    }

    // 7. Write checkpoint record to SQLite
    if err := s.store.SaveCheckpoint(checkpoint); err != nil {
        return fmt.Errorf("checkpoint save failed: %w", err)
    }

    // 8. Mark WAL entries as committed
    walCheckpoint := &CheckpointPayload{
        MMRIndex:       mmrIndex,
        CheckpointHash: checkpoint.Hash,
        WALSequence:    s.wal.LastSequence(),
    }
    s.wal.Append(WALEntryCheckpoint, walCheckpoint.Serialize())

    // 9. Truncate committed WAL entries (async, non-blocking)
    go s.wal.TruncateBeforeCheckpoint(snapshot.WALSequence)

    // 10. Update state
    s.lastCheckpointHash = checkpoint.Hash
    s.nextOrdinal++

    return nil
}
```

## Crash Recovery

### Recovery Protocol

On daemon startup, execute recovery before accepting new events:

```go
func (s *Sentinel) RecoverFromCrash() error {
    // 1. Check for existing WAL
    if !s.wal.Exists() {
        return nil // Clean start
    }

    // 2. Validate WAL integrity
    if err := s.wal.Validate(); err != nil {
        // WAL corrupted - document limitation and start fresh
        s.logRecoveryFailure("WAL validation failed", err)
        return s.startFresh()
    }

    // 3. Find last committed checkpoint
    lastCheckpoint, err := s.store.LastCheckpoint()
    if err != nil {
        return fmt.Errorf("failed to load last checkpoint: %w", err)
    }

    var lastCommittedSeq uint64
    if lastCheckpoint != nil {
        lastCommittedSeq = s.findWALSequenceForCheckpoint(lastCheckpoint)
    }

    // 4. Replay uncommitted WAL entries
    entries, err := s.wal.EntriesAfter(lastCommittedSeq)
    if err != nil {
        return fmt.Errorf("failed to read WAL entries: %w", err)
    }

    recoveredData := &RecoveryData{}
    for _, entry := range entries {
        // Verify HMAC integrity
        if !entry.VerifyHMAC(s.sessionKey) {
            s.logTamperDetected(entry)
            continue // Skip tampered entries
        }

        // Replay based on entry type
        switch entry.Type {
        case WALEntryKeystrokeBatch:
            recoveredData.AddKeystrokes(entry.Payload)
        case WALEntryDocumentHash:
            recoveredData.UpdateDocumentState(entry.Payload)
        case WALEntryJitterSample:
            recoveredData.AddJitterSample(entry.Payload)
        case WALEntryHeartbeat:
            // Heartbeat without commit = crash during commit
            recoveredData.MarkIncompleteCommit()
        }
    }

    // 5. If significant data recovered, create recovery checkpoint
    if recoveredData.Significant() {
        s.commitCheckpoint("crash-recovery")
        s.logRecoverySuccess(recoveredData.Stats())
    }

    // 6. Clean up WAL
    s.wal.TruncateBeforeCheckpoint(lastCommittedSeq)

    return nil
}
```

### Handling Specific Failure Modes

**Power loss during RAM→WAL flush:**
- Data in RAM buffer is lost (max 100ms)
- Documented as acceptable loss
- Evidence packet includes `limitations: ["Up to 100ms of keystroke data may be lost on power failure"]`

**Power loss during WAL→MMR commit:**
- WAL entries survive
- On recovery, replay WAL and create "crash-recovery" checkpoint
- VDF is recomputed (slightly different timestamp, documented)

**WAL corruption (bit rot, partial write):**
```go
func (w *WAL) Validate() error {
    // Read header
    header, err := w.readHeader()
    if err != nil {
        return fmt.Errorf("invalid header: %w", err)
    }

    // Validate each entry
    var prevHash [32]byte
    for {
        entry, err := w.readNextEntry()
        if err == io.EOF {
            break
        }
        if err != nil {
            return fmt.Errorf("entry read failed: %w", err)
        }

        // Check CRC
        if entry.CRC32 != entry.ComputeCRC() {
            return fmt.Errorf("entry %d: CRC mismatch", entry.Sequence)
        }

        // Check hash chain
        if entry.PrevHash != prevHash {
            return fmt.Errorf("entry %d: broken hash chain", entry.Sequence)
        }

        // Check HMAC (requires session key)
        // Deferred to recovery phase

        prevHash = entry.Hash()
    }

    return nil
}
```

**Recovery posture for corrupted WAL:**
- Log the corruption with details
- Start fresh session
- Add limitation to next evidence packet: `"Previous session data lost due to storage corruption"`
- Notify user if running interactively

**Clock manipulation during recovery:**
```go
func (s *Sentinel) validateRecoveryTimestamps(entries []WALEntry) error {
    var prevTime int64

    for _, entry := range entries {
        // Timestamps must be monotonically increasing
        if entry.Timestamp < prevTime {
            return fmt.Errorf("entry %d: timestamp went backward (possible clock manipulation)",
                entry.Sequence)
        }

        // Timestamp should not be in the future
        if entry.Timestamp > time.Now().UnixNano() {
            return fmt.Errorf("entry %d: timestamp in future (clock skew or manipulation)",
                entry.Sequence)
        }

        // Large gaps are suspicious but not fatal
        if prevTime > 0 {
            gap := time.Duration(entry.Timestamp - prevTime)
            if gap > 24*time.Hour {
                s.logSuspiciousGap(entry, gap)
            }
        }

        prevTime = entry.Timestamp
    }

    return nil
}
```

## Multi-Document Handling

### Shared vs. Separate WALs

**Decision: Separate WAL per tracked document**

Rationale:
- Simpler recovery (each document recovers independently)
- Natural isolation (one document's corruption doesn't affect others)
- Parallel commit (multiple documents can commit simultaneously)
- Clear ownership (WAL file tied to document path)

```
~/.witnessd/
├── wal/
│   ├── a1b2c3d4.wal    # WAL for document at /Users/dave/essay.md
│   ├── e5f6g7h8.wal    # WAL for document at /Users/dave/notes.txt
│   └── shadow/
│       └── i9j0k1l2.wal  # WAL for unsaved TextEdit document
└── ...
```

**WAL naming:**
```go
func walPathForDocument(docPath string) string {
    // Hash the document path for consistent, filesystem-safe naming
    h := sha256.Sum256([]byte(docPath))
    return filepath.Join(walDir, hex.EncodeToString(h[:8]) + ".wal")
}
```

### Concurrent Document Tracking

```go
type MultiDocumentSentinel struct {
    documents map[string]*DocumentTracker
    mu        sync.RWMutex
}

type DocumentTracker struct {
    Path        string
    WAL         *WAL
    Session     *Session
    LastActive  time.Time

    // Each document has its own commit timer
    heartbeat   *time.Timer
}

func (s *MultiDocumentSentinel) onFocusChange(docPath string) {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Pause previous document's heartbeat
    if s.activeDoc != "" && s.activeDoc != docPath {
        if tracker := s.documents[s.activeDoc]; tracker != nil {
            tracker.Pause()
        }
    }

    // Resume or create tracker for new document
    tracker, exists := s.documents[docPath]
    if !exists {
        tracker = s.createTracker(docPath)
        s.documents[docPath] = tracker
    }
    tracker.Resume()

    s.activeDoc = docPath
}
```

## Configuration

```toml
# ~/.witnessd/config.toml

[persistence]
# RAM buffer flush interval
buffer_flush_ms = 100

# Heartbeat (checkpoint) interval
heartbeat_seconds = 60

# VDF duration for each checkpoint
vdf_duration_seconds = 1

# WAL size thresholds
wal_soft_limit_mb = 10
wal_hard_limit_mb = 50

[recovery]
# Maximum WAL age before forced discard
max_wal_age_hours = 168  # 1 week

# Whether to notify user of recovery events
notify_on_recovery = true

# Whether to create evidence limitation for recovered sessions
document_recovery_limitation = true
```

## Failure Modes and Guarantees

### Guaranteed (Cryptographic)

| Scenario | Guarantee |
|----------|-----------|
| Clean shutdown | Zero data loss |
| Checkpoint committed | Immutable, tamper-evident |
| WAL entry written | Survives crash, HMAC-protected |

### Best-Effort (Documented Limitations)

| Scenario | Maximum Loss | Documented? |
|----------|--------------|-------------|
| Power loss (buffer) | 100ms of keystrokes | Yes |
| Power loss (WAL→MMR) | Recovered on restart | Yes |
| WAL corruption | Entire uncommitted session | Yes |
| Clock manipulation | Detected, logged, flagged | Yes |

### Out of Scope

| Scenario | Handling |
|----------|----------|
| Kernel compromise | Cannot detect; documented in threat model |
| Disk encryption failure | OS responsibility |
| Memory corruption | Cannot distinguish from normal operation |

## Implementation Checklist

- [ ] WAL file format and serialization
- [ ] WAL append with fsync
- [ ] WAL validation and recovery
- [ ] Heartbeat timer integration
- [ ] Save detection (Cmd+S) via CGEventTap
- [ ] File close detection via FSEvents
- [ ] VDF integration in commit path
- [ ] Session key ratcheting on commit
- [ ] MMR append integration
- [ ] Multi-document WAL management
- [ ] Recovery notification UI
- [ ] Configuration options

## References

- SQLite WAL mode: https://sqlite.org/wal.html
- fsync guarantees: POSIX.1-2017
- Merkle Mountain Range: https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md
