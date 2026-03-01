# Persistence & Fault Tolerance Specification

Witnessd is designed to ensure that no evidence is lost, even in the event of a system crash or power failure. This is achieved through a three-layer persistence stack.

---

## The Three-Layer Stack

### Layer 1: RAM Buffer (Ephemeral)
- **Frequency**: Every keystroke/event.
- **Purpose**: High-speed capture of timing and activity data.
- **Risk**: Data is lost if the application crashes before flushing to disk (max 100ms of data).

### Layer 2: [[Glossary#WAL|Write-Ahead Log (WAL)]] (Durable)
- **Frequency**: Every 100ms or when the buffer is full.
- **Purpose**: Provides a persistent record of activity that hasn't been "committed" to a checkpoint yet.
- **Recovery**: If witnessd crashes, it replays the WAL on the next start to recover any uncommitted evidence.

### Layer 3: Permanent Record ([[Glossary#MMR|MMR]]/Database)
- **Frequency**: Every 60 seconds (Heartbeat) or on manual Save (Cmd+S).
- **Purpose**: The final, cryptographically sealed record.
- **Security**: Once data is here, it is locked with a **[[Glossary#VDF|Verifiable Delay Function (VDF)]]** and signed with a **[[Glossary#Key Ratchet|Ratcheting Key]]**. It cannot be modified without breaking the cryptographic chain.

## The [[Glossary#The Labyrinth|Labyrinth]]: Machine-State Entanglement

To prevent an adversary from "cherry-picking" which evidence to keep, Witnessd implements **The Labyrinth**—a machine-wide Merkle Mountain Range (MMR).

### Global Hash Chain

Instead of isolated per-document histories, every witnessed event on a device is hashed into a single, monotonic global chain.

- **Global Binding:** Every `SecureEvent` includes the current machine-wide `chain_hash` as its `previous_hash`.
- **Integrity Table:** The local database maintains a master record of the chain state.
- **Detection Power:** If a user deletes a single event from 2 years ago, the `chain_hash` for every subsequent event created on that machine—regardless of which document it belongs to—will fail verification.

---

## Commit Triggers

Witnessd "commits" data from the WAL to the permanent database based on several triggers:

1. **Temporal Heartbeat**: Every 60 seconds of active writing.
2. **Semantic Milestones**: When you save your file (`Cmd+S`), close the document, or switch applications.
3. **Session End**: When you explicitly stop tracking a document.

---

## Crash Recovery Protocol

Upon startup, witnessd follows these steps:
1. **Detect WAL**: Checks for any non-empty Write-Ahead Logs.
2. **Integrity Check**: Validates the HMAC signatures on the WAL entries.
3. **Replay**: Reconstructs the missing activity data.
4. **Recovery Checkpoint**: Creates a special "crash-recovery" checkpoint to seal the recovered data.

---

## Data Integrity Guarantees

| Scenario | Data Protection |
|:---------|:----------------|
| **Normal Use** | 100% Integrity, fully verifiable. |
| **App Crash** | ~99.9% Recovery via WAL replay. |
| **Power Loss** | Recovery of all data flushed to WAL (max 100ms loss). |
| **Disk Corruption** | Detected via HMAC and checksums; user is notified of the "gap" in evidence. |

---

*For more on how these records are structured, see the **[[Evidence Format]]**.*
