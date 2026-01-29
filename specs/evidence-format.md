# Evidence Packet Format Specification

**Version:** 1.0.0
**Status:** Draft
**Last Updated:** 2026-01-25

## Overview

An **Evidence Packet** (`.wpkt` file) is a self-contained, portable proof of documented authorship. It bundles cryptographic proofs, process declarations, and optional attestations into a single exportable format that can be verified offline.

This specification defines:
- The structure of evidence packets
- Evidence strength tiers
- Verification procedures
- File format and encoding

## Design Goals

### Self-Contained Verification

Evidence packets include everything needed to verify claims:
- The verifier needs no network access
- The verifier needs no access to the original system
- The packet includes all cryptographic proofs inline

### Progressive Evidence Strength

Not all authorship claims require the same level of evidence. The format supports tiered evidence:
- Basic: Minimum viable proof
- Standard: Recommended for most use cases
- Enhanced: High-stakes contexts
- Maximum: Forensic-grade evidence

### Forward Compatibility

The format is designed for long-term archival:
- Explicit version numbers
- Unknown fields are preserved
- Algorithms are explicitly identified

## Evidence Strength Tiers

| Tier | Numeric | Components | Use Case |
|------|---------|------------|----------|
| Basic | 1 | Checkpoints + Declaration | Low-stakes, internal use |
| Standard | 2 | + Presence OR Keystroke | Academic, professional |
| Enhanced | 3 | + Hardware attestation | Legal, regulatory |
| Maximum | 4 | + Behavioral + External | Forensic, litigation |

### Tier Descriptions

**Basic (1):** The minimum viable evidence. Proves a chain of document states was created over time and the author made a signed declaration about the process. Suitable for internal documentation, personal records, or contexts where the author's word is generally trusted.

**Standard (2):** Adds verification that a human was present during creation (presence challenges) OR that real keystrokes occurred (jitter seal). Suitable for academic submissions, professional reports, or any context requiring reasonable assurance.

**Enhanced (3):** Adds hardware attestation via TPM, proving the evidence was created on a specific device and the chain was not modified after the fact. Suitable for regulatory compliance, legal documents, or high-value intellectual property.

**Maximum (4):** Adds full behavioral analysis (edit topology, forensic metrics) and external timestamp anchors (Bitcoin blockchain, RFC 3161 TSAs). Suitable for litigation, forensic investigation, or contexts requiring the strongest possible evidence.

## Packet Structure

### Top-Level Fields

```json
{
  "version": 1,
  "exported_at": "2026-01-25T14:30:00Z",
  "strength": 2,
  "document": { ... },
  "checkpoints": [ ... ],
  "vdf_params": { ... },
  "chain_hash": "...",
  "declaration": { ... },
  "presence": { ... },
  "hardware": { ... },
  "keystroke": { ... },
  "behavioral": { ... },
  "external": { ... },
  "claims": [ ... ],
  "limitations": [ ... ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | integer | Yes | Packet format version (currently 1) |
| `exported_at` | timestamp | Yes | When this packet was generated |
| `strength` | integer | Yes | Evidence tier (1-4) |
| `document` | object | Yes | Information about the witnessed document |
| `checkpoints` | array | Yes | Checkpoint chain with proofs |
| `vdf_params` | object | Yes | VDF parameters for time verification |
| `chain_hash` | string | Yes | Final hash of checkpoint chain |
| `declaration` | object | Yes | Process declaration (required) |
| `presence` | object | No | Presence verification (Standard+) |
| `hardware` | object | No | TPM attestation (Enhanced+) |
| `keystroke` | object | No | Jitter seal evidence (Standard+) |
| `behavioral` | object | No | Edit topology and metrics (Maximum) |
| `external` | object | No | External anchors (Maximum) |
| `claims` | array | Yes | What this evidence proves |
| `limitations` | array | Yes | What this evidence does NOT prove |

### Document Information

```json
{
  "document": {
    "title": "Research Paper on Climate Modeling",
    "path": "/home/user/papers/climate.md",
    "final_hash": "a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
    "final_size": 45678
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | Human-readable document title |
| `path` | string | Original file path (informational only) |
| `final_hash` | string | SHA-256 of final document state (hex) |
| `final_size` | integer | Final document size in bytes |

### Checkpoint Chain

The checkpoint chain is the core of the evidence. Each checkpoint represents a witnessed document state:

```json
{
  "checkpoints": [
    {
      "ordinal": 0,
      "content_hash": "a1b2c3d4...",
      "content_size": 1024,
      "timestamp": "2026-01-25T10:00:00Z",
      "message": "Initial draft",
      "vdf_input": "e5f6a7b8...",
      "vdf_output": "c9d0e1f2...",
      "vdf_iterations": 1000000,
      "elapsed_time": "5m30s",
      "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "hash": "f3a4b5c6..."
    },
    {
      "ordinal": 1,
      "content_hash": "d7e8f9a0...",
      "content_size": 2048,
      "timestamp": "2026-01-25T10:30:00Z",
      "message": "Added introduction",
      "vdf_input": "b1c2d3e4...",
      "vdf_output": "f5a6b7c8...",
      "vdf_iterations": 2000000,
      "elapsed_time": "10m45s",
      "previous_hash": "f3a4b5c6...",
      "hash": "a9b0c1d2..."
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `ordinal` | integer | Checkpoint sequence number (0-indexed) |
| `content_hash` | string | SHA-256 of document at this point |
| `content_size` | integer | Document size in bytes |
| `timestamp` | timestamp | When checkpoint was created |
| `message` | string | Optional commit message |
| `vdf_input` | string | VDF input hash (hex) |
| `vdf_output` | string | VDF output hash (hex) |
| `vdf_iterations` | integer | Number of VDF iterations |
| `elapsed_time` | duration | Minimum elapsed time proven by VDF |
| `previous_hash` | string | Hash of previous checkpoint (chain link) |
| `hash` | string | Hash of this checkpoint |

### VDF Parameters

```json
{
  "vdf_params": {
    "iterations_per_second": 1000000,
    "min_delay_seconds": 60,
    "max_delay_seconds": 3600,
    "calibrated_at": "2026-01-20T12:00:00Z",
    "device_id": "a1b2c3d4e5f6"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `iterations_per_second` | integer | VDF speed on this machine |
| `min_delay_seconds` | integer | Minimum time between checkpoints |
| `max_delay_seconds` | integer | Maximum time per checkpoint |
| `calibrated_at` | timestamp | When VDF was calibrated |
| `device_id` | string | Device identifier for calibration |

### Process Declaration

The declaration is required and follows the Process Declaration Specification:

```json
{
  "declaration": {
    "document_hash": "a3f2b8c9...",
    "chain_hash": "1a2b3c4d...",
    "title": "Research Paper on Climate Modeling",
    "input_modalities": [
      {"type": "keyboard", "percentage": 95.0},
      {"type": "paste", "percentage": 5.0, "note": "Citations"}
    ],
    "ai_tools": [
      {
        "tool": "Claude",
        "purpose": "feedback",
        "extent": "minimal"
      }
    ],
    "collaborators": [],
    "statement": "I declare this document was authored by me with minimal AI assistance for feedback only.",
    "created_at": "2026-01-25T14:30:00Z",
    "version": 1,
    "author_public_key": "mC5qZ3Jk...",
    "signature": "c2lnbmF0..."
  }
}
```

See `specs/process-declaration.md` for complete declaration specification.

### Presence Verification (Standard+)

```json
{
  "presence": {
    "sessions": 5,
    "challenges_issued": 12,
    "challenges_passed": 11,
    "challenges_failed": 1,
    "overall_rate": 0.9167,
    "session_details": [
      {
        "session_id": "abc123",
        "started_at": "2026-01-25T10:00:00Z",
        "challenges": 3,
        "passed": 3
      }
    ]
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `sessions` | integer | Number of tracked sessions |
| `challenges_issued` | integer | Total presence challenges |
| `challenges_passed` | integer | Challenges successfully completed |
| `challenges_failed` | integer | Challenges failed or timed out |
| `overall_rate` | float | Pass rate (0.0-1.0) |
| `session_details` | array | Per-session breakdown |

### Hardware Attestation (Enhanced+)

```json
{
  "hardware": {
    "device_id": "TPM-a1b2c3d4e5f6",
    "bindings": [
      {
        "chain_hash": "f3a4b5c6...",
        "tpm_counter": 42,
        "clock_info": {
          "clock": 123456789,
          "reset_count": 0,
          "restart_count": 5
        },
        "quote": "YXR0ZXN0YXRpb24...",
        "signature": "dHBtc2ln..."
      }
    ]
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `device_id` | string | TPM or secure enclave identifier |
| `bindings` | array | Chain-to-hardware bindings |
| `bindings[].chain_hash` | string | Which chain state is attested |
| `bindings[].tpm_counter` | integer | Monotonic counter value |
| `bindings[].clock_info` | object | TPM clock attestation |
| `bindings[].quote` | string | TPM quote (base64) |
| `bindings[].signature` | string | Quote signature (base64) |

### Keystroke Evidence (Standard+)

The jitter seal evidence proves real keystrokes occurred:

```json
{
  "keystroke": {
    "session_id": "jit-a1b2c3d4",
    "started_at": "2026-01-25T10:00:00Z",
    "ended_at": "2026-01-25T14:30:00Z",
    "duration": "4h30m0s",
    "total_keystrokes": 15000,
    "total_samples": 300,
    "keystrokes_per_minute": 55.56,
    "unique_document_states": 250,
    "chain_valid": true,
    "plausible_human_rate": true,
    "samples": [
      {
        "timestamp": "2026-01-25T10:05:00Z",
        "keystroke_count": 50,
        "document_hash": "a1b2c3...",
        "jitter_micros": 1847,
        "hash": "d4e5f6...",
        "previous_hash": "000000..."
      }
    ]
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | Jitter session identifier |
| `started_at` | timestamp | Session start |
| `ended_at` | timestamp | Session end |
| `duration` | duration | Total session duration |
| `total_keystrokes` | integer | Total keystrokes counted |
| `total_samples` | integer | Number of jitter samples |
| `keystrokes_per_minute` | float | Typing rate |
| `unique_document_states` | integer | Unique document hashes observed |
| `chain_valid` | boolean | Whether sample chain is intact |
| `plausible_human_rate` | boolean | Whether rate is human-like |
| `samples` | array | Jitter sample chain (for verification) |

### Behavioral Evidence (Maximum)

```json
{
  "behavioral": {
    "edit_topology": [
      {
        "start_pct": 0.0,
        "end_pct": 0.15,
        "delta_sign": "insert",
        "byte_count": 500
      },
      {
        "start_pct": 0.45,
        "end_pct": 0.50,
        "delta_sign": "delete",
        "byte_count": 100
      }
    ],
    "metrics": {
      "monotonic_append_ratio": 0.45,
      "edit_entropy": 3.2,
      "median_interval_seconds": 45.5,
      "positive_negative_ratio": 0.72,
      "deletion_clustering": 0.65
    }
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `edit_topology` | array | Where edits occurred (no content) |
| `edit_topology[].start_pct` | float | Edit start position (0.0-1.0) |
| `edit_topology[].end_pct` | float | Edit end position (0.0-1.0) |
| `edit_topology[].delta_sign` | string | Edit type: "replace", "insert", or "delete" |
| `edit_topology[].byte_count` | integer | Bytes affected |
| `metrics` | object | Forensic analysis metrics |

See `specs/behavioral-metrics.md` for metric definitions.

### External Anchors (Maximum)

```json
{
  "external": {
    "proofs": [
      {
        "provider": "opentimestamps",
        "provider_name": "OpenTimestamps",
        "legal_standing": "Proof of existence via Bitcoin blockchain",
        "regions": ["global"],
        "hash": "f3a4b5c6...",
        "timestamp": "2026-01-25T14:35:00Z",
        "status": "confirmed",
        "raw_proof": "T1RTAAJl...",
        "blockchain": {
          "chain": "bitcoin",
          "block_height": 920000,
          "block_hash": "00000000000...",
          "block_time": "2026-01-25T14:45:00Z",
          "tx_id": "a1b2c3d4..."
        },
        "verify_url": "https://opentimestamps.org/verify"
      },
      {
        "provider": "rfc3161",
        "provider_name": "DigiCert TSA",
        "legal_standing": "eIDAS qualified timestamp",
        "regions": ["EU", "US"],
        "hash": "f3a4b5c6...",
        "timestamp": "2026-01-25T14:30:05Z",
        "status": "confirmed",
        "raw_proof": "MIIHxjAD..."
      }
    ],
    "opentimestamps": [],
    "rfc3161": []
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `proofs` | array | Unified anchor proofs (preferred) |
| `proofs[].provider` | string | Provider identifier |
| `proofs[].provider_name` | string | Human-readable provider name |
| `proofs[].legal_standing` | string | Legal status of this proof |
| `proofs[].regions` | array | Jurisdictions with recognition |
| `proofs[].hash` | string | Hash that was anchored |
| `proofs[].timestamp` | timestamp | Anchor timestamp |
| `proofs[].status` | string | pending, confirmed, failed |
| `proofs[].raw_proof` | string | Raw proof data (base64) |
| `proofs[].blockchain` | object | Blockchain details (if applicable) |
| `opentimestamps` | array | Legacy OTS format (deprecated) |
| `rfc3161` | array | Legacy RFC 3161 format (deprecated) |

### Claims

The `claims` array documents what the evidence proves:

```json
{
  "claims": [
    {
      "type": "chain_integrity",
      "description": "Content states form an unbroken cryptographic chain",
      "confidence": "cryptographic"
    },
    {
      "type": "time_elapsed",
      "description": "At least 4h30m elapsed during documented composition",
      "confidence": "cryptographic"
    },
    {
      "type": "process_declared",
      "description": "Author signed declaration of creative process. AI assistance declared: minimal extent",
      "confidence": "attestation"
    },
    {
      "type": "keystrokes_verified",
      "description": "15000 keystrokes recorded over 4h30m (56/min), consistent with human typing",
      "confidence": "cryptographic"
    }
  ]
}
```

| Claim Type | Description | Confidence Level |
|------------|-------------|-----------------|
| `chain_integrity` | Unbroken cryptographic chain | cryptographic |
| `time_elapsed` | VDF-proven minimum time | cryptographic |
| `process_declared` | Signed process attestation | attestation |
| `presence_verified` | Human presence confirmed | cryptographic |
| `keystrokes_verified` | Real typing occurred | cryptographic |
| `hardware_attested` | TPM binding verified | cryptographic |
| `behavior_analyzed` | Edit patterns captured | statistical |
| `external_anchored` | Third-party timestamps | cryptographic |

### Limitations

The `limitations` array documents what the evidence does NOT prove:

```json
{
  "limitations": [
    "Cannot prove cognitive origin of ideas",
    "Cannot prove absence of AI involvement in ideation",
    "No hardware attestation - software-only security"
  ]
}
```

Standard limitations always included:
- "Cannot prove cognitive origin of ideas"
- "Cannot prove absence of AI involvement in ideation"

Conditional limitations:
- No presence: "No presence verification - cannot confirm human was at keyboard"
- No keystroke: "No keystroke evidence - cannot verify real typing occurred"
- No hardware: "No hardware attestation - software-only security"
- AI declared: "Author declares AI tool usage - verify institutional policy compliance"

## Verification Procedure

### Step 1: Parse and Validate Structure

1. Verify JSON is well-formed
2. Check `version` is supported (currently: 1)
3. Verify all required fields are present
4. Validate field types and constraints

### Step 2: Verify Checkpoint Chain

```go
// VerifyCheckpointChain verifies the integrity of a checkpoint chain.
// Returns nil if valid, or an error describing the first failure.
func VerifyCheckpointChain(checkpoints []CheckpointProof, vdfParams vdf.Parameters) error {
    if len(checkpoints) == 0 {
        return errors.New("checkpoint chain is empty")
    }

    var prevHash [32]byte // Zero-initialized (genesis)

    for i, cp := range checkpoints {
        // Verify ordinal sequence is contiguous from 0
        if cp.Ordinal != uint64(i) {
            return fmt.Errorf("checkpoint %d: ordinal mismatch (got %d, expected %d)",
                i, cp.Ordinal, i)
        }

        // Decode previous hash from hex
        var expectedPrevHash [32]byte
        if i == 0 {
            // First checkpoint must reference zero hash
            expectedPrevHash = [32]byte{}
        } else {
            expectedPrevHash = prevHash
        }

        cpPrevHash, err := hex.DecodeString(cp.PreviousHash)
        if err != nil || len(cpPrevHash) != 32 {
            return fmt.Errorf("checkpoint %d: invalid previous_hash encoding", i)
        }

        var prevHashBytes [32]byte
        copy(prevHashBytes[:], cpPrevHash)
        if prevHashBytes != expectedPrevHash {
            return fmt.Errorf("checkpoint %d: broken chain link", i)
        }

        // Recompute and verify checkpoint hash
        computed := computeCheckpointHash(&cp)
        cpHash, err := hex.DecodeString(cp.Hash)
        if err != nil || len(cpHash) != 32 {
            return fmt.Errorf("checkpoint %d: invalid hash encoding", i)
        }

        var hashBytes [32]byte
        copy(hashBytes[:], cpHash)
        if computed != hashBytes {
            return fmt.Errorf("checkpoint %d: hash mismatch", i)
        }

        // Verify VDF proof if present
        if cp.VDFIterations > 0 {
            vdfInput, err := hex.DecodeString(cp.VDFInput)
            if err != nil || len(vdfInput) != 32 {
                return fmt.Errorf("checkpoint %d: invalid vdf_input encoding", i)
            }

            vdfOutput, err := hex.DecodeString(cp.VDFOutput)
            if err != nil || len(vdfOutput) != 32 {
                return fmt.Errorf("checkpoint %d: invalid vdf_output encoding", i)
            }

            var input, output [32]byte
            copy(input[:], vdfInput)
            copy(output[:], vdfOutput)

            proof := &vdf.Proof{
                Input:      input,
                Output:     output,
                Iterations: cp.VDFIterations,
            }

            if !vdf.Verify(proof) {
                return fmt.Errorf("checkpoint %d: VDF verification failed", i)
            }
        }

        // Verify timestamp monotonicity
        if i > 0 && !cp.Timestamp.After(checkpoints[i-1].Timestamp) {
            return fmt.Errorf("checkpoint %d: timestamp not strictly monotonic", i)
        }

        prevHash = computed
    }

    return nil
}

// computeCheckpointHash computes the binding hash for a checkpoint.
func computeCheckpointHash(cp *CheckpointProof) [32]byte {
    h := sha256.New()
    h.Write([]byte("witnessd-checkpoint-v1"))

    var buf [8]byte
    binary.BigEndian.PutUint64(buf[:], cp.Ordinal)
    h.Write(buf[:])

    contentHash, _ := hex.DecodeString(cp.ContentHash)
    h.Write(contentHash)

    binary.BigEndian.PutUint64(buf[:], uint64(cp.ContentSize))
    h.Write(buf[:])

    binary.BigEndian.PutUint64(buf[:], uint64(cp.Timestamp.UnixNano()))
    h.Write(buf[:])

    prevHash, _ := hex.DecodeString(cp.PreviousHash)
    h.Write(prevHash)

    if cp.VDFIterations > 0 {
        vdfInput, _ := hex.DecodeString(cp.VDFInput)
        vdfOutput, _ := hex.DecodeString(cp.VDFOutput)
        h.Write(vdfInput)
        h.Write(vdfOutput)
        binary.BigEndian.PutUint64(buf[:], cp.VDFIterations)
        h.Write(buf[:])
    }

    var result [32]byte
    copy(result[:], h.Sum(nil))
    return result
}
```

### Step 3: Verify Process Declaration

1. Verify declaration `document_hash` matches final checkpoint `content_hash`
2. Verify declaration `chain_hash` matches final checkpoint `hash`
3. Recompute declaration signing payload
4. Verify Ed25519 signature

### Step 4: Verify Optional Components

**Presence:**
- Verify challenge/response hashes if included
- Check pass rate is reasonable (typically ≥ 0.8)

**Keystroke (Jitter Seal):**

```go
// VerifyKeystrokeEvidence verifies jitter seal evidence integrity.
// Note: Full jitter verification requires the HMAC secret, which is
// device-specific. This function verifies structural integrity only.
// For full verification with secret, use VerifyKeystrokeWithSecret.
func VerifyKeystrokeEvidence(ke *KeystrokeEvidence) error {
    if ke.TotalSamples == 0 {
        return errors.New("no jitter samples")
    }

    if len(ke.Samples) == 0 {
        // Samples may be omitted in some export modes
        // Structural validation only
        if !ke.ChainValid {
            return errors.New("chain_valid is false but no samples to verify")
        }
        return nil
    }

    var prevHash [32]byte // Zero for genesis

    for i, sample := range ke.Samples {
        // Verify timestamp monotonicity
        if i > 0 && !sample.Timestamp.After(ke.Samples[i-1].Timestamp) {
            return fmt.Errorf("sample %d: timestamp not strictly monotonic", i)
        }

        // Verify keystroke count monotonicity
        if i > 0 && sample.KeystrokeCount < ke.Samples[i-1].KeystrokeCount {
            return fmt.Errorf("sample %d: keystroke count decreased", i)
        }

        // Verify chain linkage
        sprevHash, err := hex.DecodeString(sample.PreviousHash)
        if err != nil || len(sprevHash) != 32 {
            return fmt.Errorf("sample %d: invalid previous_hash encoding", i)
        }

        var prevHashBytes [32]byte
        copy(prevHashBytes[:], sprevHash)
        if prevHashBytes != prevHash {
            return fmt.Errorf("sample %d: broken chain link", i)
        }

        // Verify sample hash
        computed := computeSampleHash(&sample)
        sampleHash, err := hex.DecodeString(sample.Hash)
        if err != nil || len(sampleHash) != 32 {
            return fmt.Errorf("sample %d: invalid hash encoding", i)
        }

        var hashBytes [32]byte
        copy(hashBytes[:], sampleHash)
        if computed != hashBytes {
            return fmt.Errorf("sample %d: hash mismatch", i)
        }

        prevHash = computed
    }

    // Verify typing rate is human-plausible (10-200 KPM typical)
    if ke.KeystrokesPerMinute > 0 {
        if ke.KeystrokesPerMinute > 300 {
            return fmt.Errorf("typing rate %.1f KPM exceeds human maximum", ke.KeystrokesPerMinute)
        }
    }

    return nil
}

// computeSampleHash computes the binding hash for a jitter sample.
func computeSampleHash(s *JitterSample) [32]byte {
    h := sha256.New()
    h.Write([]byte("witnessd-jitter-sample-v1"))

    var buf [8]byte
    binary.BigEndian.PutUint64(buf[:], uint64(s.Timestamp.UnixNano()))
    h.Write(buf[:])

    binary.BigEndian.PutUint64(buf[:], s.KeystrokeCount)
    h.Write(buf[:])

    docHash, _ := hex.DecodeString(s.DocumentHash)
    h.Write(docHash)

    binary.BigEndian.PutUint32(buf[:4], s.JitterMicros)
    h.Write(buf[:4])

    prevHash, _ := hex.DecodeString(s.PreviousHash)
    h.Write(prevHash)

    var result [32]byte
    copy(result[:], h.Sum(nil))
    return result
}

// VerifyKeystrokeWithSecret performs full jitter verification including
// HMAC-based jitter value verification. This requires the device secret.
func VerifyKeystrokeWithSecret(ke *KeystrokeEvidence, secret [32]byte) error {
    // First do structural verification
    if err := VerifyKeystrokeEvidence(ke); err != nil {
        return err
    }

    if len(ke.Samples) == 0 {
        return errors.New("cannot verify jitter values without samples")
    }

    var prevJitter uint32
    var prevHash [32]byte

    for i, sample := range ke.Samples {
        // Compute expected jitter from HMAC
        h := hmac.New(sha256.New, secret[:])
        h.Write([]byte("jitter-seal-v1"))

        var buf [8]byte
        binary.BigEndian.PutUint64(buf[:], uint64(sample.Timestamp.UnixNano()))
        h.Write(buf[:])

        binary.BigEndian.PutUint64(buf[:], sample.KeystrokeCount)
        h.Write(buf[:])

        docHash, _ := hex.DecodeString(sample.DocumentHash)
        h.Write(docHash)

        binary.BigEndian.PutUint32(buf[:4], prevJitter)
        h.Write(buf[:4])

        h.Write(prevHash[:])

        mac := h.Sum(nil)
        // Jitter = first 4 bytes mod 10000 (0-9999 microseconds)
        expected := binary.BigEndian.Uint32(mac[:4]) % 10000

        if sample.JitterMicros != expected {
            return fmt.Errorf("sample %d: jitter mismatch (got %d, expected %d)",
                i, sample.JitterMicros, expected)
        }

        prevJitter = sample.JitterMicros
        copy(prevHash[:], sample.Hash)
    }

    return nil
}
```

**Hardware:**
- Verify TPM quotes against public EK
- Verify monotonic counter is consistent
- Verify clock info is plausible

**External:**
- For OpenTimestamps: verify OTS proof against Bitcoin blockchain
- For RFC 3161: verify TSR signature against TSA certificate

### Step 5: Generate Verification Report

```json
{
  "verified": true,
  "strength_claimed": 2,
  "strength_verified": 2,
  "checks_passed": [
    "chain_integrity",
    "vdf_proofs",
    "declaration_signature",
    "keystroke_chain"
  ],
  "checks_failed": [],
  "warnings": [
    "Declaration includes AI tool usage"
  ],
  "timestamp": "2026-01-25T15:00:00Z"
}
```

## File Format

### MIME Type

```
application/vnd.witnessd.evidence+json
```

### File Extension

```
.wpkt
```

### Encoding

- UTF-8 encoded JSON
- No BOM
- LF line endings
- Pretty-printed (2-space indent) for readability
- Minified version allowed for transmission

### Compression

Evidence packets MAY be compressed:
- `.wpkt.gz` - gzip compressed
- `.wpkt.zst` - zstd compressed

Verifiers SHOULD support both compressed and uncompressed formats.

### Maximum Size

Recommended limits:
- Uncompressed: 10 MB
- Compressed: 2 MB

These limits accommodate approximately:
- 10,000 checkpoints
- 100,000 jitter samples
- Multiple external anchor proofs

## Examples

### Example 1: Basic Evidence (Tier 1)

```json
{
  "version": 1,
  "exported_at": "2026-01-25T14:30:00Z",
  "strength": 1,
  "document": {
    "title": "Meeting Notes",
    "path": "/home/user/notes/meeting-2026-01-25.md",
    "final_hash": "a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
    "final_size": 2048
  },
  "checkpoints": [
    {
      "ordinal": 0,
      "content_hash": "a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
      "content_size": 2048,
      "timestamp": "2026-01-25T14:00:00Z",
      "message": "Final version",
      "vdf_input": "",
      "vdf_output": "",
      "vdf_iterations": 0,
      "elapsed_time": "0s",
      "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "hash": "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5"
    }
  ],
  "vdf_params": {
    "iterations_per_second": 1000000,
    "min_delay_seconds": 60,
    "max_delay_seconds": 3600,
    "calibrated_at": "2026-01-20T12:00:00Z",
    "device_id": "device-123"
  },
  "chain_hash": "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5",
  "declaration": {
    "document_hash": "a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
    "chain_hash": "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5",
    "title": "Meeting Notes",
    "input_modalities": [{"type": "keyboard", "percentage": 100.0}],
    "ai_tools": [],
    "collaborators": [],
    "statement": "These meeting notes were transcribed by me during the meeting.",
    "created_at": "2026-01-25T14:30:00Z",
    "version": 1,
    "author_public_key": "dGVzdHB1YmxpY2tleQ==",
    "signature": "dGVzdHNpZ25hdHVyZQ=="
  },
  "claims": [
    {
      "type": "chain_integrity",
      "description": "Content states form an unbroken cryptographic chain",
      "confidence": "cryptographic"
    },
    {
      "type": "process_declared",
      "description": "Author signed declaration of creative process. No AI tools declared",
      "confidence": "attestation"
    }
  ],
  "limitations": [
    "Cannot prove cognitive origin of ideas",
    "Cannot prove absence of AI involvement in ideation",
    "No presence verification - cannot confirm human was at keyboard",
    "No keystroke evidence - cannot verify real typing occurred",
    "No hardware attestation - software-only security"
  ]
}
```

### Example 2: Standard Evidence with Keystroke (Tier 2)

See `examples/evidence-standard.wpkt` in the repository.

### Example 3: Maximum Evidence (Tier 4)

See `examples/evidence-maximum.wpkt` in the repository.

## Security Considerations

### Hash Algorithm Agility

Currently SHA-256 is used throughout. If SHA-256 is deprecated:
- Increment packet `version`
- Add explicit `hash_algorithm` field
- Support multiple algorithms during transition

### Signature Algorithm Agility

Currently Ed25519 is used for declarations. If Ed25519 is deprecated:
- Increment declaration `version`
- Add explicit `signature_algorithm` field
- Support multiple algorithms during transition

### Timestamp Precision

- Internal timestamps: nanosecond precision (RFC 3339)
- External anchors: varies by provider
- Clock skew: allow reasonable tolerance (minutes)

### Privacy

Evidence packets may reveal:
- Document titles and paths
- Author public keys (pseudonymous identity)
- Typing patterns and rates
- Collaboration relationships
- AI tool access

For sensitive contexts:
- Redact paths before export
- Use per-document keypairs
- Exclude optional behavioral data
- Consider legal disclosure requirements

## Implementation Notes

### Generating Evidence Packets

```go
// Example: Building a Standard evidence packet
packet, err := evidence.NewBuilder(title, chain).
    WithDeclaration(decl).
    WithKeystroke(jitterEvidence).
    Build()
```

### Verifying Evidence Packets

```go
// Example: Verifying a packet
packet, err := evidence.Decode(data)
if err != nil {
    return err
}

if err := packet.Verify(vdfParams); err != nil {
    return fmt.Errorf("verification failed: %w", err)
}
```

### CLI Usage

```bash
# Export evidence
witnessd export --file document.md --output evidence.wpkt

# Verify evidence
witnessctl verify evidence.wpkt

# Verify with full report
witnessctl verify --verbose evidence.wpkt
```

## References

- Ed25519: RFC 8032
- SHA-256: FIPS 180-4
- JSON Schema: draft-2020-12
- RFC 3339: Date and Time on the Internet
- RFC 3161: Internet X.509 PKI Time-Stamp Protocol
- OpenTimestamps: https://opentimestamps.org
