# wld_engine

**wld_engine** is the high-performance cryptographic engine at the heart of the WritersLogic ecosystem. It produces independently verifiable, tamper-evident process evidence constraining when and how a document could have been created.

**License:** Apache-2.0
**Path:** [`crates/wld_engine`](https://github.com/writerslogic/writerslogic/tree/main/crates/wld_engine)

---

## Key Responsibilities

- **Document Checkpointing**: SHA-256 hashing of document state with cryptographic signatures
- **Evidence Generation**: Creating tamper-evident evidence packets with [[Glossary#VDF|VDF]] time proofs
- **Behavioral Analysis**: Keystroke dynamics collection and human/automation classification
- **Real-time Monitoring**: File system watching, change detection, and session management
- **Key Management**: [[Ratchet Key Hierarchy|Ratchet key hierarchy]] with [[Glossary#Key Ratchet|forward secrecy]]
- **Hardware Integration**: [[Glossary#TPM|TPM 2.0]] (Linux), Secure Enclave (macOS), platform-specific APIs
- **IPC**: Daemon-client communication for GUI and CLI frontends

## Architecture

```
wld_engine/src/
├── analysis/       Signal analysis and behavioral metrics
├── anchors/        Blockchain and timestamp anchoring
├── calibration/    VDF calibration for target hardware
├── codec/          CBOR/COSE encoding
├── crypto/         Cryptographic primitives
├── evidence/       Evidence packet export and verification
├── fingerprint/    Device and author fingerprinting
├── forensics/      Authorship analysis and scoring
├── identity/       Identity management (mnemonic, sealed)
├── ipc/            Inter-process communication
├── keyhierarchy/   Ratchet key derivation
├── mmr/            [[Glossary#MMR|Merkle Mountain Range]]
├── physics/        Physical measurements ([[Glossary#PUF|PUF]])
├── platform/       OS-specific code (macOS, Linux, Windows)
├── rfc/            RFC/IETF-compliant types
├── sentinel/       Real-time monitoring and [[Glossary#Sentinel|sessions]]
├── tpm/            TPM 2.0 integration
├── vdf/            Verifiable Delay Functions
├── store.rs        SQLite-backed persistent storage
├── wal.rs          Write-Ahead Log
└── war.rs          Write-Ahead Recovery
```

## Feature Flags

| Feature | Description |
|:--------|:------------|
| `default` | Core library without optional features |
| `wld_jitter` | Hardware entropy via [[wld_jitter]] |
| `secure-enclave` | macOS Secure Enclave support |
| `x11` | X11 focus detection on Linux |
| `ffi` | UniFFI bindings for Swift/Kotlin |

## Usage

```toml
[dependencies]
wld_engine = { git = "https://github.com/writerslogic/writerslogic", branch = "main" }
```

## Dependencies

- **[[wld_protocol]]**: Wire format types and forensic models
- **[[wld_jitter]]** (optional): Hardware timing entropy

## Related Pages

- [[Evidence Format]] - Structure of evidence packets
- [[Process Declaration]] - Declaration lifecycle
- [[Ratchet Key Hierarchy]] - Key derivation protocol
- [[Behavioral Metrics]] - Keystroke dynamics analysis
- [[Persistence & Fault Tolerance]] - WAL, WAR, crash recovery
