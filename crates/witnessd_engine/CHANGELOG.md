# Changelog

All notable changes to witnessd_engine will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- IPC server/client architecture for daemon communication
- Async IPC client for non-blocking operations
- Sentinel module refactored into submodules
- Evidence module refactored into submodules
- Key hierarchy module refactored into submodules
- Jitter bridge for witnessd_jitter integration

### Changed
- Wire format aligned with draft-condrey-rats-pop CDDL schema

## [0.1.0] - 2026-02-01

### Added
- Initial release
- Merkle Mountain Range (MMR) for tamper-evident event storage
- Ed25519 signing with domain separation
- VDF-based time proofs with calibration
- Keystroke dynamics behavioral analysis
- TPM 2.0 attestation integration (Linux)
- Secure Enclave support (macOS)
- SQLite-backed persistent storage
- Write-Ahead Log (WAL) and Write-Ahead Recovery (WAR)
- UniFFI bindings for Swift/Kotlin (behind `ffi` feature)
- Platform-specific modules for macOS, Linux, Windows
- Real-time file monitoring via Sentinel
- Blockchain and timestamp anchoring
- Device and author fingerprinting

[Unreleased]: https://github.com/writerslogic/witnessd/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/writerslogic/witnessd/releases/tag/v0.1.0
