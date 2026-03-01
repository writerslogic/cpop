# Changelog

All notable changes to the witnessd project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Monorepo architecture consolidating engine, protocol, jitter, and CLI
- Workspace-level dependency management
- Root-level CI/CD, security workflows, and dependabot configuration
- Comprehensive documentation in `docs/` and `wiki/`
- JSON schemas for evidence, declaration, and WAR block formats
- Man page for `witnessd(1)`

### Changed
- Migrated from separate repositories to unified monorepo
- Updated all crate repository URLs to point to monorepo

## [0.2.0] - 2026-02-22

### Added
- witnessd_protocol crate for PoP wire format (CBOR/COSE)
- witnessd_jitter `no_std` support and security hardening
- Fuzz targets for VDF and protocol components
- Browser extension with native messaging host
- IPC server/client architecture for daemon communication

### Changed
- Wire format aligned with draft-condrey-rats-pop CDDL schema
- Evidence module refactored into submodules
- Key hierarchy module refactored into submodules

## [0.1.0] - 2026-02-01

### Added
- Initial release of witnessd_engine
- Merkle Mountain Range (MMR) for tamper-evident event storage
- Ed25519 signing with domain separation
- VDF-based time proofs
- Keystroke dynamics behavioral analysis
- TPM 2.0 integration (Linux)
- Secure Enclave support (macOS)
- SQLite-backed persistent storage with WAL/WAR
- UniFFI bindings for Swift/Kotlin

[Unreleased]: https://github.com/writerslogic/witnessd/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/writerslogic/witnessd/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/writerslogic/witnessd/releases/tag/v0.1.0
