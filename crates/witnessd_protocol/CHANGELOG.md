# Changelog

All notable changes to witnessd_protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Wire format aligned with draft-condrey-rats-pop CDDL schema
- CBOR-tagged evidence packets (tag 600) and attestation results (tag 601)
- X.509 certificate-based identity with Proof-of-Possession
- Forensic scoring models (ProcessScore, BehavioralScore)
- Proof-of-Possession (PoP) tests

### Changed
- Migrated from separate repository to witnessd monorepo
- Updated repository URL to monorepo

## [0.1.0] - 2026-02-20

### Added
- Initial crate structure
- CBOR/COSE encoding for PoP packets (RFC 8949, RFC 9052)
- Ed25519 cryptographic primitives
- Protocol models as defined in draft-condrey-rats-pop
- `no_std` support with `std` feature flag
- WASM target support behind `wasm` feature
- Integration with witnessd_jitter for timing evidence

[Unreleased]: https://github.com/writerslogic/witnessd/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/writerslogic/witnessd/releases/tag/v0.1.0
