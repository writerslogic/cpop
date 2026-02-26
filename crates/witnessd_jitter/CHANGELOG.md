# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-02-03

### Added
- **`no_std` support** - Core functionality now works in embedded and WASM environments
  - `std` feature flag controls standard library dependency (enabled by default)
  - Uses `libm` for math operations in `no_std` mode
  - `alloc` crate used for heap allocations when `std` is disabled
- **Sequence numbers for evidence chain integrity**
  - `Evidence` variants now include monotonic sequence numbers
  - `EvidenceChain::validate_sequences()` - Verify sequence continuity
  - `EvidenceChain::validate_timestamps()` - Verify timestamp ordering
  - Sequence numbers included in MAC computation for tamper detection
- **Fuzzing infrastructure** - Four fuzz targets for security testing
  - `fuzz_jitter_compute` - Jitter computation with arbitrary inputs
  - `fuzz_evidence_json` - JSON deserialization fuzzing
  - `fuzz_evidence_verify` - Evidence verification fuzzing
  - `fuzz_human_model` - Human validation model fuzzing
- **Benchmarks** - Criterion benchmarks for performance testing
  - `jitter_computation`, `entropy_sampling`, `evidence_chain`, `human_validation`, `session_workflow`
- **Examples** - Three practical usage examples
  - `basic_session.rs` - Basic session usage
  - `custom_engine.rs` - Custom engine configuration
  - `verify_evidence.rs` - Evidence chain verification
- `Session::with_engine()` - Constructor for custom engine configuration
- `derive_session_secret()` - HKDF-based key derivation helper

### Changed
- Feature flags reorganized for `no_std` compatibility
- `serde_json` and `thiserror` now require `std` feature
- Hardware entropy collection requires `std` feature
- Math operations use platform-independent implementations

### Security
- **Timestamp manipulation prevention** - Sequence numbers prevent replay and reordering attacks
- **Comprehensive fuzzing** - Automated testing for edge cases and malformed inputs

## [0.1.8] - 2026-02-01

### Changed
- Re-added Semgrep with proper token configuration

## [0.1.7] - 2026-02-01

### Changed
- License changed to Apache-2.0 only
- Simplified security workflow

## [0.1.6] - 2026-02-01

### Added
- `rust-version` field in Cargo.toml (MSRV 1.70.0)

## [0.1.5] - 2026-02-01

### Fixed
- Security workflow (generate Cargo.lock, add safety comments for semgrep)

## [0.1.4] - 2026-02-01

### Added
- `deny.toml` configuration for cargo-deny license/security checks

## [0.1.3] - 2026-02-01

### Fixed
- Corrected unsafe badge (unsafe only used with `hardware` feature)

## [0.1.2] - 2026-02-01

### Fixed
- README rendering on crates.io

## [0.1.1] - 2026-02-01

### Added
- Project logo

## [0.1.0] - 2026-02-01

### Added
- `EvidenceChain::with_secret()` - Create keyed evidence chains with HMAC integrity
- `EvidenceChain::verify_integrity()` - Verify chain integrity against session secret
- `Evidence::hash_into()` - Canonical binary hashing for deterministic chain computation
- `Evidence::hash_into_mac()` - HMAC-based canonical hashing for keyed chains
- `HumanModel::validate_iki()` - New method to validate inter-key intervals (IKI fields now used)
- `PureJitter::try_new()` - Fallible constructor with input validation
- `PhysJitter` now has `jmin` and `range` fields for consistent jitter configuration
- Domain separation prefixes (`b"physjitter/v1/jitter"`) in HMAC operations
- `zeroize` dependency for secure secret cleanup
- `subtle` dependency for constant-time comparisons
- Named constants for magic numbers:
  - `MIN_STD_DEV_THRESHOLD`
  - `DEFAULT_JITTER_MIN`
  - `DEFAULT_JITTER_RANGE`
  - `MIN_ENTROPY_SAMPLES`
  - `DEFAULT_MIN_ENTROPY_BITS`
- 20 new test cases including edge cases and security tests

### Changed
- **BREAKING**: `PhysHash` refactored from `[u8; 32]` type alias to struct with `hash` and `entropy_bits` fields
- `Session` now automatically initializes with a keyed evidence chain using the session secret
- `EvidenceChain` now uses HMAC-based chain MAC instead of plain SHA-256 hash when keyed
- Evidence hashing uses stable binary representation instead of JSON serialization
- Evidence verification now uses constant-time comparison via `subtle` crate
- `PhysJitter` API unified with `PureJitter` (both now have `jmin`/`range` configuration)
- `Evidence` and `EvidenceChain` now derive `PartialEq` and `Eq`
- `estimate_entropy()` refactored to use iterators instead of allocating `Vec`
- `PureJitter::new()` now validates that `range > 0` (panics on invalid input)

### Fixed
- **Cryptographic weakness**: Entropy bits no longer overwrite the last byte of SHA-256 hash
  - Hash integrity is now preserved; entropy bits stored as separate metadata
- **Non-deterministic hashing**: Chain hash computation no longer depends on JSON serialization order
  - Replaced with canonical binary representation for reproducible verification
- IKI (inter-key interval) fields in `HumanModel` are now actually used for validation

### Security
- **Keyed tamper detection**: Evidence chains can now be bound to session secrets via HMAC
  - Attackers cannot forge or modify evidence without the secret
- **Domain separation**: All HMAC operations now use context-specific prefixes
  - Prevents key reuse vulnerabilities across different cryptographic operations
- **Constant-time comparisons**: Evidence and chain verification use `subtle::ConstantTimeEq`
  - Mitigates timing side-channel attacks
- **Automatic secret zeroization**: Session secrets wrapped in `Zeroizing<>` for secure cleanup

#### Core Features
- **`Session`** - High-level session manager for tracking jitter evidence
  - `Session::new()` - Create session with provided secret
  - `Session::random()` - Create session with random secret (requires `rand` feature)
  - `Session::sample()` - Sample jitter for input and record evidence
  - `Session::validate()` - Validate session against human typing model
  - `Session::export_json()` - Export evidence chain as JSON

- **`HybridEngine`** - Composite jitter engine with automatic fallback
  - Attempts physics-based entropy first
  - Falls back to pure HMAC jitter in VMs/containers
  - `HybridEngine::sample()` - Returns `(Jitter, Evidence)` tuple
  - `HybridEngine::phys_available()` - Check if hardware entropy is available
  - `HybridEngine::with_min_entropy()` - Configure minimum entropy threshold

- **`PureJitter`** - HMAC-based economic security engine
  - Deterministic jitter computation using HMAC-SHA256
  - Configurable jitter range (default: 500-3000μs)
  - Works everywhere (VMs, containers, WebAssembly)

- **`PhysJitter`** - Hardware entropy-based physics security engine
  - TSC (Time Stamp Counter) sampling on x86_64
  - CNTVCT sampling on aarch64
  - Configurable minimum entropy threshold
  - Automatic entropy estimation

#### Evidence System
- **`Evidence`** - Single evidence record with two variants:
  - `Evidence::Phys` - Physics-bound with hardware entropy hash
  - `Evidence::Pure` - HMAC-based fallback
  - Includes timestamps and verification methods

- **`EvidenceChain`** - Append-only chain with cryptographic integrity
  - Running SHA-256 chain hash
  - Physics/pure ratio tracking
  - Full chain verification support
  - JSON serialization via serde

#### Human Validation
- **`HumanModel`** - Statistical validation based on Aalto 136M keystroke dataset
  - `HumanModel::validate()` - Validate jitter sequence
  - `HumanModel::baseline()` - Load embedded baseline model
  - Configurable parameters for custom models

- **Anomaly Detection**:
  - `PerfectTiming` - Detects identical consecutive values
  - `LowVariance` - Detects unnaturally consistent timing
  - `RepeatingPattern` - Detects periodic patterns
  - `OutOfRange` - Detects values outside human range
  - `DistributionMismatch` - Detects statistical anomalies

#### Traits
- **`EntropySource`** - Trait for entropy collection
  - `sample()` - Collect entropy mixed with inputs
  - `validate()` - Validate entropy meets requirements

- **`JitterEngine`** - Trait for jitter computation
  - `compute_jitter()` - Compute jitter from secret, inputs, and entropy

#### Types
- `PhysHash` - 32-byte SHA-256 hash type alias
- `Jitter` - u32 jitter delay in microseconds
- `Error` - Comprehensive error type with variants:
  - `InsufficientEntropy`
  - `HardwareUnavailable`
  - `InvalidInput`

### Feature Flags
- `default` - Core functionality with pure jitter engine
- `hardware` - Enable TSC/hardware entropy collection
- `rand` - Enable random secret generation

### Documentation
- Comprehensive README with examples
- API documentation for all public items
- Security model documentation
- Architecture diagrams in CONTRIBUTING.md

### Security
- Zero `unsafe` code in main crate
- SLSA Level 3 provenance attestation
- Automated security auditing with `cargo-audit`
- Supply chain security with `cargo-deny`
- Semgrep and CodeQL static analysis in CI

### Dependencies
- `hmac` 0.12 - HMAC computation (RustCrypto)
- `sha2` 0.10 - SHA-256 hashing (RustCrypto)
- `serde` 1.0 - Serialization framework
- `serde_json` 1.0 - JSON support
- `thiserror` 2.0 - Error derive macro
- `getrandom` 0.3 - OS entropy
- `rand` 0.8 (optional) - Random number generation

---

## Version History Summary

| Version | Date | Highlights |
|---------|------|------------|
| 0.2.0 | 2026-02-03 | no_std support, security hardening, fuzzing |
| 0.1.8 | 2026-02-01 | Semgrep with token auth |
| 0.1.7 | 2026-02-01 | Apache-2.0 license, simplified CI |
| 0.1.6 | 2026-02-01 | Add rust-version (MSRV) |
| 0.1.5 | 2026-02-01 | Fix security workflow |
| 0.1.4 | 2026-02-01 | Add cargo-deny configuration |
| 0.1.3 | 2026-02-01 | Fix unsafe badge |
| 0.1.2 | 2026-02-01 | Fix README rendering on crates.io |
| 0.1.1 | 2026-02-01 | Add project logo |
| 0.1.0 | 2026-02-01 | Initial release with dual security models |

---

## Upgrade Guide

### Upgrading from 0.1.x to 0.2.x

**No breaking API changes.** The 0.2.0 release adds new features without breaking existing code:

- `Evidence` variants now include a `sequence` field (backward compatible for deserialization)
- New `validate_timestamps()` and `validate_sequences()` methods on `EvidenceChain`
- New `Session::with_engine()` constructor
- New `derive_session_secret()` helper function

**Feature flag changes:**
- `std` is now an explicit feature (enabled by default)
- To use `no_std`, set `default-features = false`

### Upgrading to 0.1.x

This is the initial release. No upgrade path required.

### Future Breaking Changes

When upgrading between major versions, check this section for migration guides.

---

## Release Verification

All releases include SLSA Level 3 provenance attestations. Verify with:

```bash
slsa-verifier verify-artifact physjitter-<version>.crate \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/writerslogic/physjitter \
  --source-tag v<version>
```

---

## Links

- [GitHub Releases](https://github.com/writerslogic/physjitter/releases)
- [crates.io](https://crates.io/crates/physjitter)
- [Documentation](https://docs.rs/physjitter)

[Unreleased]: https://github.com/writerslogic/physjitter/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/writerslogic/physjitter/releases/tag/v0.2.0
[0.1.0]: https://github.com/writerslogic/physjitter/releases/tag/v0.1.0
