# Changelog

All notable changes to the CPoE project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.3] - 2026-03-18

### Fixed
- `cpoe export -f cpoe` crash — CBOR export path now builds from secure store
- `cpoe --version` showed `cpop_cli` instead of `cpoe`
- `cpoe export --json` silently ignored — now outputs machine-readable JSON
- `--quiet` and `--json` suppress "Basic tier" warning on stderr
- Jitter bridge tests compile error (missing `Duration` import)
- `MAX_JITTER_INTERVALS` private import from cpoe-protocol 0.1.0
- HTML report copyright: "CPoE, Inc." → "WritersLogic"

### Added
- `verification_url` field in JSON evidence packets
- "How to Verify This Evidence" section in HTML reports
- Verification URL printed after every successful export
- `config set` accepts `yes`/`no`/`1`/`0` for booleans
- Commit warns when checkpoint count < 3 (export minimum)
- `status` suggests `cpoe init` when uninitialized

### Changed
- Product data directory: `~/.writerslogic` → `~/.writersproof`
- Config file: `writerslogic.json` → `writersproof.json`
- Media type: `application/vnd.writersproof.cpoe+cbor` (IANA vendor tree)
- Scoop manifest filename: `writersproof.json`

## [1.0.2] - 2026-03-17

### Changed
- CLI binary renamed from `wld` to `cpoe` across all distribution channels
- Homebrew formula now installs `cpoe` binary (was `wld`)
- install.sh updated for `cpoe` binary name
- Scoop manifest updated for `cpoe.exe` binary name
- `cpoe_jitter` and `cpop_protocol` crates now sourced from crates.io (v0.2.0 and v0.1.0)
- `PoPSigner` trait renamed to `EvidenceSigner` (aligns with cpoe-protocol v0.1.0)
- Package manager update workflow aligned with release workflow (repository dispatch)

### Fixed
- Homebrew workflow pointed to nonexistent `writerslogic-cli` repo
- Scoop manifest had wrong archive naming, binary name, and license
- E2E test assertion for binary file rejection message

## [1.0.1] - 2026-03-16

### Changed
- Removed aarch64-unknown-linux-gnu from release matrix (cross-compilation issues)

## [1.0.0] - 2026-03-15

### Added
- Flattened CLI to 10 top-level commands with interactive menu (`cpoe` with no args)
- `cpoe man` command for full built-in manual
- Shell completions for bash, zsh, fish, elvish, powershell
- `--json` and `--quiet` output modes on all commands
- SHA-256 checksum verification in install.sh
- Version pinning support (`CPoE_VERSION=v1.0.0`) in install.sh
- aarch64-unknown-linux-gnu release target
- Steganography and WritersProof FFI bindings for GUI apps
- 5-band fingerprint comparison verdicts (SameAuthor through DifferentAuthors)
- BackspaceSignature wired into voice fingerprint similarity

### Changed
- Evidence tier validation rejects unknown tiers at entry with actionable error
- Fingerprint `show` returns proper error when no active profile exists
- Voice similarity weights rebalanced to include backspace behavioral signal
- install.sh no longer auto-runs `cpoe init`
- SLSA badge reflects actual build provenance level
- Release pipeline notarizes macOS binaries before packaging

### Security
- SWF crypto: bounds checks on iterations, constant-time byte comparisons via `subtle`
- SWF verification requires index-0 sample in proof
- Mnemonic phrases wrapped in `Zeroizing<String>` throughout identity/PUF paths
- Key files written with 0o600 permissions on Unix (PUF seeds, signing keys)
- CSPRNG failures are now fatal (no silent fallback to zeroed bytes)

### Fixed
- `cpoe verify` format list now includes `.cpoe`
- `cpoe export` tier fallback replaced with validation + clear error
- `cpoe fingerprint show` no longer falls back to nonexistent "default" profile

## [0.3.0] - 2026-03-10

### Added
- Unified CLI: `cpoe <file>` tracks keystrokes, `cpoe <folder>` watches for changes
- Graceful Ctrl+C shutdown in watch mode with `ctrlc` handler
- Atomic file operations (tmp+rename) for identity backup
- PID file locking with stale-PID detection for daemon
- Homebrew tap and Scoop bucket auto-update via CI release pipeline
- Build attestation and SBOM generation in release workflow
- Cross-compilation for 4 targets (Linux x86_64, macOS ARM/x86_64, Windows x86_64)
- Ephemeral checkpoint hash, canary seed, and identity mnemonic FFI bindings

### Changed
- CLI commands reviewed and hardened for production use
- `cpoe verify` now exits with code 1 on verification failure
- Export no longer requires unused `session_id` parameter
- `cpoe identity` (no flags) shows fingerprint + DID + public key
- Monorepo architecture consolidating engine, protocol, jitter, and CLI
- Workspace-level dependency management

### Fixed
- Commit stored message in wrong field (`context_type` instead of `context_note`)
- Log displayed wrong field for checkpoint messages
- File existence checked after `canonicalize` (crashed on missing files)
- Non-regular files (devices, sockets) accepted by track command
- Verify returned exit 0 on verification failure
- Config edit accepted invalid config without re-prompting
- Duplicate `writerslogic` binary target removed (only `cpoe` binary)
- Permission-denied errors in status command now show diagnostic message
- Empty files and oversized files now handled gracefully in commit/watch

### Security
- Anti-forgery hardening: cross-modal consistency checks, forgery cost estimation
- Browser extension: session nonce, monotonic ordinals, rate limiting
- Key zeroization on error paths across engine crate
- Lock unwrap patterns replaced with MutexRecover/RwLockRecover traits
- NaN/Inf guards on all division results

## [0.2.0] - 2026-02-22

### Added
- cpop_protocol crate for PoP wire format (CBOR/COSE)
- cpoe_jitter `no_std` support and security hardening
- Fuzz targets for VDF and protocol components
- Browser extension with native messaging host
- IPC server/client architecture for daemon communication

### Changed
- Wire format aligned with draft-condrey-rats-pop CDDL schema
- Evidence module refactored into submodules
- Key hierarchy module refactored into submodules

## [0.1.0] - 2026-02-01

### Added
- Initial release of cpop_engine
- Merkle Mountain Range (MMR) for tamper-evident event storage
- Ed25519 signing with domain separation
- VDF-based time proofs
- Keystroke dynamics behavioral analysis
- TPM 2.0 integration (Linux)
- Secure Enclave support (macOS)
- SQLite-backed persistent storage with WAL/WAR
- UniFFI bindings for Swift/Kotlin

[Unreleased]: https://github.com/writerslogic/cpoe/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/writerslogic/cpoe/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/writerslogic/cpoe/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/writerslogic/cpoe/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/writerslogic/cpoe/releases/tag/v0.1.0
