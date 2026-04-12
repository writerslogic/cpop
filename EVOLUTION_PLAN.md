# CPoE Engine Evolution Plan

> Generated 2026-03-28 | Baseline: 1024 tests, 0 warnings, 89 open items

## Current State

| Metric | Value |
|--------|-------|
| Source | 85,404 lines across 309 files in 40 modules |
| Tests | 1024 pass, 0 fail, 1 ignored |
| Clippy | 0 warnings |
| Open bugs | 89 (39 HIGH, 50 MEDIUM) |
| Files >800 lines | 12 (split candidates) |
| Unsafe blocks | 155 (platform FFI, expected) |
| Modules audited | 3 of 30 (tpm/, jitter/, ffi/mod.rs) |

## Phase 1: Security Hardening (EH-013 through EH-051)

**Goal**: Zero open HIGH items. Priority: security > correctness > data integrity.

### Wave 1.1: Crypto + Key Material (4 items)
- EH-014 `writersproof/client.rs` -- sign_payload Vec not zeroized
- EH-048 `ethereum.rs` -- key_bytes heap copy not zeroized
- EH-036 `comparison.rs` -- safe_ln(0.0) false similarity
- EH-035 `stats.rs` -- float equality check brittle

### Wave 1.2: Evidence Integrity (7 items)
- EH-024 `evidence/wire_conversion.rs` -- PROFILE_URI non-canonical
- EH-025 `evidence/wire_conversion.rs` -- attestation_tier hardcoded SoftwareOnly
- EH-026 `evidence/rfc_conversion.rs` -- unit mismatch in decibits
- EH-027 `evidence/rfc_conversion.rs` -- CV guard ineffective
- EH-028..EH-031 `evidence/builder/setters.rs` -- various field validation gaps

### Wave 1.3: Store + WAR (6 items)
- EH-017 `store/access_log.rs` -- unknown action falls back to Read/Success
- EH-018 `war/ear.rs` -- overall_status min direction wrong
- EH-019 `war/appraisal.rs` -- integer division masks density
- EH-020 `war/appraisal.rs` -- iat wall clock; replay detection broken
- EH-022 `store/events.rs` -- COUNT scan on every insert
- EH-023 `store/events.rs` -- SQL via format!() not parameterized

### Wave 1.4: Remaining HIGH (22 items)
- EH-015..EH-016 `writersproof/queue.rs` -- replay risk + non-atomic writes
- EH-021 `trust_policy/evaluation.rs` -- stale contribution field
- EH-032..EH-047 -- forensics, analysis, checkpoint, declaration, steganography items
- EH-051 `ffi/evidence.rs` -- device_id zero-filled

**Execution**: 4 `/fix-batch` runs of 10-12 items each, with test verification between runs.

## Phase 2: Medium Severity Cleanup (EM-001 through EM-050)

**Goal**: Zero open MEDIUM items. Priority: correctness > performance > convention.

### Wave 2.1: Math + Statistics (12 items)
- EM-001..EM-007 -- variance, histogram, SNR, perplexity, compression, fingerprint, stats
- EM-031..EM-036 -- cadence clone, comparison magic numbers, forgery cost constants

### Wave 2.2: Evidence + WAR (7 items)
- EM-008..EM-014 -- ethereum, types, streaming, verification, evidence fields

### Wave 2.3: Config + IPC + Store (9 items)
- Config loading, IPC message handling, store access_log, event CSV

### Wave 2.4: FFI + Remaining (22 items)
- FFI ephemeral, checkpoint, crypto, declaration, collaboration, continuation

**Execution**: 4 `/fix-batch` runs. Some items may be false positives; verify before fixing.

## Phase 3: Module Audits

**Goal**: Security audit all 30 modules. This session audited 3; 27 remain.

### Priority Tier 1 (security-critical, audit next)
| Module | Files | Lines | Why |
|--------|-------|-------|-----|
| `crypto/` | 4 | ~800 | Key management, encryption, HMAC |
| `store/` | 8 | ~1500 | SQLite, HMAC integrity, event persistence |
| `sentinel/` | 13 | ~2500 | Keystroke capture, session management |
| `ipc/` | 10 | ~2000 | Unix socket server, encrypted channels |

### Priority Tier 2 (data path, audit after Tier 1)
| Module | Files | Lines | Why |
|--------|-------|-------|-----|
| `evidence/` | 9 | ~2000 | Evidence packet building, wire format |
| `checkpoint/` | 4 | ~1800 | VDF proofs, chain integrity |
| `keyhierarchy/` | 12 | ~2200 | Key derivation, session certificates |
| `verify/` | 1 | ~860 | Evidence verification pipeline |

### Priority Tier 3 (important but lower risk)
| Module | Files | Why |
|--------|-------|-----|
| `forensics/` | 17 | Behavioral analysis (partially audited via todo items) |
| `war/` | 16 | WAR report generation |
| `platform/` | 20 | OS-specific capture (cfg-gated) |
| `sealed_identity/` | 4 | Identity sealing |

### Priority Tier 4 (lower risk, audit last)
- `analysis/`, `anchors/`, `baseline/`, `calibration/`, `config/`, `declaration/`, `fingerprint/`, `mmr/`, `physics/`, `presence/`, `rats/`, `report/`, `research/`, `steganography/`, `trust_policy/`, `vdf/`, `wal/`, `writersproof/`

**Execution**: `/audit-file` on each module's core files, then `/fix-batch` on findings.

## Phase 4: Structural Improvements

### 4.1: File Splits (12 files > 800 lines)
| File | Lines | Split Strategy |
|------|-------|---------------|
| `tpm/secure_enclave.rs` | 1152 | key_mgmt, signing, sealing, attestation |
| `platform/linux.rs` | 1110 | keystroke, mouse, focus, hid |
| `report/pdf/layout.rs` | 1031 | header, body, footer, security_features |
| `checkpoint/chain.rs` | 1023 | chain_ops, vdf_binding, entanglement |
| `ffi/evidence.rs` | 987 | export, checkpoint, c2pa, derivative |
| `sentinel/core.rs` | 929 | lifecycle, event_loop, session_mgmt |
| `fingerprint/activity.rs` | 923 | collection, analysis, persistence |
| `ffi/sentinel.rs` | 902 | start/stop, witnessing, inject |
| `verify/mod.rs` | 856 | packet_verify, chain_verify, forensic_verify |
| `mmr/mmr.rs` | 833 | tree_ops, proof, persistence |
| `engine.rs` | 817 | init, session, export, verify |
| `tpm/windows/provider.rs` | 813 | signing, sealing, quoting, helpers |

**Execution**: `/split-module` on each, starting with highest-coupling files.

### 4.2: Systemic Patterns
- **SYS-033 residual**: 4 files with unzeroized key material on error paths (partially fixed this session)
- **Bridge error types**: `cpoe_jitter_bridge/` uses `String` errors; should migrate to `crate::error::Error`
- **PhysSession restore**: `cpoe-jitter` crate needs `Session::from_json()` for proper session resume

## Phase 5: Release Readiness

### 5.1: macOS App Store
- [ ] A-005: App Store screenshots (5 at required resolutions)
- [ ] A-009: Archive and notarize
- [ ] A-010: TestFlight build
- [ ] Push macOS submodule (5 commits pending)

### 5.2: Engine
- [ ] Run full `cargo test -p cpoe_engine` (not just `--lib`) for integration + doctests
- [ ] `cargo deny check` for license and advisory audit
- [ ] Update MSRV verification (currently 1.75.0)
- [ ] Rebuild FFI static library with `--release` + LTO for production

### 5.3: Documentation
- [ ] Verify `docs/standards-alignment.md` matches current implementation
- [ ] Update API docs for new FFI symbols (48 -> ~52 after this session)
- [ ] Ensure all DST strings documented in one place

## Execution Timeline

| Phase | Items | Estimated Runs | Dependency |
|-------|-------|----------------|------------|
| 1.1-1.2 | 11 HIGH | 1 fix-batch | None |
| 1.3-1.4 | 28 HIGH | 3 fix-batch | None |
| 2.1-2.4 | 50 MEDIUM | 4 fix-batch | After Phase 1 |
| 3 Tier 1 | 4 modules | 4 audit + fix | After Phase 2 |
| 3 Tier 2 | 4 modules | 4 audit + fix | After Tier 1 |
| 4.1 | 12 splits | 12 split-module | After Phase 3 |
| 5 | Release prep | Manual | After Phase 4 |

## Success Criteria

- [ ] 0 open CRITICAL items (achieved)
- [ ] 0 open HIGH items
- [ ] 0 open MEDIUM items
- [ ] All 30 modules audited
- [ ] All files < 800 lines (or documented exceptions)
- [ ] 1024+ tests, 0 failures, 0 clippy warnings maintained
- [ ] macOS app submitted to App Store
