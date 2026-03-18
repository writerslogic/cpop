# CPOP — Unified Todo

## Session State

<!-- UPDATE THIS SECTION AT START AND END OF EVERY SESSION -->

```
ACTIVE_TASKS: [suggest-audit-5]
LAST_UPDATED: 2026-03-18
SESSION_OWNER: suggest-audit
```

### Completed Summary
<!-- Append one-line entries as tasks complete -->
- 2026-03-03: 16 CRITICALs fixed (engine C-011..C-027 except C-014), 28 HIGHs fixed (engine), 6 god-modules split
- 2026-03-03: macOS audit completed (134 issues found, 9 fixed/eliminated)
- 2026-03-04: Windows audit completed (188 issues found)
- 2026-03-04: Consolidated all todo files into single root todo.md
- 2026-03-05: Phase 1+2 batch committed (df5629cc): B-005, B-006, H-126, M-054, SYS-016, SYS-018, SYS-020, H-068, H-076, H-098, H-128, SYS-022, M-123, M-124, M-125, M-126. Tests: 702 pass, 0 fail.
- 2026-03-05: Phase 3 batch: SYS-012 (partial logging), SYS-013, H-074, H-075, H-079, H-080, H-122, H-123, H-125, M-074, M-075. Tests: 705 pass, 0 fail.
- 2026-03-05: Phase 5 (cf2caf28): B-004, H-101, M-062, M-063, M-065, M-066, M-069, M-108, M-120. FFI compiles. 705 pass.
- 2026-03-05: Phase 6 (5644f7de): M-064, M-067, M-068, M-072, M-073, M-076, M-084, M-085, M-086, M-089, M-092, M-094, M-095, M-103, M-105, M-110, M-111, M-116, M-119, M-127, M-139. 707 pass.
- 2026-03-05: Phase 7 (fe54ace2): M-088, M-128, M-129, M-130, M-131, M-144, M-145, M-146, M-147. Triaged: M-053, M-056, M-083, M-087, M-137, M-138. 707 pass.
- 2026-03-05: Phase 8 (6e43d1a3): SYS-015 (50+ named constants), SYS-019 (browser ext validation), H-105, H-106, M-052, M-070, M-071, M-079, M-080, M-081, M-082, M-090, M-091, M-098, M-099, M-102, M-112, M-114, M-115, M-118, M-132, M-135. 707 pass.
- 2026-03-06: Quality audit (ca30939e): Fixed C-025 single-leaf Merkle hash, SYS-013 FFI expect→match, SYS-015 cadence bare literal, browser dead code/unhandled rejections/dangling promises. 707 pass.
- 2026-03-11: Re-audit of 3 crates (cpop_engine, cpop_jitter, cpop_protocol). ~200 files, 15 batches, 3 waves. 5 new HIGH + 4 new MEDIUM found. 730 tests passing.
- 2026-03-11: Code quality / duplication / performance audit. ~200 files, 9 batches, 2 waves. 8 new SYS + 14 HIGH + 42 MEDIUM found.
- 2026-03-12: CLI exhaustive review: 7 bugs fixed (CLI-C1..C3, CLI-H1, CLI-H6, CLI-M11, CLI-M12), 6 false positives eliminated. 15/15 tests pass, 0 clippy warnings.
- 2026-03-12: Engine/protocol dedup batch: M-169 (nonce dedup), M-175 (causality lock dedup), M-176 (CBOR encode generic), M-192 (AIExtent Ord). CLI-L1, CLI-L6 fixed. H-150 resolved via C-032. Tests: 737 engine, 36 protocol, 15 CLI — all pass.
- 2026-03-12: CLI production polish: Added --json (status/list/log/commit), --quiet global flag, `cpop completions` command, binary file type rejection on commit, fixed clap conflicts_with assertion. 13 new tests (28 total). 0 clippy warnings.
- 2026-03-12: Full codebase re-audit (suggest run 4). ~215 files, 15 batches, 3 waves. 3 new CRITICAL + 2 new SYS + 27 new HIGH found. 737 tests passing.
- 2026-03-18: Full workspace audit (suggest run 5). ~100 files across CLI+engine, 9 batches, 2 waves. 5 new CRITICAL + 3 new SYS + 40 new HIGH + 70 new MEDIUM found. Key themes: evidence signature scope gap, IPC DoS, FFI panics (new instances), lock-across-await in sentinel, business logic in FFI boundary, unbounded inputs, silent timestamp clamping.

### Handoff Summary
<!-- Replace this block before ending a session near context limits -->
```
CONTEXT: Full workspace audit complete (2026-03-18). 100 files, 9 batches, 2 waves. Found 5C + 3SYS + 40H + 70M new. Key themes: signature scope gap (C-037), IPC DoS (C-038), sentinel deadlock (C-039), business logic in FFI (SYS-034), unbounded inputs (SYS-035), silent timestamp clamping (SYS-036).
BLOCKERS: None
REMAINING_ENGINE: C-014, C-034..C-041, H-066, H-077, H-135..H-143, H-154..H-220, SYS-024..SYS-036, M-050..M-277
REMAINING_APPS: macOS (9C + 28H + 75M + 7SYS), Windows (6C + 56H + 119M + 7SYS)
KEY_FILES: /Volumes/A/writerslogic/todo.md (this file)
```

---

## Execution Plan — Dependencies & Parallelism

### Dependency Graph

```
Engine Groups (in crates/cpop_engine, apps/cpop_cli, browser-extension):
  Group 4  (time evidence)     ──> no deps, trivial
  Group 5  (hex decode)        ──> no deps, trivial
  Group 17 (deser integrity)   ──> no deps, trivial
  Group 19 (checkpoint tests)  ──> no deps, trivial
  Group 1  (lock recovery)     ──> no deps, mechanical
  Group 2  (key zeroize)       ──> no deps, mechanical
  Group 6  (NaN/Inf guards)    ──> no deps
  Group 3  (wire validation)   ──> no deps
  Group 7  (native msg harden) ──> no deps
  Group 8  (VDF/time safety)   ──> depends on Group 6 (NaN guards)
  Group 9  (FFI compilation)   ──> depends on Group 12 (FFI panics)
  Group 12 (FFI panics)        ──> no deps
  Group 13 (queue errors)      ──> no deps
  Group 10 (browser ext)       ──> no deps
  Group 11 (config/path)       ──> no deps
  Group 14 (forensic cross)    ──> no deps
  Group 15 (TPM signing)       ──> depends on engine crypto infra, large
  Group 16 (named constants)   ──> no deps, mechanical
  Group 18 (IPC hardening)     ──> no deps

macOS app:  independent of engine groups (separate Swift codebase)
Windows app: independent of engine groups (separate C# codebase)
```

### Recommended Execution Order

**Phase 1 — Trivial quick-wins (can all run in parallel via subagents):**
| Subagent | Groups | Est. |
|----------|--------|------|
| A | Engine Group 4 (H-083, H-084 — time evidence) | 10min |
| B | Engine Group 5 (H-085, H-086 — hex decode) | 30min |
| C | Engine Group 17 (H-126, M-054 — deser integrity) | 20min |
| D | Engine Group 19 (B-006 — checkpoint tests) | 15min |
| E | Engine B-005 (rustfmt module path) | 5min |

**Phase 2 — Mechanical security fixes (can all run in parallel):**
| Subagent | Groups | Est. |
|----------|--------|------|
| A | Engine Group 1 (SYS-021 — lock recovery, 82 instances) | 2-3h |
| B | Engine Group 2 (SYS-018 + H-068,H-076,H-089,H-090,H-092 — key zeroize) | 2-3h |
| C | Engine Group 6 (SYS-016 + H-104, M-121 — NaN guards) | 1-2h |
| D | Engine Group 13 (SYS-012 partial — queue errors) | 1-2h |

**Phase 3 — Protocol hardening (can run in parallel):**
| Subagent | Groups | Est. |
|----------|--------|------|
| A | Engine Group 3 (SYS-014, SYS-017, H-082 — wire validation) | 4-5h |
| B | Engine Group 7 (H-113, H-128, SYS-022 residual — native msg) | 1h |
| C | Engine Group 8 (H-122, H-123, H-125 — VDF/time) | 3-4h |
| D | Engine Group 11 (SYS-020, H-069, H-098 — config/path) | 1h |

**Phase 4 — FFI & browser (sequential dependency: 12 before 9):**
| Subagent | Groups | Est. |
|----------|--------|------|
| A | Engine Group 12 (SYS-013, H-074, H-075 — FFI panics) then Group 9 (B-004 — FFI compilation) | 5-6h |
| B | Engine Group 10 (SYS-019, H-105, H-106 — browser ext) | 4-6h |
| C | Engine Group 14 (M-123..M-126 — forensic cross-modal) | 1h |

**Phase 5 — Large items & polish:**
- Engine Group 15 (C-014, H-066 — TPM signing): 3-5 days, Windows-specific
- Engine Group 16 (SYS-015 — named constants): 2-4h, mechanical
- Engine Group 18 (H-079, H-080, M-074, M-075 — IPC hardening): 2h

**macOS & Windows — run independently at any phase:**
- macOS quick-wins: trivial items listed in macOS section
- Windows quick-wins: trivial items listed in Windows section
- These are in separate submodule repos and can be worked in parallel with all engine work

---

## Engine — Systemic Issues

- [x] **SYS-012** `silent_error_swallow` — 20+ files — HIGH (sentinel/IPC logging added)
  <!-- pid:silent_error_swallow | verified:true | first:2026-03-02 -->
  Silent error swallowing: `.unwrap_or_default()`, `.ok()`, `let _ = ...` on I/O and crypto operations.
  Key files: `forensics/analysis.rs:50`, `ipc/server.rs:87,102`, `writersproof/queue.rs:90,127`, `ffi/system.rs:119,212`, `ffi/ephemeral.rs:464,887`, `sentinel/core.rs:164,398`, `browser-ext/background.js`, `research/collector.rs:162`, `research/helpers.rs:121,211-212`, `config/defaults.rs:18,24,33,76,115,141`
  Fix: Add `log::warn!()` before error-swallowing. For crypto/IO, propagate Result.

- [x] **SYS-013** `panic_in_ffi` — 5 files — CRITICAL
  <!-- pid:panic_in_library | verified:true | first:2026-03-02 | revalidated:2026-03-03 -->
  `expect()`/`.unwrap()` in FFI boundary code. Swift/Kotlin callers cannot recover.
  Files: `ffi/fingerprint.rs:35`, `ffi/sentinel.rs:26`, `ffi/evidence.rs:179,188,189,218`, `ffi/ephemeral.rs:342,372`
  Fix: Replace with `Result`-returning wrappers mapped to `FfiResult`.

- [x] **SYS-014** `unbounded_deser` — 8+ wire type files — HIGH
  <!-- pid:unbounded_vec_deser | verified:true | first:2026-03-02 -->
  Vec fields in wire types have no size limits. DoS via memory exhaustion.
  Files: `rfc/wire_types/packet.rs:61`, `checkpoint.rs:82`, `components.rs:156,176`, `attestation.rs:105,232`, `protocol/codec.rs:20`
  Fix: Add serde size limits or post-decode validation.

- [x] **SYS-015** `magic_constants` — 15+ files — MEDIUM (50+ constants extracted across 12 files)
  <!-- pid:magic_value | verified:true | first:2026-03-02 -->
  Hardcoded thresholds without named constants.
  Fix: Extract to named `const` with doc comments.

- [x] **SYS-016** `nan_inf_unguarded` — 5 files — HIGH
  <!-- pid:fp_division_unguarded | verified:true | first:2026-03-02 | revalidated:2026-03-03 -->
  Division results not checked for NaN/Infinity.
  Actionable files: `forensics/comparison.rs:54`, `rfc/jitter_binding.rs:546`, `analysis/behavioral_fingerprint.rs:207`, `evidence/builder.rs:571`, `protocol/forensics/engine.rs:217`
  Fix: Add `.is_finite()` guard after divisions.

- [x] **SYS-017** `missing_wire_validation` — 5+ files — HIGH
  <!-- pid:missing_validation | verified:true | first:2026-03-02 -->
  Wire types deserialized without post-decode validation.
  Files: `rfc/wire_types/packet.rs:41,92`, `checkpoint.rs:33`, `mod.rs:37`
  Fix: Implement `validate()` trait, call after deserialization.

- [x] **SYS-018** `key_zeroize_error_path` — 7+ files — HIGH
  <!-- pid:key_material_error_path_leak | verified:true | first:2026-03-02 | revalidated:2026-03-03 -->
  Key material not zeroized on error paths.
  Files: `keyhierarchy/session.rs:43,129,367`, `keyhierarchy/recovery.rs:122,165`, `keyhierarchy/puf.rs:74`, `tpm/secure_enclave.rs:542`, `ffi/helpers.rs:27`, `ffi/ephemeral.rs:794`, `identity/secure_storage.rs:39,103,302`
  Fix: Use `Zeroizing<Vec<u8>>` or scope guards.

- [x] **SYS-019** `browser_ext_unvalidated_messages` — 3 files — HIGH (message validation added to all 3 files)
  <!-- pid:security-message_origin_bypass | verified:true | first:2026-03-02 -->
  Browser extension message handlers accept from any origin.
  Files: `background.js:478`, `content.js:280`, `popup.js:262`
  Fix: Validate `sender.id` and `sender.url`.

- [x] **SYS-020** `insecure_path_fallback` — 4 files — HIGH
  <!-- pid:world_writable_fallback | verified:true | first:2026-03-02 -->
  HOME dir resolution falls back to relative paths or /tmp.
  Files: `config/types.rs:245`, `config/defaults.rs:18,24,33,76,115,141`, `writersproof/queue.rs:37`, `tpm/secure_enclave.rs:1101`
  Fix: Fail if HOME unset. Never default to /tmp.

- [x] **SYS-021** `lock_unwrap` — 82 instances, 10 files — HIGH
  <!-- pid:lock_unwrap | verified:true | first:2026-03-03 -->
  Bare `.lock().unwrap()` without poison recovery. `MutexRecover`/`RwLockRecover` traits exist but unused in these files.
  Files: `engine.rs` (14), `sentinel/helpers.rs` (17), `tpm/secure_enclave.rs` (15), `tpm/linux.rs` (8), `wal/operations.rs` (8), `sentinel/shadow.rs` (7), `sentinel/core.rs` (4), `sentinel/focus.rs` (2), `tpm/software.rs` (2), `tpm/windows.rs` (1)
  Fix: Replace with `.lock_recover()` etc. Mechanical.

- [x] **SYS-022** `commitment_chain_optional` — 2 files — CRITICAL
  <!-- pid:security-optional_security | verified:true | first:2026-03-03 -->
  Commitment chain fields are `Option` with `#[serde(default)]`. Adversary omits to bypass.
  Files: `apps/cpop_cli/src/native_messaging_host.rs:337,394`, `browser-extension/background.js:89`
  Fix: Make required after genesis checkpoint.

- [x] **SYS-023** `forensic_region_stub` — 2 files — CRITICAL (fixed by C-024 cursor heuristic)
  <!-- pid:stub_implementation | verified:true | first:2026-03-03 -->
  Edit regions hardcoded to `(1.0, 1.0)`, destroying topology analysis.
  Files: `forensics/engine.rs:57-82`, `forensics/topology.rs`
  Fix: Implement real region extraction from edit deltas.

### Code Quality Systemic (2026-03-11)

- [x] **SYS-024** `anchor_http_duplication` — 6 files — HIGH
  <!-- pid:duplicated_logic | verified:true | first:2026-03-11 -->
  HTTP client / JSON-RPC / request-building pattern duplicated across all anchor providers and WritersProof client.
  Files: `anchors/ethereum.rs:117`, `anchors/bitcoin.rs:51`, `anchors/rfc3161.rs:27`, `anchors/ots.rs:232`, `anchors/notary.rs:29`, `writersproof/client.rs:40`
  Fix: Extract shared `JsonRpcClient` trait and `fn send_authenticated_request()` helper. Effort: medium

- [x] **SYS-025** `serde_helper_duplication` — 5+ files — HIGH
  <!-- pid:duplicated_logic | verified:true | first:2026-03-11 -->
  Identical hex/base64 serde modules duplicated across crate boundaries.
  Files: `rfc/serde_helpers.rs` (120L), `rfc/wire_types/serde_helpers.rs` (104L), `evidence/serde_helpers.rs` (62L), `protocol/baseline.rs:123` (serde_bytes_opt), `anchors/types.rs:148,171,191` (3 near-identical modules)
  Fix: Consolidate into single `crate::serde_utils` module; re-export where needed. Effort: small

- [x] **SYS-026** `sentinel_ipc_code_duplication` — 8+ sites — HIGH
  <!-- pid:duplicated_logic | verified:true | first:2026-03-11 -->
  Duplicated patterns across sentinel/IPC subsystems:
  - WAL append logic repeated 3x in `sentinel/helpers.rs` (lines 134, 222, and focus_document_sync)
  - Send/recv frame logic in `ipc/async_client.rs` + `ipc/sync_client.rs` (identical protocol)
  - AX query pattern duplicated in `sentinel/macos_focus.rs` (get_document_path + get_window_title)
  - Daemon setup duplicated in `sentinel/daemon.rs` (cmd_start + cmd_start_foreground)
  - IPC path validation lists duplicated for Unix/Windows in `ipc/messages.rs:38,64`
  Fix: Extract `wal_append_session_event()`, `IpcTransport` trait, `query_ax_attribute()`, `setup_daemon_common()`. Effort: medium

- [x] **SYS-027** `double_iteration_patterns` — 6+ files — MEDIUM
  <!-- pid:collect_then_iter | verified:true | first:2026-03-11 -->
  Collections iterated multiple times where a single pass suffices.
  Files: `forensics/velocity.rs:23` (clone+sort 2x), `forensics/analysis.rs:53` (sort 2x), `presence/verifier.rs:70` (count 2x), `fingerprint/activity.rs:326` (3 passes in from_samples), `evidence/packet.rs:299` (count+hash), `c2pa.rs:623` (count+contains)
  Fix: Consolidate into single-pass accumulators. Effort: small per-file

- [x] **SYS-028** `war_profile_duplication` — 2 files — HIGH
  <!-- pid:duplicated_logic | verified:true | first:2026-03-11 -->
  WAR trust vector mapping, attestation tier derivation, and EAR data preparation duplicated between VC and C2PA profiles.
  Files: `war/profiles/vc.rs:96,125`, `war/profiles/c2pa.rs:86,129,134`
  Fix: Extract `TrustVectorSerialized` struct, `tier_from_trust_vector()`, `prepare_ear_attestation_data()`. Effort: small

- [x] **SYS-029** `histogram_stats_scattered` — 4+ files — MEDIUM
  <!-- pid:duplicated_logic | verified:true | first:2026-03-11 -->
  Histogram normalization, cosine similarity, percentile computation, and merge utilities defined independently in fingerprint and jitter modules.
  Files: `fingerprint/activity.rs:751` (normalize/merge), `jitter/profile.rs:100` (cosine similarity), `fingerprint/voice.rs:432` (bhattacharyya with f32→f64 alloc), `evidence/builder.rs:551` (5x select_nth_unstable)
  Fix: Consolidate into `analysis::stats` module with `normalize_histogram()`, `histogram_similarity()`, `compute_percentiles()`. Effort: medium

- [x] **SYS-030** `config_defaults_boilerplate` — 2 files — MEDIUM
  <!-- pid:duplicated_logic | verified:true | first:2026-03-11 -->
  168 lines of trivial `default_*()` functions in `config/defaults.rs`, each duplicated via `impl Default` in `config/types.rs` (7 structs, ~70 lines of boilerplate).
  Fix: Use `#[serde(default = "fn")]` on fields directly; eliminate manual `impl Default` blocks. Effort: small

- [x] **SYS-031** `platform_enumerate_duplication` — 3+ files — MEDIUM

### Residual Systemic (2026-03-12)

- [x] **SYS-032** `nan_inf_residual` — 6+ files — HIGH
  <!-- pid:nan_inf_residual | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Residual NaN/Inf-unguarded patterns missed by original SYS-016 fix.
  Files: `platform/linux.rs:859`, `platform/synthetic.rs:115`, `rfc/biology.rs:558,364,370`, `forensics/cross_modal.rs:310`
  Fix: Apply `.is_finite()` guards and division-by-zero checks at each site

- [ ] **SYS-033** `key_zeroize_residual` — 4+ files — CRITICAL
  <!-- pid:key_zeroize_residual | verified:true | first:2026-03-12 | last:2026-03-18 -->
  Residual key material zeroization gaps missed by original SYS-018 fix.
  Files: `ffi/system.rs:33`, `ffi/ephemeral.rs:576`, `sealed_identity/store.rs:236`, `identity/secure_storage.rs:358`
  Additional (2026-03-18): `ipc/secure_channel.rs:79` (plaintext not zeroized on encode error), `identity/secure_storage.rs:366` (cache clone bypasses mlock), `sealed_identity/store.rs:224` (old blob not zeroized on reseal error)
  Fix: Wrap seed/key data in `Zeroizing<Vec<u8>>` or `Zeroizing<[u8; 32]>` at each site

### Audit Run 5 Systemic (2026-03-18)

- [ ] **SYS-034** `logic_in_boundary` — 6+ files — HIGH
  <!-- pid:logic_in_boundary | verified:true | first:2026-03-18 | last:2026-03-18 -->
  Business logic in FFI/CLI handler layer instead of core engine.
  Files: `ffi/evidence.rs:165` (50-line checkpoint conversion), `ffi/evidence.rs:558` (C2PA decode), `ffi/system.rs:166` (forensics analysis), `ffi/helpers.rs:140` (streak calculation), `cmd_export.rs:441` (100+ line packet building), `cmd_export.rs:556` (checkpoint JSON construction)
  Fix: Extract to engine traits (SecureEventExt, ForensicEngine::metrics_ffi, ActivityAnalytics::compute_streaks). FFI/CLI become thin wrappers. Effort: large

- [ ] **SYS-035** `no_size_limit` — 5+ files — HIGH
  <!-- pid:no_size_limit | verified:true | first:2026-03-18 | last:2026-03-18 -->
  Unbounded file/input reads in security-critical code paths. DoS vector.
  Files: `ffi/evidence.rs:351` (hash_file no size limit), `ffi/helpers.rs:34` (signing key read), `ffi/attestation.rs:99` (base64 decode), `sealed_identity/store.rs:407` (hostname in HKDF salt), `identity/secure_storage.rs:445` (machine ID unbounded), `sealed_chain.rs:87` (JSON serialize no quota)
  Fix: Add size bounds before reads. `metadata().len() < MAX` checks. Effort: small per-file

- [x] **SYS-036** `silent_timestamp_clamp` — 3 files — HIGH (partially fixed)
  <!-- pid:silent_timestamp_clamp | verified:true | first:2026-03-18 | last:2026-03-18 -->
  Fixed: `ffi/ephemeral.rs:80` (log::warn before 0), `engine.rs:498` (same), `calibration/transport.rs:65` (warn on negative)
  Remaining: `transcription.rs:121`, `native_messaging_host.rs:194` — lower priority, same pattern
  <!-- pid:duplicated_logic | verified:true | first:2026-03-11 -->
  Platform device enumeration and virtual device checking logic duplicated.
  Files: `platform/linux.rs:694` (enumerate_keyboards ≈ enumerate_mice, 70+ lines each), `platform/linux.rs:200` (is_virtual_device ≈ is_virtual_mouse), `platform/windows.rs:155` (6 global statics for overlapping capture types)
  Fix: Extract `enumerate_input_devices(filter)`, `is_virtual_device_name()`. Effort: small

---

## Engine — Build Issues

- [x] **B-004** FFI feature compilation — multiple errors
  <!-- pid:build_failure | verified:true | first:2026-03-03 -->
  `cargo check --features ffi -p cpop_engine` fails. Missing `ENTROPY_NORMALIZATION_FACTOR`, mismatched `FfiFingerprintStatus` fields.
  Fix: Align FFI types with current engine types. Effort: large

- [x] **B-005** rustfmt failure — module path mismatch
  <!-- pid:build_failure | verified:true | first:2026-03-03 -->
  `lib.rs:51` declares `pub mod cpop_jitter_bridge;` but directory is `writerslogic_jitter_bridge/`.
  Fix: `git mv` directory to `cpop_jitter_bridge/`. Effort: small

- [x] **B-006** 2 pre-existing checkpoint test failures
  <!-- pid:test_failure | verified:true | first:2026-03-03 -->
  `test_entangled_commit_with_physics_context` and `test_entangled_commit_mixed_physics_and_none` — "unsigned (signature required by policy)".
  Fix: Supply signing key in test setup. Effort: medium

---

## Engine — Critical (4 open, 6 spec-conformance fixed 2026-03-12)

- [ ] **C-014** `[security]` `tpm/windows.rs:536-546` — sign_payload uses SHA256 not TPM2_Sign
  <!-- pid:sec_no_real_signing | verified:true | first:2026-03-02 | revalidated:2026-03-03 -->
  Hardware trust boundary violated. Fix: Implement TPM2_Sign. Effort: large

- [x] **C-034** `[error_handling]` `tpm/windows/provider.rs:587,589` + `tpm/windows/commands.rs:90` — `TPMError::CommunicationError` variant does not exist in enum
  <!-- pid:missing_enum_variant | batch:5 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Windows TPM module fails to compile — 3 call sites use nonexistent variant | Fix: Add `CommunicationError(String)` to `TPMError` enum in `tpm/types.rs`, or replace with `Quote(e.to_string())` | Effort: small

- [x] **C-035** `[security]` `ffi/system.rs:33` — Seed array `[u8; 32]` not zeroized after `SigningKey::from_bytes()`
  <!-- pid:key_zeroize_residual | batch:10 | verified:true | first:2026-03-12 | last:2026-03-12 | status:already-fixed -->
  Already fixed in code: `seed.zeroize()` at line 44.

- [x] **C-036** `[security]` `ffi/ephemeral.rs:576` — Key data read from disk not zeroized after use
  <!-- pid:key_zeroize_residual | batch:10 | verified:true | first:2026-03-12 | last:2026-03-12 | status:already-fixed -->
  Already fixed in code: `zeroize::Zeroizing::new()` wrapper at line 577.

- [ ] **C-037** `[security]` `evidence/packet.rs:300` — Evidence signature does not cover behavioral fields (DESIGN — requires protocol-level decision)
  <!-- pid:sec_signature_scope | verified:true | first:2026-03-18 | last:2026-03-18 -->
  `content_hash()` excludes behavioral evidence, keystroke metrics, jitter data, hardware attestation, and forensic analysis. Attacker can strip those fields without invalidating signature.
  Impact: Partial evidence packets remain cryptographically valid. Enables evidence tampering by selective field removal.
  Fix: Extend `content_hash()` to include all evidence fields or delegate to full `hash()`. Effort: large

- [ ] **C-038** `[security]` `ipc/server.rs:97` — IPC server allocates 1MB per message before validation
  <!-- pid:sec_ipc_dos | verified:true | first:2026-03-18 | last:2026-03-18 -->
  Message size check uses MAX_MESSAGE_SIZE (1MB) but deserialization is not bounded. Attacker sends MAX_MESSAGE_SIZE frames with invalid format; 100 connections = 100MB RAM.
  Impact: DoS via memory exhaustion on IPC server.
  Fix: Validate message structure before full allocation; use streaming deserialization or size-gated buffer pool. Effort: medium

- [-] **C-039** `[concurrency]` `sentinel/core.rs:324` — RwLock write held across .await in keystroke hot path
  <!-- pid:lock_held_await | verified:true | first:2026-03-18 | last:2026-03-18 -->
  `voice_collector.write_recover()` held while processing keystroke. Violates Tokio safety. Potential deadlock in async context.
  Impact: Runtime deadlock if future is suspended with lock held.
  Fix: Extract voice_collector mutation into synchronous scope; snapshot values, release lock, then process. Effort: medium

- [-] **C-040** `[error_handling]` `cpop_jitter_bridge/session.rs:285` — ~~verify_chain() result discarded~~ FALSE POSITIVE
  <!-- pid:error_status_ignored | verified:false | first:2026-03-18 | last:2026-03-18 -->
  Code correctly sets `chain_valid: self.verify_chain().is_ok()` — the boolean field accurately reflects chain validity.

- [-] **C-041** `[error_handling]` `engine.rs:401` — ~~add_secure_event() error causes evidence loss~~ FALSE POSITIVE
  <!-- pid:evidence_loss | verified:false | first:2026-03-18 | last:2026-03-18 -->
  Error IS propagated via `?` operator. Caller handles the error.

- [x] **C-028** `[spec]` Evidence Packet profile URI wrong — uses EAT URI instead of PoP URI
  <!-- pid:spec_profile_uri | verified:true | first:2026-03-12 -->
  Code: `"urn:ietf:params:rats:eat:profile:pop:1.0"` (EAT/WAR profile).
  Spec: `"urn:ietf:params:pop:profile:1.0"` (Evidence profile, §6.5).
  Files: `spec.rs:6`, `wire_conversion.rs:20`, `packet.rs:308/318/328`, `evidence.rs:43/219`, `ffi/evidence.rs:235/598`, plus test files.
  Fix: Replace all Evidence Packet URIs; keep EAT URI only for WAR/attestation-result. Effort: small

- [x] **C-029** `[spec]` Argon2id salt derivation doesn't match spec
  <!-- pid:spec_argon2_salt | verified:true | first:2026-03-12 -->
  Code (`swf_argon2.rs:83-85`): `salt = i.to_be_bytes() || current[..8]` (custom 16-byte).
  Spec (§7.1): `salt_0 = H(0x00 || "PoP-salt-v1" || seed)`, `salt_i = H(0x01 || "PoP-salt-v1" || I2OSP(i, 4))`.
  Fix: Derive 32-byte spec-conformant salts via SHA-256 with DST prefix. Effort: small

- [x] **C-030** `[spec]` Fiat-Shamir challenge derivation doesn't match spec
  <!-- pid:spec_fiat_shamir | verified:true | first:2026-03-12 -->
  Code (`swf_argon2.rs:207-213`): DST `"witnessd-fiat-shamir-v1"`, wrong field order, missing proof-params/algorithm, iterated SHA-256 for index selection.
  Spec (§7.3): DST `"PoP-Fiat-Shamir-v1"`, includes `I2OSP(proof-algorithm, 2) || CBOR-encode(proof-params) || input || merkle_root`, uses HKDF-Expand for index derivation.
  Fix: Rewrite `fiat_shamir_challenge()` and `select_indices()` per spec. Effort: medium

- [x] **C-031** `[spec]` HKDF key derivation missing two-stage hierarchy (already resolved)
  <!-- pid:spec_hkdf_hierarchy | verified:true | first:2026-03-12 -->
  Code (`crypto.rs:121-146`): Single-stage `HKDF::from_prk(merkle_root)` with info `"PoP-jitter-seal"` / `"PoP-entangled-mac"`.
  Spec (§7.6): Two-stage: `PRK = HKDF-Extract(salt="PoP-key-derivation-v1", IKM=merkle_root || input)`, then `HKDF-Expand(PRK, "PoP-jitter-tag-v1", hash_len)` / `HKDF-Expand(PRK, "PoP-entangled-binding-v1", hash_len)`.
  Fix: Add HKDF-Extract stage, update info strings, pass `process-proof.input` to both functions. Effort: small

- [x] **C-032** `[spec]` Merkle tree construction lacks tagged hashing (already resolved)
  <!-- pid:spec_merkle_tagged | verified:true | first:2026-03-12 -->
  Code (`swf_argon2.rs:244-268`): No tag prefixes; leaves stored directly; internals `H(left || right)`; padding repeats last leaf.
  Spec (§7.4): Leaf = `H(0x00 || state_i)`, Internal = `H(0x01 || left || right)`, Pad = `H(0x02 || I2OSP(steps+1, 4))`.
  Fix: Add 0x00/0x01/0x02 prefix tags in `build_merkle_tree()`, `merkle_proof()`, `verify_merkle_proof()`. Effort: medium

- [x] **C-033** `[spec]` Checkpoint hash computation differs from spec
  <!-- pid:spec_checkpoint_hash | verified:true | first:2026-03-12 -->
  Code (`checkpoint.rs:134-157`): `H("PoP-Checkpoint-v1" || CBOR-encode(checkpoint \ {key 8}))` — hashes whole map.
  Spec (§6.6): `H("PoP-Checkpoint-v1" || prev-hash || content-hash || CBOR-encode(edit-delta) || CBOR-encode(jitter-binding) || CBOR-encode(physical-state) || merkle-root)` — individual field concatenation.
  Fix: Rewrite `compute_hash()` to concatenate individual fields per spec. Effort: medium

<details><summary>Engine Critical — Fixed (16)</summary>

- [x] **C-011** tpm/software.rs:28 — Weak RNG seed (getrandom fix)
- [x] **C-012** tpm/software.rs:31 — Seed not zeroized (Zeroizing wrapper)
- [x] **C-013** tpm/windows.rs:409 — Windows TPM public_key random bytes (SRK via TPM2_CreatePrimary)
- [x] **C-015** background.js:212 — XSS via native host errors (textContent)
- [x] **C-016** background.js:173 — ECDH handshake replay (one-shot resolver)
- [x] **C-017** secure-channel.js:289 — Unguarded JSON.parse (try-catch)
- [x] **C-018** background.js:478 — Message origin bypass (sender.id check)
- [x] **C-019** content.js:112 — OOM before truncation (early-exit accumulation)
- [x] **C-020** pink_noise.rs:182 — O(n^2) DFT (Cooley-Tukey FFT)
- [x] **C-021** wal/types.rs:119 — byte_count i64/u64 mismatch (changed to u64)
- [x] **C-022** ffi/forensics.rs:74 — Wrong assessment score formula
- [x] **C-023** ffi/forensics.rs:151 — Inverted sequence score
- [x] **C-024** forensics/engine.rs:57 — Hardcoded edit regions (cursor heuristic)
- [x] **C-025** vdf/aggregation.rs:274 — Merkle root is format string (SHA-256)
- [x] **C-026** native_messaging_host.rs:362 — Evidence file truncation (append mode)
- [x] **C-027** native_messaging_host.rs:337 — Commitment chain bypass (mandatory enforcement)
</details>

---

## Engine — High (78 open + 40 new from run 5)

### Audit Run 5 — HIGH (2026-03-18)

- [x] **H-181** `[security]` `sentinel/core.rs:155` — SigningKey set without validation
  <!-- pid:missing_validation | first:2026-03-18 -->
  No length/format check on raw SigningKey. Malformed key causes silent failures downstream. Effort: small

- [-] **H-182** `[concurrency]` `sentinel/core.rs:334` — Mouse idle stats RwLock write held across .await
  <!-- pid:lock_held_await | first:2026-03-18 -->
  Mouse event processing may hold write lock across async boundary. Effort: medium

- [ ] **H-183** `[concurrency]` `sentinel/helpers.rs:116` — Lock held across file hashing in focus_document_sync
  <!-- pid:lock_held_during_io | first:2026-03-18 -->
  sessions.write_recover() held for entire function including compute_file_hash + WAL append. Effort: medium

- [x] **H-184** `[error_handling]` `sentinel/helpers.rs:132` — Silent WAL append failure — FIXED: upgraded to log::error
  <!-- pid:silent_error_swallow | first:2026-03-18 -->

- [x] **H-185** `[concurrency]` `sentinel/helpers.rs:227` — Lock drop + re-acquire race (TOCTOU)
  <!-- pid:toctou | first:2026-03-18 -->
  sessions_map dropped then end_session_sync() re-acquires. Another thread could insert between. Effort: small

- [x] **H-186** `[error_handling]` `sentinel/core.rs:522` — WAL::open() failure continues session without persistent proof
  <!-- pid:silent_error_swallow | first:2026-03-18 -->
  Evidence loss if WAL init fails. No fallback or user notification. Effort: medium

- [ ] **H-187** `[concurrency]` `sentinel/core.rs:369` — Focus event blocks all other events in select! loop
  <!-- pid:lock_contention | first:2026-03-18 -->
  Slow focus event (file hashing) blocks keystroke/mouse/idle processing. Effort: large

- [x] **H-188** `[security]` `ipc/messages.rs:54` — Windows path validation bypassed by UNC paths
  <!-- pid:path_traversal | first:2026-03-18 -->
  Hardcoded prefix checks don't catch `\\?\C:\Windows` or UNC paths. Effort: medium

- [ ] **H-189** `[concurrency]` `sentinel/daemon.rs:181` — PID file lock race (two daemons can start)
  <!-- pid:toctou | first:2026-03-18 -->
  Race between read+remove+create. Use flock(2) or atomic create+lock. Effort: medium

- [x] **H-190** `[security]` `sentinel/helpers.rs:407` — Windows path validation missing
  <!-- pid:path_traversal | first:2026-03-18 -->
  Parent directory validation only runs on Unix. Windows has no equivalent check. Effort: small

- [x] **H-191** `[security]` `war/appraisal.rs:118` — Hardware attestation falsely affirmed with empty data
  <!-- pid:validation_gap | first:2026-03-18 -->
  `.any()` checks existence but not non-empty content. Effort: small

- [x] **H-192** `[error_handling]` `war/appraisal.rs:90` — No max bounds on elapsed verification time — FIXED: added 365-day cap
  <!-- pid:bounds_unchecked | first:2026-03-18 -->

- [x] **H-193** `[error_handling]` `war/compat.rs:203` — iat timestamp overflow silently uses i64::MAX — FIXED: fallback to Utc::now().timestamp()
  <!-- pid:overflow_silent | first:2026-03-18 -->

- [x] **H-194** `[error_handling]` `rfc_conversions.rs:150` — z_score masks zero std_error as 0.001
  <!-- pid:silent_fallback | first:2026-03-18 -->
  Artificially inflated z-score if std_error is 0. False affirmation of Galton validity. Effort: small

- [-] **H-195** `[error_handling]` `error.rs:217` — From<String> and From<&str> both create Error::Legacy
  <!-- pid:type_conflation | first:2026-03-18 -->
  Cannot distinguish migrated code from actual legacy errors. Effort: medium

- [-] **H-196** `[security]` `crypto/obfuscation.rs:20` — ~~Relaxed ordering~~ FALSE POSITIVE: no AtomicU64 in this file
  <!-- pid:concurrency_memory_ordering | first:2026-03-18 -->

- [ ] **H-197** `[security]` `identity/secure_storage.rs:366` — Cache clone bypasses mlock protection
  <!-- pid:key_zeroize_error_path | first:2026-03-18 -->
  ProtectedBuf converted to unprotected heap copy via as_slice().to_vec(). Effort: medium

- [ ] **H-198** `[security]` `sealed_identity/store.rs:407` — Unbounded hostname in HKDF salt
  <!-- pid:unbounded_input_to_crypto | first:2026-03-18 -->
  Hostname fed into HKDF without length bounds. Truncate and hash before use. Effort: small

- [-] **H-199** `[concurrency]` `ipc/server.rs:150` — ~~Rate limiter held across encoding~~ FALSE POSITIVE: guard dropped after .check()
  <!-- pid:lock_contention | first:2026-03-18 -->

- [-] **H-200** `[security]` `ipc/server.rs:241` — ~~Decrypt failure continues~~ FALSE POSITIVE: code already has `break` on decrypt error
  <!-- pid:tamper_detection | first:2026-03-18 -->
  Tampering not treated as fatal. Should close connection on decrypt failure. Effort: small

- [x] **H-201** `[error_handling]` `ffi/ephemeral.rs:88` — Weak CSPRNG fallback — FIXED: returns error instead of degrading
  <!-- pid:crypto_weak_prng | first:2026-03-18 -->

- [-] **H-202** `[concurrency]` `ffi/ephemeral.rs:101` — TOCTOU on DashMap session eviction threshold
  <!-- pid:toctou | first:2026-03-18 -->
  sessions().len() check not atomic with eviction iteration. Effort: small

- [x] **H-203** `[error_handling]` `ffi/ephemeral.rs:243` — Store write errors silently discarded — FIXED: log::error on failure
  <!-- pid:silent_error_swallow | first:2026-03-18 -->

- [-] **H-204** `[concurrency]` `ffi/sentinel.rs:138` — OnceLock race leaks tokio tasks on concurrent start
  <!-- pid:resource_leak | first:2026-03-18 -->
  Two concurrent ffi_sentinel_start() calls create two Sentinels, one leaked with spawned tasks. Effort: medium

- [x] **H-205** `[security]` `ffi/attestation.rs:99` — Unbounded base64 decode (memory DoS) — FIXED: added 4KB cap
  <!-- pid:no_size_limit | first:2026-03-18 -->
  No size limit on challenge_b64. 1GB string = 1GB allocation. Challenge should be ~32 bytes. Effort: small

- [x] **H-206** `[security]` `ffi/helpers.rs:34` — Signing key file read without size limit — FIXED: added 1KB cap
  <!-- pid:no_size_limit | first:2026-03-18 -->
  Symlink to large file causes DoS. Check metadata().len() < 64 before read. Effort: small

- [-] **H-207** `[error_handling]` `ffi/steganography_ffi.rs:182` — ~~Path component unwrap~~ FALSE POSITIVE: already uses unwrap_or_default
  <!-- pid:unwrap_in_ffi | first:2026-03-18 -->

- [x] **H-208** `[security]` `ffi/writersproof_ffi.rs:139` — API key not zeroized on error — FIXED: Zeroizing<String> wrapper
  <!-- pid:key_zeroize_error_path | first:2026-03-18 -->

- [-] **H-209** `[error_handling]` `ffi/evidence.rs:273` — ~~Error message confusion~~ FALSE POSITIVE: separate match arms already distinguish
  <!-- pid:error_message_confusion | first:2026-03-18 -->

- [x] **H-210** `[error_handling]` `evidence/builder/setters.rs:331` — i32 overflow silently capped — FIXED: log::warn on overflow
  <!-- pid:overflow_silent | first:2026-03-18 -->

- [-] **H-211** `[error_handling]` `evidence/wire_conversion.rs:51` — Empty chain produces valid wire packet
  <!-- pid:unvalidated_invariant | first:2026-03-18 -->
  0-byte document on empty chain. Verifier can't distinguish 'never written' from 'data lost'. Effort: small

- [ ] **H-212** `[security]` `evidence/packet.rs:300` — SECURITY TODO: content_hash excludes behavioral fields
  <!-- pid:sec_signature_scope | first:2026-03-18 -->
  Active TODO documenting signature binding gap. Related to C-037. Effort: large

- [x] **H-213** `[code_quality]` `mmr/proof.rs:275` — RangeProof doesn't validate sibling_path exhaustion — FIXED: added post-loop check
  <!-- pid:input_validation | first:2026-03-18 -->
  Partial proof path may verify if early levels hash out by chance. Effort: small

- [ ] **H-214** `[performance]` `mmr/proof.rs:274` — O(n log n) range proof verification with per-level HashMap
  <!-- pid:performance_memalloc | first:2026-03-18 -->
  Pre-allocate and reuse single HashMap across levels. Effort: medium

- [x] **H-215** `[error_handling]` `vdf/swf_argon2.rs:482` — .expect() on CBOR in fiat_shamir_challenge
  <!-- pid:panic_in_library | first:2026-03-18 -->
  Library function panics on resource failure (OOM). Return Result instead. Effort: medium

- [x] **H-216** `[error_handling]` `research/collector.rs:185` — Silent directory removal error — FIXED: log::warn on failure
  <!-- pid:silent_error_swallow | first:2026-03-18 -->

- [-] **H-217** `[error_handling]` `engine.rs:252` — ~~Watcher setup silent~~ FALSE POSITIVE: errors propagated with ?
  <!-- pid:silent_error_swallow | first:2026-03-18 -->

- [ ] **H-218** `[concurrency]` `engine.rs:373` — Session samples cleared while monitor records (race)
  <!-- pid:race_condition | first:2026-03-18 -->
  Jitter session cleared but monitor continues recording. Timing data interleaved. Effort: medium

- [x] **H-219** `[error_handling]` `sealed_chain.rs:169` — Slice bounds assume HEADER_SIZE correct without assert
  <!-- pid:missing_bounds_check | first:2026-03-18 -->
  data[20..52] access panics if constant is wrong. Add bounds assertion. Effort: small

- [x] **H-220** `[security]` `cmd_identity.rs:30` — Recovery phrase echo — FIXED: dialoguer::Password for TTY input
  <!-- pid:credential_exposure | first:2026-03-18 -->

---

### Audit Run 5 — HIGH (CLI) (2026-03-18)

- [-] **H-221** `[security]` `cmd_export.rs:335` — ~~Session ID path traversal~~ FALSE POSITIVE: validate_session_id() already rejects
  <!-- pid:path_traversal | first:2026-03-18 -->

- [-] **H-222** `[error_handling]` `cmd_track.rs:357` — ~~Mutex unwrap~~ FALSE POSITIVE: already uses map_err pattern
  <!-- pid:lock_unwrap | first:2026-03-18 -->

- [x] **H-223** `[error_handling]` `cmd_track.rs:325,360` — Silent capture/join errors — FIXED: log + panic extraction
  <!-- pid:silent_error_swallow | first:2026-03-18 -->

- [ ] **H-224** `[concurrency]` `cmd_track.rs:478` — Lock contention on JitterSession in hot keystroke loop
  <!-- pid:lock_contention | first:2026-03-18 -->
  Arc<Mutex> locked every 250ms + by keystroke thread. VDF compute stalls keystrokes. Effort: medium

- [-] **H-225** `[security]` `native_messaging_host.rs:376` — ~~Hex decode before ct_eq~~ FALSE POSITIVE: len!=32 short-circuits before ct_eq
  <!-- pid:missing_validation | first:2026-03-18 -->

- [x] **H-226** `[security]` `native_messaging_host.rs:238` — CSPRNG panic via expect() — FIXED: returns Response::Error
  <!-- pid:panic_on_crypto | first:2026-03-18 -->

- [x] **H-227** `[error_handling]` `cmd_fingerprint.rs:132` — Profile not found vs storage error conflated
  <!-- pid:error_conflation | first:2026-03-18 -->
  Undistinguished error types. Effort: small

---

- [x] **H-149** `[spec]` ASCII armor headers don't match spec
  <!-- pid:spec_ascii_armor | verified:true | first:2026-03-12 -->
  Code (`war/encoding.rs:12`): `"-----BEGIN WITNESSD AUTHORSHIP RECORD-----"`.
  Spec (§6.10): `"-----BEGIN POP WAR-----"` / `"-----END POP WAR-----"`.
  Also missing: `"-----BEGIN POP EVIDENCE-----"` / `"-----END POP EVIDENCE-----"` armor for .cpop files.
  Fix: Update WAR armor strings; add CPOP armor support. Effort: small

- [x] **H-150** `[spec]` SWF leaf hashing double-hashes state without tag (resolved as part of C-032)
  <!-- pid:spec_leaf_hash | verified:true | first:2026-03-12 -->

- [x] **H-151** `[spec]` No enforcement of entangled mode for ENHANCED/MAXIMUM
  <!-- pid:spec_entangled_enforcement | verified:true | first:2026-03-12 -->
  Spec (§7.5): "Attesters claiming ENHANCED or MAXIMUM content tier MUST use swf-argon2id-entangled (21) instead of (20)."
  Code: No validation in CLI export path. Fix: Add check in `cmd_export.rs`. Effort: small

- [x] **H-152** `[spec]` Jitter quantization not implemented (privacy)
  <!-- pid:spec_jitter_quantize | verified:true | first:2026-03-12 -->
  Spec (§11.4): "Minimum quantization of 5ms RECOMMENDED" for privacy protection.
  Code: Raw millisecond intervals passed through without quantization.
  Fix: Round jitter intervals to nearest 5ms before inclusion in Evidence Packet. Effort: small

- [x] **H-153** `[spec]` SWF default parameters may not match spec minimums per tier
  <!-- pid:spec_swf_defaults | verified:true | first:2026-03-12 -->
  Spec (§7.5): CORE requires `steps=90, m=65536, t=1, p=1` for Mode 20.
  Code: `Argon2SwfParams::default()` needs verification against spec table.
  Fix: Ensure defaults match spec minimums; add per-tier parameter selection. Effort: small

- [x] **H-065** `tpm/secure_enclave.rs:448` — Already returns CounterRollback error on corruption
- [ ] **H-066** `tpm/verification.rs:102` — No ECDSA P-256 verification (coupled with C-014)
- [x] **H-068** `identity/secure_storage.rs:302` — Intermediate Vec not zeroized → SYS-018
- [x] **H-069** `identity/secure_storage.rs:253` — Symlink/traversal in migration path
- [x] **H-071** `sentinel/core.rs:248` — Already stores JoinHandles in bridge_threads, joined in stop()
- [x] **H-073** `sentinel/ipc_handler.rs:30` — Already returns Err, does not continue
- [x] **H-074** `ffi/sentinel.rs:26` — expect() in runtime creation → SYS-013
- [x] **H-075** `ffi/evidence.rs:179` — assert! in HashValue at FFI boundary → SYS-013
- [x] **H-076** `ffi/helpers.rs:27` — HMAC key without Zeroizing → SYS-018
- [ ] **H-077** `ffi/ephemeral.rs:361` — Business logic in FFI boundary (DEFERRED: large refactor, functional as-is)
- [x] **H-079** `ipc/messages.rs:7` — PathBuf without traversal validation
- [x] **H-081** `fingerprint/storage.rs:121` — ALREADY FIXED: file_mtimes cache skips unchanged files
- [x] **H-082** `rfc/wire_types/packet.rs:92` — No post-decode validation → SYS-017
- [x] **H-089** `keyhierarchy/session.rs:43` — Session seed not zeroized on error → SYS-018
- [x] **H-090** `keyhierarchy/session.rs:367` — Plaintext buffer leak on encrypt failure → SYS-018
- [x] **H-092** `keyhierarchy/puf.rs:74` — Legacy seed not zeroized after migration → SYS-018
- [x] **H-098** `config/defaults.rs:18` — /tmp fallback for data dir → SYS-020
- [x] **H-099** `presence/helpers.rs:8` — Already uses HMAC-SHA256 with domain separation
- [x] **H-101** `sealed_identity/store.rs` — Counter rollback gap on first unseal
- [x] **H-103** `protocol/forensics/engine.rs:217` — NaN bypass → SYS-016
- [x] **H-104** `forensics/comparison.rs:54` — ln() of zero/negative → SYS-016
- [x] **H-105** `background.js:11` — Documented service worker ephemeral state design
- [x] **H-106** `background.js:442` — Bounded pending callbacks to MAX_PENDING_CALLBACKS (256)
- [x] **H-110** `ffi/evidence.rs:191` — FALSE POSITIVE: VDF uses SHA-256, SwfSha256 is correct
- [x] **H-113** `native_messaging_host.rs:266` — Session overwrite without finalizing
- [x] **H-122** `vdf/timekeeper.rs:40` — Blocking sync I/O in async function
- [x] **H-123** `vdf/timekeeper.rs:77` — VDF proof field always `[0u8; 32]`
- [x] **H-124** `forensics/analysis.rs:146` — BY DESIGN: CV heuristic is intentional quick assessment, full analysis via BehavioralFingerprint
- [x] **H-125** `vdf/roughtime_client.rs` — Single hardcoded Roughtime server
- [x] **H-126** `jitter/session.rs:313` — Session::load no chain integrity verification
- [x] **H-128** `native_messaging_host.rs` — Jitter rate limit has no temporal component
- [x] **H-130** `[error_handling]` `checkpoint/chain.rs:357,360` — Silent `unwrap_or_default()` on CBOR encode corrupts SWF seed
  <!-- pid:silent_error_swallow | batch:6 | verified:true | first:2026-03-11 | last:2026-03-11 -->
  Impact: Empty Vec used as SWF seed input if CBOR fails, weakening proof | Fix: Propagate via `?` | Effort: small
  ```diff
  - crate::codec::cbor::encode(&jb.summary.sample_count).unwrap_or_default();
  + crate::codec::cbor::encode(&jb.summary.sample_count)
  +     .map_err(|e| Error::checkpoint(format!("CBOR encode intervals: {e}")))?;
  ```
- [x] **H-131** `[security]` `mmr/proof.rs:77,85,91,365,375,383,389` — `as u16` truncation in MMR proof serialization
  <!-- pid:truncating_cast | batch:9 | verified:true | first:2026-03-11 | last:2026-03-11 -->
  Impact: Proof integrity violation on MMR trees with >65535 elements | Fix: Bounds check before cast | Effort: small
  ```diff
  - buf[offset..offset + 2].copy_from_slice(&(self.merkle_path.len() as u16).to_be_bytes());
  + let path_len: u16 = self.merkle_path.len().try_into()
  +     .map_err(|_| MmrError::ProofTooLarge)?;
  + buf[offset..offset + 2].copy_from_slice(&path_len.to_be_bytes());
  ```
- [x] **H-132** `[error_handling]` `trust_policy/evaluation.rs:93-106` — NaN propagation through trust score
  <!-- pid:nan_inf_unguarded | batch:4 | verified:true | first:2026-03-11 | last:2026-03-11 -->
  Impact: NaN metrics → NaN trust verdict, bypassing policy | Fix: Guard with `.is_finite()` | Effort: small
  ```diff
  + if !cov.is_finite() {
  +     0.0
  + } else if cov <= 0.0 {
  - if cov <= 0.0 {
  ```
- [x] **H-133** `[security]` `wal/serialization.rs:67` — `payload_len as u32` truncates WAL payload length >4GB
  <!-- pid:truncating_cast | batch:7 | verified:true | first:2026-03-11 | last:2026-03-11 -->
  Impact: WAL chain integrity corruption on large payloads | Fix: Return error if >u32::MAX | Effort: small
- [x] **H-134** `[error_handling]` `evidence/wire_conversion.rs:146,174,178` — Silent CBOR encode failures in jitter seal and entangled MAC
  <!-- pid:silent_error_swallow | batch:8 | verified:true | first:2026-03-11 | last:2026-03-11 -->
  Impact: Weakened cryptographic bindings if CBOR encode fails | Fix: Propagate via `?` | Effort: small

### Code Quality HIGH (2026-03-11)

- [x] **H-135** `[code_quality]` `report/html.rs:1-1082` — God module: 1082 lines of monolithic HTML generation with 50+ `write!` results ignored
  <!-- pid:god_module | verified:true | first:2026-03-11 -->
  Impact: Silent formatting failures, untestable sections | Fix: Split into `write_header()`, `write_timeline()`, `write_forensics()`, `write_css()` | Effort: medium

- [ ] **H-136** `[code_quality]` `evidence/builder.rs:48` — 32+ `with_*` setter methods with duplicated strength-escalation pattern
  <!-- pid:high_complexity | verified:true | first:2026-03-11 -->
  Impact: 1094 lines of repetitive logic; strength rules scattered | Fix: Extract strength escalation into macro or `fn escalate_strength()` | Effort: large

- [ ] **H-137** `[architecture]` `platform/windows.rs:155` — 6 global static Mutex/AtomicBool for thread communication
  <!-- pid:unsafe_global_state | verified:true | first:2026-03-11 -->
  Impact: Hidden state; overlapping GLOBAL_SENDER/GLOBAL_STATS risk undefined behavior if both KeystrokeMonitor and WindowsKeystrokeCapture started | Fix: Encapsulate in struct or use channels | Effort: medium

- [ ] **H-138** `[code_quality]` `sentinel/core.rs:186` — 200+ line `start()` method with tokio::select! mixing keystroke, mouse, focus, debounce, idle
  <!-- pid:high_complexity | verified:true | first:2026-03-11 -->
  Impact: Tightly coupled async event loop, hard to test/modify | Fix: Extract `keyboard_bridge()`, `mouse_bridge()`, `focus_handler()` as separate tasks | Effort: medium

- [x] **H-139** `[code_quality]` `sentinel/helpers.rs:196` — WAL append logic repeated 3x (lines 134, 222, and focus_document_sync)
  <!-- pid:duplicated_logic | verified:true | first:2026-03-11 -->
  Impact: Bug in WAL logic must be fixed in 3 places | Fix: Extract `fn wal_append_session_event()` | Effort: small

- [ ] **H-140** `[architecture]` `ffi/forensics.rs:26` — Business logic in FFI layer; forensic metrics computed in FFI instead of core
  <!-- pid:logic_in_boundary | verified:true | first:2026-03-11 -->
  Impact: Metric calculation duplicated between `ffi_get_forensics` and `ffi_list_tracked_files` | Fix: Move to forensics module; FFI marshals only | Effort: medium

- [x] **H-141** `[error_handling]` `config/loading.rs:26` — Config loaded without calling `validate()`
  <!-- pid:missing_validation | verified:true | first:2026-03-11 -->
  Impact: Zero checkpoint intervals, invalid paths pass silently | Fix: Call `config.validate()` after `load_or_default()` | Effort: small

- [x] **H-142** `[security]` `crypto/obfuscated.rs:30` — Plaintext intermediate not zeroized during Obfuscated::new()
  <!-- pid:key_zeroize_error_path | verified:true | first:2026-03-11 -->
  Impact: Serialized plaintext held in memory before XOR mask applied | Fix: Use `Zeroizing<Vec<u8>>` for intermediate | Effort: medium

- [x] **H-143** `[code_quality]` `fingerprint/activity.rs:268` — 3 distribution types (IKI, Zone, Pause) with identical from_data/similarity/merge but no shared trait
  <!-- pid:duplicated_logic | verified:true | first:2026-03-11 -->
  Impact: 400+ lines of mechanical code; adding a distribution requires full copy-paste | Fix: `Distribution<T>` trait with generic methods | Effort: large

- [-] **H-144** `[performance]` `fingerprint/activity.rs:722` — `current_fingerprint()` clones entire VecDeque<Sample> on every call — FALSE POSITIVE: guarded by dirty flag, only recomputes on change
  <!-- pid:clone_in_loop | verified:true | first:2026-03-11 -->
  Impact: Up to 10k samples cloned on every dirty check | Fix: Pass `&[Sample]` to `from_samples()` | Effort: medium

- [-] **H-145** `[code_quality]` `jitter/content.rs:192` — `analyze_document_zones()` hardcodes bucket=5 ignoring actual interval — FALSE POSITIVE: by design for static analysis boundaries
  <!-- pid:magic_value | verified:true | first:2026-03-11 -->
  Impact: All transitions map to same bucket; temporal information lost | Fix: Compute bucket from `interval_to_bucket()` | Effort: medium

- [-] **H-146** `[code_quality]` `c2pa.rs:619` — `validate_manifest()` 78 lines with 10+ sequential checks and deep nesting — FALSE POSITIVE: well-structured sequential validation, each check is distinct
  <!-- pid:high_complexity | verified:true | first:2026-03-11 -->
  Impact: Hard to test individual rules | Fix: Split into `validate_hard_binding()`, `validate_actions()`, etc. | Effort: medium

- [x] **H-147** `[code_quality]` `keyhierarchy/puf.rs:60` — Inconsistent zeroization in `load_or_create_seed()` (3 paths, sometimes moved, sometimes cloned)
  <!-- pid:key_zeroize_error_path | verified:true | first:2026-03-11 -->
  Impact: Seed left in memory on some error paths | Fix: Use `Zeroizing<Vec<u8>>` wrapper for all paths | Effort: small

- [x] **H-148** `[code_quality]` `keyhierarchy/verification.rs:36` — Fragile counter delta logic, easy off-by-one
  <!-- pid:fragile_counter_delta | verified:true | first:2026-03-11 -->
  Impact: Counter verification silently passes on off-by-one errors | Fix: Extract `verify_counter_delta(prev, current, delta) -> Result<()>` | Effort: small

### Re-audit HIGH (2026-03-12)

#### Security

- [x] **H-154** `[security]` `mmr/proof.rs:214` — RangeProof::verify() does not check leaf_indices for duplicates; HashMap silently deduplicates
  <!-- pid:missing_bounds_check | batch:13 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Attacker could submit duplicate leaf indices to satisfy count check, weakening range proof integrity | Fix: `if leaf_indices.len() != leaf_indices.iter().collect::<HashSet<_>>().len() { return Err(InvalidProof) }` | Effort: small

- [x] **H-155** `[security]` `mmr/proof.rs:317` — Multiple remaining peaks not validated as single root after Merkle reconstruction
  <!-- pid:missing_validation | batch:13 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Proof could fraudulently claim disjoint subtrees form a single peak | Fix: Add `if current.len() != 1 { return Err(InvalidProof) }` before `values().next()` | Effort: small

- [x] **H-156** `[security]` `checkpoint/chain.rs:178` — `commit_entangled()` does not validate `jitter_session_id` is non-empty
  <!-- pid:input_validation | batch:13 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Empty session IDs weaken forensic binding; upstream assumes uniqueness | Fix: `if jitter_session_id.is_empty() { return Err(Error::checkpoint("empty session_id")) }` | Effort: small

- [x] **H-157** `[security]` `sealed_identity/store.rs:236` — Derived seed not zeroized in reseal fallback path
  <!-- pid:key_zeroize_residual | batch:10 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: PUF-derived seed persists in heap on unseal failure | Fix: Wrap in `Zeroizing<Vec<u8>>` | Effort: small

- [x] **H-158** `[security]` `identity/secure_storage.rs:358` — Seed cache returns unzeroized `Vec<u8>` copies via `to_vec()`
  <!-- pid:key_zeroize_residual | batch:14 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Callers receive raw seed bytes without zeroization guarantee | Fix: Return `Zeroizing<Vec<u8>>` from `load_seed()` | Effort: small

- [x] **H-159** `[security]` `crypto/anti_analysis.rs:48` — macOS `is_debugger_present()` returns hardcoded `false`
  <!-- pid:incomplete_impl | batch:15 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Anti-debugging defense completely bypassed on macOS | Fix: Implement via `sysctl` P_TRACED flag check | Effort: medium

- [x] **H-160** `[security]` `crypto/mem.rs:32` — `mlock()` failure silently ignored with `let _`
  <!-- pid:error_swallow | batch:15 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Key material may be paged to disk without warning | Fix: `if libc::mlock(...) != 0 { log::warn!("mlock failed") }` | Effort: small

- [ ] **H-161** `[security]` `sealed_chain.rs:96` — Key derivation uses HKDF with cleartext `document_id` as context
  <!-- pid:key_derivation_entropy | batch:15 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: If `document_id` is guessable (common filenames), key derivation is weakened | Fix: Add per-instance random nonce to key derivation | Effort: medium

- [-] **H-162** `[security]` `crypto/obfuscation.rs:30` — Serde serialization outputs plaintext, defeating obfuscation
  <!-- pid:obfuscation_transparency | batch:15 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Obfuscated data stored as plaintext on disk | Fix: Add `#[serde(skip)]` or custom encrypted serialization | Effort: small

- [ ] **H-163** `[security]` `sentinel/helpers.rs:395` — `validate_path()` TOCTOU: parent canonicalized but symlink can be swapped before file operation
  <!-- pid:path_toctou_symlink | batch:6 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Attacker on same machine could write to arbitrary location via symlink race | Fix: Use `openat(2)` or validate immediately before OS operation | Effort: medium

- [ ] **H-164** `[security]` `ipc/messages.rs:13` — Path validation does not check for symlinks; TOCTOU window with sentinel
  <!-- pid:symlink_traversal | batch:9 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Symlink traversal between IPC validation and sentinel processing | Fix: `Path::canonicalize()` during IPC validation | Effort: medium

- [-] **H-165** `[security]` `checkpoint/chain.rs:400` — `verify_hash_chain()` accepts mixed genesis modes without enforcement
  <!-- pid:integrity_binding | batch:13 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Entangled chain could have legacy all-zeros genesis, weakening mode integrity | Fix: Check entanglement_mode consistency with genesis prev_hash | Effort: medium

#### Performance

- [x] **H-166** `[performance]` `vdf/swf_argon2.rs:333` — O(n²) linear search via `indices.contains()` in Fiat-Shamir index sampling
  <!-- pid:perf_quadratic_search | batch:14 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: For k=100 (MAXIMUM tier), 5050 comparisons per proof | Fix: Use `HashSet` for O(1) lookups | Effort: small

- [-] **H-167** `[performance]` `fingerprint/storage.rs:90` — O(n³) nested `.iter().find()` in cluster analysis
  <!-- pid:perf_nested_find | batch:4 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Quadratic/cubic complexity on fingerprint lookups | Fix: Build `HashMap<ProfileId, &AuthorFingerprint>` once before loop | Effort: small

- [-] **H-168** `[performance]` `platform/linux.rs:548,871` — `device_id` cloned on every keystroke and mouse event in hot loop
  <!-- pid:perf_heap_alloc_loop | batch:2 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: O(n) String clone per event at typing/mouse frequency | Fix: Cache `device_id` before loop or use `Arc<String>` | Effort: small

#### Error Handling

- [-] **H-169** `[error_handling]` `c2pa.rs:989` — `.unwrap()` on external COSE signature data at trust boundary
  <!-- pid:unwrap_on_external | batch:1 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Malformed/tampered C2PA manifest causes library panic | Fix: `map_err()` and propagate | Effort: small

- [-] **H-170** `[error_handling]` `forensics/velocity.rs:117` — Unsafe unwrap in session statistics; panics on empty session list
  <!-- pid:error_handling_unwrap | batch:8 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Crash on edge case during forensic analysis | Fix: Guard with `if sessions.is_empty() { return default }` | Effort: small

- [x] **H-171** `[error_handling]` `forensics/cross_modal.rs:310` — Division-by-zero risk in temporal drift score
  <!-- pid:unguarded_division | batch:8 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: NaN propagation if constants misconfigured | Fix: Assert `MAX_TEMPORAL_DRIFT_SEC > DRIFT_PERFECT_SEC` or clamp denominator | Effort: small

- [x] **H-172** `[error_handling]` `rfc/biology.rs:558` — `10f64.powf(spectral_slope)` with external data; NaN/Inf silently stored
  <!-- pid:nan_inf_residual | batch:11 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Silent corruption of biological measurements | Fix: Validate `spectral_slope.is_finite()` before `powf()` | Effort: small

- [x] **H-173** `[error_handling]` `rfc/biology.rs:364` — Unclamped FP accumulation; NaN scores silently become 0 millibits
  <!-- pid:unclamped_fp_accumulation | batch:11 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Subtle data loss — invalid scores look like valid "no evidence" | Fix: Check `is_finite()` on each sub-score before accumulation | Effort: small

- [x] **H-174** `[error_handling]` `rfc/biology.rs:370` — NaN passes range check (`(0.55..=0.85).contains(&NaN)` returns false silently)
  <!-- pid:nan_skip_validation | batch:11 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Malformed Hurst exponents bypass anomaly detection | Fix: Add `h.is_finite()` check before range tests | Effort: small

- [x] **H-175** `[error_handling]` `platform/linux.rs:859` — NaN from `sqrt()` in mouse magnitude without finite guard
  <!-- pid:nan_inf_residual | batch:2 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Synthetic jitter detection silently broken on overflow | Fix: Check `.is_finite()` after sqrt | Effort: small

- [x] **H-176** `[error_handling]` `platform/synthetic.rs:115` — Variance/std NaN when window is empty
  <!-- pid:nan_guard_missing | batch:2 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: CV threshold check always false on NaN; verdicts unreliable | Fix: Guard `window.len() >= MIN_SAMPLES` before stats calc | Effort: small

- [x] **H-177** `[error_handling]` `platform/windows.rs:262` — `UnhookWindowsHookEx()` result silently discarded with `let _`
  <!-- pid:silent_error_swallow | batch:2 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Hook may fail to detach; system resource leak in Drop | Fix: Log result | Effort: small

#### Architecture

- [-] **H-178** `[architecture]` `c2pa.rs:244` — `CLAIM_GENERATOR` version string hardcoded, not from `CARGO_PKG_VERSION`
  <!-- pid:hardcoded_version | batch:1 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: C2PA manifest version becomes stale on crate version bump | Fix: Use `env!("CARGO_PKG_VERSION")` | Effort: small

#### Concurrency

- [-] **H-179** `[concurrency]` `sentinel/core.rs:322` — Keystroke accumulator write lock acquired twice without idempotency guard
  <!-- pid:double_write_guard | batch:6 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Possible duplicate writes if channel sends same event twice | Fix: Add idempotent event IDs | Effort: small

- [x] **H-180** `[concurrency]` `platform/windows.rs:186` — `GLOBAL_SESSION.lock()` poison error silently swallowed via `.ok().and_then()`
  <!-- pid:poison_error_swallow | batch:2 | verified:true | first:2026-03-12 | last:2026-03-12 -->
  Impact: Panic in hook silently treats session as None; no recovery path | Fix: Log poison errors explicitly | Effort: small

<details><summary>Engine High — Fixed/Eliminated (28)</summary>

- [x] H-067 flush_context errors logged | H-070 null ptr checks | H-072 FALSE POSITIVE (no await in handlers)
- [x] H-078 FALSE POSITIVE (no expect at lines) | H-080 full path matching | H-083 saturating_mul
- [x] H-084 try_from for casts | H-085/H-086 hex decode warnings | H-087 FALSE POSITIVE (type-safe)
- [x] H-088 ALREADY GUARDED | H-091 seed length validation | H-093 ALREADY RESOLVED
- [x] H-094 min() not max() | H-095/H-096 queue logging | H-097 health check logging
- [x] H-100 ct_eq | H-102 clock error expect | H-107 BY DESIGN | H-108 VDF iteration cap
- [x] H-109 path warn | H-111 genesis seed | H-112 ordinal at send | H-114 hard rejection
- [x] H-115 CT comparison | H-116 fail on crypto error | H-117 ordinal guard
- [x] H-118 negative doc_length | H-119 i128 widening | H-120 skip default context
- [x] H-121 checkpoint count | H-127 commitment logging removed | H-129 NaN-safe min_by
</details>

---

## Engine — Medium (135 open)

<details><summary>Architecture (12)</summary>

- [ ] M-050 tpm/windows.rs — god module 1208L (DEFERRED: large refactor)
- [x] M-051 tpm/secure_enclave.rs — duplicate key loading (refactored to load_or_create_se_key)
- [x] M-052 background.js — ACKNOWLEDGED: flat switch/case dispatch, no extraction needed
- [x] M-053 rfc/biology.rs — NO FIX NEEDED: anomaly checking is intentionally non-redundant
- [x] M-054 checkpoint/chain.rs — no post-deser VDF validation
- [x] M-056 war/types.rs — ALREADY PRESENT: V2_0 variant exists
- [x] M-057 sealed_chain — TOCTOU in post-decryption check (load_sealed_verified)
- [ ] M-058 platform/windows.rs — duplicate session tracking (DEFERRED: architecture)
- [x] M-059 forensics/engine.rs — ALREADY DONE: ForensicsError has #[from] in main Error enum
- [ ] M-060 rfc/jitter_binding.rs — incomplete builder pattern (DEFERRED: architecture)
- [x] M-061 ffi/system.rs — dashboard metrics extracted to helpers::compute_streak_stats
- [x] M-055 ELIMINATED — VDF errors already propagated
</details>

<details><summary>Error Handling (8)</summary>

- [x] M-062 sentinel/daemon.rs — unwrap() on path.parent()
- [x] M-063 sentinel/shadow.rs — bare RwLock::read() unwrap
- [x] M-064 ffi/ephemeral.rs — session removed before validation
- [x] M-065 presence/types.rs — Duration overflow on large config
- [x] M-066 config/types.rs — retention_days u64 to u32 overflow
- [x] M-067 sealed_chain.rs — migration partial failure
- [x] M-068 evidence/rfc_conversion.rs — segment count forced min 20
- [x] M-069 ipc/server.rs — accept() error loop without backoff
</details>

<details><summary>Browser Extension (4)</summary>

- [x] M-070 background.js — return true from async message handlers
- [x] M-071 background.js — isConnecting reset in finally/onDisconnect
- [x] M-079 background.js — ratchet count validated as non-negative integer
- [x] M-080 background.js — start_witnessing URL validated against ALLOWED_ORIGINS
</details>

<details><summary>Security (10)</summary>

- [x] M-072 tpm/mod.rs:57 — parse_sealed_blob overflow
- [x] M-073 tpm/mod.rs:99 — hardcoded PCR selection
- [x] M-074 ipc/secure_channel.rs:67 — nonce counter overflow
- [x] M-075 ipc/secure_channel.rs:58 — bincode without size limits
- [x] M-076 fingerprint/voice.rs:350 — non-ASCII char handling
- [x] M-077 sealed_identity/store.rs — BY DESIGN: hostname adds entropy alongside TPM device_id
- [x] M-078 research/uploader.rs — BY DESIGN: Supabase endpoint is the production API
- [x] M-081 secure-channel.js — server pubkey length and SEC1 format validated
- [x] M-082 secure-channel.js — destroy() method with best-effort zeroization
- [x] M-083 config/loading.rs — ALREADY FIXED: permissions set correctly
</details>

<details><summary>Performance (9)</summary>

- [x] M-084 labyrinth.rs:254 — O(n^2) nearest-neighbor
- [x] M-085 fingerprint/activity.rs:205 — double allocation
- [x] M-086 fingerprint/activity.rs:721 — full buffer clone on status
- [x] M-087 vdf/aggregation.rs — NO FIX NEEDED: string not cloned per level
- [x] M-088 wal/operations.rs — WAL parse bounded by MAX_WAL_ENTRIES (10M)
- [x] M-089 research/collector.rs — Vec::remove(0) O(n)
- [x] M-090 background.js — documented single-hash storage design
- [x] M-091 content.js — cached DOM element references with invalidation
- [x] M-092 forensics/velocity.rs:77 — unnecessary Vec clone
- [x] M-093 ffi/ephemeral.rs:122 — ALREADY MITIGATED: EVICTION_THRESHOLD guard + DashMap retain
</details>

<details><summary>Concurrency (8)</summary>

- [x] M-094 platform/macos/mouse_capture.rs:121 — RwLock write in CGEventTap
- [x] M-095 platform/windows.rs:580 — lock poison no recovery
- [x] M-096 ipc/server.rs:133 — ACCEPTABLE: lock held only for .check() microseconds
- [x] M-097 sentinel/focus.rs:156 — NOT A BUG: receiver consumption pattern is correct
- [x] M-098 background.js — documented: single-threaded JS event loop prevents TOCTOU
- [x] M-099 background.js — documented: get-then-compare atomic in JS event loop
- [x] M-100 engine.rs:255 — NOT A BUG: Arc cleanup via running flag
- [x] M-101 presence/verifier.rs — NOT A BUG: StdRng with &mut self is thread-safe
</details>

<details><summary>Code Quality (8)</summary>

- [x] M-102 tpm/windows.rs — PCR parse bounds checking added (checked_add + error on truncation)
- [x] M-103 evidence/builder.rs:857 — string slice no bounds check
- [x] M-104 evidence/builder.rs:571 — ALREADY FIXED: uses total_cmp
- [x] M-105 error_topology.rs:302 — u16 to u8 to char truncation
- [x] M-106 labyrinth.rs:215 — unused variable
- [x] M-107 platform/macos/hid.rs:95 — NOT A BUG: buffer matches CFSetGetCount
- [x] M-108 platform/mouse_stego.rs:21 — expect() in hot path
- [x] M-109 war/appraisal.rs:209 — NOT A BUG: Affirming=2 < Warning=32, || is correct
- [x] M-110 war/verification.rs:147 — version dispatch fragile
</details>

<details><summary>Maintainability (9)</summary>

- [x] M-111 forensics/assessment.rs:178 — scattered calibration constants
- [x] M-112 forensics/topology.rs — algorithm doc comment added to deletion_clustering_coef
- [x] M-113 rfc/time_evidence.rs:291 — ALREADY FIXED: all add methods call recalculate_tier()
- [x] M-114 secure-channel.js — domain-separation strings extracted to DST_* constants
- [x] M-115 content.js — site detection strings extracted to SITE_* constants
- [x] M-116 vdf/params.rs:46 — implicit units in calibration
- [x] M-117 writersproof/types.rs:81 — ELIMINATED: file is 69 lines, naming is consistent
- [x] M-118 background.js — shared constants extracted (VALID_ACTIONS, GENESIS_COMMITMENT_PREFIX, etc.)
- [x] M-119 ffi/forensics.rs:144 — hardcoded ML weight vector
</details>

<details><summary>New Findings 2026-03-03 (24)</summary>

- [x] M-120 evidence/builder.rs:434 — silent i32 truncation on edit index
- [x] M-121 analysis/hurst.rs:111 — NaN from linear regression → SYS-016
- [x] M-122 keyhierarchy/manager.rs — ALREADY TARGETED: per-field #[allow(dead_code)]
- [x] M-123 forensics/cross_modal.rs:243 — zero timestamp bypass
- [x] M-124 forensics/cross_modal.rs:297 — self-referential jitter ratio
- [x] M-125 forensics/forgery_cost.rs:309 — estimated_forge_time 0 when all infinite
- [x] M-126 forensics/forgery_cost.rs:176 — VeryHigh tier from unchecked bool
- [x] M-127 vdf/timekeeper.rs:65 — NTP servers hardcoded
- [x] M-128 analysis/behavioral_fingerprint.rs — fatigue detection implemented (first/last quarter comparison)
- [x] M-129 forensics/comparison.rs — removed unused cadence_cv_similarity field
- [x] M-130 analysis/labyrinth.rs — min_line_length diagonal counting implemented
- [x] M-131 forensics/types.rs — Hurst exponent computed via R/S analysis on 50+ IKI samples
- [x] M-132 background.js — sendResponse moved inside async callbacks with return true
- [x] M-133 forensics/engine.rs:62 — BY DESIGN: ForensicsError is subsystem error with #[from] integration
- [x] M-134 forensics/forgery_cost.rs:277 — NOT WORTH FIXING: two iterations acceptable
- [x] M-135 content.js — sender.id validation and VALID_CONTENT_ACTIONS whitelist
- [ ] M-136 analysis/active_probes.rs — incomplete probe coverage (DEFERRED: feature enhancement)
- [x] M-137 platform/mouse_stego.rs — ALREADY FIXED: expect() not in hot path
- [x] M-138 ipc/secure_channel.rs — ALREADY FIXED by M-075: size limits in place
- [x] M-139 rfc/biology.rs:478 — magic constant
- [x] M-140 analysis/perplexity.rs — ALREADY NAMED: FNN_DISTANCE_THRESHOLD constant exists
- [x] M-141 FALSE POSITIVE — no division in calculate_cadence_score
- [x] M-142 config/loading.rs — DUPLICATE of M-083
- [ ] M-143 ffi/ephemeral.rs — 900+ line FFI module (DEFERRED: architecture)
</details>

<details><summary>Re-audit Findings 2026-03-11 (4)</summary>

- [-] **M-148** `[code_quality]` `rfc/wire_types/hash.rs:34,63,92` — Public `sha256()`/`sha384()`/`sha512()` use `assert!()` (panicking API)
  <!-- pid:panic_in_library | batch:3 | verified:true | first:2026-03-11 | last:2026-03-11 -->
  BY DESIGN: All callers pass `[u8; 32].to_vec()` (guaranteed correct length). `try_*` alternatives exist for untrusted input. Documented `# Panics` section. Idiomatic Rust pattern.
- [x] **M-149** `[concurrency]` `sentinel/core.rs:337` — Inconsistent `.write()` vs `.write_recover()` on mouse_stego_engine
  <!-- pid:lock_unwrap | batch:5 | verified:true | first:2026-03-11 | last:2026-03-11 -->
  Impact: Mouse stego silently stops on lock poison | Fix: Change to `write_recover()` | Effort: small
- [x] **M-150** `[security]` `keyhierarchy/puf.rs:133` — `seed()` returns unprotected `Vec<u8>` clone of key material
  <!-- pid:key_material_error_path_leak | batch:4 | verified:true | first:2026-03-11 | last:2026-03-11 -->
  Impact: PUF seed copy may persist in memory | Fix: Return `Zeroizing<Vec<u8>>` | Effort: small
- [x] **M-151** `[error_handling]` `steganography/extraction.rs:65` — `hex::decode().unwrap_or_default()` silently fails tag verification
  <!-- pid:silent_error_swallow | batch:10 | verified:true | first:2026-03-11 | last:2026-03-11 -->
  Impact: Stego tag check always fails on corrupted hex | Fix: Return error on invalid hex | Effort: small
</details>

<details><summary>Code Quality Audit 2026-03-11 (42)</summary>

**Performance**
- [x] **M-152** `fingerprint/activity.rs:326` — `ZoneProfile::from_samples()` triple-pass (zone counts, transitions, IKI) | Fix: Single accumulator pass | Effort: medium
- [-] **M-153** `jitter/content.rs:340` — `extract_recorded_zones()` double iteration (decode, then normalize) | Fix: Inline into single pass | Effort: small
- [-] **M-154** `jitter/codec.rs:207` — `compare_chains()` always O(n), no early exit on first mismatch | Fix: Return on first divergence | Effort: small
- [x] **M-155** `fingerprint/voice.rs:432` — `histogram_similarity()` f32→f64 via collect; intermediate Vec per comparison | Fix: `bhattacharyya_coefficient` accept f32 directly | Effort: small
- [x] **M-156** `anchors/ethereum.rs:103` — `address()` computed via full ECDSA derivation on every RPC call | Fix: Cache in `EthereumProvider::new()` | Effort: small
- [x] **M-157** `tpm/secure_enclave.rs:460` — `device_id()` / `public_key()` clone String/Vec on every call | Fix: Cache as `Arc<String>` | Effort: small
- [ ] **M-158** `codec/cbor.rs:51` — `encode_tagged()` deserializes to Value then re-encodes (2x serde overhead) | Fix: Low-level Value construction | Effort: medium
- [ ] **M-159** `ffi/system.rs:133` — `ffi_list_tracked_files()` runs `evaluate_authorship` + `analyze_forensics` redundantly | Fix: Cache metrics or use single pass | Effort: medium
- [x] **M-160** `ffi/attestation.rs:180` — `get_model()` / `get_os_version()` shell-exec on every FFI call | Fix: Cache in `OnceLock` | Effort: small
- [-] **M-161** `platform/linux.rs:490` — `device_reader_thread()` RwLock + HashMap lookup per keystroke event | Fix: Snapshot device_info at thread start | Effort: small — FALSE POSITIVE: already snapshotted before event loop
- [ ] **M-162** `collaboration.rs:217` — `validate_coverage()` allocates `vec![false; N]` for large N | Fix: Use `BitSet` or `BTreeSet<Range>` | Effort: medium
- [-] **M-163** `anchors/rfc3161.rs:214` — `children()` iterator rebuilds Vec on each call | Fix: Cache DER tree parse results | Effort: small — FALSE POSITIVE: pure function with different inputs each call

**Code Duplication**
- [x] **M-164** `platform/linux.rs:694` — `enumerate_keyboards()` ≈ `enumerate_mice()` (70+ lines each) | Fix: Extract `enumerate_input_devices(filter)` | Effort: medium
- [-] **M-165** `platform/linux.rs:200` — `is_virtual_device()` ≈ `is_virtual_mouse()` (same pattern matching) | Fix: Merge into single fn | Effort: small
- [x] **M-166** `sentinel/macos_focus.rs:68` — `get_document_path_via_ax()` ≈ `get_window_title_via_ax()` (65 lines each, differ only in attr name) | Fix: Extract `query_ax_attribute(pid, attr)` | Effort: small
- [x] **M-167** `sentinel/daemon.rs:349` — `cmd_start()` ≈ `cmd_start_foreground()` (50 lines duplicate setup) | Fix: Extract `setup_daemon_common()` | Effort: medium
- [ ] **M-168** `ipc/sync_client.rs:1-140` — Unix/Windows IpcClient duplicated (identical send/recv protocol) | Fix: Extract `IpcTransport` trait | Effort: medium
- [x] **M-169** `ipc/crypto.rs:74` — Nonce construction duplicated between encrypt/decrypt | Fix: Extract `fn construct_nonce(prefix, seq)` | Effort: small
- [x] **M-170** `vdf/proof.rs:62` — `verify()` and `verify_with_progress()` duplicate iteration logic | Fix: Extract `verify_internal(callback)` | Effort: small
- [x] **M-171** `checkpoint/chain.rs:120` — `commit()` and `commit_with_vdf_duration()` 90% identical | Fix: Extract `commit_internal(vdf_duration: Option)` | Effort: small
- [-] **M-172** `checkpoint/chain.rs:282` — VDF input computation duplicated between `commit_entangled()` and `commit_rfc()` | Fix: Shared `compute_vdf_input()` | Effort: medium — FALSE POSITIVE: overlap is only 2 lines, methods differ significantly
- [x] **M-173** `c2pa.rs:522` — `build_assertion_jumbf_json` ≈ `build_assertion_jumbf_cbor` (identical JUMBF boilerplate) | Fix: Parameterize on content format | Effort: small
- [-] **M-174** `protocol/baseline.rs:123` — `serde_bytes_opt` duplicates `evidence/serde_helpers.rs` | Fix: Share via `cpop_protocol::serde_utils` | Effort: small — FALSE POSITIVE: cross-crate serde `with` path resolution makes sharing impractical
- [x] **M-175** `protocol/crypto.rs:21` — `compute_causality_lock` ≈ `compute_causality_lock_v2` (differ only in DST + phys_entropy) | Fix: Extract shared inner fn | Effort: small
- [x] **M-176** `protocol/codec.rs:9` — `encode_evidence` / `encode_attestation` duplicate CBOR tag wrapping | Fix: Generic `encode_cbor<T>(tag, val)` | Effort: small
- [x] **M-177** `keyhierarchy/identity.rs:13` — `derive_master_identity()` ≈ `derive_master_private_key()` (35 lines duplicated) | Fix: Single source fn | Effort: small
- [x] **M-178** `sealed_identity/store.rs:45` — `initialize()` duplicates PUF + HKDF logic from `keyhierarchy/identity.rs` | Fix: Call shared `derive_and_seal()` | Effort: small
- [-] **M-179** `writersproof/types.rs:1` — Response types (Nonce, Enroll, Attest) all identical `{ success, message, data }` | Fix: Generic `BaseResponse<T>` | Effort: small
- [x] **M-180** `identity/secure_storage.rs:34` — Keyring Entry creation + error wrapping repeated 3x | Fix: Extract `keyring_entry(account)` helper | Effort: small
- [x] **M-181** `config/types.rs:296` — `SentinelConfig::validate()` repeats zero-check pattern for 4+ interval fields | Fix: Extract `validate_interval(val, name)` | Effort: small

**Code Quality / Abstraction**
- [x] **M-182** `tpm/windows.rs:463` — Manual buffer parsing with 17 `u32::from_be_bytes` + 9 offset checks | Fix: Create `fn read_u32_be(data, offset) -> Result<u32>` | Effort: small
- [x] **M-183** `tpm/types.rs:69` — `default_pcr_selection()` hardcodes `vec![0,4,7]` duplicating `DEFAULT_QUOTE_PCRS` in mod.rs | Fix: Reuse const | Effort: small
- [x] **M-184** `tpm/verification.rs:102` — 3 sequential fallback tries (Ed25519/ECDSA/RSA) with 5+ indent levels | Fix: Break into `try_verify_*` helpers | Effort: small
- [ ] **M-185** `rfc/checkpoint.rs:111` — `compute_hash()` 24 manual `hasher.update()` calls; fragile to reordering | Fix: CBOR-then-hash for canonical form | Effort: medium
- [ ] **M-186** `checkpoint/types.rs:198` — 5 DST branches (v1-v4) scattered in conditionals | Fix: `CheckpointHashVersion` enum | Effort: medium
- [ ] **M-187** `evidence/builder.rs:284` — Hardcoded confidence strings ('high', 'cryptographic', 'statistical') in 20+ calls | Fix: `ConfidenceLevel` enum | Effort: medium
- [-] **M-188** `presence/verifier.rs:242` — 3 challenge generators (phrase/word/math) follow identical pattern | Fix: Table-driven `generate_challenge(typ)` | Effort: small — FALSE POSITIVE: math generator has different logic, each only ~10 lines
- [ ] **M-189** `trust_policy/profiles.rs:9` — Policy definitions buried in code as builder chains | Fix: Define as const data structs, build from data | Effort: medium
- [x] **M-190** `vdf/swf_argon2.rs:217` — `select_indices()` uses modulo without rejection sampling (bias for non-power-of-two) | Fix: Rejection sampling | Effort: small
- [-] **M-191** `vdf/params.rs:78` — Hash-and-finalize pattern repeated 6+ times across vdf module | Fix: Extract `hash_with_dst(dst, parts)` | Effort: small
- [x] **M-192** `declaration/helpers.rs:1` — `extent_rank()` fragile if enum variant order changes | Fix: `impl Ord for AIExtent` or `#[repr(u8)]` | Effort: small
- [ ] **M-193** `cpop_jitter_bridge/types.rs:1` — Mirror types that don't add value over `cpop_jitter` types | Fix: Remove wrappers or document value-add | Effort: medium

</details>

<details><summary>Crate Audit Findings 2026-03-05 (4)</summary>

- [x] M-144 `[security]` cpop_protocol/src/evidence.rs — profile_uri validated against spec URI
  <!-- pid:missing_validation | verified:true | first:2026-03-05 -->
  `protocol_uri` deserialized without value or length validation. Spec requires `urn:ietf:params:rats:eat:profile:pop:1.0`. Related to SYS-014 (String fields).
- [x] M-145 `[security]` cpop_protocol/src/rfc.rs — DocumentRef.filename bounded to MAX_FILENAME_LEN (256)
  <!-- pid:unbounded_string_deser | verified:true | first:2026-03-05 -->
  No max length on filename field. Related to SYS-014.
- [x] M-146 `[security]` cpop_jitter/src/evidence.rs — EvidenceChain.records bounded to MAX_EVIDENCE_RECORDS (100K)
  <!-- pid:unbounded_vec_deser | verified:true | first:2026-03-05 -->
  Deserialized chain can have arbitrary number of records. Related to SYS-014.
- [x] M-147 `[code_quality]` cpop_jitter/src/evidence.rs — expect() with descriptive message on pre-epoch clock
  <!-- pid:clock_error_silent_fallback | verified:true | first:2026-03-05 -->
  `current_timestamp_us()` returns 0 for pre-epoch clock. Engine fixed same pattern at H-102 to use `.expect()`.
</details>

---

## Engine — Fix Groups Reference

| # | Group | Items | Effort | Impact |
|---|-------|-------|--------|--------|
| 1 | Lock recovery (mechanical) | SYS-021 (82 instances) | 2-3h | Prevents cascading panics |
| 2 | Key zeroization (error paths) | SYS-018, H-068, H-076, H-089, H-090, H-092 | 2-3h | Closes key material leak class |
| 3 | Wire validation + size limits | SYS-014, SYS-017, H-082 | 4-5h | Prevents OOM/DoS |
| 4 | Time evidence fixes | H-083, H-084 | 10min | Timestamp safety |
| 5 | rfc_conversion hex fixes | H-085, H-086 | 30min | Empty Vec on failure |
| 6 | NaN/Inf guards | SYS-016, H-104, M-121 | 1-2h | Float stability |
| 7 | Native messaging hardening | H-113, H-128, SYS-022 residual | 1h | Session + rate limits |
| 8 | VDF/time safety | H-122, H-123, H-125 | 3-4h | VDF proof + async NTP |
| 9 | FFI compilation (B-004) | B-004 (42 errors) | 3-4h | Unblocks --features ffi |
| 10 | Browser ext hardening | SYS-019, H-105, H-106, M-052 | 4-6h | Message validation |
| 11 | Config/path security | SYS-020, H-069, H-098 | 1h | Absolute-path enforcement |
| 12 | FFI panics | SYS-013, H-074, H-075 | 2h | expect/assert at boundary |
| 13 | Queue error handling | SYS-012 partial, H-095, H-096, H-097 | 1-2h | Error logging |
| 14 | Forensic cross-modal | M-123, M-124, M-125, M-126 | 1h | Bypass hardening |
| 15 | TPM signing (Windows) | C-014, H-066 | 3-5 days | Real TPM2_Sign |
| 16 | Named constants | SYS-015 | 2-4h | Magic values cleanup |
| 17 | Deserialization integrity | H-126, M-054 | 20min | Chain verify on load |
| 18 | IPC hardening | H-079, H-080, M-074, M-075 | 2h | Path traversal + limits |
| 19 | Checkpoint test fixes | B-006 | 15min | Supply signing key |

---

## CLI App (apps/cpop_cli/) — Exhaustive Review (2026-03-12)

> Source: Exhaustive CLI quality review across all 20 source files + tests.
> 7 fixes applied, 6 false positives eliminated.

### CLI — Fixed (7)

- [x] **CLI-C1** `cmd_verify.rs:140` — CPOP verify prints "VERIFIED" without validation
  <!-- pid:cli_cpop_verify | verified:true | first:2026-03-12 -->
  Fix: Call `packet.validate()` after CBOR decode; show [WARN] if validation fails.

- [x] **CLI-C2** `cmd_export.rs:323,385` — char_count uses byte count instead of character count
  <!-- pid:cli_char_count | verified:true | first:2026-03-12 -->
  Fix: Document-level char_count reads file and counts `chars()`. Per-checkpoint uses byte approx (schema limitation).

- [x] **CLI-C3** `cmd_track.rs:35` — No file size limit in auto_checkpoint_file (OOM risk)
  <!-- pid:cli_file_size_limit | verified:true | first:2026-03-12 -->
  Fix: Skip files >500MB (matching cmd_watch.rs limit).

- [x] **CLI-H1** `cmd_export.rs:294` — TPM detection `Ok((_, hw)) => (hw, hw)` loses has_tpm flag
  <!-- pid:cli_tpm_flag | verified:true | first:2026-03-12 -->
  Fix: Changed to `Ok((tpm, hw)) => (tpm, hw)`.

- [x] **CLI-H6** `cmd_export.rs:343-346` — JSON export hardcodes dummy proof params (memory_cost=0)
  <!-- pid:cli_proof_params | verified:true | first:2026-03-12 -->
  Fix: Use `vdf::params_for_tier(spec_content_tier)` for actual Argon2 parameters.

- [x] **CLI-M11** `cmd_track.rs:308-314` — Silent SQLITE_BUSY, skipped checkpoints not logged
  <!-- pid:cli_sqlite_busy | verified:true | first:2026-03-12 -->
  Fix: Added timestamped warning to stderr.

- [x] **CLI-M12** `cmd_export.rs:932` — `collect_declaration` pub(crate) broader than needed
  <!-- pid:cli_visibility | verified:true | first:2026-03-12 -->
  Fix: Changed to `fn` (only used within the file).

### CLI — False Positives / Already Fixed (6)

- [-] **CLI-C4** Lock poisoning in cmd_track.rs — already handled via `if let Ok(...)` pattern
- [-] **CLI-C5** TOCTOU in file.exists() — caught by subsequent fs::metadata()
- [-] **CLI-C6** install.sh tar failure — `set -e` catches it
- [-] **CLI-H2** PID file write race — already uses `acquire_pid_file()` with atomic acquisition
- [-] **CLI-H3** Ctrl+C capture — handled within 250ms via AtomicBool + ctrlc handler
- [-] **CLI-M4** No debounce in watch — already present at line 288/303-306

### CLI — Remaining (not fixed, lower priority)

- [ ] **CLI-H4** Tests — soft assertions hide failures. Effort: medium
- [ ] **CLI-H5** Tests — 6+ commands lack test coverage (init, identity, commit, daemon, config, watch). Effort: large
- [x] **CLI-M1** WAR test expects old `WITNESSD` armor header. Effort: small
- [ ] **CLI-M3** No daemon log rotation. Effort: medium
- [ ] **CLI-M5** Verify output doesn't show which checks passed/failed. Effort: small
- [ ] **CLI-M6** Log output not paginated for large histories. Effort: medium
- [-] **CLI-M2** Hardcoded 30s — this is session-save interval, not checkpoint interval. Not a bug.
- [-] **CLI-M7** Session active/inactive — requires daemon state query, UX enhancement.
- [-] **CLI-M8** Config validation on `set` — ALREADY PRESENT: every key has type + range validation.
- [-] **CLI-M9** Mnemonic warning — ALREADY PRESENT: "WARNING: Keep this secret!" + non-terminal detection.
- [-] **CLI-M10** Progress indicator — ALREADY PRESENT: "Computing checkpoint..." + "done ({elapsed})".
- [x] **CLI-L1** `main.rs:61` — auto-start daemon now logs warning on failure.
- [ ] **CLI-L2** `cmd_daemon.rs:77,85` — permission set failures silently ignored. Effort: trivial
- [-] **CLI-L3** `cmd_config.rs` — editor retry loop bounded by user confirmation prompt. Not unbounded.
- [ ] **CLI-L4** No `--quiet` flag for scripting. Effort: medium
- [ ] **CLI-L5** No `--json` flag on most commands. Effort: medium
- [x] **CLI-L6** `cmd_watch.rs` — HashMap cleanup threshold extracted to named `stale_entry_threshold`.

---

## macOS App (apps/cpop_macos/) — 191 issues (136 original + 55 new)

> Source: `apps/cpop_macos/todo.md` (audited 2026-03-04, re-audited 2026-03-16, 86 Swift/JS/shell files)
> Submodule repo — work independently from engine.
> All 136 original issues (C-001..C-009, H-001..H-028, M-001..M-085, ELEV items) are FIXED.

### macOS Summary
| Severity | Open | Fixed | False Positive | Skipped |
|----------|------|-------|----------------|---------|
| CRITICAL | 8 (new) | 9 (original) | 1 | 0 |
| HIGH     | 15 (new) | 28 (original) | 3 | 0 |
| MEDIUM   | 32 (new) | 75 + 57 ELEV (original) | 3 | 0 |
| Systemic | 5   | 2     | 0              | 0 |

### macOS Systemic
- [x] **mac-SYS-001** `god_module` — RESOLVED — god modules split per submodule todo
- [x] **mac-SYS-002** `silent_error_swallow` — RESOLVED — error handling added across 6+ files
- [ ] **mac-SYS-003** `hardcoded_colors` — 10+ SwiftUI views with hardcoded color literals
- [ ] **mac-SYS-004** `accessibility_missing` — 8+ views missing VoiceOver labels
- [x] **mac-SYS-005** `no_test_coverage` — PARTIALLY RESOLVED — 384 tests now exist
- [ ] **mac-SYS-006** `localization_missing` — all user-facing strings hardcoded in English
- [ ] **mac-SYS-007** `error_alert_pattern` — inconsistent error presentation across views

### macOS Original Critical (all fixed)
- [x] **mac-C-001** CPOPBridge.swift — CLI path injection via unsanitized user input
- [x] **mac-C-002** CPOPService.swift — mnemonic words stored as String array, never zeroized
- [x] **mac-C-003** OnboardingView.swift — recovery phrase in plain Text view, clipboard not cleared
- [x] **mac-C-004** SettingsView.swift — recovery phrase displayed without memory cleanup
- [x] **mac-C-005** CPOPBridge.swift — annotation text passed to CLI without escaping
- [x] **mac-C-006** SafariWebExtensionHandler.swift — IPC message not validated
- [x] **mac-C-007** CPOPService.swift — session overwrite without finalizing previous
- [x] **mac-C-008** CPOPBridge.swift — process output parsed without size limit
- [x] **mac-C-009** KeychainService.swift — keychain items not deleted on identity reset

### macOS Original High (all fixed)
- [x] mac-H-001..H-028 — all 28 issues resolved (concurrency, error handling, security, UX)

### macOS NEW Critical (8 open — 2026-03-16 audit)
- [ ] **mac-C-010** SafariExtensionShared.swift:938 — Encryption fallback to plaintext UserDefaults when AES-GCM fails. Impact: security downgrade. Fix: fail-closed. Effort: medium
- [ ] **mac-C-011** ReceiptValidation.swift:721 — Legacy unversioned receipt accepted without structure validation. Fix: reject unversioned. Effort: small
- [ ] **mac-C-012** CPOPEngineFFI.swift:28 — `try!` on rustCall crashes app on FFI allocation failure. Fix: do-try-catch. Effort: medium
- [ ] **mac-C-013** CPOPEngineFFI.swift:54 — `rustBuffer.data!` force unwrap on null pointer. Fix: guard let. Effort: small
- [ ] **mac-C-014** CPOPEngineFFI.swift:2864 — 50+ cascading `try! ... try!` in FFI wrappers. Fix: Result propagation. Effort: large
- [ ] **mac-C-015** CloudSyncService.swift:618 — HTTP 429 Retry-After header parsing injection. Fix: RFC 7231 parsing. Effort: small
- [ ] **mac-C-016** SettingsDetailView.swift:286 — Blank recovery phrase sheet on FFI failure. Fix: error handling. Effort: small
- [ ] **mac-C-017** EngineService.swift:622 — Custom Base58 encoder with no test vectors. Fix: use vetted library. Effort: medium

### macOS NEW High (15 open — 2026-03-16 audit)
- [ ] **mac-H-029** AuthService.swift:838 — Keychain delete status unchecked before SecItemAdd. Effort: small
- [ ] **mac-H-030** SecureEnclaveKeyManager.swift:235 — Force unwrap on tag.data(using:). Effort: small
- [ ] **mac-H-031** DeviceAttestationService.swift:410 — Hardcoded Supabase Edge Function URL. Effort: small
- [ ] **mac-H-032** DeviceAttestationService.swift:770 — HMAC without domain separation tag. Effort: small
- [ ] **mac-H-033** DataDirectoryIntegrityService.swift:117 — First-run bypass returns .valid. Effort: small
- [ ] **mac-H-034** SettingsIntegrityService.swift:245 — "unknown-device" UUID spoofing accepted. Effort: small
- [ ] **mac-H-035** SafariExtensionShared.swift:966 — Silent decryption failure with plaintext fallback. Effort: small
- [ ] **mac-H-036** SafariExtensionShared.swift:287 — Commitment hash collision via string concat (no length prefixing). Effort: medium
- [ ] **mac-H-037** DataDirectoryIntegrityService.swift:778 — Keychain rollback attack accepted. Effort: small
- [ ] **mac-H-038** ReceiptValidation.swift:376 — Receipt version rollback not detected. Effort: small
- [ ] **mac-H-039** EngineService.swift:610 — Force unwrap on Data(base64Encoded:). Effort: small
- [ ] **mac-H-040** AuthService.swift:500 — Continuation double-resume race condition. Effort: medium
- [ ] **mac-H-041** DeviceAttestationService.swift:849 — HMAC tampering detection logged but no user notification. Effort: medium
- [ ] **mac-H-042** NotificationManager.swift:694 — Notification history saved unencrypted, forgeable. Effort: medium
- [ ] **mac-H-043** AppDelegate.swift:88 — Race: service provider callable before integrity validation completes. Effort: medium

### macOS NEW Medium (32 open — 2026-03-16 audit)
- [ ] mac-M-086..mac-M-117 — concurrency, code quality, maintainability, and performance issues across UI and services
  (See `apps/cpop_macos/todo.md` for full details per issue)

### macOS Quick Wins (new findings only — originals all fixed)
| ID | Sev | File | Issue | Effort |
|----|-----|------|-------|--------|
| mac-C-011 | CRIT | ReceiptValidation | Reject unversioned receipts | small |
| mac-C-013 | CRIT | CPOPEngineFFI | Guard let on rustBuffer.data | small |
| mac-C-015 | CRIT | CloudSyncService | RFC 7231 Retry-After parsing | small |
| mac-C-016 | CRIT | SettingsDetailView | Handle FFI failure on phrase sheet | small |
| mac-H-029 | HIGH | AuthService | Check keychain delete status | small |
| mac-H-030 | HIGH | SecureEnclaveKeyManager | Safe unwrap on tag.data | small |
| mac-H-031 | HIGH | DeviceAttestationService | Extract hardcoded URL to config | small |
| mac-H-032 | HIGH | DeviceAttestationService | Add DST to HMAC | small |
| mac-H-033 | HIGH | DataDirectoryIntegrityService | Fail-closed on first run | small |
| mac-H-034 | HIGH | SettingsIntegrityService | Reject "unknown-device" UUID | small |
| mac-H-035 | HIGH | SafariExtensionShared | Fail-closed on decryption | small |
| mac-H-037 | HIGH | DataDirectoryIntegrityService | Detect keychain rollback | small |
| mac-H-038 | HIGH | ReceiptValidation | Detect receipt version rollback | small |
| mac-H-039 | HIGH | EngineService | Guard base64 decode | small |

---

## Windows App (apps/cpop_windows/) — 229 issues (188 original + 41 new)

> Source: `apps/cpop_windows/winui/CPOP/todo.md` (audited 2026-03-04, re-audited 2026-03-16, 120 C#/PS1/WXS/XAML files)
> Submodule repo — work independently from engine.

### Windows Summary
| Severity | Open | Fixed | Skipped |
|----------|------|-------|---------|
| CRITICAL | 1 + 8 (new) | 4 (original) | 1 (C-002) |
| HIGH     | 14 + 16 (new) | 39 (original) | 3 |
| MEDIUM   | 119 + 21 (new) | 0 | 0 |
| Systemic | 7    | 0     | 0       |

### Windows Systemic
- [ ] **win-SYS-001** `fire_and_forget` — 15+ files — async calls without error handling
- [ ] **win-SYS-002** `empty_catch` — 12 files — swallowed exceptions
- [ ] **win-SYS-003** `async_void` — 5 files — losing exceptions
- [ ] **win-SYS-004** `test_quality` — 13 test files — vacuous tests, hand-rolled doubles
- [ ] **win-SYS-005** `resource_brush_duplication` — 5+ files — duplicate theme helpers
- [ ] **win-SYS-006** `accessibility_missing_automation` — 11+ XAML files — missing AutomationProperties
- [ ] **win-SYS-007** `hardcoded_colors_strings` — 20+ XAML files — hardcoded colors and strings

### Windows Original Critical
- [x] **win-C-001** IpcConnectionPool.cs:81 — ConcurrentBag.Count race, unbounded pool growth
- [x] **win-C-002** LockScreenDialog.xaml.cs:56 — brute-force lockout bypass (SKIPPED — non-issue)
- [x] **win-C-003** OnboardingPage.xaml.cs:259 — mnemonic words persist in memory
- [x] **win-C-004** SettingsPage.xaml.cs:132 — recovery phrase no memory cleanup
- [x] **win-C-005** CPOPBridge.cs:~1200 — CLI argument injection via annotation
- [ ] **win-C-006** MnemonicRecoveryDialog.xaml.cs:31 — recovery phrase in plaintext TextBox. Fix: TextBox → PasswordBox. Effort: medium

### Windows Original High
- [x] win-H-001..H-056 — 39 fixed, 3 skipped, 14 remaining open
- **Still open (14):** win-H-003, H-008, H-009, H-010, H-011, H-012, H-015, H-017, H-027, H-028, H-038, H-040, H-045, H-047, H-048, H-053
  (See `apps/cpop_windows/winui/CPOP/todo.md` for full details per issue)

### Windows NEW Critical (8 open — 2026-03-16 audit)
- [ ] **win-C-007** IpcClient.cs:477 — _eventListenerCts reassigned without atomic swap, duplicate listeners. Effort: small
- [ ] **win-C-008** App.xaml.cs:56 — NullReferenceException handled as e.Handled=true, masks real bugs. Effort: small
- [ ] **win-C-009** App.xaml.cs:660 — Environment.Exit(0) without awaiting async cleanup. Effort: medium
- [ ] **win-C-010** EntitlementManager.cs:162 — Premium tier cached unsigned in LocalSettings. Effort: medium
- [ ] **win-C-011** DataDirectoryIntegrityService.cs:209 — Manifest tampering silently accepted/normalized. Effort: medium
- [ ] **win-C-012** FileWatcherService.cs:214 — Deadlock: GetAwaiter().GetResult() inside lock(). Effort: small
- [ ] **win-C-013** InactivityService.cs:82 — CTS race: concurrent Stop/Start disposes CTS while monitor reads. Effort: small
- [ ] **win-C-014** DatabaseIntegrityService.cs:105 — Overly broad catch maps all DB errors to generic anomaly. Effort: medium

### Windows NEW High (16 open — 2026-03-16 audit)
- [ ] **win-H-057** IpcClient.cs:490 — Event listener/RequestAsync share pipe without correlation. Effort: large
- [ ] **win-H-058** IpcClient.cs:524 — No reconnection logic after daemon crash. Effort: medium
- [ ] **win-H-059** IpcClient.cs:715 — ECDH public key accepted without curve validation. Effort: medium
- [ ] **win-H-060** CPOPBridge.cs:29 — Batch operation concurrency race on _batchOperationLock. Effort: small
- [ ] **win-H-061** CPOPDatabaseService.cs:18 — Each method opens new SqliteConnection, SQLITE_BUSY contention. Effort: medium
- [ ] **win-H-062** CPOPDatabaseService.cs:70 — OpenReadOnlyConnection catches all SqliteException, returns null. Effort: small
- [ ] **win-H-063** CPOPDatabaseService.cs:722 — _disposed never checked, post-disposal calls succeed. Effort: small
- [ ] **win-H-064** SecurityService.cs:110 — WinVerifyTrust WINTRUST_DATA passed by value, P/Invoke reads garbage. Effort: medium
- [ ] **win-H-065** UndoService.cs:15 — Non-thread-safe singleton initialization. Effort: small
- [ ] **win-H-066** AccessibilityService.cs:41 — Animation preference cache never updated. Effort: small
- [ ] **win-H-067** RFCErrorMapper.cs:142 — Overly broad substring match hits wrong errors. Effort: small
- [ ] **win-H-068** DataDirectoryIntegrityService.cs:63 — Fake async (never awaits), blocks UI. Effort: small
- [ ] **win-H-069** CloudSyncDetectionService.cs:81 — Regex recompiled per file in loop. Effort: small
- [ ] **win-H-070** CloudSyncDetectionService.cs:171 — DetectCloudFolders() called per-file without caching. Effort: medium
- [ ] **win-H-071** CollaborativeEvidenceService.cs:61 — Deserialized sessions not validated. Effort: small
- [ ] **win-H-072** UndoService.cs:22 — Unsynchronized state across UI/timer threads. Effort: small

### Windows Original Medium (119 open)
- [ ] win-M-001..M-119 — performance, code quality, security, maintainability issues
  (See `apps/cpop_windows/winui/CPOP/todo.md` for full details)

### Windows NEW Medium (21 open — 2026-03-16 audit)
- [ ] win-M-120..win-M-140 — various performance, code quality, security, maintainability issues
  (See `apps/cpop_windows/winui/CPOP/todo.md` for full details)

### Windows Quick Wins
| ID | Sev | File | Issue | Effort |
|----|-----|------|-------|--------|
| win-C-007 | CRIT | IpcClient | Atomic CTS swap for event listeners | small |
| win-C-008 | CRIT | App.xaml | Stop masking NullReferenceException | small |
| win-C-012 | CRIT | FileWatcherService | Replace GetAwaiter().GetResult() in lock | small |
| win-C-013 | CRIT | InactivityService | CTS race on concurrent Stop/Start | small |
| win-H-060 | HIGH | CPOPBridge | Fix batch operation lock race | small |
| win-H-062 | HIGH | CPOPDatabaseService | Propagate SqliteException | small |
| win-H-063 | HIGH | CPOPDatabaseService | Add disposed check | small |
| win-H-065 | HIGH | UndoService | Thread-safe singleton init | small |
| win-H-066 | HIGH | AccessibilityService | Refresh animation pref cache | small |
| win-H-067 | HIGH | RFCErrorMapper | Narrow substring match | small |
| win-H-068 | HIGH | DataDirectoryIntegrityService | Make truly async | small |
| win-H-069 | HIGH | CloudSyncDetectionService | Cache compiled regex | small |
| win-H-071 | HIGH | CollaborativeEvidenceService | Validate deserialized sessions | small |
| win-H-072 | HIGH | UndoService | Synchronize cross-thread state | small |

---

## Structural Changes (2026-03-03)

6 god-level engine modules split into directory-based submodules:
| Original | New Directory | Submodules |
|----------|--------------|------------|
| `wal.rs` (999L) | `wal/` | mod.rs, types.rs, operations.rs, serialization.rs, tests.rs |
| `presence.rs` (989L) | `presence/` | mod.rs, types.rs, verifier.rs, helpers.rs, tests.rs |
| `research.rs` (695L) | `research/` | mod.rs, types.rs, collector.rs, uploader.rs, helpers.rs, tests.rs |
| `trust_policy.rs` (691L) | `trust_policy/` | mod.rs, types.rs, evaluation.rs, profiles.rs, tests.rs |
| `config.rs` (634L) | `config/` | mod.rs, types.rs, defaults.rs, loading.rs, tests.rs |
| `sealed_identity.rs` (537L) | `sealed_identity/` | mod.rs, types.rs, store.rs, tests.rs |

---

## Audit Coverage

### Engine (2026-03-02/03, re-audits 2026-03-11)
<!-- 230 files, 20 batches, 4 waves + incremental + deep review -->
<!-- Prior audit: 159 issues (133 fixed, 26 skipped/eliminated) -->
<!-- This cycle: 322 new findings, 44 fixed, 8 eliminated -->
<!-- Re-audit 2026-03-11: ~200 files, 15 batches, 3 waves. 5 new HIGH + 4 new MEDIUM. All CRITICAL/HIGH verified by file read. -->
<!-- Code quality audit 2026-03-11: ~200 files, 9 batches, 2 waves. Focus: duplication, performance, abstraction. 8 SYS + 14 HIGH + 42 MEDIUM. -->
<!-- reviewed:checkpoint/chain.rs:2026-03-11 -->
<!-- reviewed:mmr/proof.rs:2026-03-11 -->
<!-- reviewed:trust_policy/evaluation.rs:2026-03-11 -->
<!-- reviewed:wal/serialization.rs:2026-03-11 -->
<!-- reviewed:evidence/wire_conversion.rs:2026-03-11 -->
<!-- reviewed:sentinel/core.rs:2026-03-11 -->
<!-- reviewed:crypto/obfuscated.rs:2026-03-11 -->
<!-- reviewed:keyhierarchy/puf.rs:2026-03-11 -->
<!-- reviewed:rfc/wire_types/hash.rs:2026-03-11 -->
<!-- reviewed:steganography/extraction.rs:2026-03-11 -->
<!-- reviewed:report/html.rs:2026-03-11 -->
<!-- reviewed:config/defaults.rs:2026-03-11 -->
<!-- reviewed:vdf/proof.rs:2026-03-11 -->

### macOS (2026-03-04, re-audited 2026-03-16)
<!-- 86 files (Swift, JS, shell, HTML) -->
<!-- Original: 136 issues found, ALL 136 FIXED (9C + 28H + 75M + 57 ELEV) -->
<!-- Re-audit 2026-03-16: 55 new issues (8C + 15H + 32M) -->

### Windows (2026-03-04, re-audited 2026-03-16)
<!-- 120 files (C#, PS1, WXS, XAML, JSON) -->
<!-- Original: 188 issues found. Fixed: 4C + 39H. Skipped: 1C (C-002) + 3H. Open: 1C + 14H + 119M + 7 SYS. -->
<!-- Re-audit 2026-03-16: 41 new issues (8C + 16H + 21M - note: win-H-057 through win-H-072 = 16 items) -->

---

> **Note**: The macOS and Windows apps are git submodules with their own repos. For full issue details
> including code-level guidance, enriched context, and diff suggestions, refer to the original
> audit files preserved in each submodule's `todo.md`. The IDs above use `mac-` and `win-` prefixes
> to distinguish from engine issue IDs.
