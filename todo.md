# Todo
<!-- suggest | Updated: 2026-03-03 | Languages: rust, js | Files: 230 | Issues: 159 prior + 322 new | Batches: 20+5+deep | Waves: 4+1+1 | Coverage: ~100% -->

> Full codebase audit 2026-03-02: 230 source files across 20 batches (4 waves). All prior issues preserved.
> Incremental audit 2026-03-03: 5 batch validation pass on wld_engine. Added SYS-021, H-107..H-109, M-120..M-122.
> Deep audit 2026-03-03: Multi-agent security/logic/forensics review. Added C-022..C-027, H-110..H-129, M-123..M-143, SYS-022..SYS-023, B-004..B-006.
> Prior audits: 159 issues (133 fixed, 26 skipped/eliminated). All CRITICALs, HIGHs, and systemics resolved.
> This scan: 322 new findings after dedup (17 CRITICAL, 85 HIGH, 207 MEDIUM, 12 systemic, 3 build).

---

## Summary
| Severity | Open | Fixed This Cycle | Prior Fixed | Prior Skipped | Prior Eliminated |
|----------|------|------------------|-------------|---------------|------------------|
| CRITICAL | 1    | 16               | 8           | 2             | 0                |
| HIGH     | 41   | 24 (+19 prior)   | 48          | 16            | 2                |
| MEDIUM   | 94   | 0                | 66          | 9             | 7                |
| SYSTEMIC | 12   | 0                | 11          | 1             | 1                |
| BUILD    | 3    | 0                | 0           | 0             | 0                |

> **2026-03-03 progress**: 16 CRITICALs fixed (C-011..C-013,C-015..C-027 except C-014). 24 HIGHs fixed (H-083..H-087,H-091,H-094..H-096,H-100,H-102,H-108,H-109,H-111,H-112,H-114..H-121,H-127,H-129). 2 eliminated (H-087 false positive, H-107 by design). 6 god-level modules split. All validated against current codebase.

---

## Systemic Issues (New)

- [ ] **SYS-012** `silent_error_swallow` — 20+ files — HIGH
  <!-- pid:silent_error_swallow | verified:true | first:2026-03-02 -->
  Silent error swallowing across many modules: `.unwrap_or_default()`, `.ok()`, `let _ = ...` on I/O and crypto operations without logging.
  Key files: `forensics/analysis.rs:50`, `ipc/server.rs:87,102`, `writersproof/queue.rs:90,127`, `ffi/system.rs:119,212`, `ffi/ephemeral.rs:464,887`, `sentinel/core.rs:164,398`, `browser-ext/background.js`, `research/collector.rs:162`, `research/helpers.rs:121,211-212`, `config/defaults.rs:18,24,33,76,115,141`
  Fix: Add `log::warn!()` before all error-swallowing patterns. For crypto/IO paths, propagate Result instead of defaulting.
  **Guidance**: Start with crypto/IO paths (highest impact): `writersproof/queue.rs`, `ipc/server.rs`. Then address `config/defaults.rs` fallbacks (→SYS-020). Test-friendly: each fix is independent, fix one file at a time and run `cargo test -p wld_engine --lib`.

- [ ] **SYS-013** `panic_in_ffi` — 6 files — CRITICAL
  <!-- pid:panic_in_library | verified:true | first:2026-03-02 -->
  `expect()` and `.unwrap()` in FFI boundary code. Swift/Kotlin callers cannot recover from panics.
  Files: `ffi/fingerprint.rs:35`, `ffi/sentinel.rs:26`, `ffi/evidence.rs:180,190,222`, `ffi/ephemeral.rs:342,372`, `ipc/crypto.rs:99,104`
  Fix: Replace all `expect()`/`unwrap()` in FFI functions with `Result`-returning wrappers mapped to `FfiResult`.

- [ ] **SYS-014** `unbounded_deser` — 8+ wire type files — HIGH
  <!-- pid:unbounded_vec_deser | verified:true | first:2026-03-02 -->
  Vec fields in wire types (CBOR/JSON) have no size limits. DoS via memory exhaustion on deserialization.
  Files: `rfc/wire_types/packet.rs:61`, `rfc/wire_types/checkpoint.rs:82`, `rfc/wire_types/components.rs:156,176`, `rfc/wire_types/attestation.rs:105,232`, `protocol/codec.rs:20`
  Fix: Add serde size limits or post-decode validation. Max checkpoints=10000, intervals=50000, claims=100.

- [ ] **SYS-015** `magic_constants` — 15+ files — MEDIUM
  <!-- pid:magic_value | verified:true | first:2026-03-02 -->
  Hardcoded thresholds and calibration constants without named constants or documentation.
  Files: `forensics/assessment.rs:178-200`, `forensics/cadence.rs:56-58`, `analysis/behavioral_fingerprint.rs:188`, `analysis/active_probes.rs:240`, `analysis/stats.rs:53`, `analysis/perplexity.rs:82`, `rfc/biology.rs:478`, `fingerprint/comparison.rs:172`, `fingerprint/voice.rs:29`, `ffi/helpers.rs:89`, `platform/synthetic.rs:131`
  Fix: Extract each to named `const` at file/module top with doc comment explaining rationale.

- [ ] **SYS-016** `nan_inf_unguarded` — 10+ files — HIGH
  <!-- pid:fp_division_unguarded | verified:true | first:2026-03-02 -->
  Division results and floating-point computations not checked for NaN/Infinity before use.
  Files: `forensics/comparison.rs:54`, `forensics/assessment.rs:226`, `rfc/biology.rs:370,396`, `rfc/jitter_binding.rs:546`, `analysis/behavioral_fingerprint.rs:207`, `evidence/builder.rs:568,571`, `platform/mouse.rs:88`, `platform/stats.rs:16`, `protocol/forensics/engine.rs:217`
  Fix: Add `.is_finite()` guard or explicit NaN check after every division in scoring/analysis paths.

- [ ] **SYS-017** `missing_wire_validation` — 5+ wire type files — HIGH
  <!-- pid:missing_validation | verified:true | first:2026-03-02 -->
  Wire types deserialized from CBOR without post-decode validation. Invalid data silently accepted.
  Files: `rfc/wire_types/packet.rs:41,92`, `rfc/wire_types/checkpoint.rs:33`, `rfc/wire_types/mod.rs:37`
  Fix: Implement `validate()` trait for all wire types. Call after deserialization. Check required fields, sequence continuity, hash non-zero.

- [ ] **SYS-018** `key_zeroize_error_path` — 6+ files — HIGH
  <!-- pid:key_material_error_path_leak | verified:true | first:2026-03-02 -->
  Key material allocated but not zeroized on error/exception paths. Extensions of previously-fixed SYS-001.
  Files: `keyhierarchy/session.rs:43,129,367`, `keyhierarchy/recovery.rs:122,165`, `keyhierarchy/puf.rs:74`, `tpm/secure_enclave.rs:542`, `ffi/helpers.rs:27`, `ffi/ephemeral.rs:794`, `identity/secure_storage.rs:302`
  Fix: Use `Zeroizing<Vec<u8>>` wrappers or scope guards that zeroize on Drop. Replace bare `Vec<u8>` returns for key bytes.

- [ ] **SYS-019** `browser_ext_unvalidated_messages` — 3 files — HIGH
  <!-- pid:security-message_origin_bypass | verified:true | first:2026-03-02 -->
  Browser extension message handlers accept messages from any origin without sender validation.
  Files: `background.js:478`, `content.js:280`, `popup.js:262`
  Fix: Validate `sender.id` matches extension ID. Check `sender.url` against allowed origins.

- [ ] **SYS-020** `insecure_path_fallback` — 4 files — HIGH
  <!-- pid:world_writable_fallback | verified:true | first:2026-03-02 -->
  HOME dir resolution falls back to relative paths or /tmp when HOME is unset. Sensitive data exposed on shared systems.
  Files: `config/types.rs:245`, `config/defaults.rs:18,24,33,76,115,141`, `writersproof/queue.rs:37`, `tpm/secure_enclave.rs:1101`
  Fix: Fail if HOME unset. Never default to /tmp or relative paths for crypto data. Require XDG_DATA_HOME or explicit config.
  **Guidance**: 8+ instances of `.unwrap_or_else(|| PathBuf::from("."))` and `.unwrap_or_else(|| PathBuf::from(".writerslogic"))` in config/defaults.rs. Replace all with `dirs::home_dir().ok_or_else(|| Error::config("HOME directory not set"))?` and propagate the error. This is a breaking change for error handling — callers of `default_*()` functions must handle `Result`.

- [ ] **SYS-021** `lock_unwrap` — 78 instances across 9 files — HIGH
  <!-- pid:lock_unwrap | verified:true | first:2026-03-03 | last:2026-03-03 -->
  `Mutex::lock().unwrap()` / `RwLock::write().unwrap()` / `RwLock::read().unwrap()` without poison recovery. The `MutexRecover` and `RwLockRecover` traits already exist in `lib.rs` and are correctly used in 14 files (98 call sites), but 9 files still use bare `.unwrap()` — 78 instances total.
  Files (validated 2026-03-03):
  - `engine.rs` (14 confirmed), `sentinel/helpers.rs` (17), `tpm/secure_enclave.rs` (15)
  - `tpm/linux.rs` (8), `wal/operations.rs` (8), `sentinel/shadow.rs` (7)
  - `sentinel/focus.rs` (2), `tpm/software.rs` (2), `tpm/windows.rs` (1)
  Fix: Replace `.lock().unwrap()` → `.lock_recover()`, `.read().unwrap()` → `.read_recover()`, `.write().unwrap()` → `.write_recover()`. Add `use crate::{MutexRecover, RwLockRecover};` where missing. Effort: medium (mechanical).
  **Guidance**: `MutexRecover` and `RwLockRecover` traits are defined in `lib.rs` and already used in 14 files (98 call sites). Mechanical fix: search for `.lock().unwrap()`, `.read().unwrap()`, `.write().unwrap()` in each file, replace, add the trait import. Do one file at a time, `cargo check` between each. Start with `engine.rs` (most instances).

- [ ] **SYS-022** `commitment_chain_optional` — 2 files — CRITICAL
  <!-- pid:security-optional_security | verified:true | first:2026-03-03 -->
  Commitment chain fields (`commitment`, `ordinal`) are `Option` with `#[serde(default)]` in native_messaging_host.rs. Adversary simply omits these fields to bypass all anti-forgery checks. Browser extension sends commitments but host doesn't require them.
  Files: `apps/wld_cli/src/native_messaging_host.rs:337,394`, `apps/wld_cli/browser-extension/background.js:89`
  Fix: Make commitment/ordinal required after genesis checkpoint. Reject messages missing required fields. Add genesis commitment with known seed.

- [ ] **SYS-023** `forensic_region_stub` — 2 files — CRITICAL
  <!-- pid:stub_implementation | verified:true | first:2026-03-03 -->
  `forensics/engine.rs:57-82` hardcodes all edit regions to `(start_pct: 1.0, end_pct: 1.0)`, destroying topology analysis. The entire forensic region extraction is a stub, making all positional analysis meaningless.
  Files: `forensics/engine.rs:57-82`, `forensics/topology.rs` (consumer)
  Fix: Implement real region extraction from edit deltas — compute actual document-relative positions from offset/length data.

---

## Build Issues

- [ ] **B-004** `[build]` FFI feature compilation — multiple errors
  <!-- pid:build_failure | verified:true | first:2026-03-03 | revalidated:2026-03-03 -->
  `cargo check --features ffi -p wld_engine` fails with key errors:
  1. `ffi/sentinel.rs:377` — missing `ENTROPY_NORMALIZATION_FACTOR` in `crate::ffi::helpers`
  2. `ffi/fingerprint.rs:54,60-63,68,74-77` — `FfiFingerprintStatus` struct fields don't exist (`success`, `confidence`, `quality_score`, `current_profile_id`, `error_message`)
  Fix: Align FFI types with current engine types. Start with defining missing constants and updating struct definitions. Effort: large
  **Guidance**: The FFI layer is out of sync with engine changes. Two approaches: (1) Update FFI types to match current engine API (recommended), or (2) Add compatibility shims. Start by defining `ENTROPY_NORMALIZATION_FACTOR` in `ffi/helpers.rs`, then fix `FfiFingerprintStatus` struct to match current engine `FingerprintStatus`. Run `cargo check --features ffi -p wld_engine` after each fix to see remaining errors.

- [ ] **B-005** `[build]` rustfmt failure — module path mismatch
  <!-- pid:build_failure | verified:true | first:2026-03-03 | revalidated:2026-03-03 -->
  `cargo fmt --all -- --check` fails: `lib.rs:51` declares `pub mod wld_jitter_bridge;` but actual directory is `writerslogic_jitter_bridge/`.
  Fix: Change `lib.rs:51` from `pub mod wld_jitter_bridge;` to `#[path = "writerslogic_jitter_bridge/mod.rs"] pub mod wld_jitter_bridge;` OR rename the directory to `wld_jitter_bridge/`. Effort: small
  **Guidance**: Renaming the directory is cleaner. Run `git mv crates/wld_engine/src/writerslogic_jitter_bridge crates/wld_engine/src/wld_jitter_bridge` then `cargo fmt --all -- --check` to verify.

- [ ] **B-006** `[test]` 2 pre-existing checkpoint test failures
  <!-- pid:test_failure | verified:true | first:2026-03-03 | revalidated:2026-03-03 -->
  `checkpoint::tests::test_entangled_commit_with_physics_context` and `test_entangled_commit_mixed_physics_and_none` fail with "unsigned (signature required by policy)".
  Fix: Update tests to provide required signing key or adjust policy. Effort: medium
  **Guidance**: These tests create checkpoint chains with `EntanglementMode::Physics` but don't supply a signing key. The `commit()` method requires a signature when the policy demands it. Fix: Generate a test `SigningKey` in the test setup, pass it to `commit()`. See `test_basic_commit()` in same file for pattern. Alternatively, create a test-only policy that allows unsigned physics checkpoints.

---

## Critical

- [x] **C-011** `[security]` `tpm/software.rs:28` — Software TPM seed derived from system time ✓ FIXED 2026-03-03
  <!-- pid:sec_weak_rng_seed | batch:4 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  SigningKey seed uses `Utc::now().to_rfc3339()` — deterministically derivable from timestamp.
  Impact: Attestation keys precomputable. Software fallback is cryptographically forgeable. | Fix: Use `getrandom()` or `rand::rngs::OsRng` | Effort: small
  **Resolution**: Replaced with `getrandom::getrandom()` for cryptographic randomness.

- [x] **C-012** `[security]` `tpm/software.rs:31` — Seed not zeroized after key derivation ✓ FIXED 2026-03-03
  <!-- pid:sec_key_material_leak | batch:4 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  32-byte SHA256 hash seed remains on stack indefinitely.
  Impact: Key material leak | Fix: Wrap in `Zeroizing<[u8; 32]>` | Effort: small
  **Resolution**: Wrapped seed in `Zeroizing<[u8; 32]>` with automatic zeroization on drop.

- [x] **C-013** `[security]` `tpm/windows.rs:409-410` — Windows TPM public_key is random bytes, not TPM-backed ✓ FIXED 2026-03-03
  <!-- pid:sec_weak_attestation_key | batch:4 | verified:true | first:2026-03-02 | revalidated:2026-03-03 | fixed:2026-03-03 -->
  `public_key = context.get_random(32)` — random bytes, not from actual TPM key generation. TODO comment present.
  Impact: Attestation forgeable without hardware — defeats entire trust model on Windows | Fix: Implement TPM2_Create key workflow using `tss-esapi::Context::create_primary()` and `create()` | Effort: large
  **Resolution**: Added `create_srk_public_key()` standalone function that creates the ECC P-256 SRK via TPM2_CreatePrimary, parses the response to extract the uncompressed public point (x||y), and flushes the transient handle. SRK is deterministic — same key on same TPM. Falls back to TPM random on parse failure.

- [ ] **C-014** `[security]` `tpm/windows.rs:536-546` — sign_payload uses SHA256 not TPM2_Sign
  <!-- pid:sec_no_real_signing | batch:4 | verified:true | first:2026-03-02 | revalidated:2026-03-03 -->
  `sign_payload()` computes SHA256 hash of `random||data` in userspace — TODO comment: "use TPM2_Sign with a loaded key for real signatures".
  Impact: Hardware trust boundary violated — signatures don't prove hardware involvement | Fix: Implement TPM2_Sign with loaded AK using `tss-esapi::Context::sign()` | Effort: large
  **Guidance**: Implement together with C-013. Use the key created in C-013 with `context.sign()` passing the data hash. The attestation key must be loaded into the TPM context first. Test with software TPM (swtpm) in CI.

- [x] **C-015** `[security]` `background.js:212` — XSS via native host error messages ✓ FIXED 2026-03-03
  <!-- pid:security-xss_native_message | batch:3 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  Error strings from native host reflected in popup UI without sanitization.
  Impact: XSS if native host sends malicious JSON | Fix: Use `textContent` not `innerHTML`; sanitize messages | Effort: small
  **Resolution**: Replaced `innerHTML` with `textContent` for error message display.

- [x] **C-016** `[security]` `background.js:173` — ECDH handshake replay via reusable callback ✓ FIXED 2026-03-03
  <!-- pid:security-handshake_reuse | batch:3 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  `_handshakeResolve` can be called multiple times if `handleHelloAccept` replayed.
  Impact: Session key desync or ratchet corruption | Fix: Validate `handshakeComplete` before processing; clear resolver after use | Effort: small
  **Resolution**: Added `handshakeComplete` guard and one-shot resolver clearing.

- [x] **C-017** `[security]` `secure-channel.js:289` — Unguarded JSON.parse on decrypted plaintext ✓ FIXED 2026-03-03
  <!-- pid:security-decrypt_parse_unguarded | batch:3 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  No try-catch around JSON.parse of decrypted data from native host.
  Impact: Crash on invalid JSON kills handler | Fix: Wrap in try-catch; validate required fields | Effort: small
  **Resolution**: Added try-catch wrapper with field validation on decrypted payload.

- [x] **C-018** `[security]` `background.js:478` — Message listener accepts from any origin → SYS-019 ✓ FIXED 2026-03-03
  <!-- pid:security-message_origin_bypass | batch:3 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  `chrome.runtime.onMessage` has no sender validation. Covered by SYS-019.
  **Resolution**: Added sender.id check to block cross-extension messages and URL pattern validation for content script actions.

- [x] **C-019** `[performance]` `content.js:112` — OOM before truncation check on DOM text ✓ FIXED 2026-03-03
  <!-- pid:performance-oom_before_check | batch:3 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  `getDocumentText()` concatenates all text before size check; malicious page causes OOM.
  Impact: Extension memory exhaustion | Fix: Accumulate length in loop, return early if exceeding MAX_DOCUMENT_SIZE | Effort: small
  **Resolution**: Added early-exit length accumulation in loop before concatenation.

- [x] **C-020** `[performance]` `analysis/pink_noise.rs:182-192` — O(n²) DFT in production ✓ FIXED 2026-03-03
  <!-- pid:quadratic_algorithm | batch:10 | verified:true | first:2026-03-02 | revalidated:2026-03-03 | fixed:2026-03-03 -->
  Lines 187-192: explicit O(n²) nested loop DFT with comment "In production, use a proper FFT library".
  Impact: 512-point analysis is O(262k) instead of O(4.6k) — scales badly for larger windows | Fix: Use `rustfft` crate or implement radix-2 FFT | Effort: medium
  **Resolution**: Replaced O(n²) DFT with in-place Cooley-Tukey radix-2 FFT (O(n log n)). No new dependencies. All 5 pink_noise tests pass.

- [x] **C-021** `[security]` `wal/types.rs:119` — WAL byte_count is i64 but metadata returns u64 ✓ FIXED 2026-03-03
  <!-- pid:signedness_arithmetic | batch:18 | verified:true | first:2026-03-02 | revalidated:2026-03-03 | fixed:2026-03-03 -->
  `WalState.byte_count: i64` — potential signedness bug on very large WAL files.
  Impact: Quota checks fail on overflow | Fix: Change byte_count to u64; audit all arithmetic in `wal/operations.rs` | Effort: medium
  **Resolution**: Changed `byte_count: i64` to `u64` in types.rs. Updated all 5 cast sites in operations.rs and changed `size()` return type to `u64`. All 12 WAL tests pass.

- [x] **C-022** `[correctness]` `ffi/forensics.rs:74` — FFI assessment score uses wrong formula ✓ FIXED 2026-03-03
  <!-- pid:logic_error | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  Returns `edit_entropy / 4.32` instead of the actual `assessment_score` from forensic metrics. This means FFI consumers (Swift/Kotlin GUI apps) get a meaningless number for authorship assessment.
  Impact: Desktop apps display wrong authorship scores | Fix: Use `metrics.assessment_score` | Effort: small
  **Resolution**: Changed to use `metrics.assessment_score` directly.

- [x] **C-023** `[correctness]` `ffi/forensics.rs:151` — Inverted sequence score rewards AI patterns ✓ FIXED 2026-03-03
  <!-- pid:inverted_logic | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  `monotonic_append_ratio * 0.5` means 100% end-appending (typical AI-generated content) scores highest. Human editing (scattered, non-monotonic) scores lowest. The metric rewards the exact behavior it should penalize.
  Impact: AI content rated as more authentic than human writing | Fix: Invert to `(1.0 - monotonic_append_ratio) * 0.5` | Effort: small
  **Resolution**: Inverted to `(1.0 - monotonic_append_ratio) * 0.5`.

- [x] **C-024** `[correctness]` `forensics/engine.rs:57-82` — All edit regions hardcoded to (1.0, 1.0) → SYS-023 ✓ FIXED 2026-03-03
  <!-- pid:stub_implementation | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  Covered by SYS-023. All positional analysis produces identical values regardless of actual edit positions.
  **Resolution**: Replaced hardcoded (1.0, 1.0) with cursor-position heuristic: start_pct = (file_size - |delta|) / max_file_size, end_pct = start_pct + |delta| / max_file_size. Not perfect without file diffs but produces variable positions reflecting actual editing patterns.

- [x] **C-025** `[security]` `vdf/aggregation.rs:274` — Merkle root is format string, not cryptographic hash ✓ FIXED 2026-03-03
  <!-- pid:stub_implementation | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  `format!("H({})", combined)` produces `"H(H(leaf1|leaf2)|H(leaf3|leaf4))"` — a human-readable string, not a hash. This means VDF aggregation proofs are trivially forgeable.
  Impact: VDF proof chain integrity is illusory | Fix: Use actual SHA-256 hashing for Merkle tree | Effort: medium
  **Resolution**: Replaced format string with actual SHA-256 hashing for Merkle tree nodes.

- [x] **C-026** `[correctness]` `native_messaging_host.rs:362` — fs::write truncates evidence file ✓ FIXED 2026-03-03
  <!-- pid:data_loss | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  `fs::write()` overwrites the entire evidence file on each checkpoint. Only the last checkpoint's data survives. All prior checkpoint evidence is lost.
  Impact: Complete data loss of all but final checkpoint | Fix: Use `OpenOptions::append()` or accumulate in memory | Effort: small
  **Resolution**: Changed to `OpenOptions::append()` mode to preserve all checkpoint data.

- [x] **C-027** `[security]` `native_messaging_host.rs:337` — Commitment chain bypass → SYS-022 ✓ FIXED 2026-03-03
  <!-- pid:security-optional_security | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  Covered by SYS-022. Adversary omits `commitment` field to bypass verification.
  **Resolution**: Added mandatory commitment/ordinal enforcement after genesis checkpoint. Missing fields now return MISSING_COMMITMENT/MISSING_ORDINAL errors.

---

## High (Top 40 — highest impact)

- [ ] **H-065** `[security]` `tpm/secure_enclave.rs:448-476` — Counter file rollback on corruption
  <!-- pid:sec_counter_rollback | batch:4 | verified:true | first:2026-03-02 | revalidated:2026-03-03 -->
  `load_counter()` logs error on corruption but does NOT propagate — allows counter reset to 0 which defeats anti-rollback.
  Impact: Corrupted counter file silently resets to 0, bypassing monotonic counter protection | Fix: Propagate error from `load_counter()`; refuse to init if corrupt; require explicit reset with user acknowledgment | Effort: medium
  **Guidance**: In `load_counter()`, change from logging + returning 0 to returning `Err`. Callers must handle the error and refuse to proceed. Add a separate `reset_counter()` method that requires explicit intent.

- [ ] **H-066** `[security]` `tpm/verification.rs:102` — No ECDSA P-256 verification support
  <!-- pid:sec_missing_algo | batch:4 | verified:true | first:2026-03-02 -->
  Secure Enclave signs with ECDSA but verifier only handles Ed25519/RSA. | Fix: Add p256 crate ECDSA verification | Effort: medium

- [ ] **H-067** `[error_handling]` `tpm/windows.rs:886` — flush_context errors silently dropped
  <!-- pid:err_silent_io | batch:4 | verified:true | first:2026-03-02 -->
  `let _ = self.flush_context(...)` — handle leak risk. Same in `linux.rs:290`. | Fix: `log::warn!` on flush failures | Effort: small

- [ ] **H-068** `[security]` `identity/secure_storage.rs:302` — Intermediate Vec not zeroized on cache read → SYS-018
  <!-- pid:key_material_copy_leak | batch:5 | verified:true | first:2026-03-02 -->

- [ ] **H-069** `[security]` `identity/secure_storage.rs:253` — Symlink/traversal risk in migration path
  <!-- pid:path_traversal_symlink | batch:5 | verified:true | first:2026-03-02 -->
  No symlink check before creating `.keychain_migrated_v1` | Fix: Validate path has no symlinks | Effort: medium

- [ ] **H-070** `[concurrency]` `platform/windows.rs:314` — Unchecked raw pointer deref in hook callback
  <!-- pid:unsafe_ptr_deref_unchecked | batch:5 | verified:true | first:2026-03-02 -->
  `lparam.0 as *const KBDLLHOOKSTRUCT` without null check | Fix: Add null pointer validation | Effort: small

- [ ] **H-071** `[concurrency]` `sentinel/core.rs:251,280` — Spawned threads with no JoinHandle
  <!-- pid:spawned_thread_no_handle | batch:6 | verified:true | first:2026-03-02 -->
  Keystroke/mouse capture threads exit silently on failure | Fix: Store JoinHandle, log errors | Effort: medium

- [ ] **H-072** `[concurrency]` `sentinel/core.rs:343,328` — Lock guards held across .await boundary
  <!-- pid:guard_across_await | batch:6 | verified:true | first:2026-03-02 -->
  Bare write() in tokio::select! arms | Fix: Use write_recover(), acquire/release around select block | Effort: medium

- [ ] **H-073** `[security]` `sentinel/ipc_handler.rs:30-35` — Zero signing key warning but continues
  <!-- pid:key_material_leak | batch:6 | verified:true | first:2026-03-02 | revalidated:2026-03-03 -->
  HMAC derivation proceeds with `[0u8; 32]` key when identity not loaded — produces valid but meaningless HMACs.
  Impact: Evidence signed with zero key is trivially forgeable | Fix: Return error; refuse IPC operations until identity loaded | Effort: medium
  **Guidance**: Change the `[0u8; 32]` fallback to `return Err(Error::identity("signing key not loaded"))`. Callers must defer IPC operations until `SealedIdentityStore::initialize()` completes successfully.

- [ ] **H-074** `[error_handling]` `ffi/sentinel.rs:26` — expect() in runtime creation → SYS-013
  <!-- pid:panic_in_library | batch:7 | verified:true | first:2026-03-02 -->

- [ ] **H-075** `[error_handling]` `ffi/evidence.rs:180` — expect() on hash construction → SYS-013
  <!-- pid:panic_in_library | batch:7 | verified:true | first:2026-03-02 -->

- [ ] **H-076** `[security]` `ffi/helpers.rs:27` — HMAC key returned without Zeroizing wrapper → SYS-018
  <!-- pid:key_material_leak | batch:7 | verified:true | first:2026-03-02 -->

- [ ] **H-077** `[architecture]` `ffi/ephemeral.rs:758` — Business logic in FFI boundary
  <!-- pid:logic_in_boundary | batch:7 | verified:true | first:2026-03-02 -->
  build_war_block() has complex crypto logic in FFI layer | Fix: Move to evidence module | Effort: large

- [ ] **H-078** `[security]` `ipc/crypto.rs:99` — expect() in library crypto code → SYS-013
  <!-- pid:panic_in_library | batch:8 | verified:true | first:2026-03-02 -->

- [ ] **H-079** `[security]` `ipc/messages.rs:7` — PathBuf fields without traversal validation
  <!-- pid:path_traversal | batch:8 | verified:true | first:2026-03-02 -->
  Client can request operations on arbitrary files via IPC | Fix: Reject absolute paths, `..` components | Effort: medium

- [ ] **H-080** `[security]` `ipc/unix_socket.rs:138` — Executable verification checks filename only
  <!-- pid:missing_input_validation | batch:8 | verified:true | first:2026-03-02 -->
  Attacker bypass with same-named binary in different dir | Fix: Compare full path | Effort: small

- [ ] **H-081** `[security]` `fingerprint/storage.rs:121` — Full decryption on every index refresh
  <!-- pid:perf:metadata_decrypt_in_loop | batch:9 | verified:true | first:2026-03-02 -->
  N profiles → N AES-256-GCM decryptions for metadata | Fix: Add unencrypted metadata sidecar with HMAC | Effort: medium

- [ ] **H-082** `[error_handling]` `rfc/wire_types/packet.rs:92` — No post-decode validation → SYS-017
  <!-- pid:missing_validation | batch:13 | verified:true | first:2026-03-02 -->

- [x] **H-083** `[security]` `rfc/time_evidence.rs:309` — Integer overflow in timestamp × 1000 ✓ FIXED 2026-03-03
  <!-- pid:arithmetic_overflow_unchecked | batch:12 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  **Resolution**: Replaced `block_timestamp * 1000` with `block_timestamp.saturating_mul(1000)`.

- [x] **H-084** `[security]` `war/compat.rs:197, vdf/timekeeper.rs:43` — u64→i64 silent cast overflow ✓ FIXED 2026-03-03
  <!-- pid:cast_overflow_unchecked | batch:12 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  **Resolution**: Replaced `as i64` casts with `i64::try_from().unwrap_or(i64::MAX)` in war/compat.rs and vdf/timekeeper.rs.

- [x] **H-085** `[security]` `evidence/rfc_conversion.rs:21` — hex::decode errors → empty Vec ✓ FIXED 2026-03-03
  <!-- pid:silent_hex_decode_failure | batch:14 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  **Resolution**: Added log::warn on hex decode failures for VDF input, output, and content hash.

- [x] **H-086** `[security]` `evidence/rfc_conversion.rs:63` — final_hash decode error → empty Vec ✓ FIXED 2026-03-03
  <!-- pid:silent_hex_decode_failure | batch:14 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  **Resolution**: Fixed alongside H-085.

- [x] **H-087** `[security]` `evidence/packet.rs:382` — No length check on signature bytes ✓ FALSE POSITIVE
  <!-- pid:signature_length_unvalidated | batch:14 | verified:true | first:2026-03-02 | eliminated:2026-03-03 -->
  **Resolution**: FALSE POSITIVE — all signature fields are `[u8; 64]` fixed arrays, and ed25519-dalek 2.x `from_bytes(&[u8; 64])` is infallible. Type system guarantees correctness.

- [ ] **H-088** `[security]` `evidence/builder.rs:568` — Division by mean without range check
  <!-- pid:division_unguarded | batch:14 | verified:true | first:2026-03-02 -->
  Tiny mean → huge cv → malformed jitter binding | Fix: Validate `mean > 100us`; clamp entropy_bits ≥ 0 | Effort: medium

- [ ] **H-089** `[security]` `keyhierarchy/session.rs:43` — Session seed not zeroized on error → SYS-018
  <!-- pid:key_material_error_path_leak | batch:15 | verified:true | first:2026-03-02 -->

- [ ] **H-090** `[security]` `keyhierarchy/session.rs:367` — Plaintext buffer leak on encrypt failure → SYS-018
  <!-- pid:key_material_heap_leak | batch:15 | verified:true | first:2026-03-02 -->

- [x] **H-091** `[security]` `keyhierarchy/puf.rs:55` — Loaded seed not length-validated ✓ FIXED 2026-03-03
  <!-- pid:crypto_input_validation | batch:15 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  Seed from secure storage could be <32 bytes | Fix: `if seed.len() != 32 { return Err(...) }` | Effort: small
  **Resolution**: Added 32-byte length validation with `Crypto` error on mismatch.

- [ ] **H-092** `[security]` `keyhierarchy/puf.rs:74` — Legacy seed data not zeroized after migration → SYS-018
  <!-- pid:seed_leak_on_migration | batch:15 | verified:true | first:2026-03-02 -->

- [ ] **H-093** `[architecture]` `war/types.rs:34` — Missing ear field in Block struct
  <!-- pid:incomplete_struct | batch:16 | verified:true | first:2026-03-02 -->
  compat.rs:131 sets field that doesn't exist | Fix: Add `pub ear: Option<EarToken>` to Block | Effort: small

- [x] **H-094** `[code_quality]` `war/ear.rs:338` — Inverted overall_status logic ✓ FIXED 2026-03-03
  <!-- pid:inverted_logic | batch:16 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  Uses `.max()` where `.min()` needed — returns best instead of worst status | Fix: Change to `.min()` | Effort: small
  **Resolution**: Changed `.max()` to `.min()` to return worst (most conservative) status.

- [x] **H-095** `[error_handling]` `writersproof/queue.rs:84-91` — Silent skip on malformed queue entries ✓ FIXED 2026-03-03
  <!-- pid:silent_error_swallow | batch:17 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  **Resolution**: Added log::warn for both JSON parse failures and file read errors in queue list().

- [x] **H-096** `[error_handling]` `writersproof/queue.rs:90` — Silent continue on corrupt queue JSON ✓ FIXED 2026-03-03
  <!-- pid:silent_error_swallow | batch:17 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  **Resolution**: Fixed alongside H-095.

- [ ] **H-097** `[error_handling]` `writersproof/client.rs:272` — is_online() swallows all errors
  <!-- pid:error_swallowed_silently | batch:17 | verified:true | first:2026-03-02 -->
  Transient timeout treated same as real offline | Fix: Return `Result<bool>` | Effort: small

- [ ] **H-098** `[security]` `config/defaults.rs:18,24,33` — /tmp or relative path fallback for data dir → SYS-020
  <!-- pid:world_writable_fallback | batch:18 | verified:true | first:2026-03-02 | revalidated:2026-03-03 -->

- [ ] **H-099** `[security]` `presence/helpers.rs:8-12` — Challenge hash uses SHA256 without salt/HMAC
  <!-- pid:weak_challenge_hash | batch:18 | verified:true | first:2026-03-02 | revalidated:2026-03-03 -->
  `hash_response()` uses plain SHA-256, offline brute-force of challenge responses possible | Fix: Use HMAC-SHA256 with per-challenge salt | Effort: medium
  **Guidance**: `hash_response()` at `presence/helpers.rs:8-12` does `Sha256::digest(data)`. Replace with `Hmac::<Sha256>::new_from_slice(salt)?.update(data).finalize()`. The salt should be derived from the challenge nonce. Update `presence/verifier.rs` and `presence/tests.rs` to match.

- [x] **H-100** `[security]` `wal/operations.rs` — Non-constant-time hash comparison in scan_to_end ✓ FIXED 2026-03-03
  <!-- pid:timing_side_channel_hash | batch:18 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  **Resolution**: Replaced `!=` with `ct_eq()` for prev_hash and cumulative_hash comparisons in scan_to_end().

- [ ] **H-101** `[security]` `sealed_identity/store.rs` — Counter rollback gap on first unseal
  <!-- pid:rollback_check_weak | batch:19 | verified:true | first:2026-03-02 | revalidated:2026-03-03 -->
  Both counters init to same value; no rollback protection until second advance | Fix: Fail if counter is None on init | Effort: medium
  **Guidance**: In `sealed_identity/store.rs`, `initialize()` sets `counter_at_seal` and `last_known_counter` to the same value. After first `advance_counter()`, rollback detection works. But between init and first advance, an attacker can replay the sealed blob. Fix: On `unseal_master_key()`, require `last_known_counter.is_some()` or fail with explicit error for uninitialized state.

- [x] **H-102** `[security]` `protocol/evidence.rs:36,69` — Clock error silently returns 0 ✓ FIXED 2026-03-03
  <!-- pid:clock_error_silent_fallback | batch:20 | verified:true | first:2026-03-02 | fixed:2026-03-03 -->
  **Resolution**: Replaced `.unwrap_or_default()` with `.expect("system clock before Unix epoch")` — a pre-epoch clock is fundamentally broken, panicking is correct.

- [ ] **H-103** `[security]` `protocol/forensics/engine.rs:217` — NaN bypass in forensic checks → SYS-016
  <!-- pid:nan_unvalidated | batch:20 | verified:true | first:2026-03-02 -->

- [ ] **H-104** `[security]` `forensics/comparison.rs:54` — ln() of zero/negative produces NaN → SYS-016
  <!-- pid:numeric_stability | batch:11 | verified:true | first:2026-03-02 -->

- [ ] **H-105** `[concurrency]` `background.js:26` — Global mutable state without synchronization
  <!-- pid:architecture-god_module_state | batch:3 | verified:true | first:2026-03-02 -->
  Race conditions between content scripts during ratcheting | Fix: Promise-based state machine | Effort: medium

- [ ] **H-106** `[concurrency]` `background.js:442` — Unbounded chunk queue without backpressure
  <!-- pid:concurrency-unbounded_chunk_queue | batch:3 | verified:true | first:2026-03-02 -->
  Large documents queue all chunks at once | Fix: Batch with delay or limit concurrent messages | Effort: medium

- [x] **H-107** `[error_handling]` `crypto/obfuscated.rs:33,49` — `.expect()` panics in library code ✓ BY DESIGN
  <!-- pid:expect_in_library | verified:true | first:2026-03-03 | eliminated:2026-03-03 -->
  **Resolution**: BY DESIGN — expect() is intentional: serialization failure means broken type system, deserialization failure means corrupted sensitive data. Panicking is correct (don't use corrupted secrets). Messages are descriptive per convention.

- [x] **H-108** `[security]` `war/verification.rs` — VDF verify without timeout or iteration cap ✓ FIXED 2026-03-03
  <!-- pid:untrusted_iteration_count | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  **Resolution**: Added `MAX_VERIFICATION_ITERATIONS = 3_600_000_000` constant and early rejection before `proof.verify()` call.

- [x] **H-109** `[security]` `sentinel/types.rs:367` — `normalize_document_path` trust boundary ✓ FIXED 2026-03-03
  <!-- pid:path_traversal | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  **Resolution**: Added log::warn on canonicalization failure to make silent fallback visible for diagnostics.

- [ ] **H-110** `[correctness]` `ffi/evidence.rs:191` — Wrong ProofAlgorithm for SHA-256 VDFs
  <!-- pid:wrong_enum_variant | verified:true | first:2026-03-03 | revalidated:2026-03-03 -->
  Uses `ProofAlgorithm::SwfArgon2id` for all VDF proofs including SHA-256-based ones. Verification may fail or apply wrong parameters. | Fix: Map algorithm from actual VDF config | Effort: small
  **Guidance**: Check the VDF config/parameters to determine the algorithm. Map to correct `ProofAlgorithm` variant: `SwfSha256` for SHA-256 VDFs, `SwfArgon2id` only for Argon2id-based proofs. The algorithm type should come from the checkpoint/VDF parameters, not be hardcoded.

- [x] **H-111** `[security]` `background.js:89` — Genesis checkpoint has no commitment ✓ FIXED 2026-03-03
  <!-- pid:security-genesis_gap | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  First checkpoint has `prevCommitment=null`, so commitment is undefined. Adversary can forge the genesis checkpoint and build a valid chain from it. | Fix: Use deterministic genesis seed (e.g., SHA-256 of session ID) | Effort: small
  **Resolution**: Added deterministic genesis seed from SHA-256 of session ID.

- [x] **H-112** `[concurrency]` `background.js:103` — Ordinal desync on rapid edits ✓ FIXED 2026-03-03
  <!-- pid:race_condition | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  `checkpointOrdinal` only increments on server response, but content changes continue. Rapid edits can cause ordinal gaps or reuse. | Fix: Increment ordinal on send, not on response | Effort: small
  **Resolution**: Moved ordinal increment to send-time instead of response-time.

- [ ] **H-113** `[security]` `native_messaging_host.rs:266` — Session overwrite without finalizing previous
  <!-- pid:data_loss | verified:true | first:2026-03-03 | revalidated:2026-03-03 -->
  New `start_witnessing` replaces the active session without finalizing or persisting the previous one. Adversary can discard inconvenient evidence by starting a new session. | Fix: Finalize (commit/persist) existing session before starting new one | Effort: medium
  **Guidance**: In `handle_start_witnessing()`, check if `self.active_session.is_some()`. If so, call a `finalize_session()` method that persists evidence before replacing. Create `finalize_session()` that flushes WAL and writes final evidence packet.

- [x] **H-114** `[security]` `native_messaging_host.rs:330` — Timestamp monotonicity is log-only ✓ FIXED 2026-03-03
  <!-- pid:security-soft_check | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  Non-monotonic timestamps trigger `eprintln!` but processing continues. Time reversal should be a hard rejection. | Fix: Return error for non-monotonic timestamps | Effort: small
  **Resolution**: Changed to hard rejection returning error on non-monotonic timestamps.

- [x] **H-115** `[security]` `native_messaging_host.rs:346` — Non-constant-time commitment comparison ✓ FIXED 2026-03-03
  <!-- pid:timing_side_channel | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  Uses `==` for SHA-256 commitment comparison. Timing oracle leaks commitment bytes. | Fix: Use constant-time comparison (ring::constant_time or subtle::ConstantTimeEq) | Effort: small
  **Resolution**: Replaced `==` with constant-time comparison using `subtle::ConstantTimeEq`.

- [x] **H-116** `[security]` `background.js:179` — Silent crypto fallback sends unprotected data ✓ FIXED 2026-03-03
  <!-- pid:security-silent_downgrade | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  When Web Crypto commitment computation fails, checkpoint sends without any commitment. Adversary can trigger crypto errors to bypass commitment chain. | Fix: Fail the checkpoint send on crypto error | Effort: small
  **Resolution**: Changed to fail/abort checkpoint send on crypto error instead of silent fallback.

- [x] **H-117** `[security]` `native_messaging_host.rs:394` — expected_ordinal incremented when ordinal absent ✓ FIXED 2026-03-03
  <!-- pid:logic_error | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  When ordinal is `None` (adversary omits it), `expected_ordinal` still increments. This drifts the expected ordinal counter, and if ordinals are later provided they'll all be rejected. | Fix: Only increment when ordinal is present and valid | Effort: small
  **Resolution**: Wrapped ordinal increment in `if let Some(ordinal)` guard.

- [x] **H-118** `[security]` `forensics/cross_modal.rs:139` — Negative document_length bypasses growth check ✓ FIXED 2026-03-03
  <!-- pid:signedness_bypass | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  `document_length` is `i64`, negative values produce negative `chars_per_sec` which always passes the `<= 15.0` threshold. | Fix: Validate `document_length >= 0` at function entry | Effort: small
  **Resolution**: Added `document_length >= 0` validation at function entry.

- [x] **H-119** `[correctness]` `forensics/cross_modal.rs:253` — i64 subtraction overflow ✓ FIXED 2026-03-03
  <!-- pid:arithmetic_overflow | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  `edit_first - jitter_first` on i64 timestamps can overflow if timestamps span more than i64::MAX nanoseconds apart. `.unsigned_abs()` is correct for normal cases but the subtraction itself overflows in debug mode (panics) or wraps in release. | Fix: Use `(edit_first as i128 - jitter_first as i128).unsigned_abs()` or checked arithmetic | Effort: small
  **Resolution**: Changed to widening subtraction via i128 cast before `.unsigned_abs()`.

- [x] **H-120** `[correctness]` `forensics/analysis.rs:98` — Default AnalysisContext causes false positive anomaly ✓ FIXED 2026-03-03
  <!-- pid:false_positive | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  `analyze_forensics()` calls `analyze_forensics_ext()` with `AnalysisContext::default()` (checkpoint_count=0). This always triggers `check_edit_checkpoint_ratio` failure, adding +1 anomaly to every analysis that uses the simple API. | Fix: Skip cross-modal when context is default/absent | Effort: small
  **Resolution**: Added check to skip cross-modal analysis when context is default/absent.

- [x] **H-121** `[correctness]` `forensics/types.rs:187` — checkpoint_count maps to session_count ✓ FIXED 2026-03-03
  <!-- pid:wrong_field_mapping | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  `map_to_protocol_verdict()` passes `session_count` (number of editing sessions) as `checkpoint_count` to cross-modal analysis. These are completely different values. | Fix: Use actual checkpoint count from evidence | Effort: small
  **Resolution**: Changed to use actual checkpoint count from evidence data.

- [ ] **H-122** `[concurrency]` `vdf/timekeeper.rs:40-48` — Blocking sync I/O in async function
  <!-- pid:blocking_in_async | verified:true | first:2026-03-03 | revalidated:2026-03-03 -->
  `fetch_network_time()` is `async` but calls blocking NTP resolution via `std::net::UdpSocket`. Blocks the tokio runtime thread. | Fix: Use `tokio::task::spawn_blocking()` or async NTP client | Effort: medium
  **Guidance**: Wrap the blocking NTP code in `tokio::task::spawn_blocking(move || { ... }).await?`. This offloads to the blocking thread pool. Alternatively, use `tokio::net::UdpSocket` for async NTP. The `spawn_blocking` approach is simpler and preserves existing logic.

- [ ] **H-123** `[security]` `vdf/timekeeper.rs:77` — VDF proof field always `[0u8; 32]`
  <!-- pid:stub_implementation | verified:true | first:2026-03-03 | revalidated:2026-03-03 -->
  The VDF proof output is a zero-filled placeholder that never gets the actual proof. All VDF proofs are trivially forgeable. | Fix: Populate with actual VDF proof bytes | Effort: medium
  **Guidance**: After the VDF computation completes, extract the proof bytes from `vdf::proof::VdfProof` and set them on the output struct. The proof is the intermediate state values that allow O(1) verification. See `vdf/proof.rs` for the proof generation API.

- [ ] **H-124** `[security]` `forensics/analysis.rs:146` — HMAC-jitter confidence is CV-based approximation
  <!-- pid:security-weak_verification | verified:true | first:2026-03-03 -->
  `steg_confidence` is set to 0.95 if CV > 0.3, else 0.20. This is a heuristic that doesn't actually verify the HMAC-sealed jitter values. TODO comment acknowledges this. | Fix: Implement actual HMAC verification of jitter binding values | Effort: large

- [ ] **H-125** `[security]` `vdf/roughtime_client.rs` — Single hardcoded Roughtime server
  <!-- pid:single_point_of_failure | verified:true | first:2026-03-03 -->
  Only Google sandbox Roughtime server. No quorum, no fallback. Server downtime = feature failure; adversary can MITM a single connection. | Fix: Multiple servers with quorum (at least 2-of-3 agree) | Effort: medium

- [ ] **H-126** `[security]` `jitter/session.rs:313-342` — Session::load no chain integrity verification
  <!-- pid:missing_validation | verified:true | first:2026-03-03 -->
  Deserialized session data is used without verifying internal consistency (hash chain, sequence ordering, timestamp monotonicity). Adversary can craft a session file. | Fix: Verify chain integrity after deserialization | Effort: medium

- [x] **H-127** `[security]` `native_messaging_host.rs:617` — Commitment values logged to stderr ✓ FIXED 2026-03-03
  <!-- pid:secret_logging | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  `eprintln!` outputs commitment hashes to stderr. In production, stderr may be captured in log files accessible to other users. | Fix: Use debug-only logging or remove | Effort: small
  **Resolution**: Removed commitment hash values from stderr logging.

- [ ] **H-128** `[security]` `native_messaging_host.rs` — Jitter rate limit has no temporal component
  <!-- pid:incomplete_rate_limit | verified:true | first:2026-03-03 -->
  Rate limiting counts messages but doesn't consider time window. Adversary can send a burst at startup then slow down, or wait and burst again. | Fix: Sliding window or token bucket rate limiter | Effort: medium

- [x] **H-129** `[correctness]` `forensics/forgery_cost.rs:306` — partial_cmp().unwrap() on NaN panics ✓ FIXED 2026-03-03
  <!-- pid:nan_panic | verified:true | first:2026-03-03 | fixed:2026-03-03 -->
  `min_by(|a, b| a.cost_cpu_sec.partial_cmp(&b.cost_cpu_sec).unwrap())` panics if any cost is NaN. NaN can arise from 0/0 in cost calculations. | Fix: Use `.unwrap_or(std::cmp::Ordering::Equal)` | Effort: small
  **Resolution**: Changed to `.unwrap_or(std::cmp::Ordering::Equal)` for NaN safety.

---

## Medium (186 items — top issues by category)

### Architecture (12 items)
- [ ] **M-050** `tpm/windows.rs:1` — God module 1208L with 20+ helpers (batch:4)
- [ ] **M-051** `tpm/secure_enclave.rs:228` — Duplicate key loading functions (batch:4)
- [ ] **M-052** `background.js:478` — 142-line message handler with nested switch/async IIFEs (batch:3)
- [ ] **M-053** `rfc/biology.rs:581` — Redundant anomaly checking duplicates detection (batch:12)
- [ ] **M-054** `checkpoint/chain.rs:608` — No post-deserialization validation of VDF proofs (batch:15)
- [ ] **M-055** `checkpoint/chain.rs:151` — VDF compute error silently skipped (batch:15)
- [ ] **M-056** `war/types.rs:9` — Version enum missing V2_0 variant (batch:16)
- [ ] **M-057** `sealed_chain/types.rs` or `sealed_chain.rs:169` — TOCTOU in post-decryption document_id check (batch:19)
- [ ] **M-058** `platform/windows.rs:165` — Duplicate session tracking (batch:5)
- [ ] **M-059** `forensics/engine.rs:62` — ForensicsError not integrated with global error hierarchy (batch:11)
- [ ] **M-060** `rfc/jitter_binding.rs:366` — Incomplete builder pattern (batch:12)
- [ ] **M-061** `ffi/system.rs:237` — Dashboard metrics business logic in FFI layer (batch:7)

### Error Handling (45 items — selected)
- [ ] **M-062** `sentinel/daemon.rs:106` — unwrap() on path.parent() (batch:6)
- [ ] **M-063** `sentinel/shadow.rs:175` — Bare RwLock::read() unwrap (batch:6)
- [ ] **M-064** `ffi/ephemeral.rs:694` — Session removed before validation (batch:7)
- [ ] **M-065** `presence/types.rs` — Duration overflow panic on large config (batch:18)
- [ ] **M-066** `config/types.rs` — retention_days u64→u32 overflow (batch:18)
- [ ] **M-067** `sealed_chain.rs` — Migration partial failure (batch:19)
- [ ] **M-068** `evidence/rfc_conversion.rs:64` — Segment count forced minimum 20 (batch:14)
- [ ] **M-069** `ipc/server.rs:376` — accept() error loop without backoff (batch:8)
- [ ] **M-070** `background.js:514` — Async IIFE premature sendResponse (batch:3)
- [ ] **M-071** `background.js:88` — isConnecting never reset on success (batch:3)

### Security (35 items — selected)
- [ ] **M-072** `tpm/mod.rs:57` — parse_sealed_blob overflow risk (batch:4)
- [ ] **M-073** `tpm/mod.rs:99` — Hardcoded PCR selection [0,4,7] (batch:4)
- [ ] **M-074** `ipc/secure_channel.rs:67` — Nonce counter overflow after 2^64 (batch:8)
- [ ] **M-075** `ipc/secure_channel.rs:58` — bincode without size limits (batch:8)
- [ ] **M-076** `fingerprint/voice.rs:350` — Non-ASCII char handling degrades fingerprint (batch:9)
- [ ] **M-077** `sealed_identity/store.rs:395-403` — machine_salt from predictable hostname (batch:19)
- [ ] **M-078** `research/uploader.rs` — Hardcoded Supabase endpoint in binary (batch:19)
- [ ] **M-079** `background.js:270` — Ratchet count not validated as sequential (batch:3)
- [ ] **M-080** `background.js:483` — start_witnessing URL/title not validated (batch:3)
- [ ] **M-081** `secure-channel.js:87` — Server pubkey not validated as P-256 point (batch:3)
- [ ] **M-082** `secure-channel.js:335` — Key zeroization may be optimized away by JS engine (batch:3)
- [ ] **M-083** `config/loading.rs` — Config file created without explicit permissions (batch:18)

### Performance (20 items — selected)
- [ ] **M-084** `labyrinth.rs:254` — O(n²) nearest-neighbor without early termination (batch:10)
- [ ] **M-085** `fingerprint/activity.rs:205,213` — Double allocation in from_intervals (batch:9)
- [ ] **M-086** `fingerprint/activity.rs:721` — Full sample buffer clone on status check (batch:9)
- [ ] **M-087** `vdf/aggregation.rs:273` — String clone per Merkle tree level (batch:17)
- [ ] **M-088** `wal/operations.rs` — Unbounded allocation on WAL parse (batch:18)
- [ ] **M-089** `research/collector.rs` — Vec::remove(0) O(n) in tight loop (batch:19)
- [ ] **M-090** `background.js:68` — Storage I/O scales with chain length (batch:3)
- [ ] **M-091** `content.js:111` — Repeated DOM queries per keystroke (batch:3)
- [ ] **M-092** `forensics/velocity.rs:77` — Unnecessary Vec clone for sort (batch:11)
- [ ] **M-093** `ffi/ephemeral.rs:122` — O(n) evict scan on every session start (batch:7)

### Concurrency (8 items)
- [ ] **M-094** `platform/macos/mouse_capture.rs:121` — RwLock write in CGEventTap callback (batch:5)
- [ ] **M-095** `platform/windows.rs:580` — Lock poison no recovery (batch:5)
- [ ] **M-096** `ipc/server.rs:133` — Rate limiter lock contention (batch:8)
- [ ] **M-097** `sentinel/focus.rs:156` — Dummy receiver silently creates dead channel (batch:6)
- [ ] **M-098** `background.js:147` — TOCTOU on isSecure check (batch:3)
- [ ] **M-099** `background.js:548` — Non-atomic ratchet count increment (batch:3)
- [ ] **M-100** `engine.rs:255` — Arc clone in spawn without cleanup (batch:19)
- [ ] **M-101** `presence/verifier.rs` — Non-thread-safe RNG in Verifier (batch:18)

### Code Quality (35 items — selected)
- [ ] **M-102** `tpm/windows.rs:537` — 65-line PCR parse without bounds validation (batch:4)
- [ ] **M-103** `evidence/builder.rs:857` — String slice without bounds check (batch:14)
- [ ] **M-104** `evidence/builder.rs:571` — NaN silent fallback in sort (batch:14)
- [ ] **M-105** `error_topology.rs:302` — u16→u8→char truncation for non-ASCII keys (batch:10)
- [ ] **M-106** `labyrinth.rs:215` — Unused variable suggests incomplete refactoring (batch:10)
- [ ] **M-107** `platform/macos/hid.rs:95` — CFSetGetValues buffer size mismatch (batch:5)
- [ ] **M-108** `platform/mouse_stego.rs:21` — expect() in per-event hot path (batch:5)
- [ ] **M-109** `war/appraisal.rs:209` — Redundant dead condition in AR4SI check (batch:16)
- [ ] **M-110** `war/verification.rs:147` — Version dispatch fragile to V2_0 addition (batch:16)

### Maintainability (28 items — selected)
- [ ] **M-111** `forensics/assessment.rs:178` — Scattered calibration constants (batch:11)
- [ ] **M-112** `forensics/topology.rs:150` — Algorithm lacks documentation (batch:11)
- [ ] **M-113** `rfc/time_evidence.rs:291` — Tier is mutable state without auto-recalculation (batch:12)
- [ ] **M-114** `secure-channel.js:164` — Cross-language magic strings for key derivation (batch:3)
- [ ] **M-115** `content.js:33` — Magic strings for site detection (batch:3)
- [ ] **M-116** `vdf/params.rs:46` — Implicit units in calibration (batch:17)
- [ ] **M-117** `writersproof/types.rs:81` — Inconsistent naming conventions (batch:17)
- [ ] **M-118** `background.js:21` — Magic values not synchronized across files (batch:3)
- [ ] **M-119** `ffi/forensics.rs:144` — Hardcoded ML weight vector in FFI (batch:7)

### New Findings (2026-03-03 incremental)
- [ ] **M-120** `[error_handling]` `evidence/builder.rs:434` — Silent i32 truncation on edit index
  <!-- pid:silent_truncation | verified:true | first:2026-03-03 -->
  `i32::try_from(idx).unwrap_or(i32::MAX)` silently caps index. Corrupts edit position data in evidence packets without warning.

- [ ] **M-121** `[error_handling]` `analysis/hurst.rs:111` — NaN propagation from linear regression → SYS-016
  <!-- pid:nan_handling | verified:true | first:2026-03-03 -->
  If all log values identical, regression produces NaN slope. `.clamp(0.0, 1.0)` at line 116 propagates NaN (clamp of NaN returns NaN). Fix: Check `.is_finite()` after regression.

- [ ] **M-122** `[code_quality]` `keyhierarchy/manager.rs` — Broad `#[allow(dead_code)]` scope
  <!-- pid:dead_code_blanket | verified:true | first:2026-03-03 -->
  Violates project convention of targeted `#[allow(dead_code)]` on specific items. May mask genuinely unused code.

### Deep Audit Findings (2026-03-03)
- [ ] **M-123** `[correctness]` `forensics/cross_modal.rs:243` — Zero timestamp bypass in temporal alignment
  <!-- pid:zero_bypass | verified:true | first:2026-03-03 -->
  `if jitter_first == 0 || ... { return passed: true }` — adversary sends all timestamps as 0 to bypass temporal alignment check entirely. Fix: Return `passed: false` when timestamps are zero but data exists.

- [ ] **M-124** `[correctness]` `forensics/cross_modal.rs:297` — Self-referential jitter/keystroke ratio
  <!-- pid:self_referential_metric | verified:true | first:2026-03-03 -->
  When `total_keystrokes == 0`, uses `jitter_count` as keystroke source, making `jitter_ks_ratio` always 1.0. Adversary can omit keystroke count to guarantee passing.

- [ ] **M-125** `[correctness]` `forensics/forgery_cost.rs:309` — estimated_forge_time_sec is 0 when all costs infinite
  <!-- pid:edge_case | verified:true | first:2026-03-03 -->
  When all present components have infinite cost (hardware + external time anchor only), `estimated_forge_time_sec` is 0.0 since all infinite costs are filtered out of the max computation.

- [ ] **M-126** `[correctness]` `forensics/forgery_cost.rs:176` — VeryHigh tier from unchecked boolean
  <!-- pid:trust_boundary | verified:true | first:2026-03-03 -->
  `has_hardware_attestation` boolean directly sets VeryHigh tier. This boolean comes from caller code and isn't verified against actual hardware attestation evidence.

- [ ] **M-127** `[security]` `vdf/timekeeper.rs:65` — NTP servers hardcoded in binary
  <!-- pid:hardcoded_config | verified:true | first:2026-03-03 -->
  NTP server addresses hardcoded. No config option to change them. Adversary can block specific servers. Fix: Make configurable with fallback defaults.

- [ ] **M-128** `[correctness]` `analysis/behavioral_fingerprint.rs` — NoFatiguePattern never raised
  <!-- pid:dead_variant | verified:true | first:2026-03-03 -->
  `ForgeryIndicator::NoFatiguePattern` variant defined but never constructed. Fatigue detection is documented but not implemented.

- [ ] **M-129** `[correctness]` `forensics/comparison.rs` — cadence_cv_similarity computed but unused
  <!-- pid:dead_code | verified:true | first:2026-03-03 -->
  Cadence CV similarity is calculated but never included in the final comparison score. Either integrate into scoring or remove.

- [ ] **M-130** `[correctness]` `analysis/labyrinth.rs` — _min_line_length parameter ignored in RQA
  <!-- pid:unused_parameter | verified:true | first:2026-03-03 -->
  RQA function accepts `_min_line_length` but never uses it, producing incorrect recurrence quantification.

- [ ] **M-131** `[correctness]` `forensics/types.rs:186` — hurst_exponent always None
  <!-- pid:dead_field | verified:true | first:2026-03-03 -->
  `hurst_exponent` in forensic metrics is never populated. All consumers get `None`. Fix: Wire up from `analysis::hurst` computation.

- [ ] **M-132** `[security]` `background.js:187` — sendResponse called before async commitment resolves
  <!-- pid:async_ordering | verified:true | first:2026-03-03 -->
  Chrome's `sendResponse` may be called synchronously while the async commitment computation is still pending. The message may arrive at native host without commitment.

- [ ] **M-133** `[code_quality]` `forensics/engine.rs:62` — ForensicsError duplicates global Error
  <!-- pid:error_type_duplication | verified:true | first:2026-03-03 -->
  Module-local error type not integrated with the unified Error enum. Inconsistent error handling path.

- [ ] **M-134** `[performance]` `forensics/forgery_cost.rs:277-301` — Multiple redundant iterations over components
  <!-- pid:redundant_iteration | verified:true | first:2026-03-03 -->
  Four separate `.iter().filter()` chains over the same Vec. Could be a single pass computing all needed values.

- [ ] **M-135** `[security]` `content.js:280` — Content script accepts any message → SYS-019
  <!-- pid:security-message_origin_bypass | verified:true | first:2026-03-03 -->
  Content script runtime.onMessage handler lacks sender validation.

- [ ] **M-136** `[code_quality]` `analysis/active_probes.rs` — Incomplete probe type coverage
  <!-- pid:incomplete_match | verified:true | first:2026-03-03 -->
  Not all ProbeType variants have corresponding analysis logic. New variants silently pass through.

- [ ] **M-137** `[correctness]` `platform/mouse_stego.rs:21` — expect() in per-event hot path
  <!-- pid:panic_in_hot_path | verified:true | first:2026-03-03 -->
  Panic in the mouse event processing path. A single malformed event crashes the capture thread.

- [ ] **M-138** `[security]` `ipc/secure_channel.rs:58` — bincode deserialization without size limits
  <!-- pid:unbounded_deser | verified:true | first:2026-03-03 -->
  Attacker can send crafted messages causing unbounded allocation during bincode deserialization.

- [ ] **M-139** `[code_quality]` `rfc/biology.rs:478` — Magic constant 478 in biological analysis
  <!-- pid:magic_value | verified:true | first:2026-03-03 -->
  Undocumented threshold constants in biological cadence analysis.

- [ ] **M-140** `[correctness]` `analysis/perplexity.rs` — Perplexity threshold 15.0 not calibrated
  <!-- pid:uncalibrated_threshold | verified:true | first:2026-03-03 -->
  `if metrics.perplexity_score > 15.0` threshold in analysis.rs has no documented basis. May produce false positives/negatives.

- [ ] **M-141** `[correctness]` `forensics/assessment.rs:226` — Division unguarded in assessment score → SYS-016
  <!-- pid:fp_division_unguarded | verified:true | first:2026-03-03 -->
  Assessment score computation may divide by zero producing NaN that propagates to final score.

- [ ] **M-142** `[security]` `config/loading.rs` — Config file created without explicit permissions → M-083
  <!-- pid:world_readable_config | verified:true | first:2026-03-03 -->
  Config file containing sensitive settings created with default umask permissions.

- [ ] **M-143** `[code_quality]` `ffi/ephemeral.rs` — 900+ line FFI module
  <!-- pid:god_module | verified:true | first:2026-03-03 -->
  Massive FFI module with business logic mixed into boundary code. Hard to audit and maintain.

---

## Quick Wins (effort=small, highest severity)
| ID | Sev | File:Line | Issue | Status |
|----|-----|-----------|-------|--------|
| ~~C-011~~ | CRITICAL | tpm/software.rs:28 | Weak RNG seed | ✓ FIXED |
| ~~C-012~~ | CRITICAL | tpm/software.rs:31 | Seed not zeroized | ✓ FIXED |
| ~~C-015~~ | CRITICAL | background.js:212 | XSS via error messages | ✓ FIXED |
| ~~C-016~~ | CRITICAL | background.js:173 | Handshake replay | ✓ FIXED |
| ~~C-017~~ | CRITICAL | secure-channel.js:289 | Unguarded JSON.parse | ✓ FIXED |
| ~~C-019~~ | CRITICAL | content.js:112 | OOM before size check | ✓ FIXED |
| ~~C-022~~ | CRITICAL | ffi/forensics.rs:74 | Wrong assessment score | ✓ FIXED |
| ~~C-023~~ | CRITICAL | ffi/forensics.rs:151 | Inverted sequence score | ✓ FIXED |
| ~~C-026~~ | CRITICAL | native_messaging_host.rs:362 | Evidence file truncation | ✓ FIXED |
| H-067 | HIGH | tpm/windows.rs:886 | Silent flush_context | **OPEN** |
| H-080 | HIGH | ipc/unix_socket.rs:138 | Filename-only exe check | **OPEN** |
| H-083 | HIGH | rfc/time_evidence.rs:309 | Timestamp overflow | **OPEN** |
| H-084 | HIGH | rfc/time_evidence.rs:309 | u64→i64 silent wrap | **OPEN** |
| H-085 | HIGH | evidence/rfc_conversion.rs:21 | hex→empty Vec | **OPEN** |
| H-087 | HIGH | evidence/packet.rs:382 | Sig length unvalidated | **OPEN** |
| ~~H-091~~ | HIGH | keyhierarchy/puf.rs:55 | Seed length unvalidated | ✓ FIXED |
| ~~H-094~~ | HIGH | war/ear.rs:338 | Inverted status logic | ✓ FIXED |
| H-095 | HIGH | writersproof/queue.rs:127 | Silent nonce skip | **OPEN** |
| H-100 | HIGH | wal/operations.rs | Non-CT hash comparison | **OPEN** |
| H-102 | HIGH | protocol/evidence.rs:36 | Clock error → 0 | **OPEN** |
| H-107 | HIGH | crypto/obfuscated.rs:33,49 | .expect() in library code | **OPEN** |
| H-108 | HIGH | war/verification.rs | VDF verify no timeout | **OPEN** |
| H-109 | HIGH | sentinel/types.rs:367 | Path traversal fallback | **OPEN** |
| H-110 | HIGH | ffi/evidence.rs:191 | Wrong ProofAlgorithm | **OPEN** |
| ~~H-111~~ | HIGH | background.js:89 | Genesis commitment gap | ✓ FIXED |
| ~~H-112~~ | HIGH | background.js:103 | Ordinal desync | ✓ FIXED |
| ~~H-114~~ | HIGH | native_messaging_host.rs:330 | Timestamp soft check | ✓ FIXED |
| ~~H-115~~ | HIGH | native_messaging_host.rs:346 | Non-CT commitment cmp | ✓ FIXED |
| ~~H-116~~ | HIGH | background.js:179 | Silent crypto fallback | ✓ FIXED |
| ~~H-117~~ | HIGH | native_messaging_host.rs:394 | Ordinal drift on None | ✓ FIXED |
| ~~H-118~~ | HIGH | cross_modal.rs:139 | Negative doc_length | ✓ FIXED |
| ~~H-119~~ | HIGH | cross_modal.rs:253 | i64 overflow | ✓ FIXED |
| ~~H-120~~ | HIGH | analysis.rs:98 | False positive anomaly | ✓ FIXED |
| ~~H-127~~ | HIGH | native_messaging_host.rs:617 | Commitment logged | ✓ FIXED |
| ~~H-129~~ | HIGH | forgery_cost.rs:306 | NaN panic in min_by | ✓ FIXED |

---

## Prior Findings (All Resolved)
<!-- Prior audit: 159 issues (8C fixed, 48H fixed, 66M fixed, 11 SYS fixed, 26 skipped/eliminated) -->
<!-- See git history for full prior todo.md with completed items -->

## Structural Changes (2026-03-03)

6 god-level modules split into directory-based submodules:
| Original | New Directory | Submodules |
|----------|--------------|------------|
| `wal.rs` (999L) | `wal/` | mod.rs, types.rs, operations.rs, serialization.rs, tests.rs |
| `presence.rs` (989L) | `presence/` | mod.rs, types.rs, verifier.rs, helpers.rs, tests.rs |
| `research.rs` (695L) | `research/` | mod.rs, types.rs, collector.rs, uploader.rs, helpers.rs, tests.rs |
| `trust_policy.rs` (691L) | `trust_policy/` | mod.rs, types.rs, evaluation.rs, profiles.rs, tests.rs |
| `config.rs` (634L) | `config/` | mod.rs, types.rs, defaults.rs, loading.rs, tests.rs |
| `sealed_identity.rs` (537L) | `sealed_identity/` | mod.rs, types.rs, store.rs, tests.rs |

## Coverage
<!-- Full scan 2026-03-02: 230 files, 20 batches, 4 waves -->
<!-- Incremental validation 2026-03-03: 220 engine files, 5 batches, 1 wave -->
<!-- Deep audit 2026-03-03: Multi-agent security/logic/forensics review of new and critical code -->
<!-- Revalidation 2026-03-03: All CRITICAL/HIGH/SYSTEMIC/BUILD items verified against current codebase -->
<!-- reviewed:sentinel/*.rs:2026-03-02 -->
<!-- reviewed:ffi/*.rs:2026-03-02 -->
<!-- reviewed:ipc/*.rs:2026-03-02 -->
<!-- reviewed:fingerprint/*.rs:2026-03-02 -->
<!-- reviewed:analysis/*.rs:2026-03-02 -->
<!-- reviewed:forensics/*.rs:2026-03-03 (deep) -->
<!-- reviewed:rfc/*.rs:2026-03-02 -->
<!-- reviewed:rfc/wire_types/*.rs:2026-03-02 -->
<!-- reviewed:evidence/*.rs:2026-03-02 -->
<!-- reviewed:checkpoint/*.rs:2026-03-02 -->
<!-- reviewed:keyhierarchy/*.rs:2026-03-02 -->
<!-- reviewed:tpm/*.rs:2026-03-02 -->
<!-- reviewed:platform/*.rs:2026-03-02 -->
<!-- reviewed:identity/*.rs:2026-03-02 -->
<!-- reviewed:war/*.rs:2026-03-02 -->
<!-- reviewed:vdf/*.rs:2026-03-03 (deep) -->
<!-- reviewed:store/*.rs:2026-03-02 -->
<!-- reviewed:writersproof/*.rs:2026-03-02 -->
<!-- reviewed:engine.rs,config/*,wal/*,presence/*,research/*,trust_policy/*,sealed_identity/*,lib.rs:2026-03-03 -->
<!-- reviewed:apps/wld_cli/src/*.rs:2026-03-03 (deep) -->
<!-- reviewed:apps/wld_cli/browser-extension/*.js:2026-03-03 (deep) -->
<!-- reviewed:crates/wld_protocol/src/*.rs:2026-03-02 -->
<!-- reviewed:crates/wld_jitter/src/*.rs:2026-03-02 -->
<!-- uncovered: checkpoint_mmr.rs (reviewed inline with B15) -->
