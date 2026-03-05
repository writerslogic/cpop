# WritersLogic — Unified Todo

## Session State

<!-- UPDATE THIS SECTION AT START AND END OF EVERY SESSION -->

```
ACTIVE_TASKS: []
LAST_UPDATED: 2026-03-05
SESSION_OWNER: instruct-mission-3
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
- 2026-03-05: Phase 7: M-088 (WAL bounds), M-128 (fatigue detection), M-129 (unused field removal), M-130 (min_line_length), M-131 (Hurst exponent), M-144 (profile_uri validation), M-145 (filename bounds), M-146 (evidence chain bounds), M-147 (clock expect). Triaged: M-053, M-056, M-083, M-087, M-137, M-138 (no fix needed/already done). 707 pass.

### Handoff Summary
<!-- Replace this block before ending a session near context limits -->
```
CONTEXT: Phase 7 committed: WAL bounds, fatigue detection, Hurst exponent, protocol validation, cross-crate hardening. 707 tests passing, clippy clean across all crates.
BLOCKERS: None
NEXT_STEPS: Remaining engine MEDIUM (M-102, M-112, M-140), browser ext (Group 10), SYS-015 (named constants partial), C-014/H-066 (TPM signing, deferred), macOS/Windows apps. Most engine issues now resolved or triaged.
KEY_FILES: /Volumes/A/writerslogic/todo.md (this file)
           crates/wld_engine/src/ (engine code)
           apps/wld_macos/wld/ (macOS Swift code — submodule)
           apps/wld_windows/winui/WritersLogic/ (Windows C# code — submodule)
```

---

## Execution Plan — Dependencies & Parallelism

### Dependency Graph

```
Engine Groups (in crates/wld_engine, apps/wld_cli, browser-extension):
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

- [ ] **SYS-015** `magic_constants` — 15+ files — MEDIUM
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

- [ ] **SYS-019** `browser_ext_unvalidated_messages` — 3 files — HIGH
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
  Files: `apps/wld_cli/src/native_messaging_host.rs:337,394`, `browser-extension/background.js:89`
  Fix: Make required after genesis checkpoint.

- [x] **SYS-023** `forensic_region_stub` — 2 files — CRITICAL (fixed by C-024 cursor heuristic)
  <!-- pid:stub_implementation | verified:true | first:2026-03-03 -->
  Edit regions hardcoded to `(1.0, 1.0)`, destroying topology analysis.
  Files: `forensics/engine.rs:57-82`, `forensics/topology.rs`
  Fix: Implement real region extraction from edit deltas.

---

## Engine — Build Issues

- [x] **B-004** FFI feature compilation — multiple errors
  <!-- pid:build_failure | verified:true | first:2026-03-03 -->
  `cargo check --features ffi -p wld_engine` fails. Missing `ENTROPY_NORMALIZATION_FACTOR`, mismatched `FfiFingerprintStatus` fields.
  Fix: Align FFI types with current engine types. Effort: large

- [x] **B-005** rustfmt failure — module path mismatch
  <!-- pid:build_failure | verified:true | first:2026-03-03 -->
  `lib.rs:51` declares `pub mod wld_jitter_bridge;` but directory is `writerslogic_jitter_bridge/`.
  Fix: `git mv` directory to `wld_jitter_bridge/`. Effort: small

- [x] **B-006** 2 pre-existing checkpoint test failures
  <!-- pid:test_failure | verified:true | first:2026-03-03 -->
  `test_entangled_commit_with_physics_context` and `test_entangled_commit_mixed_physics_and_none` — "unsigned (signature required by policy)".
  Fix: Supply signing key in test setup. Effort: medium

---

## Engine — Critical (1 open)

- [ ] **C-014** `[security]` `tpm/windows.rs:536-546` — sign_payload uses SHA256 not TPM2_Sign
  <!-- pid:sec_no_real_signing | verified:true | first:2026-03-02 | revalidated:2026-03-03 -->
  Hardware trust boundary violated. Fix: Implement TPM2_Sign. Effort: large

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

## Engine — High (32 open)

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
- [ ] **H-105** `background.js:11` — Global mutable state without sync (service worker)
- [ ] **H-106** `background.js:442` — Unbounded chunk queue
- [x] **H-110** `ffi/evidence.rs:191` — FALSE POSITIVE: VDF uses SHA-256, SwfSha256 is correct
- [x] **H-113** `native_messaging_host.rs:266` — Session overwrite without finalizing
- [x] **H-122** `vdf/timekeeper.rs:40` — Blocking sync I/O in async function
- [x] **H-123** `vdf/timekeeper.rs:77` — VDF proof field always `[0u8; 32]`
- [x] **H-124** `forensics/analysis.rs:146` — BY DESIGN: CV heuristic is intentional quick assessment, full analysis via BehavioralFingerprint
- [x] **H-125** `vdf/roughtime_client.rs` — Single hardcoded Roughtime server
- [x] **H-126** `jitter/session.rs:313` — Session::load no chain integrity verification
- [x] **H-128** `native_messaging_host.rs` — Jitter rate limit has no temporal component

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

## Engine — Medium (92 open)

<details><summary>Architecture (12)</summary>

- [ ] M-050 tpm/windows.rs — god module 1208L (DEFERRED: large refactor)
- [x] M-051 tpm/secure_enclave.rs — duplicate key loading (refactored to load_or_create_se_key)
- [ ] M-052 background.js — 142-line message handler
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

- [ ] M-070 background.js:514 — async IIFE premature sendResponse
- [ ] M-071 background.js:88 — isConnecting never reset
- [ ] M-079 background.js:270 — ratchet count not validated
- [ ] M-080 background.js:483 — start_witnessing URL not validated
</details>

<details><summary>Security (10)</summary>

- [x] M-072 tpm/mod.rs:57 — parse_sealed_blob overflow
- [x] M-073 tpm/mod.rs:99 — hardcoded PCR selection
- [x] M-074 ipc/secure_channel.rs:67 — nonce counter overflow
- [x] M-075 ipc/secure_channel.rs:58 — bincode without size limits
- [x] M-076 fingerprint/voice.rs:350 — non-ASCII char handling
- [x] M-077 sealed_identity/store.rs — BY DESIGN: hostname adds entropy alongside TPM device_id
- [x] M-078 research/uploader.rs — BY DESIGN: Supabase endpoint is the production API
- [ ] M-081 secure-channel.js:87 — server pubkey not validated
- [ ] M-082 secure-channel.js:335 — key zeroization unreliable in JS
- [x] M-083 config/loading.rs — ALREADY FIXED: permissions set correctly
</details>

<details><summary>Performance (9)</summary>

- [x] M-084 labyrinth.rs:254 — O(n^2) nearest-neighbor
- [x] M-085 fingerprint/activity.rs:205 — double allocation
- [x] M-086 fingerprint/activity.rs:721 — full buffer clone on status
- [x] M-087 vdf/aggregation.rs — NO FIX NEEDED: string not cloned per level
- [x] M-088 wal/operations.rs — WAL parse bounded by MAX_WAL_ENTRIES (10M)
- [x] M-089 research/collector.rs — Vec::remove(0) O(n)
- [ ] M-090 background.js:68 — storage I/O scales with chain length
- [ ] M-091 content.js:111 — repeated DOM queries per keystroke
- [x] M-092 forensics/velocity.rs:77 — unnecessary Vec clone
- [x] M-093 ffi/ephemeral.rs:122 — ALREADY MITIGATED: EVICTION_THRESHOLD guard + DashMap retain
</details>

<details><summary>Concurrency (8)</summary>

- [x] M-094 platform/macos/mouse_capture.rs:121 — RwLock write in CGEventTap
- [x] M-095 platform/windows.rs:580 — lock poison no recovery
- [x] M-096 ipc/server.rs:133 — ACCEPTABLE: lock held only for .check() microseconds
- [x] M-097 sentinel/focus.rs:156 — NOT A BUG: receiver consumption pattern is correct
- [ ] M-098 background.js:147 — TOCTOU on isSecure check
- [ ] M-099 background.js:548 — non-atomic ratchet increment
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
- [ ] M-114 secure-channel.js:164 — cross-language magic strings
- [ ] M-115 content.js:33 — magic strings for site detection
- [x] M-116 vdf/params.rs:46 — implicit units in calibration
- [x] M-117 writersproof/types.rs:81 — ELIMINATED: file is 69 lines, naming is consistent
- [ ] M-118 background.js:21 — magic values not synced across files
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
- [ ] M-132 background.js:187 — sendResponse before async commitment
- [x] M-133 forensics/engine.rs:62 — BY DESIGN: ForensicsError is subsystem error with #[from] integration
- [x] M-134 forensics/forgery_cost.rs:277 — NOT WORTH FIXING: two iterations acceptable
- [ ] M-135 content.js:280 — content script accepts any message → SYS-019
- [ ] M-136 analysis/active_probes.rs — incomplete probe coverage (DEFERRED: feature enhancement)
- [x] M-137 platform/mouse_stego.rs — ALREADY FIXED: expect() not in hot path
- [x] M-138 ipc/secure_channel.rs — ALREADY FIXED by M-075: size limits in place
- [x] M-139 rfc/biology.rs:478 — magic constant
- [x] M-140 analysis/perplexity.rs — ALREADY NAMED: FNN_DISTANCE_THRESHOLD constant exists
- [x] M-141 FALSE POSITIVE — no division in calculate_cadence_score
- [x] M-142 config/loading.rs — DUPLICATE of M-083
- [ ] M-143 ffi/ephemeral.rs — 900+ line FFI module (DEFERRED: architecture)
</details>

<details><summary>Crate Audit Findings 2026-03-05 (4)</summary>

- [x] M-144 `[security]` wld_protocol/src/evidence.rs — profile_uri validated against spec URI
  <!-- pid:missing_validation | verified:true | first:2026-03-05 -->
  `protocol_uri` deserialized without value or length validation. Spec requires `urn:ietf:params:rats:eat:profile:pop:1.0`. Related to SYS-014 (String fields).
- [x] M-145 `[security]` wld_protocol/src/rfc.rs — DocumentRef.filename bounded to MAX_FILENAME_LEN (256)
  <!-- pid:unbounded_string_deser | verified:true | first:2026-03-05 -->
  No max length on filename field. Related to SYS-014.
- [x] M-146 `[security]` wld_jitter/src/evidence.rs — EvidenceChain.records bounded to MAX_EVIDENCE_RECORDS (100K)
  <!-- pid:unbounded_vec_deser | verified:true | first:2026-03-05 -->
  Deserialized chain can have arbitrary number of records. Related to SYS-014.
- [x] M-147 `[code_quality]` wld_jitter/src/evidence.rs — expect() with descriptive message on pre-epoch clock
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

## macOS App (apps/wld_macos/) — 134 issues

> Source: `apps/wld_macos/todo.md` (audited 2026-03-04, 86 Swift/JS/shell files)
> Submodule repo — work independently from engine.

### macOS Summary
| Severity | Open | Fixed | False Positive |
|----------|------|-------|----------------|
| CRITICAL | 9    | 0     | 1              |
| HIGH     | 28   | 3     | 3              |
| MEDIUM   | 75   | 5     | 3              |
| Systemic | 7    | 0     | 0              |

### macOS Systemic
- [ ] **mac-SYS-001** `god_module` — 4 files (DashboardView 744L, HistoryView 1782L, WLDService 600L, SettingsView 1108L)
- [ ] **mac-SYS-002** `silent_error_swallow` — 6+ files (WLDService, WLDBridge, GitIntegration, BrowserExtension, PopoverViews, SettingsView, CloudSync, VoiceFingerprint, SafariExtension)
- [ ] **mac-SYS-003** `hardcoded_colors` — 10+ SwiftUI views with hardcoded color literals
- [ ] **mac-SYS-004** `accessibility_missing` — 8+ views missing VoiceOver labels
- [ ] **mac-SYS-005** `no_test_coverage` — zero unit tests for any Swift code
- [ ] **mac-SYS-006** `localization_missing` — all user-facing strings hardcoded in English
- [ ] **mac-SYS-007** `error_alert_pattern` — inconsistent error presentation across views

### macOS Critical (9 open)
- [ ] **mac-C-001** WLDBridge.swift — CLI path injection via unsanitized user input
- [ ] **mac-C-002** WLDService.swift — mnemonic words stored as String array, never zeroized
- [ ] **mac-C-003** OnboardingView.swift — recovery phrase in plain Text view, clipboard not cleared
- [ ] **mac-C-004** SettingsView.swift — recovery phrase displayed without memory cleanup
- [ ] **mac-C-005** WLDBridge.swift — annotation text passed to CLI without escaping
- [ ] **mac-C-006** SafariWebExtensionHandler.swift — IPC message not validated
- [ ] **mac-C-007** WLDService.swift — session overwrite without finalizing previous
- [ ] **mac-C-008** WLDBridge.swift — process output parsed without size limit
- [ ] **mac-C-009** KeychainService.swift — keychain items not deleted on identity reset

### macOS High (28 open)
- [ ] mac-H-001..H-028 — concurrency, error handling, security, and UX issues
  (See `apps/wld_macos/todo.md` for full details per issue)

### macOS Quick Wins
| ID | Sev | File | Issue | Effort |
|----|-----|------|-------|--------|
| mac-C-003 | CRIT | OnboardingView | Clear clipboard after mnemonic display | trivial |
| mac-C-004 | CRIT | SettingsView | Clear recovery phrase on dismiss | trivial |
| mac-H-003 | HIGH | PopoverViews | Stop timer on view disappear | trivial |
| mac-H-005 | HIGH | WLDService | Add timeout to CLI process | small |
| mac-H-010 | HIGH | HistoryView | Fix UTC/local time mismatch | small |
| mac-H-014 | HIGH | DashboardView | Guard division by zero in stats | trivial |

---

## Windows App (apps/wld_windows/) — 188 issues

> Source: `apps/wld_windows/winui/WritersLogic/todo.md` (audited 2026-03-04, 120 C#/PS1/WXS/XAML files)
> Submodule repo — work independently from engine.

### Windows Summary
| Severity | Open | Fixed | Skipped |
|----------|------|-------|---------|
| CRITICAL | 6    | 0     | 0       |
| HIGH     | 56   | 0     | 0       |
| MEDIUM   | 119  | 0     | 0       |
| Systemic | 7    | 0     | 0       |

### Windows Systemic
- [ ] **win-SYS-001** `fire_and_forget` — 15+ files — async calls without error handling
- [ ] **win-SYS-002** `empty_catch` — 12 files — swallowed exceptions
- [ ] **win-SYS-003** `async_void` — 5 files — losing exceptions
- [ ] **win-SYS-004** `test_quality` — 13 test files — vacuous tests, hand-rolled doubles
- [ ] **win-SYS-005** `resource_brush_duplication` — 5+ files — duplicate theme helpers
- [ ] **win-SYS-006** `accessibility_missing_automation` — 11+ XAML files — missing AutomationProperties
- [ ] **win-SYS-007** `hardcoded_colors_strings` — 20+ XAML files — hardcoded colors and strings

### Windows Critical (6 open)
- [ ] **win-C-001** IpcConnectionPool.cs:81 — ConcurrentBag.Count race, unbounded pool growth
- [ ] **win-C-002** LockScreenDialog.xaml.cs:56 — brute-force lockout bypass
- [ ] **win-C-003** OnboardingPage.xaml.cs:259 — mnemonic words persist in memory
- [ ] **win-C-004** SettingsPage.xaml.cs:132 — recovery phrase no memory cleanup
- [ ] **win-C-005** WLDBridge.cs:~1200 — CLI argument injection via annotation
- [ ] **win-C-006** MnemonicRecoveryDialog.xaml.cs:31 — recovery phrase in plaintext TextBox

### Windows High (56 open)
- [ ] win-H-001..H-056 — security, concurrency, build, config, UX issues
  (See `apps/wld_windows/winui/WritersLogic/todo.md` for full details per issue)

### Windows Quick Wins
| ID | Sev | File | Issue | Effort |
|----|-----|------|-------|--------|
| win-C-003 | CRIT | OnboardingPage | Zero `_mnemonicWords` after display | trivial |
| win-C-004 | CRIT | SettingsPage | Clear recovery phrase on dialog close | trivial |
| win-H-001 | HIGH | SettingsIntegrityService | Fail-open on HMAC key unavailable | small |
| win-H-002 | HIGH | SettingsIntegrityService | Null hash bypass | small |
| win-H-004 | HIGH | WLDBridge | O(n^2) cache eviction | small |
| win-H-018 | HIGH | AppLogger | Log rotation delete-then-move | trivial |
| win-H-023 | HIGH | HomePage | Null check for `_bridge` | trivial |
| win-H-025 | HIGH | HistoryPage | Stop debounce timer on unload | trivial |
| win-H-029 | HIGH | ExportTierDialog | Unsafe cast to StackPanel | trivial |
| win-H-030 | HIGH | SettingsPage | Add Clipboard.Flush() | trivial |
| win-H-031 | HIGH | SessionPage | Remove redundant ItemsSource= | trivial |
| win-H-033 | HIGH | build-binaries.ps1 | Fix RepoRoot path depth | trivial |
| win-H-034 | HIGH | create-msix.ps1 | Fix RepoRoot path depth | trivial |
| win-H-035 | HIGH | build-installer.ps1 | Fix RepoRoot path depth | trivial |
| win-H-037 | HIGH | AppxManifest.xml | Align MaxVersionTested | trivial |
| win-H-039 | HIGH | Package.appxmanifest | Remove PhoneIdentity | trivial |
| win-H-042 | HIGH | WLDBridge | Truncate hashes in log output | trivial |
| win-H-044 | HIGH | WLDBridge | Read progress counters inside lock | trivial |
| win-H-046 | HIGH | WLDBridge | Change verify to RunQueryCommandAsync | trivial |
| win-H-051 | HIGH | IpcClient | Mark session key field readonly | trivial |
| win-H-055 | HIGH | AppxManifest.xml | Fix StartupTask ID | trivial |

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

### Engine (2026-03-02/03)
<!-- 230 files, 20 batches, 4 waves + incremental + deep review -->
<!-- Prior audit: 159 issues (133 fixed, 26 skipped/eliminated) -->
<!-- This cycle: 322 new findings, 44 fixed, 8 eliminated -->

### macOS (2026-03-04)
<!-- 86 files (Swift, JS, shell, HTML) -->
<!-- 134 issues found, 9 fixed/eliminated -->

### Windows (2026-03-04)
<!-- 120 files (C#, PS1, WXS, XAML, JSON) -->
<!-- 188 issues found, 0 fixed -->

---

> **Note**: The macOS and Windows apps are git submodules with their own repos. For full issue details
> including code-level guidance, enriched context, and diff suggestions, refer to the original
> audit files preserved in each submodule's `todo.md`. The IDs above use `mac-` and `win-` prefixes
> to distinguish from engine issue IDs.
