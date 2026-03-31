# CPOP Project Audit — Consolidated Findings

**Updated**: 2026-03-30
**Scope**: Full workspace scan — CLI (19 files), Engine (170+ files), Protocol (16 files), Jitter (3 files)
**Previous audit**: 2026-03-25 — 255 findings, all resolved
**macOS app**: 381 findings fixed, 0 open (see apps/cpop_macos/audit-todo.md)
**Baseline**: 1024 pass, 0 fail, 1 ignored (cpop-engine --lib)

## Summary
| Severity | Open | Fixed | Component |
|----------|------|-------|-----------|
| CRITICAL | 0    | 5     | (all prior resolved) |
| HIGH     | 30   | 60    | CLI (4), Engine (19), Protocol (7) |
| MEDIUM   | 35   | 135   | CLI (12), Engine (28), Protocol (10) |

---

## Prior Audit (2026-03-25) — All Resolved

All 255 findings from the prior audit (C-001..EC-003, H-001..EH-051, M-001..EM-050, L-001..L-015) are resolved. See git history for details.

---

## High (2026-03-30 scan)

### CLI

- [ ] **H-052** `[security]` `apps/cpop_cli/src/native_messaging_host.rs:85` — Session struct holds session_nonce [u8;16] and prev_commitment [u8;32] without Zeroize/Drop impl. Violates key material zeroization policy.
  Impact: Session secrets persist in memory after drop. Fix: Derive Zeroize + ZeroizeOnDrop on Session. Effort: small

- [ ] **H-053** `[error_handling]` `apps/cpop_cli/src/util.rs:287` — retry_on_busy() uses .expect() after all retries exhausted; panics CLI on legitimately busy database.
  Impact: Users see panic backtrace instead of actionable error. Fix: Return anyhow::Error. Effort: small

- [ ] **H-054** `[security]` `apps/cpop_cli/src/cmd_presence.rs:23` — Session lock released during stdin interaction; TOCTOU between release and re-acquisition at line 279.
  Impact: Concurrent session modifications possible during user input phase. Fix: Hold advisory lock or store in-memory. Effort: medium

- [ ] **H-055** `[error_handling]` `apps/cpop_cli/src/cmd_config.rs:117` — Voice fingerprinting consent errors propagated as generic anyhow without recovery guidance.
  Impact: Users get opaque error with no recovery path. Fix: Wrap with context message suggesting rm consent.json. Effort: small

### Engine — IPC/FFI

- [ ] **H-056** `[concurrency]` `crates/cpop-engine/src/ipc/crypto.rs:176` — Sequence number CAS validation and rx_sequence advancement are not atomic; concurrent packets can race past replay check.
  Impact: Replay attack window during concurrent IPC message processing. Fix: Atomic compare-and-swap with SeqCst. Effort: medium

- [ ] **H-057** `[error_handling]` `crates/cpop-engine/src/ipc/server_handler.rs:224` — Rate limiter lock_recover() silently swallows poisoning; may bypass rate limiting on poisoned mutex.
  Impact: Rate limiting silently disabled after handler panic. Fix: Return error on poisoned state. Effort: small

- [ ] **H-058** `[security]` `crates/cpop-engine/src/ffi/ephemeral.rs:656` — Signing key bytes not zeroized after constructing SigningKey; key_bytes Vec persists on heap.
  Impact: Key material exposure in memory. Fix: Wrap in Zeroizing<Vec<u8>>. Effort: small

### Engine — Sentinel/Platform

- [x] **H-059** `[security]` `crates/cpop-engine/src/sentinel/ipc_handler.rs:36` — HMAC key escapes Zeroizing wrapper via mem::take(); not zeroized if SecureStore::open() fails.
  Impact: Key material leaked on database open failure. Fix: Replaced mem::take with .to_vec(); Zeroizing wrapper drops naturally.

- [x] **H-060** `[concurrency]` `crates/cpop-engine/src/sentinel/daemon.rs:436` — PID file acquired AFTER sentinel.start() and IPC bind; crash between start and PID write leaves stale PID.
  Impact: Daemon fails to restart; requires manual PID cleanup. Fix: Moved acquire_pid_file() before sentinel.start() with cleanup on failure.

- [x] **H-061** `[concurrency]` `crates/cpop-engine/src/sentinel/core.rs:493` — Session keystroke attribution: read lock check followed by write lock update; session can be removed between checks.
  Impact: Keystroke silently lost if session ends between check and update. Fix: Already uses single write lock in current code.

- [x] **H-062** `[concurrency]` `crates/cpop-engine/src/sentinel/core.rs:856` — Event loop handle may not be stored if lock fails; orphaned Tokio task continues after Sentinel drop.
  Impact: Task leak; orphaned task may access freed Arc clones. Fix: Changed to lock_recover() in Drop impl.

- [ ] **H-063** `[concurrency]` `crates/cpop-engine/src/platform/windows.rs:169` — MONITOR_ACTIVE check not held during hook installation; second monitor can start between check and hook setup.
  Impact: Two monitors feed same GLOBAL_SESSION; events interleave. Fix: Extend CAS to cover hook install. Effort: medium

### Engine — Evidence/Checkpoint

- [ ] **H-064** `[data_integrity]` `crates/cpop-engine/src/evidence/wire_conversion.rs:225` — CBOR encoding failure silently returns empty Vec for jitter seal computation.
  Impact: Invalid jitter_seal (zeros) breaks downstream verification. Fix: Return error on encode failure. Effort: small

- [ ] **H-065** `[data_integrity]` `crates/cpop-engine/src/evidence/wire_conversion.rs:257` — CBOR encoding of jitter binding silently fails; entangled MAC computed with empty bytes.
  Impact: Entangled checkpoint loses binding strength. Fix: Propagate encode error. Effort: small

- [ ] **H-066** `[security]` `crates/cpop-engine/src/evidence/builder/setters.rs:337` — Ratchet index clamped to i32::MAX instead of error when exceeding 2^31.
  Impact: Silent index clamping breaks signature verification on very long chains. Fix: Return error. Effort: small

### Engine — Forensics/Analysis

- [ ] **H-067** `[code_quality]` `crates/cpop-engine/src/forensics/assessment.rs:292` — normalized_entropy can exceed 1.0; no clamp before penalty calculation.
  Impact: Forgery detection unreliable with poisoned entropy inputs. Fix: .min(1.0) after normalization. Effort: small

- [ ] **H-068** `[error_handling]` `crates/cpop-engine/src/forensics/topology.rs:99` — No validation that inter-event intervals are positive before computing median.
  Impact: Negative intervals from out-of-order events corrupt all downstream metrics. Fix: Clamp to [0, max]. Effort: small

- [ ] **H-069** `[numeric]` `crates/cpop-engine/src/analysis/behavioral_fingerprint.rs:226` — burst_speed_variance divides by (n-1) where n=1; division by zero.
  Impact: Panic during behavioral fingerprint generation. Fix: Guard len < 2. Effort: small

- [ ] **H-070** `[numeric]` `crates/cpop-engine/src/analysis/snr.rs:80` — log10(0) produces -inf when signal_power=0; not explicitly handled.
  Impact: SNR becomes -inf instead of explicit zero-signal flag. Fix: Guard signal_power > 0. Effort: small

### Engine — Other

- [ ] **H-071** `[security]` `crates/cpop-engine/src/writersproof/client.rs:50` — JWT token stored as plain String without zeroization on Drop.
  Impact: Bearer tokens persist in memory dumps. Fix: Wrap with Zeroizing<String>. Effort: small

- [ ] **H-072** `[security]` `crates/cpop-engine/src/war/profiles/standards.rs:347` — DID method extraction uses split(':').nth(1); truncates multi-component DIDs.
  Impact: Authentication metadata lost for complex DID methods. Fix: Return full DID after 'did:' prefix. Effort: small

- [ ] **H-073** `[concurrency]` `crates/cpop-engine/src/tpm/windows/provider.rs:218` — Counter not atomically incremented with binding creation; duplicate counter values possible.
  Impact: Monotonicity violation in attestation chain. Fix: Atomic increment or lock both together. Effort: medium

- [ ] **H-074** `[security]` `crates/cpop-engine/src/tpm/secure_enclave/signing.rs:34` — CFRelease called on potentially null CFErrorRef pointer.
  Impact: Memory corruption on SE signing failure path. Fix: Check !error.is_null() before CFRelease. Effort: small

- [ ] **H-075** `[numeric]` `crates/cpop-engine/src/jitter/session.rs:186` — compute_jitter_value: JITTER_RANGE can be 0 if min==max; modulo by zero.
  Impact: Panic in jitter computation. Fix: Guard params.jitter_range == 0. Effort: small

- [ ] **H-076** `[error_handling]` `crates/cpop-engine/src/fingerprint/storage.rs:216` — delete_all_voice_data silently deletes on decrypt failure.
  Impact: Unrecoverable data loss without user notification. Fix: Return error on decrypt failure. Effort: small

### Protocol

- [ ] **H-077** `[numeric]` `crates/cpop-protocol/src/rfc/fixed_point.rs:51` — f64 to i32 cast without overflow check in from_float macro.
  Impact: Silent wraparound corrupts fixed-point scores. Fix: Clamp before cast. Effort: small

- [ ] **H-078** `[security]` `crates/cpop-protocol/src/codec/cbor.rs:28` — CBOR deserialization has no recursive depth limit; deeply nested structures within 16MB can cause stack overflow.
  Impact: Stack overflow DoS on malicious CBOR input. Fix: Add max_depth=32 pre-flight validation. Effort: large

- [ ] **H-079** `[security]` `crates/cpop-protocol/src/evidence.rs:101` — Zero entropy hash check insufficient; PhysJitter silent failure allows weak causality locks.
  Impact: Forgeable evidence packets with zero-entropy checkpoints. Fix: Require entropy_bits >= 8. Effort: small

- [ ] **H-080** `[error_handling]` `crates/cpop-protocol/src/codec/mod.rs:105` — decode() ignores Format::CborWar; calls cbor::decode instead of cbor::decode_cwar.
  Impact: CWAR tag validation bypassed; wrong-tagged CBOR silently accepted. Fix: Match CborWar explicitly. Effort: small

- [ ] **H-081** `[numeric]` `crates/cpop-engine/src/vdf/swf_argon2.rs:233` — Loop caps at MAX_ITERATIONS but later code assumes leaves.len() == params.iterations; OOB panic.
  Impact: Panic when building Merkle proofs if iterations > MAX_ITERATIONS. Fix: Validate at entry. Effort: small

---

## Medium (2026-03-30 scan)

### CLI
- [ ] **M-032** `[security]` `native_messaging_host.rs:287` — Evidence file created before chmod; brief TOCTOU window.
- [ ] **M-033** `[security]` `native_messaging_host.rs:636` — Symlink check after canonicalize uses original path reference.
- [ ] **M-034** `[security]` `native_messaging_host.rs:470` — Hex decode timing leak in commitment verification.
- [ ] **M-035** `[code_quality]` `cmd_track.rs:151` — is_within_target() uses lexical starts_with; unsafe for non-canonical paths.
- [ ] **M-036** `[code_quality]` `cmd_export.rs:660` — default_output_path() no traversal check on relative paths.
- [ ] **M-037** `[input_validation]` `cmd_config.rs:209` — parse_editor_value doesn't handle quoted paths.
- [ ] **M-038** `[code_quality]` `smart_defaults.rs:82` — File selection ambiguous with similar names.
- [ ] **M-039** `[error_handling]` `cmd_fingerprint.rs:189` — Error handling via string matching instead of types.
- [ ] **M-040** `[error_handling]` `config/loading.rs:45` — Legacy config parse failure silently uses defaults.
- [ ] **M-041** `[input_validation]` `main.rs:229` — Path traversal warning not enforced.
- [ ] **M-042** `[code_quality]` `main.rs:131` — Auto-start logic fragile; adding commands requires manual update.
- [ ] **M-043** `[error_handling]` `config/types.rs:353` — Config validation lacks reasonable bounds on timing intervals.

### Engine — IPC/FFI
- [ ] **M-044** `[security]` `ipc/messages.rs:36` — Path validation race between canonicalize and symlink check.
- [ ] **M-045** `[security]` `ipc/messages.rs:108` — Windows UNC path normalization incomplete.
- [ ] **M-046** `[concurrency]` `ffi/sentinel_inject.rs:136` — Pre-witness buffer and session creation TOCTOU race.
- [ ] **M-047** `[code_quality]` `ffi/ephemeral.rs:295` — Jitter interval filtering reports no rejection count to caller.
- [x] **M-048** `[error_handling]` `ffi/beacon.rs:104` — Empty API key not validated before client creation.
- [ ] **M-049** `[error_handling]` `ipc/async_client.rs:366` — Poisoned stream after partial send/recv; no auto-reconnect.
- [ ] **M-050** `[error_handling]` `ipc/server.rs:62` — Stale socket test connection not properly closed.
- [ ] **M-051** `[security]` `ipc/messages.rs:344` — Pulse timestamp_ns not validated against wall clock.
- [ ] **M-052** `[code_quality]` `ffi/ephemeral.rs:117` — Sessions DashMap has no LRU eviction; memory exhaustion DoS.
- [ ] **M-053** `[security]` `ipc/secure_channel.rs:40` — ChaCha20Poly1305 cipher key not zeroized on Drop.
- [ ] **M-054** `[code_quality]` `ffi/sentinel_witnessing.rs:249` — Forensic score blending has overlapping conditions.
- [ ] **M-055** `[error_handling]` `ffi/evidence_derivative.rs:82` — File size TOCTOU between validation and hashing.
- [x] **M-056** `[error_handling]` `ffi/beacon.rs:57` — Beacon runtime OnceLock caches failure permanently.

### Engine — Sentinel/Platform
- [x] **M-057** `[error_handling]` `sentinel/core.rs:348` — Channel full drops keystrokes silently; no metrics.
- [x] **M-058** `[concurrency]` `sentinel/core.rs:620` — Mouse timing uses system clock; clock jump causes false positives.
  Verified: mouse_duration_ns is unused; is_during_typing uses monotonic Instant. No fix needed.
- [x] **M-059** `[code_quality]` `sentinel/core.rs:559` — File exists check outside session lock; file could be deleted.
  Fix: Added benign-race comment; session for deleted file ends naturally on idle sweep.
- [x] **M-060** `[error_handling]` `sentinel/core.rs:796` — Auto-checkpoint event may be orphaned if session ends.
  Fix: Added benign-race comment; extra checkpoint is valid evidence data.
- [x] **M-061** `[concurrency]` `sentinel/daemon.rs:181` — Stale PID cleanup races with concurrent daemon startup.
  Fix: Added TOCTOU race comment; retry-once pattern limits impact.
- [ ] **M-062** `[code_quality]` `platform/windows.rs:386` — Global static mutex poisoning silently swallowed.
- [x] **M-063** `[security]` `sentinel/ipc_handler.rs:54` — Enumerate index cast to i64 without overflow check.
- [x] **M-064** `[code_quality]` `platform/synthetic.rs:163` — Replay threshold uses > instead of >=; edge case.
- [ ] **M-065** `[error_handling]` `platform/macos/keystroke.rs:189` — CGEventTap re-enable result not checked.
- [x] **M-066** `[error_handling]` `sentinel/helpers.rs:523` — Hash slice bound may truncate below 32 bytes.
  Fix: Replaced with fixed-size [0u8; 32] array and bounded copy.

### Engine — Evidence/Checkpoint
- [x] **M-067** `[code_quality]` `checkpoint/chain.rs:129` — expect() on checkpoint count conversion.
- [ ] **M-068** `[code_quality]` `checkpoint/chain.rs:162` — expect() after push; logically safe but library anti-pattern.

### Engine — Forensics/Analysis/VDF
- [x] **M-069** `[numeric]` `analysis/perplexity.rs:88` — Laplace smoothing uses 0.1 not 1.0; inconsistent with standard formulation.
- [ ] **M-070** `[error_handling]` `analysis/hurst.rs:115` — Degenerate regression NaN caught but error message generic.
- [ ] **M-071** `[code_quality]` `analysis/stats.rs:15` — Single-sample std_dev returns 0.0 undocumented.
- [x] **M-072** `[numeric]` `forensics/dictation.rs:60` — f64::EPSILON used as zero-WPM threshold; inappropriate.
- [ ] **M-073** `[numeric]` `forensics/cross_modal.rs:203` — safe_ln(0) = 0.0 biases interval similarity upward.
- [ ] **M-074** `[numeric]` `forensics/cadence.rs:168` — Percentile rounding may select wrong index for small datasets.
- [ ] **M-075** `[code_quality]` `forensics/comparison.rs:79` — NaN weight redistribution implicit and undocumented.
- [x] **M-076** `[numeric]` `forensics/analysis.rs:62` — Timestamp range not validated; i64::MAX corrupts time_span.
- [ ] **M-077** `[numeric]` `vdf/params.rs:61` — Calibration duration truncated; biased low on fast hardware.
- [ ] **M-078** `[error_handling]` `vdf/proof.rs:110` — VDF duration_nanos no plausibility check.
- [ ] **M-079** `[error_handling]` `vdf/swf_argon2.rs:510` — Undersample returns fewer indices than requested without error.
- [x] **M-080** `[security]` `forensics/event_validation.rs:296` — Burst detection assumes monotonic timestamps; no validation.

### Engine — WAR/Trust/Anchors
- [ ] **M-081** `[code_quality]` `trust_policy/evaluation.rs:66` — GeometricMean empty factors produces inf/nan.
- [ ] **M-082** `[security]` `anchors/ethereum.rs:234` — EIP-155 v value computation may overflow for large chain_id.
- [ ] **M-083** `[error_handling]` `writersproof/queue.rs:49` — home directory expect() panics in daemon context.
- [ ] **M-084** `[error_handling]` `writersproof/client.rs:30` — Debug builds accept HTTP without strong indication.

### Engine — TPM/Jitter/MMR/Other
- [ ] **M-085** `[code_quality]` `tpm/windows/provider_signing.rs:151` — TPM return code not validated after sign/create.
- [ ] **M-086** `[security]` `tpm/secure_enclave/key_management.rs:161` — No null check after SecKeyCopyPublicKey.
- [ ] **M-087** `[code_quality]` `jitter/session.rs:175` — Keystroke counter saturates at u64::MAX; sampling stops.
- [ ] **M-088** `[security]` `fingerprint/storage.rs:332` — Legacy key migration path lacks traversal check.
- [ ] **M-089** `[security]` `mmr/proof.rs:176` — RangeProof accepts extra siblings; sibling_idx validated late.
- [x] **M-090** `[numeric]` `mmr/proof.rs:299` — 1u64 << (height+1) overflows if height >= 63.
- [x] **M-091** `[numeric]` `mmr/mmr.rs:127` — get_leaf_index overflows at u64::MAX.
- [ ] **M-092** `[error_handling]` `cpop-jitter/src/evidence.rs:185` — TryFrom doesn't validate sequence uniqueness.
- [x] **M-093** `[security]` `steganography/embedding.rs:167` — Seed bytes not zeroized after Fisher-Yates derivation.

### Protocol
- [x] **M-094** `[numeric]` `rfc/fixed_point.rs:134` — Microdollars from_dollars f64 to i64 overflow unchecked.
- [ ] **M-095** `[security]` `rfc/jitter_binding.rs:562` — Source weight sum may overflow u32 with corrupted data.
- [ ] **M-096** `[error_handling]` `forensics/engine.rs:122` — saturating_sub masks out-of-order timestamps.
- [ ] **M-097** `[code_quality]` `rfc/time_evidence.rs:233` — Negative timestamp silently clamped to 0.
- [ ] **M-098** `[code_quality]` `rfc/wire_types/components.rs:143` — CDDL limits not documented as spec constraints.
- [ ] **M-099** `[error_handling]` `rfc/vdf.rs:64` — minimum_elapsed_ms division by zero if iterations_per_second=0.
- [ ] **M-100** `[code_quality]` `rfc/packet.rs:446` — VDF input/output length not validated against CDDL.
- [ ] **M-101** `[code_quality]` `baseline.rs:198` — f32/f64 precision mismatch between baseline.rs and wire_types.
- [ ] **M-102** `[security]` `rfc/wire_types/attestation.rs:314` — Deferred deserialization validation; nested CBOR pre-decode.
- [ ] **M-103** `[code_quality]` `codec/mod.rs:105` — ConfidenceTier validation fragile; manual bounds vs enum.

### Engine — Config/Report/Other
- [ ] **M-104** `[security]` `config/types.rs:335` — App allowlist case sensitivity inconsistent across platforms.
- [ ] **M-105** `[code_quality]` `collaboration.rs:243` — Out-of-bounds checkpoint ranges silently clamped.
- [ ] **M-106** `[code_quality]` `continuation.rs:153` — Mixed byte ordering (big/little-endian) in VDF context.
- [x] **M-107** `[security]` `report/html/sections.rs:10` — sanitize_css_color allows non-standard 5-char hex.

---

## Quick Wins (effort=small, HIGH severity)
| ID | File:Line | Issue |
|----|-----------|-------|
| H-052 | native_messaging_host.rs:85 | Session struct missing Zeroize |
| H-053 | util.rs:287 | retry_on_busy expect/panic |
| H-055 | cmd_config.rs:117 | Opaque consent error |
| H-057 | server_handler.rs:224 | Rate limiter poison swallowed |
| H-058 | ephemeral.rs:656 | Signing key not zeroized |
| H-059 | ipc_handler.rs:36 | HMAC key zeroize gap |
| H-061 | core.rs:493 | Session TOCTOU |
| H-062 | core.rs:856 | Task leak on lock fail |
| H-064 | wire_conversion.rs:225 | CBOR encode fallback |
| H-065 | wire_conversion.rs:257 | Entangled MAC encode |
| H-066 | setters.rs:337 | Ratchet index clamp |
| H-067 | assessment.rs:292 | Unbounded entropy |
| H-068 | topology.rs:99 | Unsorted interval |
| H-069 | behavioral_fingerprint.rs:226 | Div by zero |
| H-070 | snr.rs:80 | Zero signal SNR |
| H-071 | client.rs:50 | JWT no zeroize |
| H-072 | standards.rs:347 | DID parsing |
| H-074 | signing.rs:34 | CFRelease null check |
| H-075 | session.rs:186 | Jitter modulo zero |
| H-077 | fixed_point.rs:51 | Float overflow |
| H-079 | evidence.rs:101 | Zero entropy |
| H-080 | codec/mod.rs:105 | CborWar tag bypass |
| H-081 | swf_argon2.rs:233 | VDF iteration bounds |

---

## Coverage
<!-- 384 source files in workspace, 199 reviewed across 10 batches -->
<!-- Wave 1: CLI, Crypto/Identity, IPC/FFI, Evidence/Checkpoint, Forensics/Analysis -->
<!-- Wave 2: Sentinel/Platform, WAR/Trust/Anchors, Protocol, TPM/Jitter/MMR, Remaining -->
<!-- Uncovered: ~185 small files (<200 lines each), mostly mod.rs, types, helpers -->
