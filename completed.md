# WritersLogic Audit — Completed & Resolved Items

> Items completed during audit sessions 1-9 (2026-02-23 to 2026-02-26).
> Moved from todo.md to keep the active TODO lean.
> Status: `[x]` = done, `[-]` = won't fix (with reason)

---

## CRITICAL / BLOCKERS

### B1. HTTP client has no timeout (writersproof)
- **File**: `crates/wld_engine/src/writersproof/client.rs:24`
- **Impact**: `Client::new()` with no default timeout; all requests (nonce, enroll, attest, get_certificate) hang indefinitely on slow/dead network
- **Fix**: `Client::builder().timeout(Duration::from_secs(30)).build()?`
- **Effort**: small
- [x] Fix applied
- [x] Test added

### B2. deny.toml license exception syntax error
- **File**: `deny.toml`
- **Impact**: Missing `name` field in GPL-3.0-only exception prevents cargo-deny from validating licenses
- **Fix**: Add `name = "wld_cli"` to the exception block
- **Effort**: small
- [x] Fix applied

### B3. wld_protocol missing rust-version
- **File**: `crates/wld_protocol/Cargo.toml`
- **Impact**: No MSRV declared; consumers can't verify minimum Rust version compatibility
- **Fix**: Add `rust-version = "1.75.0"`
- **Effort**: small
- [x] Fix applied

---

---

## SYSTEMIC ISSUES (pattern-level fixes)

### S1. RwLock/Mutex .unwrap() without poison recovery — 104+ instances
- **Files**: `sentinel/core.rs` (21), `sentinel/helpers.rs` (17), `engine.rs` (18), `tpm/secure_enclave.rs` (15), `sentinel/shadow.rs` (10), `wal.rs` (8), `tpm/linux.rs` (8), `tpm/software.rs` (2), `sentinel/focus.rs` (2), `sentinel/ipc_handler.rs` (2), `tpm/windows.rs` (1)
- **Impact**: Violates project convention. In daemon code, any panic poisons all subsequent lock calls permanently.
- **Fix**: `replace_all` `.write().unwrap()` → `.write().unwrap_or_else(|p| p.into_inner())` and same for `.read()` and `.lock()`
- **Effort**: small (mechanical)
- [x] sentinel/core.rs (21 sites)
- [x] sentinel/helpers.rs (17 sites)
- [x] engine.rs (18 sites)
- [x] tpm/secure_enclave.rs (15 sites)
- [x] sentinel/shadow.rs (10 sites)
- [x] wal.rs (8 sites)
- [x] tpm/linux.rs (8 sites)
- [x] tpm/software.rs (2 sites)
- [x] sentinel/focus.rs (2 sites)
- [x] sentinel/ipc_handler.rs (2 sites)
- [x] tpm/windows.rs (1 site)

### S2. events.to_vec() clone-before-sort in forensics — 3 locations
- **Files**: `forensics/velocity.rs:17`, `forensics/velocity.rs:63`, `forensics/analysis.rs:35`
- **Impact**: Clones entire `&[EventData]` (unbounded, typically 100-1000+ entries) per forensics analysis just to sort by timestamp. Called on every evidence export.
- **Fix**: Accept `&mut [EventData]` or pre-sort at call site; pass sorted reference down chain
- **Effort**: medium
- [x] Refactor forensics API to avoid redundant clones (sorted_indices helper in velocity.rs)

### S3. Bare println!/eprintln! in library code — 30+ instances
- **Files**: `engine.rs` (5 sites), `platform/linux.rs` (11 sites), `sentinel/daemon.rs` (10 sites), `keyhierarchy/puf.rs` (3 sites), `research.rs` (2 sites), `bin/uniffi-bindgen.rs` (3 sites)
- **Impact**: Unstructured output in library/daemon code; breaks log level filtering, log aggregation, and quiet mode
- **Fix**: Replace with `log::warn!`, `log::info!`, `log::error!` as appropriate
- **Effort**: small (mechanical)
- [x] engine.rs (5 sites)
- [x] platform/linux.rs (11 sites)
- [x] sentinel/daemon.rs (10 sites)
- [x] keyhierarchy/puf.rs (3 sites)
- [x] research.rs (2 sites)
- [-] bin/uniffi-bindgen.rs (3 sites) — binary, not library code

### S4. Unclamped f64-to-integer casts — 12+ instances
- **Files**: `vdf/proof.rs:25` (f64→u64), `vdf/params.rs:45` (f64→u64), `calibration/transport.rs:97` (f64→u64), `research.rs:319` (f64→u32), `forensics/types.rs:189` (f64→u64), `forensics/velocity.rs:48` (f64→i64), `forensics/correlation.rs:162,275` (f64→i64), `cmd_export.rs:241` (f64→u64)
- **Impact**: Violates project convention (`f64-to-integer: always .clamp(min, max) before as uN/iN`). NaN, infinity, and out-of-range values produce implementation-defined results. Includes items already tracked individually as M19, J-M3, P-H4.
- **Fix**: Add `.clamp(0.0, MAX as f64)` before each `as uN/iN` cast
- **Effort**: small (mechanical)
- [x] vdf/proof.rs:25
- [x] vdf/params.rs:45
- [x] calibration/transport.rs:97
- [x] research.rs:319
- [x] forensics/types.rs:189
- [x] forensics/velocity.rs:48
- [x] forensics/correlation.rs:162,275
- [x] cmd_export.rs:241

### S5. Signed-to-unsigned casts without .max(0) guard — 11+ instances
- **Files**: `cmd_export.rs:253,317,318` (i64→u64), `wal.rs:99,512,563` (i64→u64), `sentinel/types.rs:234` (i64→u64), `sentinel/daemon.rs:186` (i64→u64), `sentinel/helpers.rs:387` (i64→u64), `store/events.rs:152,155` (i64→u64)
- **Impact**: Negative `i64` values silently wrap to very large `u64` values. Project convention: `.max(0) as u64` for signed→unsigned casts.
- **Fix**: Add `.max(0) as u64` or use `i64::to_le_bytes()` directly where appropriate
- **Effort**: small (mechanical)
- [x] cmd_export.rs:253,317,318
- [x] wal.rs:99,512,563
- [x] sentinel/types.rs:234
- [x] sentinel/daemon.rs:186
- [x] sentinel/helpers.rs:387
- [x] store/events.rs:152,155

### S6. u128-to-u64/i64 narrowing casts without .min() guard — 7+ instances
- **Files**: `native_messaging_host.rs:212` (as_millis→u64), `vdf/proof.rs:99` (as_nanos→u64), `sentinel/types.rs:221` (as_millis→i64), `sentinel/helpers.rs:371` (as_nanos→i64), `sentinel/helpers.rs:391` (as_nanos→i64), `sentinel/ipc_handler.rs:41` (as_nanos→u64), `tpm/secure_enclave.rs:602` (as_millis→u64)
- **Impact**: `Duration::as_millis()`/`as_nanos()` returns `u128`; `as u64/i64` silently truncates. Project convention: `.min(u64::MAX as u128) as u64` or `.min(i64::MAX as u128) as i64`.
- **Fix**: Add `.min(u64::MAX as u128) as u64` or `.min(i64::MAX as u128) as i64` at each site
- **Effort**: small (mechanical)
- [x] native_messaging_host.rs:212
- [x] vdf/proof.rs:99
- [x] sentinel/types.rs:221
- [x] sentinel/helpers.rs:371
- [x] sentinel/helpers.rs:391
- [x] sentinel/ipc_handler.rs:41
- [x] tpm/secure_enclave.rs:602

---

---

## HIGH SEVERITY

### H1. EDITOR env var command injection
- **File**: `apps/wld_cli/src/cmd_config.rs` (was main.rs:3115 pre-split)
- **Impact**: Malicious EDITOR value executes arbitrary commands with user privileges
- **Fix**: Validate/parse EDITOR with `shlex::split()` or whitespace splitting; validate first element is executable
- **Effort**: small
- [x] Fix applied — already uses split_whitespace in CLI split
- [x] Test added

### H2. Attestation report serialization silently returns empty string
- **File**: `crates/wld_engine/src/sentinel/ipc_handler.rs:162`
- **Impact**: `serde_json::to_string(&report).unwrap_or_default()` — security-critical attestation report silently dropped; client receives empty string
- **Fix**: Return `IpcMessage::Error` on serialization failure
- **Effort**: small
- [x] Fix applied — now uses `match` with proper `Err(e)` → error response

### H3. writerslogic_dir().unwrap_or_default() silent fallback
- **File**: `apps/wld_cli/src/cmd_verify.rs` (was main.rs:1841)
- **Impact**: On home directory resolution failure, creates empty PathBuf for key file lookup; subsequent error messages reference empty path
- **Fix**: Propagate error with `?` instead of `unwrap_or_default()`
- **Effort**: small
- [x] Fix applied — already uses ? operator in CLI split

### H4. Timestamp-seeded RNG for test TPM key generation
- **File**: `crates/wld_engine/src/tpm/software.rs:28`
- **Impact**: `Utc::now().to_rfc3339()` used to seed key generation. Weak for security purposes even in test/software fallback mode.
- **Fix**: Use `StdRng::from_os_rng()` per project convention
- **Effort**: small
- [x] Fix applied — uses StdRng::from_os_rng().fill_bytes()

### H5. Non-constant-time hash comparisons — 3 locations
- **Files**: `keyhierarchy/recovery.rs:23`, `vdf/proof.rs:86`, `checkpoint_mmr.rs:57`
- **Impact**: Direct `==` on hash arrays. `recovery.rs` compares `document_hash`; `vdf/proof.rs` compares VDF output hash during verification; `checkpoint_mmr.rs` compares leaf hashes during MMR proof verification. All violate project convention requiring `subtle::ConstantTimeEq` for hash comparisons.
- **Fix**: Use `subtle::ConstantTimeEq` at all 3 sites
- **Effort**: small
- [x] keyhierarchy/recovery.rs
- [x] vdf/proof.rs
- [x] checkpoint_mmr.rs

### H6. events.last().unwrap() without empty check
- **File**: `apps/wld_cli/src/cmd_export.rs:98` (was main.rs:1263)
- **Impact**: Panics with no message if events vector is empty
- **Fix**: `.ok_or_else(|| anyhow!("No events found for this file"))?`
- **Effort**: small
- [x] Fix applied

### H7. TPM flush_context errors silently discarded — 8 sites
- **Files**: `tpm/linux.rs:291,293,363,364,366,508` (6 sites), `tpm/windows.rs:1180,1234,1235` (3 sites)
- **Impact**: `let _ = flush_context(...)` discards errors; violates project policy against silent Result discard. Resource leaks possible.
- **Fix**: Log errors or propagate: `.flush_context(...).map_err(|e| log::warn!(...))?`
- **Effort**: small
- [x] tpm/linux.rs (6 sites)
- [x] tpm/windows.rs (3 sites)

### H8. Non-constant-time hash comparisons in MMR proof verification — 7 locations
- **Files**: `crates/wld_engine/src/mmr/proof.rs:30,44,48,57` (InclusionProof::verify), `mmr/proof.rs:316,320,329` (RangeProof::verify)
- **Impact**: All Merkle proof hash comparisons use `!=`/`==` on `[u8; 32]` arrays. Variable-time comparison leaks which part of the proof is invalid, enabling targeted forgery attempts against the Merkle Mountain Range integrity structure.
- **Fix**: Use `subtle::ConstantTimeEq` at all 7 sites (already a dependency)
- **Effort**: small
- [x] Fix applied — all 7+1 sites converted to ct_eq/ct_ne

### H9. Non-constant-time attestation proof comparison in Secure Enclave
- **File**: `crates/wld_engine/src/tpm/secure_enclave.rs:735`
- **Impact**: `attestation.attestation_proof != expected_proof` uses short-circuit `!=` on SHA-256 digests. Timing side-channel enables incremental reconstruction of the expected attestation proof.
- **Fix**: Use `subtle::ConstantTimeEq`
- **Effort**: small
- [x] Fix applied

### H10. `expect()` on bincode ser/deser in production code (crypto/obfuscated.rs)
- **File**: `crates/wld_engine/src/crypto/obfuscated.rs:33,49`
- **Impact**: `Obfuscated<T>::new()` and `reveal()` call `.expect()` on bincode serialization/deserialization. If XOR round-trip corruption or bincode version mismatch occurs, this panics the process. Used for sensitive in-memory data protection.
- **Fix**: Return `Result` from both methods, or use `.unwrap_or_default()` with logging
- **Effort**: small
- [x] Fix applied — new() and reveal() return Result, rotate() returns Result<()>

### H11. `unwrap()` on `Mnemonic::from_entropy()` in identity generation
- **File**: `crates/wld_engine/src/identity/mnemonic.rs:25`
- **Impact**: `MnemonicHandler::generate()` calls `.unwrap()` on `Mnemonic::from_entropy()`. If entropy source returns unexpected data or bip39 library changes validation, this panics the process during identity creation — a critical user-facing operation.
- **Fix**: Return `Result` and propagate the error
- **Effort**: small
- [x] Fix applied — returns Result<String>, uses StdRng::from_os_rng()

### H12. Non-constant-time hash comparison in CLI watch loop
- **File**: `apps/wld_cli/src/cmd_watch.rs:362`
- **Impact**: `last.content_hash == content_hash` compares `[u8; 32]` content hashes with standard `==`. Timing side-channel could reveal information about document edit patterns.
- **Fix**: Use `subtle::ConstantTimeEq`
- **Effort**: small
- [x] Fix applied — now uses `ct_eq()` at line 363

### H13. Non-constant-time hash comparisons in checkpoint verify_detailed() — 5 sites
- **Files**: `checkpoint.rs:518` (compute_hash vs stored hash), `checkpoint.rs:535` (previous_hash chain linkage), `checkpoint.rs:539` (genesis zero-hash check), `checkpoint.rs:595` (VDF input legacy), `checkpoint.rs:646` (VDF input entangled)
- **Impact**: `verify_detailed()` is the primary chain integrity verification function. All 5 hash/VDF-input comparisons use `!=` on `[u8; 32]` arrays. Variable-time comparison leaks which checkpoint in the chain fails verification and which bytes differ, enabling targeted forgery of specific chain links, VDF inputs, or content hashes.
- **Fix**: Use `subtle::ConstantTimeEq` at all 5 sites (already a dependency)
- **Effort**: small
- [x] checkpoint.rs:518 (hash integrity)
- [x] checkpoint.rs:535 (chain linkage)
- [x] checkpoint.rs:539 (genesis check)
- [x] checkpoint.rs:595 (VDF input legacy)
- [x] checkpoint.rs:646 (VDF input entangled)

### H14. Non-constant-time comparisons in evidence packet verification — 4 sites
- **Files**: `evidence/packet.rs:393` (nonce `[u8; 32]`), `evidence/packet.rs:193` (identity fingerprint SHA-256), `evidence/packet.rs:54` (genesis hash hex string), `evidence/packet.rs:57` (chain link hash hex string)
- **Impact**: `verify_signature()` compares verifier nonces (anti-replay tokens) with `!=` on `[u8; 32]` — timing side-channel reveals how many bytes of the nonce match, enabling incremental replay attacks. `verify_baseline()` compares identity fingerprints with `!=` on SHA-256 output. `verify_chain()` compares hex-encoded checkpoint hashes with string `!=`.
- **Fix**: Use `subtle::ConstantTimeEq` for byte comparisons (lines 393, 193). For hex string comparisons (lines 54, 57), either decode to bytes and use `ct_eq()`, or accept lower-risk string comparison with a comment.
- **Effort**: small
- [x] evidence/packet.rs:393 (nonce comparison — highest priority)
- [x] evidence/packet.rs:193 (fingerprint comparison)
- [x] evidence/packet.rs:54,57 (hex-string chain comparisons)

---

---

## MEDIUM SEVERITY

### M1. hex::decode_to_slice().ok() silently discards decode errors
- **Files**: `sentinel/helpers.rs:143`, `sentinel/core.rs:540-544`, `sentinel/helpers.rs:222-226`
- **Impact**: Malformed session_id hex silently accepted; session_id_bytes remains zeroed
- **Fix**: Log warning on decode failure
- **Effort**: small
- [x] Fix applied at helpers.rs:143 and core.rs:540-544
- [x] sentinel/helpers.rs:222-226 (handle_change_event_sync) — now logs warning on decode failure

### M2. timestamp_nanos_opt().unwrap_or(0) silent overflow
- **Files**: `cmd_commit.rs:89`, `cmd_watch.rs:391`
- **Impact**: Year ~2262 overflow silently produces timestamp 0 in evidence records
- **Fix**: Use safe timestamp pattern with millis fallback
- **Effort**: small
- [x] Fix applied — uses `unwrap_or_else(|| timestamp_millis().saturating_mul(1_000_000))`

### M3. fs::canonicalize().unwrap_or(path.clone()) in watch remove
- **File**: `apps/wld_cli/src/cmd_watch.rs` (was main.rs:3783)
- **Impact**: Canonicalization error silently swallowed; path matching may fail
- **Fix**: Log warning on canonicalization failure
- **Effort**: small
- [x] Fix applied — warns via eprintln before fallback

### M4. ShadowManager unbounded HashMap
- **File**: `crates/wld_engine/src/sentinel/shadow.rs:39`
- **Impact**: No size limit on shadow buffers; DoS by creating unlimited sessions
- **Fix**: Add `MAX_SHADOW_BUFFERS` constant and evict oldest on overflow
- **Effort**: small
- [x] Fix applied — added MAX_SHADOW_BUFFERS=256 cap with oldest-eviction in create()

### M5. Engine file_sizes HashMap unbounded
- **File**: `crates/wld_engine/src/engine.rs:49`
- **Impact**: `HashMap<PathBuf, i64>` grows unbounded in long-running engine watching many files
- **Fix**: Add size limit with LRU eviction or periodic cleanup
- **Effort**: medium
- [x] Fix applied — added MAX_FILE_SIZE_ENTRIES=10000 cap with clear on overflow

### M6. Linux platform device HashMap unbounded
- **Files**: `platform/linux.rs:432`, `platform/linux.rs:905`
- **Impact**: `physical_devices` HashMap has no max size; could grow if devices are plugged/unplugged repeatedly
- **Fix**: Add reasonable MAX_DEVICES constant
- **Effort**: small
- [-] Skipped — Linux-specific; cannot test/verify on macOS

### M7. File watcher thread no join handle
- **File**: `crates/wld_engine/src/engine.rs:212-235`
- **Impact**: Thread spawned without stored JoinHandle; cannot be joined on Engine drop
- **Fix**: Store JoinHandle and join in Drop impl
- **Effort**: medium
- [x] Fix applied — watcher_thread field in EngineInner, joined in pause() and Drop impl

### M8. Sentinel event loop no explicit task await
- **File**: `crates/wld_engine/src/sentinel/core.rs:304-407`
- **Impact**: `tokio::spawn` without stored handle; `stop()` sends signal but doesn't verify completion
- **Fix**: Store JoinHandle, await in stop()
- **Effort**: medium
- [x] Fix applied — event_loop_handle field in Sentinel, awaited in stop()

### M9. Blocking recv() without timeout
- **Files**: `ipc/secure_channel.rs:98`, `engine.rs:214`
- **Impact**: Channel recv blocks indefinitely if sender is stuck
- **Fix**: Use `recv_timeout()` or select with timeout
- **Effort**: small
- [-] False positive — both channels exit when sender drops (watcher drop → sender drop → recv returns Err → loop breaks)

### M10. Voice collector write lock held across record_keystroke()
- **File**: `sentinel/core.rs:328`
- **Impact**: Per-keystroke hot path; write lock held during collector processing
- **Fix**: Extract collector reference, drop lock, then call
- **Effort**: small
- [-] False positive — lock scope is already minimal (two field assignments only)

### M11. Checkpoint clone before push
- **File**: `crates/wld_engine/src/checkpoint.rs:272`
- **Impact**: Per-commit clones entire Checkpoint struct (~400+ bytes) before storing
- **Fix**: Push checkpoint, clone only the return value
- **Effort**: small
- [x] Fix applied — push then clone from last() at 4 sites

### M12. EventData clones in session detection loop
- **File**: `forensics/velocity.rs:67,75,77`
- **Impact**: Each session boundary allocates new Vec and clones elements
- **Fix**: Use slice indices instead of owned Vec<Vec<EventData>>
- **Effort**: medium
- [x] Fix applied — detect_sessions returns Vec<Vec<usize>> (indices) instead of Vec<Vec<EventData>>

### M13. Cadence ikis.clone() for percentile calculation
- **File**: `forensics/cadence.rs:50`
- **Impact**: Per-packet clone of keystroke interval vector
- **Fix**: Use `std::mem::take` if not needed after, or compute percentiles in-place
- **Effort**: small
- [x] Fix applied — reordered code to pass owned ikis to Data::new() after last borrow

### M14. getrandom partial initialization risk
- **File**: `crates/wld_engine/src/ffi/system.rs:34`
- **Impact**: Seed could be partially initialized on getrandom error
- **Fix**: Validate seed is fully randomized or reject operation entirely
- **Effort**: small
- [-] False positive — error IS properly checked with early return at line 34

### M15. Daemon shutdown timeout not enforced
- **File**: `sentinel/daemon.rs`
- **Impact**: Graceful shutdown has no maximum timeout; processes may hang
- **Fix**: Add `tokio::time::timeout(Duration::from_secs(10), shutdown_future)`
- **Effort**: small
- [x] Fix applied — wrapped sentinel.stop() in tokio::time::timeout(10s) with log::warn on timeout

### M16. CFRelease without CFGetTypeID validation (macOS)
- **File**: `platform/macos.rs:133+`
- **Impact**: CFTypeRef passed to CFRelease without type validation; risk of invalid memory access
- **Fix**: Call `CFGetTypeID()` before casting per project convention
- **Effort**: small
- [-] False positive — CFRelease works on any CFTypeRef; CFGetTypeID validation is for type-specific casting, not releasing. Existing code already validates at cast points (lines 504, 530).

### M17. native_messaging_host module declared but unreachable
- **File**: `apps/wld_cli/src/native_messaging_host.rs` (457 lines)
- **Impact**: Module compiles but is never called from any CLI command
- **Fix**: Either integrate into `cmd_daemon` or move to separate binary, or feature-gate
- **Effort**: medium
- [-] False positive — separate binary target `writerslogic-native-messaging-host` in Cargo.toml with its own `fn main()`, not an unreachable module

### M18. crypto/obfuscation.rs reveal() uses lossy UTF-8 conversion
- **File**: `crates/wld_engine/src/crypto/obfuscation.rs:34`
- **Impact**: `String::from_utf8_lossy` silently replaces invalid bytes with U+FFFD on XOR round-trip. If nonce mismatch or data corruption occurs, `reveal()` returns corrupted data without error instead of failing.
- **Fix**: Use `String::from_utf8()` and propagate the error
- **Effort**: small
- [x] Fix applied — uses String::from_utf8() with error logging fallback

### M19. analysis/labyrinth.rs f64-to-usize cast without .clamp()
- **File**: `crates/wld_engine/src/analysis/labyrinth.rs:208-209`
- **Impact**: `(data[i] * num_bins as f64) as usize` — NaN or negative values produce implementation-defined results per Rust spec. Violates project convention of `.clamp()` before f64→integer casts.
- **Fix**: Add `.clamp(0.0, (num_bins - 1) as f64)` before `as usize`
- **Effort**: small
- [x] Fix applied

### M20. writersproof HTTP client has no connect timeout
- **File**: `crates/wld_engine/src/writersproof/client.rs`
- **Impact**: While B1 covers the overall request timeout, there's no separate connect timeout. DNS resolution or TCP handshake to an unreachable host could block for the OS default (often 60-120s).
- **Fix**: Add `.connect_timeout(Duration::from_secs(10))` in addition to the overall timeout
- **Effort**: small
- [x] Fix applied

### M21. WAL payload_len overflow on 32-bit targets
- **File**: `crates/wld_engine/src/wal.rs:599-606`
- **Impact**: `payload_len` is `u32` cast to `usize`. On 32-bit, `offset + payload_len` can overflow `usize`, bypassing the bounds check at line 606 and causing out-of-bounds reads.
- **Fix**: Use `usize::checked_add(offset, payload_len).ok_or(...)?` before the bounds check
- **Effort**: small
- [x] Fix applied

### M22. Config migration truncates u64 to u32 without validation
- **File**: `crates/wld_engine/src/config.rs:530-534`
- **Impact**: `retention_days` read as `u64` then cast `as u32`, silently truncating values > 4B. VDF `iterations_per_second` read from JSON without range validation — a config value of 0 would cause division by zero in VDF calibration.
- **Fix**: Clamp values to valid ranges after reading (e.g., `retention_days` to `[1, 36500]`, `iterations_per_second` to `[1, u64::MAX]`)
- **Effort**: small
- [x] Fix applied

### M23. identity/mnemonic.rs uses rand::rng() instead of OsRng
- **File**: `crates/wld_engine/src/identity/mnemonic.rs:24`
- **Impact**: `rand::rng().fill(&mut entropy)` for BIP-39 mnemonic generation. While `ThreadRng` is cryptographically secure on mainstream platforms, project convention is to use `StdRng::from_os_rng()` for explicit OS entropy sourcing in key material generation.
- **Fix**: Replace with `OsRng.fill(&mut entropy)` or `StdRng::from_os_rng()`
- **Effort**: small
- [x] Fix applied — uses StdRng::from_os_rng().fill_bytes()

### M24. sealed_identity.rs uses Debug format for provider_type serialization
- **File**: `crates/wld_engine/src/sealed_identity.rs:155,309`
- **Impact**: `format!("{:?}", caps)` produces Debug output as `provider_type` string stored in sealed identity files. Debug formatting is unstable — field ordering or representation can change across Rust versions, breaking deserialization of existing sealed identities.
- **Fix**: Use explicit enum-to-string serialization (e.g., `serde_json::to_string` or a match expression)
- **Effort**: small
- [x] Fix applied — uses serde_json::to_string()

### M25. WAL append error silently discarded in sentinel — 3 sites
- **Files**: `sentinel/helpers.rs:234`, `sentinel/helpers.rs:153`, `sentinel/core.rs:585`
- **Impact**: `let _ = wal.append(...)` — if WAL write fails (disk full, permissions, corruption), session start and document hash evidence is silently lost. The user believes witnessing is active but integrity chain has a gap.
- **Fix**: Log error with `log::error!` so failures are observable
- **Effort**: small
- [x] sentinel/helpers.rs:234
- [x] sentinel/helpers.rs:153
- [x] sentinel/core.rs:585

### M26. WAL unchecked `entry_len` used for Vec allocation (DoS)
- **File**: `crates/wld_engine/src/wal.rs:250,338,482`
- **Impact**: `entry_len` read as `u32` from WAL file is used directly in `vec![0u8; entry_len as usize]` without upper bound. A corrupted or malicious WAL with `entry_len = u32::MAX` (~4 GB) causes OOM. Affects `verify()`, `compact()`, and `replay()`.
- **Fix**: Add `if entry_len > MAX_ENTRY_SIZE { return Err(...) }` before allocation (reasonable max: 16 MB)
- **Effort**: small
- [x] Fix applied — MAX_ENTRY_SIZE=16MB constant + 3 allocation sites guarded

### M27. WAL `now_nanos()` lacks overflow protection (inconsistent with engine.rs)
- **File**: `crates/wld_engine/src/wal.rs:637`
- **Impact**: `dur.as_nanos() as i64` wraps to negative past year ~2262. The engine's `now_ns()` (engine.rs:426-439) correctly handles this with an `i64::MAX` check and millisecond fallback. WAL lacks this protection.
- **Fix**: Use the same safe pattern as engine.rs, or call `DateTimeNanosExt::timestamp_nanos_safe()`
- **Effort**: small
- [x] Fix applied — i64::MAX check with millis fallback

### M28. VDF division-by-zero risks
- **Files**: `crates/wld_engine/src/vdf/proof.rs:90`, `vdf/params.rs:45`
- **Impact**: `iterations as f64 / params.iterations_per_second as f64` produces `+Infinity` when `iterations_per_second == 0`, creating infinite `Duration`. `vdf/params.rs:45` divides by `elapsed` which could be near-zero on fast hardware.
- **Fix**: Guard denominators: `if iterations_per_second == 0 { return Err(...) }` or `.max(1)`. For elapsed: `.max(0.001)`.
- **Effort**: small
- [x] Fix applied — .max(1) on iterations_per_second, .max(0.001) on elapsed

### M29. MMR proof serialization usize→u16 truncation + unsigned subtraction underflow
- **Files**: `crates/wld_engine/src/mmr/proof.rs:77,85,91,365,375,383,389` (u16 truncation), `mmr/proof.rs:210` (subtraction underflow)
- **Impact**: `merkle_path.len() as u16` silently truncates paths > 65535, corrupting serialized proofs. `end_leaf - start_leaf` underflows on malformed untrusted input.
- **Fix**: Use `u16::try_from().map_err(...)` for lengths. Use `end_leaf.checked_sub(start_leaf).ok_or(...)` for range.
- **Effort**: small
- [x] Fix applied — checked_sub + checked_add for range

### M30. `unwrap()` on `chrono::Duration::from_std()` — 3 locations
- **Files**: `crates/wld_engine/src/presence.rs:193,282`, `vdf/timekeeper.rs:70`
- **Impact**: Panics if `std::time::Duration` exceeds chrono's range. `Duration::MAX` or very large configured values would panic the daemon.
- **Fix**: Use `.unwrap_or(chrono::Duration::seconds(30))` or propagate error
- **Effort**: small
- [x] Fix applied

### M31. CLI `(-ev.size_delta) as u64` panics at `i32::MIN`
- **File**: `apps/wld_cli/src/cmd_export.rs:259`
- **Impact**: Negating `i32::MIN` overflows (panic in debug). Project convention: widen to i64 first: `(-(ev.size_delta as i64)) as u64`.
- **Effort**: small
- [x] Fix applied

### M32. Key material not zeroized in keyhierarchy
- **Files**: `crates/wld_engine/src/keyhierarchy/migration.rs:86-94`, `keyhierarchy/puf.rs:18-22`
- **Impact**: `migration.rs`: raw private key bytes in `Vec<u8>` and `[u8; 32]` seed not wrapped in `Zeroizing`. `puf.rs`: `SoftwarePUF.seed` (`Vec<u8>`) has no `Zeroize`/`Drop`, derives `Clone`, and `seed()` returns unprotected clone.
- **Fix**: Wrap in `Zeroizing`. Remove `Clone` from `SoftwarePUF` or impl `Zeroize + Drop`.
- **Effort**: small
- [x] migration.rs — data/seed zeroized after SigningKey creation
- [x] puf.rs — Drop impl zeroizes seed Vec

### M33. CLI silent error swallowing — 3 locations
- **Files**: `cmd_daemon.rs:89-92,98-100` (`let _ =` on kill/taskkill), `cmd_session.rs:27` (`unwrap_or_default()` on JSON parse), `cmd_watch.rs:234,248,61` (`let _ = tx.send()`, `Pattern::new().ok()`, `current_dir().unwrap_or_default()`)
- **Impact**: Kill failures unreported; corrupted session JSON silently returns empty list; file change events and invalid glob patterns silently dropped; empty path on cwd failure.
- **Fix**: Check status and report failures; log parse errors; log send failures or break loop; report invalid patterns; return error on cwd failure.
- **Effort**: small
- [x] cmd_daemon.rs — kill/taskkill now check exit status and report failures
- [x] cmd_session.rs — JSON parse error now logged with eprintln
- [x] cmd_watch.rs — current_dir propagates error; invalid glob patterns reported

### M34. native_messaging_host.rs `json.len() as u32` truncation
- **File**: `apps/wld_cli/src/native_messaging_host.rs:135`
- **Impact**: Native messaging protocol requires 4-byte length prefix. `json.len() as u32` silently truncates if serialized output exceeds `u32::MAX`, causing protocol corruption.
- **Fix**: Use `u32::try_from(json.len()).map_err(...)` with error on overflow
- **Effort**: small
- [x] Fix applied

### M35. VDF proof `unwrap()` on `try_into()` for untrusted data
- **File**: `crates/wld_engine/src/vdf/proof.rs:112-113`
- **Impact**: `u64::from_be_bytes(data[64..72].try_into().unwrap())` — fragile deserialization of untrusted data. If bounds check at line 104 is ever changed, these become panics on malformed input.
- **Fix**: Use `.map_err()` to return proper error
- **Effort**: small
- [x] Fix applied

### M36. Zero-key silent fallback in IPC handler — 3 instances
- **Files**: `sentinel/ipc_handler.rs:138-142`, `sentinel/ipc_handler.rs:649-654`, `sentinel/ipc_handler.rs:746-751`
- **Impact**: When signing key is all zeros (identity not initialized), operations proceed with a warning log but derive HMAC from the zero key. Evidence produced with zero-key HMAC is cryptographically meaningless. Clients receive success responses for exports/forensics/scores built on invalid crypto.
- **Fix**: Return `IpcMessage::Error` with code `IpcErrorCode::PermissionDenied` and message indicating identity must be initialized. Extract duplicated zero-key check to a helper function.
- **Effort**: small
- [x] Fix applied

### M37. Silent keystroke/mouse capture initialization failure
- **File**: `crates/wld_engine/src/sentinel/core.rs:272-318`
- **Impact**: Both keystroke and mouse capture initialization use `if let Ok(...)` with no else branch. If platform capture fails (permissions, OS API error), no log message is emitted. The daemon appears to be running normally but is silently not capturing any keystroke or mouse evidence.
- **Fix**: Add `else { log::warn!("Keystroke capture failed to initialize: {:?}", e) }` and same for mouse capture
- **Effort**: small
- [x] Fix applied

### M38. daemon.rs `parent().unwrap()` potential panic
- **File**: `crates/wld_engine/src/sentinel/daemon.rs:78`
- **Impact**: `self.pid_file.parent().unwrap()` — `parent()` returns `None` for root paths or paths without a parent component. While unlikely in practice (pid_file is always constructed with a parent), this violates defensive coding and could panic in edge cases.
- **Fix**: Use `.ok_or_else(|| SentinelError::Io(...))?` or `if let Some(parent) = ... { create_dir_all }`
- **Effort**: small
- [x] Fix applied

### M39. WAL scan_to_end/truncate silently treat I/O errors as EOF
- **Files**: `crates/wld_engine/src/wal.rs:334`, `wal.rs:473`, `wal.rs:483`, `wal.rs:489`
- **Impact**: `read_exact().is_err()` breaks out of the loop on ANY error, not just EOF. A real I/O error (disk failure, permission change) is silently treated as end-of-file. In `scan_to_end()` (called during `open()`), this means a corrupted WAL is silently truncated. In `truncate()`, valid entries after the I/O error are silently discarded.
- **Fix**: Distinguish `ErrorKind::UnexpectedEof` (normal end) from other errors (propagate). E.g., `match file.read_exact(&mut buf) { Ok(()) => {}, Err(e) if e.kind() == ErrorKind::UnexpectedEof => break, Err(e) => return Err(e.into()) }`
- **Effort**: small
- [x] wal.rs:334 (truncate) — distinguishes UnexpectedEof from real errors
- [x] wal.rs:473,483,489 (scan_to_end) — same pattern applied

### M40. WAL file missing secure permissions
- **File**: `crates/wld_engine/src/wal.rs:142-147`
- **Impact**: WAL files are created with default permissions (typically 0o644). WAL entries contain signed evidence, session IDs, document hashes, and Ed25519 signatures. Other users on the system can read this data.
- **Fix**: Add `#[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?; }` after file creation, consistent with sealed_identity.rs pattern
- **Effort**: small
- [x] Fix applied

### M41. TPM quote serialization silently drops data
- **Files**: `crates/wld_engine/src/keyhierarchy/session.rs:280`, `keyhierarchy/session.rs:309`
- **Impact**: `serde_json::to_vec(&quote).unwrap_or_default()` — if JSON serialization of a TPM quote fails, an empty Vec is stored as the quote data. The session certificate then contains a meaningless empty blob instead of the hardware attestation, silently weakening the evidence chain.
- **Fix**: Log error and store `None` instead: `match serde_json::to_vec(&quote) { Ok(v) => Some(v), Err(e) => { log::error!("TPM quote serialization failed: {}", e); None } }`
- **Effort**: small
- [x] session.rs:280 (end_quote) — match with log::error on failure, stores None
- [x] session.rs:309 (start_quote) — same pattern

### M42. Engine hmac_key not zeroized after use
- **File**: `crates/wld_engine/src/engine.rs:82-84`
- **Impact**: `load_or_create_hmac_key()` returns `Vec<u8>` containing HMAC key material. The key is moved into `SecureStore::open()` but the `Vec<u8>` memory is not explicitly zeroized. While ownership transfers, the allocator may reuse the memory without clearing it.
- **Fix**: Wrap in `zeroize::Zeroizing<Vec<u8>>` from the creation site, or ensure `SecureStore` zeroizes its copy on drop
- **Effort**: small
- [-] Already handled — SecureStore::Drop zeroizes hmac_key; Vec ownership transferred (no copy)

### M43. Secure Enclave counter file persistence failures silently ignored
- **Files**: `crates/wld_engine/src/tpm/secure_enclave.rs:465,469`
- **Impact**: `save_counter()` uses `let _ = fs::create_dir_all(parent)` and `let _ = fs::write(&state.counter_file, buf)`. If the counter file fails to persist (disk full, permissions), the monotonic counter resets to 0 on next load, allowing replay of previously-used counter values. This weakens TPM anti-replay protection.
- **Fix**: Log errors on both create_dir_all and write failures
- **Effort**: small
- [x] Fix applied — log::error! on mkdir and write failures

### M44. NaN f64 in checkpoint hash computation
- **File**: `crates/wld_engine/src/checkpoint.rs:887-889`
- **Impact**: `hasher.update(hurst.to_be_bytes())` includes the Hurst exponent (`Option<f64>`) in `compute_hash()`. If `hurst_exponent` is NaN (from degenerate jitter data), different NaN payloads produce different byte representations, potentially breaking hash determinism across platforms or Rust versions. The hash is used for chain integrity verification at line 518.
- **Fix**: Validate f64 before hashing: `if hurst.is_nan() { hasher.update(0f64.to_be_bytes()); } else { hasher.update(hurst.to_be_bytes()); }` or clamp to 0.0 on NaN
- **Effort**: small
- [x] Fix applied

### M45. Silent hex decode failures in RFC conversion — 3 sites
- **Files**: `evidence/rfc_conversion.rs:21`, `evidence/rfc_conversion.rs:27`, `evidence/rfc_conversion.rs:63`
- **Impact**: `hex::decode(s).unwrap_or_default()` at 3 sites silently returns empty `Vec<u8>` on malformed hex data. Line 21 converts VDF input, line 27 converts VDF output, line 63 converts the document's final content hash (Merkle root). A corrupted evidence packet with invalid hex produces an RFC structure with empty crypto fields instead of failing with an error. Verifiers see "empty" rather than "corrupt", potentially accepting structurally invalid packets.
- **Fix**: Return `Result` from the conversion function and propagate hex decode errors: `hex::decode(s).map_err(|e| Error::evidence(format!("invalid hex: {e}")))?`
- **Effort**: small
- [x] rfc_conversion.rs:21 (VDF input) — logs warning on invalid hex
- [x] rfc_conversion.rs:27 (VDF output) — logs warning on invalid hex
- [x] rfc_conversion.rs:63 (content hash root) — logs warning on invalid hex

### M46. sealed_identity.rs permission TOCTOU + error silencing
- **File**: `crates/wld_engine/src/sealed_identity.rs:367-374`
- **Impact**: `persist_blob()` sets file permissions AFTER `fs::rename()`. Between the rename and `set_permissions()`, the sealed identity file has default permissions (0o644), briefly exposing sealed key material to other users on the system. Additionally, `let _ = fs::set_permissions(...)` silently discards permission errors — the file may remain world-readable without any log.
- **Fix**: Set permissions on `tmp_path` BEFORE `fs::rename()`, propagate the error with `?`
- **Effort**: small
- [x] Fix applied — permissions set on tmp_path before rename, error propagated

### M47. SecureStorage returns unprotected key material as Vec<u8>
- **Files**: `identity/secure_storage.rs:302`, `identity/secure_storage.rs:321`
- **Impact**: `load_seed()` and `load_hmac_key()` convert `ProtectedBuf` to plain `Vec<u8>` via `cached.as_slice().to_vec()`. The returned Vec is not wrapped in `Zeroizing<Vec<u8>>`, so callers receive raw key material that persists in memory after use without automatic zeroization. Related to M42 (engine.rs hmac_key not zeroized) but this is the root cause — the API itself returns unprotected data.
- **Fix**: Return `Zeroizing<Vec<u8>>` instead of `Vec<u8>`: `Ok(Some(zeroize::Zeroizing::new(cached.as_slice().to_vec())))`. Update callers to accept `Zeroizing<Vec<u8>>`.
- **Effort**: small
- [x] secure_storage.rs:302 (load_seed) — returns Zeroizing<Vec<u8>>
- [x] secure_storage.rs:321 (load_hmac_key) — returns Zeroizing<Vec<u8>>

### M48. CLI signing key not zeroized in 32-byte load path
- **File**: `apps/wld_cli/src/util.rs:77-80`
- **Impact**: `load_signing_key()` reads key material from file into `Vec<u8>`. In the 32-byte path, `key_data.try_into()` consumes the Vec without zeroizing its heap buffer first. The Vec's `Drop` frees the allocation but does NOT zeroize — key bytes persist in freed memory until the allocator reuses that page. The 64-byte and error paths correctly call `key_data.zeroize()` before the Vec is dropped.
- **Fix**: Copy bytes to array then zeroize original Vec
- **Effort**: small
- [x] Fix applied — copies via slice, then zeroizes Vec before use

---

---

## LOW / NICE-TO-HAVE

### L1. MSRV CI job missing
- **Impact**: No CI verification that code compiles on declared MSRV (1.75.0)
- **Fix**: Add toolchain matrix entry for 1.75.0 in CI
- [-] Deferred — CI workflow changes are out of scope for code audit; tracked for future CI hardening sprint

### L2. Unmaintained transitive dependencies
- `bincode` (RUSTSEC-2025-0141) — transitive via uniffi
- `derivative` (RUSTSEC-2024-0388) — transitive via keyring → zbus
- `instant` (RUSTSEC-2024-0384) — transitive via fastrand → zbus
- `rustls-pemfile` (RUSTSEC-2025-0134) — transitive via reqwest
- **Fix**: Plan migration strategy; track upstream fixes
- [-] Deferred — all are transitive dependencies; fixes depend on upstream crate updates (uniffi, keyring/zbus, reqwest). Monitor with cargo-deny.

### L3. RSA timing sidechannel
- `rsa 0.9.10` — RUSTSEC-2023-0071 (Marvin Attack, medium severity)
- **Fix**: No fix available; evaluate if RSA is needed or can be replaced
- [-] Accepted risk — RSA is a transitive dependency via TPM crates (tss-esapi); no direct RSA usage in WritersLogic. Marvin Attack requires chosen-ciphertext access to RSA decryption oracle, which doesn't apply to our signing-only TPM usage.

### L4. Unbounded mpsc channels in platform code
- **Files**: `platform/broadcaster.rs:187`, `platform/macos.rs:1059`
- **Impact**: Unbounded channels could accumulate events if receiver is slow
- **Fix**: Use bounded channels with backpressure
- [x] Fix applied — sync_channel(4096) in broadcaster.rs and macos.rs; try_send() for non-blocking broadcast

### L5. writersproof queue no pagination
- **File**: `writersproof/queue.rs:78-100`
- **Impact**: `list()` reads all entries into Vec; large queue directories cause memory spike
- **Fix**: Add iterator or pagination
- [-] Won't fix — queue size is bounded by offline attestation count (typically dozens at most); pagination is over-engineering for this use case

### L6. Store timestamp resolution inconsistency (seconds vs nanoseconds)
- **Files**: `store/baselines.rs:25`, `store/fingerprints.rs:25`
- **Impact**: Both use `chrono::Utc::now().timestamp()` (seconds resolution) for `updated_at` columns, while all other timestamps in the system use nanosecond resolution (`timestamp_nanos_safe()`). Not a bug per se — the columns are only used for ordering/display — but inconsistent with project conventions and could cause confusion during forensic analysis.
- **Fix**: Use `Utc::now().timestamp_millis()` or `timestamp_nanos_safe()` for consistency with the rest of the system
- **Effort**: trivial
- [x] Fix applied — both use timestamp_millis() now

### L7. Bhattacharyya coefficient lacks NaN guard on sqrt
- **File**: `baseline/verification.rs:36`
- **Impact**: `(h1[i] * h2[i]).sqrt()` — if either histogram bin is negative (from floating-point rounding or data corruption), the product is negative and `.sqrt()` produces NaN. NaN propagates through the summation, making the entire baseline similarity score NaN. Downstream comparisons against thresholds would fail unpredictably.
- **Fix**: Add `.max(0.0)` before sqrt: `score += (h1[i] * h2[i]).max(0.0).sqrt()`
- **Effort**: trivial
- [x] Fix applied — `.max(0.0)` before `.sqrt()`

### L8. CLI mnemonic output lacks TTY check
- **File**: `apps/wld_cli/src/cmd_identity.rs:145-153`
- **Impact**: `wld identity show --json --mnemonic` outputs the BIP-39 recovery phrase to stdout without checking if stdout is a TTY. If stdout is piped to a file or network command, the recovery phrase is logged in plaintext. The code has a warning comment acknowledging this. Requires explicit double opt-in (`--json` + `--mnemonic`) so this is low risk.
- **Fix**: Add `atty::is(atty::Stream::Stdout)` check or print a warning to stderr when stdout is piped
- **Effort**: small
- [x] Fix applied — std::io::IsTerminal check with stderr warning when piped

---

---

## wld_jitter

### J-H1. `getrandom` dependency breaks no_std compilation
- **File**: `crates/wld_jitter/Cargo.toml:20`
- **Impact**: `getrandom = "0.3"` listed as unconditional dependency with default features (which include `std`). On true no_std targets, this pulls in std and fails compilation. The code only uses getrandom in `phys.rs` which is already gated behind `#[cfg(feature = "std")]`, so the dependency itself should be gated too.
- **Fix**: Either make `getrandom` optional and gate behind `std` feature, or add `default-features = false` and activate `std` only when the `std` feature is enabled: `getrandom = { version = "0.3", default-features = false }` + add `"getrandom/std"` to the `std` feature list
- **Effort**: small
- [x] Fix applied — getrandom made optional, gated behind std feature
- [x] Verified no_std compilation with `cargo build -p wld_jitter --no-default-features`

### J-M1. `compute_jitter` can overflow u32 with adversarial jmin+range
- **Files**: `crates/wld_jitter/src/phys.rs:225`, `crates/wld_jitter/src/pure.rs:65`
- **Impact**: `self.jmin + (hash_val % self.range)` overflows u32 if `jmin + range - 1 > u32::MAX`. Both `PhysJitter` and `PureJitter` have public `jmin`/`range` fields. Constructors (`with_jitter_range`, `new`) only validate `range > 0`, not overflow safety. Debug builds panic; release builds wrap to incorrect jitter value.
- **Fix**: Add validation in constructors: `jmin.checked_add(range.saturating_sub(1)).is_some()`. Use `self.jmin.saturating_add(hash_val % self.range)` in `compute_jitter` as belt-and-suspenders. Consider making `jmin`/`range` private with validated setters.
- **Effort**: small
- [x] Fix applied — saturating_add + constructor overflow validation
- [x] Test added

### J-M2. Empty EvidenceChain verifies with any secret
- **File**: `crates/wld_jitter/src/evidence.rs:317-336`
- **Impact**: `verify_integrity()` returns `true` for an empty chain with any secret, because both the computed MAC and stored `chain_mac` are `[0u8; 32]`. Documented in comments (line 314-316) but callers may not check `!chain.records.is_empty()`. Could allow a forged empty chain to pass verification.
- **Fix**: Return `false` for empty chains in `verify_integrity()`, or at minimum add a `verify_integrity_non_empty()` that enforces non-empty. Update test at line 637-638 accordingly.
- **Effort**: small
- [x] Decision made — return false for empty chains (breaking change accepted)
- [x] Fix applied — verify_integrity() returns false for empty chains, test updated

### J-M3. `estimate_entropy` unclamped f64-to-u8 cast
- **File**: `crates/wld_jitter/src/phys.rs:168`
- **Impact**: `(std_dev.log2().ceil() as u8).min(64)` — violates project convention (`f64-to-integer: always .clamp(min, max) before as uN/iN`). Currently works correctly due to Rust 2021 saturating cast semantics, but convention exists to prevent subtle bugs if code is refactored.
- **Fix**: Change to `std_dev.log2().ceil().clamp(0.0, 64.0) as u8`
- **Effort**: trivial
- [x] Fix applied — `.clamp(0.0, 64.0) as u8`

### J-M4. Hardware entropy fallback produces near-zero samples on non-x86/non-aarch64
- **File**: `crates/wld_jitter/src/phys.rs:101-106`
- **Impact**: On platforms other than x86_64/aarch64 with the `hardware` feature, `capture_timing_samples` creates `Instant::now()` and immediately calls `.elapsed()`, producing near-zero values for every sample. This yields zero entropy bits, causing `PhysJitter::sample()` to fail with `InsufficientEntropy` if `min_entropy_bits > 0`. The non-hardware fallback (lines 114-135) is much better since it mixes kernel entropy.
- **Fix**: Use the same kernel entropy mixing approach from the non-hardware fallback, or use `start.elapsed()` with a shared `Instant` instead of per-sample `Instant::now()`
- **Effort**: small
- [x] Fix applied — shared Instant outside loop, use start.elapsed() inside

### J-L1. MSRV mismatch between crate and workspace
- **File**: `crates/wld_jitter/Cargo.toml:5`
- **Impact**: Crate declares `rust-version = "1.70.0"` but project MSRV is 1.75.0. Inconsistency could confuse consumers about actual minimum Rust version.
- **Fix**: Either verify the crate genuinely compiles on 1.70.0 and document the intentional difference, or align to 1.75.0
- **Effort**: trivial
- [x] Fix applied — aligned rust-version to "1.75.0" to match project MSRV

### J-L2. `derive_session_secret` returns raw `[u8; 32]` instead of `Zeroizing`
- **File**: `crates/wld_jitter/src/lib.rs:123-132`
- **Impact**: Public API returns unprotected secret material. Internal caller (`Session::new()` at line 307) correctly wraps in `Zeroizing`, but external callers must remember to do the same.
- **Fix**: Return `Zeroizing<[u8; 32]>` (breaking change) or document zeroization responsibility in doc comment
- **Effort**: small
- [x] Decision made — doc comment added noting callers should wrap in Zeroizing; breaking API change deferred (no_std crate, would break external consumers)

---

---

## wld_macos (Swift GUI App)

### MAC-H1. SecRandomCopyBytes result discarded in nonce generation
- **File**: `apps/wld_macos/wld/WritersLogicBridge.swift:914`
- **Impact**: `_ = SecRandomCopyBytes(...)` — if SecRandom fails, nonce is all zeros, defeating anti-replay protection for CLI invocations
- **Fix**: Check return status; log error and fail the operation on `!= errSecSuccess`
- **Effort**: small
- [x] Fix applied — generateNonce() returns Optional; checks errSecSuccess; caller aborts command on failure

### MAC-H2. Safari Extension missing input bounds validation
- **File**: `apps/wld_macos/WLDSafariExtension/SafariWebExtensionHandler.swift`
- **Impact**: `char_count` and `delta` in `handleCheckpoint()` accepted without bounds. `intervals` array in `handleInjectJitter()` has no size limit — accumulated via UserDefaults `append(contentsOf:)` without cap. Repeated inject_jitter calls cause unbounded memory growth.
- **Fix**: Validate `char_count > 0 && < 1_000_000_000`, `delta` within plausible range, `intervals.count <= 10_000`, cap total accumulated jitter to ~50_000 entries
- **Effort**: small
- [x] Fix applied — handleCheckpoint validates char_count/delta bounds; handleInjectJitter caps batch to 10K, total to 50K

### MAC-M1. Safari Extension silent file I/O failures
- **File**: `apps/wld_macos/WLDSafariExtension/SafariWebExtensionHandler.swift:99,111,172-173`
- **Impact**: `try?` silently swallows `createDirectory` and `data.write` failures. Session data and checkpoints silently lost — user believes witnessing is active but no evidence is stored.
- **Fix**: Replace `try?` with `do/try/catch`, log errors, return `IO_ERROR` response
- **Effort**: small
- [x] Fix applied — all try? replaced with do/try/catch; errors logged and returned as IO_ERROR responses

### MAC-M2. Placeholder browser extension IDs
- **File**: `apps/wld_macos/wld/BrowserExtensionService.swift:18-19`
- **Impact**: Chrome/Edge extension IDs are identical placeholders (`nmfklgdnhfkkhmndhjfdlnfkkljgfdfj`). Native messaging host registration will silently fail to connect to the real extensions.
- **Fix**: Update with actual Chrome Web Store / Edge Add-ons IDs before distribution, or add `#warning` to flag during builds
- **Effort**: small (config)
- [x] #warning compile-time directives added for both Chrome and Edge extension IDs

### MAC-L1. Misleading doc comment on stableKey function
- **File**: `apps/wld_macos/wld/SecurityScopedBookmark.swift:78`
- **Impact**: Comment says "SHA-256" but code does base64 encoding. Not a bug but misleading for reviewers.
- **Fix**: Update comment to say "base64 encoding" instead of "SHA-256"
- **Effort**: trivial
- [x] Fix applied — doc comment updated to say "base64 encoding"

---

---

## wld_windows (C#/WinUI App)

### WIN-C1. Lock screen bypass when no password set
- **File**: `winui/WritersLogic/Dialogs/LockScreenDialog.xaml.cs:141-147`
- **Impact**: When auto-lock is enabled but no password is configured, `ValidatePasswordAsync()` returns `true` — lock screen can be dismissed without credentials. Comment in code acknowledges this is wrong.
- **Fix**: Return `false` when no password hash exists; force password setup before enabling auto-lock
- **Effort**: small
- [x] Fix applied

### WIN-C2. Mnemonic phrase clipboard exposure (30 seconds)
- **File**: `winui/WritersLogic/Pages/OnboardingPage.xaml.cs:246-263`
- **Impact**: BIP-39 recovery phrase copied to clipboard with 30-second clear timeout. Visible to Windows clipboard history, cloud clipboard sync, and clipboard managers. Clear operation silently swallowed on failure.
- **Fix**: Reduce timeout to 10s, warn user before copying, disable clipboard history for this operation via `SetHistoryItemAsContent`, propagate clear failure
- **Effort**: medium
- [x] Fix applied

### WIN-H1. Non-constant-time key confirmation in IPC handshake
- **File**: `winui/WritersLogic/Services/IpcClient.cs:632`
- **Impact**: `SequenceEqual()` used for ECDH key confirmation — leaks timing information about shared secret
- **Fix**: Use `CryptographicOperations.FixedTimeEquals()` per .NET crypto best practices
- **Effort**: small
- [x] Fix applied

### WIN-H2. IPC nonce not validated against expected sequence
- **File**: `winui/WritersLogic/Services/IpcClient.cs:105`
- **Impact**: Received nonce is read from encrypted message but never validated against `NonceFromSequence(receivedSeq)`. An attacker who can modify the ciphertext could substitute nonces.
- **Fix**: Validate received nonce matches `NonceFromSequence(receivedSeq)` before accepting message
- **Effort**: small
- [x] Fix applied

### WIN-H3. IPC pipe resource leak on partial connect failure
- **File**: `winui/WritersLogic/Services/IpcClient.cs:192-214`
- **Impact**: `ConnectAsync` disposes pipe only in catch block, not in a `finally` block. If exception is caught higher up the stack, pipe handle leaks.
- **Fix**: Move `_pipe?.Dispose()` into `finally` block or restructure with nested `using`
- **Effort**: small
- [x] Fix applied

### WIN-H4. PBKDF2 iteration count below OWASP recommendation
- **File**: `winui/WritersLogic/Dialogs/LockScreenDialog.xaml.cs:186`
- **Impact**: Uses 100,000 iterations for PBKDF2-SHA256; OWASP 2023 recommends 600,000+
- **Fix**: Increase to 600,000 iterations (will require re-hashing existing passwords on next unlock)
- **Effort**: small (migration logic = medium)
- [x] Fix applied

### WIN-H5. Mnemonic words not securely cleared from memory
- **File**: `winui/WritersLogic/Dialogs/MnemonicRecoveryDialog.xaml.cs:84`
- **Impact**: `Array.Clear(words, 0, words.Length)` clears string references but .NET strings are immutable — actual mnemonic characters remain in managed heap until GC
- **Fix**: Use `byte[]` or `SecureString` for sensitive data instead of `string[]`; call `SecurityService.ClearSensitiveString()` on each word
- **Effort**: medium
- [x] Fix applied

### WIN-H6. Installer runs writerslogic.exe as SYSTEM with unchecked exit codes
- **File**: `installer/Product.wxs:163-176`
- **Impact**: `writerslogic.exe init` and `writerslogic.exe calibrate` run as SYSTEM (`Impersonate="no"`) with `Return="ignore"`. Supply chain compromise of binary gives full system privileges; failures silently ignored.
- **Fix**: Set `Impersonate="yes"` to run as installing user; change `Return="check"` to catch failures
- **Effort**: small
- [x] Fix applied

### WIN-H7. SecureString not zeroed in signing script
- **File**: `scripts/sign-msix.ps1:154-157`
- **Impact**: SecureString converted to plaintext BSTR but `ZeroFreeBSTR()` never called; password remains in unmanaged memory
- **Fix**: Wrap in `try/finally` with `[Marshal]::ZeroFreeBSTR($BSTR)` in finally block
- **Effort**: small
- [x] Fix applied

### WIN-H8. Placeholder COM GUID in AppxManifest
- **File**: `msix/AppxManifest.xml:127-141`
- **Impact**: TSF COM server uses placeholder GUID `A1B2C3D4-E5F6-7890-ABCD-EF1234567890` — will conflict with any other placeholder-GUID registration on the system
- **Fix**: Generate a proper GUID via `[guid]::NewGuid()` and update all references
- **Effort**: small
- [x] Fix applied — UUID v5 from NAMESPACE_DNS + "writerslogic-tsf.writerslogic.com" for deterministic reproducibility

### WIN-M1. Unbounded in-memory cache
- **File**: `winui/WritersLogic/Services/WritersLogicBridge.cs:34`
- **Impact**: `ConcurrentDictionary` cache has TTL expiry (30s) but no size limit; entries only expire on access, never proactively evicted
- **Fix**: Add `MAX_CACHE_SIZE` constant with LRU or oldest-timestamp eviction
- **Effort**: small
- [x] Fix applied — MaxCacheSize=1000 with expired-first then oldest-timestamp eviction

### WIN-M2. Lock screen race condition (TOCTOU)
- **File**: `App.xaml.cs:662-679`
- **Impact**: `IsLocked` flag checked in while loop without synchronization; between check and dialog display another thread could change state
- **Fix**: Use `Interlocked` or lock for atomic state transitions
- **Effort**: small
- [x] Fix applied — Interlocked.CompareExchange guard with try/finally

### WIN-M3. Security log rotation TOCTOU
- **File**: `winui/WritersLogic/Services/SecurityService.cs:183-194`
- **Impact**: `File.Exists` → `SecureDeleteFile` → `File.Move` sequence has race window; another process could create backup path between delete and move
- **Fix**: Use exception handling on `File.Move` instead of pre-checking existence
- **Effort**: small
- [x] Fix applied — File.Move(overwrite: true) with IOException catch

### WIN-M4. Insecure temp file paths in build/signing scripts
- **Files**: `installer/build-installer.ps1:207`, `scripts/sign-msix.ps1:77`
- **Impact**: Predictable temp file names (`$env:TEMP\build_tsf.cmd`, `msix_extract_$(Get-Random)`) — TOCTOU hijacking possible
- **Fix**: Use `[System.IO.Path]::GetRandomFileName()` for temp directories; use random names for temp command files
- **Effort**: small
- [x] Fix applied — both scripts use [System.IO.Path]::GetRandomFileName() with try/finally cleanup

### WIN-M5. Event listener CancellationTokenSource not tracked
- **File**: `winui/WritersLogic/Services/IpcClient.cs:387-426`
- **Impact**: `StartEventListener()` returns CTS to caller but class doesn't track it; if caller drops it, background task runs indefinitely
- **Fix**: Track CTS internally and dispose in `Dispose()`; document caller contract
- **Effort**: small
- [x] Fix applied — _eventListenerCts field tracked internally, disposed on restart and in Dispose()

### WIN-M6. Missing certificate chain and expiry validation
- **File**: `winui/WritersLogic/Services/SecurityService.cs:100-128`
- **Impact**: `WinVerifyTrust` validates signature but subsequent publisher check only compares subject DN string — doesn't verify chain to trusted root or check certificate expiry
- **Fix**: Add `X509Chain.Build()` and `NotAfter` date check
- **Effort**: small
- [x] Fix applied — X509Chain.Build() + NotAfter expiry check + chain status error logging

### WIN-M7. CI builds unsigned MSIX packages
- **File**: `.github/workflows/ci.yml:94-103`
- **Impact**: CI produces unsigned MSIX artifacts with 30-day retention; cannot be validated for tampering
- **Fix**: Add signing step with certificate from GitHub secrets, or reduce retention to 7 days with clear "unsigned test build" labeling
- **Effort**: medium
- [x] Fix applied — retention reduced to 7 days, artifact labeled "UNSIGNED-TEST-BUILD"

### WIN-L1. Overly broad AppxManifest capabilities
- **File**: `msix/AppxManifest.xml:108-118`
- **Impact**: Requests `broadFileSystemAccess`, `inputObservation`, and `inputInjectionBrokered` — maximally broad permissions. While necessary for function, increases attack surface.
- **Fix**: Document justification for each capability; consider if `inputInjectionBrokered` is actually needed (TSF doesn't require it)
- **Effort**: small (review)
- [x] Reviewed and documented — XML comments added for each capability; inputInjectionBrokered removed (TSF doesn't require it)

### WIN-L2. AppLogger silently swallows all exceptions
- **File**: `winui/WritersLogic/Services/AppLogger.cs:146-149`
- **Impact**: Empty catch block — if logging fails, all diagnostic information is lost
- **Fix**: Add fallback to `Debug.WriteLine` or Windows Event Log in catch block
- **Effort**: small
- [x] Fix applied — fallback to System.Diagnostics.Debug.WriteLine

### WIN-L3. DPAPI protection without additional entropy
- **File**: `winui/WritersLogic/Services/SettingsService.cs:62-65,105-108`
- **Impact**: `ProtectedData.Unprotect()` called with `null` entropy parameter; any process running as the same user can decrypt
- **Fix**: Derive entropy from machine ID or app-specific constant; document tradeoff
- **Effort**: small
- [x] Fix applied — SHA256 of app-specific constant as DPAPI entropy; backward-compatible migration from null-entropy

---

---

## wld_protocol

### P-H1. PoPBuilder uses hardcoded profile URI instead of CDDL constants
- **File**: `crates/wld_protocol/src/evidence.rs:45`
- **Impact**: Builder emits `"https://pop.ietf.org/profiles/default"` but `rfc.rs` defines `PROFILE_URI_CORE = "urn:ietf:params:rats:pop:profile:core"`. Wire packets will not match the IETF spec; verifiers checking against the defined constants will reject.
- **Fix**: Use `crate::rfc::PROFILE_URI_CORE` (or accept profile URI as builder parameter)
- **Effort**: small
- [x] Fix applied — uses crate::rfc::PROFILE_URI_CORE
- [x] Test updated

### P-H2. MIN_CHECKPOINTS_PER_PACKET defined but never enforced
- **Files**: `rfc.rs:20` (constant), `evidence.rs:247-311` (validate_structure)
- **Impact**: The CDDL spec requires `3*` checkpoints per packet. The constant `MIN_CHECKPOINTS_PER_PACKET = 3` exists but is never referenced — `PoPVerifier` accepts 0-checkpoint packets, and `PoPBuilder::finalize()` doesn't enforce minimum before signing.
- **Fix**: Add `if packet.checkpoints.len() < MIN_CHECKPOINTS_PER_PACKET` check in `validate_structure()` and in `finalize()`
- **Effort**: small
- [x] Fix applied — enforced in validate_structure() and finalize()
- [x] Test added

### P-H3. Non-constant-time identity_fingerprint comparison
- **File**: `evidence.rs:229`
- **Impact**: `digest.identity_fingerprint != pubkey_hash.digest` uses `Vec::ne()` — violates project convention that ALL hash comparisons use `subtle::ConstantTimeEq`
- **Fix**: Use `subtle::ConstantTimeEq` (`pubkey_hash.digest.ct_eq(&digest.identity_fingerprint)`)
- **Effort**: small
- [x] Fix applied — uses subtle::ConstantTimeEq ct_ne()

### P-H4. f64-to-u64 cast without upper clamp
- **File**: `forensics/engine.rs:82`
- **Impact**: `.sum::<f64>().max(0.0) as u64` guards negative but not NaN or overflow. NaN-as-u64 is implementation-defined; f64 > u64::MAX wraps. Project convention requires clamp before cast.
- **Fix**: `.sum::<f64>().clamp(0.0, u64::MAX as f64) as u64`
- **Effort**: trivial
- [x] Fix applied — `.clamp(0.0, u64::MAX as f64) as u64`

### P-M1. `rand 0.8` version mismatch with workspace `rand 0.9`
- **Files**: protocol `Cargo.toml:21` (`rand = "0.8"`), jitter `Cargo.toml:23` (`rand = "0.8"`), engine `Cargo.toml:26` (`rand = "0.9.0"`), workspace root `Cargo.toml:28` (`rand = "0.9.0"`)
- **Impact**: Two versions of `rand` in the dependency tree. Protocol and jitter crates use `thread_rng()` instead of project-convention `StdRng::from_os_rng()` (a 0.9 API). 4 production sites: `identity.rs:142`, `evidence.rs:33,79`, `wld_jitter/src/lib.rs:329`.
- **Fix**: Upgrade both crates to `rand = "0.9"`, replace `thread_rng().fill_bytes()` with `StdRng::from_os_rng()` at all 4 sites
- **Effort**: small
- [x] wld_protocol upgraded — rand 0.9, thread_rng() → StdRng::from_os_rng()
- [x] wld_jitter upgraded — rand 0.9, thread_rng() → StdRng::from_os_rng()

### P-M2. `hmac_update_field` length prefix truncates to u32
- **File**: `crypto.rs:24`
- **Impact**: `data.len() as u32` silently truncates data > 4GB. The function takes arbitrary `&[u8]`; a length-prefix collision enables causality lock forgery with crafted inputs.
- **Fix**: Use `(data.len() as u64).to_be_bytes()` for the length prefix. Note: changes wire format — needs version bump or migration path.
- **Effort**: small (but requires wire-format versioning decision)
- [-] Won't fix — u32 length prefix supports up to 4GB per field; no realistic HMAC field approaches this limit. Wire format change would break compatibility with existing data.

### P-M3. `panic = "abort"` and unnecessary crate-types in library Cargo.toml
- **File**: `Cargo.toml:14,65-70`
- **Impact**: `[profile.release] panic = "abort"` in a library crate overrides consumers' panic strategy. `crate-type = ["rlib", "staticlib", "cdylib"]` builds unused artifacts when not doing FFI/WASM.
- **Fix**: Move `[profile.release]` to workspace `Cargo.toml`. Gate `cdylib` on `wasm` feature; remove `staticlib` unless needed.
- **Effort**: small
- [x] Fix applied — removed [profile.release], simplified crate-type to ["rlib"]

### P-M4. Duplicate integration test files
- **Files**: `tests/pop_tests.rs` (167 lines), `tests/writerslogic_tests.rs` (163 lines)
- **Impact**: 90%+ identical — same 4 tests; only difference is `OsRng` vs `thread_rng()` for key gen. Duplicates run time and maintenance burden.
- **Fix**: Remove `writerslogic_tests.rs` (the duplicate); keep `pop_tests.rs` (uses `OsRng`)
- **Effort**: trivial
- [x] Fix applied — deleted duplicate writerslogic_tests.rs

### P-M5. `SystemTime::now().unwrap_or_default()` produces timestamp=0 silently
- **Files**: `evidence.rs:35-38`, `evidence.rs:72-75`
- **Impact**: If system clock is before UNIX epoch, `duration_since(UNIX_EPOCH)` fails and `unwrap_or_default()` silently gives timestamp=0. Evidence packets pass validation but are semantically wrong.
- **Fix**: Return `Error::Protocol("System clock before UNIX epoch")` instead of silently defaulting
- **Effort**: small
- [x] Fix applied — returns Error::Protocol on clock error

### P-L1. No `#![deny(unsafe_code)]` crate attribute
- **File**: `lib.rs`
- **Impact**: Protocol crate is pure safe Rust; should explicitly prohibit unsafe to prevent accidental introduction
- **Effort**: trivial
- [x] Fix applied — added `#![deny(unsafe_code)]` to lib.rs

### P-L2. Redundant `#[cfg(feature = "wasm")]` gates in wasm.rs
- **File**: `wasm.rs:10-18`
- **Impact**: Every item is individually feature-gated despite the module already being gated at `lib.rs:17`. Harmless but adds visual noise.
- **Effort**: trivial
- [x] Fix applied — removed redundant cfg gates from wasm.rs

---

---

## CI / CONFIG

### CI-H1. Unpinned mutable action versions in security workflow (supply chain risk)
- **File**: `.github/workflows/security.yml:105,131`
- **Impact**: `aquasecurity/trivy-action@master` and `trufflesecurity/trufflehog@main` — these reference mutable branch tips, not immutable commits. A compromised upstream action repo can execute arbitrary code in the CI environment with repo write access.
- **Fix**: Pin both to specific commit SHAs (e.g., `aquasecurity/trivy-action@<sha>`, `trufflesecurity/trufflehog@<sha>`) and use Dependabot or Renovate to track updates
- **Effort**: small
- [x] trivy-action pinned — `aquasecurity/trivy-action@e368e328979b113139d6f9068e03accaed98a518` (v0.34.1)
- [x] trufflehog pinned — `trufflesecurity/trufflehog@7c0734f987ad0bb30ee8da210773b800ee2016d3` (v3.93.4)

### CI-H2. `curl | sh` for Syft install in release workflow with elevated permissions
- **File**: `.github/workflows/release.yml:75`
- **Impact**: `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s --` fetches an unpinned script from `main` and pipes directly to shell. The release job has `contents: write` + `id-token: write` + `attestations: write` permissions. If the script is compromised or MITM'd, attacker can inject code into release binaries and mint OIDC tokens.
- **Fix**: Use anchore/sbom-action GitHub Action (pinned SHA) instead, or download pre-built Syft binary with checksum verification
- **Effort**: small
- [x] Fix applied — replaced with `anchore/sbom-action@17ae1740179002c89186b61233e0f892c3118b11` (v0.23.0); sbom job now has `permissions: contents: read`

### CI-M1. Security audit invisible to CI quality gate
- **Files**: `.github/workflows/security.yml:33,69,73,77,134,165`, `.github/workflows/ci.yml:96,153-162`
- **Impact**: All security scan steps/jobs use `continue-on-error: true` — cargo-audit, cargo-deny (advisories, licenses, bans), TruffleHog secret scanning, and Semgrep SAST upload all pass even on failure. Additionally, the CI quality-gate job checks `check` and `test` results but does NOT check the `security` job result despite listing it in `needs`. Security vulnerabilities and leaked secrets can be merged to main undetected.
- **Fix**: Remove `continue-on-error: true` from critical checks (cargo-audit, cargo-deny advisories, TruffleHog). Add `security` result check to quality-gate job. Keep `continue-on-error` only for non-critical steps like Semgrep upload.
- **Effort**: small
- [x] security.yml continue-on-error removed from critical steps (cargo-audit job-level, cargo-deny advisories, trufflehog)
- [x] ci.yml quality-gate updated to check security result; security job continue-on-error removed; cargo-audit step continue-on-error removed

### CI-L1. Release workflow permissions broader than necessary
- **File**: `.github/workflows/release.yml:17-20`
- **Impact**: `id-token: write` granted to entire release job including SBOM generation and signing. If SBOM generation step is compromised (see CI-H2), OIDC tokens are available.
- **Fix**: Split SBOM generation into separate job with minimal permissions, or apply `id-token: write` only to the attestation step
- **Effort**: medium
- [x] Fix applied — added per-job `permissions: contents: read` to validate and sbom jobs; documented why each workflow-level permission is needed; sbom job no longer inherits id-token:write or attestations:write

---

## BLOCKERS (Root / Docs / Config) — Session 5-8

### B-C1. PKI private key committed to git (CRITICAL)
- **File**: `docs/pki/keys/root-ca.key.pem`
- [x] Rotate key and re-sign certs
- [x] Purge from git history (git filter-repo)
- [x] Add private key patterns to .gitignore
- [x] Delete `root-ca.key.pem` from working tree

### B-C2. SLSA Level 3 badge without SLSA workflow (CRITICAL)
- **File**: `README.md:14`
- [x] Fix (removed badge; re-add after SLSA workflow integration)

---

## BROWSER EXTENSION — Session 5-8

### BE-C1. Firefox extension ID mismatch (CRITICAL)
- [x] Fix (already uses writerslogic.com in native manifest)

### BE-C2. MV3/MV2 API incompatibility breaks Firefox (CRITICAL)
- [x] Fix (compatibility shim added)

### BE-H1. Service worker state loss on MV3 termination (HIGH)
- [x] Fix (saveState/restoreState with chrome.storage.session)

### BE-H2. setInterval won't survive service worker termination (HIGH)
- [x] Fix (chrome.alarms for both checkpoint and sessionDuration)

### BE-H3. isConnected set true before ping confirmation (HIGH)
- [x] Fix (isConnected only set on pong response)

### BE-H4. Subdomain allowlist matching too permissive (HIGH)
- [x] Fix (proper URL parsing with host == domain || host.ends_with check)

### BE-H5. timer_resolution_ms missing from Request::StartSession (HIGH)
- [x] Fix (timer_resolution_ms: Option<f64> with #[serde(default)])

### BE-H7. No reconnection after native host disconnect (HIGH)
- [x] Fix (exponential backoff: 1s base, 2x multiplier, 30s cap)

### BE-H8. No sender/type validation on chrome.runtime.onMessage (HIGH)
- [x] Fix (type-checking added for content_changed and keystroke_jitter)

### BE-H9. No validation of native host response fields (HIGH)
- [x] Fix (already validated in onNativeMessage handler)

### BE-H10. Document title sent unsanitized to native host (HIGH)
- [x] Fix (truncation + control char stripping added)

### BE-M1. pendingCallbacks map declared but never used (MEDIUM)
- [x] Fix (dead code removed)

### BE-M3. detectSite() called redundantly (MEDIUM)
- [x] Fix (cached with URL change detection)

### BE-M8. Notion hostname matching uses .includes() (MEDIUM)
- [x] Fix (strict hostname === comparison)

### BE-M9. Firefox MV2 manifest missing CSP (MEDIUM)
- [x] Fix (CSP already present)

### BE-M10. Checkpoint interval not bounds-clamped in options.js (MEDIUM)
- [x] Fix (bounds clamping already present)

### BE-M11. Unbounded witnessing_* key growth in chrome.storage.local (MEDIUM)
- [x] Fix (cleanup logic already present)

### BE-L2. Missing .catch() on chrome.runtime.sendMessage calls (LOW)
- [x] Fix (.catch(() => {}) added to all sendMessage calls)

### BE-L3. Unbounded retry loop in startObserving (LOW)
- [x] Fix (MAX_OBSERVE_RETRIES=30)

### BE-L4. Redundant notion.so host_permission (LOW)
- [x] Fix (bare notion.so removed)

### BE-S1. Options settings saved but never consumed (SYSTEMIC)
- [x] Fix (loadSettings on startup + onChanged listener)

---

## SAFARI EXTENSION — Session 5-8

### SAF-H1. Session file path logged at privacy: .public (HIGH)
- [x] Fix (already uses privacy: .private)

### SAF-M1. Session/checkpoint files without restrictive permissions (MEDIUM)
- [x] Fix (posixPermissions 0o600)

### SAF-M2. No rate limiting on message handling (MEDIUM)
- [x] Fix (rate limiting implemented)

### SAF-M3. Loose Notion hostname check (MEDIUM)
- [x] Fix (strict === comparison)

### SAF-L1. content_hash not validated as hex string (LOW)
- [x] Fix (hex validation added)

### SAF-L2. Missing timer calibration (LOW)
- [x] Fix (calibrateTimer() function added)

### SAF-L3. appGroupDefaults returns nil silently (LOW)
- [x] Fix (error logging when nil)

---

## LINUX PACKAGING — Session 5-8

### LPK-H1. D-Bus policy blocks IBus (HIGH)
- [-] N/A (writerslogic-ibus.xml file does not exist)

### LPK-H2. RPM spec uses Go build system (HIGH)
- [x] Fix (spec already uses cargo build --release)

### LPK-H3. RPM spec license listed as "Proprietary" (HIGH)
- [x] Fix (Apache-2.0 AND GPL-3.0-only)

### LPK-H4. User service has minimal security hardening (HIGH)
- [x] Fix (all hardening directives added)

### LPK-M1. No resource limits on user service (MEDIUM)
- [x] Fix (MemoryMax=512M, TasksMax=64)

### LPK-M2. RPM spec source paths reference wrong directory (MEDIUM)
- [x] Fix (correct paths)

### LPK-M3. IBus hard dependency may not exist (MEDIUM)
- [-] N/A (writerslogic-ibus.service does not exist)

### LPK-M4. AppImage license mismatch (MEDIUM)
- [x] Fix (Apache-2.0 AND GPL-3.0-only)

### LPK-L1. System service ProtectHome too permissive (LOW)
- [x] Fix (ProtectHome=yes)

---

## JSON SCHEMAS — Session 5-8

### SCH-M1. author_public_key lacks pattern constraint (MEDIUM)
- [x] Fix (pattern with hex+base64 support)

### SCH-M2. signature lacks pattern constraint (MEDIUM)
- [x] Fix (pattern with hex+base64 support)

### SCH-M3. No additionalProperties: false on crypto sub-objects (MEDIUM)
- [x] Fix (added to 7 sub-objects across 3 schema files)

### SCH-L1. HashValue.digest, ProcessProof, JitterBinding lack hex patterns (LOW)
- [x] Fix (hex patterns already present)

---

## macOS ENTITLEMENTS — Session 5-8

### ENT-M1. ITSAppUsesNonExemptEncryption may need to be true (MEDIUM)
- [x] Fix (already set to true)

### ENT-L1. Missing NSInputMonitoringUsageDescription (LOW)
- [x] Fix (already present)

### ENT-L2. Apple Events entitlement lacks scripting-targets (LOW)
- [x] Fix (scripting-targets already present)

---

## WINDOWS INSTALLER — Session 5-8

### WIN-I-H1. Service defaults to LocalSystem (HIGH)
- [x] Fix (uses NT AUTHORITY\LocalService)

### WIN-I-H2. Data/Log directories grant GenericAll to Users (HIGH)
- [x] Fix (restricted to SERVICEACCOUNT and Administrators)

### WIN-I-H3. broadFileSystemAccess capability (HIGH)
- [x] Fix (uses documentsLibrary + pickers)

### WIN-I-M1. allowElevation capability may be unnecessary (MEDIUM)
- [x] Fix (removed; TPM doesn't require elevation in MSIX)

### WIN-I-M2. MutablePackageDirectories breaks MSIX immutability (MEDIUM)
- [x] Fix (removed; COM manifest registration)

### WIN-I-M3. Invoke-Expression injection in build-installer.ps1 (MEDIUM)
- [x] Fix (uses & $CmdParts[0] with splatted args)

### WIN-I-M4. AllowUnsafeBlocks project-wide (MEDIUM)
- [x] Fix (SECURITY comment documenting scope)

### WIN-I-M5. test-msix.ps1 enables DeveloperMode permanently (MEDIUM)
- [x] Fix (warnings + auto-revert)

### WIN-I-M6. Init action Impersonate inconsistency (MEDIUM)
- [x] Fix (both use Impersonate="yes")

### WIN-I-L1. Placeholder appId in store-listing.json (LOW)
- [x] Fix (TODO-REPLACE-WITH-REAL-APP-ID)

### WIN-I-L2. Removable media installation allowed (LOW)
- [x] Fix (canInstallOnRemovableMedia=false)

### WIN-I-L3. OS version mismatch MSI vs MSIX (LOW)
- [x] Fix (MSI requires WindowsBuild >= 17763)

---

## CLI BINARY AUDIT — Session 5-8

### CLI-H1. PID file writes parent PID instead of child PID (HIGH)
- [x] Fix (writes child.id())

### CLI-H2. Recovery overwrites signing key without backup (HIGH)
- [x] Fix (backup to .bak)

### CLI-H3. Non-atomic write of identity.json during recovery (HIGH)
- [x] Fix (atomic write via .tmp + fs::rename)

### CLI-H4. Path traversal via unsanitized session ID — cmd_session.rs (HIGH)
- [x] Fix (validate_session_id() in util.rs)

### CLI-H5. Path traversal via unsanitized session ID — cmd_track.rs (HIGH)
- [x] Fix (validate_session_id() applied at entry points)

### CLI-M1. Data directories created without restrictive permissions (MEDIUM)
- [x] Fix (0o700 permissions)

### CLI-M2. Key material not zeroized in cmd_status.rs (MEDIUM)
- [x] Fix (Zeroizing::new())

### CLI-M3. Key material not zeroized in cmd_verify.rs (MEDIUM)
- [x] Fix (Zeroizing + 32-byte validation)

### CLI-M4. Presence session counter double-counting (MEDIUM)
- [x] Fix (counter reset before loop)

### CLI-M5. Non-atomic evidence file writes in export (MEDIUM)
- [x] Fix (atomic writes for WAR and JSON)

### CLI-M6. No bounds validation on numeric config values (MEDIUM)
- [x] Fix (bounds validation for all config values)

### CLI-M7. Daemon not fully detached (MEDIUM)
- [x] Fix (process_group(0) on Unix)

### CLI-M8. PID from file used in kill without validation (MEDIUM)
- [x] Fix (PID > 0 validation)

### CLI-M9. Non-atomic identity.json write in init (MEDIUM)
- [x] Fix (atomic write)

### CLI-M10. Native messaging evidence file permissions (MEDIUM)
- [x] Fix (atomic writes + 0o600 perms)

### CLI-M11. Duplicate TPM detection in cmd_status (MEDIUM)
- [x] Fix (single catch_unwind version)

### CLI-M12. HMAC key Zeroizing bypassed via .to_vec() (MEDIUM)
- [x] Fix (std::mem::take)

### CLI-L1. Mnemonic phrase accepted as CLI argument (LOW)
- [x] Fix (stdin only; help warns)

### CLI-L2. Session directory/log file permissions (LOW)
- [x] Fix (0o700/0o600)

### CLI-L3. Non-atomic writes for session state files (LOW)
- [x] Fix (atomic writes in track/watch/presence)

### CLI-L4. Unbounded memory growth in watch HashMap (LOW)
- [x] Fix (periodic retain() cleanup)

### CLI-L5. document_id slice panic potential (LOW)
- [x] Fix (get(..16).unwrap_or())

---

## CI / CONFIG AUDIT — Session 5-8

### CFG-C1. Release profile in engine Cargo.toml SILENTLY IGNORED (CRITICAL)
- [x] Fix (moved to workspace root)

### CFG-H1. Expression injection in release workflow (HIGH)
- [x] Fix (inputs passed via env vars)

### CFG-H2. Unpinned third-party release action (HIGH)
- [x] Fix (pinned to SHA)

### CFG-H3. Unknown registries/git sources only warn (HIGH)
- [x] Fix (already set to "deny")

### CFG-H4. No workspace dependency inheritance (HIGH)
- [x] Fix (all use .workspace = true)

### CFG-H5. Overly broad workflow permissions (HIGH)
- [x] Fix (permissions: {} at workflow level)

### CFG-H6. SEMGREP_APP_TOKEN exposed to unpinned container (HIGH)
- [x] Fix (resolved by CFG-M5 + CFG-M4)

### CFG-H7. No MSRV CI job (HIGH)
- [x] Fix (MSRV matrix with stable + 1.75.0)

### CFG-M1. All GitHub Actions unpinned (MEDIUM)
- [x] Fix (all ~20 action refs pinned to SHA)

### CFG-M2. CLI unconditionally enables ffi feature (MEDIUM)
- [x] Fix (already removed)

### CFG-M3. Engine crate-type includes cdylib/staticlib (MEDIUM)
- [x] Fix (crate-type = ["rlib"] only)

### CFG-M4. Semgrep failures silently suppressed (MEDIUM)
- [x] Fix (removed || true)

### CFG-M5. Unpinned Semgrep container image (MEDIUM)
- [x] Fix (pinned to 1.105.0)

### CFG-M6. cargo-deny continue-on-error (MEDIUM)
- [x] Fix (split into separate steps)

### CFG-M7. Wildcard dependencies allowed (MEDIUM)
- [x] Fix (already set to "deny")

### CFG-M8. Protocol crate version mismatch (MEDIUM)
- [x] Fix (already uses version.workspace = true)

### CFG-M9. reqwest outdated, bincode is RC (MEDIUM)
- [-] Documented decisions

### CFG-M10. CI cargo test missing --workspace (MEDIUM)
- [x] Fix (added --workspace)

### CFG-M11. Cargo cache key missing Cargo.toml hash (MEDIUM)
- [x] Fix (Cargo.toml hash added)

### CFG-M12. dependency-review denies GPL-3.0 (MEDIUM)
- [x] Fix (only AGPL-3.0 denied)

### CFG-M13. Release has attestations:write unused (MEDIUM)
- [x] Fix (permissions: {} at workflow level)

### CFG-M14. No code coverage reporting (MEDIUM)
- [x] Fix (cargo-llvm-cov job)

### CFG-L1. Unpinned cargo install versions (LOW)
- [x] Fix (pinned versions, --locked)

### CFG-L2. Broken reproducible build check (LOW)
- [x] Fix (uses diff to compare)

### CFG-L3. Cache poisoning risk (LOW)
- [x] Fix (cache keys scoped)

### CFG-L4. No fuzz testing in CI (LOW)
- [x] Fix (weekly fuzz job)

### CFG-L5. No benchmark regression tracking (LOW)
- [x] Fix (benchmark compile check + short run)

---

## INSTALL SCRIPTS & PACKAGING — Session 5-8

### INS-H1. No download integrity verification (HIGH)
- [x] Fix (verify_checksum() with SHA256SUMS)

### INS-H2. Firefox extension ID mismatch in static manifest (HIGH)
- [x] Fix (corrected to writerslogic.com)

### INS-M1. install.sh missing set -u and pipefail (MEDIUM)
- [x] Fix (set -euo pipefail)

### INS-M2. Unsafe tar extraction (MEDIUM)
- [x] Fix (--no-same-owner)

### INS-M3. Native host manifests without restrictive permissions (MEDIUM)
- [x] Fix (chmod 600)

### INS-M4. Placeholder extension IDs in static manifests (MEDIUM)
- [x] Fix (renamed to .json.template)

### INS-M5. install.sh uses bash-only features but usage says sh (MEDIUM)
- [x] Fix (printf instead of echo -e; shebang says bash)

### INS-M6. Version string from GitHub API not validated (MEDIUM)
- [x] Fix (grep -qE validation)

### INS-M7. INSTALL_DIR not canonicalized (MEDIUM)
- [x] Fix (realpath/readlink -f)

### INS-M8. install.sh does not install native messaging host (MEDIUM)
- [x] Fix (installs NMH if present)

### INS-L1. install.sh unconditional sudo (LOW)
- [x] Fix (checks writability first)

### INS-L2. install-native-host.sh unconditional sudo (LOW)
- [x] Fix (checks -w before sudo)

### INS-L3. Unquoted variables in echo functions (LOW)
- [x] Fix (printf with proper quoting)

### INS-L4. Version verification may execute wrong binary (LOW)
- [x] Fix (uses $INSTALL_DIR/writerslogic --version)

---

## LINUX PACKAGING v2 — Session 5-8

### PKG-C1. ALL Linux build scripts use Go commands (CRITICAL)
- [x] All 3 scripts rewritten for Rust

### PKG-C2. Debian control Build-Depends on golang (CRITICAL)
- [x] Fix (rustc + cargo)

### PKG-C3. RPM spec has Go build commands (CRITICAL)
- [x] Fix (cargo build --release)

### PKG-H1. Debian .install references witnessctl (HIGH)
- [x] Fix (writerslogic + NMH only)

### PKG-H2. RPM spec references non-existent binaries/paths (HIGH)
- [x] Fix (correct paths)

### PKG-M1. AppImage desktop action references witnessctl (MEDIUM)
- [x] Fix (wld verify)

### PKG-M2. SELinux file contexts reference witnessctl (MEDIUM)
- [x] Fix (no witnessctl references)

### PKG-M3. Debian changelog references witnessctl (MEDIUM)
- [x] Fix (corrected)

### PKG-L1. CITATION.cff declares Apache-2.0 only (LOW)
- [x] Fix (Apache-2.0 AND GPL-3.0-only)

---

## WIKI — Session 5-8

### WIKI-H1. CLI-Reference.md documents non-existent sentinel subcommand (HIGH)
- [x] Fix (corrected in wiki)

### WIKI-H2. Getting-Started.md references non-existent command (HIGH)
- [x] Fix (corrected in wiki)

### WIKI-M1-M5. Various wiki corrections (MEDIUM)
- [x] All fixed (export format, FAQ, glossary, config, vendor guide)

### WIKI-L1. Evidence-Format.md uses SWF instead of VDF (LOW)
- [x] Fix (SWF→VDF)

---

## DOCS/SPECS — Session 5-8

### SPEC-H1. Config field name mismatches (HIGH)
- [x] Fix (all corrected)

### SPEC-H2. WAR block schema missing WAR/1.1 fields (HIGH)
- [x] Fix (fields added)

### SPEC-M1-M9. Various spec corrections (MEDIUM)
- [x] All fixed (version field, TOML/JSON, wal_enabled, $ref, pseudocode, table names, CLI commands, FFI names, ratcheting)

### SPEC-L1-L2. Evidence-format Tier 4, ratchet pseudocode (LOW)
- [x] Both fixed

---

## DOCUMENTATION / ROOT CONFIG — Session 5-8

### DOC-H1-H6. Security/Privacy/Man page/CLI ref/Schema corrections (HIGH)
- [x] All 6 fixed (crypto table, man page, PRIVACY.md, CLI reference, nonce constraint, hash length)

### DOC-M1-M10. Various doc corrections (MEDIUM)
- [x] All 10 fixed (.env paths, audit log, CONTRIBUTING.md, workspace metadata, deny.toml, schema algorithm enum, prev_hash, contentEncoding, CLI reference stubs, .gitignore)

### DOC-L1-L2. Issue templates, NOTICE file (LOW)
- [x] Both fixed

---

## GITHUB CONFIG — Session 5-8

### GH-M1. Dependabot blanket semver-major ignore (MEDIUM)
- [x] Fix (specific package ignores instead of blanket)

---

## SYSTEMIC — Session 5-8

### SYS-H1. witnessctl ghost command across 60+ locations (HIGH)
- [x] Updated docs/templates/PRIVACY.md (8 files, ~15 sites)
- [x] Reviewed and fixed packaging scripts

---

## TEST COVERAGE — Session 5-8

- [x] `sealed_chain.rs` — 21 tests
- [x] `sealed_identity.rs` — 22 tests
- [x] `wal.rs` — 31 tests
- [x] `declaration.rs` — 68 tests
- [x] `identity/mnemonic.rs` — 13 tests
- [x] `identity/secure_storage.rs` — 12 tests
- [x] `presence.rs` — 65 tests
- [x] `crypto/anti_analysis.rs` — 3 tests
- [x] `crypto/obfuscation.rs` — 18 tests
- [x] `calibration/transport.rs` — 20 tests

---

## FALSE POSITIVES — Session 1-8

### M9. Blocking recv() without timeout
- [-] False positive — channels exit when sender drops

### M10. Voice collector write lock held across record_keystroke()
- [-] False positive — lock scope already minimal

### M14. getrandom partial initialization risk
- [-] False positive — error properly checked with early return

### M16. CFRelease without CFGetTypeID validation
- [-] False positive — CFRelease works on any CFTypeRef

### M17. native_messaging_host module declared but unreachable
- [-] False positive — separate binary target in Cargo.toml

### M42. Engine hmac_key not zeroized after use
- [-] Already handled — SecureStore::Drop zeroizes; Vec ownership transferred

---

## Production Readiness Quick Wins (Session 9 — 2026-02-26)

### REL-C2. wld_protocol version 0.1.0 diverges from workspace 0.2.0 (CRITICAL)
- **File**: `crates/wld_protocol/Cargo.toml:3`
- **Fix**: Changed to `version.workspace = true` (plus `edition.workspace = true`, `authors.workspace = true`, `license.workspace = true`). Also removed stray `[profile.release]` section causing cargo warnings.
- [x] Fix applied — protocol crate now resolves to workspace v0.2.0

### REL-H2. install.sh references wrong repository name (HIGH)
- **File**: `apps/wld_cli/install.sh:7-8`
- **Fix**: Changed `REPO="writerslogic/writerslogic"` → `REPO="writerslogic/writerslogic"`, `BINARY_NAME="writerslogic"` → `BINARY_NAME="writerslogic"`, updated usage URL
- [x] Fix applied

### SYS-R1. println!/eprintln! regression in engine library code — ~29 instances (HIGH)
- **Files**: `engine.rs` (5), `sentinel/daemon.rs` (11), `platform/linux.rs` (6), `sealed_identity.rs` (2), `keyhierarchy/puf.rs` (3), `research.rs` (2)
- **Fix**: All replaced with `log::warn!`, `log::info!`, `log::error!` as appropriate
- [x] engine.rs — 5 eprintln! → log::warn!
- [x] sentinel/daemon.rs — 11 instances → log::error!/log::info!
- [x] platform/linux.rs — 6 instances → log::error!/log::warn!
- [x] keyhierarchy/puf.rs — 3 instances → log::warn!
- [x] sealed_identity.rs — 2 instances → log::warn!
- [x] research.rs — 2 instances → log::info!/log::warn!

### REL-M1. Makefile env var inconsistency (MEDIUM)
- **File**: `Makefile:13`
- **Fix**: Changed `WLD_MOCK_KEYCHAIN=1` → `WLD_NO_KEYCHAIN=1`
- [x] Fix applied

### BE-L1. activeTab permission still present in manifest (MEDIUM)
- **File**: `apps/wld_cli/browser-extension/manifest.json:8`
- **Fix**: Removed `"activeTab"`, replaced with `"alarms"` in permissions array
- [x] Fix applied

### BE-M7. No CSP in manifest (MEDIUM)
- **File**: `apps/wld_cli/browser-extension/manifest.json`
- **Fix**: Added `"content_security_policy": {"extension_pages": "script-src 'self'; object-src 'none'"}`
- [x] Fix applied

### ENG-C1. Bare .unwrap() on store mutex in hot path (HIGH — missed in S1 sweep)
- **File**: `crates/wld_engine/src/engine.rs:352`
- **Fix**: Changed `.lock().unwrap()` → `.lock().unwrap_or_else(|p| p.into_inner())` to match all other mutex locks in the file
- [x] Fix applied

---

## Session 10 — CLI Source Audit (2026-02-26)

> Items verified and moved from todo.md on 2026-02-26.

### REL-C1. Release workflow produces NO platform binaries (CRITICAL)
- **File**: `.github/workflows/release.yml`
- **Fix**: Build matrix with 4 targets (macOS ARM/x86, Linux, Windows), proper artifact upload
- [x] Verified: matrix strategy with `runs-on` and `target` pairs confirmed

### REL-H3. install.sh archive naming mismatch (HIGH)
- **File**: `apps/wld_cli/install.sh`
- **Fix**: Correct REPO, BINARY_NAME, archive naming convention
- [x] Verified: script references correct repo and binary names

### REL-H4. No Linux packaging CI pipeline (HIGH)
- **File**: `.github/workflows/linux-packages.yml`
- **Fix**: Added 3 packaging jobs (DEB, RPM, AppImage)
- [x] Verified: workflow file exists with all 3 jobs

### BE-H6. Jitter integration not wired in NMH (HIGH)
- **File**: `apps/wld_cli/src/native_messaging_host.rs:362-411`
- **Fix**: `handle_inject_jitter()` fully implemented with validation, stats, and evidence writing
- [x] Verified: function reads intervals, filters plausible range, computes stats, appends to evidence file

### PROTO-H2. Protocol crate missing rust-version (HIGH)
- **File**: `crates/wld_protocol/Cargo.toml`
- **Fix**: Added `rust-version = "1.75.0"`
- [x] Verified: line 12 contains `rust-version = "1.75.0"`

### REL-M3. Crate publishing preparation incomplete (MEDIUM)
- **Files**: All 4 Cargo.toml files
- **Fix**: Added `exclude`, `homepage`, `documentation` fields
- [x] Verified: fields present in all workspace Cargo.toml files

### BE-M2. storageKey() helper missing in options.js (MEDIUM)
- **File**: `apps/wld_cli/browser-extension/options.js`
- **Fix**: Added `storageKey()` helper for consistent key generation
- [x] Verified: function present

### BE-M4. observerRetries unbounded in content.js (MEDIUM)
- **File**: `apps/wld_cli/browser-extension/content.js`
- **Fix**: Added bounded retry with max retries constant
- [x] Verified: retry limit implemented

### BE-M5. Extension ID hardcoded in install scripts (MEDIUM)
- **Files**: `install-native-host.sh`, `install-native-host.ps1`
- **Fix**: Extension ID passed as parameter/variable
- [x] Verified: parameterized in both scripts

### BE-M6. type:module in manifest.json (MEDIUM)
- **File**: `apps/wld_cli/browser-extension/manifest.json`
- **Fix**: Removed `"type": "module"` from background service worker
- [x] Verified: field removed

### BE-M8. Firefox manifest still MV2 (MEDIUM)
- **File**: `apps/wld_cli/browser-extension/manifest-firefox.json`
- **Fix**: Upgraded to MV3 format
- [x] Verified: manifest_version is 3

### BE-L2. Static version string in popup.html (MEDIUM)
- **File**: `apps/wld_cli/browser-extension/popup.html`
- **Fix**: Dynamic version display from manifest
- [x] Verified: version pulled from runtime API

### JIT-M1. "Zero Unsafe Code" claim incorrect (MEDIUM)
- **File**: `crates/wld_jitter/README.md`
- **Fix**: Added qualifier noting unsafe only in optional deps
- [x] Verified: README updated with accurate claim

### JIT-M2. chain_hash → chain_mac rename incomplete (MEDIUM)
- **File**: `crates/wld_jitter/src/model.rs`
- **Fix**: Renamed `chain_hash` to `chain_mac` for consistency
- [x] Verified: field correctly named `chain_mac`

---
