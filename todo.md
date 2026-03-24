# CPOP Security Audit — Consolidated Findings

**Date**: 2026-03-23
**Scope**: 57+ files across engine, macOS app, and FFI layers
**Auditors**: 48 agents (39 engine + 9 macOS security files)

## Summary

| Severity | Count | Fixed | Deferred | Open |
|----------|-------|-------|----------|------|
| CRITICAL | 11    | 8     | 0        | 3    |
| HIGH     | 115   | 37    | 3        | 75   |
| MEDIUM   | 180   | 0     | 0        | 180  |
| LOW      | 62    | 0     | 0        | 62   |
| SYSTEMIC | 6     | 0     | 0        | 6    |
| **Total**| **374**| **45**| **3**   | **326**|

---

## CRITICAL

- [x] C-001 | sentinel/core.rs:164 | CRITICAL | CONCURRENCY | 90 | Reentrant RwLock deadlock: set_signing_key acquires write lock then calls update_mouse_stego_seed which acquires read on same lock — guaranteed deadlock on single-threaded runtime | Split into separate locks or restructure to avoid nested acquire
- [x] C-002 | sentinel/core.rs:342 | CRITICAL | RESOURCE | 90 | tokio::spawn JoinHandle dropped without abort(); if Sentinel dropped without stop(), spawned task and capture threads leak forever (unbounded resource leak) | Store JoinHandle and call .abort() in Drop impl
- [x] C-003 | ipc/server.rs:357 | CRITICAL | DoS | 90 | run_with_shutdown lacks MAX_CONCURRENT_CONNECTIONS; attacker can open unlimited Unix socket connections exhausting file descriptors | Add semaphore or Arc<AtomicUsize> counter with configurable limit
- [x] C-004 | verify/mod.rs:95-168 | CRITICAL | DATA_INTEGRITY | 95 | full_verify() does not short-circuit on structural failure; continues seal/duration/key/forensics checks on already-failed evidence — misleading results and wasted computation | Short-circuit after structural verification failure
- [x] C-005 | anchors/rfc3161.rs:6-10 | CRITICAL | CRYPTO/NETWORK | 95 | All default TSA URLs use plain HTTP, not HTTPS; MITM can forge timestamps | Switch all default TSA URLs to HTTPS; reject HTTP in production builds
- [x] C-006 | tpm/linux.rs:141 | CRITICAL | CONCURRENCY | 99 | quote() deadlocks: acquires inner lock then calls device_id() which locks same mutex | Remove nested lock acquisition; extract device_id before acquiring inner lock
- [x] C-007 | tpm/linux.rs:158 | CRITICAL | CONCURRENCY | 99 | bind() deadlocks: same reentrant mutex issue as quote() | Same fix as C-006
- [x] C-008 | tpm/linux.rs:250-267 | CRITICAL | SECURITY | 95 | seal() creates PCR policy session but never calls set_sessions(); PCR policy unenforced, sealed data accessible regardless of PCR state | Call context.set_sessions() with the policy session before sealing

---

## HIGH — Security

- [x] H-001 | secure_storage.rs:55 | HIGH | ZEROIZE | 95 | Non-macOS save(): base64-encoded String from seed bytes not zeroized after keyring set_password() — secret persists in heap | Wrap in Zeroizing<String> or overwrite bytes before drop
- [x] H-002 | secure_storage.rs:120 | HIGH | ZEROIZE | 95 | macOS save_macos(): base64-encoded String not zeroized after SecItemAdd | Same fix as H-001
- [x] H-003 | secure_storage.rs:26 | HIGH | ZEROIZE | 90 | IDENTITY_CACHE stores device_id/machine_id in OnceLock<(String, String)> without zeroize-on-drop — identity material in memory forever | Use Zeroizing wrapper or clear on delete
- [x] H-004 | sentinel/core.rs:187 | HIGH | ZEROIZE | 95 | set_hmac_key takes Vec<u8> parameter; caller's copy is never zeroized after handoff | Accept Zeroizing<Vec<u8>> or document caller obligation
- [x] H-005 | sentinel/core.rs:584 | HIGH | ZEROIZE | 80 | signing_key.clone() out of RwLock creates unzeroized copy on heap | Return guard reference instead of cloning, or use Zeroizing wrapper
- [x] H-006 | ipc/crypto.rs:89 | HIGH | CRYPTO | 85 | Nonce prefix not direction-specific: client and server share same prefix, creating nonce collision risk on bidirectional traffic | Use distinct prefixes for tx/rx (e.g., 0x00 for client->server, 0x01 for server->client)
- [x] H-007 | ipc/crypto.rs:109 | HIGH | CRYPTO | 80 | tx_sequence is u64 that wraps on overflow without check — nonce reuse after 2^64 messages (theoretical but spec violation) | Return error on overflow instead of wrapping
- [-] H-008 | ipc/server.rs:269 | HIGH | TOCTOU | 85 | Socket bind race: between remove_file and bind, symlink attack possible — attacker could redirect socket | Use atomic bind with O_EXCL or flock before remove+bind
- [-] H-009 | sentinel/core.rs:357 | HIGH | SECURITY | 85 | Keystroke dedup uses timestamp equality alone; doesn't protect against injected keystrokes with spoofed timestamps | Add source validation or sequence numbering
- [x] H-010 | ffi/ephemeral.rs:590 | HIGH | ZEROIZE | 85 | build_war_block reads signing key from disk into Zeroizing vec but then constructs SigningKey from slice — the SigningKey itself is not zeroized after use; also no file permission check (SYS-033 residual) | Wrap SigningKey in a scope, zeroize on drop, add file permission validation
- [-] H-011 | war/verification.rs:448 | HIGH | CRYPTO | 85 | WRITERSPROOF_CA_PUBKEY_HEX is a hardcoded constant — if CA key is compromised, all deployed clients must be updated; no key rotation mechanism | Add key pinning with backup keys and expiry checks
- [x] H-012 | ipc/server.rs:269 | HIGH | AUTH | 82 | No peer UID verification on Unix socket connections — any local user can connect | Check SO_PEERCRED/getpeereid and reject non-matching UIDs
- [x] H-013 | checkpoint/chain.rs:464-476 | HIGH | CRYPTO | 90 | Signature verification in verify_detailed() only checks length (== 64 bytes); no cryptographic verification — any 64 random bytes pass | Perform actual Ed25519 signature verification against the signing public key
- [x] H-014 | checkpoint/chain.rs:130-165 | HIGH | DATA_INTEGRITY | 92 | commit_internal() TOCTOU between hash_file_with_size and checkpoint push; no file lock, concurrent commits corrupt ordinal sequence | Add file-level locking (flock) around commit_internal
- [x] H-015 | checkpoint/chain.rs:652-664 | HIGH | DATA_INTEGRITY | 95 | save() missing fsync/sync_all before rename — data loss on crash (RT-07 claimed fixed but is not) | Add File::sync_all() on temp file before rename
- [x] H-016 | verify/mod.rs:171-223 | HIGH | CRYPTO | 90 | verify_seals() does NOT re-derive HMAC seals; only checks non-zero — tampered jitter_hash passes verification | Re-derive HMAC seals from inputs and compare
- [x] H-017 | war/verification.rs:251-254 | HIGH | SECURITY | 90 | compute_seal silently accepts non-32-byte pubkeys by zeroing — allows seal bypass with truncated keys | Reject pubkeys that are not exactly 32 bytes
- [x] H-018 | store/events.rs:211 | HIGH | DATA_INTEGRITY | 90 | update_file_path() changes file_path without recomputing event_hash/HMAC; guarantees HMAC mismatch on next open | Recompute integrity HMAC after path update
- [x] H-019 | store/events.rs:68 | HIGH | DATA_INTEGRITY | 95 | Integrity uses last_insert_rowid as event_count; diverges from actual count on row deletion — HMAC chain breaks | Use SELECT COUNT(*) or maintain a separate monotonic counter
- [x] H-020 | proof.rs:240 | HIGH | SECURITY | 90 | RangeProof::verify underflows on crafted end_leaf < start_leaf | Add bounds check: reject if end_leaf < start_leaf
- [x] H-021 | mmr.rs:249 | HIGH | CORRECTNESS | 85 | find_family 1u64 << (height+1) panics when height >= 63 | Use checked_shl or cap height
- [x] H-022 | proof.rs:284 | HIGH | CORRECTNESS | 85 | RangeProof::verify shift overflow when height pushed past 63 by crafted sibling_path | Validate height before shift operations
- [x] H-023 | swf_argon2.rs:533 | HIGH | NUMERIC | 90 | padding_value (steps+1) as u32 overflows when steps == u32::MAX | Use checked_add and return error on overflow
- [x] H-024 | analysis.rs:148 | HIGH | NUMERIC | 90 | IKI interval i64 subtraction overflow + as f64 precision loss for large timestamps | Use checked_sub, handle overflow, cast carefully
- [x] H-025 | ffi/evidence.rs:195 | HIGH | RESOURCE | 80 | CBOR output write not atomic (crash produces corrupt .cpop) | Use tempfile + rename pattern
- [x] H-026 | ffi/evidence.rs:607 | HIGH | RESOURCE | 82 | fs::read on evidence file has no size limit (OOM on large/malicious files) | Add file size check before reading
- [x] H-027 | ffi/ephemeral.rs:324-327 | HIGH | DATA_INTEGRITY | 90 | UTF-8 panic: statement[..MAX] slices by byte offset, panics on multi-byte chars | Use statement.char_indices() to find safe truncation point
- [x] H-028 | ffi/evidence.rs:167 | HIGH | DATA_INTEGRITY | 90 | Wrong profile URI (urn:ietf:params:pop:profile:1.0 vs spec urn:ietf:params:rats:eat:profile:pop:1.0) | Fix to canonical EAT profile URI
- [x] H-029 | AuthService.swift:649-667 | HIGH | AUTH_BYPASS | 95 | Biometric gate bypassed when device has no passcode/biometric; returns true (allow) | Return false or require alternative authentication when biometrics unavailable
- [x] H-030 | CloudSyncService.swift:486 | HIGH | PATH_TRAVERSAL | 92 | Storage path from deserialized queue not re-validated; path injection possible | Re-validate and sandbox-check all deserialized paths
- [x] H-031 | StatusBarController.swift:311-330 | HIGH | CONCURRENCY | 90 | Local event monitor accesses @MainActor state without isolation (breaks under Swift 6) | Dispatch to MainActor before accessing state
- [x] H-032 | DashboardView.swift:387 | HIGH | CONCURRENCY | 90 | defer in cancelled Task resets isSavingPasteCheckpoint, racing with replacement Task | Use actor-isolated state or cancellation token
- [x] H-033 | ExportFormView.swift:565 | HIGH | UX | 90 | isExporting set AFTER biometric prompt; double-export possible during prompt | Set isExporting=true BEFORE biometric prompt
- [x] H-034 | EngineService.swift:24 | HIGH | CONCURRENCY | 90 | FFI timeout does not actually cancel the blocking thread; thread leaks on timeout | Use DispatchWorkItem with cancel, or document leaking behavior
- [x] H-035 | EngineService.swift:538-543 | HIGH | CONCURRENCY | 85 | nonisolated synchronous FFI calls can block MainActor (getForensicBreakdown etc) | Move FFI calls to detached Task or DispatchQueue.global
- [x] H-036 | EngineService.swift:505 | HIGH | DATA_INTEGRITY | 85 | Cross-language checkpoint hash delimiter must match Rust; no test verifies this | Add cross-language delimiter consistency test
- [x] H-037 | ExportFormView.swift:547-656 | HIGH | ERROR_HANDLING | 90 | Partial export failure shown as success (green checkmark) | Check all export steps succeeded before showing success
- [x] H-038 | DataDirectoryIntegrityService.swift:351-381 | HIGH | TOCTOU | 85 | Permission check before symlink check; attacker swaps real dir for symlink | Check symlink FIRST, then permissions, or use O_NOFOLLOW
- [x] H-039 | DataDirectoryIntegrityService.swift:750-758 | HIGH | TOCTOU | 82 | buildManifest lstat+read are separate operations; file can be swapped between | Use fstat on open fd instead of lstat + separate read
- [x] H-040 | CertificateService.swift:267 | HIGH | ATOMICITY | 80 | Sidecar .sig temp file written non-atomically | Use tempfile + rename pattern
- [x] H-041 | AppDelegate.swift:167-191 | HIGH | CONCURRENCY | 90 | windowWillClose races with autoInitializeIfNeeded; two concurrent engine.initialize() calls | Add initialization lock or guard flag
- [x] H-042 | AppDelegate.swift:598-604 | HIGH | RESOURCE | 88 | showInitializationFailureAlert unbounded recursive retry stacks modal alerts | Limit retries or use iterative approach with cooldown
- [x] H-043 | StatusBarController.swift:472-500 | HIGH | UX | 85 | Right-click menu flag and statusItem.menu=nil fire before menu closes | Delay menu teardown until menuDidClose callback
- [x] H-044 | WARReportPDFRenderer.swift:68 | HIGH | CORRECTNESS | 90 | makeImage() failure silently drops PDF page; report content lost without error | Return error or insert placeholder page on rendering failure
- [x] H-045 | windows.rs:164-166 | HIGH | RESOURCE | 95 | KeystrokeMonitor message pump thread leaks permanently; no stop mechanism, no Drop, hook never unhooked | Add Drop impl that posts WM_QUIT and joins thread; unhook on stop
- [x] H-046 | windows.rs:108 | HIGH | RESOURCE | 90 | get_process_path leaks HANDLE on every focus query (~10/sec); exhausts handle limit within hours | Close HANDLE after use with CloseHandle in a scopeguard/Drop wrapper
- [x] H-047 | windows.rs:250-258 | HIGH | CONCURRENCY | 85 | Message pump thread blocked in GetMessageW after stop(); no PostQuitMessage to unblock | Post WM_QUIT to message pump thread in stop()
- [x] H-048 | engine.rs:241-260 | HIGH | RESOURCE | 95 | Watcher thread JoinHandle dropped; thread can outlive Engine with no cleanup | Store JoinHandle and join/abort in Drop impl
- [x] H-049 | fingerprint/voice.rs:46-51 | HIGH | SECURITY/PRIVACY | 90 | consent_given is passive flag with no enforcement at collector level; any code can bypass consent | Enforce consent check in collect() method, not just flag
- [x] H-050 | platform/synthetic.rs:70-73 | HIGH | SECURITY | 85 | 20ms superhuman threshold too generous; attacker at 25ms intervals evades detection | Lower threshold or use adaptive detection based on population statistics
- [x] H-051 | anchors/rfc3161.rs:68-70 | HIGH | CRYPTO | 90 | TSA request nonce never verified in response; replay attack possible per RFC 3161 | Compare nonce in TSA response against request nonce
- [x] H-052 | anchors/rfc3161.rs:133-150 | HIGH | CRYPTO | 90 | verify_timestamp_token only checks hash; no CMS signature or cert chain verification | Implement full CMS signature and certificate chain verification
- [x] H-053 | ipc/async_client.rs:130-236 | HIGH | CONCURRENCY | 85 | ECDH handshake has no timeout; stalled server hangs client indefinitely | Add configurable timeout on handshake with tokio::time::timeout
- [x] H-054 | jitter/session.rs:306-336 | HIGH | SECURITY | 85 | Session seed written to disk with default umask permissions briefly before restrict_permissions | Set umask before write or use O_CREAT|O_EXCL with mode 0o600
- [x] H-055 | tpm/secure_enclave.rs:77-105 | HIGH | RESOURCE | 90 | SecKeyRef never CFReleased in Drop; CoreFoundation key objects leak | Implement Drop that calls CFRelease on stored SecKeyRef
- [x] H-056 | tpm/secure_enclave.rs:104-105 | HIGH | CONCURRENCY | 95 | unsafe Send+Sync without documented safety invariant for SecKeyRef | Add SAFETY comment documenting thread-safety guarantee, or remove Send+Sync
- [x] H-057 | DeviceAttestationService.swift:534 | HIGH | AUTH_BYPASS | 90 | submitVerification accepts unparseable 200 response as successful attestation | Require valid parsed response body; treat parse failure as attestation failure
- [x] H-058 | BrowserExtensionService.swift:744-748 | HIGH | SECURITY | 85 | HMAC key fallback is deterministic SHA256(bundleID); attacker can compute same key and forge manifests | Use Keychain-stored random key; fail hard if Keychain unavailable
- [x] H-059 | SettingsIntegrityService.swift:227 | HIGH | SECURITY | 85 | Non-constant-time HMAC comparison; timing side-channel | Use constant-time comparison (e.g., Data equality via hmac.isValidAuthenticationCode)
- [x] H-060 | sealed_chain.rs:72-74 | HIGH | SECURITY | 90 | ChainEncryptionKey empty Drop impl doesn't zeroize; latent defect if refactored | Derive Zeroize + ZeroizeOnDrop, or implement Drop with explicit zeroize
- [x] H-061 | tpm/linux.rs:382 | HIGH | SECURITY | 90 | AK is deterministic transient primary with no auth; any process with /dev/tpmrm0 recreates identical key | Add auth value to AK template or use persistent key with password
- [x] H-062 | tpm/linux.rs:349-390 | HIGH | RESOURCE | 85 | AK transient handle never flushed; no Drop impl; leaks TPM handle slot per init | Implement Drop that calls flush_context on AK handle
- [x] H-063 | tpm/linux.rs:248,316 | HIGH | RESOURCE | 85 | SRK handle leaks on error paths in seal()/unseal() | Use scopeguard or RAII wrapper to flush SRK handle on all paths
- [x] H-064 | wal/operations.rs:96-97 | HIGH | DATA_INTEGRITY | 85 | Split write (length prefix + body as two write_all calls); crash between them corrupts WAL | Use single write_all with pre-assembled buffer, or write to tempfile + rename
- [x] H-065 | wal/operations.rs:401 | HIGH | DATA_INTEGRITY | 85 | read_header overwrites session_id without verifying match; attacker can change session identity | Verify session_id matches existing or reject mismatched headers
- [x] H-066 | report/html/sections.rs:147 | HIGH | XSS | 95 | DimensionScore.color injected into CSS style= without validation; XSS via crafted color | Validate color against allowlist of CSS color values
- [x] H-067 | report/html/sections.rs:232 | HIGH | XSS | 95 | Same d.color XSS in write_dimension_analysis() | Same fix as H-066
- [x] H-068 | report/html/sections.rs:292 | HIGH | XSS | 95 | Same d.color XSS in write_dimension_lr_table() | Same fix as H-066
- [x] H-069 | writersproof/client.rs:30-36 | HIGH | NETWORK | 90 | HTTPS not enforced in release; HTTP URLs accepted with only a warning; JWT sent cleartext | Reject HTTP URLs in release builds; require HTTPS
- [x] H-070 | platform/macos/keystroke.rs:147 | HIGH | CONCURRENCY | 90 | Mutex lock inside real-time CGEventTap callback; contention stalls system-wide input | Use lock-free queue or try_lock with fallback
- [x] H-071 | platform/macos/keystroke.rs:174-206 | HIGH | RESOURCE | 85 | CGEventTap and RunLoopSource never CFReleased; Mach port leak on stop/restart | CFRelease tap and source in stop(); add Drop impl
- [x] H-072 | platform/macos/keystroke.rs:342-374 | HIGH | RESOURCE | 85 | Same CGEventTap/RunLoopSource leak in MacOSKeystrokeCapture | Same fix as H-071
- [x] H-073 | EncryptedSessionStore.swift:200-203 | HIGH | SECURITY | 90 | Plaintext zeroing ineffective due to Data copy-on-write; original plaintext never scrubbed | Use mutable UnsafeMutableBufferPointer to zero in-place before release
- [x] H-074 | CPOPService+Actions.swift:256-273 | HIGH | RESOURCE | 90 | Fire-and-forget backup Tasks accumulate; no cancellation path | Store Task handles and cancel previous before starting new; add max concurrent limit

---

## MEDIUM — Security

- [x] M-001 | secure_storage.rs:25 | MEDIUM | ZEROIZE | 85 | MNEMONIC_CACHE in OnceLock never drops; mnemonic phrase stays in memory for entire process lifetime | Clear on explicit logout/lock or use ProtectedBuf
- [x] M-002 | secure_storage.rs:21 | MEDIUM | CACHE | 85 | SEED_CACHE (OnceLock) never invalidated after delete_seed() — stale cached seed returned after deletion | Invalidate cache in delete_seed()
- [x] M-003 | secure_storage.rs:24 | MEDIUM | CACHE | 85 | FINGERPRINT_KEY_CACHE (OnceLock) never invalidated — key rotation leaves stale cache | Same pattern as M-002
- [x] M-004 | secure_storage.rs:344 | MEDIUM | ZEROIZE | 80 | migrate_macos_keychain(): intermediate base64-encoded String not zeroized during migration | Wrap in Zeroizing<String>
- [x] M-005 | sentinel/core.rs:57 | MEDIUM | ZEROIZE | 85 | mouse_stego_seed field not zeroized when sentinel stops or seed is updated | Zeroize old seed before overwrite
- [x] M-006 | ipc/crypto.rs:140 | MEDIUM | CRYPTO | 80 | Sequence validation on decrypt has TOCTOU: concurrent callers can race past sequence check | Use atomic compare-and-swap for rx_sequence
- [x] M-007 | ipc/crypto.rs:300 | MEDIUM | CRYPTO | 80 | Zero-length confirmation message not rejected in handshake — allows empty-message oracle | Reject messages shorter than minimum expected length
- [x] M-008 | ipc/crypto.rs:311 | MEDIUM | CRYPTO | 72 | Key confirmation uses non-constant-time comparison (== on Vec<u8>) | Use subtle::ConstantTimeEq
- [x] M-009 | war/verification.rs:520 | MEDIUM | CRYPTO | 80 | Beacon signature verification reconstructs signed_msg using string .as_bytes() — if fields contain non-ASCII, encoding differs from server | Use explicit UTF-8 encoding with length prefixes or canonical serialization
- [x] M-010 | checkpoint/chain.rs:383-405 | MEDIUM | DATA_INTEGRITY | 85 | verify_hash_chain() accepts legacy all-zeros genesis hash, bypassing document-binding | Reject all-zeros genesis hash or require migration
- [x] M-011 | checkpoint/chain.rs:97 | MEDIUM | SECURITY | 85 | new_with_mode() follows symlinks via canonicalize(); symlink-to-sensitive-file attack | Use std::fs::metadata to reject symlinks before canonicalize
- [x] M-012 | checkpoint/chain.rs:286-297 | MEDIUM | DATA_INTEGRITY | 75 | rfc_vdf layout not verified on verification side | Add VDF layout validation during verification
- [x] M-013 | verify/mod.rs:238-242 | MEDIUM | DATA_INTEGRITY | 85 | iterations_per_second=0 bypasses duration cross-check | Reject zero iterations_per_second
- [x] M-014 | verify/mod.rs:253-257 | MEDIUM | DATA_INTEGRITY | 80 | Stripped VDF data passes duration verification | Fail verification when expected VDF data is missing
- [x] M-015 | verify/mod.rs:542-544 | MEDIUM | CRYPTO | 78 | compute_verdict defers to forensics BEFORE duration >3x check | Check duration bounds before forensic analysis
- [x] M-016 | war/verification.rs:405-410 | MEDIUM | SECURITY | 80 | verify_vdf_proofs returns passed=true when no VDF fields exist | Return failed or inconclusive when no VDF data present
- [x] M-017 | sentinel/ipc_handler.rs:265-266 | MEDIUM | SECURITY | 82 | handle_verify_file ignores sig_ok; reports success with invalid signature | Propagate sig_ok result to caller
- [x] M-018 | sentinel/ipc_handler.rs:368 | MEDIUM | DATA_INTEGRITY | 80 | IPC export write not atomic (RT-07 violation) | Use tempfile + rename pattern
- [x] M-019 | swf_argon2.rs:508 | MEDIUM | NUMERIC | 85 | select_indices division by zero when num_leaves==0 | Guard against zero num_leaves
- [x] M-020 | analysis.rs:299-307 | MEDIUM | NUMERIC | 85 | Timing CV can overflow to Inf/NaN from large intervals | Clamp or validate intermediate values
- [x] M-021 | store/integrity.rs:138 | MEDIUM | DATA_INTEGRITY | 85 | First event chain link not validated (previous_hash == zeros) | Validate genesis link explicitly
- [x] M-022 | CloudSyncService.swift:769-801 | MEDIUM | DESERIALIZATION | 80 | Plaintext JSON fallback if decryption fails; attacker can craft queue file | Remove plaintext fallback or require authenticated decryption
- [x] M-023 | CloudSyncService.swift:863-886 | MEDIUM | ZEROIZE | 85 | Symmetric key material not zeroized after Keychain storage | Zeroize key data after Keychain write
- [x] M-024 | keyhierarchy/crypto.rs:45-55 | MEDIUM | DOMAIN_SEPARATION | 90 | compute_entangled_nonce missing domain prefix; collision risk with other 3x32-byte hashes | Add domain separation prefix (e.g., "witnessd-entangled-nonce-v1")
- [x] M-025 | keyhierarchy/crypto.rs:16 | MEDIUM | HKDF_PARAM_SWAP | 80 | hkdf_expand passes domain strings as salt instead of info; deviates from RFC 5869 | Swap salt/info parameters to match RFC 5869
- [x] M-026 | crypto.rs:114-118 | MEDIUM | WEAK_KDF | 85 | derive_hmac_key uses raw SHA-256 instead of HKDF; inconsistent with rest of module | Use HKDF for key derivation
- [x] M-053 | WARReportPDFRenderer.swift:179 | MEDIUM | SECURITY | 80 | outputPath not validated; path traversal possible | Validate outputPath against sandbox and reject traversal sequences
- [x] M-054 | WARReportPDFRenderer.swift:170-175 | MEDIUM | RESOURCE | 80 | All page CGImages accumulated in memory before PDF; 100-page report = ~190MB | Stream pages to PDF context one at a time, releasing each after write

## MEDIUM — Concurrency

- [x] M-027 | sentinel/core.rs:276 | MEDIUM | CONCURRENCY | 80 | blocking_send on keystroke_tx blocks bridge thread if async receiver loop is slow; drops keystrokes silently | Use try_send() and log/count drops
- [x] M-028 | sentinel/core.rs:317 | MEDIUM | CONCURRENCY | 80 | Same blocking_send issue on mouse_tx | Same fix as M-027
- [x] M-029 | sentinel/core.rs:371 | MEDIUM | CONCURRENCY | 75 | voice_collector.write_recover() acquired every keystroke even when voice collection is disabled — unnecessary lock contention | Guard with is_enabled check before acquiring lock
- [x] M-030 | mmr/mmr.rs:248 | MEDIUM | CONCURRENCY | 80 | find_family acquires state read lock on every call inside generate_merkle_path loop — high lock contention for large trees | Pass state snapshot instead of re-acquiring per iteration
- [x] M-055 | BatchVerifyView.swift:395 | MEDIUM | CONCURRENCY | 85 | loadItem callback accesses @MainActor viewModel from background thread via DispatchQueue.main.async; data race under Swift 6 | Use MainActor.run or @MainActor closure instead of DispatchQueue.main.async
- [x] M-056 | windows.rs:595 | MEDIUM | CORRECTNESS | 85 | is_idle set to kb_active (inverted semantics); misclassifies active-typing mouse movements | Invert: is_idle = !kb_active
- [x] M-057 | windows.rs:614 | MEDIUM | CORRECTNESS | 80 | MOUSE_KEYBOARD_ACTIVE reset on every mouse event; ~6ms window too narrow for stego | Widen window or use separate flag for stego readiness
- [x] M-058 | windows.rs:421-424 | MEDIUM | RESOURCE | 80 | WindowsFocusMonitor thread not joined on stop; continues leaking handles | Join thread in stop() or Drop impl

## MEDIUM — Correctness

- [x] M-031 | secure_storage.rs:44 | MEDIUM | SILENT_FAIL | 90 | save() silently returns Ok when CPOP_NO_KEYCHAIN=1 — caller believes data is persisted when it is not | Return a distinct result type or log a warning
- [x] M-032 | secure_storage.rs:401 | MEDIUM | SILENT_FAIL | 85 | save_hmac_key() silently ignores Mutex poison — corrupted state propagates | Use write_recover() pattern or return error
- [x] M-033 | secure_storage.rs:354 | MEDIUM | TOCTOU | 75 | migrate_macos_keychain(): create_dir_all result discarded — migration silently continues with missing directory | Check result and return error
- [x] M-034 | sentinel/core.rs:206 | MEDIUM | CORRECTNESS | 75 | start() sets running flag before event loop enters select! — brief window where is_running() returns true but no events are processed | Set flag inside the spawned task after select! is entered
- [x] M-035 | verify/mod.rs:173 | MEDIUM | CORRECTNESS | 78 | verify_seals: entangled_binding_valid is declared but never set to anything other than None — entangled binding verification is incomplete | Implement actual entangled binding re-derivation check
- [x] M-036 | verify/mod.rs:407 | MEDIUM | CORRECTNESS | 75 | run_forensics: events derived from behavioral.edit_topology all have timestamp_ns=0 — forensic analysis gets garbage input | Skip forensic analysis when events lack real timestamps, or reconstruct from checkpoint timestamps
- [x] M-037 | checkpoint/chain.rs:148-154 | MEDIUM | CORRECTNESS | 80 | Zero-duration VDF on clock backwards (NTP adjustment) silently undermines time-proof | Detect clock regression, use monotonic clock, or flag checkpoint
- [x] M-038 | checkpoint/chain.rs:137 | MEDIUM | CORRECTNESS | 78 | ordinal computed as checkpoints.len() as u64 — truncation on 32-bit platforms where usize is 32 bits | Use u64::try_from or document platform constraint
- [x] M-039 | checkpoint/chain.rs:294 | MEDIUM | CORRECTNESS | 75 | commit_rfc: vdf_output field packs output||input into 64 bytes but VdfProofRfc expects a proper 64-byte output — semantic mismatch | Align with spec: use actual VDF output or document the concatenation
- [x] M-040 | ffi/evidence.rs:90 | MEDIUM | CORRECTNESS | 78 | timestamp_ns cast: (ev.timestamp_ns.max(0) / 1_000_000) as u64 — negative timestamps silently become 0 instead of returning an error | Validate timestamp range and return error for negative values
- [x] M-041 | ffi/ephemeral.rs:62 | MEDIUM | RESOURCE | 78 | EPHEMERAL_SESSIONS is OnceLock<DashMap> — sessions only evicted when new session is started, not from checkpoint/jitter/status | Call evict_stale_sessions from more entry points, or use a background timer
- [x] M-042 | sentinel/ipc_handler.rs:33 | MEDIUM | ZEROIZE | 82 | open_db() derives hmac_key from signing_key.to_bytes() but the intermediate key_bytes Vec is not zeroized | Use Zeroizing<[u8; 32]> for key_bytes
- [x] M-043 | sentinel/ipc_handler.rs:334 | MEDIUM | ZEROIZE | 80 | export_file handler reads signing key bytes for HMAC derivation without zeroizing the intermediate | Same pattern as M-042
- [x] M-044 | store/integrity.rs:68 | MEDIUM | MIGRATION | 78 | Schema migration uses PRAGMA-free column existence check (try prepare) — fragile if column name changes | Use PRAGMA table_info for robust migration detection
- [x] M-045 | swf_argon2.rs:224 | MEDIUM | PERFORMANCE | 85 | with_capacity(iterations as usize) can allocate 128GB for crafted params; no upper bound | Cap iterations at a reasonable maximum before allocation
- [x] M-046 | DataDirectoryIntegrityService.swift:620 | MEDIUM | DEADLOCK | 80 | readDataToEndOfFile after waitUntilExit; classic pipe deadlock | Read pipe before waitUntilExit, or use async I/O

## MEDIUM — macOS App

- [x] M-047 | CloudSyncService.swift:28 | MEDIUM | CONCURRENCY | 78 | SyncSemaphore continuation stored in array — if cancelWaiter races with release, double-resume is possible despite the `resumed` flag (flag check + resume is not atomic within the actor) | Use an enum state machine or AsyncSemaphore from swift-async-algorithms
- [x] M-048 | AppDelegate.swift:84 | MEDIUM | CORRECTNESS | 78 | performAppInitialization is called from Task{} in applicationDidFinishLaunching — if it throws, the catch only logs; app continues in partially-initialized state | Show user-facing error dialog or exit gracefully
- [x] M-049 | StatusBarController.swift:41 | MEDIUM | RESOURCE | 75 | checkpointIntervalSeconds read from UserDefaults on every timer fire without caching validation — corrupt defaults could cause rapid timer firing | Validate bounds on each read, not just in readCheckpointInterval
- [x] M-050 | DataDirectoryIntegrityService.swift:34 | MEDIUM | CONCURRENCY | 78 | _hashCache and _openFdCache use DispatchQueue.sync for access but cache invalidation is not atomic with reads — stale reads possible | Use actor isolation or NSLock with paired read/write
- [x] M-051 | AuthService.swift:42 | MEDIUM | INFO_LEAK | 75 | rateLimited error message includes exact remaining seconds — helps attacker time retry precisely | Round to nearest 10 seconds or use vague "please wait"
- [x] M-052 | CertificateService.swift:82 | MEDIUM | INPUT_VALIDATION | 78 | evidenceHash validated as hex but no length check — accepts arbitrarily long hex strings | Add maximum length check (e.g., 128 chars for SHA-512)

## MEDIUM — Engine (new audit agents)

- [x] M-059 | sentinel/daemon.rs:393 | MEDIUM | RESOURCE | 85 | Sentinel left running if post-start setup fails; no cleanup on error path | Add cleanup (sentinel.stop()) in error path after successful start
- [x] M-060 | sentinel/daemon.rs:410-419 | MEDIUM | TOCTOU | 80 | write_pid used instead of acquire_pid_file; race between concurrent starts | Use flock-based PID file acquisition for atomic startup
- [x] M-061 | sentinel/daemon.rs:57-64 | MEDIUM | RESOURCE | 80 | shutdown() short-circuits on sentinel.stop error; PID file and socket leak | Continue cleanup of PID file and socket even if sentinel.stop fails
- [x] M-062 | engine.rs:243-246 | MEDIUM | CORRECTNESS | 85 | Blocking recv with no timeout; watcher thread ignores running flag between events | Use recv_timeout or select! with shutdown channel
- [x] M-063 | engine.rs:462 | MEDIUM | SECURITY | 85 | Wrong-length HMAC key silently triggers regeneration; breaks chain integrity | Log warning and return error instead of silent regeneration
- [x] M-064 | fingerprint/activity.rs:102 | MEDIUM | NUMERIC | 85 | Timestamp i64 subtraction overflow + as f64 precision loss | Use checked_sub and handle overflow; use TryFrom for safe cast
- [x] M-065 | fingerprint/activity.rs:226 | MEDIUM | NUMERIC | 90 | Variance divides by (n-1); when n==1, divides by 0 producing Inf/NaN | Guard n > 1 before computing variance; return 0.0 for single sample
- [x] M-066 | platform/synthetic.rs:130 | MEDIUM | SECURITY | 80 | Replay detection tolerance 5ms too generous; 6ms jitter defeats it | Tighten tolerance or use statistical replay detection
- [x] M-067 | platform/synthetic.rs:243-244 | MEDIUM | SECURITY | 85 | has_critical_anomaly requires compound conditions; robotic timing alone not flagged as critical | Flag robotic timing as critical anomaly independently
- [x] M-068 | platform/synthetic.rs:414-416 | MEDIUM | NUMERIC | 85 | fatigue_indicator divides by first_mean which can be 0.0; produces Inf/NaN | Guard against zero first_mean; return 1.0 (no fatigue) when mean is zero
- [x] M-069 | anchors/rfc3161.rs:121 | MEDIUM | CORRECTNESS | 85 | extract_generalized_time falls back to Utc::now() on parse failure; masks errors | Return error on parse failure instead of falling back to current time
- [x] M-070 | anchors/rfc3161.rs:122-123 | MEDIUM | CORRECTNESS | 85 | extract_serial_number fabricates serial on parse failure; non-unique, meaningless | Return error on parse failure instead of fabricating serial number
- [x] M-071 | anchors/rfc3161.rs:58-63 | MEDIUM | NETWORK | 80 | No response body size limit; malicious TSA can cause OOM | Add Content-Length check and streaming read with size cap
- [x] M-072 | tpm/secure_enclave.rs:236-243 | MEDIUM | SECURITY | 85 | SecAccessControl failure silently falls through to weaker key protection | Return error or log warning when SecAccessControl creation fails
- [x] M-073 | tpm/secure_enclave.rs:559-565 | MEDIUM | SECURITY | 90 | Deterministic seal nonce from plaintext; same data produces same AEAD key | Use random nonce or include counter in nonce derivation
- [x] M-074 | tpm/secure_enclave.rs:427-443 | MEDIUM | SECURITY | 95 | v4 legacy unseal uses XOR cipher; trivially breakable | Migrate all v4 data to AEAD; reject v4 in new code paths
- [x] M-075 | tpm/secure_enclave.rs:402-423 | MEDIUM | SECURITY | 80 | Non-atomic counter write; crash corrupts file causing false rollback alarm | Use atomic write (tempfile + rename) for counter file
- [x] M-076 | platform/linux.rs:694-698 | MEDIUM | RESOURCE | 90 | LinuxFocusMonitor thread never joined; no Drop impl | Implement Drop that signals thread shutdown and joins
- [x] M-077 | platform/linux.rs:523-580 | MEDIUM | RESOURCE | 85 | Blocking evdev fetch_events with no timeout; stop() hangs if device idle | Use poll/epoll with timeout, or non-blocking fd with shutdown pipe
- [x] M-078 | platform/linux.rs:270-311 | MEDIUM | SECURITY | 80 | /proc cmdline scan info leak + substring match spoofable | Use /proc/pid/exe readlink for reliable process identification

## MEDIUM — macOS App (new audit agents)

- [x] M-079 | ReceiptValidation.swift:150 | MEDIUM | TOCTOU | 85 | Receipt re-read after validation; validated result may not match cached fields | Use validated receipt data directly; don't re-read from disk
- [x] M-080 | SafariExtensionShared.swift:801-803 | MEDIUM | ATOMICITY | 85 | Ephemeral checkpoint writes with wrong permission pattern; briefly world-readable | Write with restrictive permissions from the start (0o600) or use atomic write
- [x] M-081 | ReceiptValidation.swift:1021-1048 | MEDIUM | CRYPTO | 80 | OID byte-scanning can false-positive on crafted certificates | Use proper ASN.1 parser instead of raw byte scanning
- [x] M-082 | DeviceAttestationService.swift:640-644 | MEDIUM | REPLAY | 80 | Locked Keychain returns counter=0; replay risk if server doesn't reject | Handle Keychain locked state explicitly; fail attestation rather than return 0
- [x] M-083 | BrowserExtensionService.swift:719-722 | MEDIUM | CONCURRENCY | 80 | _cachedHMACKey race; concurrent callers can overwrite each other's keys | Use actor isolation or dispatch barrier for cache access
- [x] M-084 | SettingsIntegrityService.swift:180-199 | MEDIUM | DATA_INTEGRITY | 80 | signSettings doesn't verify write succeeded; counter ahead of HMAC causes false tamper | Verify write success before incrementing counter; or use atomic write
- [x] M-085 | sealed_chain.rs:203-207 | MEDIUM | RESOURCE | 80 | is_sealed_file reads entire file to check 4-byte magic | Read only first 4 bytes instead of entire file

## MEDIUM — Engine (deep audit agents)

- [x] M-086 | wal/operations.rs:410-481 | MEDIUM | DATA_INTEGRITY | 90 | scan_to_end does not verify Ed25519 signatures during replay; forged sigs accepted | Verify each entry signature during WAL replay
- [x] M-087 | wal/operations.rs:294-301 | MEDIUM | DATA_INTEGRITY | 80 | truncate() re-signs all entries destroying original signatures | Preserve original signatures; only re-sign if key rotation required
- [x] M-088 | wal/operations.rs:270-273 | MEDIUM | DATA_INTEGRITY | 75 | truncate() doesn't verify retained entries form contiguous sequence | Validate ordinal continuity of retained entries
- [x] M-089 | wal/operations.rs:68-107 | MEDIUM | RESOURCE | 75 | No max WAL file size; 160TB theoretical max | Add configurable max WAL size with rotation or error
- [x] M-090 | report/html/sections.rs:22 | MEDIUM | XSS | 90 | report_id interpolated into HTML without escaping | Pass report_id through html_escape() before interpolation
- [x] M-091 | report/html/sections.rs:695 | MEDIUM | XSS | 90 | report_id/algorithm_version/schema_version unescaped in footer | Escape all interpolated values in footer HTML
- [x] M-092 | evidence/builder/setters.rs:511 | MEDIUM | DATA_INTEGRITY | 85 | sample_count uses unfiltered count while stats use filtered intervals | Use filtered count for sample_count to match stats
- [x] M-093 | evidence/builder/setters.rs:522-528 | MEDIUM | SECURITY | 80 | binding_mac uses entropy_hash as both commitment and MAC key; self-referential | Use separate key for binding MAC derivation
- [x] M-094 | report/html/helpers.rs:14-19 | MEDIUM | XSS | 90 | html_escape() doesn't escape single quotes | Add &#39; or &apos; mapping for single quotes
- [x] M-095 | tpm/linux.rs:245 | MEDIUM | SECURITY | 80 | seal() ignores _policy parameter; hardcodes default_pcr_selection() | Use provided policy parameter or document why it's ignored
- [x] M-096 | tpm/linux.rs:549 | MEDIUM | SECURITY | 75 | NV counter uses empty Auth; any owner-hierarchy process can increment | Set auth value on NV counter or use policy-based access
- [x] M-097 | tpm/linux.rs:422 | MEDIUM | SECURITY | 75 | SRK uses SymmetricDefinitionObject::Null instead of AES_128_CFB | Use AES_128_CFB for SRK symmetric definition per TPM best practices
- [x] M-098 | writersproof/client.rs:43 | MEDIUM | ERROR | 85 | Client builder failure silently falls back to default client without TLS/timeout | Return error on builder failure instead of silent fallback
- [x] M-099 | writersproof/client.rs:120 | MEDIUM | SECURITY | 80 | Signature doesn't cover nonce or hardware_key_id; replay possible | Include nonce and hardware_key_id in signed payload
- [x] M-100 | writersproof/client.rs:185-196 | MEDIUM | RESOURCE | 80 | Response body fully downloaded before size check; OOM from large response | Add Content-Length check and streaming read with size cap

## MEDIUM — macOS App (deep audit agents)

- [x] M-101 | NotificationManager.swift:51-66 | MEDIUM | PRIVACY | 85 | Notification history stores unredacted PII to unencrypted JSON file | Redact PII before storage or encrypt notification history
- [x] M-102 | EncryptedSessionStore.swift:268 | MEDIUM | SECURITY | 80 | Raw key material in Data not zeroized after SecItemAdd | Zero key Data after Keychain write
- [x] M-103 | EncryptedSessionStore.swift:245 | MEDIUM | SECURITY | 75 | Key fingerprint comparison uses non-constant-time != | Use constant-time comparison for key fingerprint checks
- [x] M-104 | EncryptedSessionStore.swift:110 | MEDIUM | DATA_INTEGRITY | 75 | keyQueue.sync can deadlock if called from key queue | Use trySync or restructure to avoid self-dispatch
- [x] M-105 | CPOPService+Actions.swift:84-131 | MEDIUM | CONCURRENCY | 85 | stopTracking reads status fields without snapshot; concurrent refresh causes stale data | Snapshot status atomically before decision logic
- [x] M-106 | CPOPService+Actions.swift:50-82 | MEDIUM | CONCURRENCY | 80 | Advisory file checks return early preventing FFI from making authoritative decision | Move file checks after FFI validation or use as warning only
- [x] M-107 | CPOPService+Actions.swift:152-156 | MEDIUM | CORRECTNESS | 80 | Checkpoint count race: currentSession can be nil'd by concurrent refresh | Capture session reference before checkpoint count read
- [x] M-108 | CPOPService+Actions.swift:157 | MEDIUM | SECURITY | 75 | Blocking manifest update on main actor; no error handling | Move to background task; add error handling
- [x] M-109 | CPOPService+Actions.swift:174-282 | MEDIUM | CONCURRENCY | 80 | Multi-step export has no cancellation checking between steps | Check Task.isCancelled between export steps

---

## LOW — Security

- [x] L-001 | secure_storage.rs:125 | LOW | HARDCODED_STR | 80 | Uses hardcoded "pdmn" instead of kSecAttrAccessible constant name | Use documented Security framework constant names
- [x] L-002 | secure_storage.rs:182 | LOW | HARDCODED_STR | 80 | Uses hardcoded "r_Data" instead of kSecReturnData constant name | Same as L-001
- [x] L-003 | secure_storage.rs:440 | LOW | ZEROIZE | 75 | load_mnemonic() returns plain String instead of Zeroizing<String> — mnemonic exposed in caller's stack | Return Zeroizing<String>
- [x] L-004 | ipc/server.rs:322 | LOW | RESOURCE | 75 | Spawned connection tasks have no per-connection timeout — idle connections never cleaned up | Add configurable connection timeout
- [x] L-005 | ipc/server.rs:186 | LOW | INFO_LEAK | 75 | Panic messages forwarded verbatim to IPC client — may expose internal paths or state | Sanitize error messages before sending to client
- [x] L-006 | ipc/secure_channel.rs:89 | LOW | CRYPTO | 70 | Nonce counter increments even if encryption fails — wastes nonce space | Only increment on successful encryption

## LOW — Correctness

- [x] L-007 | sentinel/core.rs:363 | LOW | CORRECTNESS | 80 | duration_since_last_ns hardcoded to 0 for every mouse sample — mouse jitter analysis always sees zero intervals | Compute actual duration from previous sample timestamp
- [x] L-008 | sentinel/core.rs:682 | LOW | CORRECTNESS | 90 | start_time() always returns None — callers cannot determine sentinel uptime | Set start_time field when sentinel starts
- [x] L-009 | sentinel/core.rs:55 | LOW | CORRECTNESS | 75 | broadcast channel events silently lost if no subscriber is active | Log dropped event count for diagnostics
- [x] L-010 | checkpoint/chain.rs:36 | LOW | CORRECTNESS | 70 | genesis_prev_hash uses char_count: content_size (bytes) as character count approximation — misleading for multi-byte encodings | Document limitation or attempt UTF-8 char count
- [x] L-011 | checkpoint/chain.rs:153 | LOW | CORRECTNESS | 72 | commit_internal: signed_duration_since can return negative Duration if clock goes backwards — unwrap_or(0) silently hides clock skew | Log warning on negative duration
- [x] L-012 | verify/mod.rs:248 | LOW | CORRECTNESS | 70 | verify_duration: claimed_seconds computed from first-to-last checkpoint but VDF iterations may span different intervals — comparison is approximate | Document approximation or sum per-checkpoint durations
- [x] L-013 | mmr/mmr.rs:124 | LOW | CORRECTNESS | 72 | get_leaf_index formula 2n - popcount(n) underflows for n=0 (returns 0 which is correct) but has no overflow guard for very large n | Add checked arithmetic for n close to u64::MAX
- [x] L-014 | ffi/evidence.rs:452 | LOW | CORRECTNESS | 70 | ffi_get_compact_ref uses "writerslogic:" prefix but ephemeral.rs uses "pop-ref:writerslogic:" — inconsistent compact ref format | Unify to single canonical format
- [x] L-015 | ffi/evidence.rs:291 | LOW | CORRECTNESS | 70 | MAX_FILE_SIZE constant duplicated between FFI and CLI — should be shared | Extract to a common const in engine crate
- [x] L-016 | ffi/ephemeral.rs:650 | LOW | CORRECTNESS | 68 | flush_session_state uses fs::write (not atomic) for crash recovery — partial write on crash corrupts recovery file | Use tempfile + rename pattern

## LOW — Performance

- [x] L-017 | mmr/mmr.rs:288 | LOW | PERFORMANCE | 70 | generate_range_merkle_path uses HashMap<u64, bool> for processed tracking — HashSet would be more idiomatic and efficient | Replace HashMap<_, bool> with HashSet
- [x] L-018 | verify/mod.rs:421 | LOW | PERFORMANCE | 68 | run_forensics creates EventData vec from edit_topology with all-zero timestamps, then immediately checks events_have_timestamps — wasted allocation | Check data availability before constructing events vec
- [x] L-019 | forensics/analysis.rs:49 | LOW | PERFORMANCE | 70 | build_profile clones entire events vec for sorting — could sort a vec of indices instead | Sort indices or use sort_unstable_by_key on reference
- [x] L-020 | vdf/swf_argon2.rs:381 | LOW | CORRECTNESS | 68 | verify() checks for index 0 twice: once at line 328 and again at line 381 — redundant check | Remove duplicate check at line 381

## LOW — macOS App

- [x] L-021 | OnboardingView.swift:20 | LOW | CONCURRENCY | 70 | accessibilityContinuation stored as @State — if view is recreated by SwiftUI, continuation may be orphaned | Use a separate ObservableObject to hold continuation state
- [x] L-022 | ExportFormView.swift:31 | LOW | RESOURCE | 68 | browseTask and exportTask stored as @State but not cancelled in onDisappear — tasks leak if user navigates away mid-operation | Cancel tasks in .onDisappear
- [x] L-023 | BatchVerifyView.swift:145-146 | LOW | RESOURCE | 75 | Unnecessary startAccessingSecurityScopedResource on NSOpenPanel URLs | Remove redundant security-scoped access calls for panel-returned URLs
- [x] L-024 | BatchVerifyView.swift:348-350 | LOW | RESOURCE | 75 | Double stopAccessing race between onDisappear and task completion | Guard with flag or single-owner pattern for stopAccessing calls
- [x] L-025 | WARReportPDFRenderer.swift:640-646 | LOW | CORRECTNESS | 75 | DateFormatter created per-call with no locale; output varies by user locale | Set locale to en_US_POSIX or cache formatter
- [x] L-026 | WARReportPDFRenderer.swift:584 | LOW | CORRECTNESS | 70 | Table cell truncation assumes 5pt per glyph; wrong for CJK/emoji | Use NSString.boundingRect for actual text measurement
- [x] L-027 | windows.rs:156 | LOW | CONCURRENCY | 75 | Module-level statics; second instance silently overwrites first | Use per-instance state or guard against multiple instantiation
- [x] L-028 | windows.rs:318 | LOW | SECURITY | 75 | Synthetic detection relies only on LLKHF_INJECTED; sophisticated injection bypasses | Add secondary detection (timing analysis, known injection patterns)
- [x] L-029 | windows.rs:153-154 | LOW | CORRECTNESS | 70 | KeystrokeMonitor _hook handle never unhooked on Drop | Implement Drop to call UnhookWindowsHookEx

## LOW — Engine (new audit agents)

- [x] L-030 | sealed_chain.rs:111-113 | LOW | DATA_INTEGRITY | 70 | save_sealed missing fsync before rename (RT-07 pattern) | Add File::sync_all() before rename for crash safety

---

## Dependency Graph

Fix order (respects dependencies):

### Wave 1 — Critical (8 items)
No dependencies between these. Fix first.
- C-001 (sentinel deadlock), C-002 (task leak), C-003 (DoS), C-004 (verify short-circuit), C-005 (HTTP TSA URLs)
- C-006, C-007 (TPM linux.rs deadlocks), C-008 (PCR policy unenforced)

### Wave 2 — High Security + Crypto (30 items)
Independent of each other. Can parallelize.
- H-001..H-012 (zeroize, crypto, TOCTOU, auth — from initial audit)
- H-013 (signature verification bypass)
- H-016 (HMAC seal re-derivation)
- H-017 (pubkey length validation)
- H-029 (biometric bypass)
- H-030 (path traversal)
- H-049 (consent enforcement), H-050 (superhuman threshold)
- H-051, H-052 (RFC 3161 nonce + CMS verification — depends on C-005)
- H-059 (HMAC timing side-channel), H-060 (sealed_chain zeroize)
- H-061 (TPM AK no auth), H-066..H-068 (HTML color XSS — 3 items)
- H-069 (HTTPS not enforced in client), H-073 (EncryptedSessionStore plaintext zeroing)

### Wave 3 — High Data Integrity + Concurrency (32 items)
Some depend on Wave 2 crypto fixes.
- H-014, H-015, H-018, H-019 (chain integrity, fsync, store HMAC)
- H-020..H-022 (MMR proof safety)
- H-023, H-024 (numeric overflow)
- H-025..H-028 (FFI atomicity, size limits, UTF-8, profile URI)
- H-031, H-032, H-034, H-035 (Swift concurrency)
- H-044 (PDF renderer silent page drop)
- H-045, H-046, H-047 (Windows handle/thread leaks, message pump)
- H-048 (Engine watcher thread leak)
- H-053 (async_client handshake timeout)
- H-054 (session seed permissions)
- H-055, H-056 (Secure Enclave CFRelease + Send+Sync)
- H-062, H-063 (TPM handle leaks — depends on C-006/C-007)
- H-064, H-065 (WAL split write + session_id overwrite)
- H-070 (keystroke callback mutex), H-071, H-072 (CGEventTap leaks)
- H-074 (fire-and-forget backup Tasks)

### Wave 4 — High UX + Resource + Remaining (13 items)
- H-033, H-037, H-043 (export UX)
- H-036 (cross-language test)
- H-038, H-039 (TOCTOU — macOS)
- H-040 (atomic write)
- H-041, H-042 (AppDelegate races)
- H-057 (DeviceAttestation auth bypass)
- H-058 (BrowserExtension HMAC fallback)

### Wave 5 — Medium (109 items)
Can be parallelized in batches of 8-10.
- **Batch A** (security): M-001..M-009, M-017, M-053, M-054
- **Batch B** (data integrity + crypto): M-010..M-016, M-018..M-026
- **Batch C** (concurrency + correctness): M-027..M-046, M-055..M-058
- **Batch D** (macOS app — original): M-047..M-052
- **Batch E** (engine — new agents): M-059..M-078 (daemon, engine, fingerprint, rfc3161, secure_enclave, linux)
- **Batch F** (macOS app — new agents): M-079..M-085 (receipt, safari, attestation, browser, settings, sealed_chain)
- **Batch G** (deep audit — engine): M-086..M-100 (WAL replay/truncate, HTML XSS, evidence builder, TPM linux, writersproof client)
- **Batch H** (deep audit — macOS app): M-101..M-109 (NotificationManager, EncryptedSessionStore, CPOPService+Actions)

### Wave 6 — Low (30 items)
Lowest priority. Polish and minor correctness.
- L-001..L-030

## Cross-References

| ID | Replaces / Merges | Notes |
|----|-------------------|-------|
| H-015 | old H-016 | Upgraded from conf 80 to 95 (agent confirmed RT-07 not fixed) |
| H-019 | old H-017 | Upgraded from conf 85 to 95 (agent confirmed divergence) |
| H-028 | old M-023 | Promoted MEDIUM->HIGH, conf 75->90 (spec-violating URI) |
| H-024 | old M-025 | Promoted MEDIUM->HIGH, conf 80->90 (overflow is exploitable) |
| M-024 | old M-030 | Upgraded conf 78->90 (agent confirmed collision risk) |
| M-045 | old M-029 | Upgraded conf 78->85 (agent confirmed 128GB allocation) |
| M-074 | — | conf 95 despite MEDIUM: legacy code, migration path needed before removal |

---

## Deep Audit — Top 10 Engine Files (2026-03-23)

Audited: sentinel/core.rs, checkpoint/chain.rs, verify/mod.rs, ipc/server.rs, engine.rs, crypto.rs, evidence/builder (mod+helpers), error.rs, store/events.rs, keyhierarchy/manager.rs

### HIGH

- [x] H-075 | sentinel/core.rs:59-78 | HIGH | SECURITY | 85 | mouse_stego_seed (32-byte key) not zeroized after constructor; persists on stack | Add mouse_stego_seed.zeroize() after MouseStegoEngine::new()
- [x] H-076 | sentinel/core.rs:103-106 | HIGH | SECURITY | 85 | Session nonce (32 bytes) not zeroized before reset_nonce sets Option to None | Zeroize nonce bytes before setting to None
- [x] H-077 | sentinel/core.rs:371 | HIGH | CORRECTNESS | 95 | duration_since_last_ns hardcoded to 0 in jitter samples; degrades all behavioral fingerprint quality | Compute delta from last_keystroke_ts_ns
- [x] H-078 | sentinel/core.rs:596 | HIGH | SECURITY | 75 | signing_key.clone() in start_witnessing creates unzeroized copy (same class as H-005, different call site) | Pass &SigningKey to Wal::open or ensure SigningKey has ZeroizeOnDrop
- [x] H-079 | checkpoint/chain.rs:219-414 | HIGH | CONCURRENCY | 85 | commit_entangled and commit_rfc bypass file lock added for H-014; concurrent writer causes stale content binding | Wrap both with acquire_lock/release_lock like commit_internal
- [x] H-080 | checkpoint/chain.rs:335-347 | HIGH | DATA_INTEGRITY | 75 | VDF output field packs output||input into 64-byte array without documenting encoding; downstream misinterpretation risk | Document encoding or use named struct fields; sync with types.rs:293
- [x] H-081 | verify/mod.rs:552 | HIGH | SECURITY | 80 | compute_verdict does not check signing_key_consistent; unrelated signing key gets V2LikelyHuman instead of V4LikelySynthetic | Add signing_key_consistent check before hierarchy/ratchet gate
- [x] H-082 | verify/mod.rs:440-446 | HIGH | CORRECTNESS | 85 | Synthetic EventData with timestamp_ns:0 and size_delta:0 produces misleading forensic metrics | Skip forensic analysis when events lack real timestamps
- [x] H-083 | verify/mod.rs:356-401 | HIGH | CORRECTNESS | 90 | Duplicate iteration passes for ratchet verification; first loop breaks early masking second loop's check | Merge into single pass checking negativity, monotonicity, and bounds
- [x] H-084 | ipc/server.rs:89 | HIGH | DATA_INTEGRITY | 75 | Response length cast as u32 silently truncates; no outbound size cap (pattern repeats at lines 144,169,204,224,246) | Use try_into with error, or cap outbound response size
- [x] H-085 | ipc/server.rs:310 | HIGH | CONCURRENCY | 80 | Connection count load+check+increment is non-atomic with Relaxed ordering; exceeds MAX_CONCURRENT_CONNECTIONS under race | Use fetch_add first, check, fetch_sub if over limit; use AcqRel ordering
- [x] H-086 | ipc/server.rs:186 | HIGH | SECURITY | 90 | Panic message forwarded to client leaks file paths and internal state (re-assess of L-005) | Log internally, return generic "Internal processing error" to client
- [x] H-087 | engine.rs:50 | HIGH | RESOURCE | 95 | No Drop impl for Engine; watcher thread, file watcher, and keystroke monitor leaked on drop | Add impl Drop for Engine that calls self.pause()
- [x] H-088 | crypto.rs:135 | HIGH | SECURITY | 85 | tag_key (32-byte HKDF-derived HMAC key) not zeroized after use in compute_jitter_seal | Add tag_key.zeroize() after HmacSha256::new_from_slice
- [x] H-089 | crypto.rs:157 | HIGH | SECURITY | 85 | binding_key not zeroized after use in compute_entangled_mac; same memory exposure | Add binding_key.zeroize() after HmacSha256::new_from_slice
- [x] H-090 | crypto.rs:163-167 | HIGH | SECURITY | 75 | compute_entangled_mac HMAC inputs lack length prefixes; variable-length fields enable concatenation collision | Add u32 length prefix before each variable-length field
- [x] H-091 | manager.rs:57-61 | HIGH | SECURITY | 95 | unseal_master_key returns bare SigningKey; not zeroized after start_session_with_key | Call master_key.zeroize() after use or wrap in Zeroizing
- [x] H-092 | manager.rs:29 | HIGH | SECURITY | 75 | document_path accepted without canonicalization; symlink/traversal could bind session to wrong file | Use std::fs::canonicalize before hashing
- [x] H-093 | store/events.rs:246-248 | HIGH | DATA_INTEGRITY | 85 | prune_payloads with days_to_keep=0 wipes all historical data; no input validation | Reject days_to_keep < 1
- [x] H-094 | store/events.rs:158 | HIGH | TYPE_SAFETY | 70 | i64 as u64 cast for vdf_iterations on read; negative from corruption wraps to u64::MAX | Use u64::try_from(v).unwrap_or(0)
- [x] H-095 | error.rs:49,101 | HIGH | OBSERVABILITY | 100 | VdfAggregate and Vdf variants share identical #[error("vdf: {0}")] display; indistinguishable in logs | Change VdfAggregate to #[error("vdf aggregate: {0}")]

### MEDIUM

- [x] M-110 | sentinel/core.rs:308-313 | MEDIUM | CORRECTNESS | 90 | Missing #[cfg] fallback for mouse capture on unsupported platforms; compile error | Add cfg(not(any(...))) fallback returning Err
- [x] M-111 | sentinel/core.rs:594 | MEDIUM | CORRECTNESS | 65 | session_id hex_decode into 32-byte buffer fails silently (32 hex chars = 16 bytes, not 32); WAL entries dropped | Fix buffer size or generate 64-char hex session IDs
- [x] M-112 | sentinel/core.rs:694-696 | MEDIUM | API_CONTRACT | 95 | start_time() always returns None; dead method | Track start time or remove method
- [x] M-113 | sentinel/core.rs:282-284 | MEDIUM | OBSERVABILITY | 95 | Log says "channel full" but blocking_send Err means channel closed | Fix log message to "channel closed"
- [x] M-114 | checkpoint/chain.rs:39,364 | MEDIUM | DATA_INTEGRITY | 70 | char_count set to content_size (byte length); diverges for multibyte UTF-8 | Count actual characters or use sentinel value
- [x] M-115 | checkpoint/chain.rs:154,239,292 | MEDIUM | TYPE_SAFETY | 50 | No cap on checkpoint count; malicious chain file causes OOM on load | Add MAX_CHECKPOINTS constant and reject in load
- [x] M-116 | checkpoint/chain.rs:716 | MEDIUM | SECURITY | 60 | Deterministic temp file name (.tmp) enables symlink attack | Use tempfile::NamedTempFile + persist()
- [x] M-117 | checkpoint/chain.rs:726-731 | MEDIUM | RESOURCE | 70 | No file size check before fs::read on chain file; multi-GB causes OOM | Check metadata().len() against MAX_CHAIN_FILE_SIZE
- [x] M-118 | checkpoint/chain.rs:392 | MEDIUM | API_CONTRACT | 60 | vdf_params.min_iterations reused as Argon2id time cost; couples unrelated params | Use dedicated Argon2 parameter
- [x] M-119 | checkpoint/chain.rs:147-273 | MEDIUM | MAINTAINABILITY | 85 | Three commit methods duplicate ~15 lines of boilerplate; lock fix missed two paths | Extract prepare_commit/finalize_commit helpers
- [x] M-120 | verify/mod.rs:270-274 | MEDIUM | DATA_INTEGRITY | 75 | iterations_per_second == 0 treated as plausible; bypasses duration check | Emit warning and treat as implausible
- [x] M-121 | verify/mod.rs:460 | MEDIUM | DATA_INTEGRITY | 70 | timestamp_nanos_opt None fallback saturates to i64::MAX; corrupts jitter duration | Add bounds check when timestamp_nanos_opt returns None
- [x] M-122 | verify/mod.rs:213 | MEDIUM | SECURITY | 65 | jitter_tag_valid naming implies crypto validation but only checks non-zero bytes | Rename to jitter_tag_present
- [x] M-123 | verify/mod.rs:478 | MEDIUM | CORRECTNESS | 80 | Empty regions HashMap always passed to analyze_forensics_ext; region-based analysis skipped | Extract region data from packet behavioral data
- [x] M-124 | verify/mod.rs:280 | MEDIUM | CORRECTNESS | 70 | num_seconds() truncates sub-second precision; short sessions get wrong ratio | Use num_milliseconds() as f64 / 1000.0
- [x] M-125 | ipc/server.rs:308 | MEDIUM | ERROR_HANDLING | 90 | run_with_handler accept error propagates via ? killing entire server; run_with_shutdown handles correctly | Match on accept error, log, sleep 100ms, continue
- [x] M-126 | ipc/server.rs:144-248 | MEDIUM | MAINTAINABILITY | 72 | Dead plaintext fallback branches (~50 lines) after SecureJson-only enforcement | Remove unreachable else branches or make secure_session non-optional
- [x] M-127 | ipc/server.rs:500 | MEDIUM | RESOURCE | 60 | Windows SID string PWSTR not wrapped in RAII guard; relies on manual LocalFree ordering | Use scopeguard or RAII wrapper for PWSTR
- [x] M-128 | engine.rs:311 | MEDIUM | CONCURRENCY | 75 | old_path.exists() filesystem I/O while content_hash_map Mutex held; blocks on slow FS | Extract values, drop lock, check exists, re-acquire
- [x] M-129 | engine.rs:380 | MEDIUM | CORRECTNESS | 80 | samples.clear() discards all jitter data on first file event in burst; subsequent files misattributed as paste | Partition or timestamp-filter samples
- [x] M-130 | engine.rs:408 | MEDIUM | CONCURRENCY | 50 | store and status locks acquired in specific undocumented order; future callers risk deadlock | Document lock ordering invariant
- [x] M-131 | crypto.rs:114 | MEDIUM | SECURITY | 80 | derive_hmac_key returns plain Vec<u8> instead of Zeroizing; callers store key material without zeroize-on-drop | Return Zeroizing<Vec<u8>>, update 4 call sites
- [x] M-132 | crypto.rs:182-189 | MEDIUM | ERROR_HANDLING | 90 | restrict_permissions Windows branch discards icacls exit status; callers believe permissions set when they may not be | Check output.status.success() and return Err on failure
- [x] M-133 | crypto.rs:180 | MEDIUM | SECURITY | 60 | to_string_lossy on Windows path may target wrong file for icacls | Use path.as_os_str() for argument passing
- [x] M-134 | manager.rs:152 | MEDIUM | API_CONTRACT | 100 | signed_checkpoints returns &Vec<Checkpoint> instead of idiomatic &[Checkpoint] | Change return type to &[checkpoint::Checkpoint]
- [x] M-135 | manager.rs:111-142 | MEDIUM | MAINTAINABILITY | 100 | commit_and_sign and commit_and_sign_with_duration duplicate sign-last-checkpoint logic | Extract private sign_last_checkpoint helper
- [x] M-136 | manager.rs:116 | MEDIUM | ERROR_HANDLING | 60 | chain.commit() error mapped to Crypto(String) loses original variant | Add Checkpoint variant or preserve chain with format!("{e:#}")
- [x] M-137 | manager.rs:80 | MEDIUM | API_CONTRACT | 50 | end() allows double-call silently with no guard or documented idempotency | Return Result or document contract
- [x] M-138 | store/events.rs:57 | MEDIUM | TYPE_SAFETY | 60 | u64 as i64 lossy cast for vdf_iterations on insert; values > i64::MAX wrap negative | Use i64::try_from with error
- [x] M-139 | store/events.rs:83-88 | MEDIUM | PERFORMANCE | 65 | get_events_for_file has no LIMIT; long sessions load full history into memory | Add optional limit parameter or separate recent-events method
- [x] M-140 | store/events.rs:246-258 | MEDIUM | DATA_INTEGRITY | 75 | prune_payloads nullifies fields without documenting HMAC-safety invariant | Add doc comment clarifying pruned fields are not HMAC inputs
- [x] M-141 | evidence/builder/helpers.rs:110-112 | MEDIUM | DATA_INTEGRITY | 85 | Silent zeroing on short hash input; corrupted evidence if final_hash < 32 bytes | Reject input with error if len != 32
- [x] M-142 | evidence/builder/helpers.rs:153-154 | MEDIUM | CORRECTNESS | 90 | ended - started can overflow on extreme i64 values before .max(0) guard | Use ended.saturating_sub(started).max(0) as u64
- [x] M-143 | evidence/builder/helpers.rs:172 | MEDIUM | TYPE_SAFETY | 80 | usize as i32 truncates silently on 64-bit for total_samples and unique_doc_states | Use i32::try_from(...).unwrap_or(i32::MAX)
- [x] M-144 | evidence/builder/mod.rs:289-294 | MEDIUM | CORRECTNESS | 50 | NaN plausibility_score values produce "avg plausibility NaN%" in claims | Guard against NaN sum
- [x] M-145 | evidence/builder/mod.rs:161-337 | MEDIUM | MAINTAINABILITY | 90 | generate_claims is 176 lines with 12 independent branches | Extract per-claim-type helpers
- [x] M-146 | error.rs:217-227 | MEDIUM | TYPE_SAFETY | 80 | From<String> and From<&str> impls silently convert any string to Error::Legacy; no production callers | Deprecate or remove Legacy variant
- [x] M-147 | error.rs:28-30 | MEDIUM | API_CONTRACT | 75 | #[cfg(unix)] on Ipc variant means Error enum shape differs across platforms | Add platform-agnostic IPC error variant
- [x] M-148 | error.rs:204-206 | MEDIUM | CORRECTNESS | 70 | is_transient() omits Ipc errors which are typically retryable | Add cfg-gated Error::Ipc match arm

### LOW

- [x] L-031 | sentinel/core.rs:211 | LOW | MAINTAINABILITY | 95 | start() is 244 lines; handles config, platform dispatch, bridge threads, event loop, cleanup | Extract spawn_keystroke_bridge and spawn_mouse_bridge helpers
- [x] L-032 | checkpoint/chain.rs:66 | LOW | OBSERVABILITY | 80 | VerificationReport::fail overwrites error; cannot accumulate if verify changes to continue-on-error | Change error: Option<String> to errors: Vec<String>
- [x] L-033 | verify/mod.rs:617 | LOW | MAINTAINABILITY | 95 | Import placed after function definitions, far from other imports | Move to import block at top of file
- [x] L-034 | ipc/server.rs:298 | LOW | API_CONTRACT | 95 | socket_path() returns &PathBuf instead of idiomatic &Path | Change return type to &Path
- [x] L-035 | engine.rs:259 | LOW | DATA_INTEGRITY | 75 | last_event_timestamp_ns updated on error path even though no event was written | Remove timestamp update from error branch
- [x] L-036 | engine.rs:208 | LOW | TYPE_SAFETY | 50 | count as u64 from i64 without guarding negative; safe in practice (SQLite COUNT) | Use count.max(0) as u64
- [x] L-037 | engine.rs:452 | LOW | MAINTAINABILITY | 30 | Device identity fallback written as minified JSON | Use serde_json::to_string_pretty
- [x] L-038 | crypto/obfuscated.rs:14-17 | LOW | CONCURRENCY | 70 | ROLLING_KEY load+compute+store non-atomic; concurrent threads get duplicate XOR keys | Use fetch_update or document accepted trade-off
- [x] L-039 | crypto/obfuscated.rs:31 | LOW | ERROR_HANDLING | 50 | bincode encode_to_vec .expect() panics in library code on serialization failure | Return Result or document panic contract
- [x] L-040 | error.rs:229-233 | LOW | TYPE_SAFETY | 50 | From<Error> for String discards variant info; round-trip yields Legacy | Remove if unused or document lossy conversion
- [x] L-041 | error.rs:204-214 | LOW | MAINTAINABILITY | 100 | is_transient() and is_validation() are public but have zero callers outside tests | Scope to pub(crate) or remove
- [x] L-042 | evidence/builder/helpers.rs:184-230 | LOW | API_CONTRACT | 85 | build_ephemeral_packet skips claims/trust_tier generation; structurally different from Builder-produced packets | Document or add shared finalization step
- [x] L-043 | evidence/builder/mod.rs:231-237 | LOW | API_CONTRACT | 70 | physical_context and hardware both use ClaimType::HardwareAttested; cannot distinguish by type | Add ClaimType::PhysicalContextCaptured or merge claims
- [x] L-044 | manager.rs:29,55 | LOW | PERFORMANCE | 40 | Both constructors hash document file; callers may double-hash same file | Accept pre-computed doc_hash parameter
- [x] L-045 | store/events.rs:182-189 | LOW | MAINTAINABILITY | 90 | get_global_activity and get_all_event_timestamps execute identical SQL; minor DRY violation | Implement get_global_activity in terms of get_all_event_timestamps

---

## macOS Security File Audit (2026-03-23)

Audited: AuthService, EncryptedSessionStore, CertificateService, DeviceAttestationService, BrowserExtensionService, SettingsIntegrityService, CodeSigningValidation, CryptoHelpers, SecureEnclaveKeyManager

### Systemic Patterns

- [x] SYS-S01 | 4 files | ATOMICITY | Non-atomic Keychain delete+add; crash between ops loses data permanently. Use SecItemUpdate with SecItemAdd fallback. Affects: EncryptedSessionStore:267, DeviceAttestationService:665, SecureEnclaveKeyManager:243, SettingsIntegrityService (counter path). DataDirectoryIntegrityService already fixed.
- [x] SYS-S02 | 4 files | ZEROIZE | Key material/plaintext lingers in heap as plain Data; never zeroed. Affects: EncryptedSessionStore (save/load/restore), SettingsIntegrityService:500, BrowserExtensionService:726, SecureEnclaveKeyManager (post-save).
- [x] SYS-S03 | 2 files | TIMING | constantTimeEqual early-returns on length mismatch. Safe for fixed-length HMACs but fragile. Affects: CryptoHelpers:73, SettingsIntegrityService:73. DataDirectoryIntegrityService already fixed.
- [x] SYS-S04 | 2 files | TOCTOU | Predictable temp filenames or non-atomic rename. Affects: BrowserExtensionService:633,638, CertificateService:269.
- [ ] SYS-S05 | 2 files | ACCESS_CONTROL | Keychain items lack kSecAttrAccessControl; any same-user process reads them. Affects: EncryptedSessionStore:279, SecureEnclaveKeyManager:237.
- [x] SYS-S06 | 3 files | SILENT_FAIL | SecItemAdd status discarded; downstream bypasses security. Affects: AuthService:923, BrowserExtensionService:670, SecureEnclaveKeyManager:272.

### CRITICAL

- [ ] C-009 | EncryptedSessionStore.swift:279 | CRITICAL | ACCESS_CONTROL | 95 | Keychain item lacks kSecAttrAccessControl; any user-level process extracts AES key after first unlock | Add SecAccessControl with appropriate flags; add kSecAttrSynchronizable:false. **SYS-S05**
- [x] C-010 | DeviceAttestationService.swift:330 | CRITICAL | SIGNING_ORDER | 90 | Counter not cryptographically bound to signed attestation payload; signature and counter can be mixed by attacker | Move incrementCounter before signing; include counter value in signed challenge data
- [x] C-011 | BrowserExtensionService.swift:683 | CRITICAL | INPUT_VALIDATION | 90 | resolveChromiumExtensionId silently falls through to default on invalid override; masks config errors in production | Return nil and propagate as .failed() when override is non-nil but fails validation

### HIGH

- [ ] H-096 | AuthService.swift:579 | HIGH | AUTH_CONFIG | 90 | OAuth session uses persistent browser state (prefersEphemeralWebBrowserSession=false); session fixation risk | Set prefersEphemeralWebBrowserSession=true; gate non-ephemeral on trusted device check
- [ ] H-097 | AuthService.swift:691 | HIGH | AUTH_BYPASS | 88 | Biometric grace window (30 min) not invalidated on screen lock, sleep, or app backgrounding | Subscribe to willSleepNotification/screensDidSleepNotification to nil lastBiometricAuthDate
- [ ] H-098 | EncryptedSessionStore.swift:43 | HIGH | ZEROIZE | 90 | Plaintext Data from JSONEncoder never zeroed after encryption in save() | Zero mutableData via withUnsafeMutableBytes after seal. **SYS-S02**
- [ ] H-099 | EncryptedSessionStore.swift:85 | HIGH | ZEROIZE | 90 | Plaintext Data from AES.GCM.open in load() never zeroed | Zero decrypted Data after JSONDecoder.decode. **SYS-S02**
- [ ] H-100 | EncryptedSessionStore.swift:220 | HIGH | ZEROIZE | 85 | restoreFilesWithKey never zeros plaintext after re-encrypting | Zero plaintext in restore loop body. **SYS-S02**
- [ ] H-101 | CertificateService.swift:285 | HIGH | ATOMICITY | 92 | Cleanup path constructs wrong temp URL; orphaned temp file on failure | Capture sigTmpURL outside do block; use in catch/defer
- [ ] H-102 | CertificateService.swift:269 | HIGH | ATOMICITY | 88 | Sidecar temp file written non-atomically (atomically:false) | Change to atomically:true or write to NSTemporaryDirectory first. **SYS-S04**
- [ ] H-103 | DeviceAttestationService.swift:347 | HIGH | DOWNGRADE_BYPASS | 85 | Hardware-binding downgrade check only runs on old state; first attestation can always be software-only | Query SecureEnclave.isAvailable directly; reject software fallback if hardware available
- [ ] H-104 | DeviceAttestationService.swift:133 | HIGH | TLS_PIN_BYPASS | 80 | spkiData() falls back to hashing raw key bytes for unrecognized key type; fragile | Return nil for unrecognized key types instead of hashing incomplete data
- [ ] H-105 | DeviceAttestationService.swift:436 | HIGH | HARDCODED_URL | 85 | Fallback Supabase Edge Function URL hardcoded; silently used if Info.plist key missing | Fail with explicit error if SUPABASE_FUNCTIONS_URL not set
- [ ] H-106 | BrowserExtensionService.swift:617 | HIGH | INJECTION | 85 | Extension ID interpolated into allowed_origins without re-validation on default path | Always validate resolved ID with isValidChromeExtensionId before interpolation
- [ ] H-107 | BrowserExtensionService.swift:633 | HIGH | TOCTOU | 80 | Predictable temp filename in user-writable dir; symlink attack possible | Use mkstemp-style random temp filenames. **SYS-S04**
- [ ] H-108 | BrowserExtensionService.swift:638 | HIGH | TOCTOU | 80 | removeItem+moveItem is not atomic; symlink race between operations | Use replaceItemAt or POSIX rename(). **SYS-S04**
- [ ] H-109 | CodeSigningValidation.swift:126 | HIGH | MISSING_TEAM_ID | 92 | No team ID or bundle ID pinning in code signing requirements; any Apple-signed app passes | Add identifier and certificate leaf[subject.OU] to requirement strings
- [ ] H-110 | CodeSigningValidation.swift:47 | HIGH | TOCTOU | 85 | isCodeSigned/isMacAppStoreBuild still use path-based SecStaticCodeCreateWithPath (H-022 residual) | Refactor to use copyStaticCode() like validate() does
- [ ] H-111 | CodeSigningValidation.swift:219 | HIGH | FAIL_OPEN | 80 | errSecOCSPNotTrustedToAnchor (-67631) misclassified as network error; bypasses revocation on attacker-controlled OCSP | Remove -67631 from network codes set
- [ ] H-112 | SettingsIntegrityService.swift:180 | HIGH | ATOMICITY | 85 | Counter incremented before HMAC written; crash between them = permanent false tamper detection | Compute HMAC first, write counter+HMAC+backup together, revert counter on failure. **SYS-S01**
- [ ] H-113 | SettingsIntegrityService.swift:500 | HIGH | ZEROIZE | 85 | HMAC key returned as plain Data; persists in heap with no zeroing | Return SymmetricKey directly or zero Data after constructing key. **SYS-S02**
- [ ] H-114 | SecureEnclaveKeyManager.swift:237 | HIGH | KEY_PROTECTION | 90 | Keychain save uses kSecAttrAccessible instead of kSecAttrAccessControl; SE access policy silently downgraded | Pass SecAccessControl from key creation into saveKey(). Refinement of H-021. **SYS-S05**
- [ ] H-115 | SecureEnclaveKeyManager.swift:50 | HIGH | SIGNING_SAFETY | 85 | sign(data:) hashes internally; callers cannot verify algorithm; pre-hashed data gets double-hashed | Document SHA-256 internal hashing; consider requiring sign(digest:) overload

### MEDIUM

- [ ] M-149 | AuthService.swift:988 | MEDIUM | TIMING | 80 | Device fingerprint binding uses non-constant-time string comparison | Use constantTimeEqual for fingerprint comparison
- [ ] M-150 | AuthService.swift:907 | MEDIUM | SILENT_FAIL | 78 | SecureAuthStore.set silently drops errors from SecItemAdd; device binding bypassed | Check OSStatus; return Bool or throw on failure. **SYS-S06**
- [ ] M-151 | AuthService.swift:76 | MEDIUM | RATE_LIMIT | 78 | SignInRateLimiter is in-memory only; app restart resets all rate limits | Persist failureCount/lockedUntil to SecureAuthStore
- [ ] M-152 | AuthService.swift:546 | MEDIUM | REDIRECT | 75 | OAuth redirect URL hardcoded; no PKCE state parameter validation at app layer | Verify Supabase SDK uses PKCE flow; add explicit state validation
- [ ] M-153 | AuthService.swift:1014 | MEDIUM | TIME_MANIPULATION | 72 | TrustedDeviceManager trust expiry uses system clock; clock rollback extends window indefinitely | Store monotonic reference alongside wall clock; reject if clock went backward
- [ ] M-154 | EncryptedSessionStore.swift:56 | MEDIUM | FILE_PERMISSIONS | 75 | Store directory and files created with default permissions (0755/0644) | Set directory to 0700, files to 0600
- [ ] M-155 | EncryptedSessionStore.swift:267 | MEDIUM | ATOMICITY | 80 | Delete-then-add Keychain pattern; crash window loses key permanently | Use SecItemUpdate with SecItemAdd fallback. **SYS-S01**
- [ ] M-156 | EncryptedSessionStore.swift:141 | MEDIUM | CONCURRENCY | 70 | rotateKey holds keyQueue for entire duration of file I/O on all files | Document blocking behavior or restructure to minimize critical section
- [ ] M-157 | CertificateService.swift:127 | MEDIUM | CONCURRENCY | 80 | nonisolated(unsafe) on shared CIContext; not thread-safe for concurrent QR gen | Create local CIContext per call or protect with lock
- [ ] M-158 | CertificateService.swift:257 | MEDIUM | PATH_TRAVERSAL | 78 | Sidecar .sig path re-resolves symlinks after original validation; TOCTOU window | Compute volume check for sigURL; or skip re-resolving
- [ ] M-159 | CertificateService.swift:260 | MEDIUM | PATH_TRAVERSAL | 82 | Sidecar allowed-directory check uses trailing-slash prefix but sigPath not normalized same way | Use starts(with:) on URL path components instead of string prefix
- [ ] M-160 | CertificateService.swift:996 | MEDIUM | INPUT_VALIDATION | 75 | Steganographic watermark embeds raw hash with no HMAC authentication | Compute HMAC over (evidenceHash, imageHash) or document as informational only
- [ ] M-161 | DeviceAttestationService.swift:466 | MEDIUM | CHALLENGE_SIZE | 85 | Server challenge has no minimum length check; 1-byte challenge = negligible replay resistance | Verify decoded challenge is at least 16 bytes
- [ ] M-162 | DeviceAttestationService.swift:654 | MEDIUM | OVERFLOW | 75 | Monotonic counter wraps on UInt64 overflow; produces false sentinel value | Check for UInt64.max-1 before incrementing
- [ ] M-163 | DeviceAttestationService.swift:665 | MEDIUM | ATOMICITY | 80 | Counter delete-then-add; crash resets to 0 enabling replay | Use SecItemUpdate. **SYS-S01**
- [ ] M-164 | DeviceAttestationService.swift:250 | MEDIUM | MIGRATION | 75 | UserDefaults migration trusts unverified values; attacker pre-plants future lastAttestedAt | Force needsReattestation=true after migration or cap timestamp to Date()
- [ ] M-165 | BrowserExtensionService.swift:726 | MEDIUM | KEY_LIFECYCLE | 75 | _cachedHMACKey held indefinitely in static var; SymmetricKey not zeroized on dealloc | Re-derive from Keychain on each check or clear after timeout. **SYS-S02**
- [ ] M-166 | BrowserExtensionService.swift:670 | MEDIUM | SILENT_FAIL | 80 | HMAC write failure silently returns .ok(); creates false-positive tamper alarm loop | Treat HMAC write failure as manifest installation failure. **SYS-S06**
- [ ] M-167 | BrowserExtensionService.swift:676 | MEDIUM | RESOURCE | 70 | Immutable flag set after HMAC write; if HMAC fails, manifest locked without HMAC | Set immutable flag only after both writes succeed
- [ ] M-168 | SettingsIntegrityService.swift:614 | MEDIUM | INTEGRITY | 80 | buildPayload uses pipe-delimited key=value without escaping; delimiter injection produces HMAC collision | Use structured serialization (JSON with sorted keys) or escape delimiters
- [ ] M-169 | SettingsIntegrityService.swift:641 | MEDIUM | INTEGRITY | 75 | serializeValue maps nil and unknown types to same "nil" string | Use distinct sentinel strings for nil vs unknown-type
- [ ] M-170 | SettingsIntegrityService.swift:384 | MEDIUM | AUTH_BYPASS | 80 | importSettings uses local HMAC key; cross-device import silently fails; same-device attacker can forge blobs | Implement passphrase-derived key or surface "same device only" as explicit error
- [ ] M-171 | CodeSigningValidation.swift:104 | MEDIUM | INCONSISTENCY | 78 | isCodeSigned uses no flags (accepts non-strict sigs) while validate() uses strict flags | Use same strict flags in all code signing checks
- [ ] M-172 | CodeSigningValidation.swift:34 | MEDIUM | TOCTOU | 72 | checkRevocationStatus called standalone creates second code object; potential divergence | Make code parameter non-optional or make method private
- [ ] M-173 | CryptoHelpers.swift:73 | MEDIUM | TIMING | 90 | constantTimeEqual(Data) early-returns false on length mismatch; leaks length info to caller | Add doc warning or pad shorter input. **SYS-S03**
- [ ] M-174 | CryptoHelpers.swift:44 | MEDIUM | PERFORMANCE | 75 | hexString uses String(format:) per byte via ObjC bridge; ~100x slower than lookup table | Replace with static hex lookup table
- [ ] M-175 | SecureEnclaveKeyManager.swift:19 | MEDIUM | CONCURRENCY | 80 | isAvailable is non-isolated static; races with actor-isolated methods | Add actor-isolated ensureAvailable() called at top of signingKey()/agreementKey()
- [ ] M-176 | SecureEnclaveKeyManager.swift:183 | MEDIUM | ACCESS_CONTROL | 85 | Neither createSigningKey nor agreementKey sets .userPresence in access control flags | Add .userPresence or .biometryCurrentSet to ACL flags; document if omitted intentionally
- [ ] M-177 | SecureEnclaveKeyManager.swift:231 | MEDIUM | ATOMICITY | 80 | saveKey() performs delete-then-add; crash loses key reference permanently | Use SecItemUpdate with SecItemAdd fallback. **SYS-S01**
- [ ] M-178 | SecureEnclaveKeyManager.swift:88 | MEDIUM | INPUT_VALIDATION | 80 | sha256Stream accepts unbounded bufferSize; Int.max causes OOM | Clamp bufferSize to max 1MB, min 4KB
- [ ] M-179 | SecureEnclaveKeyManager.swift:152 | MEDIUM | INPUT_VALIDATION | 75 | deriveSymmetricKey accepts 0 outputByteCount and empty salt | Validate outputByteCount 16-64; reject empty salt
- [ ] M-180 | SettingsIntegrityService.swift:73 | MEDIUM | TIMING | 80 | constantTimeEqual early-returns on length mismatch | Pad or reject non-32-byte input. **SYS-S03**

### LOW

- [ ] L-046 | AuthService.swift:295 | LOW | INFO_LEAK | 68 | Auth state listener logs user email without .private redaction | Use privacy:.private consistently
- [ ] L-047 | AuthService.swift:262 | LOW | CONCURRENCY | 65 | authStateTask and sessionMonitorTask not cancelled in deinit | Add deinit that cancels both Tasks
- [ ] L-048 | CertificateService.swift:246 | LOW | LOGGING | 70 | Rejected path logged at error level includes resolved path | Log only filename or hash of path
- [ ] L-049 | CertificateService.swift:100 | LOW | INPUT_VALIDATION | 65 | processScore validated for NaN/Inf but not for reasonable bounds | Add range check (0.0...100.0)
- [ ] L-050 | DeviceAttestationService.swift:301 | LOW | RATE_LIMIT | 60 | recentAttempts suffix(20) cap can forget attempts within the same hour | Remove suffix(20) cap or raise to match hour window
- [ ] L-051 | BrowserExtensionService.swift:442 | LOW | PERFORMANCE | 70 | verifyManifestIntegrity called per-browser inside loop; O(N^2) integrity checks | Call once before loop and check per-browser from results
- [ ] L-052 | BrowserExtensionService.swift:164 | LOW | INPUT_VALIDATION | 65 | Firefox extension ID regex allows %; URL-encoded injection if used in URL context | Tighten regex or document constraint
- [ ] L-053 | EncryptedSessionStore.swift:24 | LOW | CONCURRENCY | 65 | cachedKeyFingerprint read outside keyQueue in keyWasRotated() | Wrap body in keyQueue.sync
- [ ] L-054 | SettingsIntegrityService.swift:96 | LOW | SPOOFING | 65 | IOPlatformUUID spoofable on VMs or with SIP disabled | Document as known limitation; consider combining with SE attestation
- [ ] L-055 | SettingsIntegrityService.swift:792 | LOW | CONCURRENCY | 60 | logAuditEntry has no serialization guard; concurrent calls can lose entries | Use dedicated serial queue for audit writes
- [ ] L-056 | SettingsIntegrityService.swift:196 | LOW | CONSISTENCY | 55 | HMAC read-back uses == instead of constantTimeEqual (non-secret comparison but inconsistent) | Use constantTimeEqual or add comment explaining why == is acceptable
- [ ] L-057 | CodeSigningValidation.swift:109 | LOW | COMPLETENESS | 68 | Validity flags do not include kSecCSEnforceRevocationChecks | Consider adding to unify revocation with signature validation
- [ ] L-058 | CodeSigningValidation.swift:21 | LOW | OBSERVABILITY | 65 | validate() returns failure variants without logging | Add os.Logger calls for non-valid results
- [ ] L-059 | CryptoHelpers.swift:75 | LOW | COMPILER | 70 | XOR loop in constantTimeEqual could theoretically be optimized to short-circuit by future LLVM | Add @inline(never) or delegate to CRYPTO_memcmp
- [ ] L-060 | CryptoHelpers.swift:24 | LOW | ERROR_GRANULARITY | 65 | sha256HexStream returns nil for both missing file and read error | Return Result<String, Error> to let callers distinguish
- [ ] L-061 | SecureEnclaveKeyManager.swift:272 | LOW | SILENT_FAIL | 75 | deleteKey discards OSStatus; deleteAllKeys logs "All keys deleted" even on failure | Check return status; log warning for non-success/non-not-found. **SYS-S06**
- [ ] L-062 | SecureEnclaveKeyManager.swift:6 | LOW | NAMING | 70 | Logger subsystem uses stale "witnessd" name instead of "cpop" or "writersproof" | Update to com.writerslogic.cpop

## Session State

**ACTIVE_TASKS**: None (macOS security audit complete, fixes not started)
**LAST_UPDATED**: 2026-03-23
**ENGINE_TESTS**: 868 pass, 0 fail, 1 ignored (pre-audit baseline)
**AUDIT_AGENTS**: 48 total (39 engine + 9 macOS security files)
