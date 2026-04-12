# Consolidated Audit Findings

Generated: 2026-03-25 | Updated: 2026-03-25
Files audited: 50
Total findings: 190 (14 High, 52 Medium, 124 Low)
**Resolved: 14 High + 38 Medium = 52 fixed | Remaining: 14 Medium + 124 Low**

## Summary by Severity

| Severity | Count | Action |
|----------|-------|--------|
| C (Critical) | 0 | Immediate fix required |
| H (High) | 14 | Fix before release |
| M (Medium) | 52 | Fix in next sprint |
| L (Low) | 124 | Track for future cleanup |

---

## HIGH-SEVERITY FINDINGS (Fix Before Release)

### Crypto / Key Management

- [ ] **AUD-005** [H] `crypto/mem.rs:27` - ProtectedKey::new copies bytes before caller's copy is zeroized; caller's stack copy of key material persists in memory
- [ ] **AUD-015** [H] `keyhierarchy/identity.rs:17` - derive_signing_key does not zeroize puf_response Vec; PUF challenge-response material persists on heap

### Checkpoint / Evidence Integrity

- [ ] **AUD-026** [H] `checkpoint/chain.rs:600` - verify_detailed() only checks signature length (64 bytes) but never verifies Ed25519 signature cryptographically; garbage signatures pass
- [ ] **AUD-027** [H] `checkpoint/types.rs:230` - compute_hash() calls timestamp_nanos_safe() which silently clamps; two different timestamps could produce same hash if validate_timestamp() not called first
- [ ] **AUD-030** [H] `evidence/builder/helpers.rs:144` - build_ephemeral_packet uses content_hash as chain linkage instead of checkpoint hash; no tamper detection between checkpoints
- [ ] **AUD-036** [H] `evidence/builder/helpers.rs:205` - build_ephemeral_packet sets VDF params to all zeros (iterations_per_second=0); causes division-by-zero if verify() called on resulting packet

### Platform / FFI

- [ ] **AUD-089** [H] `ffi/system.rs:46` - ffi_init writes raw signing key to disk; if crash between write and restrict_permissions, key file is world-readable
- [ ] **AUD-093** [H] `platform/macos/mouse_capture.rs` - MacOSMouseCapture has no Drop impl; CGEventTap thread runs forever if stop() not called, CF objects leaked
- [ ] **AUD-094** [H] `platform/macos/mouse_capture.rs:131` - CGEventTap and CFRunLoopSource created in thread never stored for later release; resource leak
- [ ] **AUD-097** [H] `platform/macos/keystroke.rs:316` - KeystrokeMonitor::stop() potential double-free: ptr used by CFRunLoopStop then again by CFRelease in else branch
- [ ] **AUD-084** [H] `ffi/sentinel.rs:554` - ffi_sentinel_witnessing_status casts session counts to u64 without checking for negative values; wrapping on signed negative

### Anchors / Verification

- [ ] **AUD-124** [H] `anchors/rfc3161.rs:176` - No TSA certificate chain validation; verify_timestamp_token never verifies CMS signature; forged tokens with correct hash pass
- [ ] **AUD-130** [H] `tpm/mod.rs:127` - generate_attestation_report returns report with empty signature; consumers trusting report get no authenticity guarantee
- [ ] **AUD-132** [H] `tpm/secure_enclave.rs:747` - verify_key_attestation uses non-constant-time != for attestation proof comparison; timing side-channel

### Steganography

- [ ] **AUD-148** [H] `steganography/embedding.rs:103` - compute_watermark_tag cycles through only 32 HMAC bytes; for zwc_count > 128, values repeat with period 128; zero additional entropy
- [ ] **AUD-151** [H] `steganography/extraction.rs:50` - verify() returns expected HMAC tag on both success and failure; attacker can learn correct tag, enabling forgery

### Other

- [ ] **AUD-107** [H] `wal/serialization.rs:128` - deserialize_entry sets length with double-counted signature offset; stored length field is wrong
- [ ] **AUD-111** [H] `mmr/proof.rs:274` - RangeProof::verify uses HashMap with non-deterministic iteration; valid proofs may fail verification non-deterministically
- [ ] **AUD-117** [H] `vdf/proof.rs:105` - VdfProof::encode truncates Duration::as_nanos() (u128) to u64; silently corrupts data for large durations
- [ ] **AUD-183** [H] `baseline/verification.rs:34` - gaussian_similarity returns 1.0 when count < 2; first session against fresh baseline auto-trusted (attacker gets 1.0 score)
- [ ] **AUD-186** [H] `collaboration.rs:123` - attestation_signature never verified; forged collaborator records accepted without detection

---

## MEDIUM-SEVERITY FINDINGS

### Crypto / Key Management

- [ ] **AUD-003** [M] `crypto.rs:191` - restrict_permissions on Windows uses spoofable %USERNAME% env var; should use GetUserNameW
- [ ] **AUD-007** [M] `crypto/mem.rs:89` - ProtectedBuf::new clones Vec before zeroizing; two copies of sensitive data exist simultaneously
- [ ] **AUD-008** [M] `crypto/mem.rs:84` - ProtectedBuf has no mlock protection; key material can be swapped to disk
- [ ] **AUD-009** [M] `crypto/mem.rs:84` - ProtectedBuf derives Clone without mlock; cloned copies are unprotected
- [ ] **AUD-011** [M] `crypto/anti_analysis.rs:55` - is_debugger_present uses hardcoded struct offset (P_FLAG_OFFSET=32); architecture-dependent
- [ ] **AUD-012** [M] `crypto/anti_analysis.rs:53` - KINFO_PROC_SIZE hardcoded to 648 bytes; may break on future macOS

### Checkpoint / Evidence

- [ ] **AUD-020** [M] `checkpoint/chain.rs:281` - `as u64` cast on checkpoints.len() skips try_from check used elsewhere
- [ ] **AUD-021** [M] `checkpoint/chain.rs:226` - Windows file locking is no-op; concurrent commits can corrupt chain
- [ ] **AUD-023** [M] `checkpoint/chain.rs:508` - verify_hash_chain() returns bool with no detail on which checkpoint failed
- [ ] **AUD-025** [M] `checkpoint/chain.rs:185` - commit_internal_locked has dead-code unwrap_or that could mask future bugs
- [ ] **AUD-028** [M] `checkpoint/types.rs:213` - compute_hash version selection based on optional field presence, not explicit version tag
- [ ] **AUD-031** [M] `evidence/builder/helpers.rs:184` - build_ephemeral_packet sets chain_valid=false and never corrects it
- [ ] **AUD-032** [M] `evidence/builder/helpers.rs:241` - build_ephemeral_packet skips generate_claims/limitations; empty vectors unlike normal path
- [ ] **AUD-034** [M] `evidence/builder/setters.rs:636` - with_dictation_events re-scores plausibility without idempotency check
- [ ] **AUD-037** [M] `evidence/types.rs:265` - InputDeviceInfo vendor_id/product_id `as u16` silently truncates

### Sentinel / IPC

- [ ] **AUD-040** [M] `sentinel/core.rs:575` - Race between running flag and event loop; is_running() can return false while loop processes events
- [ ] **AUD-041** [M] `sentinel/core.rs:747` - Inconsistent lock ordering (sessions then signing_key vs reverse elsewhere); deadlock risk
- [ ] **AUD-043** [M] `sentinel/core.rs:311` - Bridge thread debug logging writes to disk every 100th keystroke indefinitely; unbounded disk I/O
- [ ] **AUD-047** [M] `sentinel/helpers.rs:29` - Debug logging writes user document paths and app bundle IDs to world-readable /tmp file
- [ ] **AUD-048** [M] `sentinel/helpers.rs:520` - create_session_start_payload silently truncates hash_bytes if != 32 bytes instead of erroring
- [ ] **AUD-052** [M] `ipc/server.rs:238` - Rate limiter uses InternalError code; clients can't distinguish rate limiting from actual errors
- [ ] **AUD-053** [M] `ipc/server.rs:465` - Double timeout: connection timeout + idle timeout could kill active connections

### Forensics / Analysis

- [ ] **AUD-060** [M] `forensics/assessment.rs:304` - NaN possible if BIOLOGICAL_CADENCE_THRESHOLD were 0; currently safe but fragile
- [ ] **AUD-061** [M] `forensics/assessment.rs:310` - NaN possible if IKI_AUTOCORR_TRANSCRIPTIVE equals 1.0; currently safe but fragile
- [ ] **AUD-064** [M] `forensics/cross_modal.rs:183` - i64 sum of positive deltas can overflow for billions of events
- [ ] **AUD-067** [M] `forensics/forgery_cost.rs:273` - overall_difficulty takes ln() of costs; negative cost (no guard) would produce NaN
- [ ] **AUD-068** [M] `forensics/forgery_cost.rs:194` - cross_modal_cost = 0 with single check; forgery free with 1 cross-modal check
- [ ] **AUD-072** [M] `forensics/velocity.rs:70` - count_sessions_sorted assumes sorted input; unsorted timestamps silently undercount sessions
- [ ] **AUD-073** [M] `forensics/velocity.rs:119` - compute_session_stats can produce negative durations from wrong-order events
- [ ] **AUD-074** [M] `forensics/velocity.rs:136` - time_span_sec can underflow i64 for malformed timestamps
- [ ] **AUD-076** [M] `analysis/behavioral_fingerprint.rs:113` - Timestamp subtraction can underflow if not monotonically increasing
- [ ] **AUD-077** [M] `analysis/behavioral_fingerprint.rs:279` - detect_forgery interval threshold very sensitive for small sample sizes

### FFI / Platform

- [ ] **AUD-080** [M] `ffi/helpers.rs:62` - load_hmac_key partial read failure leaves raw Vec unzeroized
- [ ] **AUD-081** [M] `ffi/helpers.rs:89` - load_signing_key reads entire file without size check; unbounded allocation
- [ ] **AUD-085** [M] `ffi/sentinel.rs:143` - Poisoned mutex causes sentinel to be created but never stored; silent resource leak
- [ ] **AUD-086** [M] `ffi/sentinel.rs:655` - Relaxed ordering on LAST_INJECT_TS atomic; stale reads on ARM (Apple Silicon)
- [ ] **AUD-090** [M] `ffi/system.rs:32` - TOCTOU race on key_path.exists(); concurrent ffi_init calls could overwrite keys
- [ ] **AUD-095** [M] `platform/macos/mouse_capture.rs:138` - TapCallback closure captures mutable ref on spawned thread stack; dangling if run loop exits
- [ ] **AUD-096** [M] `platform/macos/mouse_capture.rs:87` - idle_only_mode logic inverted: captures during typing, not idle
- [ ] **AUD-098** [M] `platform/macos/keystroke.rs:523` - MacOSKeystrokeCapture::stop() has same double-free pattern as KeystrokeMonitor
- [ ] **AUD-099** [M] `platform/macos/keystroke.rs:230` - on_keystroke callback &mut without synchronization; reentrant call would be UB

### Store / WAL / MMR / VDF

- [ ] **AUD-103** [M] `store/events.rs:98` - SQL query uses format!() for LIMIT instead of parameterized query
- [ ] **AUD-105** [M] `wal/types.rs:147` - Entry::compute_hash casts i64 to u64; negative timestamps produce wrong hash
- [ ] **AUD-106** [M] `wal/serialization.rs:12` - serialize/deserialize cast i64<->u64 mangles negative timestamps
- [ ] **AUD-108** [M] `wal/operations.rs:454` - rotate_if_needed resets sequence to 0; breaks monotonic invariant
- [ ] **AUD-109** [M] `wal/operations.rs:548` - scan_to_end silently breaks on deserialization errors; hides corruption
- [ ] **AUD-112** [M] `mmr/proof.rs:465` - RangeProof deserialize doesn't validate leaf count matches range
- [ ] **AUD-115** [M] `mmr/mmr.rs:127` - get_leaf_index overflow for leaf_ordinal near u64::MAX/2
- [ ] **AUD-118** [M] `vdf/proof.rs:51` - VdfProof allows iterations=0; trivially verifiable proof with no work
- [ ] **AUD-120** [M] `vdf/params.rs:222` - BatchVerifier spawns unbounded OS threads before semaphore check
- [ ] **AUD-122** [M] `vdf/aggregation.rs:266` - MerkleVdfBuilder casts leaf count to u32; wraps silently above u32::MAX

### Anchors / TPM

- [ ] **AUD-122b** [M] `anchors/http.rs:37` - JSON-RPC id hardcoded to 1; concurrent calls could mismatch through proxy
- [ ] **AUD-125** [M] `anchors/rfc3161.rs:145` - DER length encoding uses 0x82 for all >= 128 bytes; malformed for 128-255
- [ ] **AUD-126** [M] `anchors/rfc3161.rs:423` - extract_nonce assumes exactly 8 bytes; compliant TSAs with different lengths fail
- [ ] **AUD-134** [M] `tpm/secure_enclave.rs:650` - clock_info returns safe:false but capabilities claims secure_clock:true; contradictory
- [ ] **AUD-135** [M] `tpm/secure_enclave.rs:563` - Counter increment before signing; failed sign leaves gap in sequence
- [ ] **AUD-136** [M] `tpm/secure_enclave.rs:450` - save_counter sets permissions after rename; brief world-readable window
- [ ] **AUD-137** [M] `tpm/secure_enclave.rs:376` - Counter HMAC key derived from public key; anyone with pubkey can forge counter file

### Config / Steganography / SCITT

- [ ] **AUD-140** [M] `config/loading.rs:14` - TOCTOU race between exists() and read_to_string() on config files
- [ ] **AUD-141** [M] `config/loading.rs:28` - Legacy config read errors silently swallowed; corruption indistinguishable from missing
- [ ] **AUD-144** [M] `config/types.rs:211` - VdfConfig allows min/max iterations of 0; can cause division-by-zero downstream
- [ ] **AUD-149** [M] `steganography/embedding.rs:128` - compute_positions uses doc_hash (public) as HMAC key; positions deterministic from public data
- [ ] **AUD-152** [M] `steganography/extraction.rs:82` - verify_binding leaks stored_tag on failure; enables tag extraction

### Jitter / Calibration

- [ ] **AUD-162** [M] `cpoe_jitter_bridge/session.rs:336` - Loaded session gets fresh PhysSession; jitter evidence chain lost on load
- [ ] **AUD-163** [M] `cpoe_jitter_bridge/session.rs:59` - key_material not zeroized after derive_session_secret
- [ ] **AUD-168** [M] `cpoe_jitter_bridge/helpers.rs:10` - duration.as_millis() u128 cast to i64 truncates; subsequent < 0 guard is dead code
- [ ] **AUD-169** [M] `calibration/transport.rs:74` - std_dev f64 cast to u64 truncates fractional part; 0.9 becomes 0
- [ ] **AUD-170** [M] `calibration/transport.rs:17` - No validation min_samples > 0; allows potential division by zero

### Declaration / Baseline / Collaboration

- [ ] **AUD-180** [M] `declaration/builder.rs:142` - NaN percentage passes validation; NaN < 0.0 is false
- [ ] **AUD-184** [M] `baseline/verification.rs:46` - No NaN/Inf guard on session inputs; NaN propagates through scoring
- [ ] **AUD-187** [M] `collaboration.rs:236` - validate_coverage silently ignores ranges where start > end
- [ ] **AUD-188** [M] `collaboration.rs:237` - validate_coverage silently clamps out-of-range indices; no warning

---

## LOW-SEVERITY FINDINGS

### Crypto
- [ ] **AUD-001** [L] `crypto.rs:119` - derive_hmac_key uses SHA-256 instead of HKDF for key derivation
- [ ] **AUD-002** [L] `crypto.rs:129` - derive_pop_prk does not zeroize local ikm Vec
- [ ] **AUD-004** [L] `crypto.rs:214` - restrict_permissions is no-op on non-unix/non-windows; silent
- [ ] **AUD-006** [L] Note: ProtectedKey Drop order (zeroize then munlock) is actually safer but lacks compiler fence
- [ ] **AUD-010** [L] `crypto/mem.rs:62` - ProtectedKey Deref exposes raw bytes; easy to accidentally copy
- [ ] **AUD-013** [L] `crypto/anti_analysis.rs:20` - harden_process is no-op on Linux/Windows
- [ ] **AUD-014** [L] `crypto/anti_analysis.rs:72` - is_debugger_present returns false on sysctl failure; evadable
- [ ] **AUD-016** [M->L] `keyhierarchy/identity.rs:29` - signing_key not explicitly zeroized on non-error path
- [ ] **AUD-017** [L] `keyhierarchy/identity.rs:16` - PUF challenge is static SHA-256 of fixed string

### Checkpoint / Evidence
- [ ] **AUD-022** [L] `checkpoint/chain.rs:815` - tmp file not cleaned up on fsync/rename failure
- [ ] **AUD-024** [L] `checkpoint/chain.rs:116` - document_id 64-bit collision probability non-negligible at scale
- [ ] **AUD-029** [L] `checkpoint/types.rs:84` - JitterBinding.session_id unbounded String; no length validation
- [ ] **AUD-033** [L] `evidence/builder/setters.rs:523` - with_jitter_from_keystroke uses filtered count for entropy estimate
- [ ] **AUD-035** [L] `evidence/builder/setters.rs:331` - with_key_hierarchy uses enumerate index instead of actual ratchet index
- [ ] **AUD-038** [L] `evidence/types.rs:383` - DictationEvent no validation end_ns >= start_ns
- [ ] **AUD-039** [L] `evidence/types.rs:360` - ForensicMetrics no NaN/Inf guards on deserialization
- [ ] **AUD-040b** [L] `evidence/types.rs:73` - Packet.version no validation rejects unknown versions
- [ ] **AUD-041** [L] `evidence/tests.rs:16` - temp_document_path leaks files on test panic

### Sentinel / IPC
- [ ] **AUD-042** [L] `sentinel/core.rs:311` - Debug logging to /tmp in production code
- [ ] **AUD-044** [L] `sentinel/core.rs:900` - Drop impl only aborts event loop; doesn't stop captures or join threads
- [ ] **AUD-045** [L] `sentinel/focus.rs:42` - Channel capacity 100 hardcoded; events silently dropped under heavy switching
- [ ] **AUD-046** [L] `sentinel/focus.rs:189` - focus_events/change_events via take(); second call permanently breaks channel
- [ ] **AUD-049** [L] `sentinel/helpers.rs:376` - Confusing control flow: sessions_map dropped mid-match
- [ ] **AUD-050** [L] `sentinel/helpers.rs:526` - timestamp cast as_nanos as i64 wraps around year 2262
- [ ] **AUD-051** [L] `sentinel/helpers.rs:555` - validate_path TOCTOU between exists() and canonicalize()
- [ ] **AUD-054** [L] `ipc/server.rs:396` - run_with_handler never cleans up socket file; stale socket on crash
- [ ] **AUD-055** [L] `ipc/server.rs:477` - Windows named pipe no security descriptor; brief unauthorized connection
- [ ] **AUD-056** [L] `ipc/server.rs:366` - Deserialization error leaks internal details to client
- [ ] **AUD-057** [L] `ipc/secure_channel.rs:51` - cipher Clone doesn't zeroize original; key in two heap locations
- [ ] **AUD-058** [L] `ipc/secure_channel.rs:82` - Send error types indistinguishable
- [ ] **AUD-059** [L] `ipc/secure_channel.rs:143` - Size check after decryption; large ciphertext fully allocated first

### Forensics / Analysis
- [ ] **AUD-062** [L] `forensics/assessment.rs:295` - No NaN/Inf guard on cadence inputs
- [ ] **AUD-063** [L] `forensics/assessment.rs:300` - anomaly_count as f64 unbounded multiplication
- [ ] **AUD-065** [L] `forensics/cross_modal.rs:186` - Fallback to document_length when net_additions <= 0
- [ ] **AUD-066** [L] `forensics/cross_modal.rs:228` - EVENTS_PER_CHECKPOINT_MAX of 200 may be too permissive
- [ ] **AUD-069** [L] `forensics/forgery_cost.rs:302` - estimated_forge_time_sec returns 0 when no components present
- [ ] **AUD-070** [L] `forensics/forgery_cost.rs:287` - NaN cost compares as Equal in weakest_link
- [ ] **AUD-071** [L] `forensics/forgery_cost.rs:169` - Hardware attestation absent cost=1.0 underestimates extraction
- [ ] **AUD-075** [L] `forensics/velocity.rs:34` - saturating_sub on negative timestamps produces unexpected values
- [ ] **AUD-078** [L] `analysis/behavioral_fingerprint.rs:142` - Subtraction without sort can misclassify burst boundaries
- [ ] **AUD-079** [L] `analysis/behavioral_fingerprint.rs:261` - skewness=0 when std=0; design quirk

### FFI / Platform
- [ ] **AUD-082** [L] `ffi/helpers.rs:148` - HMAC mismatch detection case-sensitive string matching
- [ ] **AUD-083** [L] `ffi/helpers.rs:259` - compute_streak_stats negative timestamps produce incorrect days
- [ ] **AUD-087** [L] `ffi/sentinel.rs:365` - total_focus_ms sum of i64 can overflow on extreme uptime
- [ ] **AUD-088** [L] `ffi/sentinel.rs:711` - ffi_sentinel_notify_paste accepts negative char_count
- [ ] **AUD-091** [L] `ffi/system.rs:281` - ffi_list_tracked_files casts signed keystroke_count to u64
- [ ] **AUD-092** [L] `ffi/system.rs:383` - ffi_get_activity_data truncates ns to day granularity
- [ ] **AUD-100** [L] `platform/macos/keystroke.rs:56` - EventTapResources blanket Send+Sync could mask issues
- [ ] **AUD-101** [L] `platform/macos/keystroke.rs:23` - debug_write_keystroke does file I/O in CGEventTap callback hot path

### Store / WAL / MMR / VDF
- [ ] **AUD-102** [L] `store/integrity.rs:69` - Migrations not in transaction; concurrent opens race
- [ ] **AUD-104** [L] `store/events.rs:108` - Duplicated 80-line row-mapping closure; divergence risk
- [ ] **AUD-110** [L] `wal/operations.rs:535` - scan_to_end doesn't verify sequence matches expected
- [ ] **AUD-113** [L] `mmr/proof.rs:118` - Proof deserialization accepts trailing bytes without error
- [ ] **AUD-114** [L] `mmr/proof.rs:148` - Deserialization uses attacker-controlled u16 for allocation (up to ~2MB)
- [ ] **AUD-116** [L] `mmr/mmr.rs:34` - Mmr::append no rollback on internal node append failure
- [ ] **AUD-119** [L] `vdf/proof.rs:81` - verify_with_progress divides by iterations; NaN when iterations=0
- [ ] **AUD-121** [L] `vdf/params.rs:61` - calibrate() elapsed=0 produces infinity
- [ ] **AUD-123** [L] `vdf/aggregation.rs:257` - total_iterations unchecked addition overflow
- [ ] **AUD-124b** [L] `vdf/aggregation.rs:305` - Odd-node Merkle tree promotion diverges from RFC 6962

### Anchors / TPM
- [ ] **AUD-121b** [L] `anchors/http.rs:50` - HTTP response status not checked before JSON parsing
- [ ] **AUD-123b** [L] `anchors/verification.rs:8` - verify_proof_format Result<bool> misleading; can only return Ok(true) or Err
- [ ] **AUD-127** [L] `anchors/rfc3161.rs:118` - AlgorithmIdentifier length calc fragile; works by coincidence
- [ ] **AUD-128** [L] `anchors/rfc3161.rs:29` - Variable shadowing between response bindings
- [ ] **AUD-129** [L] `anchors/rfc3161.rs:9` - DEFAULT_TSA_URLS includes unreliable freetsa.org first
- [ ] **AUD-131** [L] `tpm/mod.rs:24` - DEFAULT_QUOTE_PCRS missing PCR 1 and PCR 2
- [ ] **AUD-138** [L] `tpm/secure_enclave.rs:878` - String literal for kSecAttrKeyClass instead of symbol import
- [ ] **AUD-139** [L] `tpm/secure_enclave.rs:998` - hardware_uuid() parses ioreg with fragile string searching
- [ ] **AUD-133** [H->L] `tpm/secure_enclave.rs:737` - verify_key_attestation uses local hardware_info; fails silently on different device

### Config / Steganography / SCITT
- [ ] **AUD-142** [L] `config/loading.rs:48` - watch_dirs from legacy config accepted without path validation
- [ ] **AUD-143** [L] `config/loading.rs:58` - validate() not called after merging legacy config values
- [ ] **AUD-145** [L] `config/types.rs:48` - WritersProofConfig.base_url not validated; arbitrary URL possible
- [ ] **AUD-146** [L] `config/types.rs:308` - is_app_allowed uses case-sensitive match; bypass possible
- [ ] **AUD-147** [L] `config/types.rs:113` - No upper bound on retention_days
- [ ] **AUD-150** [L] `steganography/embedding.rs:37` - No validation zwc_count <= word_boundaries before positions
- [ ] **AUD-153** [L] `steganography/extraction.rs:27` - extract_tag no upper bound on returned length
- [ ] **AUD-154** [L] `rats/scitt.rs:47` - Silently discards fmt::Write errors
- [ ] **AUD-155** [L] `rats/scitt.rs:52` - No validation evidence_cbor is valid COSE_Sign1 before wrapping
- [ ] **AUD-156** [L] `rats/scitt.rs:63` - beacon_to_receipt_format doesn't validate field contents

### Jitter / Calibration
- [ ] **AUD-160** [L] `cpoe_jitter_bridge/zone_engine.rs:87` - total_transitions u64 overflow without saturation
- [ ] **AUD-161** [L] `cpoe_jitter_bridge/zone_engine.rs:88` - Tautological guard; always true after increment
- [ ] **AUD-164** [L] `cpoe_jitter_bridge/session.rs:308` - Session save not atomic; crash produces corrupt JSON
- [ ] **AUD-165** [L] `cpoe_jitter_bridge/session.rs:281` - samples.len() cast to i32 overflows for >2^31 samples
- [ ] **AUD-166** [L] `cpoe_jitter_bridge/session.rs:284` - unique_doc_hashes cast to i32 overflow
- [ ] **AUD-167** [L] `cpoe_jitter_bridge/session.rs:274` - HashSet built every call; O(n) with no caching
- [ ] **AUD-171** [L] `calibration/transport.rs:62` - Population variance used instead of sample variance

### Declaration / Baseline / Collaboration
- [ ] **AUD-181** [L] `declaration/builder.rs:16` - Builder err field never populated; dead code
- [ ] **AUD-182** [L] `declaration/builder.rs:171` - ai_assisted_declaration creates builder with no defaults
- [ ] **AUD-185** [L] `baseline/streaming.rs:23` - min/max initialized to sentinel values; serializes if no samples
- [ ] **AUD-189** [L] `collaboration.rs:303` - TimeInterval no validation end >= start
- [ ] **AUD-190** [L] `collaboration.rs:104` - ContributionClaim.extent no 0-1 range validation

---

## SYSTEMIC PATTERNS

| Pattern | Files Affected | Recommended Fix |
|---------|---------------|-----------------|
| NaN/Inf unguarded in f64 math | assessment, cross_modal, forgery_cost, velocity, behavioral_fingerprint, baseline, declaration | Add NaN/Inf guards at function entry or use `f64::is_finite()` checks |
| Negative timestamp as u64 casts | wal, checkpoint, sentinel, jitter_bridge | Use `TryFrom<i64>` or validate non-negative before cast |
| Key material not zeroized | identity, mem, jitter_session, ffi/helpers | Wrap all key material in `Zeroizing<>` |
| Debug logging to /tmp | sentinel/core, sentinel/helpers, keystroke | Gate behind `#[cfg(debug_assertions)]` or feature flag |
| TOCTOU on file operations | config/loading, ffi/system, sentinel/helpers | Use atomic file operations or lock files |
| Unsorted input assumptions | velocity, behavioral_fingerprint | Sort at function entry or validate monotonicity |
