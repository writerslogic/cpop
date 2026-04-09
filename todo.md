# CPOP Project Audit -- Consolidated Findings

<!-- suggest | Updated: 2026-04-09 | Domain: code | Languages: rust | Files: 27 delta + 677 prior | Issues: 340 -->

**Updated**: 2026-04-09 (session 7 -- delta scan of 27 changed files since session 6; 4 batches, 1 wave)
**Previous audit**: 2026-04-08 session 6 (42 files medium sweep); 2026-04-07 session 4 (677 files)
**Baseline**: 1097 pass, 0 fail, 1 ignored (witnessd --lib)

## Summary
| Severity | Open | Fixed (this+prior) | Skipped/FP (this+prior) |
|----------|------|--------------------|--------------------------|
| CRITICAL | 0    | 25                 | 17+                      |
| HIGH     | 10   | 162                | 32+                      |
| MEDIUM   | 58   | 247                | 22                       |
| SYSTEMIC | 2    | 8                  | 1                        |

---

## Compound Risk

- [x] **CLU-001** `timestamp_anchor_bypass`, CRITICAL, components: C-001(fixed), C-002(n/a), C-003(fp) -- RESOLVED 2026-04-07
  <!-- compound_impact: C-001 fixed (CMS sig verified); C-002 not applicable (Bitcoin/OTS out of scope); C-003 false positive (decode_eat_cwt only called in tests, never in production IPC path) -->

- [-] **CLU-006** `evidence_integrity_triple_bypass`, CRITICAL, components: C-015, C-016, C-017 -- FALSE POSITIVE 2026-04-07
  <!-- compound_impact: C-015 FP (sign() already uses ? operator); C-016 FP (verify() checks signature field before proceeding); C-017 FP (HMAC verified per-row before pushing to output via verify_event_row_hmac) -->

- [x] **CLU-007** `checkpoint_rollback_surface`, CRITICAL, components: C-019(-fp), C-020(-fp), H-007(fixed) -- RESOLVED 2026-04-07
  <!-- compound_impact: C-019 FP (at() is an index accessor, not a sequential read API; monotonicity is enforced at commit layer); C-020 FP (verify() receives root from caller, not self-validated peaks); H-007 fixed (MMR root anchored in signed checkpoint; cross-checkpoint proof verification in verify_detailed) -->

- [x] **CLU-002** `identity_trust_chain_failure`, CRITICAL, components: C-011(-fixed), C-012(fixed), C-013(-fixed) -- RESOLVED 2026-04-07
  <!-- compound_impact: C-011 XOR recovery rejected; C-013 no plaintext key fallback; C-012 DID SSRF fixed (hostname blocklist+IP rejection) + H-017 false positive (didwebvh_rs enforces log sig chain by construction) -->

- [x] **CLU-003** `evidence_integrity_false_signal`, CRITICAL, components: C-005(-fp), C-006(fixed), C-008(fixed), C-009(fixed) -- RESOLVED 2026-04-06
  <!-- compound_impact: C-006 zero-edit returns Inconsistent; C-008 CBOR errors propagate via Result; C-009 broken chain returns Error; C-005 architectural (external trust anchor) -->

- [x] **CLU-004** `report_exposure_cluster`, HIGH, components: C-010(-fp), C-014(fixed) -- RESOLVED 2026-04-06
  <!-- compound_impact: C-014 HTTP exception removed unconditionally; C-010 false positive (HTML sections use pre-escaped data) -->

- [x] **CLU-005** `ffi_bypass_cluster`, HIGH, components: H-006, H-013, H-025, SYS-007 -- FIXED 2026-04-06
  <!-- compound_impact: All components fixed: H-006 raised unverified FFI confidence threshold to 0.5; H-013/H-025 both FFI sites use validated_path; SYS-007 evidence_export.rs TOCTOU fixed -->

## Systemic Issues

- [x] **SYS-001** `nan_inf_unguarded`, 8 files (new instances in re-audit), CRITICAL -- FIXED 2026-04-06
  <!-- pid:nan_inf_unguarded | first:2026-04-06 -->
  Fixed: analysis.rs:173 (H-005), analysis.rs:549, transcription/audio.rs:145, physics/biological.rs:39. tpm/linux.rs and ipc/async_client.rs had no NaN instances. cpop_jitter_bridge/session.rs (H-019) confirmed false positive.

- [-] **SYS-002** `silent_error_swallow`, 15 files (new instances), HIGH -- TRIAGED 2026-04-06
  <!-- pid:silent_error | first:2026-04-06 -->
  rats/eat.rs: C-003 architectural (COSE verification). vc.rs:245: already returns error via sign_error capture. keyhierarchy/recovery.rs: fixed in C-011 (XOR path removed). ffi/sentinel_inject.rs: intentional design (caller doesn't need per-keystroke errors). trust_policy, declaration: no actionable silent swallows found. Remaining in research/collaboration are benign log::warn fallbacks.

- [x] **SYS-003** `business_logic_in_ffi`, 8 files, HIGH -- FIXED 2026-04-07
  <!-- pid:logic_in_boundary | first:2026-04-06 | updated:2026-04-07 -->
  Files (session 3): `ffi/sentinel_inject.rs:102`, `ffi/sentinel_witnessing.rs:51`, `ffi/sentinel_witnessing.rs` (chain lookup), `ffi/evidence_export.rs`, `ffi/beacon.rs`, `ffi/attestation.rs`.
  New instances (session 4): `ffi/ephemeral.rs:565` (C-027 -- WAR proof signing), `ffi/report.rs:198` (C-028 -- full forensic analysis per call).
  Fix: Move to crate modules; FFI layer should only marshal types and forward to engine.

- [x] **SYS-008** `debug_output_regression`, 1 file, CRITICAL -- FIXED 2026-04-07
  <!-- pid:no_structured_logging | first:2026-04-07 -->
  Regression of SYS-004 (fixed 2026-04-02). Instance: `ffi/system.rs:228-255` -- removed `#[cfg(debug_assertions)]` block writing to `/tmp/cpop_list_debug.txt`; replaced with `log::debug!()` calls. See C-025.

- [-] **SYS-004** `hmac_not_verified_on_read`, 3 files, HIGH -- TRIAGED 2026-04-07
  <!-- pid:missing_validation | first:2026-04-06 -->
  store/integrity.rs: FALSE POSITIVE -- get_events_for_file/get_all_events_grouped/export_all_events_for_identity all call verify_event_row_hmac before returning events; per-row HMAC IS verified pre-output.
  sealed_chain.rs:95: FALSE POSITIVE -- AES-GCM AEAD authenticates full payload via auth tag; the "AAD partial" claim misunderstands AEAD; ciphertext is authenticated by the tag, not just the AAD.
  cpop_jitter_bridge/session.rs: ARCHITECTURAL -- save() has no key parameter; adding file HMAC requires API refactoring across all callers. Deferred.

- [x] **SYS-005** `toctou_file_access`, 5 files, HIGH -- FIXED 2026-04-06
  <!-- pid:toctou | first:2026-04-06 -->
  Fixed: core_session.rs (H-002/H-004), helpers.rs (H-010), fingerprint/storage.rs (C-013), engine/watcher.rs (symlink_metadata check). identity/did_webvh.rs: deferred with C-012/H-017 (architectural DID validation).

- [-] **SYS-006** `magic_constants_scoring`, 12 files, MEDIUM -- FALSE POSITIVE 2026-04-06
  <!-- pid:magic_value | first:2026-04-06 -->
  Verified: forensics/analysis.rs, war/appraisal.rs, rats/eat.rs all use named constants. continuation.rs and collaboration.rs have no bare float literals. No actionable instances found in remaining files.

- [x] **SYS-007** `ffi_path_validation_discarded`, 3 files, HIGH -- FIXED 2026-04-06
  <!-- pid:path_traversal | first:2026-04-06 -->
  Fixed: sentinel_witnessing.rs start_witnessing and stop_witnessing both use &validated_path (H-013/H-025). evidence_export.rs:258 TOCTOU fixed in M-038 (read-once with hash verification).

- [ ] **SYS-009** `nan_in_biometric_analysis`, 3+ files, HIGH
  <!-- pid:nan_inf_unguarded | first:2026-04-08 -->
  Files: `fingerprint/activity_analysis.rs:52` (skewness/kurtosis unguarded), `analysis/labyrinth.rs:392` (sort with NaN=Equal), `analysis/lyapunov.rs:193` (regression returns 0.0 on degenerate input)
  Fix: Filter NaN before statistical operations; return Option from degenerate paths; add is_finite() guards after stats::skewness/kurtosis calls

- [ ] **SYS-010** `toctou_in_file_operations`, 2 files, HIGH
  <!-- pid:toctou | first:2026-04-08 -->
  Files: `engine/watcher.rs:78` (symlink_metadata then separate hash_file_with_size), `engine/watcher.rs:105` (lock released before filesystem existence check)
  Fix: Use file-descriptor-based hashing after open; keep hash_map lock through filesystem check

---

## Critical

- [x] **C-001** `[security]` `anchors/rfc3161.rs:197`: RFC3161 TSA response CMS signature not verified -- FIXED 2026-04-07
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Fix: Implemented CMS RSA-PKCS1v15-SHA256 signature verification via rsa crate; verify_cms_signature() navigates SignedData, extracts TSA certificate SPKI, re-encodes signedAttrs as SET, verifies signature. Returns Unavailable for non-RSA/SHA256 algorithms.

- [x] **C-002** `[security]` `anchors/ots.rs:430`: Bitcoin block header cross-check -- NOT APPLICABLE 2026-04-07
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Bitcoin/OTS integration removed from scope; OTS anchor path will not be used.

- [-] **C-003** `[security]` `rats/eat.rs:75`: decode_eat_cwt() parses EAT payload without COSE_Sign1 verification -- FALSE POSITIVE (production) 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  decode_eat_cwt() is only called in tests (rats/mod.rs:88); it is never reached from the production IPC path. Docstring explicitly documents this as inspection/debug use. Architectural concern (IPC boundary) tracked separately in H-021.

- [x] **C-004** `[security]` `war/profiles/vc.rs:31`: W3C Verifiable Credential has no validUntil/expirationDate field
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Impact: Issued VCs never expire; revoked or compromised credentials remain valid indefinitely | Fix: Add expirationDate (VC 1.x) or validUntil (VC 2.0) field; document max VC lifetime constant | Effort: small

- [-] **C-005** `[security]` `evidence/packet.rs:29`: Self-signed verification used as default; no external trust anchor required
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Impact: Attacker substitutes signing key in packet; verification passes using their own key as anchor | Fix: Require external trusted key parameter for verification; reject self-verification by default | Effort: medium

- [x] **C-006** `[security]` `forensics/cross_modal.rs:190`: Zero-edit document receives 0.3 partial consistency score instead of Inconsistent verdict
  <!-- pid:business_logic | verified:true | first:2026-04-06 -->
  Impact: AI-generated document with no recorded keystrokes passes cross-modal check; bypasses behavioral detection | Fix: Return CrossModalVerdict::Inconsistent when total_edits == 0; no partial score on missing data | Effort: small

- [-] **C-007** `[security]` `ipc/secure_channel.rs:65`: Cipher cloned without zeroization; unsafe pointer arithmetic in zeroize_cipher at line 26 -- FALSE POSITIVE 2026-04-07
  <!-- pid:key_zeroize_error_path | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  Clone goes to SecureSender; original goes to SecureReceiver. Both have Drop impls that call zeroize_cipher(). zeroize_cipher() uses write_volatile per byte + SeqCst fence, which prevents compiler elimination (see H-015 for full analysis).

- [x] **C-008** `[error_handling]` `evidence/wire_conversion.rs:249`: CBOR encode failure produces all-zero jitter_seal vector silently
  <!-- pid:silent_error | verified:true | first:2026-04-06 -->
  Impact: Evidence packet ships with fake all-zero seal on encode error; caller cannot detect failure; all-zero seal passes zero-check | Fix: Propagate error via Result; never produce all-zero seal on failure path | Effort: small

- [x] **C-009** `[security]` `checkpoint/chain.rs` (commit_entangled): Uses [0u8;32] stub when previous VDF output is missing
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Impact: Entangled mode checkpoint chain can be broken at any link by substituting all-zero VDF output; no chain integrity | Fix: Return Error if previous VDF output required but missing; reject [0u8;32] as invalid VDF | Effort: small

- [-] **C-010** `[security]` `report/html/sections.rs:69`: HTML report templates interpolate user-controlled strings (document paths, author names) without escaping
  <!-- pid:command_injection | verified:true | first:2026-04-06 -->
  Impact: XSS via document path containing `<script>`; attacker-controlled file name executes arbitrary script in any viewer | Fix: html_escape() all user-controlled fields before interpolation; use a safe templating API | Effort: small

- [x] **C-011** `[security]` `keyhierarchy/recovery.rs:68`: Legacy v1 recovery uses unauthenticated XOR cipher with static key
  <!-- pid:hardcoded_secret | verified:true | first:2026-04-06 -->
  Impact: V1 recovery blobs can be decrypted with the known static XOR key; no authentication on decryption | Fix: Reject legacy v1 recovery format with descriptive error; require migration to v2 AEAD format | Effort: medium

- [x] **C-012** `[security]` `identity/did_webvh.rs:402,417`: SSRF via unvalidated DID URI -- FIXED 2026-04-07
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Fix: Added validate_did_host() rejecting IP addresses and private/reserved hostnames (localhost, .local, .internal, .corp, .lan, etc.) before any HTTP fetch in resolve_and_verify_key(); 4 tests added.

- [x] **C-013** `[security]` `fingerprint/storage.rs:363`: Biometric encryption key written to disk in plaintext as fallback when keychain unavailable
  <!-- pid:hardcoded_secret | verified:true | first:2026-04-06 -->
  Impact: If keychain fails, biometric key stored unprotected in filesystem; attacker with read access recovers key | Fix: Fail hard if keychain unavailable; never write key material to plaintext files; provide migration UX | Effort: medium

- [x] **C-014** `[security]` `writersproof/client.rs:38`: HTTP (non-TLS) connections permitted in debug builds
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Impact: Debug build in CI or staging allows cleartext API calls; credentials and evidence packets transmitted in the clear | Fix: Unconditionally require HTTPS; remove debug HTTP exception entirely | Effort: small

- [-] **C-015** `[security]` `evidence/packet.rs:432`: `sign()` swallows `signing_payload()` error; returns `Ok(())` with packet unsigned -- FALSE POSITIVE 2026-04-07
  <!-- pid:silent_error | verified:false | first:2026-04-07 | cluster:CLU-006 -->
  sign() already uses the `?` operator to propagate signing_payload() errors; no silent swallow present.

- [-] **C-016** `[security]` `evidence/packet.rs:645`: No pre-flight signature presence check in `verify()`; verification proceeds on unsigned packet -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 | cluster:CLU-006 -->
  verify() checks signature field presence before proceeding; absent signature returns Err as expected.

- [-] **C-017** `[security]` `store/events.rs:323,396`: Per-entry HMAC verified AFTER full event deserialization in `get_all_events_grouped` and `export_all_events_for_identity` -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 | cluster:CLU-006 -->
  row_to_event_with_hmac + verify_event_row_hmac call pattern verifies HMAC per-row before the event is pushed to the output buffer; data does not reach the caller until HMAC passes.

- [x] **C-018** `[security]` `war/verification.rs:23`: Non-constant-time length check before `ct_eq()` call; timing side-channel reveals key length -- FIXED 2026-04-07
  <!-- pid:timing_side_channel | verified:true | first:2026-04-07 -->
  Removed length pre-check; now calls `bool::from(trusted.ct_eq(&self.seal.public_key))` directly. subtle::ConstantTimeEq handles different-length slices in constant time.

- [-] **C-019** `[security]` `checkpoint/chain.rs:368`: `at()` accepts arbitrary ordinal without monotonicity enforcement -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 | cluster:CLU-007 -->
  at() is an index accessor (read-only by ordinal); monotonicity is enforced at the commit layer, not the retrieval layer. Retrieval by arbitrary ordinal is intentional API behavior.

- [-] **C-020** `[security]` `mmr/proof.rs:59-72`: `InclusionProof::verify()` does not validate that peaks match current MMR state -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 | cluster:CLU-007 -->
  verify() receives the expected root from the caller as an explicit parameter; it does not self-validate peaks. The caller is responsible for supplying the trusted root. Design is correct.

- [x] **C-021** `[concurrency]` `sentinel/core.rs:839`: Lock ordering violation -- acquires `sessions` write lock before `signing_key` read lock; violates AUD-041 invariant -- FIXED 2026-04-07
  <!-- pid:lock_ordering | verified:true | first:2026-04-07 -->
  Restructured to read signing_key under read lock first (guard dropped), then acquire sessions write lock. AUD-041 ordering (signing_key < sessions) restored.

- [-] **C-022** `[security]` `forensics/cross_modal.rs:234`: Division by `checkpoint_count` without zero-check -- FALSE POSITIVE 2026-04-07
  <!-- pid:nan_inf_unguarded | verified:false | first:2026-04-07 -->
  Zero-check guard already present at lines 225-232 before the division at line 234; returns CrossModalVerdict::Inconsistent when checkpoint_count == 0.

- [-] **C-023** `[security]` `forensics/writing_mode.rs:236`: Division by `TRANSCRIPTIVE_THRESHOLD` without epsilon guard -- FALSE POSITIVE 2026-04-07
  <!-- pid:nan_inf_unguarded | verified:false | first:2026-04-07 -->
  TRANSCRIPTIVE_THRESHOLD is a compile-time constant 0.35; it cannot be zero or misconfigured at runtime. No runtime division-by-zero risk.

- [-] **C-024** `[security]` `anchors/rfc3161.rs:31`: No timeout on TSA HTTP POST -- FALSE POSITIVE 2026-04-07
  <!-- pid:no_timeout | verified:false | first:2026-04-07 -->
  build_http_client(None) already applies DEFAULT_TIMEOUT_SECS; timeout is set on the shared reqwest Client before the POST is executed.

- [x] **C-025** `[security]` `ffi/system.rs:228-255`: `#[cfg(debug_assertions)]` block writes list output to `/tmp/cpop_list_debug.txt`; SYS-004 regression -- FIXED 2026-04-07
  <!-- pid:no_structured_logging | verified:true | first:2026-04-07 | systemic:SYS-008 -->
  Removed entire cfg(debug_assertions) block; replaced with log::debug!() calls for sentinel session and store result counts.

- [x] **C-026** `[security]` `authorproof-protocol/src/rfc/jitter_binding.rs:443`: `attractor_points` inner vector length not validated against `embedding_dimension`; memory exhaustion on malformed input -- FIXED 2026-04-07
  <!-- pid:no_backpressure | verified:true | first:2026-04-07 -->
  Added MAX_ATTRACTOR_POINTS (10000) cap and per-row length validation against embedding_dimension; ValidationFinding::error on any violation.

- [x] **C-027** `[architecture]` `ffi/ephemeral.rs:565`: `build_war_block()` signing logic moved out of FFI layer -- FIXED 2026-04-07
  <!-- pid:logic_in_boundary | verified:true | first:2026-04-07 | systemic:SYS-003 -->
  Added `war::build_signed_ephemeral_block()` in war/mod.rs; FFI layer retains key loading + snapshot marshaling, delegates packet assembly + signing + encoding to the engine function.

- [x] **C-028** `[architecture]` `ffi/report.rs:198-227`: Full forensic analysis re-executed on every Swift call -- FIXED 2026-04-07
  <!-- pid:logic_in_boundary | verified:true | first:2026-04-07 | systemic:SYS-003 -->
  Added process-level `ForensicCacheEntry` DashMap in ffi/report.rs keyed by (path, event_count); cache hit skips both evaluate_authorship and run_full_forensics; cache capped at 10 entries with clear-on-overflow.

- [x] **C-029** `[security]` `apps/cpop_macos/cpop/SubscriptionService.swift:176`: Storage upgrade purchase proceeds without `appAccountToken` when `userId` is nil -- FIXED 2026-04-07
  <!-- pid:missing_validation | verified:true | first:2026-04-07 -->
  Added guard requiring userId + valid UUID before purchase; always passes appAccountToken(accountUUID) so Apple's S2S notification can identify the account.

---

## High

- [x] **H-001** `[concurrency]` `sentinel/core.rs:614`: Race condition in keystroke attribution -- read lock released then separate write lock acquired; session can change in window
  <!-- pid:data_race | verified:true | first:2026-04-06 -->
  Impact: Keystroke attributed to wrong session under concurrent focus change at 100+ WPM | Fix: Acquire write lock for full attribution sequence without releasing between read and update | Effort: medium

- [x] **H-002** `[security]` `sentinel/core_session.rs:208`: Relative path accepted for session creation; directory traversal via crafted app title
  <!-- pid:path_traversal | verified:true | first:2026-04-06 -->
  Impact: title:// sessions with ../ components bypass session isolation; evidence file written to arbitrary location | Fix: Reject relative paths; require absolute path or title:// with no traversal components | Effort: small

- [-] **H-003** `[security]` `sealed_chain.rs:90,95`: AES-GCM nonce does not include document counter; nonce reuse possible across chains sharing same document_id -- FALSE POSITIVE 2026-04-07
  <!-- pid:data_race | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  Nonce is 96-bit random (rand::rng()); birthday collision probability is negligible at any practical write frequency. Key is HKDF-derived per document_id so different documents use different keys entirely. 96-bit random nonce is NIST SP 800-38D recommended approach when fewer than 2^32 encryptions are expected.

- [x] **H-004** `[security]` `sentinel/core_session.rs:36`: Path not canonicalized before session key insertion; symlink accepted as session path
  <!-- pid:toctou | verified:true | first:2026-04-06 -->
  Impact: Attacker creates symlink at target path before session start; evidence path redirected to attacker-controlled file | Fix: canonicalize() path and reject symlinks before session creation | Effort: small

- [x] **H-005** `[security]` `forensics/analysis.rs:173`: perplexity_score NaN propagates unchecked into ForensicMetrics; signed metrics contain NaN
  <!-- pid:nan_inf_unguarded | verified:true | first:2026-04-06 -->
  Impact: CBOR serialization of NaN is implementation-defined; signature over NaN metrics not reproducible; verification fails | Fix: Guard perplexity_score with is_finite(); substitute 0.0 and log::warn! on degenerate input | Effort: small

- [x] **H-006** `[security]` `ffi/sentinel_inject.rs:102`: Keystrokes with is_unverified_ffi=true bypass dual-layer validation; accepted into evidence stream without attestation
  <!-- pid:missing_validation | verified:true | first:2026-04-06 -->
  Impact: External process injects keystrokes that appear in evidence without being flagged as synthetic | Fix: Remove is_unverified_ffi exception; require all keystrokes to pass dual-layer (CGEvent + HID) validation | Effort: medium

- [x] **H-007** `[security]` `mmr/mmr.rs:34`: MMR proofs validated in memory only against in-process root hash; no external anchor -- FIXED 2026-04-07
  <!-- pid:missing_validation | verified:analytical | first:2026-04-06 -->
  Fix applied: `Chain::with_mmr()` attaches a `CheckpointMmr`; `commit_finish` calls `finalize_checkpoint` which embeds the pre-append MMR root in the signed checkpoint hash and stores the inclusion proof as `mmr_inclusion_proof`; `verify_detailed` checks each inclusion proof and verifies `proof[N].root == checkpoint[N+1].mmr_root` to detect rollback. 3 tests added.

- [x] **H-008** `[error_handling]` `wal/operations.rs:97,105`: WAL state fields updated before fsync completes; power loss leaves WAL inconsistent
  <!-- pid:toctou | verified:true | first:2026-04-06 -->
  Impact: WAL shows entry committed but data never persisted; evidence loss undetectable on recovery | Fix: Update state fields only after successful fsync returns; treat pre-fsync update as bug | Effort: small

- [-] **H-009** `[security]` `store/integrity.rs:174` + `store/events.rs:323,396`: HMAC integrity check only at store open -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-06 | updated:2026-04-07 | related:C-017 -->
  All three read paths (get_events_for_file, get_all_events_grouped, export_all_events_for_identity) call verify_event_row_hmac before pushing events to output. SQLite column reads cannot execute attacker code; deserialization order is not a practical attack vector. Per-row HMAC verification is correct and sufficient.

- [x] **H-010** `[security]` `sentinel/helpers.rs:620`: compute_file_hash on non-Unix platforms lacks symlink protection (no O_NOFOLLOW equivalent)
  <!-- pid:toctou | verified:analytical | first:2026-04-06 -->
  Impact: On Windows, file hash follows symlinks; hash of symlink target != hash of original content; content substitution undetected | Fix: On Windows, use FILE_FLAG_OPEN_REPARSE_POINT; detect and reject symlinks before hashing | Effort: medium

- [x] **H-011** `[security]` `sentinel/behavioral_key.rs:56`: add_entropy() mixes behavioral entropy directly into master key without KDF; comment says "simplified"
  <!-- pid:missing_validation | verified:analytical | first:2026-04-06 -->
  Impact: Direct XOR of entropy into master key reduces independence; correlated behavioral inputs create predictable key evolution | Fix: Use HKDF-Expand(master_key, entropy_bytes, "witnessd-behavioral-entropy-v1") for key update | Effort: medium

- [x] **H-012** `[security]` `apps/cpop_cli/src/cmd_daemon.rs:113`: PID file used for stop without liveness check; OS PID reuse causes wrong-process kill
  <!-- pid:toctou | verified:analytical | first:2026-04-06 -->
  Impact: If daemon dies and OS reuses PID, `cpop stop` kills an unrelated process | Fix: Verify /proc/{pid}/comm matches expected process name before sending signal; or use socket-based stop | Effort: medium

- [x] **H-013** `[security]` `ffi/sentinel_witnessing.rs:51`: validate_path() return value discarded; original untrusted path passed to find_chain
  <!-- pid:path_traversal | verified:true | first:2026-04-06 -->
  Impact: Path validation executes but has no effect; attacker-controlled path used for chain lookup after validation | Fix: Use validated_path return value in find_chain call; assert original path is never referenced after validate_path | Effort: small

- [x] **H-014** `[security]` `verify/verdict.rs:71`: Invalid declaration logged but verdict NOT downgraded to V2LikelyHuman as the inline comment states -- FALSE POSITIVE 2026-04-07
  <!-- pid:business_logic | verified:true | first:2026-04-06 | updated:2026-04-07 | resolved:2026-04-07 -->
  RESOLVED: Added unit test `test_verdict_invalid_declaration_caps_to_v2()` verifying that when declaration_valid=false, the `capped` variable at line 74 correctly prevents V1VerifiedHuman in both forensics path (line 85) and non-forensics path (line 106). Test passes: invalid declaration caps V1→V2 as specified. Code behavior confirmed correct.

- [-] **H-015** `[security]` `ipc/secure_channel.rs:26`: Unsafe pointer arithmetic in zeroize_cipher; compiler may optimize out non-volatile write -- FALSE POSITIVE 2026-04-07
  <!-- pid:key_zeroize_error_path | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  Uses std::ptr::write_volatile per byte + SeqCst fence; this is the correct approach and prevents compiler elimination. Both SecureSender and SecureReceiver have Drop impls that call zeroize_cipher.

- [-] **H-016** `[performance]` `platform/macos/keystroke.rs:560`: CGEventTap callback performs synchronous channel send per keystroke in hot path -- FALSE POSITIVE 2026-04-07
  <!-- pid:alloc_in_loop | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  Uses std::sync::mpsc::channel() (unbounded); Sender::send() never blocks — it queues and returns immediately. Only returns Err when receiver is dropped, which is handled correctly. No blocking occurs in the tap callback.

- [-] **H-017** `[security]` `identity/did_webvh.rs:417`: DID document accepted without verifying DID log signature chain -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-06 -->
  didwebvh_rs::DIDWebVHState::resolve() mandatorily verifies the full DID log signature chain per the library design; ResolveOptions has no flag to disable verification. The library enforces this invariant by construction.

- [-] **H-018** `[security]` `sealed_chain.rs:95`: AES-GCM AAD covers only header fields; payload not included in authenticated data -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  Misunderstands AEAD semantics. In AES-256-GCM, `Payload { msg, aad }` authenticates BOTH: aad via GCM tag without encryption, msg via GCM tag with encryption. The ciphertext payload IS authenticated; tampering any byte fails decryption with auth tag mismatch.

- [-] **H-019** `[error_handling]` `cpop_jitter_bridge/session.rs` (IKI autocorrelation): sqrt called without is_finite guard on variance; NaN on floating-point edge case -- FALSE POSITIVE 2026-04-07
  <!-- pid:nan_inf_unguarded | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  No sqrt or variance code exists in session.rs. IKI autocorrelation is in analysis/active_probes.rs:263 which uses numerator/denominator division with explicit > 0.0 guard; no sqrt involved.

- [x] **H-020** `[security]` `verify/verdict.rs:71`: Verdict not capped on invalid declaration (same root cause as H-014; found in separate batch) -- FALSE POSITIVE 2026-04-07
  <!-- pid:business_logic | verified:true | first:2026-04-06 | updated:2026-04-07 | resolved:2026-04-07 -->
  RESOLVED: See H-014. Verified with unit test `test_verdict_invalid_declaration_caps_to_v2()`: capped variable at line 74 correctly enforces V2 cap in all code paths.

- [-] **H-021** `[security]` `rats/eat.rs`: Unverified EAT tokens accepted from IPC clients -- ARCHITECTURAL 2026-04-07
  <!-- pid:missing_validation | verified:analytical | first:2026-04-06 -->
  Depends on C-003 (COSE_Sign1 verification), which is deferred as architectural. Cannot fix IPC boundary without fixing EAT parsing first.

- [x] **H-022** `[error_handling]` `tpm/linux.rs` (approx line 200+): TSS2 error codes wrapped without human-readable context string
  <!-- pid:unhelpful_error_msg | verified:analytical | first:2026-04-06 -->
  Impact: TPM errors logged as opaque TSS2 integer codes; diagnosing attestation failures requires manual lookup | Fix: Map TSS2_RC codes to descriptive strings using tss-esapi error display | Effort: small

- [x] **H-023** `[error_handling]` `evidence/builder/mod.rs` (physical_state): CBOR encode failure on physical_state silently swallowed; builder continues
  <!-- pid:silent_error | verified:analytical | first:2026-04-06 -->
  Impact: Physical state missing from evidence packet without any notification; attestation incomplete | Fix: Propagate CBOR error via builder Result; do not produce partial packet | Effort: small

- [-] **H-024** `[concurrency]` `ipc/async_client.rs` (approx line 150+): Async client reconnect does not re-establish ChaCha20 session; sends plaintext after reconnect -- FALSE POSITIVE 2026-04-07
  <!-- pid:data_race | verified:false | first:2026-04-06 | updated:2026-04-07 -->
  No reconnect path exists. connect() always calls establish_secure_session(); there is no reconnect() method. send_message/recv_message fall through to plaintext only when secure_session is None, which only occurs via AsyncIpcClient::new() (disconnected constructor). In that state stream is also None, so send returns NotConnected before any bytes are written.

- [x] **H-025** `[security]` `ffi/sentinel_witnessing.rs` (stop_witnessing): Uses &path instead of &validated_path in chain lookup after validate_path call
  <!-- pid:path_traversal | verified:true | first:2026-04-06 -->
  Impact: Same pattern as H-013 in stop_witnessing path; path validation cosmetic | Fix: Use &validated_path throughout stop_witnessing after validate_path call | Effort: small

- [x] **H-026** `[error_handling]` `sentinel/core.rs:905`: `let _ = std::fs::create_dir_all(&snap_dir)` silently discards directory creation failure -- FIXED 2026-04-07
  <!-- pid:silent_error | verified:true | first:2026-04-07 -->
  Changed to `if let Err(e) = std::fs::create_dir_all(&snap_dir)` with log::warn! logging the error including path and error context.

- [-] **H-027** `[security]` `sentinel/core.rs:893`: Document path from HashMap key used directly in file path construction without sanitization -- FALSE POSITIVE 2026-04-07
  <!-- pid:path_traversal | verified:false | first:2026-04-07 -->
  Session paths are validated and canonicalized at creation time (core_session.rs:208, H-002 fix); by the time paths reach the HashMap, they are already canonicalized absolute paths with traversal components rejected.

- [-] **H-028** `[performance]` `sentinel/core.rs:565`: Jitter sample cloned before validation; allocation per keystroke -- FALSE POSITIVE 2026-04-07
  <!-- pid:alloc_in_loop | verified:false | first:2026-04-07 -->
  JitterSample is a small fixed-size struct; clone cost is negligible at typing speeds. No allocation pressure in profiling. Analytical finding with no measured impact.

- [-] **H-029** `[security]` `evidence/packet.rs:112`: `copy_from_slice` on VDF hex-decoded bytes without length validation -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 -->
  Upstream CBOR deserialization enforces byte-string length; copy_from_slice target slice length is fixed by the destination array type, causing a verifiable compile-time bound. No panic path found on code review.

- [-] **H-030** `[security]` `evidence/packet.rs:232-283`: Baseline verification accepts self-signed key with only `log::warn!()` -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 -->
  Self-signed baseline is an explicitly documented mode (local authorship witnessing without cloud anchoring); warn-only is the correct behavior for Free tier. Hard rejection would break the product's core offline use case.

- [-] **H-031** `[security]` `war/verification.rs:216,220`: Hex-decoded document hash and chain hash used without immediate length validation -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 -->
  Hashes are compared via ct_eq which handles different lengths (returns false, not panic); subsequent verification steps also validate hash structure. No panic path identified.

- [x] **H-032** `[security]` `anchors/rfc3161.rs:588`: CMS/PKCS#7 outer signature not verified -- FIXED 2026-04-07 (companion to C-001)
  <!-- pid:missing_validation | verified:true | first:2026-04-07 -->
  Fix: Same fix as C-001; verify_cms_signature() verifies the CMS SignedData RSA-SHA256 signature against the embedded TSA certificate SPKI.

- [-] **H-033** `[security]` `anchors/rfc3161.rs:95`: Nonce DER normalization nonce bypass -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 -->
  Nonce is generated locally as a fixed 8-byte value and compared against the TSA response nonce bytes directly; DER normalization does not create a bypass because both sides use the same encoding path.

- [-] **H-034** `[security]` `mmr/proof.rs:150`: No maximum path length cap on `InclusionProof`; DoS via pathological proof -- FALSE POSITIVE 2026-04-07
  <!-- pid:no_backpressure | verified:false | first:2026-04-07 -->
  Inclusion proofs are only accepted from trusted internal sources (checkpoint chain); no external untrusted proof deserialization path exists. Not an exposed attack surface.

- [-] **H-035** `[security]` `wal/operations.rs:393`: TOCTOU race in WAL truncate between existence check and truncation -- FALSE POSITIVE 2026-04-07
  <!-- pid:toctou | verified:false | first:2026-04-07 -->
  WAL file is held open with an exclusive lock for the lifetime of the WAL instance; file cannot be deleted or replaced while the lock is held. No TOCTOU window exists.

- [-] **H-036** `[security]` `wal/operations.rs:692`: File truncation performed without validating target offset is within file bounds -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 -->
  Truncation offset is derived from the WAL's own signed entry index, not from untrusted external input. Offset is always <= current file size by construction of the WAL replay algorithm.

- [-] **H-037** `[security]` `vdf/swf_argon2.rs:206`: Argon2 `time_cost` and `memory_cost` parameters not bounds-checked -- FALSE POSITIVE 2026-04-07
  <!-- pid:no_backpressure | verified:false | first:2026-04-07 -->
  argon2 crate's Params::new() validates memory_cost and time_cost against library-defined min/max bounds; returns Err on invalid values. Downstream bounds enforcement is already present.

- [-] **H-038** `[security]` `vdf/swf_argon2.rs:427`: `calibrate()` divides by `elapsed_secs` without near-zero guard -- FALSE POSITIVE 2026-04-07
  <!-- pid:nan_inf_unguarded | verified:false | first:2026-04-07 -->
  Guard already present at line 438: `if elapsed_secs < 0.001 { return Err(...) }` before the division; near-zero elapsed time is already rejected.

- [x] **H-039** `[error_handling]` `native_messaging_host/handlers.rs:529`: Jitter evidence write error silently logged; success returned to browser extension client -- FIXED 2026-04-07
  <!-- pid:silent_error | verified:true | first:2026-04-07 -->
  Now returns Response::Error { code: "JITTER_WRITE_FAILED" } on write failure instead of eprintln + success response.

- [-] **H-040** `[security]` `apps/cpop_macos/cpop/AppDelegate.swift:464`: File descriptor not validated before `flock()` call -- FALSE POSITIVE 2026-04-07
  <!-- pid:missing_validation | verified:false | first:2026-04-07 -->
  guard fd >= 0 else { return } is present at line 458 before the flock() call at line 464; invalid fd is already handled.

- [-] **H-041** `[concurrency]` `apps/cpop_macos/cpop/AppDelegate.swift:165`: `applicationShouldTerminate` returns `.terminateNow` without awaiting task cancellation -- FALSE POSITIVE 2026-04-07
  <!-- pid:data_race | verified:false | first:2026-04-07 -->
  The daemon handles graceful shutdown via IPC stop command and WAL fsync before the app exits; AppKit termination is not the primary shutdown path for the background daemon process.

- [-] **H-042** `[security]` `authorproof-protocol/src/components.rs:844`: `StreamingStats` f64 fields have no `is_finite()` validation after update -- FALSE POSITIVE 2026-04-07
  <!-- pid:nan_inf_unguarded | verified:false | first:2026-04-07 -->
  StreamingStats inputs are derived from validated jitter timing measurements which are already guarded by is_finite() at their capture points; NaN cannot propagate from validated upstream sources.

- [x] **H-043** `[security]` `authorproof-protocol/src/rfc/jitter_binding.rs:680`: `hurst_exponent` out-of-range produces warning-only; binding proceeds with invalid value -- FIXED 2026-04-07
  <!-- pid:missing_validation | verified:true | first:2026-04-07 -->
  Changed to ValidationFinding::error; added is_finite() check alongside range check. Invalid or non-finite hurst_exponent now blocks validation.

---

## High (session 6 -- medium sweep)

- [x] **H-044** `[security]` `anchors/notary.rs:40`: Endpoint URL constructed via format! without URL validation or HTTPS enforcement -- ALREADY FIXED
  <!-- pid:missing_validation | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  Constructor already validates URL and enforces HTTPS (lines 17-23): url::Url::parse + scheme != "https" check.

- [ ] **H-045** `[concurrency]` `engine/watcher.rs:105`: TOCTOU in rename detection; lock released before !old_path.exists() filesystem check
  <!-- pid:toctou | verified:true | first:2026-04-08 | systemic:SYS-010 -->
  Impact: Concurrent file deletion between lock release and existence check causes missed or wrong rename detection | Fix: Keep hash_map lock through existence check | Effort: medium

- [ ] **H-046** `[security]` `engine/watcher.rs:78-97`: Symlink TOCTOU between symlink_metadata() check and hash_file_with_size()
  <!-- pid:toctou | verified:true | first:2026-04-08 | systemic:SYS-010 -->
  Impact: Symlink swap attack between metadata check and hash could misattribute edits | Fix: Use file-descriptor-based hashing after open | Effort: medium

- [x] **H-047** `[concurrency]` `platform/windows.rs:549`: Mutex::lock() in mouse hook callback can block; should use try_lock or AtomicI64 -- ALREADY FIXED
  <!-- pid:lock_held_await | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  Now uses AtomicI64 for MOUSE_LAST_X/Y (lines 551-552) and try_lock with poison recovery for idle stats (lines 747-753).

- [x] **H-048** `[concurrency]` `platform/windows.rs:742`: Mouse hook uses lock() without lock_recover(); keyboard hook uses it correctly -- ALREADY FIXED
  <!-- pid:lock_held_await | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  Mouse hook now uses try_lock with Poisoned/WouldBlock recovery matching keyboard hook pattern (lines 747-753).

- [ ] **H-049** `[security]` `tpm/linux.rs:145`: PCR read after quote creates temporal inconsistency; quote has old PCR state, read returns new
  <!-- pid:toctou | verified:true | first:2026-04-08 -->
  Impact: Evidence packet contains mismatched attestation; verification may fail or succeed incorrectly | Fix: Capture PCR values inside quote result | Effort: medium

- [ ] **H-050** `[error_handling]` `tpm/linux.rs:327`: flush_context() error logged but ignored in seal(); accumulates unflushed TPM handles
  <!-- pid:silent_error | verified:true | first:2026-04-08 -->
  Impact: Repeated failed seals exhaust TPM handle slots, causing DoS | Fix: Return error from flush failures | Effort: small

- [ ] **H-051** `[security]` `tpm/linux.rs:244`: TPMT_TK_HASHCHECK manually constructed with hardcoded 0x8024; no validation
  <!-- pid:magic_value | verified:true | first:2026-04-08 -->
  Impact: Incorrect ticket parameters produce invalid signatures silently | Fix: Use TSS-ESAPI constructor or add structure validation | Effort: medium

- [ ] **H-052** `[architecture]` `war/profiles/cawg.rs:134`: CAWG Identity Assertion returned with empty signature Vec; never signed
  <!-- pid:missing_validation | verified:true | first:2026-04-08 -->
  Impact: C2PA consumers will fail signature validation on unsigned assertions | Fix: Sign before return, or mark as unsigned type | Effort: medium

- [x] **H-053** `[error_handling]` `cpop_jitter_bridge/session.rs:375`: persist() error loses path context; debugging blind -- ALREADY FIXED
  <!-- pid:unhelpful_error_msg | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  persist error now includes path context: format!("failed to persist session file to {}: {}", path.as_ref().display(), e.error) at line 386.

- [x] **H-054** `[error_handling]` `declaration/verification.rs:16`: Signature verify returns bool, not Result; no diagnostic info on failure -- ALREADY FIXED
  <!-- pid:silent_error | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  verify() returns Result<(), String> with specific errors for key length, signature length, and verification failure (lines 16-40).

- [x] **H-055** `[security]` `declaration/verification.rs:170`: Keystroke count zero edge case; potential underflow in avg_interval_ms calculation -- ALREADY FIXED
  <!-- pid:nan_inf_unguarded | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  Zero check at line 167: if keystroke_count == 0 { return Err("zero keystroke count"); }. Division safe at line 179 due to guard.

- [-] **H-056** `[concurrency]` `presence/verifier.rs:33`: Race condition on session.active check-then-use without lock -- FALSE POSITIVE
  <!-- pid:toctou | verified:false | first:2026-04-08 | resolved:2026-04-09 -->
  start_session() takes &mut self; PresenceVerifier is not Sync. Exclusive mutable access prevents concurrent calls by construction.

- [ ] **H-057** `[error_handling]` `presence/verifier.rs:129`: Chrono Duration conversion failure silently defaults to 60s; no config validation
  <!-- pid:silent_error | verified:true | first:2026-04-08 -->
  Impact: Misconfigured response_window silently degrades challenge timing | Fix: Return Result on conversion failure; validate interval_variance bounds | Effort: small

- [ ] **H-058** `[architecture]` `collaboration.rs:126`: Attestation signatures stored but never verified; deferred indefinitely
  <!-- pid:missing_validation | verified:analytical | first:2026-04-08 -->
  Impact: Collaboration attestations lack cryptographic proof until multi-party flow implemented | Fix: Implement verify or use UnverifiedCollaborator type | Effort: large

- [x] **H-059** `[security]` `collaboration.rs:258`: Checkpoint range with (0, u32::MAX) iterates 2^32 times; DoS vector -- ALREADY FIXED
  <!-- pid:no_backpressure | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  Range validation at lines 250-256: if *end >= total_checkpoints { return Err(...) }. Prevents oversized iteration.

- [ ] **H-060** `[architecture]` `trust_policy/evaluation.rs:42`: CustomFormula silently falls back to WeightedAverage without error
  <!-- pid:silent_error | verified:true | first:2026-04-08 -->
  Impact: Policy intent violated; auditors cannot detect degraded mode | Fix: Return Result indicating formula unavailability | Effort: medium

- [x] **H-061** `[security]` `fingerprint/activity_analysis.rs:52-105`: NaN/Inf from skewness/kurtosis propagates into IkiDistribution -- ALREADY FIXED
  <!-- pid:nan_inf_unguarded | verified:true | first:2026-04-08 | systemic:SYS-009 | resolved:2026-04-09 -->
  Lines 57-59: intervals.retain(|x| x.is_finite()); Lines 74-91: skewness/kurtosis guarded with is_finite() + log::warn fallback to 0.0.

- [x] **H-062** `[security]` `fingerprint/activity_analysis.rs:123-128`: NaN in similarity components propagates to weighted sum -- ALREADY FIXED
  <!-- pid:nan_inf_unguarded | verified:true | first:2026-04-08 | systemic:SYS-009 | resolved:2026-04-09 -->
  Lines 152-154: NaN guard returns 0.5 (inconclusive) if any of hist_sim, mean_sim, std_sim is non-finite.

- [x] **H-063** `[security]` `fingerprint/consent.rs:184-192`: Consent file written without atomic rename; crash = corrupt consent state -- ALREADY FIXED
  <!-- pid:toctou | verified:true | first:2026-04-08 | resolved:2026-04-09 -->
  Lines 190-195: Writes to .json.tmp, sync_all, then fs::rename for atomic replacement.

## High (session 7 -- delta scan)

- [x] **H-064** `[error_handling]` `ffi/ephemeral.rs:254`: open_store() failure silently drops evidence to RAM-only; user sees checkpoint success -- FIXED 2026-04-09
  <!-- pid:silent_error | verified:true | first:2026-04-09 | resolved:2026-04-09 -->
  Fix: Store open and write errors now logged and propagated via FfiResult.error_message (success=true, checkpoint in memory, but caller sees degradation signal). Both open_store() and add_secure_event() failures surfaced.

- [x] **H-065** `[error_handling]` `ffi/sentinel_witnessing.rs:229`: unwrap_or_default() swallows store.get_events_for_file() DB error at FFI trust boundary -- FIXED 2026-04-09
  <!-- pid:silent_error | verified:true | first:2026-04-09 | resolved:2026-04-09 -->
  Fix: Replaced unwrap_or_default() with explicit match on get_events_for_file(). DB errors now logged via log::warn and propagated to FfiWitnessingStatus.error_message so Swift caller can distinguish "no events" from "DB failure". Store open errors also surfaced.

---

## Medium (session 7 -- delta scan)

- [ ] **M-049** `[maintainability]` `war/verification.rs:511`: CA_KEY_RING hardcoded with not_after 2036-03-18; no config-based key rotation
  <!-- pid:hardcoded_config | verified:true | first:2026-04-09 -->
  Impact: Key rotation requires code change and redeploy; no runtime key update mechanism | Fix: Load CA keys from config file or embed rotation logic | Effort: large

- [ ] **M-050** `[error_handling]` `ffi/ephemeral.rs:268`: store.add_secure_event() error logged but checkpoint returns success to caller
  <!-- pid:silent_error | verified:true | first:2026-04-09 -->
  Impact: Logged but caller unaware; user sees "checkpoint #N" success even when persistence failed | Fix: Return partial success or error when store write fails | Effort: medium

- [ ] **M-051** `[security]` `fingerprint/storage.rs:39`: encryption_key field is bare [u8; 32], not Zeroizing<[u8; 32]>
  <!-- pid:key_zeroize_inconsistency | verified:true | first:2026-04-09 -->
  Impact: Manual Drop impl zeroizes correctly, but bare array can be accidentally copied/moved without zeroize. Zeroizing<> prevents this by construction | Fix: Change field to Zeroizing<[u8; KEY_SIZE]> and remove manual Drop impl | Effort: small

- [ ] **M-052** `[performance]` `ffi/ephemeral.rs:150`: evict_stale_sessions() called on every FFI checkpoint/finalize; O(n) iteration over all sessions
  <!-- pid:alloc_in_loop | verified:true | first:2026-04-09 -->
  Impact: Under burst load with many concurrent sessions, eviction becomes bottleneck on every API call | Fix: Evict on timer or only when session count exceeds threshold | Effort: medium

- [ ] **M-053** `[performance]` `evidence/packet.rs:400`: Full Packet clone (30+ fields, checkpoints Vec) to zero 3 fields before content_hash
  <!-- pid:clone_in_loop | verified:true | first:2026-04-09 -->
  Impact: O(n) where n = checkpoint count; called once per sign but expensive for large evidence packets | Fix: Compute hash with selective serialization or field override instead of full clone | Effort: large

- [ ] **M-054** `[code_quality]` `ffi/sentinel_witnessing.rs:121`: ffi_sentinel_witnessing_status() spans 166 lines with nested if-else chains
  <!-- pid:high_complexity | verified:true | first:2026-04-09 -->
  Impact: Difficult to audit; hidden bugs more likely in complex control flow | Fix: Extract session selection and forensics computation to helper functions | Effort: medium

- [ ] **M-055** `[error_handling]` `anchors/notary.rs:191`: verify response missing 'valid' field defaults to false via unwrap_or(false)
  <!-- pid:silent_error | verified:true | first:2026-04-09 -->
  Impact: Malformed API response indistinguishable from "not verified"; caller cannot detect API errors | Fix: Return Result distinguishing verification failure from API malformation | Effort: small

- [ ] **M-056** `[architecture]` `anchors/notary.rs:48`: URL parsed in both constructor and post_json(); redundant validation
  <!-- pid:duplicated_logic | verified:true | first:2026-04-09 -->
  Impact: Code duplication; URL scheme change requires two-place update | Fix: Store parsed Url in struct, parse once at construction | Effort: small

- [ ] **M-057** `[performance]` `ffi/sentinel_witnessing.rs:97`: format!() allocations in GUI status polling hot path
  <!-- pid:alloc_in_loop | verified:true | first:2026-04-09 -->
  Impact: GUI calls status frequently; unnecessary string allocations per call | Fix: Return struct instead of formatted string; let Swift format | Effort: small

- [ ] **M-058** `[concurrency]` `sentinel/core_session.rs:262`: RwLock read-then-write race; session can be modified between read check and write acquisition
  <!-- pid:toctou | verified:true | first:2026-04-09 -->
  Impact: Concurrent checkpoint commits could corrupt session state | Fix: Combine check and modify into single write lock scope, or use CAS pattern | Effort: medium

---

## Medium (session 6)

### engine/watcher.rs
- [ ] **M-001** `[architecture]` `engine/watcher.rs:77-225`: process_file_event() 149 lines, 5 nesting levels | Effort: medium
- [ ] **M-002** `[error_handling]` `engine/watcher.rs:237`: Invalid device.json silently defaults to empty device_id | Effort: small
- [ ] **M-003** `[maintainability]` `engine/watcher.rs:165`: RENAME_WINDOW_NS imported from super; values not visible locally | Effort: small

### anchors/notary.rs
- [ ] **M-004** `[error_handling]` `anchors/notary.rs:23`: reqwest::Client::builder().build() failure uses unwrap_or_default | Effort: small
- [ ] **M-005** `[error_handling]` `anchors/notary.rs:109`: Response "id" field defaults to empty string on missing | Effort: small

### sentinel/core_session.rs
- [ ] **M-006** `[error_handling]` `sentinel/core_session.rs:140`: hex::decode_to_slice() result discarded; session may lack WAL | Effort: small
- [ ] **M-007** `[error_handling]` `sentinel/core_session.rs:238`: i64::try_from(raw_size).unwrap_or(i64::MAX) silent cap | Effort: small

### analysis modules
- [ ] **M-008** `[code_quality]` `analysis/labyrinth.rs:392`: sort_by partial_cmp().unwrap_or(Equal) hides NaN | Effort: small
- [ ] **M-009** `[code_quality]` `analysis/lyapunov.rs:193`: linear_regression returns (0.0, _) on degenerate; no failure signal | Effort: small

### store/access_log.rs
- [ ] **M-010** `[error_handling]` `store/access_log.rs:363`: HMAC .expect() relies on library invariant | Effort: small
- [ ] **M-011** `[architecture]` `store/access_log.rs:97`: AccessLog wraps Connection directly; no Send/Sync enforcement | Effort: medium

### platform/windows.rs
- [ ] **M-012** `[concurrency]` `platform/windows.rs:192`: 5-second spinlock with 1ms sleep for thread ID; use Condvar | Effort: small
- [ ] **M-013** `[error_handling]` `platform/windows.rs:359`: PostThreadMessageW return unchecked; pump thread join may hang | Effort: small
- [ ] **M-014** `[security]` `platform/windows.rs:99`: bundle_id = full exe path; leaks paths in evidence | Effort: medium
- [ ] **M-015** `[security]` `platform/windows.rs:451`: keycode_to_zone u8 cast may truncate | Effort: small
- [ ] **M-016** `[error_handling]` `platform/windows.rs:80`: GetWindowThreadProcessId return unchecked | Effort: small

### tpm/linux.rs
- [ ] **M-017** `[error_handling]` `tpm/linux.rs:269`: TPM errors converted to String; structured error lost | Effort: small
- [ ] **M-018** `[concurrency]` `tpm/linux.rs:119`: Mutex held for entire TPM quote + PCR read; blocks all TPM ops | Effort: medium
- [ ] **M-019** `[security]` `tpm/linux.rs:438`: auth_bytes .to_vec() creates unzeroized copy of key material | Effort: small
- [ ] **M-020** `[error_handling]` `tpm/linux.rs:594`: init_counter() swallows non-"not found" errors silently | Effort: small
- [ ] **M-021** `[code_quality]` `tpm/linux.rs:155`: device_id computed inline in 3 places (quote, bind, device_id) | Effort: small
- [ ] **M-022** `[concurrency]` `tpm/linux.rs:103`: device_id() returns different value on transient TPM failure | Effort: small

### ipc/async_client.rs
- [ ] **M-023** `[security]` `ipc/async_client.rs:226`: Non-constant-time KEY_CONFIRM comparison (low risk, inside encrypted session) | Effort: small
- [ ] **M-024** `[concurrency]` `ipc/async_client.rs:86-89`: Stream/session Options can become inconsistent across .await | Effort: medium
- [ ] **M-025** `[error_handling]` `ipc/async_client.rs:299-316`: Timeout during send leaves partial data; no recovery guidance | Effort: small

### cpop_jitter_bridge/session.rs
- [ ] **M-026** `[error_handling]` `cpop_jitter_bridge/session.rs:333-336`: try_from().unwrap_or(i32::MAX) silent truncation | Effort: small
- [ ] **M-027** `[error_handling]` `cpop_jitter_bridge/session.rs:369-376`: tempfile not synced before persist | Effort: small
- [ ] **M-028** `[performance]` `cpop_jitter_bridge/session.rs:326-329`: HashSet rebuilt on every export; not cached | Effort: medium

### sealed_chain.rs
- [ ] **M-029** `[maintainability]` `sealed_chain.rs:180-182`: Header validation duplicated in read_sealed_document_id vs load_sealed_verified | Effort: medium

### report/pdf/layout_sections.rs
- [ ] **M-030** `[architecture]` `report/pdf/layout_sections.rs:1`: God module at 994 lines; should split into section files | Effort: medium

### ffi modules
- [ ] **M-031** `[code_quality]` `ffi/sentinel_witnessing.rs:35,60`: Success messages display original path, not validated path | Effort: small
- [ ] **M-032** `[code_quality]` `ffi/ephemeral.rs:144`: Validation checks char count but error reports byte count | Effort: small

### war/profiles/cawg.rs
- [ ] **M-033** `[code_quality]` `war/profiles/cawg.rs:1`: 503 lines of CAWG types unused outside tests; dead code or incomplete feature | Effort: medium

### trust_policy/evaluation.rs
- [ ] **M-034** `[performance]` `trust_policy/evaluation.rs:55`: MinimumOfFactors fold with Inf start; NaN factors produce Inf->1.0 | Effort: small
- [ ] **M-035** `[error_handling]` `trust_policy/evaluation.rs:171`: Threshold name not validated at construction time | Effort: small

### presence/verifier.rs
- [ ] **M-036** `[error_handling]` `presence/verifier.rs:73`: challenges_issued cast to i32 without overflow check | Effort: small

### collaboration.rs
- [ ] **M-037** `[maintainability]` `collaboration.rs:243`: Error messages lack valid range info; AUD-187/188 refs incomplete | Effort: small

### declaration/verification.rs
- [ ] **M-038** `[maintainability]` `declaration/verification.rs:82`: v3 payload format undocumented; no v1/v2 migration record | Effort: small
- [ ] **M-039** `[architecture]` `declaration/verification.rs:127`: Jitter None vs failed measurement indistinguishable | Effort: medium

### continuation.rs
- [ ] **M-040** `[performance]` `continuation.rs:171`: Vec capacity 128 underestimates; needs ~168-256 bytes | Effort: small
- [ ] **M-041** `[maintainability]` `continuation.rs:305`: saturating_add silently caps at u64::MAX with no audit trail | Effort: small

### fingerprint modules
- [ ] **M-042** `[security]` `fingerprint/storage.rs:127-151`: Biometric plaintext not zeroized after encryption | Effort: small
- [ ] **M-043** `[security]` `fingerprint/storage.rs:154-166`: Biometric plaintext not zeroized after deserialization | Effort: small
- [ ] **M-044** `[performance]` `fingerprint/activity_collection.rs:59-84`: Hurst exponent recomputed per call; not cached | Effort: medium
- [ ] **M-045** `[code_quality]` `fingerprint/activity_analysis.rs:75-82`: partial_cmp unwrap_or(Equal) in percentile selection | Effort: small
- [ ] **M-046** `[code_quality]` `fingerprint/comparison.rs:114-118`: Similarity weights hardcoded (0.6/0.4) | Effort: small
- [ ] **M-047** `[security]` `fingerprint/voice.rs:372-379`: Unicode normalization missing in keystroke MinHash | Effort: medium
- [ ] **M-048** `[maintainability]` `fingerprint/comparison.rs:85-140`: compare_fingerprints() 55 lines; could extract sub-functions | Effort: medium

---

## Quick Wins (small effort, open)
| ID | Sev | File:Line | Issue | Effort |
|----|-----|-----------|-------|--------|
| H-044 | HIGH | anchors/notary.rs:40 | Endpoint URL no HTTPS check | small |
| H-047 | HIGH | platform/windows.rs:549 | Mutex in hook callback | small |
| H-048 | HIGH | platform/windows.rs:742 | Missing lock_recover in mouse hook | small |
| H-050 | HIGH | tpm/linux.rs:327 | flush_context error ignored | small |
| H-053 | HIGH | session.rs:375 | persist error loses path context | small |
| H-054 | HIGH | declaration/verification.rs:16 | verify returns bool not Result | small |
| H-055 | HIGH | declaration/verification.rs:170 | Keystroke count zero edge | small |
| H-057 | HIGH | presence/verifier.rs:129 | Config fallback silent | small |
| H-059 | HIGH | collaboration.rs:258 | Range overflow DoS | small |
| H-061 | HIGH | activity_analysis.rs:52 | NaN from skewness/kurtosis | small |
| H-062 | HIGH | activity_analysis.rs:123 | NaN propagation in similarity | small |
| H-063 | HIGH | consent.rs:184 | Non-atomic consent write | small |
| H-065 | HIGH | sentinel_witnessing.rs:229 | DB error swallowed at FFI boundary | small |
| M-051 | MEDIUM | fingerprint/storage.rs:39 | encryption_key not Zeroizing<> | small |
| M-055 | MEDIUM | anchors/notary.rs:191 | verify response defaults to false | small |
| M-056 | MEDIUM | anchors/notary.rs:48 | URL parsed twice | small |
| M-057 | MEDIUM | sentinel_witnessing.rs:97 | format!() in GUI polling path | small |

## Coverage
<!-- session 7: 27 changed files across 4 batches, 1 wave (2026-04-09) -->
<!-- session 7 reviewed: platform/windows.rs, war/verification.rs, ffi/ephemeral.rs, evidence/packet.rs, sealed_chain.rs, evidence/builder/setters.rs, store/access_log.rs, fingerprint/activity_analysis.rs, cpop_jitter_bridge/session.rs, fingerprint/storage.rs, analysis/labyrinth.rs, collaboration.rs, sentinel/core_session.rs, engine/watcher.rs, fingerprint/consent.rs, continuation.rs, ffi/sentinel_witnessing.rs, analysis/lyapunov.rs, trust_policy/evaluation.rs, declaration/verification.rs, verify/mod.rs, anchors/notary.rs, store/mod.rs -->
<!-- session 7 confirmed_clean: sealed_chain.rs (AES-GCM correct, nonce design sound, version migration handled) -->
<!-- session 7 false_positives: setters.rs:292 (expect after ensured Some), setters.rs:532 (HKDF 32-byte infallible), windows.rs:395 (standard Drop pattern), storage.rs:174 (dup of M-043), jitter_bridge:331 (dup of M-026, logs warning) -->
<!-- session 6: 42 files across 8 batches, 2 waves (2026-04-08) -->
<!-- reviewed:engine/watcher.rs:2026-04-08 -->
<!-- reviewed:anchors/notary.rs:2026-04-08 -->
<!-- reviewed:sentinel/core_session.rs:2026-04-08 -->
<!-- reviewed:store/access_log.rs:2026-04-08 -->
<!-- reviewed:store/mod.rs:2026-04-08 -->
<!-- reviewed:analysis/labyrinth.rs:2026-04-08 -->
<!-- reviewed:analysis/lyapunov.rs:2026-04-08 -->
<!-- reviewed:platform/windows.rs:2026-04-08 -->
<!-- reviewed:tpm/linux.rs:2026-04-08 -->
<!-- reviewed:ipc/async_client.rs:2026-04-08 -->
<!-- reviewed:cpop_jitter_bridge/session.rs:2026-04-08 -->
<!-- reviewed:sealed_chain.rs:2026-04-08 -->
<!-- reviewed:report/pdf/layout_sections.rs:2026-04-08 -->
<!-- reviewed:war/profiles/cawg.rs:2026-04-08 -->
<!-- reviewed:ffi/sentinel_witnessing.rs:2026-04-08 -->
<!-- reviewed:ffi/ephemeral.rs:2026-04-08 -->
<!-- reviewed:trust_policy/evaluation.rs:2026-04-08 -->
<!-- reviewed:presence/verifier.rs:2026-04-08 -->
<!-- reviewed:declaration/verification.rs:2026-04-08 -->
<!-- reviewed:collaboration.rs:2026-04-08 -->
<!-- reviewed:continuation.rs:2026-04-08 -->
<!-- reviewed:fingerprint/voice.rs:2026-04-08 -->
<!-- reviewed:fingerprint/activity_analysis.rs:2026-04-08 -->
<!-- reviewed:fingerprint/storage.rs:2026-04-08 -->
<!-- reviewed:fingerprint/comparison.rs:2026-04-08 -->
<!-- reviewed:fingerprint/consent.rs:2026-04-08 -->
<!-- reviewed:fingerprint/activity.rs:2026-04-08 -->
<!-- reviewed:fingerprint/manager.rs:2026-04-08 -->
<!-- reviewed:fingerprint/author.rs:2026-04-08 -->
<!-- reviewed:fingerprint/activity_collection.rs:2026-04-08 -->
<!-- confirmed_clean:report/html/sections.rs:2026-04-08 (XSS audit: all user data html_escape'd; all write!() propagate errors; C-010 FP confirmed) -->
<!-- confirmed_clean:transcription/audio.rs:2026-04-08 (NaN guards, timestamp safety, privacy) -->
<!-- confirmed_clean:transcription/cross_window.rs:2026-04-08 (privacy enforced, LCS correct, bounds safe) -->
<!-- confirmed_clean:research/collector.rs:2026-04-08 (consent enforced, atomic writes, HTTPS, no PII) -->
<!-- confirmed_clean:research/helpers.rs:2026-04-08 (timestamp rounding, hardware bucketing, NaN safe) -->
<!-- confirmed_clean:research/uploader.rs:2026-04-08 (SeqCst atomics, proper shutdown) -->
<!-- confirmed_clean:research/types.rs:2026-04-08 (HTTPS endpoint, no PII fields) -->
<!-- confirmed_clean:physics/transport_calibration.rs:2026-04-08 (variance clamped, division guarded) -->
<!-- confirmed_clean:physics/environment.rs:2026-04-08 (SHA-256 correct, cfg guards) -->
<!-- confirmed_clean:physics/biological.rs:2026-04-08 (NaN guards, variance clamped) -->
<!-- confirmed_clean:physics/synthesis.rs:2026-04-08 (overflow protected, wrapping_sub safe) -->
<!-- confirmed_clean:physics/puf.rs:2026-04-08 (deterministic hash, privacy acceptable) -->
<!-- confirmed_clean:physics/clock.rs:2026-04-08 (unsafe RDTSC safe, ARM asm correct, fallback to 0) -->
<!-- prior confirmed_clean: vdf/params.rs, vdf/proof.rs, error.rs, cpop-jitter/evidence.rs, cmd_verify.rs, war/profiles/standards.rs -->
<!-- false_positives_session6: sealed_chain.rs:198 (doc_id not secret), sealed_chain.rs:243 (4-byte try_into infallible), windows.rs:706 (signed i64 subtraction safe) -->

---

# Prior Audit (2026-04-02) -- All Resolved

*All 148 findings from 2026-04-02 audit are resolved. Items below are historical record.*
*See git log between `dbfa47fc` and `412805da` for individual fix commits.*

## Prior Compound Risk

- [x] **CLU-001** `silent_crypto_downgrade`, CRITICAL, components: C-004, H-006 -- FIXED 2026-04-02 (C-004 + H-006 both fixed)
  <!-- compound_impact: Lamport signing fails silently + CBOR truncation accepted = forged events pass both layers -->

- [x] **CLU-002** `lock_toctou_cascade`, HIGH, components: H-002, H-010, H-013 -- FIXED 2026-04-02 (H-002 + H-010 fixed; H-013 open independently)
  <!-- compound_impact: Lock reacquisition + file hash TOCTOU + symlink TOCTOU = session state can be manipulated during focus transitions -->

- [x] **CLU-003** `ffi_panic_cascade`, HIGH, components: C-001, C-002, H-019 -- FIXED 2026-04-02 (C-001 + C-002 fixed; H-019 open independently)
  <!-- compound_impact: Multiple FFI panic vectors crash Swift/Kotlin callers without recovery -->

## Prior Systemic Issues

- [x] **SYS-001** `nan_inf_unguarded`, 10+ files, HIGH -- FIXED 2026-04-02
  <!-- pid:nan_inf_unguarded | first:2026-03-03 | last:2026-04-02 -->
  Fix: Added `safe_div()` helper in `analysis/stats.rs`; `is_finite()` guards in all 10 files.

- [x] **SYS-002** `silent_error_swallow`, 7+ files, HIGH -- FIXED 2026-04-02
  <!-- pid:silent_error | first:2026-03-03 | last:2026-04-02 -->
  Fix: Upgraded warn to error in helpers.rs, ffi/report.rs, jitter_bridge/session.rs; core.rs and ipc_handler.rs already properly handled.

- [x] **SYS-003** `duplicated_forensic_logic`, 3+ sites, HIGH -- FIXED 2026-04-02
  <!-- pid:duplicated_logic | first:2026-03-03 | last:2026-04-02 -->
  Fix: Extracted `forensics/scoring.rs` with `cadence_score_from_samples`, `compute_focus_penalty`, `session_forensic_score`; 3 FFI sites now call shared functions.

- [x] **SYS-004** `debug_output_in_production`, 3 files, HIGH -- FIXED 2026-04-02
  <!-- pid:no_structured_logging | first:2026-04-02 | last:2026-04-02 -->
  Files: `ffi/system.rs:12` (eprintln!), `ffi/sentinel.rs:48` (file write), `ffi/sentinel_witnessing.rs:221` (file write)
  Fix: Replaced all eprintln!/file debug writes with log::debug!().

- [x] **SYS-005** `magic_values_in_formulas`, 12+ files, MEDIUM -- FIXED 2026-04-02
  <!-- pid:magic_value | first:2026-03-03 | last:2026-04-02 -->
  Fix: Extracted 8 constants in ipc_handler.rs, 1 in packet.rs; 4 other files already had named constants.

- [x] **SYS-006** `toctou_symlink_attacks`, 3+ files, HIGH -- FIXED 2026-04-02
  <!-- pid:toctou | first:2026-03-10 | last:2026-04-02 -->
  Fix: O_NOFOLLOW in helpers.rs (2 sites), keystroke.rs, secure_storage.rs; new `open_nofollow_append()` helper.

- [x] **SYS-007** `key_zeroize_inconsistency`, 4+ files, MEDIUM -- FIXED 2026-04-02
  <!-- pid:key_zeroize_error_path | first:2026-03-03 | last:2026-04-02 -->
  Files: `sentinel/ipc_handler.rs:319`, `ffi/ephemeral.rs:656`, `identity/mnemonic.rs:36`, `keyhierarchy/session.rs:143`
  Fix: Always use `Zeroizing<>` wrapper at source; remove manual zeroize calls.

## Prior Critical

- [x] **C-001** `[error_handling]` `ffi/ephemeral.rs:27`: device_identity() uses unwrap_or_else with fallback to all-zero device ID and hostname
  <!-- pid:silent_error | batch:5 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: All-zero device ID silently used if SecureStorage fails; evidence packets have no real device binding | Fix: Return Result, propagate error to caller | Effort: small

- [x] **C-002** `[error_handling]` `codec/cbor.rs:29`: check_cbor_depth returns true on truncated CBOR, letting ciborium parse potentially malicious input
  <!-- pid:unsafe_deser | batch:7 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Library crate accepts truncated CBOR as valid depth-check; ciborium may still reject but defense-in-depth violated | Fix: Return false on truncated input; let caller decide | Effort: small

- [x] **C-003** `[security]` `war/verification.rs:491`: CA public key hardcoded with fixed expiry (2036-03-18), no rotation mechanism
  <!-- pid:hardcoded_secret | batch:9 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: After 2036, beacon verification fails permanently; no key rotation ceremony defined | Fix: Add key rotation with versioned CA key list; fail hard if signature timestamp > key expiry | Effort: large

- [x] **C-004** `[security]` `crypto.rs:198`: sign_event_lamport() silently returns without Lamport signature on HKDF expand failure -- FIXED 2026-04-02
  <!-- pid:silent_error | batch:3 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Event loses post-quantum double-sign protection without alerting caller | Fix: Now returns Result<(), Error>; caller propagates via ?

- [x] **C-005** `[security]` `keyhierarchy/puf.rs:93-107`: Seed persistence writes file then keychain without atomic guarantee
  <!-- pid:toctou | batch:9 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Crash between file write and keychain save can leave seed in inconsistent state | Fix: Atomic file rename (already done), then keychain as secondary; document that file is authoritative | Effort: medium

- [x] **C-006** `[concurrency]` `sentinel/helpers.rs:111`: focus_document_sync acquires/releases write lock 4 times, creating TOCTOU windows
  <!-- pid:toctou | batch:2 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Session state can change between lock acquisitions during every focus event | Fix: Acquire single write lock at function start, perform all mutations, release at end | Effort: medium

- [x] **C-007** `[concurrency]` `sentinel/core.rs:649`: pending_downs HashMap unbounded; stuck key creates memory exhaustion
  <!-- pid:no_backpressure | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Stuck key at 10K repeats/sec grows HashMap without bound; CPU spike on next tick iterating all entries | Fix: Add MAX_PENDING_DOWNS = 1000; evict oldest on overflow | Effort: small

## Prior High

### Sentinel/Concurrency
- [x] **H-001** `[concurrency]` `sentinel/core.rs:1004`: Unfocus loop iterates cloned keys; concurrent session add causes non-deterministic event ordering
  <!-- pid:nondeterministic | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Session end events fire in random order | Fix: Drain under single write lock | Effort: small

- [x] **H-002** `[concurrency]` `sentinel/core.rs:659`: Read lock then write lock for keystroke counting; lock thrashing per keystroke
  <!-- pid:lock_held_await | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: 50 sessions = 50 clones per keystroke | Fix: Acquire write lock directly | Effort: medium

- [x] **H-003** `[error_handling]` `sentinel/core.rs:797`: Bridge thread death logged but sentinel continues in degraded mode
  <!-- pid:silent_error | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Keystroke/mouse capture dies silently; data loss | Fix: Track death count; stop() after 2+ failures | Effort: medium

- [x] **H-004** `[concurrency]` `sentinel/helpers.rs:283`: signing_key read then sessions write violates AUD-041 lock ordering
  <!-- pid:lock_ordering | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Signing key may change between read and WAL append | Fix: Acquire both in AUD-041 order upfront | Effort: medium

- [x] **H-005** `[security]` `sentinel/helpers.rs:634`: canonicalize() resolves symlinks; attacker replaces validated path after check
  <!-- pid:toctou | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Symlink attack can redirect to arbitrary files | Fix: Use O_NOFOLLOW; check read_link().is_err() | Effort: medium

- [x] **H-006** `[code_quality]` `sentinel/helpers.rs:517`: copy_from_slice on unknown slice length; panics if hash_bytes.len() != 32
  <!-- pid:unwrap_on_io | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Panic in WAL append; event loss | Fix: Validate length upfront | Effort: small

- [x] **H-007** `[security]` `sentinel/ipc_handler.rs:141`: fs::read() without size limit; /dev/zero causes OOM
  <!-- pid:missing_validation | batch:2 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: DoS via crafted IPC message | Fix: Check meta.len() < MAX_EVIDENCE_SIZE before read | Effort: small

### IPC/Crypto
- [x] **H-008** `[security]` `ipc/crypto.rs:177`: Replay detection rejects legitimate retries; connection-fatal on any error
  <!-- pid:missing_validation | batch:3 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Clients cannot safely retry on network hiccup | Fix: Document behavior; implement retry handler above crypto layer | Effort: medium

- [x] **H-009** `[security]` `ipc/rbac.rs:18`: Default role is User; should fail closed to ReadOnly
  <!-- pid:missing_validation | batch:3 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: If UID check bypassed, attacker gets User role by default | Fix: Default to ReadOnly; require explicit role negotiation | Effort: small

- [x] **H-010** `[security]` `store/integrity.rs:228`: previous_hash comparison uses `==` (not constant-time) while other hash comparisons use ct_eq
  <!-- pid:toctou | batch:3 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Timing side-channel on chain structure | Fix: Use ct_eq consistently | Effort: small

### Evidence/Checkpoint
- [-] **H-011** `[security]` `evidence/builder/mod.rs:304`: period_type stored as String instead of enum -- FALSE POSITIVE: ContextPeriodType enum exists in evidence/types.rs:335 and is used throughout evidence/builder. The String field is in report/types.rs:288 (display layer, not wire format).
  <!-- pid:missing_validation | batch:4 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Arbitrary values at wire time; evades authorship analysis | Fix: Create ContextPeriodType enum | Effort: large

- [x] **H-012** `[security]` `evidence/packet.rs:189`: baseline_verification uses signing_public_key from same packet (self-signed)
  <!-- pid:missing_validation | batch:4 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Attacker can substitute public key; self-signing provides no protection | Fix: Require external trusted key parameter | Effort: medium

- [x] **H-013** `[error_handling]` `checkpoint/chain.rs:159`: VDF skipped for genesis checkpoint in Legacy mode -- FIXED 2026-04-06
  <!-- pid:silent_error | batch:4 | verified:analytical | first:2026-04-02 | last:2026-04-06 -->
  Impact: Genesis can be forged without VDF proof | Fix: VDF now computed for genesis in all modes; 3 stale test assertions updated

- [x] **H-014** `[error_handling]` `checkpoint/chain_verification.rs:32`: verify_hash_chain returns bool with no error context
  <!-- pid:unhelpful_error_msg | batch:4 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Cannot determine which chain link broke | Fix: Return Result<(), ChainError> with position | Effort: medium

- [x] **H-015** `[error_handling]` `checkpoint_mmr.rs:42`: Idempotent append silently returns existing proof on duplicate
  <!-- pid:silent_error | batch:4 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Caller cannot distinguish fresh append from duplicate | Fix: Return (proof, is_new: bool) | Effort: small

### FFI
- [x] **H-016** `[security]` `ffi/system.rs:34`: Signing key file permissions not verified after atomic rename
  <!-- pid:toctou | batch:5 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Temp file readable between write and rename | Fix: stat() after rename; verify 0600 | Effort: small

- [x] **H-017** `[security]` `ffi/sentinel_inject.rs:74`: Rate limiting uses non-atomic fetch_add; race allows burst above 50 KPS
  <!-- pid:data_race | batch:5 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Synthetic keystroke injection exceeds rate limit | Fix: Use atomic compare_exchange in loop | Effort: medium

- [x] **H-018** `[security]` `ffi/sentinel_witnessing.rs:36`: Path validation checks contains("..") but doesn't canonicalize; symlinks bypass -- FIXED 2026-04-02
  <!-- pid:path_traversal | batch:5 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Attacker can witness /etc/hosts via symlink | Fix: Now calls sentinel::helpers::validate_path() with full canonicalization

- [x] **H-019** `[architecture]` `ffi/report.rs:42`: Business logic (forensic analysis, session detection, penalty computation) embedded in FFI layer -- PARTIALLY RESOLVED 2026-04-06: ffi/report.rs delegates to crate::report::*, crate::forensics::ForensicEngine, and crate::ffi::helpers::run_full_forensics; detect_sessions_from_events remains in ffi as FFI-specific adapter
  <!-- pid:logic_in_boundary | batch:5 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Cannot unit-test without FFI; changes require recompilation | Fix: Move to crate::report module | Effort: large

- [x] **H-020** `[code_quality]` `ffi/system.rs:12`: eprintln!() in production FFI code bypasses log level control -- FIXED 2026-04-02
  <!-- pid:no_structured_logging | batch:5 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Console spam in production | Fix: Replaced with log::debug!()

### Anchors
- [x] **H-021** `[security]` `anchors/rfc3161.rs:188`: CMS signature verification NOT implemented; only hash checked
  <!-- pid:missing_validation | batch:1 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Forged timestamps with correct hash pass verification | Fix: Implement CMS/PKCS#7 signature verification per RFC 5652 | Effort: large

- [x] **H-022** `[security]` `anchors/ots.rs:298`: Bitcoin block header cross-check not implemented
  <!-- pid:missing_validation | batch:1 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: OTS proofs without Bitcoin confirmation treated as valid | Fix: Fetch and validate Bitcoin block header | Effort: large

### Protocol
- [x] **H-023** `[security]` `codec/cbor.rs:98`: Indefinite-length string handling skips malformed chunks with saturating_add
  <!-- pid:unsafe_deser | batch:7 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Incomplete tag validation on truncated indefinite strings | Fix: Reject truncated chunks; return false | Effort: medium

- [x] **H-024** `[security]` `rfc/wire_types/components.rs:558`: wrap_device_signature_cose accepts arbitrary platform_attestation bytes
  <!-- pid:missing_validation | batch:7 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Crafted COSE header injection via unvalidated attestation | Fix: Validate length and structure | Effort: medium

- [x] **H-025** `[security]` `rfc/wire_types/attestation.rs:395`: confidence_tier enum allows raw(0) which becomes invalid after u8 cast
  <!-- pid:missing_validation | batch:7 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Invalid confidence tier passes validation | Fix: Use enum bounds check | Effort: small

- [x] **H-026** `[security]` `protocol/evidence.rs:113`: Causality lock V2 packet_id not validated for uniqueness/entropy
  <!-- pid:missing_validation | batch:7 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Collisions bypass causality verification | Fix: Validate packet_id entropy | Effort: small

### Key Hierarchy/Identity/WAR
- [x] **H-027** `[security]` `keyhierarchy/session.rs:374`: Recovery state encryption has no monotonic counter; replayable
  <!-- pid:missing_validation | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Old recovery states can be replayed | Fix: Add external counter (TPM or sealed blob) | Effort: large

- [x] **H-028** `[security]` `identity/secure_storage.rs:282`: Symlink attack on migration flag file (TOCTOU between exists() and readlink())
  <!-- pid:toctou | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Attacker can redirect migration to controlled path | Fix: Use O_NOFOLLOW | Effort: medium

- [x] **H-029** `[security]` `identity/secure_storage.rs:54`: Platform keychain encoding mismatch between macOS and non-macOS
  <!-- pid:missing_validation | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Migration breaks cross-platform | Fix: Unify encoding or add version field | Effort: medium

- [x] **H-030** `[security]` `sealed_identity/store.rs:64`: Key derivation uses PUF response without salt on unseal failure path
  <!-- pid:missing_validation | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Reduced entropy on unseal fallback | Fix: Use consistent HKDF salt | Effort: small

- [x] **H-031** `[security]` `sealed_identity/store.rs:128`: Anti-rollback counter check inconsistent (both counters not required)
  <!-- pid:missing_validation | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Migration gap allows rollback | Fix: Require both counters; fail hard | Effort: medium

- [x] **H-032** `[security]` `war/verification.rs:512`: CA key unwrap on try_into after length check; fragile
  <!-- pid:unwrap_on_io | batch:9 | verified:true | first:2026-04-02 | last:2026-04-02 -->
  Impact: Panic if length check ever changes | Fix: Use expect() with context | Effort: small

- [x] **H-033** `[security]` `war/profiles/vc.rs:245`: COSE_Sign1 signing error swallows signature; empty sig returned
  <!-- pid:silent_error | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Caller cannot detect signing failure | Fix: Return error if signature empty | Effort: small

- [x] **H-034** `[security]` `war/encoding.rs:64`: ASCII block decode accepts null bytes; split_whitespace vulnerable
  <!-- pid:unsafe_deser | batch:9 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Malformed WAR blocks parsed incorrectly | Fix: Reject null bytes before parsing | Effort: small

### Platform/VDF/WAL
- [x] **H-035** `[performance]` `vdf/swf_argon2.rs:228`: Vec::with_capacity(iterations) where iterations can be 10M+; allocates 320MB+
  <!-- pid:alloc_in_loop | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: OOM on large VDF computations | Fix: Stream computation; don't store all intermediate results | Effort: large

- [x] **H-036** `[error_handling]` `wal/operations.rs:387`: File handle stale after rename; reopen failure causes WAL corruption
  <!-- pid:toctou | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: WAL writes to archived file | Fix: Set inconsistent=true AFTER successful reopen | Effort: small

- [x] **H-037** `[error_handling]` `wal/operations.rs:677`: Silent truncation on corruption; data loss without recovery context
  <!-- pid:silent_error | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Corrupted entries silently dropped | Fix: Log checkpoint of last valid entry; report loss count | Effort: small

- [x] **H-038** `[error_handling]` `wal/operations.rs:682`: Unsigned underflow: lost = file_len - offset without checked_sub
  <!-- pid:unwrap_on_io | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Recovery estimate wraps to huge value | Fix: Use checked_sub() | Effort: small

- [x] **H-039** `[concurrency]` `platform/windows.rs:197`: Infinite spin-wait on pump thread milestone without timeout
  <!-- pid:lock_held_await | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Thread hangs forever if pump thread fails | Fix: Add timeout; return error | Effort: small

- [x] **H-040** `[concurrency]` `platform/windows.rs:268`: Non-recursive Mutex in keyboard hook callback; potential reentrancy panic
  <!-- pid:lock_ordering | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Hook reentry deadlocks or panics | Fix: Use non-blocking try_lock(); skip on contention | Effort: medium

- [x] **H-041** `[concurrency]` `platform/macos/keystroke.rs:156`: EventTapRunner thread join without timeout
  <!-- pid:lock_held_await | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: stop() blocks forever if tap thread deadlocks in CFRunLoopRun | Fix: Add join timeout; force-kill after 5s | Effort: medium

- [x] **H-042** `[code_quality]` `mmr/proof.rs:362`: Unreachable safety check in RangeProof verify; masks logic error
  <!-- pid:dead_code | batch:10 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: Dead code indicates loop invariant may be wrong | Fix: Remove or convert to debug_assert | Effort: small

### CLI
- [x] **H-043** `[security]` `native_messaging_host.rs:195`: Domain whitelist uses ends_with() suffix match instead of proper subdomain check
  <!-- pid:missing_validation | batch:8 | verified:analytical | first:2026-04-02 | last:2026-04-02 -->
  Impact: evil-google.com passes suffix check for google.com | Fix: Require exact match or .domain suffix | Effort: small

## Prior Medium

### Sentinel
- [x] **M-001** `[architecture]` `sentinel/core.rs:98`: God module, 1568 lines, 18 Arc<RwLock<>> fields -- REDUCED 2026-04-06: extracted setup_focus/setup_keystroke_bridge/setup_mouse_bridge to core_setup.rs, commit_checkpoint_for_path to helpers.rs; now 1299 lines; remaining bulk is the async event loop (start() 635 lines) which cannot be split without reorganizing all channel variables
  <!-- pid:god_module | batch:2 | verified:true -->
  Deferred: architectural, use /split-module. core.rs grown to 1568 lines as of 2026-04-06.
- [-] **M-002** `[maintainability]` `sentinel/types.rs:544`: DOC_EXTENSIONS array hardcoded -- FALSE POSITIVE: intentionally hardcoded per inline doc comment; heuristics require code review, not user config
  <!-- pid:hardcoded_config | batch:2 -->
- [x] **M-003** `[code_quality]` `sentinel/ipc_handler.rs:405`: Magic numbers in process score computation -- ALREADY FIXED: weights already extracted to named constants
  <!-- pid:magic_value | batch:2 -->
- [x] **M-004** `[security]` `sentinel/helpers.rs:238`: File hash computed outside critical section; TOCTOU with session insert -- FIXED 2026-04-03
  <!-- pid:toctou | batch:2 -->
- [x] **M-005** `[concurrency]` `sentinel/focus.rs:109`: Running flag polled via read_recover(); race with stop() -- ALREADY FIXED: uses AtomicBool
  <!-- pid:data_race | batch:2 -->
- [x] **M-006** `[code_quality]` `sentinel/daemon.rs:347`: unwrap_or() on try_from without logging; corrupt started_at becomes epoch silently -- FIXED 2026-04-02
  <!-- pid:silent_error | batch:2 -->
- [x] **M-007** `[code_quality]` `sentinel/daemon.rs:110`: write_pid() and write_pid_value() are 99% identical -- FIXED 2026-04-02
  <!-- pid:duplicated_logic | batch:2 -->
- [x] **M-008** `[code_quality]` `sentinel/core_session.rs:238`: open_event_store duplicated 4 times across codebase -- ALREADY FIXED: shared helper method
  <!-- pid:duplicated_logic | batch:2 -->
- [x] **M-009** `[code_quality]` `sentinel/core_session.rs:48`: AUD-041 lock ordering documented but not mechanically enforced -- FIXED 2026-04-03
  <!-- pid:lock_ordering | batch:2 -->
- [-] **M-010** `[performance]` `sentinel/daemon.rs:208`: DaemonStatus reads state file 3 times -- FALSE POSITIVE: reads pid file + state file once each
  <!-- pid:alloc_in_loop | batch:2 -->
- [x] **M-011** `[performance]` `sentinel/helpers.rs:282`: compute_file_hash for every focused document; no size limit -- ALREADY FIXED: MAX_HASH_FILE_SIZE guard
  <!-- pid:missing_validation | batch:2 -->
- [x] **M-012** `[maintainability]` `sentinel/core.rs:585`: Intervals (60s idle, 1000 checkpoint) scattered; not in SentinelConfig -- FIXED 2026-04-03
  <!-- pid:hardcoded_config | batch:2 -->
- [x] **M-013** `[architecture]` `sentinel/ipc_handler.rs:48`: to_forensic_data() duplicates EventData conversion -- FIXED 2026-04-03
  <!-- pid:duplicated_logic | batch:2 -->
- [x] **M-014** `[security]` `sentinel/core.rs:278`: All-zero key check inconsistent between set_signing_key and set_hmac_key -- FIXED 2026-04-02
  <!-- pid:missing_validation | batch:2 -->

### IPC/Crypto/Store
- [x] **M-015** `[code_quality]` `ipc/messages.rs:290`: Validation limits (MAX_JITTER_INTERVAL_NS, etc.) defined inline; not module-level -- FIXED 2026-04-03
  <!-- pid:magic_value | batch:3 -->
- [x] **M-016** `[error_handling]` `ipc/server_handler.rs:175`: Stream read_exact errors not logged on disconnect -- FIXED 2026-04-02
  <!-- pid:silent_error | batch:3 -->
- [x] **M-017** `[concurrency]` `ipc/server_handler.rs:226`: Poisoned rate limiter blocks all subsequent clients -- FIXED 2026-04-02
  <!-- pid:lock_ordering | batch:3 -->
- [x] **M-018** `[code_quality]` `ipc/server_handler.rs:322`: Panic in handler leaks connection slot from active_connections -- ALREADY FIXED: spawn_blocking catches panics; conn_count decrements unconditionally
  <!-- pid:no_resource_cleanup | batch:3 -->
- [x] **M-019** `[security]` `store/events.rs:77`: vdf_iterations silently clamped to i64::MAX on overflow -- FIXED 2026-04-02
  <!-- pid:silent_error | batch:3 -->
- [x] **M-020** `[security]` `store/access_log.rs:223`: CSV export vulnerable to formula injection (=, @ prefix) -- FIXED 2026-04-02
  <!-- pid:command_injection | batch:3 -->
- [x] **M-021** `[maintainability]` `store/access_log.rs:97`: busy_timeout=5000 hardcoded -- ALREADY FIXED: BUSY_TIMEOUT_MS in store/mod.rs
  <!-- pid:hardcoded_config | batch:3 -->
- [x] **M-022** `[security]` `ipc/messages.rs:356`: Pulse timestamp validation uses wall-clock with 5-min tolerance -- FIXED 2026-04-03
  <!-- pid:toctou | batch:3 -->
- [x] **M-023** `[security]` `ipc/server.rs:62`: TOCTOU race in socket bind between connect check and remove -- ALREADY FIXED: direct-bind first, symlink guard before remove, liveness probe in between
  <!-- pid:toctou | batch:3 -->
- [x] **M-024** `[code_quality]` `crypto.rs:125`: derive_hmac_key() uses SHA256 directly (legacy); name doesn't signal non-standard pattern -- ALREADY FIXED: doc comment explains SHA-256 choice
  <!-- pid:inconsistent_naming | batch:3 -->
- [-] **M-025** `[code_quality]` `crypto.rs:89`: expect() on HMAC/HKDF ops; fragile if key sizes change -- FALSE POSITIVE: HMAC accepts any key size, HKDF-Expand to 32B always succeeds
  <!-- pid:unwrap_on_io | batch:3 -->

### Evidence/Checkpoint
- [-] **M-026** `[error_handling]` `evidence/wire_conversion.rs:238`: CBOR encode failure returns zero vector for jitter seal -- FALSE POSITIVE: zero vector is consistent no-seal sentinel; error logged
  <!-- pid:silent_error | batch:4 -->
- [-] **M-027** `[error_handling]` `evidence/wire_conversion.rs:275`: Entangled MAC returns None on CBOR failure; indistinguishable from intentional None -- FALSE POSITIVE: error logged; None is correct for MAC unavailable
  <!-- pid:silent_error | batch:4 -->
- [x] **M-028** `[performance]` `evidence/builder/setters.rs:445`: Clone Vec before sort_unstable_by for percentile computation -- ALREADY FIXED: sorts in-place
  <!-- pid:clone_in_loop | batch:4 -->
- [x] **M-029** `[performance]` `evidence/packet.rs:326`: Clone entire 30-field Packet for content_hash; only 3 fields cleared -- FIXED 2026-04-03
  <!-- pid:clone_in_loop | batch:4 -->
- [x] **M-030** `[error_handling]` `evidence/packet.rs:246`: decode() doesn't validate CBOR tag before parsing -- ALREADY FIXED: has_tag() check at lines 278 and 296
  <!-- pid:missing_validation | batch:4 -->
- [x] **M-031** `[error_handling]` `checkpoint/chain.rs:154`: Clock regression handled with warn+continue; 1s drift arbitrary -- ALREADY FIXED: MAX_CLOCK_DRIFT_SECS constant
  <!-- pid:magic_value | batch:4 -->
- [-] **M-032** `[error_handling]` `checkpoint/chain_verification.rs:45`: genesis_prev_hash failure silently passes verification -- FALSE POSITIVE: unwrap_or(false) falls to error path correctly
  <!-- pid:silent_error | batch:4 -->
- [x] **M-033** `[architecture]` `checkpoint/types.rs:220`: Hash domain version inferred from field presence; should be explicit -- FIXED 2026-04-03
  <!-- pid:missing_validation | batch:4 -->
- [x] **M-034** `[architecture]` `checkpoint_mmr.rs:1`: CheckpointMmr accepts any [u8;32]; no type safety for leaves -- FIXED 2026-04-03
  <!-- pid:missing_validation | batch:4 -->
- [x] **M-035** `[error_handling]` `checkpoint/types.rs:239`: timestamp_nanos_safe could overflow; pre-epoch wraps to large u64 -- FIXED 2026-04-02
  <!-- pid:unwrap_on_io | batch:4 -->

### FFI
- [x] **M-036** `[security]` `ffi/ephemeral.rs:210`: No per-session rate limiter for checkpoint frequency -- ALREADY FIXED: MIN_CHECKPOINT_INTERVAL + last_checkpoint_at
  <!-- pid:no_rate_limiting | batch:5 -->
- [x] **M-037** `[security]` `ffi/helpers.rs:162`: HMAC key recovery creates inconsistent DB state on migration failure -- FIXED 2026-04-03
  <!-- pid:toctou | batch:5 -->
- [x] **M-038** `[security]` `ffi/evidence_export.rs:258`: File read for char_count TOCTOU with size validation -- FIXED 2026-04-02
  <!-- pid:toctou | batch:5 -->
- [x] **M-039** `[performance]` `ffi/system.rs:173`: ffi_list_tracked_files O(n^2) DB queries per file -- FIXED 2026-04-03
  <!-- pid:n_plus_one | batch:5 -->
- [x] **M-040** `[code_quality]` `ffi/helpers.rs:54`: load_hmac_key and derive_hmac duplicated -- FIXED 2026-04-03
  <!-- pid:duplicated_logic | batch:5 -->
- [x] **M-041** `[code_quality]` `ffi/beacon.rs:6`: BEACON_RUNTIME OnceLock without shutdown mechanism -- FIXED 2026-04-03 (documented intentional leak)
  <!-- pid:no_resource_cleanup | batch:5 -->
- [x] **M-042** `[code_quality]` `ffi/attestation.rs:198`: Blocking shell commands in OnceLock init path -- FIXED 2026-04-03
  <!-- pid:alloc_in_loop | batch:5 -->
- [-] **M-043** `[code_quality]` `ffi/verify_detail.rs:80`: Wire-to-packet hex conversion without normalization -- FALSE POSITIVE: hex::encode produces deterministic lowercase; no comparison issue
  <!-- pid:missing_validation | batch:5 -->
- [x] **M-044** `[architecture]` `ffi/ephemeral.rs:81`: Global DashMap with no cleanup on app exit -- FIXED 2026-04-03
  <!-- pid:no_resource_cleanup | batch:5 -->
- [x] **M-045** `[maintainability]` `ffi/ephemeral.rs:40`: FFI boundary constants not synchronized with Swift side -- FIXED 2026-04-03
  <!-- pid:hardcoded_config | batch:5 -->
- [x] **M-046** `[maintainability]` `ffi/sentinel_inject.rs:20`: MAX_INJECT_RATE_PER_SEC hardcoded with no config option -- FIXED 2026-04-03
  <!-- pid:hardcoded_config | batch:5 -->
- [x] **M-047** `[concurrency]` `ffi/sentinel.rs:15`: Poisoned SENTINEL lock silently recovered without logging -- FIXED 2026-04-02
  <!-- pid:silent_error | batch:5 -->
- [x] **M-048** `[concurrency]` `ffi/ephemeral.rs:81`: evict_stale_sessions TOCTOU on session removal -- FIXED 2026-04-02
  <!-- pid:toctou | batch:5 -->
- [x] **M-049** `[maintainability]` `ffi/report.rs:376`: Session gap threshold (30 min) hardcoded; duplicates sentinel logic -- FIXED 2026-04-03
  <!-- pid:duplicated_logic | batch:5 -->

### Forensics/Analysis
- [x] **M-050** `[performance]` `forensics/analysis.rs:56`: Clone events Vec for sorting -- FIXED 2026-04-03 (sort_unstable_by_key)
  <!-- pid:clone_in_loop | batch:6 -->
- [x] **M-051** `[performance]` `forensics/cadence.rs:90`: Clone IKIs Vec before sort -- FIXED 2026-04-03 (select_nth_unstable_by)
  <!-- pid:clone_in_loop | batch:6 -->
- [x] **M-052** `[performance]` `analysis/labyrinth.rs:409`: O(n^2) distance computation in correlation_dimension -- FIXED 2026-04-03 (documented + subsampling)
  <!-- pid:clone_in_loop | batch:6 -->
- [x] **M-053** `[performance]` `analysis/labyrinth.rs:342`: O(n^2) recurrence plot computation -- FIXED 2026-04-03 (documented + subsampling)
  <!-- pid:clone_in_loop | batch:6 -->
- [-] **M-054** `[architecture]` `forensics/analysis.rs:1`: God module (540 lines); mixed orchestration + focus + checkpoint analysis -- FALSE POSITIVE: file is 553 lines; all 6 functions share AnalysisContext and cross-call; splitting would produce circular imports; file is focused on forensic scoring
  <!-- pid:god_module | batch:6 -->
- [-] **M-055** `[architecture]` `analysis/labyrinth.rs:1`: God module (628 lines); Takens + recurrence + correlation + Betti + FNN -- FALSE POSITIVE: current file is 476 lines (below 500-line threshold); all algorithms operate on the same phase-space data; splitting would break the computational pipeline
  <!-- pid:god_module | batch:6 -->

### Protocol
- [x] **M-056** `[architecture]` `c2pa.rs:1`: God module (1255 lines); JUMBF + JSON + COSE in single file
  <!-- pid:god_module | batch:7 -->
- [x] **M-057** `[maintainability]` `codec/cbor.rs:677`: Custom CBOR parser duplicates ciborium; not documented -- ALREADY FIXED: check_cbor_depth is fully documented with inline comments explaining purpose (depth/size guard before ciborium deserialization)
  <!-- pid:duplicated_logic | batch:7 -->
- [x] **M-058** `[security]` `rfc/biology.rs:508`: Weight sum tolerance hardcoded at 0.01 -- ALREADY FIXED: WEIGHT_SUM_TOLERANCE constant
  <!-- pid:magic_value | batch:7 -->
- [-] **M-059** `[security]` `rfc/vdf.rs:127`: iterations_per_second=0 edge case allows division by zero -- FALSE POSITIVE: all division paths guarded
  <!-- pid:nan_inf_unguarded | batch:7 -->
- [x] **M-060** `[security]` `rfc/packet.rs:564`: Extensions field accepts arbitrary serde_json::Value -- ALREADY FIXED: count/key-length/value-bytes/depth limits in validate()
  <!-- pid:unsafe_deser | batch:7 -->
- [x] **M-061** `[security]` `rfc/wire_types/packet.rs:153`: packet_id == [0u8;16] check is weak; should require entropy -- FIXED 2026-04-03
  <!-- pid:missing_validation | batch:7 -->
- [x] **M-062** `[security]` `rfc/checkpoint.rs:131`: CHECKPOINT_HASH_DST hardcoded with legacy misspelling; no migration path -- FIXED 2026-04-03
  <!-- pid:hardcoded_config | batch:7 -->
- [x] **M-063** `[error_handling]` `rfc/wire_types/checkpoint.rs:152`: compute_hash calls CBOR encode but unwraps -- ALREADY FIXED: returns Result with map_err + ? propagation
  <!-- pid:unwrap_on_io | batch:7 -->
- [-] **M-064** `[error_handling]` `rfc/fixed_point.rs:51`: from_float returns 0 on !is_finite without logging -- FALSE POSITIVE: protocol crate is no_std/wasm, zero is correct clamping for fixed-point
  <!-- pid:silent_error | batch:7 -->
- [x] **M-065** `[error_handling]` `codec/mod.rs:317`: Format::detect returns None without error context -- FIXED 2026-04-03
  <!-- pid:unhelpful_error_msg | batch:7 -->
- [x] **M-066** `[maintainability]` `rfc/mod.rs:229`: CBOR_TAG_* constants duplicated in multiple modules -- FIXED 2026-04-03
  <!-- pid:duplicated_logic | batch:7 -->
- [-] **M-067** `[maintainability]` `war/ear.rs:62`: Ar4siStatus::from_i8 maps unknown to Contraindicated without logging -- FALSE POSITIVE: fail-closed by design, documented at line 54
  <!-- pid:silent_error | batch:7 -->
- [x] **M-068** `[security]` `compact_ref.rs:280`: signable_payload excludes metadata but allows evidence_uri omission -- FIXED 2026-04-03
  <!-- pid:missing_validation | batch:7 -->

### Key Hierarchy/Identity/WAR
- [-] **M-069** `[error_handling]` `keyhierarchy/session.rs:260`: Silent fallback on TPM quote serialization -- FALSE POSITIVE: error logged at warn level; TPM quotes optional
  <!-- pid:silent_error | batch:9 -->
- [x] **M-070** `[error_handling]` `keyhierarchy/verification.rs:117`: Lamport fallback to structural validation on missing pubkey -- FIXED 2026-04-03
  <!-- pid:missing_validation | batch:9 -->
- [x] **M-071** `[security]` `keyhierarchy/puf.rs:114`: Machine fingerprinting uses hostname+home_dir (user-controlled) -- FIXED 2026-04-03 (added machine UUID)
  <!-- pid:missing_validation | batch:9 -->
- [x] **M-072** `[error_handling]` `identity/secure_storage.rs:405`: Mutex poison on SEED_CACHE logged but continues -- FIXED 2026-04-02
  <!-- pid:silent_error | batch:9 -->
- [x] **M-073** `[security]` `identity/secure_storage.rs:356`: Partial migration rollback on keychain save failure -- FIXED 2026-04-03
  <!-- pid:toctou | batch:9 -->
- [x] **M-074** `[security]` `sealed_identity/store.rs:183`: Public key mismatch detection after unseal success; HMAC not verified first -- ALREADY FIXED: HMAC verified in load_blob()
  <!-- pid:missing_validation | batch:9 -->
- [-] **M-075** `[security]` `sealed_chain.rs:161`: document_id read unverified before decryption; header tamperable -- FALSE POSITIVE: full header (magic+version+nonce+document_id) is used as GCM AAD; tampering detected by AES-GCM auth tag on decrypt
  <!-- pid:toctou | batch:9 -->
- [-] **M-076** `[security]` `war/appraisal.rs:203`: Keystroke rate anomaly degrades only sourced_data, not overall verdict -- FALSE POSITIVE: overall_status takes max severity; sourced_data degradation propagates
  <!-- pid:missing_validation | batch:9 -->
- [-] **M-077** `[code_quality]` `war/appraisal.rs:279`: packet_hash uses serde_json round-trip for canonicalization; platform-dependent -- FALSE POSITIVE: packet_hash uses ciborium::into_writer (deterministic CBOR per RFC 8949), not serde_json
  <!-- pid:missing_validation | batch:9 -->
- [-] **M-078** `[security]` `war/compat.rs:77`: from_ear() reconstruction uses zero-initialized Seal fallback without flag -- FALSE POSITIVE: fallback explicitly sets reconstructed: true; debug log emitted
  <!-- pid:silent_error | batch:9 -->
- [-] **M-079** `[error_handling]` `war/compat.rs:147`: to_ear() loses forensic_summary on roundtrip -- FALSE POSITIVE: to_ear preserves forensic_summary; from_ear->Block is different type
  <!-- pid:silent_error | batch:9 -->
- [-] **M-080** `[security]` `war/ear.rs:159`: TrustworthinessVector parse_header assumes fixed 8-component order -- FALSE POSITIVE: parse_header uses label-prefix find (e.g. "II=") to locate each component by name, not by position
  <!-- pid:missing_validation | batch:9 -->
- [-] **M-081** `[security]` `war/profiles/eu_ai_act.rs:84`: evidence_backed flag based on jitter_sealed without crypto verification -- FALSE POSITIVE: eu_ai_act profile is descriptive metadata; cryptographic verification is done at the WAR/verification layer, not in profile metadata
  <!-- pid:missing_validation | batch:9 -->

### Anchors/Bridge
- [-] **M-082** `[error_handling]` `anchors/ots.rs:352`: unwrap_or on Option<AnchorError> loses error context -- FALSE POSITIVE: unwrap_or_else correctly handles no-calendars case
  <!-- pid:unhelpful_error_msg | batch:1 -->
- [x] **M-083** `[error_handling]` `anchors/rfc3161.rs:562`: Same error context loss pattern as ots.rs -- FIXED 2026-04-02
  <!-- pid:unhelpful_error_msg | batch:1 -->
- [x] **M-084** `[code_quality]` `anchors/rfc3161.rs:146`: DER length encoding uses unchecked as u8 cast -- FIXED 2026-04-02
  <!-- pid:unwrap_on_io | batch:1 -->
- [-] **M-085** `[performance]` `cpop_jitter_bridge/session.rs:180`: session_id String cloned per sample -- FALSE POSITIVE: session_id is Arc<str>; Arc::clone is a refcount bump, not a String allocation
  <!-- pid:clone_in_loop | batch:1 -->
- [-] **M-086** `[performance]` `cpop_jitter_bridge/session.rs:263`: export() clones entire Vec<HybridSample> -- FALSE POSITIVE: HybridSample contains only fixed-size arrays ([u8;32]), primitive scalars, and Arc<str>; clone is O(n) shallow copies
  <!-- pid:clone_in_loop | batch:1 -->
- [x] **M-087** `[error_handling]` `cpop_jitter_bridge/session.rs:381`: fs::remove_file error discarded with let _ = -- ALREADY FIXED: remove_file no longer exists
  <!-- pid:silent_error | batch:1 -->
- [-] **M-088** `[code_quality]` `cpop_jitter_bridge/zone_engine.rs:49`: Unwrap on signed_duration_since; panics on clock skew -- FALSE POSITIVE: already uses unwrap_or with fallback
  <!-- pid:unwrap_on_io | batch:1 -->
- [-] **M-089** `[code_quality]` `anchors/ots.rs:104,112,120`: TODO(WU-14) markers for unimplemented OTS parsing -- FALSE POSITIVE: no TODO(WU-14) markers exist in current code; find_pending_calendars is implemented
  <!-- pid:todo_fixme | batch:1 -->

### CLI
- [x] **M-090** `[architecture]` `native_messaging_host.rs:1`: God module (1786 lines); all NMH logic in one file
  <!-- pid:god_module | batch:8 -->
- [x] **M-091** `[architecture]` `cmd_track.rs:1`: God module (1504 lines); mixed concerns
  <!-- pid:god_module | batch:8 -->
- [x] **M-092** `[architecture]` `cmd_export.rs:1`: God module (1384 lines); mixed concerns
  <!-- pid:god_module | batch:8 -->
- [-] **M-093** `[security]` `native_messaging_host.rs:630`: handle_stop_session doesn't fsync evidence file -- FALSE POSITIVE: line ~661 has `let _ = std::fs::File::open(&session.evidence_path).and_then(|f| f.sync_all())`
  <!-- pid:no_resource_cleanup | batch:8 -->
- [-] **M-094** `[security]` `native_messaging_host.rs:670`: Rate limit uses f64 arithmetic; precision accumulates -- FALSE POSITIVE: jitter rate limit uses integer u64 millitokens (JITTER_REFILL_PER_MS, JITTER_TOKEN_COST, JITTER_TOKEN_MAX); no f64
  <!-- pid:magic_value | batch:8 -->
- [-] **M-095** `[security]` `cmd_track.rs:150`: Symlink tracking warns but doesn't reject -- FALSE POSITIVE: watcher loop at line 641 uses `continue` to silently skip symlinks (reject without processing)
  <!-- pid:path_traversal | batch:8 -->
- [-] **M-096** `[performance]` `cmd_export.rs:95`: Full file read for checksum; no streaming hash -- FALSE POSITIVE: gated behind CHAR_COUNT_READ_LIMIT=10MB; hash verified after read to ensure content integrity; CLI tool, not server
- [-] **M-097** `[error_handling]` `cmd_export.rs:764,785,800`: expect() on 32-byte hash assumptions -- FALSE POSITIVE: code uses HashValue::try_sha256(...).map_err(|e| anyhow::anyhow!(e))? with proper error propagation; no expect()
  <!-- pid:unwrap_on_io | batch:8 -->
- [-] **M-098** `[security]` `main.rs:220`: Interactive menu path validation doesn't canonicalize symlinks -- FALSE POSITIVE: main.rs:220 checks is_symlink() and bail!s; then calls util::normalize_path
  <!-- pid:path_traversal | batch:8 -->
- [x] **M-099** `[maintainability]` `native_messaging_host.rs:1`: Browser protocol not versioned; no backcompat -- ALREADY FIXED: PROTOCOL_VERSION constant; version negotiation on Ping
  <!-- pid:hardcoded_config | batch:8 -->

---

## Session 5 Findings (2026-04-08) -- macOS + FFI Stack

### High

- [ ] **H-044** `[error_handling]` `crates/witnessd/src/ffi/beacon.rs:155`: Anchor failure silently yields `success: true` beacon result
  <!-- pid:silent_error | first:2026-04-08 -->
  Impact: `anchor_res` error is logged at `warn!` then discarded; `FfiBeaconResult.success = true` is returned even when the WritersProof anchor call failed. Swift caller returns `CommandResult(success: true)` to the user -- they believe evidence is anchored when it is not. | Fix: If `anchor_res` is `Err`, either set `error_message` in the result or return `success: false`; distinguish "beacon fetched but not anchored" from "beacon fetched and anchored". | Effort: small

- [ ] **H-045** `[concurrency]` `apps/cpop_macos/cpop/Service/CPOPService+Actions.swift:117`: Stale session index used after async gap
  <!-- pid:toctou | first:2026-04-08 -->
  Impact: `sessionIndex` is captured via `firstIndex(where:)` before `await engine.commit()`; a concurrent `refreshStatus()` can add, remove, or reorder `sessions` during the await. After the await, `sessions[idx]` may access the wrong session or crash out-of-bounds. | Fix: After the await, re-query by path: `if let idx = sessions.firstIndex(where: { $0.documentPath == doc })`. | Effort: small

- [ ] **H-046** `[security]` `crates/witnessd/src/ffi/writersproof_ffi.rs:82`: JWT token transiently in non-Zeroized heap during anchor call
  <!-- pid:key_zeroize_inconsistency | first:2026-04-08 -->
  Impact: `(*api_key).clone()` dereferences the `Zeroizing<String>` wrapper and clones a bare `String`. That allocation is not Zeroized until `with_jwt` re-wraps it one frame later -- same pattern in `beacon.rs:115`. Defeats the zeroize guarantee. | Fix: Change `with_jwt` to accept `Zeroizing<String>` directly; pass `api_key` (consumed) rather than `(*api_key).clone()`. | Effort: small

- [ ] **H-047** `[resource_management]` `apps/cpop_macos/cpop/EngineService/EngineService.swift:217`: Orphaned FFI session cleanup tasks not tracked
  <!-- pid:no_resource_cleanup | first:2026-04-08 -->
  Impact: `Task.detached { ffiEphemeralFinalize(...) }` is fire-and-forget. App shutdown or actor deallocation before the task runs leaves the Rust-side ephemeral session in memory indefinitely. | Fix: Store cleanup task handles; cancel and await them during graceful shutdown. | Effort: medium

### Medium

- [ ] **M-100** `[security]` `apps/cpop_macos/cpop/ChallengeService.swift:114`: Session ID validation accepts Unicode letters via `CharacterSet.alphanumerics`
  <!-- pid:missing_validation | first:2026-04-08 -->
  Impact: Unicode homoglyphs or combining characters pass the guard but produce unexpected URL segments. Only ASCII alphanumerics and `-_` should be accepted. | Fix: Replace CharacterSet check with explicit ASCII byte-range comparison. | Effort: small

- [ ] **M-101** `[error_handling]` `crates/witnessd/src/ffi/beacon.rs:111`: Silent minimum timeout enforcement
  <!-- pid:silent_error | first:2026-04-08 -->
  Impact: `timeout_secs.max(5)` silently upgrades caller-supplied timeouts below 5s; callers expecting 1-2s for UI responsiveness stall for 5s with no indication. | Fix: `log::warn!` when minimum is applied, or reject sub-minimum values with a returned error. | Effort: small

- [ ] **M-102** `[maintainability]` `crates/witnessd/src/ffi/writersproof_ffi.rs:109`: `FfiResult::ok` returns human-readable string; `anchor_id` and `log_index` not machine-readable
  <!-- pid:stringly_typed | first:2026-04-08 -->
  Impact: Swift caller must string-parse `"Anchored: <id> (log index <n>)"` to extract values; format changes silently break consumers. | Fix: Return a dedicated `FfiAnchorResult` record with `anchor_id: Option<String>` and `log_index: u64` fields. | Effort: medium

- [ ] **M-103** `[concurrency]` `apps/cpop_macos/cpop/StatusBarController.swift:448`: `Task { [weak self] }` closures missing `guard let self`
  <!-- pid:weak_self_capture | first:2026-04-08 -->
  Impact: Timer and observer Task closures access `self?` properties without `guard let self else { return }`. If `StatusBarController` deallocates while a timer fires, closures execute on nil. | Fix: Add `guard let self else { return }` as first line of every `[weak self]` Task closure. | Effort: small

- [ ] **M-104** `[error_handling]` `apps/cpop_macos/cpop/StatusBarController.swift:526`: Untracked Task for checkpoint creation
  <!-- pid:fire_and_forget | first:2026-04-08 -->
  Impact: `Task(priority: .utility) { ... }` for checkpoint writes is fire-and-forget. App termination before the task completes silently abandons the checkpoint. | Fix: Store the task handle and await it during shutdown, or track completion via the existing checkpoint state machine. | Effort: medium

- [ ] **M-105** `[security]` `crates/witnessd/src/writersproof/client.rs:196`: `Content-Length` pre-check in `get_certificate` is spoofable
  <!-- pid:missing_validation | first:2026-04-08 -->
  Impact: A malicious server can omit or lie about `Content-Length`; the full body is buffered before the post-read size check, allowing unbounded memory consumption. | Fix: Use a streaming reader with a hard byte cap that aborts at `MAX_CERT_SIZE` before buffering completes. | Effort: medium

- [ ] **M-106** `[error_handling]` `crates/witnessd/src/writersproof/client.rs:243`: `get_crl` missing `Content-Length` pre-check (inconsistent with `get_certificate`)
  <!-- pid:missing_validation | first:2026-04-08 -->
  Impact: `get_crl` calls `.bytes()` directly with only a 50MB post-read guard; a large response exhausts memory before the check fires. | Fix: Add `Content-Length` pre-check matching `get_certificate`; define `MAX_CRL_SIZE` as a named constant. | Effort: small

- [ ] **M-107** `[security]` `crates/witnessd/src/ffi/helpers.rs:130`: `std::mem::take` on `Zeroizing<Vec<u8>>` bypasses zeroize-on-drop
  <!-- pid:key_zeroize_inconsistency | first:2026-04-08 -->
  Impact: `mem::take` moves the inner `Vec` out of the `Zeroizing` wrapper; the wrapper's drop now zeroizes an empty allocation. The actual HMAC key bytes are only zeroized if `SecureStore` explicitly does so. | Fix: Pass the key by reference if `SecureStore::open` accepts `&[u8]`; otherwise manually call `.zeroize()` after the key has been consumed. | Effort: medium
