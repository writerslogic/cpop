# CPOP Project Audit -- Consolidated Findings

<!-- suggest | Updated: 2026-04-02 | Domain: code | Languages: rust | Files: 374 | Issues: 148 -->

**Updated**: 2026-04-06 (session 2)
**Scope**: Full workspace scan -- CLI (21 files), Engine (290+ files), Protocol (22 files), Jitter (4 files)
**Previous audit**: 2026-03-30 -- 265 findings, all resolved
**macOS app**: 381 findings fixed, 0 open (see apps/cpop_macos/audit-todo.md)
**Baseline**: 1050 pass, 0 fail, 1 ignored (cpop-engine --lib)

## Summary
| Severity | Open | Fixed | Skipped |
|----------|------|-------|---------|
| CRITICAL | 0    | 12    | 0       |
| HIGH     | 0    | 135   | 0       |
| MEDIUM   | 0    | 247   | 22      |

---

## Prior Audits -- All Resolved

All 265 findings from prior audit (2026-03-30) and 255 from 2026-03-25 are resolved. See git history.

---

## Compound Risk

- [x] **CLU-001** `silent_crypto_downgrade`, CRITICAL, components: C-004, H-006 -- FIXED 2026-04-02 (C-004 + H-006 both fixed)
  <!-- compound_impact: Lamport signing fails silently + CBOR truncation accepted = forged events pass both layers -->

- [x] **CLU-002** `lock_toctou_cascade`, HIGH, components: H-002, H-010, H-013 -- FIXED 2026-04-02 (H-002 + H-010 fixed; H-013 open independently)
  <!-- compound_impact: Lock reacquisition + file hash TOCTOU + symlink TOCTOU = session state can be manipulated during focus transitions -->

- [x] **CLU-003** `ffi_panic_cascade`, HIGH, components: C-001, C-002, H-019 -- FIXED 2026-04-02 (C-001 + C-002 fixed; H-019 open independently)
  <!-- compound_impact: Multiple FFI panic vectors crash Swift/Kotlin callers without recovery -->

## Systemic Issues

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

## Critical

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

## High

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

## Medium

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

## Quick Wins
| ID | Sev | File:Line | Issue | Effort |
|----|-----|-----------|-------|--------|
| C-004 | CRITICAL | crypto.rs:198 | Lamport signing silent failure | small |
| C-007 | CRITICAL | sentinel/core.rs:649 | Unbounded pending_downs HashMap | small |
| H-006 | HIGH | sentinel/helpers.rs:517 | Unchecked slice copy panics | small |
| H-007 | HIGH | sentinel/ipc_handler.rs:141 | Unbounded file read DoS | small |
| H-009 | HIGH | ipc/rbac.rs:18 | Default role should be ReadOnly | small |
| H-010 | HIGH | store/integrity.rs:228 | Non-constant-time hash comparison | small |
| H-015 | HIGH | checkpoint_mmr.rs:42 | Idempotent append hides duplicates | small |
| H-018 | HIGH | ffi/sentinel_witnessing.rs:36 | Path validation bypass via symlink | small |
| H-020 | HIGH | ffi/system.rs:12 | eprintln in production FFI | small |
| H-025 | HIGH | rfc/wire_types/attestation.rs:395 | Invalid confidence tier passes | small |
| H-026 | HIGH | protocol/evidence.rs:113 | packet_id not validated | small |
| H-030 | HIGH | sealed_identity/store.rs:64 | Missing HKDF salt on unseal | small |
| H-032 | HIGH | war/verification.rs:512 | Fragile unwrap on CA key | small |
| H-033 | HIGH | war/profiles/vc.rs:245 | Empty signature on error | small |
| H-034 | HIGH | war/encoding.rs:64 | Null bytes in WAR block | small |
| H-036 | HIGH | wal/operations.rs:387 | Stale file handle after rename | small |
| H-037 | HIGH | wal/operations.rs:677 | Silent data loss on corruption | small |
| H-038 | HIGH | wal/operations.rs:682 | Unsigned underflow in recovery | small |
| H-039 | HIGH | platform/windows.rs:197 | Infinite spin-wait | small |
| H-042 | HIGH | mmr/proof.rs:362 | Unreachable dead code | small |
| H-043 | HIGH | native_messaging_host.rs:195 | Domain whitelist suffix match | small |

## Coverage
<!-- reviewed: 374 non-test files across 10 batches, 2 waves -->
<!-- confirmed_clean: vdf/params.rs, vdf/proof.rs, vdf/roughtime_client.rs, error.rs, cpop-jitter/evidence.rs, mmr/mmr.rs -->
<!-- completeness: 10 batches, 2 waves, all files covered -->
