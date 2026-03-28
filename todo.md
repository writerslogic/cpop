# CPOP Project Audit — Consolidated Findings

**Updated**: 2026-03-25
**Scope**: CLI (10 Rust files), Engine (55 Rust files), Atlassian (6 TS files), Google Workspace (6 TS files)
**macOS app**: 381 findings fixed, 0 open (see apps/cpop_macos/audit-todo.md)
**Engine deep audit**: 55 files audited, 120+ prior fixes applied, findings below are REMAINING issues

## Summary
| Severity | Open | Component |
|----------|------|-----------|
| CRITICAL | 5    | Google Workspace (2), Engine (3) |
| HIGH     | 60   | CLI (3), Engine (51), Marketplace (6) |
| MEDIUM   | 120  | CLI (17), Engine (95), Marketplace (8) |
| LOW      | 70   | CLI (6), Engine (60), Marketplace (4) |

---

## Critical

- [x] **C-001** `[security]` `cpop_google_workspace/src/Settings.ts:121` — API key stored in plaintext UserProperties. Any script editor can extract all user API keys.
  Impact: API key exposure. Fix: OAuth token exchange or client-side encryption. Effort: large

- [x] **C-002** `[security]` `cpop_google_workspace/src/Code.ts:321-322` — Stego HMAC tag and embedding seed in DocumentProperties, readable by any document editor.
  Impact: Watermark forgery. Fix: Store seed server-side only. Effort: large

---

## High

### CLI (Rust)
- [x] **H-001** `cpop_cli/src/native_messaging_host.rs:189` — Subdomain allowlist permissive (`evil.notion.so` passes).
- [x] **H-002** `cpop_cli/src/cmd_track.rs:96` — Auto-creates files at arbitrary paths without confirmation.
- [x] **H-003** `cpop_cli/src/cmd_export.rs:80` — `--no-beacons` and `--beacon-timeout` flags silently ignored (no-ops).

### Engine (Rust)
- [x] **H-004** `cpop_engine/src/tpm/secure_enclave.rs:1032` — `writersproof_dir()` panics on missing home directory.
- [x] **H-005** `cpop_engine/src/sentinel/core.rs:782` — HMAC key escapes `Zeroizing` wrapper via `mem::take`.

### Marketplace (TypeScript)
- [x] **H-006** `cpop_google_workspace/src/WritersProofClient.ts:168` — User email sent to API without consent.
- [x] **H-007** `cpop_atlassian/src/services/WritersProofClient.ts:136` — Error bodies leak to Confluence UI.
- [x] **H-008** `cpop_google_workspace/src/WritersProofClient.ts:381` — Error bodies leak to Google Workspace notifications.
- [x] **H-009** `cpop_atlassian/src/resolvers/index.ts` — No page edit permission check on resolver invocations.
- [x] **H-010** `cpop_google_workspace/src/Settings.ts:79` — Tier enforcement client-side only; trivially bypassable.
- [x] **H-011** `cpop_google_workspace/src/Code.ts:598` — `downloadUrl` from API used as open-link without full validation.

---

## Medium

### CLI
- [x] **M-001** `native_messaging_host.rs:246` — Data dir falls back to CWD if home unavailable.
- [x] **M-002** `native_messaging_host.rs:453` — Rejects non-monotonic char count; breaks on delete/undo.
- [x] **M-003** `cmd_track.rs:606` — ctrlc handler failure silently discarded.
- [x] **M-004** `cmd_track.rs:640` — Symlink following may track unintended files.
- [x] **M-005** `cmd_export.rs:582` — TOCTOU: char_count computed from different file read than hash.
- [x] **M-006** `cmd_export.rs:1011` — Stego HMAC key uses SHA-256 not HKDF.
- [x] **M-007** `cmd_export.rs:1335` — Timestamp subtraction may underflow on unordered events.
- [x] **M-008** `util.rs:112` — HMAC key cloned out of Zeroizing wrapper.
- [x] **M-009** `util.rs:191` — `with_extension("tmp")` replaces extension; temp file collision.
- [x] **M-010** `cmd_verify.rs:46` — Evidence file deserialized twice.
- [x] **M-011** `cmd_verify.rs:70` — Unsigned packets pass as `"valid": true` in JSON output.
- [x] **M-012** `cmd_verify.rs:471` — No file size check on `.cwar` before read. Large file DoS.
- [x] **M-013** `cmd_config.rs:205` — EDITOR env var doesn't handle quoted paths.
- [x] **M-014** `cmd_config.rs:79` — Display shows "true" for integer config set to "1".
- [x] **M-015** `cmd_status.rs:130` — `catch_unwind` around TPM; false safety for FFI panics.
- [x] **M-016** `cmd_fingerprint.rs:186` — Error matching via string comparison.
- [x] **M-017** `cli.rs:116` — `beacon_timeout` no upper bound validation.

### Engine
- [x] **M-018** `tpm/secure_enclave.rs:465` — Legacy v4 XOR seal non-authenticated, repeating keystream.
- [x] **M-019** `tpm/secure_enclave.rs:600` — Seal nonce deterministic; linkable operations.
- [x] **M-020** `checkpoint/chain.rs:152` — File lock not released on panic (relies on File drop).
- [x] **M-021** `vdf/swf_argon2.rs:480` — `panic!` in CBOR encoding reachable from verification path.
- [x] **M-022** `ffi/ephemeral.rs:616` — Signing key read with no size bound. OOM risk.
- [x] **M-023** `mmr/mmr.rs:344` — `find_peaks` could infinite loop on malformed size.

### Marketplace
- [x] **M-024** `cpop_atlassian/src/resolvers/index.ts:163` — Race condition in session state read-modify-write.
- [x] **M-025** `cpop_google_workspace/src/Code.ts:424` — No input validation on AI tool name.
- [x] **M-026** `cpop_google_workspace/src/Code.ts:758` — Unbounded polling document list in ScriptProperties.
- [x] **M-027** `cpop_google_workspace/src/Code.ts:346` — Stego tag verified from editable DocumentProperties.
- [x] **M-028** `cpop_atlassian/src/services/WritersProofClient.ts:47` — Session ID not validated before URL path interpolation.
- [x] **M-029** `cpop_atlassian/src/services/WritersProofClient.ts:63` — Evidence ID not validated before URL interpolation.
- [x] **M-030** `cpop_google_workspace/src/Code.ts:550` — API key validation too permissive.
- [x] **M-031** `cpop_google_workspace/src/Settings.ts:79` — Tier stored locally without server verification.

---

## Low

### CLI
- [x] **L-001** `cmd_track.rs:681` — `last_checkpoint_map` unbounded between cleanups.
- [x] **L-002** `cmd_export.rs:525` — Integer negation could use `.unsigned_abs()`.
- [x] **L-003** `util.rs:204` — `normalize_path` doesn't resolve `..` for non-existent paths.
- [x] **L-004** `cmd_verify.rs:387` — `write_war_appraisal` silently swallows errors.
- [x] **L-005** `cmd_log.rs:236` — Duplicate `#[test]` attribute.
- [x] **L-006** `cmd_fingerprint.rs:297` — Delete reads stdin in non-interactive contexts.
- [x] **L-007** `cmd_status.rs:76` — Derived HMAC key not zeroized.

### Engine
- [x] **L-008** `tpm/secure_enclave.rs:972` — `extract_public_key` leaks SecKeyRef.
- [x] **L-009** `checkpoint/chain.rs:802` — No fsync on parent directory after rename.
- [x] **L-010** `ffi/evidence.rs:711` — C2PA manifest write not atomic.
- [x] **L-011** `ffi/ephemeral.rs:119` — `.len()` checks bytes but error says "chars".

### Marketplace
- [x] **L-012** `cpop_atlassian/resolvers/index.ts:212` — Console logs may contain session IDs.
- [x] **L-013** `cpop_google_workspace/CardBuilder.ts:734` — API key masking reveals too much for short keys.
- [x] **L-014** `cpop_atlassian/resolvers/index.ts` — No rate limiting on resolver invocations.
- [x] **L-015** `cpop_google_workspace/Code.ts:652` — Polling jitter uses Math.random (appropriate).

---

## Engine Deep Audit (2026-03-25) — 55 files, 10 parallel agents

### Critical (Engine)

- [x] **EC-001** `forensics/cadence.rs:49` — Unsigned subtraction on signed i64 timestamps; negative IKI corrupts all metrics. Use saturating_sub or cast to i128.
- [x] **EC-002** `forensics/dictation.rs:67` — `i64::saturating_sub` saturates to `i64::MIN` not 0 on inverted timestamps; negative duration treated as enormous negative.
- [x] **EC-003** `forensics/forgery_cost.rs:273` — `ln()` on geometric mean not fully guarded against subnormals; `ln(subnormal)` collapses geo_mean toward 0.

### High (Engine)

#### Security
- [x] **EH-001** `ipc/sync_client.rs:36,103` — `encoded.len() as u32` truncates silently; no outgoing message size check.
- [x] **EH-002** `ipc/sync_client.rs` — Protocol mismatch: sync client sends bincode; server only accepts SecureJson magic.
- [x] **EH-003** `ipc/messages.rs:36-63` — Hand-rolled path normalizer doesn't handle all Component types (Windows UNC).
- [x] **EH-004** `ipc/messages.rs:68-82` — `/usr/` not in Unix blocked prefix list.
- [x] **EH-005** `ipc/server.rs:394-396` — TOCTOU between remove_file and bind on Unix socket path.
- [x] **EH-006** `ipc/server.rs:450` — `Ordering::Relaxed` on connection counter insufficient for guard correctness.
- [x] **EH-007** `crypto/mem.rs:27-30` — ProtectedKey::new panic in lock_memory leaves stack copy unzeroized.
- [x] **EH-008** `crypto/mem.rs:89-92` — ProtectedBuf::new clone-then-zeroize; panic loses zeroize on input.
- [x] **EH-009** `crypto/obfuscated.rs:23-27` — mask_key stored in plaintext alongside masked_data; trivially recoverable.
- [x] **EH-010** `ffi/report.rs:156-166` — Identity signing key used as guilloche seed oracle; should use HKDF.
- [x] **EH-011** `ffi/beacon.rs:119-120` — checkpoint_hash and evidence_hash both carry event_hash; evidence binding broken.
- [x] **EH-012** `ffi/ephemeral.rs:245,523` — device_id and machine_id zero-filled in all persisted ephemeral events.
- [x] **EH-013** `ffi/evidence.rs:405,526` — device_id and machine_id zero-filled in link_derivative and create_checkpoint.
- [x] **EH-014** `writersproof/client.rs:115-131` — sign_payload Vec not zeroized after use; evidence CBOR left on heap.
- [x] **EH-015** `writersproof/queue.rs:52` — enqueue signature has no nonce/DST; deterministic replay risk.
- [x] **EH-016** `writersproof/queue.rs:76,190` — Non-atomic file writes violate RT-07; data loss on crash.
- [x] **EH-017** `store/access_log.rs:179-190` — Unknown DB action/result falls back to Read/Success; audit corruption.

#### Correctness
- [x] **EH-018** `war/ear.rs:128-136` — overall_status min-over-i8 treats None=0 as worst; wrong direction.
- [x] **EH-019** `war/appraisal.rs:107` — Integer division masks implausible checkpoint density.
- [x] **EH-020** `war/appraisal.rs:264` — iat uses wall clock; EAR replay detection broken.
- [x] **EH-021** `trust_policy/evaluation.rs:43` — compute_score reads stale contribution field; wrong before evaluate().
- [x] **EH-022** `store/events.rs:68` — Full-table COUNT scan on every insert; O(n) per write.
- [x] **EH-023** `store/events.rs:103` — SQL LIMIT via format!() not parameterized query.
- [x] **EH-024** `evidence/wire_conversion.rs:20` — PROFILE_URI uses non-canonical form vs rats:eat: everywhere else.
- [x] **EH-025** `evidence/wire_conversion.rs:74` — attestation_tier hardcoded SoftwareOnly; ignores hardware evidence.
- [x] **EH-026** `evidence/rfc_conversion.rs:98-100` — Unit mismatch: raw microsecond std_dev in decibits field.
- [x] **EH-027** `evidence/rfc_conversion.rs:83-84` — CV guard max(1.0) ineffective for microsecond-scale means.
- [x] **EH-028** `evidence/builder/setters.rs:479` — select_nth_unstable_by percentile indices in wrong order; corrupts p25/p75.
- [x] **EH-029** `evidence/builder/setters.rs:524` — entropy_bits is -inf when intervals_us.len() == 1.
- [x] **EH-030** `baseline/digest.rs:40-45` — mean_iki computed from non-normalized histogram.
- [x] **EH-031** `baseline/verification.rs:30` — Similarity score can exceed 1.0 with unnormalized histograms.
- [x] **EH-032** `behavioral_fingerprint.rs:279` — Integer division truncation in forgery threshold check.
- [x] **EH-033** `iki_compression.rs:45` — Negative IKI values silently clamp to 0ms; inflates zero-byte frequency.
- [x] **EH-034** `perplexity.rs:47` — expect() panics on counts key missing when totals key exists.
- [x] **EH-035** `stats.rs:126-127` — Exact float equality check `ss_xx == 0.0` is brittle; near-zero produces garbage.
- [x] **EH-036** `comparison.rs:49-53` — safe_ln(0.0) = 0.0 creates false perfect similarity for zero-interval profiles.
- [x] **EH-037** `dictation.rs:56-63` — No penalty for extremely slow short utterances (WPM=0 blind spot).
- [x] **EH-038** `forgery_cost.rs:282-290` — partial_cmp unwrap_or(Equal) allows NaN to win weakest-link.
- [x] **EH-039** `topology.rs:99` — Zero-interval duplicate timestamps silently depress median_interval.
- [x] **EH-040** `continuation.rs:131` — u32 overflow in packet_sequence + 1 validation.
- [x] **EH-041** `keyhierarchy/migration.rs:78-98` — Expanded key second half not validated for consistency.
- [x] **EH-042** `checkpoint/chain.rs:281,356` — checkpoints.len() as u64 truncating cast on 32-bit.
- [x] **EH-043** `checkpoint_mmr.rs:39-44` — append_checkpoint has no rollback on sync failure; duplicate leaf.
- [x] **EH-044** `config/loading.rs:14-20` — TOCTOU between exists() and read_to_string on config file.
- [x] **EH-045** `ffi/attestation.rs:204,230` — sysctl/sw_vers spawned as child process; PATH injection risk.
- [x] **EH-046** `ffi/evidence.rs:34-40` — validate_path does not prevent overwriting key material files.
- [x] **EH-047** `ethereum.rs:63` — reqwest client has no timeout.
- [x] **EH-048** `ethereum.rs:44-54` — key_bytes heap copy not zeroized (SYS-033).
- [x] **EH-049** `declaration/builder.rs:140-145` — NaN passes per-field percentage check.
- [x] **EH-050** `steganography/extraction.rs:46` — verify hashes stripped text; no diagnostic if doc modified vs wrong key.
- [x] **EH-051** `steganography/embedding.rs:103` — Tag bytes cycle/repeat when zwc_count > 128.

### Medium (Engine) — Top 50

- [ ] **EM-001** `active_probes.rs:183-184` — Population variance instead of sample variance in std_error.
- [ ] **EM-002** `behavioral_fingerprint.rs:127` — thinking_pause_frequency denominator off by 1.
- [ ] **EM-003** `iki_compression.rs:34` — Unit mismatch risk (ns vs ms) with no runtime validation.
- [ ] **EM-004** `perplexity.rs:58` — sample_count counts bytes not chars for multibyte UTF-8.
- [ ] **EM-005** `snr.rs:46-49` — 50% overlapping windows inflate SNR by ~3dB.
- [ ] **EM-006** `stats.rs:49-53` — bhattacharyya_coefficient silent length truncation on zip.
- [ ] **EM-007** `stats.rs:71-75` — merge_histogram silently truncates mismatched lengths.
- [ ] **EM-008** `ethereum.rs:254` — Gas price off-by-one; first attempt already bumped 10%.
- [ ] **EM-009** `ethereum.rs:375` — confirmed_at is poll time not block timestamp.
- [ ] **EM-010** `ethereum.rs:413` — verify() does not check tx.from address.
- [x] **EM-011** `types.rs:142` — Anchor.status never demotes from Confirmed to Failed.
- [x] **EM-012** `types.rs:161` — best_proof fallback returns failed/pending proofs.
- [x] **EM-013** `streaming.rs:23-24` — f64::MIN sentinel for max is confusing.
- [x] **EM-014** `verification.rs:34-36` — Undocumented: single-session baseline returns 1.0 for all metrics.
- [x] **EM-015** `checkpoint/chain.rs:598-609` — verify_detailed structural check only; deferred crypto not surfaced.
- [x] **EM-016** `checkpoint/types.rs:258-260` — NaN hurst_exponent hashed differently; breaks hash stability.
- [x] **EM-017** `config/defaults.rs:8-11` — default_data_dir panics on missing home directory.
- [x] **EM-018** `config/loading.rs:27-38` — Legacy config migration silently ignores parse errors.
- [x] **EM-019** `config/loading.rs:86-91` — persist() non-atomic write; crash = corrupt config.
- [x] **EM-020** `calibration/transport.rs:63` — latency_variance_us stores std_dev not variance.
- [ ] **EM-021** `crypto/obfuscated.rs:11-18` — ROLLING_KEY race can produce duplicate keys.
- [ ] **EM-022** `crypto/obfuscation.rs:29-33` — reveal() returns String; caller cannot zeroize.
- [ ] **EM-023** `declaration/verification.rs:171-180` — entropy_bits is sample-count-dependent, not true entropy.
- [ ] **EM-024** `evidence/builder/helpers.rs:173` — Plausibility upper bound 600 KPM contradicts "30-300" comment.
- [ ] **EM-025** `evidence/types.rs:302` — CheckpointProof.hash naming confusion (chain hash vs content hash).
- [ ] **EM-026** `evidence/wire_conversion.rs:293-302` — EditDelta always zero; verifiers expecting data get zeros.
- [ ] **EM-027** `ffi/beacon.rs:66-81` — Four independent copies of load_signing_key; drift risk.
- [ ] **EM-028** `ffi/ephemeral.rs:100-117` — Eviction scan skips sessions when len < 4.
- [ ] **EM-029** `ffi/ephemeral.rs:122-131` — MAX_CONTEXT_LABEL_LEN checks bytes not chars.
- [ ] **EM-030** `ffi/evidence.rs:973` — C2PA manifest created timestamp is current time, not evidence time.
- [ ] **EM-031** `cadence.rs:87` — ikis.clone() for percentile computation doubles peak memory.
- [ ] **EM-032** `cadence.rs:184` — Autocorrelation covariance summed over n-1 pairs divided by n.
- [ ] **EM-033** `comparison.rs:95-98` — gaussian_similarity output not clamped; can exceed [0,1].
- [ ] **EM-034** `comparison.rs:72` — Magic number 0.6 for is_consistent threshold.
- [ ] **EM-035** `forgery_cost.rs:262-279` — Magic x100 multiplier for infinite-cost components.
- [ ] **EM-036** `forgery_cost.rs:137` — Magic constant 0.1 for jitter cost per sample.
- [ ] **EM-037** `ipc/messages.rs:108-125` — Windows device namespace `\\.\` not stripped.
- [ ] **EM-038** `ipc/messages.rs:154` — Pulse jitter fields unvalidated; attacker-controlled.
- [ ] **EM-039** `ipc/server.rs:437,510` — Rate limiter created fresh per run_* call.
- [ ] **EM-040** `war/appraisal.rs:143` — HardwareHardened and HardwareBound produce identical scores.
- [ ] **EM-041** `war/appraisal.rs:272` — Evidence reference hashed via non-deterministic JSON.
- [ ] **EM-042** `war/ear.rs:155` — parse_header accepts arbitrary i8; bypasses AR4SI validation.
- [ ] **EM-043** `trust_policy/evaluation.rs:155` — MinimumFactor checks any factor not named factor.
- [ ] **EM-044** `store/events.rs:248` — update_file_path TOCTOU between check and UPDATE.
- [ ] **EM-045** `store/events.rs:277` — 80-line row-mapping closure duplicated verbatim.
- [ ] **EM-046** `store/access_log.rs:223` — CSV export doesn't quote action/result fields.
- [ ] **EM-047** `store/access_log.rs:97` — No PRAGMA synchronous set; WAL alone insufficient for audit.
- [ ] **EM-048** `collaboration.rs:123` — attestation_signature unvalidated; no verification method.
- [ ] **EM-049** `continuation.rs:77` — packet_sequence increment no overflow check.
- [ ] **EM-050** `writersproof/queue.rs:82-101` — list() loads unbounded queue into memory.
