# CPOP Project Audit — Consolidated Findings

**Updated**: 2026-03-24
**Scope**: CLI (10 Rust files), Engine (10 Rust files), Atlassian (6 TS files), Google Workspace (6 TS files)
**macOS app**: 381 findings fixed, 0 open (see apps/cpop_macos/audit-todo.md)

## Summary
| Severity | Open | Component |
|----------|------|-----------|
| CRITICAL | 2    | Google Workspace |
| HIGH     | 9    | CLI (3), Engine (0), Marketplace (6) |
| MEDIUM   | 25   | CLI (17), Engine (0), Marketplace (8) |
| LOW      | 11   | CLI (6), Engine (0), Marketplace (4) |

---

## Critical

- [x] **C-001** `[security]` `cpop_google_workspace/src/Settings.ts:121` — API key stored in plaintext UserProperties. Any script editor can extract all user API keys.
  Impact: API key exposure. Fix: OAuth token exchange or client-side encryption. Effort: large

- [x] **C-002** `[security]` `cpop_google_workspace/src/Code.ts:321-322` — Stego HMAC tag and embedding seed in DocumentProperties, readable by any document editor.
  Impact: Watermark forgery. Fix: Store seed server-side only. Effort: large

---

## High

### CLI (Rust)
- [ ] **H-001** `cpop_cli/src/native_messaging_host.rs:189` — Subdomain allowlist permissive (`evil.notion.so` passes).
- [ ] **H-002** `cpop_cli/src/cmd_track.rs:96` — Auto-creates files at arbitrary paths without confirmation.
- [ ] **H-003** `cpop_cli/src/cmd_export.rs:80` — `--no-beacons` and `--beacon-timeout` flags silently ignored (no-ops).

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
- [ ] **M-001** `native_messaging_host.rs:246` — Data dir falls back to CWD if home unavailable.
- [ ] **M-002** `native_messaging_host.rs:453` — Rejects non-monotonic char count; breaks on delete/undo.
- [ ] **M-003** `cmd_track.rs:606` — ctrlc handler failure silently discarded.
- [ ] **M-004** `cmd_track.rs:640` — Symlink following may track unintended files.
- [ ] **M-005** `cmd_export.rs:582` — TOCTOU: char_count computed from different file read than hash.
- [ ] **M-006** `cmd_export.rs:1011` — Stego HMAC key uses SHA-256 not HKDF.
- [ ] **M-007** `cmd_export.rs:1335` — Timestamp subtraction may underflow on unordered events.
- [ ] **M-008** `util.rs:112` — HMAC key cloned out of Zeroizing wrapper.
- [ ] **M-009** `util.rs:191` — `with_extension("tmp")` replaces extension; temp file collision.
- [ ] **M-010** `cmd_verify.rs:46` — Evidence file deserialized twice.
- [ ] **M-011** `cmd_verify.rs:70` — Unsigned packets pass as `"valid": true` in JSON output.
- [ ] **M-012** `cmd_verify.rs:471` — No file size check on `.cwar` before read. Large file DoS.
- [ ] **M-013** `cmd_config.rs:205` — EDITOR env var doesn't handle quoted paths.
- [ ] **M-014** `cmd_config.rs:79` — Display shows "true" for integer config set to "1".
- [ ] **M-015** `cmd_status.rs:130` — `catch_unwind` around TPM; false safety for FFI panics.
- [ ] **M-016** `cmd_fingerprint.rs:186` — Error matching via string comparison.
- [ ] **M-017** `cli.rs:116` — `beacon_timeout` no upper bound validation.

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
- [ ] **L-001** `cmd_track.rs:681` — `last_checkpoint_map` unbounded between cleanups.
- [ ] **L-002** `cmd_export.rs:525` — Integer negation could use `.unsigned_abs()`.
- [ ] **L-003** `util.rs:204` — `normalize_path` doesn't resolve `..` for non-existent paths.
- [ ] **L-004** `cmd_verify.rs:387` — `write_war_appraisal` silently swallows errors.
- [ ] **L-005** `cmd_log.rs:236` — Duplicate `#[test]` attribute.
- [ ] **L-006** `cmd_fingerprint.rs:297` — Delete reads stdin in non-interactive contexts.
- [ ] **L-007** `cmd_status.rs:76` — Derived HMAC key not zeroized.

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
