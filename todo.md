# CPOP Project Audit — Consolidated Findings

**Updated**: 2026-03-24
**Scope**: CLI (10 Rust files), Engine (10 Rust files), Atlassian (6 TS files), Google Workspace (6 TS files)
**macOS app**: 381 findings fixed, 0 open (see apps/cpop_macos/audit-todo.md)

## Summary
| Severity | Open | Component |
|----------|------|-----------|
| CRITICAL | 2    | Google Workspace |
| HIGH     | 11   | CLI (3), Engine (2), Marketplace (6) |
| MEDIUM   | 31   | CLI (17), Engine (6), Marketplace (8) |
| LOW      | 15   | CLI (6), Engine (4), Marketplace (4) |

---

## Critical

- [ ] **C-001** `[security]` `cpop_google_workspace/src/Settings.ts:121` — API key stored in plaintext UserProperties. Any script editor can extract all user API keys.
  Impact: API key exposure. Fix: OAuth token exchange or client-side encryption. Effort: large

- [ ] **C-002** `[security]` `cpop_google_workspace/src/Code.ts:321-322` — Stego HMAC tag and embedding seed in DocumentProperties, readable by any document editor.
  Impact: Watermark forgery. Fix: Store seed server-side only. Effort: large

---

## High

### CLI (Rust)
- [ ] **H-001** `cpop_cli/src/native_messaging_host.rs:189` — Subdomain allowlist permissive (`evil.notion.so` passes).
- [ ] **H-002** `cpop_cli/src/cmd_track.rs:96` — Auto-creates files at arbitrary paths without confirmation.
- [ ] **H-003** `cpop_cli/src/cmd_export.rs:80` — `--no-beacons` and `--beacon-timeout` flags silently ignored (no-ops).

### Engine (Rust)
- [ ] **H-004** `cpop_engine/src/tpm/secure_enclave.rs:1032` — `writersproof_dir()` panics on missing home directory.
- [ ] **H-005** `cpop_engine/src/sentinel/core.rs:782` — HMAC key escapes `Zeroizing` wrapper via `mem::take`.

### Marketplace (TypeScript)
- [ ] **H-006** `cpop_google_workspace/src/WritersProofClient.ts:168` — User email sent to API without consent.
- [ ] **H-007** `cpop_atlassian/src/services/WritersProofClient.ts:136` — Error bodies leak to Confluence UI.
- [ ] **H-008** `cpop_google_workspace/src/WritersProofClient.ts:381` — Error bodies leak to Google Workspace notifications.
- [ ] **H-009** `cpop_atlassian/src/resolvers/index.ts` — No page edit permission check on resolver invocations.
- [ ] **H-010** `cpop_google_workspace/src/Settings.ts:79` — Tier enforcement client-side only; trivially bypassable.
- [ ] **H-011** `cpop_google_workspace/src/Code.ts:598` — `downloadUrl` from API used as open-link without full validation.

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
- [ ] **M-018** `tpm/secure_enclave.rs:465` — Legacy v4 XOR seal non-authenticated, repeating keystream.
- [ ] **M-019** `tpm/secure_enclave.rs:600` — Seal nonce deterministic; linkable operations.
- [ ] **M-020** `checkpoint/chain.rs:152` — File lock not released on panic (relies on File drop).
- [ ] **M-021** `vdf/swf_argon2.rs:480` — `panic!` in CBOR encoding reachable from verification path.
- [ ] **M-022** `ffi/ephemeral.rs:616` — Signing key read with no size bound. OOM risk.
- [ ] **M-023** `mmr/mmr.rs:344` — `find_peaks` could infinite loop on malformed size.

### Marketplace
- [ ] **M-024** `cpop_atlassian/src/resolvers/index.ts:163` — Race condition in session state read-modify-write.
- [ ] **M-025** `cpop_google_workspace/src/Code.ts:424` — No input validation on AI tool name.
- [ ] **M-026** `cpop_google_workspace/src/Code.ts:758` — Unbounded polling document list in ScriptProperties.
- [ ] **M-027** `cpop_google_workspace/src/Code.ts:346` — Stego tag verified from editable DocumentProperties.
- [ ] **M-028** `cpop_atlassian/src/services/WritersProofClient.ts:47` — Session ID not validated before URL path interpolation.
- [ ] **M-029** `cpop_atlassian/src/services/WritersProofClient.ts:63` — Evidence ID not validated before URL interpolation.
- [ ] **M-030** `cpop_google_workspace/src/Code.ts:550` — API key validation too permissive.
- [ ] **M-031** `cpop_google_workspace/src/Settings.ts:79` — Tier stored locally without server verification.

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
- [ ] **L-008** `tpm/secure_enclave.rs:972` — `extract_public_key` leaks SecKeyRef.
- [ ] **L-009** `checkpoint/chain.rs:802` — No fsync on parent directory after rename.
- [ ] **L-010** `ffi/evidence.rs:711` — C2PA manifest write not atomic.
- [ ] **L-011** `ffi/ephemeral.rs:119` — `.len()` checks bytes but error says "chars".

### Marketplace
- [ ] **L-012** `cpop_atlassian/resolvers/index.ts:212` — Console logs may contain session IDs.
- [ ] **L-013** `cpop_google_workspace/CardBuilder.ts:734` — API key masking reveals too much for short keys.
- [ ] **L-014** `cpop_atlassian/resolvers/index.ts` — No rate limiting on resolver invocations.
- [ ] **L-015** `cpop_google_workspace/Code.ts:652` — Polling jitter uses Math.random (appropriate).
