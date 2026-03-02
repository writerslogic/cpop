# Todo
<!-- suggest | Updated: 2026-02-26 | PM-audit: 2026-02-26 | Fix-review: 2026-02-26 | Languages: rust | Files: 77 | Issues: 88 -->

> Resolved items moved to `completed.md`. This file tracks only pending work.
> Updated 2026-02-26 (full engine deep audit — 77 source files across 10 batches).
> PM/Security audit pass 2026-02-26: deduplication, cross-refs, summary recount, style.
> Verification pass 2026-02-26: spot-checked all CRITs, reopened items, and representative HIGHs/MEDs against source. Fixed stale line numbers from checkpoint.rs and macos.rs splits. M-040 confirmed fixed. M-002 noted as intentional design. SYS-002 updated (2 of 4 resolved).
> Fix-review pass 2026-02-26: All 95 issues reviewed against source code. 3 false positives removed (M-009, M-019, M-024). 11 fix descriptions rewritten to prevent introducing new problems. 1 escalation (M-036 → HIGH as H-037). 1 new systemic added (SYS-008). C-003+H-030 merged. Fix descriptions now include migration notes, compilation caveats, and phased approaches where applicable.
> Previous audits: 390+ issues found and fixed across sessions 1-9; CLI src audit session 10.
> Fix pass 2026-02-27: 82 of 88 issues fixed. All 9 CRITs resolved. 35 of 37 HIGHs resolved (H-013 deferred: large scope, H-025 deferred: medium effort). 31 of 36 MEDs resolved. 4 of 8 systemics fully resolved (SYS-001, SYS-004, SYS-006, SYS-008). Remaining open: SYS-002 (god modules), SYS-003 (blocking I/O), SYS-005 (error swallow), SYS-007 (O(n^2)).

---

## Summary
| Severity | Open | Fixed | Skipped | Eliminated |
|----------|------|-------|---------|------------|
| CRITICAL | 0    | 11    | 0       | 0          |
| HIGH     | 2    | 42    | 0       | 0          |
| MEDIUM   | 3    | 34    | 8       | 3          |
| SYSTEMIC | 4    | 4     | 0       | 0          |

> **Dedup note**: 18 specific issues are fully covered by a systemic root cause.
> Fixing the systemic resolves the specific — see `→ SYS-XXX` tags below.
> Effective unique work items: ~75 (not 93) after systemic dedup.
>
> **Eliminated**: M-009 (false positive — no hex round-trip in code), M-019 (false positive — algorithm correct for monotonic indices), M-024 (false positive — division by zero already guarded).

---

## Systemic Issues

- [x] **SYS-001** `missing_zeroize` — 7 files — HIGH — FIXED
  <!-- pid:missing_zeroize | verified:true | first:2026-02-26 | last:2026-02-26 -->
  Key material not zeroized after use. Violates project crypto policy (CLAUDE.md: "Zeroize all key material after use").
  **Covers**: C-006, C-007, H-002
  Files: `keyhierarchy/puf.rs:17` (SoftwarePUF derives Clone, seed Vec not zeroized), `keyhierarchy/puf.rs:231` (HardwarePUF also derives Clone with `seed: [u8; 32]`), `keyhierarchy/migration.rs:82` (legacy key stack bytes), `keyhierarchy/session.rs:39` (master_key.to_bytes() copy), `ipc/crypto.rs:64` (AES-256-GCM expanded round key in cipher field), `sealed_identity.rs:381` (XOR wrap key), `sentinel/core.rs:149` (signing key bytes passed to stego engine)
  Fix: Remove `Clone`, add `#[derive(Zeroize, ZeroizeOnDrop)]` to SoftwarePUF and HardwarePUF. **Caveat**: `PathBuf` does not implement `Zeroize` — use `#[zeroize(skip)]` on `seed_path` and `device_id: String` fields that aren't secret. Wrap returned key bytes in `Zeroizing<[u8;32]>` or `Zeroizing<Vec<u8>>`. Enable aes-gcm `zeroize` feature flag (verify version supports it in Cargo.lock). Zeroize stack copies immediately after use.

- [ ] **SYS-002** `god_module` — 2 files remaining — HIGH
  <!-- pid:god_module | verified:true | first:2026-02-26 | last:2026-02-26 -->
  God modules/functions >800 lines with mixed concerns.
  ~~`main.rs` (4023 lines)~~ — RESOLVED: split into 16 modules (140-line dispatcher).
  ~~`checkpoint.rs` (1979 lines)~~ — RESOLVED: split into `checkpoint/` submodule (chain.rs, types.rs, tests.rs).
  ~~`platform/macos.rs` (1567 lines)~~ — RESOLVED: split into `platform/macos/` submodule (keystroke.rs, mouse_capture.rs, focus.rs, hid.rs, +4 smaller files).
  Remaining: `sentinel/ipc_handler.rs:handle()` (795 lines, 6-level nesting), `ipc/async_client.rs` (1108 lines, Unix/Windows fully duplicated)
  Fix: Extract ipc_handler arms into dedicated methods; deduplicate async_client via generic I/O trait

- [ ] **SYS-003** `blocking_io_async` — 3 files — HIGH
  <!-- pid:blocking_io_async | verified:true | first:2026-02-26 | last:2026-02-26 -->
  Synchronous blocking I/O on Tokio async worker threads. Starves task scheduler.
  Files: `sentinel/ipc_handler.rs` (fs::read/write in sync handle()), `cmd_watch.rs` (recv_timeout + VDF in async run_watcher), `ipc/server.rs` (sync handler.handle() in async loop)
  Fix: Wrap blocking calls in `spawn_blocking`. Long-term: make `IpcMessageHandler::handle()` async; replace `std::sync::mpsc` with `tokio::sync::mpsc` in watcher

- [x] **SYS-004** `missing_input_validation` — 6+ files — HIGH — FIXED
  <!-- pid:missing_input_validation | verified:true | first:2026-02-26 | last:2026-02-26 -->
  Missing validation on deserialized data at trust boundaries. Attacker-controlled input accepted unchecked.
  **Covers**: H-011, H-028, H-029
  Files: `rfc/time_evidence.rs:452` (blank Roughtime samples pass), `rfc/time_evidence.rs:448` (blank blockchain anchors pass), `rfc/biology.rs:500` (NaN weights not checked), `rfc/vdf.rs:282` (calibration signature not verified), `analysis/behavioral_fingerprint.rs:189` (unfiltered negative intervals in forgery detection), `analysis/labyrinth.rs:314` (integer overflow in embedding params)
  Fix: Add `is_finite()` checks on all f64 fields; validate non-zero hashes/keys; bounds-check LabyrinthParams (max_embedding_dim <= 20, max_delay <= 50) at `analyze_labyrinth` entry; use `checked_mul` as defense-in-depth; apply same `> 0.0 && < 5000.0` interval filter in detect_forgery as in from_samples

- [ ] **SYS-005** `silent_error_swallow` — 10+ files — HIGH
  <!-- pid:silent_error_swallow | verified:true | first:2026-02-26 | last:2026-02-26 -->
  Errors silently discarded via `let _ =`, `unwrap_or_default()`, or `if let Ok()`. Security-critical failures vanish.
  **Covers**: H-020, H-021, H-033, H-035, M-007
  Files: `sentinel/core.rs:522` (WAL append), `sentinel/helpers.rs:131` (hex decode to zeros), `sentinel/ipc_handler.rs:120` (serialize), `cmd_daemon.rs` (PID write), `fingerprint/storage.rs:155` (voice deletion), `wal.rs:469` (scan_to_end no sig verify), plus CLI files
  Fix: Codebase-wide pass: propagate with `?` or log at warn level; never silently discard errors on security-critical paths

- [x] **SYS-006** `duplicated_security_code` — 6+ files — MEDIUM — FIXED
  <!-- pid:duplicated_logic | verified:true | first:2026-02-26 | last:2026-02-26 -->
  Security-critical code duplicated 3+ times. Divergent copies = inconsistent security posture.
  **Covers**: M-001, M-015, M-016, M-026, M-034
  Files: `keyhierarchy/session.rs` + `migration.rs` (session start logic 3x), `sentinel/ipc_handler.rs` (store open 3x), `platform/macos/keystroke.rs` (event-tap lifecycle 3x), `checkpoint/chain.rs` (commit struct init 4x), `rfc/` (hex bytes serde 3x)
  Note: CLI key loading (was 4x in monolith) now centralized in `util.rs` after main.rs split. File refs updated after checkpoint.rs and macos.rs splits.
  Fix: Extract shared helpers for each pattern; single source of truth for security logic

- [ ] **SYS-007** `perf_on2_analysis` — 3 files — MEDIUM
  <!-- pid:perf_on2_analysis | verified:true | first:2026-02-26 | last:2026-02-26 -->
  O(n^2) algorithms in analysis path. No FFT, no spatial indexing. Sample-size caps mitigate but don't solve.
  Files: `analysis/pink_noise.rs:191` (O(n^2) DFT), `analysis/labyrinth.rs:361` (O(n^2) recurrence matrix), `analysis/labyrinth.rs:276` (O(n^2) FNN nearest-neighbor)
  Fix: Replace DFT with rustfft crate; use k-d tree for neighbor queries

- [x] **SYS-008** `unauthenticated_xor_cipher` — 3 files — HIGH — FIXED
  <!-- pid:unauthenticated_xor | verified:true | first:2026-02-26 | last:2026-02-26 -->
  Three separate subsystems use XOR cipher without authentication (MAC) for cryptographic protection. Ciphertext is trivially malleable — bit-flips in ciphertext produce controlled bit-flips in plaintext. Key material cycling every 32 bytes enables known-plaintext attacks on data longer than 32 bytes.
  **Covers**: H-009, H-010, H-016
  Files: `tpm/secure_enclave.rs:560` (seal: XOR with SHA256(ECDSA-sig)), `sealed_identity.rs:337` (software wrap: XOR with SHA256(machine_salt)), `keyhierarchy/session.rs:396` (ratchet recovery: XOR with PUF-derived key)
  Fix: Replace all three with ChaCha20-Poly1305 AEAD (crate already in deps via `fingerprint/storage.rs`). Each needs a version byte prefix for backward-compatible migration — unseal old format, re-seal as new on next access. H-010 additionally requires strengthening the key derivation (see H-010 for details).

---

## Critical

- [x] **C-001** `[security]` `platform/macos/keystroke.rs:259` — Use-after-free in CFRunLoop stop — FIXED
  <!-- pid:use_after_free | batch:5 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `CFRunLoopStop(handle.0); CFRelease(handle.0)` at :259-260 (KeystrokeMonitor::stop) and :432-433 (MacOSKeystrokeCapture::stop). CFRelease races event-loop thread — thread may still be referencing the run loop. UB on Apple Silicon — heap corruption / crash in keystroke capture.
  Note: Same pattern in both stop() impls. The `RunLoopHandle` is inside `Arc<Mutex<Option<RunLoopHandle>>>`, which complicates the fix.
  Fix: Restructure the stop sequence: (1) Extract raw pointer from `run_loop.lock()` via `rl.take()`, (2) call `CFRunLoopStop(ptr)` to signal stop, (3) release the mutex lock, (4) call `thread.join()` to wait for the event-loop thread to exit, (5) **only then** call `CFRelease(ptr)`. The current code does CFRunLoopStop + CFRelease together, then joins — the join must happen BEFORE CFRelease. | Effort: medium

- [x] **C-002** `[concurrency]` `platform/macos/keystroke.rs:227` — Race in start_event_tap ready signal — FIXED
  <!-- pid:race_condition | batch:5 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `ready_tx.send(Ok(()))` at :227 fires before CFRetain at :231 and run_loop store at :232-233. Main thread can call stop() between :227 and :233, causing use-after-free of unretained CFRunLoop.
  Note: Same race in both `KeystrokeMonitor::start_event_tap` (line 227) and `MacOSKeystrokeCapture::start` (line 392). Fix both.
  Fix: Move `ready_tx.send(Ok(()))` to after the `run_loop` handle is stored (after line 234 / line 399). If the mutex lock or CFRetain fails after tap creation, the channel drop will signal the caller via recv error — consistent with existing error paths. | Effort: small

- [x] **C-003** `[security]` `native_messaging_host.rs:155-163` — Domain allowlist bypass (two vulnerabilities) — FIXED
  <!-- pid:url_bypass | batch:10 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  **Two distinct bugs in the same code block** (lines 155-163):
  1. **Subdomain bypass** (line 157): `host.ends_with(d)` matches `evildocs.google.com` against allowed `docs.google.com`. (Previously tracked separately as H-030.)
  2. **Parse fallback bypass** (line 162): `document_url.contains(d)` matches domain string anywhere in URL (query, path, fragment). Allowlist fully defeated.
  Fix: (1) Replace `ends_with(d)` with `host == *d || host.ends_with(&format!(".{}", d))`. (2) Remove the `else` fallback entirely — reject unparseable URLs. Both changes are in the same 8-line block. | Effort: small

- [x] **C-004** `[security]` `fingerprint/voice.rs:316` — VoiceCollector hardcodes consent_given=true — FIXED
  <!-- pid:consent_bypass | batch:7 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `VoiceFingerprint::new(true)` at :316 in `VoiceCollector::new()` and :422 in `VoiceCollector::reset()` unconditionally set consent.
  Note: `FingerprintManager::with_config` already gates VoiceCollector construction on `consent_manager.has_voice_consent()`, but `Sentinel::enable_voice_fingerprinting` (core.rs:102-107) does NOT check consent before constructing. The `consent_given` field in the serialized fingerprint is a fabricated claim.
  Fix: (1) Change `VoiceCollector::new()` to use `VoiceFingerprint::new(false)`. (2) Add `VoiceCollector::with_consent(consent: bool)` constructor. (3) Update `FingerprintManager` callers to pass `true` (they already gate on consent). (4) Update `Sentinel::enable_voice_fingerprinting` to either check consent or document the precondition. **Do NOT** just flip the default without updating callers — `FingerprintManager` calls that already verified consent would produce fingerprints claiming consent=false. | Effort: small

- [x] **C-005** `[security]` `rfc/jitter_binding.rs:656` — LabyrinthStructure emits fabricated evidence — FIXED
  <!-- pid:fabricated_data | batch:6 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  Hardcodes `lyapunov_exponent: 0.0` at :656 (with `// TODO: separate calculation needed`). Also `attractor_points: Vec::new()` at :645. Two of six fields are fabricated. Implies non-chaotic system (opposite of human typing). Verifiers get structurally valid but semantically false phase-space data.
  Note: `LabyrinthAnalysis` has no Lyapunov field — the value literally cannot be computed from the source data. The `JitterBinding::labyrinth_structure` field is already `Option<LabyrinthStructure>`.
  Fix: Change `lyapunov_exponent` from `f64` to `Option<f64>`, set to `None` in the `From` impl. Update `validate()` to accept `None` (currently doesn't check this field anyway). Also update M-027 (same root cause). Wire format change — verify CDDL schema allows optional. | Effort: medium

- [x] **C-006** `[security]` `keyhierarchy/puf.rs:17` — SoftwarePUF seed not zeroized on Drop `→ SYS-001` — FIXED
  <!-- pid:missing_zeroize | batch:8 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `#[derive(Clone)]` creates unzeroized copies of 32-byte PUF seed. Root identity seed persists in heap after drop. `HardwarePUF` (line 231) has the same problem.
  Fix: Remove `Clone` from both `SoftwarePUF` and `HardwarePUF` (verified: `.clone()` is never called on either in the codebase). Add `#[derive(Zeroize, ZeroizeOnDrop)]` with `#[zeroize(skip)]` on `seed_path: PathBuf` (`PathBuf` does not implement `Zeroize`). Add `use zeroize::{Zeroize, ZeroizeOnDrop}` import. | Effort: small

- [x] **C-007** `[security]` `keyhierarchy/migration.rs:82` — Legacy private key bytes not zeroized `→ SYS-001` — FIXED
  <!-- pid:missing_zeroize | batch:8 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `seed: [u8; 32]` at :86 on stack, used for SigningKey at :88, never zeroized. Private key lingers in stack memory. Also `data` from `fs::read()` at :83 is a Vec<u8> containing the raw key — also not zeroized. (`zeroize::Zeroize` is already imported on line 9.)
  Fix: Change `let data = fs::read(path)?;` to `let data = Zeroizing::new(fs::read(path)?);` (implements `Deref<Target=Vec<u8>>`). Add `seed.zeroize();` before each `return Ok(SigningKey::from_bytes(&seed));`. Update import to `use zeroize::{Zeroize, Zeroizing};`. | Effort: small

### ~~CLI-C1. cmd_watch.rs syntax corruption~~ [x] FIXED
- Duplicate/truncated code fragment at lines 406-409 deleted

### LPK-C1+C2. Linux build scripts: wrong paths + Go compiler — FIXED
- **Previously marked fixed — verified NOT fixed 2026-02-26**
- **Files**: `apps/witnessd_cli/packaging/linux/scripts/build-{deb,rpm,appimage}.sh` + `packaging/linux/rpm/witnessd.spec`
- **Combined scope** (these must be fixed together — same 3 files + spec):
  - `PROJECT_ROOT` set via `cd "${SCRIPT_DIR}/../../.."` — resolves to `apps/witnessd_cli/` (3 levels up), NOT workspace root (needs 5 levels: `"${SCRIPT_DIR}/../../../../.."`). All `${PROJECT_ROOT}/platforms/linux/` references point to non-existent path.
  - All 3 scripts check `command -v go`. `build-appimage.sh` runs `go build` for Go source dirs that don't exist.
  - RPM spec file has `BuildRequires: golang >= 1.21` and uses `go build`.
- **Full fix scope**: (1) Fix `PROJECT_ROOT` to 5 levels up. (2) Update all `platforms/linux/` refs to `apps/witnessd_cli/packaging/linux/`. (3) Replace `go` with `cargo` in dependency checks. (4) Rewrite `build-appimage.sh` build section to use `cargo build --release --package witnessd_cli`. (5) Update `witnessd.spec` BuildRequires and %build section. (6) Fix binary names to match Cargo output (`witnessd`, `witnessd-native-messaging-host`). | Effort: large

### ~~REL-C1. Release workflow produces NO platform binaries~~ [x] FIXED

---

## High

- [x] **H-001** `[security]` `ipc/crypto.rs:143` — Sequence counter advances before decrypt verification
  <!-- pid:seq_advance | batch:4 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `rx_sequence.fetch_add(2)` consumes slot even on AES-GCM decrypt fail. One bad packet permanently desynchronizes session.
  Note: Comment at :148-150 claims intentional for timing oracle prevention, but logic is inverted — advances *before* decrypt. The server (`server.rs:138-144`) already closes connections on decrypt failure (`break`), making the desync moot in practice.
  Fix: Two options — **(a) Preferred**: Use `load(SeqCst)` to peek expected sequence, perform decrypt+sequence check, then `compare_exchange_strong` to advance only on success. Handles concurrent access correctly. **(b) Simpler**: Document that decrypt failure MUST be connection-fatal (already true in server.rs). Add `debug_assert!` or comment-level invariant. Do NOT use `load()` then `fetch_add()` — that creates a TOCTOU race under concurrent access. | Effort: small

- [x] **H-002** `[security]` `ipc/crypto.rs:64` — AES-256-GCM expanded key not zeroized `→ SYS-001`
  <!-- pid:missing_zeroize | batch:4 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `cipher: Aes256Gcm` round key survives drop. Only `key_bytes` zeroized. Session key persists in memory after teardown.
  Fix: Enable aes-gcm `zeroize` feature flag in Cargo.toml. Verify the crate version in Cargo.lock supports this feature (aes-gcm >= 0.10 does). | Effort: small

- [x] **H-003** `[security]` `ipc/server.rs:260` — IPC socket world-accessible
  <!-- pid:socket_perms | batch:4 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `IpcServer::bind()` creates socket with default umask. `SecureUnixSocket` at `unix_socket.rs:72-96` correctly sets 0o600 but uses `std::os::unix::net::UnixListener` (sync), while `IpcServer` uses `tokio::net::UnixListener` (async).
  Note: Cannot use `SecureUnixSocket` directly due to sync/async mismatch. Brief TOCTOU window between bind and chmod is standard practice and acceptable.
  Fix: Add `#[cfg(unix)] { std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?; }` immediately after `UnixListener::bind()` at line 260. | Effort: small

- [x] **H-004** `[security]` `keyhierarchy/verification.rs:157` — Certificate "verification" checks byte lengths only
  <!-- pid:crypto_bypass | batch:8 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `verify_session_certificate_bytes()` checks master_pubkey(32), session_pubkey(32), cert_signature(64) lengths only. No Ed25519 verify. Function name misleads callers.
  Note: Function lacks parameters (no session_id, created_at, document_hash) to perform real verification — it's structurally incapable of crypto verify. `verify_session_certificate()` (lines 11-31) does real Ed25519 verify on `SessionCertificate` structs.
  Fix: Rename to `validate_cert_byte_lengths()`. Add doc comment warning that this does NOT perform cryptographic verification. Audit all callers to ensure they also call `verify_session_certificate()`. | Effort: small

- [x] **H-005** `[security]` `sentinel/ipc_handler.rs:182` — CreateFileCheckpoint skips path validation
  <!-- pid:path_traversal | batch:2 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `handle_create_checkpoint()` uses `fs::canonicalize` directly while all other IPC handlers call `validate_path()`. IPC client can checkpoint /etc/passwd.
  Fix: Replace `std::fs::canonicalize(&path)` with `super::helpers::validate_path(&path)?` | Effort: small

- [x] **H-006** `[security]` `sentinel/helpers.rs:400` — Path validation blocklist incomplete
  <!-- pid:path_traversal | batch:2 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `validate_canonical_path()` blocks /etc/, /var/root/, /System/ only.
  Note: On macOS, `/etc` is a symlink to `/private/etc`, so `canonicalize("/etc/foo")` yields `/private/etc/foo` — bypasses the `/etc/` check entirely.
  Fix: Platform-aware blocklist. **macOS**: add `/private/etc/`, `/private/var/root/`, `/Library/`. **Linux**: add `/proc/`, `/dev/`, `/sys/`, `/root/`, `/boot/`. **Both**: keep existing entries, add `/sbin/`, `/bin/`. Long-term: consider allowlist approach. | Effort: small

- [x] **H-007** `[security]` `tpm/windows.rs:414` — Windows TPM provider is a stub (public key)
  <!-- pid:fake_tpm_key | batch:5 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `public_key` filled with 32 bytes of TPM random, not actual asymmetric key. All Windows attestations unverifiable. `create_primary_srk()` exists at :560 but is not wired to `try_init()`.
  Note: Related to H-008 (sign is also a stub) and M-039 (TODOs document this). All three are the same root cause: Windows TPM integration incomplete.
  Impact: `hardware_backed: true` is a false claim | Fix: Wire existing `create_primary_srk()` into `try_init()`, parse TPM2B_PUBLIC response for the public key. Short-term alternative: set `supports_attestation: false` until properly implemented. | Effort: large

- [x] **H-008** `[security]` `tpm/windows.rs:541` — Windows TPM provider is a stub (signing)
  <!-- pid:fake_tpm_sign | batch:5 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `sign_payload` = `SHA256(random || data)` in software. Random is included in output — anyone can reproduce the "signature". No private key involved.
  Note: Requires H-007 (real TPM key) before TPM2_Sign can work.
  Impact: Windows attestation signatures trivially forgeable | Fix: Short-term: set `supports_attestation: false`. Long-term: implement TPM2_Sign with loaded key after H-007. | Effort: large

- [x] **H-009** `[security]` `tpm/secure_enclave.rs:560` — Seal uses XOR cipher, no MAC `→ SYS-008`
  <!-- pid:malleable_seal | batch:5 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  XOR with `SHA256(ECDSA-sig)` repeating every 32 bytes. No authentication. Ciphertext trivially malleable.
  Fix: ChaCha20-Poly1305 AEAD under new version byte (e.g., `5`; current is `4` at line 571). Keep old XOR unseal path for version `4` blobs to enable migration. On unseal of a v4 blob, re-seal as v5 immediately. | Effort: medium

- [x] **H-010** `[security]` `sealed_identity.rs:337` — Software wrap: weak key derivation + unauthenticated XOR `→ SYS-008`
  <!-- pid:weak_wrap | batch:8 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `SHA256(machine_salt || constant)` as XOR key. `machine_salt` = `SHA256("witnessd-machine-salt-v1" || device_id || hostname)` — all inputs public/guessable. Master seed extractable by anyone who knows the hostname and device_id.
  Note: **Two problems**: (1) cipher lacks authentication (→ SYS-008), (2) key derivation uses only guessable inputs. Upgrading to AEAD alone is insufficient — the key material itself is weak.
  Fix: (1) Generate a random 256-bit salt, store it in the sealed blob header. (2) Derive key via HKDF(ikm=machine_salt, salt=random_salt, info="witnessd-software-wrap-v2"). (3) Encrypt with ChaCha20-Poly1305 AEAD. (4) Use version byte `0x02` (current is `0x01`). Keep v1 unwrap for migration. Also zeroize the wrap key (→ SYS-001). | Effort: medium

- [x] **H-011** `[security]` `rfc/time_evidence.rs:452` — Blank Roughtime samples pass validation `→ SYS-004`
  <!-- pid:missing_validation | batch:6 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  Roughtime sample validation (lines 452-461) only checks `server.is_empty()`. All-zero public_key, signature, nonce, and midpoint_us pass. Fake samples count toward Enhanced tier.
  Fix: Add non-zero checks: `public_key`, `signature`, `nonce` must not be all-zero; `midpoint_us != 0`; optionally cap `radius_us` (e.g., reject > 60s). | Effort: small

- [x] **H-012** `[security]` `rfc/vdf.rs:282` — Calibration signature never cryptographically verified
  <!-- pid:missing_sig_verify | batch:6 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `CalibrationAttestation::validate()` checks non-empty/non-zero but never verifies signature. Forged calibration inflates `iterations_per_second`, defeats VDF time-lower-bound.
  Fix: **Phased approach.** (1) Short-term: rename `validate()` to document it's structural-only. Add separate `verify_signature(authority_pubkey: &[u8; 32]) -> Result<()>` method for callers who have an authority key. Add doc-link pointing callers to where crypto verification should happen. (2) Long-term: implement calibration authority key pinning and signing infrastructure. Do NOT block production readiness on the authority infrastructure — the structural validation + documentation is the immediate fix. | Effort: small (phase 1) / large (phase 2)

- [ ] **H-013** `[security]` `fingerprint/storage.rs:260` — Storage key colocated with encrypted data
  <!-- pid:key_colocation | batch:7 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `.storage_key` file in same dir as encrypted profiles. Read access = full decrypt. Encryption is security theater.
  Fix: **Phased.** Phase 1: Add `StorageKeyProvider` trait with platform-specific implementations and file-based fallback. Phase 2: Implement macOS Keychain, DPAPI, libsecret backends. Phase 3: Migration logic. Interim mitigation: existing chmod 600 on key file (line 275) is already in place. | Effort: large

- [x] **H-014** `[security]` `fingerprint/storage.rs:235` — export_json leaks consent-protected voice data
  <!-- pid:consent_bypass_export | batch:7 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `export_json()` serializes full `AuthorFingerprint` including voice biometrics as plaintext JSON. No consent re-check against `ConsentManager`.
  Impact: Silent exfiltration of biometric data | Fix: Clone fingerprint and set `voice = None` before serializing in default `export_json()`. Add `export_json_full(consent_manager: &ConsentManager)` for workflows that need voice data. Do NOT rely on the `consent_given` boolean alone — it could be spoofed since it's stored in the profile itself. | Effort: small

- [x] **H-015** `[security]` `wal.rs:469` — WAL scan_to_end accepts unverified entries
  <!-- pid:wal_no_verify | batch:8 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  Post-crash WAL reopens and chains to unverified entries. Tampered entries become trusted chain base.
  Fix: During `scan_to_end()`, verify each entry: (1) check `entry.prev_hash` matches `state.last_hash` (chain linkage), (2) verify cumulative hash consistency, (3) verify Ed25519 signature (verifying key derivable from `state.signing_key`). On first invalid entry, truncate to last valid entry and log warning. This preserves "append from last valid point" semantic. | Effort: medium

- [x] **H-016** `[security]` `keyhierarchy/session.rs:396` — Ratchet recovery uses unauthenticated XOR `→ SYS-008`
  <!-- pid:unsafe_crypto | batch:8 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  XOR with no MAC for ratchet recovery blob (32-byte ratchet state + 8-byte plaintext ordinal). Bit-flip silently accepted — attacker forks ratchet to earlier state.
  Fix: ChaCha20-Poly1305 AEAD (crate already in deps). Encrypt both ratchet state and ordinal (ordinal leaks info about checkpoint count). Add version byte prefix. Blob grows from 40 to ~57 bytes (12 nonce + 41 ciphertext + 16 tag) — acceptable. | Effort: medium

- [x] **H-017** `[concurrency]` `sentinel/helpers.rs:192+213` — Lock ordering violation: signing_key vs sessions
  <!-- pid:lock_ordering | batch:2 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `handle_change_event_sync` holds `sessions.write()` (line 192) while acquiring `signing_key.read()` (line 213). `focus_document_sync` acquires in opposite order (signing_key first, but clones and drops before sessions). Not a current deadlock since `focus_document_sync` doesn't hold both simultaneously, but fragile.
  Fix: In `handle_change_event_sync`, clone the signing key via `signing_key.read().clone()` before line 192 (before acquiring sessions write lock). This matches the `focus_document_sync` pattern and eliminates nested lock acquisition. | Effort: small

- [x] **H-018** `[concurrency]` `platform/macos/synthetic.rs` + `platform/macos/keystroke.rs` — HID callback dead code, dual-layer always false-flags
  <!-- pid:hid_unregistered | batch:5 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `hid_input_callback` in `synthetic.rs:159-192` is marked `#[allow(dead_code)]` — never registered as IOHIDManager callback. `HID_KEYSTROKE_COUNT` stays 0. `validate_dual_layer` (synthetic.rs:211) flags all sessions as synthetic after 6 keystrokes because HID count never increments.
  Note: `validate_dual_layer` is only called from tests, not from keystroke capture hot path. `KeystrokeMonitor` already has its own event source verification.
  Fix: **Preferred**: Remove or `#[cfg(test)]`-gate `validate_dual_layer`. Remove dead `hid_input_callback` and `#[allow(dead_code)]`. If HID monitoring is needed later, implement as a separate subsystem with proper IOHIDManager lifecycle. | Effort: medium

- [x] **H-019** `[error_handling]` `wal.rs:250` — WAL verify: unbounded allocation from file data
  <!-- pid:oom_from_file | batch:8 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `vec![0u8; entry_len as usize]` where entry_len is u32 from file. Corrupt/malicious WAL triggers 4 GB alloc. Same pattern in `scan_to_end()` (:482) and `truncate()` (:338).
  Fix: Add `const MAX_ENTRY_SIZE: u32 = 16 * 1024 * 1024;` guard before all three allocation sites. Return `WalError::CorruptedEntry` (or new `WalError::EntryTooLarge(u32)` variant). | Effort: small

- [x] **H-020** `[error_handling]` `sentinel/helpers.rs:131` — hex::decode falls back to zero session ID `→ SYS-005`
  <!-- pid:silent_error | batch:2 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `.ok()` on hex decode → all-zero session_id_bytes. Same pattern at :207 in `handle_change_event_sync` and core.rs:510 in `start_witnessing`.
  Fix: Return error on invalid hex. Log warning and skip WAL creation for that session. Apply consistently across all three locations. | Effort: small

- [x] **H-021** `[error_handling]` `sentinel/ipc_handler.rs:120` — Serialize failure returns hollow success `→ SYS-005`
  <!-- pid:silent_serialize | batch:2 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `serde_json::to_string(&report).unwrap_or_default()` → `success: true` with empty `attestation_report`. (Actual line is :120, not :162 as originally reported.)
  Fix: Replace `unwrap_or_default()` with `?` propagation. On serialization failure, return error response to client. | Effort: small

- [x] **H-022** `[error_handling]` `ipc/server.rs:209` — Encode failure leaves client hanging forever
  <!-- pid:client_hang | batch:4 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `encode_for_protocol` fails → server logs error, sends nothing. Client blocks on read_exact indefinitely.
  Fix: Attempt to send `IpcMessage::Error` response. If that also fails to encode, use a hardcoded fallback error string. Either way, `break` after the error to close the connection. | Effort: small

- [x] **H-023** `[performance]` `sentinel/core.rs:314` — Write lock per-keystroke on activity_accumulator
  <!-- pid:rwlock_hot_path | batch:2 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  RwLock::write() serializes all concurrent readers on every keystroke event.
  Note: At human typing speeds (5-10 Hz), the write lock is held very briefly (~μs). The same pattern exists for `voice_collector` (:315) and `mouse_idle_stats` (:326). Practical contention is unlikely at human speeds.
  Fix: **Low priority.** Intermediate step: switch to `parking_lot::RwLock` for lower overhead. Full fix (atomic counters with batch-merge) warranted only if profiling shows contention. | Effort: medium

- [x] **H-024** `[performance]` `platform/macos/keystroke.rs:344` — RwLock::write in CGEventTap callback
  <!-- pid:rwlock_event_tap | batch:5 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `MacOSKeystrokeCapture::start()` callback acquires `RwLock::write()` on `stats` at line 344. macOS auto-disables slow taps (~1s accumulated delay).
  Note: `KeystrokeMonitor` (lines 191-201) already uses `AtomicU64::fetch_add` correctly — use the same pattern.
  Fix: Replace `RwLock<SyntheticStats>` with three `Arc<AtomicU64>` fields matching `KeystrokeMonitor`'s pattern. | Effort: small

- [ ] **H-025** `[performance]` `fingerprint/voice.rs:190` — 100x SHA-256 per 3 keystrokes in MinHash
  <!-- pid:crypto_hot_path | batch:7 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `add_ngram()` (line 190) calls `hash_with_seed` (SHA-256) 100 times per trigram. Triggers every 3 alphabetic characters, not every keystroke. Still ~33 crypto ops per character for non-security purpose.
  Fix: Replace SHA-256 with `SipHash` via `std::hash::Hasher` (already in stdlib, no new dep). Seed becomes the SipHash key. Add version field to `NgramSignature` for forward compatibility with existing profiles. | Effort: medium

- [x] **H-026** `[performance]` `wal.rs:209` — fsync on every WAL entry
  <!-- pid:fsync_hot_path | batch:8 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `sync_all()` after every append in per-event hot path. 1-50ms latency per batch on HDD.
  Fix: **Phased.** Phase 1: Replace `sync_all()` with `sync_data()` (fdatasync — skips metadata, cheaper). Phase 2: Add configurable batch sync — `sync_data()` every N entries or M milliseconds, with explicit flush on checkpoint/session-end. Keep current behavior as default for correctness. Document the durability tradeoff for batch mode. | Effort: medium

- [x] **H-027** `[performance]` `checkpoint/chain.rs:540` — summary() re-verifies entire chain + VDF
  <!-- pid:expensive_summary | batch:3 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `summary()` calls `verify()` at line 540. `verify()` → `verify_detailed()` → recomputes all VDF proofs. O(n * VDF_cost). Status/UI queries trigger full chain reverification.
  Fix: **Preferred**: Remove `chain_valid` from `summary()` entirely, or make it `Option<bool>` defaulting to `None`. Let callers call `verify()` explicitly when needed. **Alternative**: Cache verification result in `Cell<Option<bool>>`, set by `verify()`, cleared by any mutation method (`commit`, `commit_entangled`, `commit_rfc`, `load`). | Effort: small

- [x] **H-028** `[security]` `analysis/behavioral_fingerprint.rs:189` — Forgery detection skips interval filter `→ SYS-004`
  <!-- pid:unvalidated_input | batch:9 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `detect_forgery` (line 189) computes intervals without filtering. `from_samples` (line 58) filters `> 0.0 && < 5000.0`. Inconsistent.
  Impact: Negative intervals from out-of-order timestamps corrupt CV/skewness → forgery evasion
  Fix: Apply same `.filter(|&i| i > 0.0 && i < 5000.0)` to `detect_forgery` interval computation | Effort: small

- [x] **H-029** `[security]` `analysis/labyrinth.rs:314` — Integer overflow in embedding params `→ SYS-004`
  <!-- pid:integer_overflow | batch:9 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `(dim - 1) * delay` overflows usize in release if LabyrinthParams from deserialized config. Same risk at line 288: `orig_idx_i = i * delay + (dim - 1) * delay`.
  Fix: Validate `LabyrinthParams` at `analyze_labyrinth` entry: `max_embedding_dim <= 20`, `max_delay <= 50`. Additionally use `checked_mul`/`saturating_mul` at line 314 as defense-in-depth. | Effort: small

- [ ] **H-030** — **Merged into C-003** (same code block, lines 155-163 of `native_messaging_host.rs`)

- [x] **H-031** `[error_handling]` `native_messaging_host.rs:240` — Bare mutex unwrap at 5 sites — **REOPENED**
  <!-- pid:unwrap_on_io | batch:10 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `.lock().unwrap()` at lines 240, 257, 310, 346, 369. Single panic poisons mutex, permanently kills NMH.
  Fix: `.lock().unwrap_or_else(|p| p.into_inner())` at all 5 sites. Note: `into_inner()` exposes potentially inconsistent state, but `Session` contains simple scalar fields — stale data is strictly better than crashing. | Effort: small

- [x] **H-032** `[security]` `native_messaging_host.rs:387` — Unbounded jitter interval accumulation
  <!-- pid:unbounded_vec | batch:10 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `session.jitter_intervals.extend_from_slice(&valid)` grows without cap. Malicious browser extension OOMs host.
  Fix: Cap at 100,000 entries (`MAX_JITTER_INTERVALS`). When cap is reached, drain oldest entries before appending new ones (ring buffer behavior) — recent intervals are more valuable for behavioral analysis than early ones. | Effort: small

- [x] **H-033** `[error_handling]` `cmd_export.rs:151+165` — Jitter serialization failure → null evidence `→ SYS-005`
  <!-- pid:silent_serialize | batch:10 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `serde_json::to_value(s.export()).unwrap_or(Value::Null)` at two sites. User thinks evidence is included.
  Fix: Use `eprintln!("Warning: ...")` + `Value::Null` fallback (warn-and-continue). Full error propagation with `?` is acceptable for "maximum" tier but too aggressive for "enhanced" tier where jitter is supplementary. | Effort: small

- [x] **H-034** `[security]` `cmd_export.rs:115` — Session discovery via raw substring match
  <!-- pid:substring_match | batch:10 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `content.contains(&abs_path_str)` matches path anywhere in session file. Wrong session silently embedded in evidence.
  Fix: Parse JSON via `serde_json::from_str::<serde_json::Value>`, compare `value["document_path"]` field. | Effort: small

- [x] **H-035** `[error_handling]` `fingerprint/storage.rs:155` — Voice deletion skips corrupt profiles `→ SYS-005`
  <!-- pid:silent_skip | batch:7 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `if let Ok(mut fp) = self.load(&id)` skips profiles failing decrypt. On consent revocation, voice data persists.
  Impact: Biometric data deletion guarantee violated
  Fix: On decrypt failure, delete the entire file and remove from index. Log warning: "Profile {id} deleted (could not decrypt to verify voice data removal)". Return collected warnings/errors so caller knows which profiles were force-deleted. | Effort: small

- [x] **H-036** `[error_handling]` `fingerprint/consent.rs:127` — Consent request flow incomplete
  <!-- pid:consent_stub | batch:7 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `request_consent()` sets `first_requested` timestamp but (1) never calls `self.save()?` to persist it, and (2) always returns `Ok(false)`.
  Note: The doc comment (line 125-126) says "Caller must display `CONSENT_EXPLANATION` and call `grant_consent`/`deny_consent` based on user input." The design intent is correct — the engine library should NOT prompt users directly (would break GUI apps, tests). The function is meant to record "consent was requested" and return "not yet granted."
  Fix: (1) Add `self.save()?` after setting `first_requested` to persist the timestamp. (2) Rename to `begin_consent_request()` to clarify it initiates the flow rather than completing it. (3) Add doc comment explaining return value: `Ok(false)` = "consent not yet granted, caller must prompt user." Do NOT add an interactive prompt here — that belongs in the CLI layer, not the engine. | Effort: small

- [x] **H-037** `[correctness]` `platform/macos/mouse_capture.rs:130` — Inverted is_idle flag corrupts mouse classification
  <!-- pid:inverted_flag | batch:5 | verified:true | first:2026-02-26 | last:2026-02-26 -->
  `let is_idle = keyboard_active.load(Ordering::SeqCst)` — logic is inverted. When keyboard IS active, mouse events are tagged as `idle_jitter`. When keyboard IS idle, mouse events are tagged as active. All macOS sessions have wrong mouse event classification.
  Note: **Escalated from M-036.** This is a correctness bug affecting every macOS session, not a code quality issue.
  Fix: Change to `let is_idle = !keyboard_active.load(Ordering::SeqCst)` | Effort: small

### Existing HIGH (preserved)
- [x] **REL-H1** No code signing for release artifacts — `.github/workflows/release.yml` — FIXED (Sigstore provenance)
  Note: Workflow already has `permissions: id-token: write` and `attestations: write` (lines 19-20), suggesting Sigstore intent.
  Fix: Add `uses: actions/attest-build-provenance@v2` in the build job after artifact upload. This provides cryptographic provenance via Sigstore without managing keys. Platform-native signing (Apple/Windows) can be added later as a separate enhancement. | Effort: medium
### ~~REL-H3~~ [x] FIXED | ~~REL-H4~~ [x] FIXED | ~~BE-H6~~ [x] FIXED | ~~PROTO-H2~~ [x] FIXED

### PROTO-H1. Protocol crate uses deprecated thread_rng() — FIXED
- **Previously marked fixed — verified NOT fixed 2026-02-26**
- **Audit Note**: `rand = "0.8"` at `crates/witnessd_protocol/Cargo.toml:25`. 3 production call sites use `thread_rng()`: `evidence.rs:33`, `evidence.rs:79`, `identity.rs:142`. Test files already use `OsRng`.
- **Fix**: Replace `thread_rng()` with `OsRng` at all 3 production call sites (`OsRng` is already used in test files and is cryptographically stronger). Do NOT upgrade to rand 0.9 — `ed25519-dalek 2.1` depends on `rand_core 0.6` (rand 0.8). Upgrading rand without also upgrading ed25519-dalek creates a version conflict. The `OsRng` fix achieves the goal (removing deprecated API) without the dependency risk.

### CI-H1. Security workflow silently ignores failures — FIXED
- **Previously marked fixed — verified NOT fixed 2026-02-26**
- **Audit Note**: 6 `continue-on-error: true` at lines 33, 69, 73, 77, 134, 165 in `.github/workflows/security.yml`. Also `|| true` at lines 45 and 152.
- **Fix**: **Phased approach.** (1) Remove `continue-on-error` from TruffleHog (line 134) — verified secrets must always fail CI. (2) Remove job-level `continue-on-error` from cargo-audit (line 33) and fix `|| true` (line 45). (3) For cargo-deny, add `--allow` flags for known accepted advisories rather than suppressing all failures. (4) Keep Semgrep upload `continue-on-error` (line 165) — it's just the result upload step, not the scan. (5) Add summary quality gate job. Do NOT remove all `continue-on-error` at once — will break CI on known/accepted advisories.

---

## Medium

### Engine Core
- [x] **M-001** `checkpoint/chain.rs` — 4 commit methods duplicate 12-field struct init `→ SYS-006` | effort:small
  Fix: Extract `Checkpoint::new_base(ordinal, previous_hash, content_hash, content_size, message)` constructor. Each `commit_*` calls it, then sets variant-specific fields.
- [x] **M-002** `checkpoint/chain.rs:387` — Signature verification checks length only, no crypto | effort:small
  Note: **Intentional separation of concerns.** Comment at :388-389 states "Format check only; full crypto verification deferred to key_hierarchy." `keyhierarchy/verification.rs:33-53` does actual Ed25519 verify. This is architectural — the chain verifier validates structure; the key_hierarchy module verifies crypto.
  Fix: Add doc comment linking to `keyhierarchy/verification.rs:33-53` for the crypto verification path. No code behavior change needed.
- [x] **M-003** `checkpoint_mmr.rs:109` — Falls back to relative path when home_dir unavailable | effort:small
  Fix: Return `Result<PathBuf>` instead of falling back to relative path. Let caller decide fallback behavior.
- [x] **M-004** `evidence/builder.rs:248+492+502+534` — Magic floats in evidence scoring; audit trail unclear | effort:small
  Fix: Extract named constants: `HARDWARE_ENTROPY_RATIO`, `MAX_INTERVAL_US`, `MIN_SAMPLES`, `MIN_HURST_SAMPLES`.
- [x] **M-005** `evidence/builder.rs:779` — String comparison for period_type instead of enum | effort:small
  Fix: Convert `period_type` from `String` to an enum with `#[serde(rename_all = "lowercase")]` for backward-compatible deserialization. Test with existing serialized data.
- [x] **M-006** `evidence/packet.rs:191` — Behavioral similarity < 0.7 only warns, verification passes | effort:small
  Note: A hard failure at 0.7 would cause false rejections — behavioral baselines have known variance (time of day, fatigue, injured hand).
  Fix: Add a `warnings: Vec<VerificationWarning>` field to the verification result. Surface the low similarity as a structured warning, not just a log message. Do NOT make this a hard failure. Callers can apply policy based on warnings.

### Sentinel / IPC
- [ ] **M-007** `sentinel/core.rs:522` — WAL append errors silently swallowed `→ SYS-005` | effort:small
  Fix: Log at `warn!` level. A disk-full error propagated as hard failure would prevent all session starts — warn is the safer default.
- [x] **M-008** `sentinel/daemon.rs:273` — IPC shutdown handle immediately dropped (TODO acknowledged) | effort:medium
  Fix: Store `ipc_shutdown_tx` and `ipc_handle` in `DaemonManager` fields. Wire to daemon shutdown signal.
- [x] **M-010** `sentinel/types.rs:274` — Malformed URLs produce misleading domain_hash | effort:small
  Note: The hash is not empty — `hash_string("")` produces a valid hash of the empty string. The real issue: all URLs with no path component share the same domain_hash, and garbage input (non-URLs) is treated as a domain.
  Fix: Validate that the domain part is non-empty and contains at least one dot. Return error or log warning for malformed URLs.
- [x] **M-011** `ipc/server.rs:82` — Dead Bincode protocol branch (unreachable) | effort:small
  Fix: Remove the dead `if protocol == WireProtocol::Bincode { ... }` branch and associated `first_message_pending`/`first_len` variables.
- [x] **M-012** `ipc/server.rs:100` — Rate limiter bypassed by multiple connections (TODO acknowledged) | effort:medium
  Fix: Shared `Arc<Mutex<RateLimiter>>` passed into connection handler.
- [x] **M-013** `ipc/crypto.rs:177` — RateLimiter allocates String key per check | effort:small
  Fix: Use `&'static str` keys (category strings are all literals) or an enum-based key.

### Key Hierarchy / WAL / Identity
- [x] **M-014** `wal.rs:324` — truncate() re-signs entries without verifying originals first | effort:small
  Fix: Verify each entry's signature before re-signing. On invalid entry, abort truncation with error. Need recovery path for case where WAL is partially corrupt.
- [x] **M-015** `keyhierarchy/session.rs:22+82` — Session start logic duplicated 2x `→ SYS-006` | effort:small
  Fix: Extract common body into `fn start_session_inner(signing_key: &SigningKey, ...) -> Result<Session>`. Both public functions call it.
- [x] **M-016** `keyhierarchy/migration.rs:100` — Third copy of session establishment `→ SYS-006` | effort:small
  Fix: Delegate to `start_session_inner` from M-015. The migration path adds `session_seed.zeroize()` (line 148) — ensure the helper includes this.
- [x] **M-017** `keyhierarchy/session.rs:280` — TPM quote serialize failure → empty Vec silently | effort:small
  Fix: Change `unwrap_or_default()` to `.ok()` wrapped in `Some` — store `None` on failure instead of `Some(vec![])`. An empty `Vec<u8>` in `Some` is semantically misleading.
- [x] **M-018** `sealed_identity.rs:132` — provider_type uses Debug format (unstable repr) | effort:small
  Note: `{:?}` output has no stability guarantee across Rust versions. This value is persisted on disk.
  Fix: Use stable string: `"secure_enclave"` / `"tpm2"` / `"software"`. Handle both old (Debug format) and new (stable string) during `load_blob()` for migration.

### Fingerprint / Biometrics
- [x] **M-020** `fingerprint/activity.rs:675` — Hurst exponent hardcoded 0.5 placeholder in evidence | effort:medium
  Fix: Call `crate::analysis::calculate_hurst_rs()` on interval data. Fall back to 0.5 on too-few-samples. Gate behind minimum sample count for performance.
- [x] **M-021** `fingerprint/activity.rs:703` — Full VecDeque cloned on every fingerprint query + broken cache | effort:small
  Note: **Two bugs.** (1) When `dirty == true`, the entire `VecDeque` is cloned into a `Vec`. (2) The `dirty` flag is NEVER set to `false` after recompute — the cache never works, every call recomputes.
  Fix: (1) Use `self.samples.make_contiguous()` and pass as slice instead of cloning. (2) Set `self.dirty = false` after recompute. Requires changing `current_fingerprint(&self)` to `current_fingerprint(&mut self)`, or using `Cell`/`RefCell` for interior mutability on the cache.
- [x] **M-022** `fingerprint/consent.rs:100` — Consent version not validated on load | effort:small
  Fix: After loading, compare `record.consent_version` with `CONSENT_VERSION`. If different, set status to `ConsentStatus::NotRequested` to force re-consent.
- [x] **M-023** `fingerprint/comparison.rs:261` — O(n^2) pairwise comparisons without caching | effort:medium
  Note: For typical use (< 100 fingerprints), O(n^2) is fine. Over-engineering risk.
  Fix: Add guard: if `n > 500`, return error or sample. Do NOT add spatial indexing — premature optimization.

### RFC / Wire Types
- [ ] **M-025** `rfc/biology.rs:601` — PinkNoise power values are hardcoded approximations | effort:medium
  Fix: Add `low_freq_power` and `high_freq_power` fields to `analysis::pink_noise::PinkNoiseAnalysis` from actual DFT computation. Current approximation is mathematically consistent — low risk of wrong conclusions.
- [x] **M-026** `rfc/time_evidence.rs` — hex_bytes serde duplicated in 3 rfc files `→ SYS-006` | effort:small
  Fix: Extract to shared `rfc::serde_helpers` module or `crate::codec::hex_serde`. Change from private `mod hex_bytes` to `pub(crate)`.
- [x] **M-027** `rfc/jitter_binding.rs:656` — lyapunov_exponent always 0.0 (same root as C-005) | effort:medium
  Fix: See C-005. Make `lyapunov_exponent` field `Option<f64>` in both `LabyrinthStructure` and the wire format.

### Analysis
- [x] **M-028** `analysis/behavioral_fingerprint.rs:203` — CV threshold 0.2 vs documented 0.3 | effort:small
  Note: The 0.2 threshold is a **conservative forgery detection floor** (minimize false positives). The 0.3 value in the comment is the **typical human minimum**. The gap is intentional.
  Fix: Update the comment to explain: "Threshold 0.2 is conservative for forgery detection. Human typing typically > 0.3-0.4. The gap reduces false positives for slow/regular typists." Do NOT raise threshold to 0.3.
- [x] **M-029** `analysis/behavioral_fingerprint.rs:68` — Double Vec clone for mean/std_dev | effort:small
  Note: Same pattern at lines 197-198 in `detect_forgery`. `statrs::Statistics` trait's `mean()`/`std_dev()` consume `self`.
  Fix: Compute manually with single pass (sum, sum_of_squares) or use iterator-based API. Apply to both sites.
- [x] **M-030** `analysis/labyrinth.rs:432` — Division by zero when all distances identical | effort:small
  Note: `r_min == r_max == 0.0` can't happen (filtered at line 416), but `r_min == r_max > 0.0` produces identical `(log_r, log_c)` points causing regression failure.
  Fix: Guard: if `r_max == r_min`, return 0.0 early.
- [x] **M-031** `analysis/labyrinth.rs:263` — FNN threshold 15.0 undocumented magic number | effort:small
  Fix: Extract as named constant `FNN_DISTANCE_THRESHOLD` with doc comment citing Kennel et al. 1992.
- [x] **M-032** `analysis/error_topology.rs:156` — O(n*m) contains() instead of HashSet | effort:small
  Fix: `let error_set: HashSet<usize> = error_indices.iter().copied().collect();` before the loop.
- [x] **M-033** `analysis/hurst.rs:114+240` — DFA/RS clamp ranges different | effort:small
  Note: RS clamps to [0.0, 1.0], DFA to [0.0, 2.0]. **Mathematically correct**: R/S Hurst ∈ [0,1], DFA alpha can reach 2.0. Shared validity range [0.55, 0.85] is intentional.
  Fix: Add comment explaining the mathematical distinction. No code change needed.
- [x] **M-034** `analysis/pink_noise.rs:239` — linear_regression duplicated verbatim in hurst.rs `→ SYS-006` | effort:small
  Fix: Extract to `crate::analysis::stats::linear_regression()`.

### Platform / TPM
- [x] **M-035** `platform/mod.rs:14-20` — Blanket `#[allow(dead_code)]` on platform modules | effort:small
  Note: Violates CLAUDE.md convention ("targeted, never blanket"). macOS module does not have this.
  Fix: Remove blanket allows. Add targeted `#[allow(dead_code)]` on specific items. May reveal genuinely dead code.
- [x] **M-037** `tpm/secure_enclave.rs:455` — Monotonic counter silently resets to 0 on corrupt file | effort:small
  Fix: Distinguish "file not found" (first run, counter=0 correct) from "file exists but corrupt/truncated" (return error). On corruption, return error — a silent reset defeats anti-rollback.
- [x] **M-038** `tpm/secure_enclave.rs:664` — Attestation proof hash computed but redundant with signature | effort:small
  Fix: Remove dead `attestation_proof` computation. The ECDSA signature already provides attestation.
- [ ] **M-039** `tpm/windows.rs:413` — Two TODOs document unimplemented security invariants | effort:medium
  Note: Same root cause as H-007/H-008 (Windows TPM is a stub). Tracked there. Resolve M-039 when H-007/H-008 are fixed.

### CLI
### ~~M-040~~ [x] FIXED — getrandom fallback to all-zeros for packet ID
- [x] **M-041** `cmd_watch.rs:373` — auto_checkpoint reloads config from disk on every call | effort:small
  Fix: Cache config in watcher state. Reload on explicit user action or longer interval (e.g., once per minute).
- [x] **M-042** `smart_defaults.rs:328` — Deprecated `Utc.timestamp_nanos()` (clippy warning) | effort:small
  Fix: Replace with `Utc.timestamp_nanos_opt(*ts).map(|dt| dt.format(...)).unwrap_or_else(|| ...)`. Pattern already used elsewhere.

---

## Eliminated (False Positives)
These issues were removed during the fix-review pass (2026-02-26) after source code verification.

- ~~**M-009**~~ `sentinel/ipc_handler.rs:509` — "Redundant hex encode/decode round-trip"
  **Reason**: No hex encode/decode round-trip exists in the file. Line 509 contains `anomaly_count: 0,` in an error fallback. The file uses `hex::encode` for serialization but never `hex::decode`. Stale finding from prior audit.

- ~~**M-019**~~ `fingerprint/activity.rs:212` — "select_nth_unstable_by reuse corrupts percentile values"
  **Reason**: Algorithm is correct for monotonically increasing indices. Percentiles [0.05, 0.25, 0.50, 0.75, 0.95] produce monotonically increasing indices. `select_nth_unstable_by` guarantees `buf[idx]` is correct regardless of prior calls when indices increase, because each call partitions the buffer such that elements below idx are ≤ and elements above are ≥.

- ~~**M-024**~~ `rfc/biology.rs:551` — "Zero weights pass validation → division issues downstream"
  **Reason**: Division by zero is already guarded. `calculate_score()` (line 476) checks `if total_weight > 0.0` before dividing. When all weights are 0.0, score remains 0.0 and division is skipped.

---

## Quick Wins
| ID | Sev | File:Line | Issue | Effort |
|----|-----|-----------|-------|--------|
| C-002 | CRIT | macos/keystroke.rs:227 | Move ready_tx after run_loop store (both impls) | small |
| C-003 | CRIT | native_messaging_host.rs:155 | Fix ends_with + remove URL fallback (two bugs, one block) | small |
| C-004 | CRIT | voice.rs:316 | Add with_consent(bool), update callers | small |
| C-006 | CRIT | puf.rs:17 | Zeroize+ZeroizeOnDrop, skip PathBuf, remove Clone (both PUF structs) | small |
| C-007 | CRIT | migration.rs:82 | Zeroizing wrapper + seed.zeroize() | small |
| H-001 | HIGH | crypto.rs:143 | CAS after decrypt or document fatal-on-failure | small |
| H-002 | HIGH | crypto.rs:64 | Enable aes-gcm zeroize feature | small |
| H-003 | HIGH | server.rs:260 | set_permissions(0o600) after bind | small |
| H-004 | HIGH | verification.rs:157 | Rename to validate_cert_byte_lengths | small |
| H-005 | HIGH | ipc_handler.rs:182 | Add validate_path() call | small |
| H-006 | HIGH | helpers.rs:400 | Platform-aware blocklist (/private/etc/, /proc/, etc.) | small |
| H-011 | HIGH | time_evidence.rs:452 | Non-zero checks on crypto fields | small |
| H-014 | HIGH | storage.rs:235 | Strip voice data unless consent verified | small |
| H-017 | HIGH | helpers.rs:192 | Clone signing_key before sessions write lock | small |
| H-019 | HIGH | wal.rs:250 | MAX_ENTRY_SIZE guard (3 sites) | small |
| H-020 | HIGH | helpers.rs:131 | Return error on invalid hex (3 sites) | small |
| H-021 | HIGH | ipc_handler.rs:120 | Replace unwrap_or_default with ? | small |
| H-022 | HIGH | server.rs:209 | Send error + break on encode fail | small |
| H-024 | HIGH | macos/keystroke.rs:344 | AtomicU64 counters (match KeystrokeMonitor) | small |
| H-027 | HIGH | checkpoint/chain.rs:540 | Remove chain_valid from summary() or cache | small |
| H-028 | HIGH | behavioral_fingerprint.rs:189 | Add interval filter (match from_samples) | small |
| H-029 | HIGH | labyrinth.rs:314 | Bounds-check params + checked_mul | small |
| H-031 | HIGH | native_messaging_host.rs:240 | unwrap_or_else at 5 sites | small |
| H-032 | HIGH | native_messaging_host.rs:387 | Cap + drain oldest on overflow | small |
| H-033 | HIGH | cmd_export.rs:151 | eprintln warning on serialize fail | small |
| H-034 | HIGH | cmd_export.rs:115 | Parse JSON, compare document_path | small |
| H-035 | HIGH | storage.rs:155 | Delete file on decrypt fail + log | small |
| H-036 | HIGH | consent.rs:127 | Add save(), rename to begin_consent_request | small |
| H-037 | HIGH | mouse_capture.rs:130 | Add ! to keyboard_active.load() | small |

---

## Skipped / Won't Fix

### M6. Linux platform device HashMap unbounded [-]
- **Files**: `platform/linux.rs:432,905`
- **Reason**: Linux-specific; cannot test/verify on macOS

### L2. Unmaintained transitive dependencies [-]
- `bincode` (RUSTSEC-2025-0141), `derivative` (RUSTSEC-2024-0388), `instant` (RUSTSEC-2024-0384), `rustls-pemfile` (RUSTSEC-2025-0134)
- **Reason**: All transitive; fixes depend on upstream crate updates

### L3. RSA timing sidechannel [-]
- **Reason**: Transitive via TPM crates; no direct RSA usage

### L5. writersproof queue no pagination [-]
- **Reason**: Queue bounded by offline attestation count

### P-M2. HMAC length prefix truncates to u32 [-]
- **Reason**: Wire format change would break compatibility

### CFG-M9. reqwest outdated, bincode is RC [-]
- **Reason**: Migration tracked separately

### LPK-H1. D-Bus policy file doesn't exist [-]
  Note: No `dbus-witnessd.conf` or equivalent policy XML found. Still missing as of 2026-02-26.
### ~~LPK-M3. IBus service file doesn't exist~~ [-] NOW EXISTS
  IBus service files verified present: `packaging/linux/systemd/witnessd-ibus.xml`, `witnessd-ibus.service`, `debian/witnessd-ibus.install`.

---

## Coverage
<!-- suggest | Updated: 2026-02-26 | Languages: rust | Files: 77 | Batches: 10 | Waves: 2 | Coverage: 100% -->
<!-- reviewed:apps/witnessd_cli/src/main.rs:2026-02-26 -->
<!-- reviewed:apps/witnessd_cli/src/native_messaging_host.rs:2026-02-26 -->
<!-- reviewed:apps/witnessd_cli/src/cmd_export.rs:2026-02-26 -->
<!-- reviewed:apps/witnessd_cli/src/cmd_track.rs:2026-02-26 -->
<!-- reviewed:apps/witnessd_cli/src/cmd_watch.rs:2026-02-26 -->
<!-- reviewed:apps/witnessd_cli/src/cmd_verify.rs:2026-02-26 -->
<!-- reviewed:apps/witnessd_cli/src/cmd_config.rs:2026-02-26 -->
<!-- reviewed:apps/witnessd_cli/src/cmd_fingerprint.rs:2026-02-26 -->
<!-- reviewed:apps/witnessd_cli/src/cmd_status.rs:2026-02-26 -->
<!-- reviewed:apps/witnessd_cli/src/smart_defaults.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/sentinel/core.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/sentinel/daemon.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/sentinel/ipc_handler.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/sentinel/helpers.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/sentinel/types.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/checkpoint.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/checkpoint_mmr.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/evidence/builder.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/evidence/packet.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/ipc/async_client.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/ipc/server.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/ipc/crypto.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/ipc/messages.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/ipc/secure_channel.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/ipc/sync_client.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/ipc/unix_socket.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/ipc/mod.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/platform/macos.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/platform/mod.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/platform/synthetic.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/platform/broadcaster.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/tpm/windows.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/tpm/secure_enclave.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/rfc/biology.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/rfc/jitter_binding.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/rfc/time_evidence.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/rfc/vdf.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/fingerprint/activity.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/fingerprint/comparison.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/fingerprint/consent.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/fingerprint/storage.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/fingerprint/voice.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/keyhierarchy/manager.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/keyhierarchy/session.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/keyhierarchy/puf.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/keyhierarchy/verification.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/keyhierarchy/recovery.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/keyhierarchy/migration.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/wal.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/sealed_identity.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/analysis/active_probes.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/analysis/behavioral_fingerprint.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/analysis/error_topology.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/analysis/hurst.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/analysis/labyrinth.rs:2026-02-26 -->
<!-- reviewed:crates/witnessd_engine/src/analysis/pink_noise.rs:2026-02-26 -->
