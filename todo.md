# CPOP — Unified Todo

## Session State
<!-- suggest | Updated: 2026-03-18 | Domain: code | Languages: rust | Files: 20 CLI | Issues: 42 -->

## Summary
| Severity | Open | Fixed | Skipped |
|----------|------|-------|---------|
| CRITICAL | 0    | 6     | 0       |
| HIGH     | 0    | 18    | 0       |
| MEDIUM   | 10   | 8     | 0       |

## Systemic Issues
- [x] **SYS-001** `non_atomic_key_write` — 3 files — CRITICAL
  Files: `cmd_identity.rs:92`, `cmd_init.rs:54`, `util.rs:172`
  fs::write() then restrict_permissions() is non-atomic. If chmod fails, key file is world-readable.
  Fix: Write to temp file with restrictive umask, then atomic rename.

- [ ] **SYS-002** `toctou_file_ops` — 4 files — HIGH
  Files: `cmd_track.rs:238`, `cmd_track.rs:678`, `cmd_presence.rs:240`, `cmd_export.rs:560`
  File metadata checked, then file read without locking. Race window for replacement/deletion.

- [ ] **SYS-003** `silent_error_swallow` — 4 files — HIGH
  Files: `native_messaging_host.rs:381`, `cmd_track.rs:517`, `cmd_daemon.rs:96`, `native_messaging_host.rs:270`
  Errors converted to defaults or logged without propagation.

## Critical
- [x] **C-001** `[security]` `cmd_track.rs:1266` — Export paths relative, arbitrary file write if CWD controlled
  Impact: Evidence files written to attacker-controlled location | Fix: tracking_dir.join() | Effort: small

- [x] **C-002** `[security]` `native_messaging_host.rs:381` — hex::decode error returns empty vec, bypassing commitment
  Impact: Browser commitment chain bypass | Fix: Return error on decode failure | Effort: small

- [x] **C-003** `[security]` `native_messaging_host.rs:608` — Division by zero in compute_jitter_stats
  Impact: NaN/panic | Fix: Guard with is_empty() | Effort: small

## High
- [x] **H-001** `[security]` `cmd_export.rs:732` — Wire packet profile_uri hardcoded ignoring spec parameter
  Impact: Wrong profile URI for enhanced/maximum tiers | Effort: medium
  Fix: Thread spec_profile_uri, spec_content_tier, spec_attestation_tier through build_wire_packet_from_events

- [x] **H-002** `[security]` `cmd_export.rs:33` — Session lookup string contains() fallback = path injection
  Impact: Wrong session selected | Effort: medium | Fix: Remove string fallback, only match parsed JSON

- [x] **H-003** `[concurrency]` `cmd_track.rs:323` — Keystroke thread panics silently, evidence lost
  Impact: All keystroke data lost | Effort: medium | Fix: catch_unwind in thread loop

- [x] **H-004** `[concurrency]` `cmd_track.rs:374` — Mutex poison at finalization = entire session lost
  Impact: Complete session loss | Fix: into_inner() recovery | Pre-existing fix verified

- [x] **H-005** `[concurrency]` `cmd_track.rs:512` — Database unsynchronized across watcher callbacks
  Impact: SQLite BUSY, checkpoint loss | Fix: retry_on_busy with exponential backoff | Effort: medium

- [x] **H-006** `[performance]` `cmd_track.rs:551` — Debounce HashMap unbounded (memory leak)
  Impact: RAM grows unbounded | Fix: Eviction when >1000 entries | Pre-existing fix verified

- [x] **H-007** `[security]` `cmd_track.rs:567` — Symlink attack in watcher events
  Impact: Checkpoint arbitrary files | Fix: fs::canonicalize() | Pre-existing fix verified

- [x] **H-008** `[concurrency]` `native_messaging_host.rs:256` — Mutex poison recovery silences corruption
  Impact: Corrupted session state used | Fix: unwrap_or_else with logging | Pre-existing fix verified

- [x] **H-009** `[security]` `cmd_verify.rs:352` — HMAC key truncation ambiguous for 64-byte keys
  Impact: Wrong key material used | Fix: Explicit note + first 32 bytes (seed) | Pre-existing fix verified

- [x] **H-010** `[error_handling]` `cmd_verify.rs:23` — Unknown extension routes to db verification
  Impact: Wrong verification path | Fix: Return error for unknown extensions | Pre-existing fix verified

- [x] **H-011** `[error_handling]` `cmd_track.rs:517` — Initial checkpoint errors ignored, zero evidence
  Impact: User unaware | Fix: Per-file warnings + zero-checkpoint warning | Pre-existing fix verified

- [x] **H-012** `[security]` `util.rs:113` — HMAC key not zeroized after SecureStore::open()
  Impact: Key material in memory | Fix: key_vec.zeroize() and hmac_key.zeroize() | Pre-existing fix verified

- [x] **H-013** `[error_handling]` `main.rs:171` — print_long_help().unwrap() panics on IO failure
  Impact: CLI crash | Fix: let _ = ... | Pre-existing fix verified

- [x] **H-014** `[error_handling]` `cmd_daemon.rs:86` — Child process never awaited
  Impact: Daemon failure undetected | Fix: try_wait after 500ms sleep | Effort: medium

- [x] **H-015** `[concurrency]` `cmd_presence.rs:240` — TOCTOU in session modification detection
  Impact: Stale session data | Fix: fs2 exclusive file lock on session | Effort: medium

- [x] **H-016** `[error_handling]` `cmd_presence.rs:104` — debug_assert only, silent in release
  Impact: Counter inconsistency | Fix: Runtime if-check with eprintln | Pre-existing fix verified

- [x] **H-017** `[security]` `cmd_config.rs:211` — Editor path relative, $PATH injection
  Impact: Arbitrary code execution | Fix: which + absolute path resolution | Pre-existing fix verified

- [x] **H-018** `[error_handling]` `cmd_export.rs:85` — SQLite lock contention with daemon
  Impact: Export fails during tracking | Fix: retry_on_busy with exponential backoff | Effort: medium

## Medium
- [x] **M-001** `[validation]` `native_messaging_host.rs:306` — content_hash not validated as hex SHA-256
  Impact: Malformed hash accepted into commitment chain | Fix: Validate 64-char hex | Effort: small

- [x] **M-002** `[correctness]` `native_messaging_host.rs:620` — Jitter response reports accepted count, not stored
  Impact: Browser thinks all jitter was recorded when buffer-full truncation drops samples | Fix: Return stored count | Effort: small

- [x] **M-003** `[validation]` `cmd_attest.rs:97` — Unknown format silently defaults to war_block
  Impact: User typos silently ignored | Fix: Error on unrecognized format | Effort: small

- [x] **M-004** `[error_handling]` `cmd_config.rs:256` — Config edit loop has no retry limit
  Impact: User trapped in infinite loop if config stays broken | Fix: Max 3 retries | Effort: small

- [x] **M-005** `[correctness]` `cmd_commit.rs:80` — Size delta silently clamped on >2GB deltas
  Impact: Checkpoint records incorrect delta without user awareness | Fix: Warn on clamp | Effort: small

- [x] **M-006** `[validation]` `spec.rs:8` — Unknown content tier silently defaults to basic
  Impact: Typo in tier name silently produces wrong tier | Fix: Log warning | Effort: small

- [x] **M-007** `[correctness]` `cmd_fingerprint.rs:24` — min_samples division by zero if config default is 0
  Impact: NaN/panic in progress calculation | Fix: .max(1) guard | Effort: small

- [x] **M-008** `[error_handling]` `cmd_identity.rs:150` — Mnemonic errors silently omitted in JSON mode
  Impact: JSON consumers get no mnemonic field without knowing why | Fix: Add mnemonic_error field | Effort: small

- [ ] **M-009** `[validation]` `smart_defaults.rs:125` — Non-UTF-8 filenames unreachable via text search
  Impact: Files with non-UTF-8 names invisible in selection | Effort: medium

- [ ] **M-010** `[correctness]` `cmd_log.rs:28` — DateTime::from_timestamp_nanos on corrupt DB timestamps
  Impact: Bad dates displayed from corrupted database | Effort: medium

- [ ] **M-011** `[security]` `cmd_init.rs:55` — Public key file written without restrictive permissions
  Impact: Public key readable by other users (low risk for pub key) | Effort: small

- [ ] **M-012** `[error_handling]` `cmd_status.rs:89` — list_files() error silently defaults to empty
  Impact: Database errors masked in status output | Effort: small

- [ ] **M-013** `[validation]` `cmd_fingerprint.rs:188` — Profile error matched by string contains("not found")
  Impact: Brittle error matching, may change with library updates | Effort: small

- [ ] **M-014** `[error_handling]` `cmd_identity.rs:183` — PUF load error silently returns generic message
  Impact: User gets unhelpful error when PUF seed is corrupted | Effort: small

- [ ] **M-015** `[validation]` `cmd_commit.rs:45` — MAX_FILE_SIZE check uses metadata.len() before read
  Impact: TOCTOU race between size check and read (very unlikely) | Effort: small

- [ ] **M-016** `[correctness]` `cmd_status.rs:102` — chain_count silently 0 on read_dir error
  Impact: Permission errors on chains dir masked | Effort: small

- [ ] **M-017** `[validation]` `native_messaging_host.rs:154` — Subdomain matching allows suffix attacks
  Impact: e.g. "evildocs.google.com" would match | Effort: small

- [ ] **M-018** `[error_handling]` `cmd_attest.rs:79` — Declaration prompt reads stdin after piped content consumed
  Impact: EOF on declaration prompt after piped input | Effort: small
