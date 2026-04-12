# Audit Resolution Prompts

**Generated**: 2026-04-07
**Source**: `todo.md` consolidated findings (session 4, 677 files)
**Scope**: 4 open CRITICAL, 6 open HIGH, 1 false-positive closure

---

## Tier 1: Haiku

Mechanical, well-scoped fixes. Each is a single-file change with clear before/after.

### Parallel Group H-A (no shared files)

---

#### Prompt H-1: H-014/H-020 -- Verdict cap on invalid declaration

**Todo item**: H-014 `[security]` `verify/verdict.rs:71`: Invalid declaration logged but verdict NOT downgraded to V2LikelyHuman as the inline comment states. H-020 is the same root cause found in a separate batch.

**File**: `crates/cpoe/src/verify/verdict.rs`

**Context**: The function `compute_verdict()` (line 15) has an empty if-block at lines 71-74:

```rust
if !declaration_valid {
    // Declaration is missing or has an invalid signature; the best
    // attainable verdict is V2LikelyHuman.
}
```

This block has no body. The `capped` variable at line 80 (`let capped = !declaration_valid || seals_structural_only;`) does partially enforce the cap by preventing `V1VerifiedHuman` in the forensics branch (line 91) and the final signed-packet branch (line 111). However, the empty if-block is misleading dead code.

**Task**:
1. Read `crates/cpoe/src/verify/verdict.rs` in full.
2. Verify that the `capped` variable at line 80 already prevents `V1VerifiedHuman` when `!declaration_valid` in all code paths (forensics branch at line 91, and final branch at line 111).
3. If fully enforced: remove the empty if-block (lines 70-74) since `capped` handles it. Keep the `capped` variable and its comment.
4. If NOT fully enforced (edge case found): add the missing enforcement so invalid declaration can never produce `V1VerifiedHuman`.
5. Add a unit test: call `compute_verdict()` with `declaration_valid = false`, all other inputs set to produce `V1VerifiedHuman` (valid signature, plausible duration with VDF, consistent key provenance, forensics returning `V1VerifiedHuman`). Assert the result is `V2LikelyHuman`, not `V1VerifiedHuman`.
6. Check for and avoid code duplication: do not add a second capping mechanism if `capped` already handles it.
7. Follow existing patterns: the file uses `ForensicVerdict` from `authorproof_protocol::forensics`, tests in `crates/cpoe/src/verify/` use `#[test]` with `use super::*`.

**Verification**: Run `cargo test -p cpoe --lib -- verify::verdict`. All existing tests must pass. New test must pass. Run `cargo clippy -p cpoe -- -D warnings` and confirm 0 warnings.

**Definition of done**: The empty if-block is gone (or filled with enforcement), a test proves the cap, no dead code added, no regressions.

---

#### Prompt H-2: H-019 -- NaN guard on IKI-surprisal correlation

**Todo item**: H-019 `[error_handling]` `cpoe_jitter_bridge/session.rs` (IKI autocorrelation): sqrt called without is_finite guard on variance; NaN on floating-point edge case.

**File**: `crates/cpoe/src/forensics/advanced_metrics.rs`

**Context**: Function `compute_iki_surprisal_correlation()` at line 118. Lines 130-135:

```rust
let iki_var = iki_sample.iter().map(|x| (x - iki_mean).powi(2)).sum::<f64>();
let surp_var = surp_sample.iter().map(|x| (x - surp_mean).powi(2)).sum::<f64>();

if iki_var <= 0.0 || surp_var <= 0.0 {
    return 0.0;
}
```

The guard at line 133 checks `<= 0.0` but does NOT check `is_finite()`. If input arrays contain NaN values, the sums of squares will be NaN, and `NaN <= 0.0` evaluates to `false`, so NaN passes through. Line 143 then computes `covariance / (iki_var.sqrt() * surp_var.sqrt())` which propagates the NaN into signed metrics.

**Task**:
1. Read `crates/cpoe/src/forensics/advanced_metrics.rs` in full.
2. Add `is_finite()` checks alongside the existing `<= 0.0` guard at line 133. The idiomatic pattern used elsewhere in this codebase (see `cadence.rs:145`, `cadence.rs:164`) is:
   ```rust
   if !iki_var.is_finite() || !surp_var.is_finite() || iki_var <= 0.0 || surp_var <= 0.0 {
       return 0.0;
   }
   ```
3. Also verify `iki_mean` and `surp_mean` cannot be NaN when the function reaches line 130 (they use `mean()` from `crate::utils::stats`; check if `mean()` guards against NaN).
4. Do NOT add guards to other sqrt sites in this file or other files; they have their own guards already (verified: `cadence.rs:145`, `cadence.rs:164`, `analysis.rs:419` all already check `is_finite()`).
5. Add a test: pass an array containing `f64::NAN` and verify the function returns `0.0`, not NaN.

**Verification**: Run `cargo test -p cpoe --lib -- forensics::advanced_metrics`. All tests pass. `cargo clippy -p cpoe -- -D warnings` shows 0 warnings.

**Definition of done**: `compute_iki_surprisal_correlation()` never returns NaN regardless of input. One test proves it. No changes outside this function.

---

#### Prompt H-3: H-018 -- Verify sealed_chain AAD as false positive

**Todo item**: H-018 `[security]` `sealed_chain.rs:95`: AES-GCM AAD covers only header fields; payload not included in authenticated data.

**File**: `crates/cpoe/src/sealed_chain.rs`

**Context**: The `save_sealed()` function at line 78 encrypts with AES-256-GCM:
```rust
let ciphertext = cipher.encrypt(
    nonce,
    Payload {
        msg: &plaintext,   // ← this IS the payload
        aad: &header,
    },
)
```

The todo claims "Attacker modifies payload bytes without invalidating GCM authentication tag." This is incorrect. AES-GCM encrypts AND authenticates the `msg` parameter via the GCM authentication tag. The `aad` parameter provides ADDITIONAL authenticated data that is NOT encrypted. Both `msg` and `aad` are authenticated by the tag. Any modification to either the ciphertext or the header will cause decryption to fail at line ~195 (`load_sealed_verified`).

**Task**:
1. Read `crates/cpoe/src/sealed_chain.rs` in full.
2. Confirm that `aes_gcm::Payload { msg, aad }` authenticates BOTH msg and aad via the GCM tag (this is the standard AES-GCM construction per NIST SP 800-38D).
3. Confirm the `load_sealed_verified()` function at line 145 decrypts with the same AAD header, so any tampering of header OR ciphertext causes an auth tag mismatch error.
4. If confirmed: update `todo.md` to mark H-018 as FALSE POSITIVE with the explanation: "AES-GCM authenticates both the encrypted payload (msg) and the additional data (aad) via the authentication tag. The payload IS authenticated; the finding misunderstands AEAD construction."
5. Change `- [-]` to `- [-]` with `-- FALSE POSITIVE 2026-04-07` appended.
6. Do NOT modify any Rust code. This is a documentation-only change.

**Verification**: Read the `aes-gcm` crate documentation or source to confirm AEAD semantics. No code changes, so no test run needed.

**Definition of done**: H-018 marked as FALSE POSITIVE in `todo.md` with clear technical justification. No code changes. Summary table HIGH count decremented by 1.

---

## Tier 2: Sonnet

Moderate complexity: logic fixes, crypto correctness, integration work.

### Parallel Group S-A (no shared files)

---

#### Prompt S-1: C-007/H-015 -- Replace unsafe cipher zeroization with safe API

**Todo item**: C-007 `[security]` `ipc/secure_channel.rs:65`: Cipher cloned without zeroization; unsafe pointer arithmetic in `zeroize_cipher` at line 26. H-015 is the companion finding for the unsafe pointer itself.

**File**: `crates/cpoe/src/ipc/secure_channel.rs`

**Context**: The `zeroize_cipher()` function (line 26) uses unsafe `write_volatile` pointer arithmetic to overwrite the internals of a `ChaCha20Poly1305` cipher:

```rust
fn zeroize_cipher(cipher: &mut ChaCha20Poly1305) {
    let ptr = cipher as *mut ChaCha20Poly1305 as *mut u8;
    let len = std::mem::size_of::<ChaCha20Poly1305>();
    for i in 0..len {
        unsafe { std::ptr::write_volatile(ptr.add(i), 0u8) };
    }
    std::sync::atomic::fence(Ordering::SeqCst);
}
```

Problems:
1. Relies on `ChaCha20Poly1305` being `repr(transparent)` over `GenericArray<u8, U32>`, which is not guaranteed across versions.
2. The compiler may still optimize out the writes despite `write_volatile` in some scenarios.
3. At line 65, `cipher.clone()` creates a second copy of key material that is only zeroized when the sender is dropped, but if the sender leaks (e.g., stored in a `Box` that's forgotten), the clone persists.

The crate already imports `zeroize::{Zeroize, Zeroizing}` (line 11).

**Task**:
1. Read `crates/cpoe/src/ipc/secure_channel.rs` in full.
2. Replace the `zeroize_cipher()` function with a safe approach. The `chacha20poly1305` crate's `ChaCha20Poly1305` does NOT implement `Zeroize` directly. Two options:
   - **Option A** (preferred): Store the key in a `Zeroizing<[u8; 32]>` alongside the cipher. On drop, the `Zeroizing` wrapper handles key zeroization automatically. Remove the cipher clone; instead, create two independent cipher instances from the same key material.
   - **Option B**: Use `zeroize::Zeroize` on the raw bytes via `unsafe { std::slice::from_raw_parts_mut(...) }` but wrap it in a `ZeroizeOnDrop` newtype that is sound.
3. Eliminate `cipher.clone()` at line 65. Instead, create both sender and receiver ciphers independently from the key bytes:
   ```rust
   let sender_cipher = ChaCha20Poly1305::new(&key);
   let receiver_cipher = ChaCha20Poly1305::new(&key);
   ```
   Then zeroize the key immediately. This avoids having two cipher copies where only one is cleaned up on panic.
4. Remove the `zeroize_cipher()` function entirely if no longer needed.
5. Update `Drop` impls for `SecureSender` and `SecureReceiver` (lines 91-96 and the corresponding receiver Drop) to use the new zeroization strategy.
6. Verify all `unsafe` blocks are removed from this file.
7. Existing imports: `chacha20poly1305::{aead::{rand_core::RngCore, Aead, KeyInit, OsRng}, ChaCha20Poly1305, Nonce}`, `zeroize::{Zeroize, Zeroizing}`.
8. Error type: this module uses `SendError<EncryptedMessage>` and `RecvError`, not the crate `Error`.

**Verification**: Run `cargo test -p cpoe --lib -- ipc::secure_channel`. Run `cargo clippy -p cpoe -- -D warnings`. Grep the file for `unsafe` and confirm zero occurrences.

**Definition of done**: No `unsafe` code in `secure_channel.rs`. Key material stored in `Zeroizing<>` wrapper. No cipher clone. Both sender and receiver independently constructed. All existing tests pass. Zero clippy warnings.

---

#### Prompt S-2: H-003 -- Sealed chain nonce determinism

**Todo item**: H-003 `[security]` `sealed_chain.rs:90,95`: AES-GCM nonce does not include document counter; nonce reuse possible across chains sharing same document_id.

**File**: `crates/cpoe/src/sealed_chain.rs`

**Context**: `save_sealed()` (line 78) generates a fully random 12-byte nonce at line 90-91:

```rust
let mut nonce_bytes = [0u8; 12];
rand::Fill::fill(&mut nonce_bytes, &mut rand::rng());
```

If the encryption key is derived from `document_id`, then two calls to `save_sealed` with the same `document_id` (and thus the same key) use independent random nonces. With 96-bit random nonces under the same key, the birthday bound gives ~2^48 encryptions before a collision is expected. In practice, a single document will see far fewer saves, but the standard recommendation for AES-GCM with random nonces is to limit usage to 2^32 invocations per key.

The `ChainEncryptionKey` struct is defined elsewhere. Check how it is derived and whether a document can realistically accumulate enough saves to approach the birthday bound.

**Task**:
1. Read `crates/cpoe/src/sealed_chain.rs` in full.
2. Find where `ChainEncryptionKey` is created/derived. Check if the key changes per save or is static per document.
3. If the key is static per document: add a monotonic counter to the nonce derivation. Use the first 8 bytes from the counter and 4 random bytes, or use a SIV-like construction:
   ```rust
   // Nonce = counter (8 bytes LE) || random (4 bytes)
   let counter = /* read from header or derive from chain.checkpoints.len() */;
   nonce_bytes[..8].copy_from_slice(&counter.to_le_bytes());
   rand::Fill::fill(&mut nonce_bytes[8..], &mut rand::rng());
   ```
4. If the key changes per save (e.g., HKDF with a fresh salt each time): document this in a code comment, mark H-003 as mitigated by key rotation, and add an assertion that verifies the key is not reused.
5. The nonce format change must be backward-compatible: existing sealed files use 12 random bytes. Either:
   - Bump `SEALED_VERSION` and handle both formats in `load_sealed_verified()`
   - Or add the counter as a separate header field
6. Do NOT modify the AAD structure unless necessary for the counter. The existing AAD (magic + version + nonce + document_id) is correct.
7. Follow existing error patterns: `Error::crypto("message")`, `Error::checkpoint("message")`.

**Verification**: Run `cargo test -p cpoe --lib -- sealed_chain`. All existing tests pass. If version bumped, add a test that loads a v1-format sealed file and verifies backward compatibility. `cargo clippy -p cpoe -- -D warnings` shows 0 warnings.

**Definition of done**: Nonce reuse probability reduced below 2^-32 per document lifetime. Backward-compatible with existing sealed files. No regressions.

---

#### Prompt S-3: H-016 -- Non-blocking keystroke send in CGEventTap callback

**Todo item**: H-016 `[performance]` `platform/macos/keystroke.rs:560`: CGEventTap callback performs synchronous channel send per keystroke in hot path.

**File**: `crates/cpoe/src/platform/macos/keystroke.rs`

**Context**: Inside the CGEventTap callback closure (around line 560):

```rust
if tx.send(keystroke).is_err() {
    running.store(false, Ordering::SeqCst);
}
```

`tx` is a `std::sync::mpsc::Sender<KeystrokeEvent>`. The `send()` call is synchronous and will block if the receiver's buffer is full or if the receiver is slow. macOS disables a CGEventTap if the callback blocks for more than ~15ms (undocumented but observed threshold). At 100+ WPM with key-up/key-down events, this creates backpressure risk.

**Task**:
1. Read `crates/cpoe/src/platform/macos/keystroke.rs` in full to understand the callback setup.
2. Replace `tx.send(keystroke)` with `tx.try_send(keystroke)`:
   - If the channel is `std::sync::mpsc::Sender`, it has no `try_send`. Switch to `std::sync::mpsc::sync_channel(BUFFER_SIZE)` which provides `SyncSender::try_send()`, OR use `crossbeam_channel::bounded()` if already in dependencies.
   - Check `Cargo.toml` for existing channel crate dependencies before adding a new one.
3. Define a buffer size constant: `const KEYSTROKE_CHANNEL_CAPACITY: usize = 512;` (sufficient for ~5 seconds of 100 WPM typing).
4. On `try_send` failure (`Full`), increment a dropped-event counter (`AtomicU64`) and continue without blocking. Log dropped count periodically (not per event) via `log::warn!`.
5. On `try_send` failure (`Disconnected`), set `running.store(false, ...)` as before.
6. Do NOT change the receiver side. The sentinel's event loop reads from this channel; it will drain the buffer at its own pace.
7. Maintain the existing `KeystrokeEvent` struct and `KeyEventType` enum unchanged.
8. Follow existing patterns: the file uses `std::sync::atomic::{AtomicBool, AtomicU64, Ordering}`, `log::warn!`.

**Verification**: Run `cargo test -p cpoe --lib -- platform::macos`. All tests pass. `cargo clippy -p cpoe -- -D warnings` shows 0 warnings. If `crossbeam-channel` added, verify it's in `Cargo.toml` and `cargo-deny` passes.

**Definition of done**: CGEventTap callback never blocks on channel send. Dropped events counted and logged. No new dependencies unless necessary. No regressions.

---

#### Prompt S-4: H-024 -- Re-establish encrypted session on async client reconnect

**Todo item**: H-024 `[concurrency]` `ipc/async_client.rs` (approx line 150+): Async client reconnect does not re-establish ChaCha20 session; sends plaintext after reconnect.

**File**: `crates/cpoe/src/ipc/async_client.rs`

**Context**: The `AsyncIpcClient` struct has fields `stream: Option<...>` and `secure_session: Option<SecureSession>`. The `connect()` method (line 102) creates a new stream and calls `establish_secure_session()` to perform ECDH key exchange.

However, there is no `reconnect()` method. If the stream is dropped and a new `connect()` is called, a fresh client is created. The concern is about the case where the stream dies mid-session and the caller attempts to reuse the client without re-running key exchange.

**Task**:
1. Read `crates/cpoe/src/ipc/async_client.rs` in full.
2. Identify all code paths where `self.stream` could become `None` or invalid after initial `connect()`:
   - Explicit `disconnect()` method (if any)
   - Error handling in `send_request()` that drops the stream
   - Timeout/EOF conditions
3. For each such path, verify that `self.secure_session` is also set to `None` so the client cannot send plaintext on a stale or new connection.
4. If there IS a reconnect path that preserves `secure_session` while replacing `stream`: fix it by setting `self.secure_session = None` whenever `self.stream` is replaced, and require `establish_secure_session()` before the next send.
5. Add a guard in `send_request()` (or equivalent send method): if `self.secure_session.is_none()`, return `Err(AsyncIpcClientError::NotConnected)` instead of sending plaintext.
6. If no reconnect path exists (i.e., the client is always constructed fresh via `connect()`): add a code comment documenting this invariant and verify no caller reuses a disconnected client.
7. Error type: `AsyncIpcClientError` enum (defined in the same file).
8. Crypto imports: `p256::ecdh::EphemeralSecret`, `p256::PublicKey`, custom `SecureSession`.

**Verification**: Run `cargo test -p cpoe --lib -- ipc::async_client`. All tests pass. `cargo clippy -p cpoe -- -D warnings` shows 0 warnings.

**Definition of done**: No code path can send plaintext on a connection that previously had an encrypted session. Either reconnect re-keys automatically, or the client refuses to send without a session. Test or assertion proves the invariant.

---

## Tier 3: Opus

Architectural decisions, cross-cutting changes, ambiguous requirements.

### Sequential Group O-A (C-003 must complete before H-021 can be unblocked)

---

#### Prompt O-1: C-003 -- COSE_Sign1 verification for EAT CWT tokens

**Todo item**: C-003 `[security]` `rats/eat.rs:75`: `decode_eat_cwt()` parses EAT payload without COSE_Sign1 verification.

**Files**:
- Primary: `crates/cpoe/src/rats/eat.rs`
- Related: `crates/cpoe/src/rats/mod.rs`, `crates/cpoe/src/rats/types.rs`
- Dependency: `coset` crate (COSE implementation)

**Context**: The function `decode_eat_cwt()` (line 79 of `eat.rs`) explicitly states in its doc comment:

```rust
/// This extracts the payload without verifying the signature, which is
/// appropriate when the caller has already verified via a separate path
/// or for inspection/debugging.
```

It calls `coset::CoseSign1::from_slice(bytes)` to parse the COSE structure but never calls `verify_signature()` or equivalent. The companion function `encode_eat_cwt()` (earlier in the file) DOES sign via COSE_Sign1 with Ed25519.

This is a CRITICAL finding because unverified EAT tokens from IPC clients could be forged. H-021 (IPC client EAT acceptance) is blocked on this fix.

**Task**:
1. Read `crates/cpoe/src/rats/eat.rs` in full.
2. Read `crates/cpoe/src/rats/types.rs` to understand `EarToken` structure.
3. Read the `coset` crate's `CoseSign1::verify_signature()` API. The crate is already in `Cargo.toml`. Use the rust-docs MCP server (`search_items` for `verify_signature` in `coset`) if needed.
4. Create a new function `decode_eat_cwt_verified()` that:
   - Takes `bytes: &[u8]` and `trusted_key: &[u8; 32]` (Ed25519 public key)
   - Parses the COSE_Sign1 structure
   - Verifies the signature against `trusted_key` using `coset`'s verification API
   - Only then decodes the payload into `EarToken`
   - Returns `Result<EarToken>` using the crate's `Error::crypto()` for verification failures
5. Keep the existing `decode_eat_cwt()` function for backward compatibility but:
   - Rename it to `decode_eat_cwt_unverified()`
   - Add `#[deprecated(note = "Use decode_eat_cwt_verified() for production; this skips signature verification")]`
   - Or, if no callers outside tests use it, make it `#[cfg(test)]` only
6. Find all callers of `decode_eat_cwt()` across the codebase (grep for `decode_eat_cwt`). Update each caller:
   - If the caller has access to a trusted key: switch to `decode_eat_cwt_verified()`
   - If the caller is in a test: keep using the unverified version
   - If the caller cannot obtain a trusted key: document why and add a `// SECURITY: unverified EAT` comment
7. The signing function `encode_eat_cwt()` uses Ed25519 via the TPM abstraction. Verify that the verification function uses the same algorithm. The COSE header should contain `Algorithm::EdDSA`.
8. Error handling: use `Error::crypto("EAT signature verification failed")` for signature mismatches, `Error::crypto("EAT missing signature")` for unsigned tokens.
9. Do NOT modify `encode_eat_cwt()`.
10. Check existing imports: `coset::{CoseSign1, CoseEncrypt}`, `ed25519_dalek`, `ciborium::Value`.

**Verification**:
- Run `cargo test -p cpoe --lib -- rats`. All tests pass.
- Add at least 2 new tests:
  1. Encode an EAT with `encode_eat_cwt()`, then verify with `decode_eat_cwt_verified()` using the correct public key. Must succeed.
  2. Encode an EAT, then attempt verification with a WRONG public key. Must return `Err`.
- `cargo clippy -p cpoe -- -D warnings` shows 0 warnings.
- Grep for remaining `decode_eat_cwt(` calls (without `_verified` or `_unverified` suffix) and confirm zero outside of deprecated wrapper.

**Definition of done**: All production code paths verify EAT COSE_Sign1 signatures before trusting the payload. Unverified path is deprecated or test-only. H-021 can be unblocked after this fix (IPC clients now have verified EAT tokens). No regressions.

---

### Parallel Group O-B (independent of O-A)

---

#### Prompt O-2: C-002 -- Bitcoin block header verification for OTS proofs

**Todo item**: C-002 `[security]` `anchors/ots.rs:430`: Bitcoin block header cross-check not implemented; OTS proofs accepted without Bitcoin confirmation.

**Files**:
- Primary: `crates/cpoe/src/anchors/ots.rs`
- Related: `crates/cpoe/src/anchors/mod.rs` (AnchorProvider trait), `crates/cpoe/src/anchors/types.rs`

**Context**: The `OpenTimestampsProvider::verify()` method (line 511) explicitly warns:

```rust
log::warn!(
    "ots verify: Bitcoin block header cross-check not implemented; \
     performing structural check only"
);
```

It currently:
1. Parses the attestation path
2. Checks that a `Verify` step exists
3. Runs the hash operations to get a final 32-byte hash
4. Returns `Err(AnchorError::Unavailable("Bitcoin block header cross-check not yet implemented"))` -- so callers already handle the "not implemented" case

The `verify_attestation_path()` function (line 393) processes `AttestationStep` operations (SHA256, RIPEMD160, prepend, append, Verify) and produces a candidate block header hash.

**Task**:
1. Read `crates/cpoe/src/anchors/ots.rs` in full.
2. Read `crates/cpoe/src/anchors/types.rs` for `Proof`, `ProofStatus`, `AnchorError`.
3. Understand the OTS verification flow: the attestation path produces a 32-byte hash that should match the Merkle root in a Bitcoin block header.
4. Implement Bitcoin block header fetching and verification:
   - **API choice**: Use a public Bitcoin block explorer API (e.g., `blockstream.info/api/block-height/{height}` or `blockchain.info/rawblock/{hash}?format=hex`). The `reqwest::Client` is already available on `self.client`.
   - **Block header structure**: 80 bytes: version (4) + prev_block (32) + merkle_root (32) + timestamp (4) + bits (4) + nonce (4). The merkle_root field is what we compare against.
   - **Verification steps**:
     a. The OTS attestation path's `Verify` step should reference a Bitcoin block height or block hash. Check how the OTS format encodes this (it's in the attestation step metadata).
     b. Fetch the block header from a trusted source.
     c. Extract the 32-byte merkle_root from the header.
     d. Compare the attestation path's final hash against the merkle_root.
     e. Optionally: verify the block header's own proof-of-work (double-SHA256 < target from bits field).
5. Design considerations:
   - **Multiple API endpoints**: Allow fallback between 2-3 block explorers for reliability. Store URLs in a config constant, not hardcoded in the verify function.
   - **Caching**: Block headers are immutable once confirmed. Cache verified headers by block hash to avoid repeated API calls.
   - **Timeout**: Use the existing `self.client` which already has timeout configured (verified via `build_http_client()`).
   - **Offline mode**: If no block explorer is reachable, return `AnchorError::Unavailable` (current behavior) rather than failing hard. The structural check is still valuable.
6. Update the `verify()` method to:
   - Perform structural check (existing code)
   - Attempt Bitcoin block header fetch and verification
   - Return `Ok(true)` on successful block header match
   - Return `Ok(false)` on block header mismatch (forged proof)
   - Return `AnchorError::Unavailable` if block explorer unreachable (graceful degradation)
7. Remove or update the `log::warn!` about "not implemented."
8. Follow existing error patterns: `AnchorError::Unavailable(String)`, `AnchorError::VerificationFailed(String)`.
9. Do NOT add new crate dependencies for Bitcoin parsing; the header is simple enough to parse with manual byte slicing and `sha2::Sha256` (already in deps).
10. Check for code duplication: `verify_attestation_path()` already runs the hash chain; reuse it, don't duplicate.

**Verification**:
- Run `cargo test -p cpoe --lib -- anchors::ots`. All existing tests pass.
- Add tests:
  1. Unit test: given a known block header (hardcoded bytes), verify merkle_root extraction is correct.
  2. Unit test: given a valid attestation path result and matching merkle_root, verify returns `Ok(true)`.
  3. Unit test: given a mismatched merkle_root, verify returns `Ok(false)`.
  4. Integration test (optional, may need `#[ignore]`): fetch a real block header from blockstream.info.
- `cargo clippy -p cpoe -- -D warnings` shows 0 warnings.

**Definition of done**: OTS proofs verified against actual Bitcoin block headers when network available. Graceful fallback to structural-only when offline. CLU-001 compound risk reduced (C-002 component resolved). No regressions.

---

#### Prompt O-3: C-005 -- Require external trust anchor for evidence verification

**Todo item**: C-005 `[security]` `evidence/packet.rs:29`: Self-signed verification used as default; no external trust anchor required.

**Files**:
- Primary: `crates/cpoe/src/evidence/packet.rs`
- Related: all callers of `Packet::verify()` across the codebase
- Related: `crates/cpoe/src/ffi/` (FFI verification functions), `apps/cpoe_cli/src/` (CLI verify command)

**Context**: `Packet::verify()` (line 29) delegates to `verify_inner(None)`, which uses the packet's own embedded `signing_public_key` for baseline verification. The doc comment (lines 25-28) explains this:

```rust
/// Baseline verification uses the packet's own `signing_public_key`, so it only proves
/// internal consistency (self-signed), not authenticity. Use [`verify_with_trusted_key`]
/// to supply an externally trusted public key for stronger assurance.
```

`Packet::verify_with_trusted_key()` (line 36) already exists and takes a `trusted_public_key: [u8; 32]`. The infrastructure for external trust anchors is already built; the issue is that `verify()` (self-signed) is the default and most callers use it.

**Task**:
1. Read `crates/cpoe/src/evidence/packet.rs` in full.
2. Grep the entire codebase for all callers of `.verify(` on `Packet` (or similar types). Categorize each caller:
   - **Must have trusted key**: FFI verification functions exposed to Swift/Kotlin (these are the primary verification entry points for end users)
   - **Self-signed acceptable**: Internal engine operations (checkpoint creation, evidence building) where the signing key is local and known
   - **Test code**: Can use either
3. Design the migration:
   - **Do NOT remove `verify()`**. Self-signed verification is a documented feature for the Free tier (offline local witnessing without cloud anchoring). Removing it would break the product.
   - **Deprecate `verify()` in favor of explicit naming**: Rename `verify()` to `verify_self_signed()` to make the security posture explicit. Add `#[deprecated(note = "Use verify_with_trusted_key() for production verification")]` to the old name.
   - **Add a new `verify()` that requires a key**: The new default `verify()` takes a trusted key parameter. This is a breaking API change for the crate, but since `publish = false` (local crate), this is acceptable.
   - OR: Keep both methods, but add a `log::warn!("Self-signed verification provides no authenticity guarantee")` in `verify_self_signed()` so it's auditable.
4. For each FFI verification function (grep `ffi_verify` or similar):
   - Determine where the trusted key comes from (WritersProof CA, beacon certificate, local keychain)
   - If a trusted key is available: switch to `verify_with_trusted_key()`
   - If no trusted key available (Free tier): use `verify_self_signed()` and document the limitation
5. For the CLI `verify` command: check if it accepts a `--trusted-key` flag. If not, add one. Default behavior should warn about self-signed verification.
6. Do NOT change the verification logic itself (the `verify_inner` function). Only change the API surface and caller behavior.
7. Follow existing naming conventions: the crate uses `snake_case` for methods, `Error::crypto()` for errors.

**Verification**:
- Run `cargo test --workspace --lib`. All tests pass (callers updated).
- `cargo clippy --workspace -- -D warnings` shows 0 warnings.
- Grep for remaining `.verify(` calls on `Packet` and confirm each is either:
  - Using `verify_with_trusted_key()` (preferred), or
  - Using `verify_self_signed()` with a documented reason, or
  - In test code

**Definition of done**: Self-signed verification is explicitly named and warns/logs. Production verification paths use trusted keys where available. API change is backward-compatible (old method exists but deprecated). No regressions. The security posture of each verification call site is documented.

---

## Dependency Map and Execution Order

```
Parallel Group H-A (Haiku):     H-1, H-2, H-3    ← all independent, run simultaneously

Parallel Group S-A (Sonnet):    S-1, S-2, S-3, S-4  ← all independent, run simultaneously
  S-1 touches ipc/secure_channel.rs only
  S-2 touches sealed_chain.rs only
  S-3 touches platform/macos/keystroke.rs only
  S-4 touches ipc/async_client.rs only

Sequential Group O-A (Opus):    O-1 (C-003) → then H-021 unblocked
  O-1 touches rats/eat.rs and its callers

Parallel Group O-B (Opus):      O-2, O-3    ← independent of each other and O-A
  O-2 touches anchors/ots.rs only
  O-3 touches evidence/packet.rs and all its callers (broad but non-overlapping with O-1/O-2)
```

**Recommended execution order**:
1. Start H-A (all 3 Haiku prompts in parallel)
2. Start S-A (all 4 Sonnet prompts in parallel)
3. Start O-1 and O-2 in parallel; start O-3 after S-A completes (O-3 touches FFI callers that S-1 also touches via `ipc/`)
4. After O-1 completes: H-021 can be addressed in a follow-up

**Post-resolution**: Run `cargo test --workspace --lib` and `cargo clippy --workspace -- -D warnings` as a final gate. Update `todo.md` summary table counts.
