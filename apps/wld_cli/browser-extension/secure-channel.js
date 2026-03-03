/**
 * WritersLogic Secure Channel — ECDH + AES-256-GCM encrypted communication
 *
 * Provides end-to-end encryption between the browser extension and the
 * native messaging host using P-256 ECDH key exchange and AES-256-GCM
 * authenticated encryption with sequence number replay protection.
 *
 * Key ratcheting: after each jitter batch, both sides re-derive the session
 * key using the jitter hash as entropy, providing forward secrecy bound to
 * actual keystroke behavior.
 */

// eslint-disable-next-line no-unused-vars
class SecureChannel {
  constructor() {
    this.keyPair = null;
    this.sessionKey = null; // CryptoKey for AES-256-GCM
    this.rawKeyBytes = null; // Uint8Array(32) for ratcheting
    this.txSequence = 0; // Client sends even: 0, 2, 4, ...
    this.rxSequence = 1; // Server sends odd: 1, 3, 5, ...
    this.ratchetCount = 0;
    this.handshakeComplete = false;
    this.canarySeed = null; // Uint8Array(32)
  }

  /** Generate ephemeral P-256 ECDH keypair. */
  async generateKeyPair() {
    this.keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true, // extractable (need raw public key bytes)
      ["deriveKey", "deriveBits"]
    );
  }

  /** Export public key as uncompressed SEC1 bytes (65 bytes: 0x04 || X || Y). */
  async getPublicKeyBytes() {
    const raw = await crypto.subtle.exportKey("raw", this.keyPair.publicKey);
    return new Uint8Array(raw);
  }

  /** Export public key as base64 for JSON transport. */
  async getPublicKeyBase64() {
    const bytes = await this.getPublicKeyBytes();
    return uint8ToBase64(bytes);
  }

  /**
   * Perform the v2 handshake with the native messaging host.
   * @param {Function} sendRaw - function to send raw JSON to native port
   * @returns {Promise<boolean>} true if handshake succeeded
   */
  async performHandshake(sendRaw) {
    await this.generateKeyPair();
    const clientPubKey = await this.getPublicKeyBase64();

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error("Handshake timed out (3s)"));
      }, 3000);

      this._handshakeResolve = (serverMsg) => {
        clearTimeout(timeout);
        resolve(serverMsg);
      };
      this._handshakeReject = (err) => {
        clearTimeout(timeout);
        reject(err);
      };

      sendRaw({
        type: "hello",
        protocol_version: 2,
        client_pubkey: clientPubKey,
      });
    });
  }

  /**
   * Handle the server's hello_accept message during handshake.
   * Derives session key and verifies the server's confirmation token.
   * @param {Object} message - { server_pubkey, confirm } from NMH
   * @param {Function} sendRaw - function to send raw JSON to native port
   */
  async handleHelloAccept(message, sendRaw) {
    // Guard: reject replayed hello_accept after handshake is complete
    if (this.handshakeComplete) {
      console.warn("Ignoring replayed hello_accept: handshake already complete");
      return;
    }

    try {
      const serverPubKeyBytes = base64ToUint8(message.server_pubkey);
      if (serverPubKeyBytes.length !== 65) {
        throw new Error(`Invalid server pubkey size: ${serverPubKeyBytes.length}`);
      }

      // Import server's public key
      const serverPubKey = await crypto.subtle.importKey(
        "raw",
        serverPubKeyBytes,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
      );

      // Compute ECDH shared secret
      const sharedBits = await crypto.subtle.deriveBits(
        { name: "ECDH", public: serverPubKey },
        this.keyPair.privateKey,
        256
      );
      const sharedSecret = new Uint8Array(sharedBits);

      // Derive session key + canary seed via multi-output HKDF
      const clientPubKeyBytes = await this.getPublicKeyBytes();
      const { sessionKeyBytes, canarySeed } = await this.deriveKeys(
        sharedSecret,
        clientPubKeyBytes,
        serverPubKeyBytes
      );

      this.rawKeyBytes = sessionKeyBytes;
      this.canarySeed = canarySeed;

      // Import as AES-256-GCM CryptoKey
      this.sessionKey = await crypto.subtle.importKey(
        "raw",
        sessionKeyBytes,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );

      // Decrypt and verify server's confirmation
      const confirmCiphertext = base64ToUint8(message.confirm);
      const confirmPlaintext = await this.decryptRaw(confirmCiphertext);
      const expectedConfirm = new TextEncoder().encode("wld-key-confirm-ok");
      if (!constantTimeEqual(confirmPlaintext, expectedConfirm)) {
        throw new Error("Key confirmation failed: server derived different key");
      }

      // Send client's confirmation
      const clientConfirm = await this.encryptRaw(expectedConfirm);
      sendRaw({
        type: "hello_confirm",
        confirm: uint8ToBase64(clientConfirm),
      });

      this.handshakeComplete = true;

      if (this._handshakeResolve) {
        this._handshakeResolve(true);
        this._handshakeResolve = null;
        this._handshakeReject = null;
      }
    } catch (err) {
      if (this._handshakeReject) {
        this._handshakeReject(err);
        this._handshakeResolve = null;
        this._handshakeReject = null;
      }
      throw err;
    }
  }

  /**
   * Multi-output HKDF: derive session key (32 bytes) and canary seed (32 bytes).
   * Info strings match the Rust side exactly for cross-language compatibility.
   */
  async deriveKeys(sharedSecret, clientPubKey, serverPubKey) {
    const salt = new TextEncoder().encode("wld-nmh-v1");

    // Import shared secret as HKDF key material
    const ikm = await crypto.subtle.importKey(
      "raw",
      sharedSecret,
      "HKDF",
      false,
      ["deriveBits"]
    );

    // Session key info: "aes-256-gcm-key" || client_pubkey(65) || server_pubkey(65)
    const keyInfo = concatBytes(
      new TextEncoder().encode("aes-256-gcm-key"),
      clientPubKey,
      serverPubKey
    );

    const sessionKeyBits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: keyInfo },
      ikm,
      256
    );
    const sessionKeyBytes = new Uint8Array(sessionKeyBits);

    // Canary seed info: "canary-seed" || client_pubkey(65) || server_pubkey(65)
    const canaryInfo = concatBytes(
      new TextEncoder().encode("canary-seed"),
      clientPubKey,
      serverPubKey
    );

    const canarySeedBits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: canaryInfo },
      ikm,
      256
    );
    const canarySeed = new Uint8Array(canarySeedBits);

    return { sessionKeyBytes, canarySeed };
  }

  /**
   * Encrypt plaintext bytes. Returns [8-byte seq][12-byte nonce][ciphertext+tag].
   * Matches the Rust SecureSession::encrypt format exactly.
   */
  async encryptRaw(plaintext) {
    const seq = this.txSequence;
    this.txSequence += 2;

    const nonceBytes = new Uint8Array(12);
    const seqBytes = uint64ToLE(seq);
    nonceBytes.set(seqBytes, 4); // nonce[4..12] = seq LE

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonceBytes, tagLength: 128 },
      this.sessionKey,
      plaintext
    );

    const result = new Uint8Array(8 + 12 + ciphertext.byteLength);
    result.set(seqBytes, 0);
    result.set(nonceBytes, 8);
    result.set(new Uint8Array(ciphertext), 20);
    return result;
  }

  /**
   * Decrypt wire bytes. Verifies sequence number for replay protection.
   * Input format: [8-byte seq][12-byte nonce][ciphertext+tag].
   */
  async decryptRaw(data) {
    if (data.length < 36) {
      throw new Error(`Encrypted message too short: ${data.length} bytes`);
    }

    const seq = leToUint64(data.subarray(0, 8));
    if (seq !== this.rxSequence) {
      throw new Error(
        `Sequence mismatch: expected ${this.rxSequence}, got ${seq} (replay?)`
      );
    }

    const nonce = data.subarray(8, 20);
    const ciphertext = data.subarray(20);

    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      this.sessionKey,
      ciphertext
    );

    this.rxSequence += 2;
    return new Uint8Array(plaintext);
  }

  /**
   * Encrypt a JSON message for transport as an encrypted envelope.
   * Returns the envelope object ready to send via native messaging.
   */
  async encrypt(jsonObj) {
    const plaintext = new TextEncoder().encode(JSON.stringify(jsonObj));
    const encrypted = await this.encryptRaw(plaintext);
    return {
      type: "encrypted",
      seq: this.txSequence - 2, // already advanced
      rc: this.ratchetCount,
      payload: uint8ToBase64(encrypted),
    };
  }

  /**
   * Decrypt an encrypted envelope from the native host.
   * @param {Object} envelope - { type: "encrypted", seq, rc, payload }
   * @returns {Object} Decrypted JSON message with validated `type` field
   */
  async decrypt(envelope) {
    if (envelope.rc !== undefined && envelope.rc !== this.ratchetCount) {
      throw new Error(
        `Ratchet count desync: local=${this.ratchetCount}, remote=${envelope.rc}`
      );
    }
    const data = base64ToUint8(envelope.payload);
    const plaintext = await this.decryptRaw(data);

    let parsed;
    try {
      parsed = JSON.parse(new TextDecoder().decode(plaintext));
    } catch (e) {
      throw new Error("Decrypted payload is not valid JSON");
    }

    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Decrypted payload is not a JSON object");
    }
    if (typeof parsed.type !== "string" || parsed.type.length === 0) {
      throw new Error("Decrypted message missing required 'type' field");
    }

    return parsed;
  }

  /**
   * Compute jitter hash for key ratcheting.
   * jitter_hash = SHA-256("wld-jitter-binding" || interval_1_le64 || interval_2_le64 || ...)
   */
  async computeJitterHash(intervals) {
    const prefix = new TextEncoder().encode("wld-jitter-binding");
    const data = new Uint8Array(prefix.length + intervals.length * 8);
    data.set(prefix, 0);
    for (let i = 0; i < intervals.length; i++) {
      data.set(uint64ToLE(intervals[i]), prefix.length + i * 8);
    }
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(hashBuffer);
  }

  /**
   * Ratchet the session key using jitter entropy.
   * new_key = HKDF(IKM=current_key, salt=jitter_hash, info="wld-key-ratchet" || ratchet_count_le64)
   * Must be called AFTER receiving jitter_received ACK from NMH.
   */
  async ratchetWithJitter(jitterHash, newRatchetCount) {
    const info = concatBytes(
      new TextEncoder().encode("wld-key-ratchet"),
      uint64ToLE(newRatchetCount)
    );

    // Import current key as HKDF IKM
    const ikm = await crypto.subtle.importKey(
      "raw",
      this.rawKeyBytes,
      "HKDF",
      false,
      ["deriveBits"]
    );

    const newKeyBits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: jitterHash, info },
      ikm,
      256
    );

    // Zeroize old key
    if (this.rawKeyBytes) {
      this.rawKeyBytes.fill(0);
    }

    this.rawKeyBytes = new Uint8Array(newKeyBits);
    this.sessionKey = await crypto.subtle.importKey(
      "raw",
      this.rawKeyBytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    this.ratchetCount = newRatchetCount;
  }

  /**
   * Compute a dual-channel commitment for a checkpoint.
   * commitment = SHA-256("wld-browser-commit" || session_id || ordinal_le64 || content_hash || timestamp_le64)
   */
  async computeCommitment(sessionId, ordinal, contentHash, timestamp) {
    const data = concatBytes(
      new TextEncoder().encode("wld-browser-commit"),
      new TextEncoder().encode(sessionId),
      uint64ToLE(ordinal),
      new TextEncoder().encode(contentHash),
      uint64ToLE(timestamp)
    );
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return uint8ToHex(new Uint8Array(hashBuffer));
  }

  /**
   * Compute canary token for a checkpoint.
   * canary = HMAC-SHA256(canary_seed, ordinal_le64 || content_hash_bytes)[0..4] as u32 LE
   */
  async computeCanary(ordinal, contentHashHex) {
    const key = await crypto.subtle.importKey(
      "raw",
      this.canarySeed,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const contentHashBytes = hexToUint8(contentHashHex);
    const data = concatBytes(uint64ToLE(ordinal), contentHashBytes);
    const sig = await crypto.subtle.sign("HMAC", key, data);
    const sigBytes = new Uint8Array(sig);
    // u32 LE from first 4 bytes (>>> 0 ensures unsigned)
    return (sigBytes[0] | (sigBytes[1] << 8) | (sigBytes[2] << 16) | (sigBytes[3] << 24)) >>> 0;
  }

  /** True if the encrypted channel is established. */
  get isSecure() {
    return this.handshakeComplete;
  }
}

// --- Utility functions ---

function uint8ToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function uint8ToHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

function hexToUint8(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function uint64ToLE(n) {
  const bytes = new Uint8Array(8);
  // Safe for values up to 2^53 (Number.MAX_SAFE_INTEGER)
  bytes[0] = n & 0xff;
  bytes[1] = (n >> 8) & 0xff;
  bytes[2] = (n >> 16) & 0xff;
  bytes[3] = (n >> 24) & 0xff;
  // For values > 2^32, use division
  const high = Math.floor(n / 0x100000000);
  bytes[4] = high & 0xff;
  bytes[5] = (high >> 8) & 0xff;
  bytes[6] = (high >> 16) & 0xff;
  bytes[7] = (high >> 24) & 0xff;
  return bytes;
}

function leToUint64(bytes) {
  const low =
    bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | ((bytes[3] << 24) >>> 0);
  const high =
    bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | ((bytes[7] << 24) >>> 0);
  return low + high * 0x100000000;
}

function concatBytes(...arrays) {
  let totalLen = 0;
  for (const a of arrays) totalLen += a.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

/** Constant-time comparison to prevent timing side-channels. */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
