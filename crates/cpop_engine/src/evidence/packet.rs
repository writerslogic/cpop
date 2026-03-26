// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Packet impl block: verification, signing, encoding/decoding, and hashing.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;

use crate::error::Error;
use crate::keyhierarchy;
use crate::tpm;
use crate::vdf;
use crate::DateTimeNanosExt;
use cpop_protocol::codec::{self, Format, CBOR_TAG_CPOP};
use cpop_protocol::rfc;

use super::types::Packet;

impl Packet {
    /// Verify packet integrity: chain hashes, VDF proofs, declaration, hardware, and key hierarchy.
    pub fn verify(&self, _vdf_params: vdf::Parameters) -> crate::error::Result<()> {
        if let Some(last) = self.checkpoints.last() {
            let expected_chain_hash = last.hash.clone();
            if self
                .chain_hash
                .as_bytes()
                .ct_eq(expected_chain_hash.as_bytes())
                .unwrap_u8()
                == 0
            {
                return Err(Error::evidence("chain hash mismatch"));
            }
            if self
                .document
                .final_hash
                .as_bytes()
                .ct_eq(last.content_hash.as_bytes())
                .unwrap_u8()
                == 0
            {
                return Err(Error::evidence("document final hash mismatch"));
            }
            if self.document.final_size != last.content_size {
                return Err(Error::evidence("document final size mismatch"));
            }
        } else if !self.chain_hash.is_empty() {
            return Err(Error::evidence("chain hash present with no checkpoints"));
        }

        let mut prev_hash = String::new();
        for (i, cp) in self.checkpoints.iter().enumerate() {
            if i == 0 {
                // Accept legacy all-zeros OR spec-correct H(CBOR(document-ref))
                let is_legacy_zeros = cp.previous_hash == hex::encode([0u8; 32]);
                let is_valid_hex = cp.previous_hash.len() == 64
                    && cp.previous_hash.chars().all(|c| c.is_ascii_hexdigit());
                if !is_legacy_zeros && !is_valid_hex {
                    return Err(Error::evidence(
                        "checkpoint 0: invalid genesis previous hash",
                    ));
                }
            } else if cp.previous_hash != prev_hash {
                return Err(Error::evidence(format!(
                    "checkpoint {i}: broken chain link"
                )));
            }
            prev_hash = cp.hash.clone();

            if let (Some(iterations), Some(input_hex), Some(output_hex)) = (
                cp.vdf_iterations,
                cp.vdf_input.as_ref(),
                cp.vdf_output.as_ref(),
            ) {
                let input = hex::decode(input_hex)
                    .map_err(|e| Error::evidence(format!("invalid hex: {e}")))?;
                let output = hex::decode(output_hex)
                    .map_err(|e| Error::evidence(format!("invalid hex: {e}")))?;
                if input.len() != 32 || output.len() != 32 {
                    return Err(Error::evidence(format!(
                        "checkpoint {i}: VDF input/output size mismatch"
                    )));
                }
                let mut input_arr = [0u8; 32];
                let mut output_arr = [0u8; 32];
                input_arr.copy_from_slice(&input);
                output_arr.copy_from_slice(&output);
                let proof = vdf::VdfProof {
                    input: input_arr,
                    output: output_arr,
                    iterations,
                    duration: Duration::from_secs(0),
                };
                if !vdf::verify(&proof) {
                    return Err(Error::evidence(format!(
                        "checkpoint {i}: VDF verification failed"
                    )));
                }
            }
        }

        if let Some(decl) = &self.declaration {
            if !decl.verify() {
                return Err(Error::evidence("declaration signature invalid"));
            }
        }

        if let Some(hardware) = &self.hardware {
            if let Err(err) = tpm::verify_binding_chain(&hardware.bindings, &[]) {
                return Err(Error::evidence(format!(
                    "hardware attestation invalid: {:?}",
                    err
                )));
            }
        }

        if let Some(kh) = &self.key_hierarchy {
            let master_pub = hex::decode(&kh.master_public_key)
                .map_err(|e| Error::evidence(format!("invalid master_public_key hex: {e}")))?;
            let session_pub = hex::decode(&kh.session_public_key)
                .map_err(|e| Error::evidence(format!("invalid session_public_key hex: {e}")))?;
            let cert_raw = general_purpose::STANDARD
                .decode(&kh.session_certificate)
                .map_err(|e| Error::evidence(format!("invalid session_certificate base64: {e}")))?;

            if let Some(ref doc_hash_hex) = kh.session_document_hash {
                let session_id_bytes = hex::decode(&kh.session_id)
                    .map_err(|e| Error::evidence(format!("invalid session_id hex: {e}")))?;
                let doc_hash_bytes = hex::decode(doc_hash_hex).map_err(|e| {
                    Error::evidence(format!("invalid session_document_hash hex: {e}"))
                })?;
                if session_id_bytes.len() != 32 {
                    return Err(Error::evidence("session_id must be 32 bytes"));
                }
                if doc_hash_bytes.len() != 32 {
                    return Err(Error::evidence("session_document_hash must be 32 bytes"));
                }
                let mut session_id_arr = [0u8; 32];
                let mut doc_hash_arr = [0u8; 32];
                session_id_arr.copy_from_slice(&session_id_bytes);
                doc_hash_arr.copy_from_slice(&doc_hash_bytes);
                if let Err(err) = keyhierarchy::validate_cert_byte_lengths(
                    &master_pub,
                    &session_pub,
                    &cert_raw,
                    &session_id_arr,
                    kh.session_started,
                    &doc_hash_arr,
                ) {
                    return Err(Error::evidence(format!(
                        "key hierarchy verification failed: {err}"
                    )));
                }
            }

            for sig in &kh.checkpoint_signatures {
                if sig.ratchet_index < 0 {
                    return Err(Error::evidence(format!(
                        "negative ratchet index {}",
                        sig.ratchet_index
                    )));
                }
                let ratchet_index = sig.ratchet_index as usize;
                let ratchet_hex = kh.ratchet_public_keys.get(ratchet_index).ok_or_else(|| {
                    Error::evidence(format!(
                        "ratchet index {} out of range (have {} keys)",
                        ratchet_index,
                        kh.ratchet_public_keys.len()
                    ))
                })?;
                let ratchet_pub = hex::decode(ratchet_hex)
                    .map_err(|e| Error::evidence(format!("invalid ratchet key hex: {e}")))?;
                let checkpoint_hash = hex::decode(&sig.checkpoint_hash)
                    .map_err(|e| Error::evidence(format!("invalid checkpoint_hash hex: {e}")))?;
                let signature = general_purpose::STANDARD
                    .decode(&sig.signature)
                    .map_err(|e| Error::evidence(format!("invalid signature base64: {e}")))?;

                keyhierarchy::verify_ratchet_signature(&ratchet_pub, &checkpoint_hash, &signature)
                    .map_err(|e| {
                        Error::evidence(format!("key hierarchy verification failed: {e}"))
                    })?;
            }
        }

        if let Some(bv) = &self.baseline_verification {
            if let Some(digest) = &bv.digest {
                if let Some(sig) = &bv.digest_signature {
                    let public_key_bytes = self.signing_public_key.ok_or_else(|| {
                        Error::signature("missing signing public key for baseline")
                    })?;
                    let public_key = VerifyingKey::from_bytes(&public_key_bytes)
                        .map_err(|e| Error::signature(format!("invalid public key: {e}")))?;

                    let signature = Signature::from_bytes(
                        sig.as_slice()
                            .try_into()
                            .map_err(|_| Error::evidence("invalid signature length"))?,
                    );

                    let digest_cbor = serde_json::to_vec(digest)
                        .map_err(|e| Error::evidence(format!("digest serialize failed: {e}")))?;

                    public_key.verify(&digest_cbor, &signature).map_err(|e| {
                        Error::signature(format!("baseline digest signature invalid: {e}"))
                    })?;
                }

                let public_key_bytes = self
                    .signing_public_key
                    .ok_or_else(|| Error::signature("missing signing public key"))?;
                let mut hasher = Sha256::new();
                hasher.update(public_key_bytes);
                let actual_fp = hasher.finalize();
                if digest.identity_fingerprint != actual_fp.as_slice() {
                    return Err(Error::evidence("baseline identity fingerprint mismatch"));
                }

                let similarity =
                    crate::baseline::verify_against_baseline(digest, &bv.session_summary);
                if similarity < 0.7 {
                    // Not a hard failure: low behavioral similarity can occur
                    // legitimately (e.g., different device, fatigue, new writing
                    // style). Forensic analysis can weigh this signal later.
                    log::warn!("Behavioral consistency low: {:.2}", similarity);
                }
            }
        }

        Ok(())
    }

    /// Sum elapsed time across all checkpoints.
    pub fn total_elapsed_time(&self) -> Duration {
        let mut total = Duration::from_secs(0);
        for cp in &self.checkpoints {
            if let Some(elapsed) = cp.elapsed_time {
                total += elapsed;
            }
        }
        total
    }

    /// Encode to CBOR with PPP semantic tag (RFC-compliant default).
    pub fn encode(&self) -> crate::error::Result<Vec<u8>> {
        codec::cbor::encode_cpop(self).map_err(|e| Error::evidence(format!("encode failed: {e}")))
    }

    /// Encode in the specified format.
    pub fn encode_with_format(&self, format: Format) -> crate::error::Result<Vec<u8>> {
        match format {
            Format::Cbor => codec::cbor::encode_cpop(self)
                .map_err(|e| Error::evidence(format!("encode failed: {e}"))),
            Format::CborWar => Err(Error::evidence(
                "CborWar format is for attestation results, not evidence packets",
            )),
            Format::Json => serde_json::to_vec_pretty(self)
                .map_err(|e| Error::evidence(format!("encode failed: {e}"))),
        }
    }

    /// Decode a packet, auto-detecting format. Validates CBOR tag if present.
    pub fn decode(data: &[u8]) -> crate::error::Result<Packet> {
        const MAX_EVIDENCE_SIZE: usize = 100 * 1024 * 1024; // 100 MB
        if data.len() > MAX_EVIDENCE_SIZE {
            return Err(Error::evidence(format!(
                "Evidence data too large: {} bytes (max {})",
                data.len(),
                MAX_EVIDENCE_SIZE
            )));
        }

        let format =
            Format::detect(data).ok_or_else(|| Error::evidence("unable to detect format"))?;

        match format {
            Format::Cbor => {
                if !codec::cbor::has_tag(data, CBOR_TAG_CPOP) {
                    return Err(Error::evidence("missing or invalid CBOR PPP tag"));
                }
                codec::cbor::decode_cpop(data)
                    .map_err(|e| Error::evidence(format!("decode failed: {e}")))
            }
            Format::CborWar => Err(Error::evidence(
                "CborWar format is for attestation results, not evidence packets",
            )),
            Format::Json => serde_json::from_slice(data)
                .map_err(|e| Error::evidence(format!("decode failed: {e}"))),
        }
    }

    /// Decode with explicit format (skips format detection).
    pub fn decode_with_format(data: &[u8], format: Format) -> crate::error::Result<Packet> {
        match format {
            Format::Cbor => {
                if !codec::cbor::has_tag(data, CBOR_TAG_CPOP) {
                    return Err(Error::evidence("missing or invalid CBOR PPP tag"));
                }
                codec::cbor::decode_cpop(data)
                    .map_err(|e| Error::evidence(format!("decode failed: {e}")))
            }
            Format::CborWar => Err(Error::evidence(
                "CborWar format is for attestation results, not evidence packets",
            )),
            Format::Json => serde_json::from_slice(data)
                .map_err(|e| Error::evidence(format!("decode failed: {e}"))),
        }
    }

    /// Deterministic SHA-256 hash via untagged CBOR (RFC 8949 Section 4.2).
    pub fn hash(&self) -> crate::error::Result<[u8; 32]> {
        let data = codec::cbor::encode(self)
            .map_err(|e| Error::evidence(format!("packet hash encode failed: {e}")))?;
        Ok(Sha256::digest(data).into())
    }

    /// Hash of ALL packet content excluding only the three signature-related fields
    /// (`verifier_nonce`, `packet_signature`, `signing_public_key`) to avoid
    /// circular dependencies during signing.
    ///
    /// Uses deterministic CBOR serialization of a clone with signature fields cleared,
    /// ensuring every evidence field (behavioral, keystroke, jitter, hardware, forensics,
    /// etc.) is covered. Stripping any field invalidates the signature.
    pub fn content_hash(&self) -> [u8; 32] {
        // Clone and clear signature-related fields to break circular dependency
        let mut signable = self.clone();
        signable.verifier_nonce = None;
        signable.packet_signature = None;
        signable.signing_public_key = None;

        // Deterministic CBOR serialization covers ALL remaining fields
        let data = match codec::cbor::encode(&signable) {
            Ok(d) => d,
            Err(_) => {
                // Fallback: if CBOR encoding fails, hash the structural fields directly.
                // This should never happen with a well-formed Packet.
                log::error!("content_hash: CBOR encoding failed, using structural fallback");
                return self.structural_hash();
            }
        };

        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-packet-content-v3");
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Fallback structural hash covering only core fields (used if CBOR encoding fails).
    fn structural_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-packet-content-v3-fallback");
        hasher.update(self.version.to_be_bytes());
        hasher.update(self.exported_at.timestamp_nanos_safe().to_be_bytes());
        hasher.update((self.strength as i32).to_be_bytes());
        hasher.update(self.document.final_hash.as_bytes());
        hasher.update(self.document.final_size.to_be_bytes());
        hasher.update(self.chain_hash.as_bytes());
        hasher.update((self.checkpoints.len() as u64).to_be_bytes());
        for cp in &self.checkpoints {
            hasher.update(cp.hash.as_bytes());
        }
        hasher.finalize().into()
    }

    /// Signing payload: `SHA-256(content_hash || nonce)` if nonce present,
    /// otherwise just `content_hash`.
    pub fn signing_payload(&self) -> [u8; 32] {
        let content = self.content_hash();
        match &self.verifier_nonce {
            Some(nonce) => {
                let mut hasher = Sha256::new();
                hasher.update(b"witnessd-nonce-binding-v1");
                hasher.update(content);
                hasher.update(nonce);
                hasher.finalize().into()
            }
            None => content,
        }
    }

    /// Set a verifier-provided 32-byte freshness nonce. Clears any existing signature.
    pub fn set_verifier_nonce(&mut self, nonce: [u8; 32]) {
        self.verifier_nonce = Some(nonce);
        self.packet_signature = None;
        self.signing_public_key = None;
    }

    /// Ed25519-sign the packet. Binds to verifier nonce if one is set.
    pub fn sign(&mut self, signing_key: &SigningKey) -> crate::error::Result<()> {
        let payload = self.signing_payload();
        let signature = signing_key.sign(&payload);
        self.packet_signature = Some(signature.to_bytes());
        self.signing_public_key = Some(signing_key.verifying_key().to_bytes());
        Ok(())
    }

    /// Convenience: set nonce and sign in one call.
    pub fn sign_with_nonce(
        &mut self,
        signing_key: &SigningKey,
        nonce: [u8; 32],
    ) -> crate::error::Result<()> {
        self.set_verifier_nonce(nonce);
        self.sign(signing_key)
    }

    /// Verify the packet signature, optionally checking `expected_nonce`
    /// to prevent replay attacks.
    pub fn verify_signature(&self, expected_nonce: Option<&[u8; 32]>) -> crate::error::Result<()> {
        match (expected_nonce, &self.verifier_nonce) {
            (Some(expected), Some(actual)) => {
                if expected.ct_eq(actual).unwrap_u8() != 1 {
                    return Err(Error::signature("verifier nonce mismatch"));
                }
            }
            (Some(_), None) => {
                return Err(Error::signature("expected verifier nonce but none present"));
            }
            // Nonce present but not expected is fine -- signature still binds to it
            (None, Some(_)) => {}
            (None, None) => {}
        }

        let signature_bytes = self
            .packet_signature
            .ok_or_else(|| Error::signature("packet not signed"))?;
        let public_key_bytes = self
            .signing_public_key
            .ok_or_else(|| Error::signature("missing signing public key"))?;

        let public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| Error::signature(format!("invalid public key: {e}")))?;

        let signature = Signature::from_bytes(&signature_bytes);

        let payload = self.signing_payload();
        public_key
            .verify(&payload, &signature)
            .map_err(|e| Error::signature(format!("signature verification failed: {e}")))?;

        Ok(())
    }

    /// Return true if a verifier nonce is set.
    pub fn has_verifier_nonce(&self) -> bool {
        self.verifier_nonce.is_some()
    }

    /// Return true if the packet has both a signature and public key.
    pub fn is_signed(&self) -> bool {
        self.packet_signature.is_some() && self.signing_public_key.is_some()
    }

    /// Return the verifier nonce, if set.
    pub fn get_verifier_nonce(&self) -> Option<&[u8; 32]> {
        self.verifier_nonce.as_ref()
    }

    /// Derive trust tier: `Attested` > `NonceBound` > `Signed` > `Local`.
    pub fn compute_trust_tier(&self) -> super::types::TrustTier {
        use super::types::TrustTier;

        if self.writersproof_certificate_id.is_some() {
            TrustTier::Attested
        } else if self.is_signed() && self.has_verifier_nonce() {
            TrustTier::NonceBound
        } else if self.is_signed() {
            TrustTier::Signed
        } else {
            TrustTier::Local
        }
    }

    /// Convert to `PacketRfc` with integer keys for compact CBOR encoding.
    pub fn to_rfc(&self) -> rfc::PacketRfc {
        rfc::PacketRfc::from(self)
    }
}
