// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce as AeadNonce,
};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use sha2::Digest;
use zeroize::{Zeroize, Zeroizing};

use super::crypto::{
    build_cert_data, compute_entangled_nonce, hkdf_expand, RATCHET_ADVANCE_DOMAIN,
    RATCHET_INIT_DOMAIN, SESSION_DOMAIN, SIGNING_KEY_DOMAIN,
};
use super::error::KeyHierarchyError;
use super::types::{
    CheckpointSignature, KeyHierarchyEvidence, MasterIdentity, PUFProvider, RatchetState, Session,
    SessionCertificate, SessionRecoveryState, VERSION,
};

use super::identity::derive_master_private_key;

/// Shared session-creation logic used by all `start_session*` variants.
pub(crate) fn start_session_inner(
    signing_key: &SigningKey,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    let master_pub_key = signing_key.verifying_key().to_bytes().to_vec();

    let mut session_id = [0u8; 32];
    rand::rng().fill_bytes(&mut session_id);

    let session_input = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&session_id);
        bytes.extend_from_slice(Utc::now().to_rfc3339().as_bytes());
        bytes
    };

    let key_bytes = Zeroizing::new(signing_key.to_bytes());
    let session_seed = Zeroizing::new(hkdf_expand(
        key_bytes.as_slice(),
        SESSION_DOMAIN.as_bytes(),
        &session_input,
    )?);
    drop(key_bytes);
    let session_key = SigningKey::from_bytes(&session_seed);
    let session_pub = session_key.verifying_key().to_bytes().to_vec();

    let created_at = Utc::now();
    let cert_data = build_cert_data(session_id, &session_pub, created_at, document_hash);
    let signature = signing_key.sign(&cert_data).to_bytes();

    let certificate = SessionCertificate {
        session_id,
        session_pubkey: session_pub,
        created_at,
        document_hash,
        master_pubkey: master_pub_key,
        signature,
        version: VERSION,
        start_quote: None,
        end_quote: None,
        start_counter: None,
        end_counter: None,
        start_reset_count: None,
        start_restart_count: None,
        end_reset_count: None,
        end_restart_count: None,
    };

    let ratchet_init = hkdf_expand(session_seed.as_slice(), RATCHET_INIT_DOMAIN.as_bytes(), &[])?;

    Ok(Session {
        certificate,
        ratchet: RatchetState {
            current: ratchet_init.into(),
            ordinal: 0,
            wiped: false,
        },
        signatures: Vec::new(),
    })
}

/// Start a session using a pre-derived master signing key (for sealed store path).
pub fn start_session_with_key(
    master_key: &SigningKey,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    start_session_inner(master_key, document_hash)
}

pub fn start_session(
    puf: &dyn PUFProvider,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    let master_key = derive_master_private_key(puf)?;
    start_session_inner(&master_key, document_hash)
}

impl Session {
    pub fn sign_checkpoint(
        &mut self,
        checkpoint_hash: [u8; 32],
    ) -> Result<CheckpointSignature, KeyHierarchyError> {
        if self.ratchet.wiped {
            return Err(KeyHierarchyError::RatchetWiped);
        }

        let mut signing_seed = hkdf_expand(
            self.ratchet.current.as_bytes(),
            SIGNING_KEY_DOMAIN.as_bytes(),
            &[],
        )?;
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let signature = signing_key.sign(&checkpoint_hash).to_bytes();

        let next_ratchet = hkdf_expand(
            self.ratchet.current.as_bytes(),
            RATCHET_ADVANCE_DOMAIN.as_bytes(),
            &checkpoint_hash,
        )?;

        let current_ordinal = self.ratchet.ordinal;
        signing_seed.zeroize();
        self.ratchet.current = next_ratchet.into();
        self.ratchet.ordinal += 1;

        let sig = CheckpointSignature {
            ordinal: current_ordinal,
            public_key,
            signature,
            checkpoint_hash,
            counter_value: None,
            counter_delta: None,
        };
        self.signatures.push(sig.clone());
        Ok(sig)
    }

    /// Sign a checkpoint with hardware counter integration.
    ///
    /// If a TPM provider is available, binds the checkpoint to the hardware
    /// counter and hashes the counter delta into the ratchet advance.
    pub fn sign_checkpoint_with_counter(
        &mut self,
        checkpoint_hash: [u8; 32],
        provider: &dyn crate::tpm::Provider,
        sealed_store: Option<&crate::sealed_identity::SealedIdentityStore>,
    ) -> Result<CheckpointSignature, KeyHierarchyError> {
        if self.ratchet.wiped {
            return Err(KeyHierarchyError::RatchetWiped);
        }

        // Get counter from binding
        let binding = provider.bind(&checkpoint_hash).ok();
        let current_counter = binding.as_ref().and_then(|b| b.monotonic_counter);

        // Compute counter delta from previous checkpoint
        let previous_counter = self.signatures.last().and_then(|s| s.counter_value);
        let counter_delta = match (current_counter, previous_counter) {
            (Some(curr), Some(prev)) => Some(curr.saturating_sub(prev)),
            (Some(_), None) => Some(0), // first checkpoint with counter
            _ => None,
        };

        // Derive signing key
        let mut signing_seed = hkdf_expand(
            self.ratchet.current.as_bytes(),
            SIGNING_KEY_DOMAIN.as_bytes(),
            &[],
        )?;
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let signature = signing_key.sign(&checkpoint_hash).to_bytes();

        // Hash counter_delta into the ratchet advance (makes ratchet state
        // depend on counter progression, preventing time-skip attacks)
        let mut ratchet_input = checkpoint_hash.to_vec();
        if let Some(delta) = counter_delta {
            ratchet_input.extend_from_slice(&delta.to_be_bytes());
        }
        let next_ratchet = hkdf_expand(
            self.ratchet.current.as_bytes(),
            RATCHET_ADVANCE_DOMAIN.as_bytes(),
            &ratchet_input,
        )?;

        let current_ordinal = self.ratchet.ordinal;
        signing_seed.zeroize();
        self.ratchet.current = next_ratchet.into();
        self.ratchet.ordinal += 1;

        // Advance the sealed store's counter (anti-rollback ratchet)
        if let (Some(store), Some(counter)) = (sealed_store, current_counter) {
            if let Err(e) = store.advance_counter(counter) {
                log::warn!("Failed to advance sealed counter: {}", e);
            }
        }

        let sig = CheckpointSignature {
            ordinal: current_ordinal,
            public_key,
            signature,
            checkpoint_hash,
            counter_value: current_counter,
            counter_delta,
        };
        self.signatures.push(sig.clone());
        Ok(sig)
    }

    pub fn end(&mut self) {
        if !self.ratchet.wiped {
            self.ratchet.wiped = true;
        }
    }

    /// End session with TPM binding — generates closing quote with chain-entangled nonce
    /// and records end counter/reboot state for time-travel detection.
    pub fn end_with_provider(&mut self, provider: &dyn crate::tpm::Provider, mmr_root: &[u8; 32]) {
        // Compute chain-entangled closing nonce:
        // SHA256(session_id || final_checkpoint_hash || current_mmr_root)
        let final_checkpoint_hash = self
            .signatures
            .last()
            .map(|s| s.checkpoint_hash)
            .unwrap_or([0u8; 32]);
        let closing_nonce = compute_entangled_nonce(
            &self.certificate.session_id,
            &final_checkpoint_hash,
            mmr_root,
        );

        // Generate closing TPM quote with entangled nonce
        if let Ok(quote) = provider.quote(&closing_nonce, &[0, 4, 7]) {
            self.certificate.end_quote = serde_json::to_vec(&quote)
                .map_err(|e| {
                    log::warn!("TPM quote serialization failed: {e}");
                    e
                })
                .ok();
        }

        // Record end counter and reboot state
        if let Ok(binding) = provider.bind(&closing_nonce) {
            self.certificate.end_counter = binding.monotonic_counter;
        }
        if let Ok(clock) = provider.clock_info() {
            self.certificate.end_reset_count = Some(clock.reset_count);
            self.certificate.end_restart_count = Some(clock.restart_count);
        }

        // End session (wipes ratchet)
        self.end();
    }

    /// Bind session start to TPM state with chain-entangled nonce.
    /// Called after session creation when a TPM provider is available.
    pub fn bind_start_quote(&mut self, provider: &dyn crate::tpm::Provider, mmr_root: &[u8; 32]) {
        // Compute chain-entangled start nonce:
        // SHA256(session_id || document_hash || previous_mmr_root)
        let start_nonce = compute_entangled_nonce(
            &self.certificate.session_id,
            &self.certificate.document_hash,
            mmr_root,
        );

        // Generate TPM quote over PCRs [0, 4, 7] with entangled nonce
        if let Ok(quote) = provider.quote(&start_nonce, &[0, 4, 7]) {
            self.certificate.start_quote = serde_json::to_vec(&quote)
                .map_err(|e| {
                    log::warn!("TPM quote serialization failed: {e}");
                    e
                })
                .ok();
        }

        // Record start counter
        if let Ok(binding) = provider.bind(&start_nonce) {
            self.certificate.start_counter = binding.monotonic_counter;
        }

        // Record start reboot state
        if let Ok(clock) = provider.clock_info() {
            self.certificate.start_reset_count = Some(clock.reset_count);
            self.certificate.start_restart_count = Some(clock.restart_count);
        }
    }

    /// Sign chain metadata with the current ratchet key.
    ///
    /// Signs `SHA256("witnessd-chain-metadata-v1" || checkpoint_count || mmr_root || mmr_leaf_count)`.
    /// This makes checkpoint deletion detectable: changing the count breaks the signature.
    pub fn sign_chain_metadata(
        &self,
        metadata: &mut crate::checkpoint::ChainMetadata,
    ) -> Result<(), KeyHierarchyError> {
        if self.ratchet.wiped {
            return Err(KeyHierarchyError::RatchetWiped);
        }

        let payload = crate::checkpoint_mmr::metadata_signing_payload(metadata);

        let mut signing_seed = hkdf_expand(
            self.ratchet.current.as_bytes(),
            SIGNING_KEY_DOMAIN.as_bytes(),
            &[],
        )?;
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let signature = signing_key.sign(&payload).to_bytes();
        signing_seed.zeroize();

        metadata.metadata_signature = Some(signature.to_vec());
        Ok(())
    }

    pub fn signatures(&self) -> Vec<CheckpointSignature> {
        self.signatures.clone()
    }

    pub fn current_ordinal(&self) -> u64 {
        self.ratchet.ordinal
    }

    pub fn export(&self, identity: &MasterIdentity) -> KeyHierarchyEvidence {
        let mut evidence = KeyHierarchyEvidence {
            version: VERSION as i32,
            master_identity: Some(identity.clone()),
            session_certificate: Some(self.certificate.clone()),
            checkpoint_signatures: self.signatures.clone(),
            master_fingerprint: identity.fingerprint.clone(),
            master_public_key: identity.public_key.clone(),
            device_id: identity.device_id.clone(),
            session_id: hex::encode(self.certificate.session_id),
            session_public_key: self.certificate.session_pubkey.clone(),
            session_started: self.certificate.created_at,
            session_certificate_raw: self.certificate.signature.to_vec(),
            ratchet_count: self.signatures.len() as i32,
            ratchet_public_keys: Vec::new(),
            hardware_attestation: None,
        };

        for sig in &self.signatures {
            evidence.ratchet_public_keys.push(sig.public_key.clone());
        }

        evidence
    }

    pub fn export_recovery_state(
        &self,
        puf: &dyn PUFProvider,
    ) -> Result<SessionRecoveryState, KeyHierarchyError> {
        if self.ratchet.wiped {
            return Err(KeyHierarchyError::RatchetWiped);
        }

        let challenge = sha2::Sha256::digest(b"witnessd-ratchet-recovery-v2");
        let response = puf.get_response(&challenge)?;
        let key = Zeroizing::new(hkdf_expand(&response, b"ratchet-recovery-key-v2", &[])?);

        // Plaintext: ratchet_state(32) || ordinal(8)
        let mut plaintext = Zeroizing::new(vec![0u8; 40]);
        plaintext[..32].copy_from_slice(self.ratchet.current.as_bytes());
        plaintext[32..40].copy_from_slice(&self.ratchet.ordinal.to_be_bytes());

        let cipher = ChaCha20Poly1305::new_from_slice(&*key)
            .map_err(|e| KeyHierarchyError::Crypto(format!("AEAD init: {e}")))?;

        // Generate random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| KeyHierarchyError::Crypto(format!("rng: {e}")))?;
        let aead_nonce = AeadNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(aead_nonce, plaintext.as_ref())
            .map_err(|e| KeyHierarchyError::Crypto(format!("AEAD encrypt: {e}")))?;

        // Format: version(1) || aead_nonce(12) || ciphertext+tag
        let mut encrypted = Vec::with_capacity(1 + 12 + ciphertext.len());
        encrypted.push(0x02); // version 2 = AEAD
        encrypted.extend_from_slice(&nonce_bytes);
        encrypted.extend_from_slice(&ciphertext);

        Ok(SessionRecoveryState {
            certificate: self.certificate.clone(),
            signatures: self.signatures.clone(),
            last_ratchet_state: encrypted,
        })
    }
}
