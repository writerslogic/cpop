// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroize;

use crate::checkpoint;
use crate::physics::puf::SiliconPUF;

const VERSION: u32 = 1;
const IDENTITY_DOMAIN: &str = "witnessd-identity-v1";
const SESSION_DOMAIN: &str = "witnessd-session-v1";
const RATCHET_INIT_DOMAIN: &str = "witnessd-ratchet-init-v1";
const RATCHET_ADVANCE_DOMAIN: &str = "witnessd-ratchet-advance-v1";
const SIGNING_KEY_DOMAIN: &str = "witnessd-signing-key-v1";

mod serde_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<u8>::deserialize(deserializer)?;
        if values.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64-byte array, got {} bytes",
                values.len()
            )));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&values);
        Ok(out)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyHierarchyError {
    #[error("keyhierarchy: ratchet state has been wiped")]
    RatchetWiped,
    #[error("keyhierarchy: invalid session certificate")]
    InvalidCert,
    #[error("keyhierarchy: checkpoint ordinal mismatch")]
    OrdinalMismatch,
    #[error("keyhierarchy: signature verification failed")]
    SignatureFailed,
    #[error("keyhierarchy: checkpoint hash mismatch")]
    HashMismatch,
    #[error("keyhierarchy: legacy signing key not found")]
    LegacyKeyNotFound,
    #[error("keyhierarchy: migration failed")]
    MigrationFailed,
    #[error("keyhierarchy: invalid migration record")]
    InvalidMigration,
    #[error("keyhierarchy: session cannot be recovered")]
    SessionNotRecoverable,
    #[error("keyhierarchy: session recovery failed")]
    SessionRecoveryFailed,
    #[error("keyhierarchy: no recovery data available")]
    NoRecoveryData,
    #[error("keyhierarchy: failed to initialize software PUF")]
    SoftwarePUFInit,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterIdentity {
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub device_id: String,
    pub created_at: DateTime<Utc>,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCertificate {
    pub session_id: [u8; 32],
    pub session_pubkey: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub document_hash: [u8; 32],
    pub master_pubkey: Vec<u8>,
    #[serde(with = "serde_array_64")]
    pub signature: [u8; 64],
    pub version: u32,
    /// TPM quote at session start (chain-entangled nonce)
    #[serde(default)]
    pub start_quote: Option<Vec<u8>>,
    /// TPM quote at session end
    #[serde(default)]
    pub end_quote: Option<Vec<u8>>,
    /// Hardware monotonic counter at session start
    #[serde(default)]
    pub start_counter: Option<u64>,
    /// Hardware monotonic counter at session end
    #[serde(default)]
    pub end_counter: Option<u64>,
    /// TPM ResetCount at session start (reboot detection)
    #[serde(default)]
    pub start_reset_count: Option<u32>,
    /// TPM RestartCount at session start
    #[serde(default)]
    pub start_restart_count: Option<u32>,
    /// TPM ResetCount at session end
    #[serde(default)]
    pub end_reset_count: Option<u32>,
    /// TPM RestartCount at session end
    #[serde(default)]
    pub end_restart_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointSignature {
    pub ordinal: u64,
    pub public_key: Vec<u8>,
    #[serde(with = "serde_array_64")]
    pub signature: [u8; 64],
    pub checkpoint_hash: [u8; 32],
    /// Hardware monotonic counter value at this checkpoint (None for software-only)
    #[serde(default)]
    pub counter_value: Option<u64>,
    /// Delta from previous checkpoint's counter value
    #[serde(default)]
    pub counter_delta: Option<u64>,
}

#[derive(Debug, Clone)]
struct RatchetState {
    current: [u8; 32],
    ordinal: u64,
    #[allow(dead_code)]
    session_id: [u8; 32],
    wiped: bool,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub certificate: SessionCertificate,
    ratchet: RatchetState,
    signatures: Vec<CheckpointSignature>,
}

pub trait PUFProvider: Send + Sync {
    fn get_response(&self, challenge: &[u8]) -> Result<Vec<u8>, KeyHierarchyError>;
    fn device_id(&self) -> String;
}

pub fn derive_master_identity(puf: &dyn PUFProvider) -> Result<MasterIdentity, KeyHierarchyError> {
    let challenge = Sha256::digest(format!("{}-challenge", IDENTITY_DOMAIN).as_bytes());
    let puf_response = puf.get_response(&challenge)?;

    let mut seed = hkdf_expand(&puf_response, IDENTITY_DOMAIN.as_bytes(), b"master-seed")?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();

    let fingerprint = Sha256::digest(&public_key);
    let fingerprint_hex = hex::encode(&fingerprint[0..8]);

    seed.zeroize();

    Ok(MasterIdentity {
        public_key,
        fingerprint: fingerprint_hex,
        device_id: puf.device_id(),
        created_at: Utc::now(),
        version: VERSION,
    })
}

fn derive_master_private_key(puf: &dyn PUFProvider) -> Result<SigningKey, KeyHierarchyError> {
    let challenge = Sha256::digest(format!("{}-challenge", IDENTITY_DOMAIN).as_bytes());
    let puf_response = puf.get_response(&challenge)?;

    let mut seed = hkdf_expand(&puf_response, IDENTITY_DOMAIN.as_bytes(), b"master-seed")?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(signing_key)
}

/// Start a session using a pre-derived master signing key (for sealed store path).
pub fn start_session_with_key(
    master_key: &SigningKey,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    let master_pub_key = master_key.verifying_key().to_bytes().to_vec();

    let mut session_id = [0u8; 32];
    rand::rng().fill_bytes(&mut session_id);

    let session_input = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&session_id);
        bytes.extend_from_slice(Utc::now().to_rfc3339().as_bytes());
        bytes
    };

    let mut session_seed = hkdf_expand(
        master_key.to_bytes().as_slice(),
        SESSION_DOMAIN.as_bytes(),
        &session_input,
    )?;
    let session_key = SigningKey::from_bytes(&session_seed);
    let session_pub = session_key.verifying_key().to_bytes().to_vec();

    let created_at = Utc::now();
    let cert_data = build_cert_data(session_id, &session_pub, created_at, document_hash);
    let signature = master_key.sign(&cert_data).to_bytes();

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

    let ratchet_init = hkdf_expand(&session_seed, RATCHET_INIT_DOMAIN.as_bytes(), &[])?;
    session_seed.zeroize();

    Ok(Session {
        certificate,
        ratchet: RatchetState {
            current: ratchet_init,
            ordinal: 0,
            session_id,
            wiped: false,
        },
        signatures: Vec::new(),
    })
}

pub fn start_session(
    puf: &dyn PUFProvider,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    let master_key = derive_master_private_key(puf)?;
    let master_pub_key = master_key.verifying_key().to_bytes().to_vec();

    let mut session_id = [0u8; 32];
    rand::rng().fill_bytes(&mut session_id);

    let session_input = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&session_id);
        bytes.extend_from_slice(Utc::now().to_rfc3339().as_bytes());
        bytes
    };

    let mut session_seed = hkdf_expand(
        master_key.to_bytes().as_slice(),
        SESSION_DOMAIN.as_bytes(),
        &session_input,
    )?;
    let session_key = SigningKey::from_bytes(&session_seed);
    let session_pub = session_key.verifying_key().to_bytes().to_vec();

    let created_at = Utc::now();
    let cert_data = build_cert_data(session_id, &session_pub, created_at, document_hash);
    let signature = master_key.sign(&cert_data).to_bytes();

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

    let ratchet_init = hkdf_expand(&session_seed, RATCHET_INIT_DOMAIN.as_bytes(), &[])?;
    session_seed.zeroize();

    Ok(Session {
        certificate,
        ratchet: RatchetState {
            current: ratchet_init,
            ordinal: 0,
            session_id,
            wiped: false,
        },
        signatures: Vec::new(),
    })
}

impl Session {
    pub fn sign_checkpoint(
        &mut self,
        checkpoint_hash: [u8; 32],
    ) -> Result<CheckpointSignature, KeyHierarchyError> {
        if self.ratchet.wiped {
            return Err(KeyHierarchyError::RatchetWiped);
        }

        let mut signing_seed =
            hkdf_expand(&self.ratchet.current, SIGNING_KEY_DOMAIN.as_bytes(), &[])?;
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let signature = signing_key.sign(&checkpoint_hash).to_bytes();

        let next_ratchet = hkdf_expand(
            &self.ratchet.current,
            RATCHET_ADVANCE_DOMAIN.as_bytes(),
            &checkpoint_hash,
        )?;

        let current_ordinal = self.ratchet.ordinal;
        self.ratchet.current.zeroize();
        signing_seed.zeroize();
        self.ratchet.current = next_ratchet;
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
        let previous_counter = self
            .signatures
            .last()
            .and_then(|s| s.counter_value);
        let counter_delta = match (current_counter, previous_counter) {
            (Some(curr), Some(prev)) => Some(curr.saturating_sub(prev)),
            (Some(_), None) => Some(0), // first checkpoint with counter
            _ => None,
        };

        // Derive signing key
        let mut signing_seed =
            hkdf_expand(&self.ratchet.current, SIGNING_KEY_DOMAIN.as_bytes(), &[])?;
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
            &self.ratchet.current,
            RATCHET_ADVANCE_DOMAIN.as_bytes(),
            &ratchet_input,
        )?;

        let current_ordinal = self.ratchet.ordinal;
        self.ratchet.current.zeroize();
        signing_seed.zeroize();
        self.ratchet.current = next_ratchet;
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
            self.ratchet.current.zeroize();
            self.ratchet.wiped = true;
        }
    }

    /// End session with TPM binding — generates closing quote with chain-entangled nonce
    /// and records end counter/reboot state for time-travel detection.
    pub fn end_with_provider(
        &mut self,
        provider: &dyn crate::tpm::Provider,
        mmr_root: &[u8; 32],
    ) {
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
            self.certificate.end_quote = Some(serde_json::to_vec(&quote).unwrap_or_default());
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
    pub fn bind_start_quote(
        &mut self,
        provider: &dyn crate::tpm::Provider,
        mmr_root: &[u8; 32],
    ) {
        // Compute chain-entangled start nonce:
        // SHA256(session_id || document_hash || previous_mmr_root)
        let start_nonce = compute_entangled_nonce(
            &self.certificate.session_id,
            &self.certificate.document_hash,
            mmr_root,
        );

        // Generate TPM quote over PCRs [0, 4, 7] with entangled nonce
        if let Ok(quote) = provider.quote(&start_nonce, &[0, 4, 7]) {
            self.certificate.start_quote = Some(serde_json::to_vec(&quote).unwrap_or_default());
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

        let challenge = Sha256::digest(b"witnessd-ratchet-recovery-v1");
        let response = puf.get_response(&challenge)?;
        let mut key = hkdf_expand(&response, b"ratchet-recovery-key", &[])?;

        let mut encrypted = vec![0u8; 40];
        for i in 0..32 {
            encrypted[i] = self.ratchet.current[i] ^ key[i % 32];
        }
        encrypted[32..40].copy_from_slice(&self.ratchet.ordinal.to_be_bytes());
        key.zeroize();

        Ok(SessionRecoveryState {
            certificate: self.certificate.clone(),
            signatures: self.signatures.clone(),
            last_ratchet_state: encrypted,
        })
    }
}

pub fn verify_session_certificate(cert: &SessionCertificate) -> Result<(), KeyHierarchyError> {
    let cert_data = build_cert_data(
        cert.session_id,
        &cert.session_pubkey,
        cert.created_at,
        cert.document_hash,
    );

    let pubkey = VerifyingKey::from_bytes(
        cert.master_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| KeyHierarchyError::InvalidCert)?,
    )
    .map_err(|_| KeyHierarchyError::InvalidCert)?;

    let signature = Signature::from_bytes(&cert.signature);
    pubkey
        .verify(&cert_data, &signature)
        .map_err(|_| KeyHierarchyError::InvalidCert)
}

pub fn verify_checkpoint_signatures(
    signatures: &[CheckpointSignature],
) -> Result<(), KeyHierarchyError> {
    let mut prev_counter: Option<u64> = None;

    for (i, sig) in signatures.iter().enumerate() {
        if sig.ordinal != i as u64 {
            return Err(KeyHierarchyError::OrdinalMismatch);
        }

        let pubkey = VerifyingKey::from_bytes(
            sig.public_key
                .as_slice()
                .try_into()
                .map_err(|_| KeyHierarchyError::SignatureFailed)?,
        )
        .map_err(|_| KeyHierarchyError::SignatureFailed)?;
        let signature = Signature::from_bytes(&sig.signature);
        pubkey
            .verify(&sig.checkpoint_hash, &signature)
            .map_err(|_| KeyHierarchyError::SignatureFailed)?;

        // Validate hardware counter monotonicity
        if let Some(current) = sig.counter_value {
            if let Some(prev) = prev_counter {
                if current < prev {
                    return Err(KeyHierarchyError::Crypto(format!(
                        "counter rollback at ordinal {}: {} < {}",
                        sig.ordinal, current, prev,
                    )));
                }
                // Validate delta matches actual difference
                if let Some(delta) = sig.counter_delta {
                    if delta != current - prev {
                        return Err(KeyHierarchyError::Crypto(format!(
                            "counter delta mismatch at ordinal {}: delta {} != {} - {}",
                            sig.ordinal, delta, current, prev,
                        )));
                    }
                }
            }
            prev_counter = Some(current);
        }
    }
    Ok(())
}

/// Compute a chain-entangled nonce for TPM quote binding.
/// The nonce is SHA256(session_id || data_hash || mmr_root), which cryptographically
/// binds the TPM's proof of platform integrity to the exact state of the authorship chain.
/// This prevents replaying quotes from clean boots against dirty sessions.
pub fn compute_entangled_nonce(
    session_id: &[u8; 32],
    data_hash: &[u8; 32],
    mmr_root: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(session_id);
    hasher.update(data_hash);
    hasher.update(mmr_root);
    hasher.finalize().into()
}

/// Verify session TPM binding: checks that reboot counters haven't changed
/// mid-session (time-travel detection) and that counter deltas are consistent.
pub fn verify_session_binding(
    cert: &SessionCertificate,
) -> Result<SessionBindingReport, KeyHierarchyError> {
    let mut report = SessionBindingReport {
        has_start_quote: cert.start_quote.is_some(),
        has_end_quote: cert.end_quote.is_some(),
        counter_delta: None,
        reboot_detected: false,
        restart_detected: false,
        warnings: Vec::new(),
    };

    // Check counter progression
    if let (Some(start), Some(end)) = (cert.start_counter, cert.end_counter) {
        if end < start {
            return Err(KeyHierarchyError::Crypto(format!(
                "session counter rollback: end {} < start {}",
                end, start,
            )));
        }
        report.counter_delta = Some(end - start);
    }

    // Check for reboot mid-session (reset_count changed)
    if let (Some(start_rc), Some(end_rc)) = (cert.start_reset_count, cert.end_reset_count) {
        if end_rc != start_rc {
            report.reboot_detected = true;
            report.warnings.push(format!(
                "TPM ResetCount changed mid-session: {} -> {} (machine was rebooted)",
                start_rc, end_rc,
            ));
        }
    }

    // Check for restart mid-session (restart_count changed)
    if let (Some(start_rst), Some(end_rst)) =
        (cert.start_restart_count, cert.end_restart_count)
    {
        if end_rst != start_rst {
            report.restart_detected = true;
            report.warnings.push(format!(
                "TPM RestartCount changed mid-session: {} -> {} (TPM was restarted)",
                start_rst, end_rst,
            ));
        }
    }

    Ok(report)
}

/// Report from verifying session TPM binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBindingReport {
    pub has_start_quote: bool,
    pub has_end_quote: bool,
    pub counter_delta: Option<u64>,
    pub reboot_detected: bool,
    pub restart_detected: bool,
    pub warnings: Vec<String>,
}

fn build_cert_data(
    session_id: [u8; 32],
    session_pub_key: &[u8],
    created_at: DateTime<Utc>,
    document_hash: [u8; 32],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(32 + 32 + 8 + 32);
    data.extend_from_slice(&session_id);
    data.extend_from_slice(session_pub_key);
    data.extend_from_slice(&(created_at.timestamp_nanos_opt().unwrap_or(0) as u64).to_be_bytes());
    data.extend_from_slice(&document_hash);
    data
}

pub fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], KeyHierarchyError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| KeyHierarchyError::Crypto("HKDF expand failed".to_string()))?;
    Ok(okm)
}

pub fn fingerprint_for_public_key(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    hex::encode(&digest[0..8])
}

// =============================================================================
// Evidence export structures
// =============================================================================

/// Evidence of hardware TPM binding for a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareEvidence {
    /// Provider type (e.g., "secure-enclave", "tpm2-windows", "software")
    pub provider_type: String,
    /// Attestation tier (T1-T4)
    pub attestation_tier: u8,
    /// Whether key is hardware-bound
    pub hardware_bound: bool,
    /// Device binding (TPM quote at session start, if available)
    pub device_binding: Option<Vec<u8>>,
    /// Monotonic counter range (start→end of session)
    pub counter_start: Option<u64>,
    pub counter_end: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHierarchyEvidence {
    pub version: i32,
    pub master_identity: Option<MasterIdentity>,
    pub session_certificate: Option<SessionCertificate>,
    pub checkpoint_signatures: Vec<CheckpointSignature>,
    pub master_fingerprint: String,
    pub master_public_key: Vec<u8>,
    pub device_id: String,
    pub session_id: String,
    pub session_public_key: Vec<u8>,
    pub session_started: DateTime<Utc>,
    pub session_certificate_raw: Vec<u8>,
    pub ratchet_count: i32,
    pub ratchet_public_keys: Vec<Vec<u8>>,
    /// Hardware attestation evidence (None for pure software sessions)
    #[serde(default)]
    pub hardware_attestation: Option<HardwareEvidence>,
}

pub fn verify_key_hierarchy(evidence: &KeyHierarchyEvidence) -> Result<(), KeyHierarchyError> {
    let cert = evidence
        .session_certificate
        .as_ref()
        .ok_or(KeyHierarchyError::InvalidCert)?;
    verify_session_certificate(cert)?;

    if let Some(identity) = &evidence.master_identity {
        if identity.public_key != cert.master_pubkey {
            return Err(KeyHierarchyError::InvalidCert);
        }
    }

    if !evidence.master_public_key.is_empty() {
        let expected = fingerprint_for_public_key(&evidence.master_public_key);
        if expected != evidence.master_fingerprint {
            return Err(KeyHierarchyError::InvalidCert);
        }
    }

    if evidence.ratchet_count != evidence.checkpoint_signatures.len() as i32 {
        return Err(KeyHierarchyError::InvalidCert);
    }

    verify_checkpoint_signatures(&evidence.checkpoint_signatures)
}

// =============================================================================
// Session recovery
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecoveryState {
    pub certificate: SessionCertificate,
    pub signatures: Vec<CheckpointSignature>,
    pub last_ratchet_state: Vec<u8>,
}

pub fn recover_session(
    puf: &dyn PUFProvider,
    recovery: &SessionRecoveryState,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    if recovery.certificate.session_id == [0u8; 32] {
        return Err(KeyHierarchyError::NoRecoveryData);
    }

    verify_session_certificate(&recovery.certificate)?;

    if recovery.certificate.document_hash != document_hash {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    let identity = derive_master_identity(puf)?;
    if identity.public_key != recovery.certificate.master_pubkey {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    if !recovery.last_ratchet_state.is_empty() {
        return recover_session_with_ratchet(puf, recovery);
    }

    recover_session_with_new_ratchet(puf, recovery)
}

fn recover_session_with_ratchet(
    puf: &dyn PUFProvider,
    recovery: &SessionRecoveryState,
) -> Result<Session, KeyHierarchyError> {
    let challenge = Sha256::digest(b"witnessd-ratchet-recovery-v1");
    let response = puf.get_response(&challenge)?;
    let mut key = hkdf_expand(&response, b"ratchet-recovery-key", &[])?;

    if recovery.last_ratchet_state.len() < 40 {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    let mut ratchet_state = [0u8; 32];
    for i in 0..32 {
        ratchet_state[i] = recovery.last_ratchet_state[i] ^ key[i % 32];
    }
    let ordinal = u64::from_be_bytes(
        recovery.last_ratchet_state[32..40]
            .try_into()
            .unwrap_or([0u8; 8]),
    );
    key.zeroize();

    Ok(Session {
        certificate: recovery.certificate.clone(),
        ratchet: RatchetState {
            current: ratchet_state,
            ordinal,
            session_id: recovery.certificate.session_id,
            wiped: false,
        },
        signatures: recovery.signatures.clone(),
    })
}

fn recover_session_with_new_ratchet(
    puf: &dyn PUFProvider,
    recovery: &SessionRecoveryState,
) -> Result<Session, KeyHierarchyError> {
    let mut next_ordinal = 0u64;
    if let Some(last) = recovery.signatures.last() {
        next_ordinal = last.ordinal + 1;
    }

    let challenge = Sha256::digest(b"witnessd-ratchet-continuation-v1");
    let response = puf.get_response(&challenge)?;

    let mut last_hash = [0u8; 32];
    if let Some(last) = recovery.signatures.last() {
        last_hash = last.checkpoint_hash;
    }

    let mut continuation_input = Vec::new();
    continuation_input.extend_from_slice(&response);
    continuation_input.extend_from_slice(&last_hash);
    continuation_input.extend_from_slice(&recovery.certificate.session_id);

    let ratchet_init = hkdf_expand(
        &continuation_input,
        RATCHET_INIT_DOMAIN.as_bytes(),
        b"continuation",
    )?;

    Ok(Session {
        certificate: recovery.certificate.clone(),
        ratchet: RatchetState {
            current: ratchet_init,
            ordinal: next_ordinal,
            session_id: recovery.certificate.session_id,
            wiped: false,
        },
        signatures: recovery.signatures.clone(),
    })
}

// =============================================================================
// Legacy migration
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyKeyMigration {
    pub legacy_public_key: Vec<u8>,
    pub new_master_public_key: Vec<u8>,
    pub migration_timestamp: DateTime<Utc>,
    #[serde(with = "serde_array_64")]
    pub transition_signature: [u8; 64],
    pub version: u32,
}

pub fn migrate_from_legacy_key(
    puf: &dyn PUFProvider,
    legacy_key_path: impl AsRef<Path>,
) -> Result<(LegacyKeyMigration, MasterIdentity), KeyHierarchyError> {
    let legacy_key = load_legacy_private_key(legacy_key_path)?;
    let legacy_pub = legacy_key.verifying_key().to_bytes().to_vec();

    let new_identity = derive_master_identity(puf)?;

    let migration_ts = Utc::now();
    let data = build_migration_data(&legacy_pub, &new_identity.public_key, migration_ts);
    let signature = legacy_key.sign(&data).to_bytes();

    Ok((
        LegacyKeyMigration {
            legacy_public_key: legacy_pub,
            new_master_public_key: new_identity.public_key.clone(),
            migration_timestamp: migration_ts,
            transition_signature: signature,
            version: VERSION,
        },
        new_identity,
    ))
}

pub fn verify_legacy_migration(migration: &LegacyKeyMigration) -> Result<(), KeyHierarchyError> {
    if migration.legacy_public_key.len() != 32 || migration.new_master_public_key.len() != 32 {
        return Err(KeyHierarchyError::InvalidMigration);
    }

    let data = build_migration_data(
        &migration.legacy_public_key,
        &migration.new_master_public_key,
        migration.migration_timestamp,
    );

    let pubkey = VerifyingKey::from_bytes(
        migration
            .legacy_public_key
            .as_slice()
            .try_into()
            .map_err(|_| KeyHierarchyError::InvalidMigration)?,
    )
    .map_err(|_| KeyHierarchyError::InvalidMigration)?;
    let signature = Signature::from_bytes(&migration.transition_signature);
    pubkey
        .verify(&data, &signature)
        .map_err(|_| KeyHierarchyError::InvalidMigration)
}

fn build_migration_data(
    legacy_pub: &[u8],
    new_master_pub: &[u8],
    timestamp: DateTime<Utc>,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"witnessd-key-migration-v1");
    data.extend_from_slice(legacy_pub);
    data.extend_from_slice(new_master_pub);
    data.extend_from_slice(&(timestamp.timestamp_nanos_opt().unwrap_or(0) as u64).to_be_bytes());
    data
}

fn load_legacy_private_key(path: impl AsRef<Path>) -> Result<SigningKey, KeyHierarchyError> {
    let data = fs::read(path)?;

    if data.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&data);
        return Ok(SigningKey::from_bytes(&seed));
    }

    if data.len() == 64 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&data[0..32]);
        return Ok(SigningKey::from_bytes(&seed));
    }

    Err(KeyHierarchyError::LegacyKeyNotFound)
}

pub fn start_session_from_legacy_key(
    legacy_key_path: impl AsRef<Path>,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    let legacy_key = load_legacy_private_key(legacy_key_path)?;
    let legacy_pub = legacy_key.verifying_key().to_bytes().to_vec();

    let mut session_id = [0u8; 32];
    rand::rng().fill_bytes(&mut session_id);

    let session_input = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&session_id);
        bytes.extend_from_slice(Utc::now().to_rfc3339().as_bytes());
        bytes
    };

    let mut session_seed = hkdf_expand(
        legacy_key.to_bytes().as_slice(),
        SESSION_DOMAIN.as_bytes(),
        &session_input,
    )?;
    let session_key = SigningKey::from_bytes(&session_seed);
    let session_pub = session_key.verifying_key().to_bytes().to_vec();

    let created_at = Utc::now();
    let cert_data = build_cert_data(session_id, &session_pub, created_at, document_hash);
    let signature = legacy_key.sign(&cert_data).to_bytes();

    let certificate = SessionCertificate {
        session_id,
        session_pubkey: session_pub,
        created_at,
        document_hash,
        master_pubkey: legacy_pub,
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

    let ratchet_init = hkdf_expand(&session_seed, RATCHET_INIT_DOMAIN.as_bytes(), &[])?;
    session_seed.zeroize();

    Ok(Session {
        certificate,
        ratchet: RatchetState {
            current: ratchet_init,
            ordinal: 0,
            session_id,
            wiped: false,
        },
        signatures: Vec::new(),
    })
}

// =============================================================================
// Evidence helpers used by evidence module
// =============================================================================

pub fn verify_session_certificate_bytes(
    master_pubkey: &[u8],
    session_pubkey: &[u8],
    cert_signature: &[u8],
) -> Result<(), String> {
    if master_pubkey.len() != 32 {
        return Err("invalid master public key size".to_string());
    }
    if session_pubkey.len() != 32 {
        return Err("invalid session public key size".to_string());
    }
    if cert_signature.len() != 64 {
        return Err("invalid certificate signature size".to_string());
    }
    Ok(())
}

pub fn verify_ratchet_signature(
    ratchet_pubkey: &[u8],
    checkpoint_hash: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    if ratchet_pubkey.len() != 32 {
        return Err("invalid ratchet public key size".to_string());
    }
    if checkpoint_hash.len() != 32 {
        return Err("invalid checkpoint hash size".to_string());
    }
    if signature.len() != 64 {
        return Err("invalid signature size".to_string());
    }

    let pubkey = VerifyingKey::from_bytes(
        ratchet_pubkey
            .try_into()
            .map_err(|_| "invalid ratchet public key size".to_string())?,
    )
    .map_err(|_| "invalid ratchet public key".to_string())?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| "invalid signature size".to_string())?;
    let sig = Signature::from_bytes(&sig_bytes);
    pubkey
        .verify(checkpoint_hash, &sig)
        .map_err(|_| "signature verification failed".to_string())
}

// =============================================================================
// Integration helpers
// =============================================================================

pub struct SessionManager {
    session: Session,
    identity: MasterIdentity,
    #[allow(dead_code)]
    puf: Box<dyn PUFProvider>,
    #[allow(dead_code)]
    document_path: String,
}

impl SessionManager {
    pub fn new(
        puf: Box<dyn PUFProvider>,
        document_path: impl Into<String>,
    ) -> Result<Self, KeyHierarchyError> {
        let identity = derive_master_identity(puf.as_ref())?;
        let document_path = document_path.into();
        let content = fs::read(&document_path)?;
        let doc_hash: [u8; 32] = Sha256::digest(&content).into();

        let session = start_session(puf.as_ref(), doc_hash)?;

        Ok(Self {
            session,
            identity,
            puf,
            document_path,
        })
    }

    /// Create a session manager using a `SealedIdentityStore` for TPM-protected key material.
    ///
    /// The master signing key is obtained via `sealed.unseal_master_key()` (TPM-protected)
    /// rather than `derive_master_private_key(puf)` (in-memory derivation).
    pub fn new_with_sealed_store(
        sealed: &crate::sealed_identity::SealedIdentityStore,
        puf: Box<dyn PUFProvider>,
        document_path: impl Into<String>,
    ) -> Result<Self, KeyHierarchyError> {
        // Get identity from sealed store (public data, no unseal needed)
        let identity = sealed.public_identity().map_err(|e| {
            KeyHierarchyError::Crypto(format!("sealed identity error: {}", e))
        })?;

        let document_path = document_path.into();
        let content = fs::read(&document_path)?;
        let doc_hash: [u8; 32] = Sha256::digest(&content).into();

        // Unseal the master key — this is TPM-protected
        let master_key = sealed.unseal_master_key().map_err(|e| {
            KeyHierarchyError::Crypto(format!("unseal master key: {}", e))
        })?;

        // Start session using the unsealed key directly
        let session = start_session_with_key(&master_key, doc_hash)?;

        Ok(Self {
            session,
            identity,
            puf,
            document_path,
        })
    }

    pub fn sign_checkpoint(
        &mut self,
        checkpoint: &mut checkpoint::Checkpoint,
    ) -> Result<(), KeyHierarchyError> {
        let sig = self.session.sign_checkpoint(checkpoint.hash)?;
        checkpoint.signature = Some(sig.signature.to_vec());
        Ok(())
    }

    pub fn end(&mut self) {
        self.session.end();
    }

    pub fn identity(&self) -> &MasterIdentity {
        &self.identity
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn export_evidence(&self) -> KeyHierarchyEvidence {
        self.session.export(&self.identity)
    }
}

pub struct ChainSigner {
    chain: checkpoint::Chain,
    manager: SessionManager,
}

impl ChainSigner {
    pub fn new(
        chain: checkpoint::Chain,
        puf: Box<dyn PUFProvider>,
    ) -> Result<Self, KeyHierarchyError> {
        let manager = SessionManager::new(puf, chain.document_path.clone())?;
        Ok(Self { chain, manager })
    }

    pub fn commit_and_sign(
        &mut self,
        message: Option<String>,
    ) -> Result<checkpoint::Checkpoint, KeyHierarchyError> {
        let mut cp = self
            .chain
            .commit(message)
            .map_err(|e| KeyHierarchyError::Crypto(e.to_string()))?;
        self.manager.sign_checkpoint(&mut cp)?;
        Ok(cp)
    }

    pub fn commit_and_sign_with_duration(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
    ) -> Result<checkpoint::Checkpoint, KeyHierarchyError> {
        let mut cp = self
            .chain
            .commit_with_vdf_duration(message, vdf_duration)
            .map_err(|e| KeyHierarchyError::Crypto(e.to_string()))?;
        self.manager.sign_checkpoint(&mut cp)?;
        Ok(cp)
    }

    pub fn end(&mut self) {
        self.manager.end();
    }

    pub fn chain(&self) -> &checkpoint::Chain {
        &self.chain
    }

    pub fn signed_checkpoints(&self) -> &Vec<checkpoint::Checkpoint> {
        &self.chain.checkpoints
    }

    pub fn key_hierarchy_evidence(&self) -> KeyHierarchyEvidence {
        self.manager.export_evidence()
    }

    pub fn identity(&self) -> &MasterIdentity {
        self.manager.identity()
    }
}

// =============================================================================
// Software PUF
// =============================================================================

const SOFTWARE_PUF_SEED_NAME: &str = "puf_seed";

#[derive(Clone)]
pub struct SoftwarePUF {
    device_id: String,
    seed: Vec<u8>,
    seed_path: PathBuf,
}

impl SoftwarePUF {
    pub fn new() -> Result<Self, KeyHierarchyError> {
        let seed_path = witnessd_dir().join(SOFTWARE_PUF_SEED_NAME);
        Self::new_with_path(seed_path)
    }

    pub fn new_with_path(seed_path: impl AsRef<Path>) -> Result<Self, KeyHierarchyError> {
        let seed_path = seed_path.as_ref().to_path_buf();
        let mut puf = SoftwarePUF {
            device_id: String::new(),
            seed: Vec::new(),
            seed_path,
        };
        puf.load_or_create_seed()?;
        Ok(puf)
    }

    pub fn new_from_seed(device_id: impl Into<String>, seed: Vec<u8>) -> Self {
        SoftwarePUF {
            device_id: device_id.into(),
            seed,
            seed_path: PathBuf::new(),
        }
    }

    fn load_or_create_seed(&mut self) -> Result<(), KeyHierarchyError> {
        if let Some(parent) = self.seed_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if let Ok(data) = fs::read(&self.seed_path) {
            if data.len() == 32 {
                self.seed = data;
                self.device_id = self.compute_device_id();
                return Ok(());
            }
        }

        let seed = self.generate_seed()?;
        let tmp_path = self.seed_path.with_extension("tmp");
        fs::write(&tmp_path, &seed)?;
        fs::rename(tmp_path, &self.seed_path)?;

        self.seed = seed;
        self.device_id = self.compute_device_id();
        Ok(())
    }

    fn generate_seed(&self) -> Result<Vec<u8>, KeyHierarchyError> {
        let mut hasher = Sha256::new();

        let mut random_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut random_bytes);
        hasher.update(random_bytes);
        hasher.update(b"witnessd-software-puf-v1");

        if let Ok(hostname) = hostname::get() {
            hasher.update(hostname.to_string_lossy().as_bytes());
        }

        if let Some(home) = dirs::home_dir() {
            hasher.update(home.to_string_lossy().as_bytes());
        }

        if let Ok(exe) = std::env::current_exe() {
            hasher.update(exe.to_string_lossy().as_bytes());
        }

        hasher.update(std::env::consts::OS.as_bytes());
        hasher.update(std::env::consts::ARCH.as_bytes());
        hasher.update(Utc::now().to_rfc3339().as_bytes());

        Ok(hasher.finalize().to_vec())
    }

    fn compute_device_id(&self) -> String {
        let digest = Sha256::digest(&self.seed);
        format!("swpuf-{}", hex::encode(&digest[0..4]))
    }

    pub fn seed(&self) -> Vec<u8> {
        self.seed.clone()
    }

    pub fn seed_path(&self) -> PathBuf {
        self.seed_path.clone()
    }

    pub fn get_seed(&self) -> [u8; 32] {
        let mut arr = [0u8; 32];
        if self.seed.len() == 32 {
            arr.copy_from_slice(&self.seed);
        }
        arr
    }

    pub fn get_mnemonic(&self) -> Result<String, KeyHierarchyError> {
        crate::identity::mnemonic::MnemonicHandler::entropy_to_phrase(&self.seed)
            .map_err(|e| KeyHierarchyError::Crypto(e.to_string()))
    }

    pub fn recover_from_mnemonic(
        seed_path: &Path,
        phrase: &str,
    ) -> Result<Self, KeyHierarchyError> {
        let entropy = crate::identity::mnemonic::MnemonicHandler::phrase_to_entropy(phrase)
            .map_err(|e| KeyHierarchyError::Crypto(e.to_string()))?;

        if entropy.len() != 16 && entropy.len() != 32 {
            return Err(KeyHierarchyError::Crypto("Invalid entropy length".into()));
        }

        // Standardize on 32-byte seed for SoftwarePUF
        let seed = if entropy.len() == 32 {
            entropy
        } else {
            Sha256::digest(&entropy).to_vec()
        };

        if let Some(parent) = seed_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(seed_path, &seed)?;

        Self::new_with_path(seed_path)
    }
}

impl PUFProvider for SoftwarePUF {
    fn get_response(&self, challenge: &[u8]) -> Result<Vec<u8>, KeyHierarchyError> {
        if self.seed.is_empty() {
            return Err(KeyHierarchyError::SoftwarePUFInit);
        }

        let hk = Hkdf::<Sha256>::new(Some(challenge), &self.seed);
        let mut response = [0u8; 32];
        hk.expand(b"puf-response-v1", &mut response)
            .map_err(|_| KeyHierarchyError::Crypto("HKDF expand failed".to_string()))?;
        Ok(response.to_vec())
    }

    fn device_id(&self) -> String {
        self.device_id.clone()
    }
}

pub fn get_or_create_puf() -> Result<Box<dyn PUFProvider>, KeyHierarchyError> {
    if let Ok(hw) = detect_hardware_puf() {
        return Ok(hw);
    }
    Ok(Box::new(SoftwarePUF::new()?))
}

fn detect_hardware_puf() -> Result<Box<dyn PUFProvider>, KeyHierarchyError> {
    Ok(Box::new(HardwarePUF::new()?))
}

fn witnessd_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("WITNESSD_DATA_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(home) = dirs::home_dir() {
        return home.join(".witnessd");
    }
    PathBuf::from(".witnessd")
}

#[derive(Clone)]
struct HardwarePUF {
    device_id: String,
    seed: [u8; 32],
}

impl HardwarePUF {
    fn new() -> Result<Self, KeyHierarchyError> {
        let seed = SiliconPUF::generate_fingerprint();
        let digest = Sha256::digest(seed);
        Ok(Self {
            device_id: format!("puf-{}", hex::encode(&digest[0..4])),
            seed,
        })
    }
}

impl PUFProvider for HardwarePUF {
    fn get_response(&self, challenge: &[u8]) -> Result<Vec<u8>, KeyHierarchyError> {
        let hk = Hkdf::<Sha256>::new(Some(challenge), &self.seed);
        let mut response = [0u8; 32];
        hk.expand(b"puf-response-v1", &mut response)
            .map_err(|_| KeyHierarchyError::Crypto("HKDF expand failed".to_string()))?;
        Ok(response.to_vec())
    }

    fn device_id(&self) -> String {
        self.device_id.clone()
    }
}

#[cfg(test)]
#[allow(clippy::needless_borrows_for_generic_args)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_puf() -> SoftwarePUF {
        SoftwarePUF::new_from_seed("device-1", vec![7u8; 32])
    }

    fn different_puf() -> SoftwarePUF {
        SoftwarePUF::new_from_seed("device-2", vec![8u8; 32])
    }

    #[test]
    fn test_session_certificate_verification() {
        let puf = test_puf();
        let session = start_session(&puf, [9u8; 32]).expect("start session");
        verify_session_certificate(&session.certificate).expect("verify certificate");
    }

    #[test]
    fn test_checkpoint_signature_verification() {
        let puf = test_puf();
        let mut session = start_session(&puf, [3u8; 32]).expect("start session");
        session.sign_checkpoint([1u8; 32]).expect("sign");
        session.sign_checkpoint([2u8; 32]).expect("sign");
        verify_checkpoint_signatures(&session.signatures()).expect("verify signatures");
    }

    #[test]
    fn test_key_hierarchy_evidence_verification() {
        let puf = test_puf();
        let identity = derive_master_identity(&puf).expect("identity");
        let mut session = start_session(&puf, [6u8; 32]).expect("start session");
        session.sign_checkpoint([8u8; 32]).expect("sign");
        let evidence = session.export(&identity);
        verify_key_hierarchy(&evidence).expect("verify evidence");
    }

    #[test]
    fn test_verify_session_certificate_bytes_invalid() {
        let err = verify_session_certificate_bytes(&[1u8; 10], &[2u8; 32], &[3u8; 64]).unwrap_err();
        assert!(err.contains("invalid master public key size"));
    }

    #[test]
    fn test_session_recovery_with_ratchet() {
        let puf = test_puf();
        let document_hash = [4u8; 32];
        let mut session = start_session(&puf, document_hash).expect("start session");
        session.sign_checkpoint([1u8; 32]).expect("sign");
        session.sign_checkpoint([2u8; 32]).expect("sign");

        let recovery = session
            .export_recovery_state(&puf)
            .expect("export recovery");
        let recovered = recover_session(&puf, &recovery, document_hash).expect("recover session");
        assert_eq!(recovered.signatures().len(), session.signatures().len());
        assert_eq!(recovered.current_ordinal(), session.current_ordinal());
    }

    #[test]
    fn test_derive_master_identity() {
        let puf = test_puf();
        let identity = derive_master_identity(&puf).expect("derive identity");

        assert_eq!(identity.public_key.len(), 32);
        assert!(!identity.fingerprint.is_empty());
        assert_eq!(identity.device_id, "device-1");
        assert_eq!(identity.version, VERSION);
    }

    #[test]
    fn test_same_puf_produces_same_identity() {
        let puf1 = test_puf();
        let puf2 = test_puf();

        let identity1 = derive_master_identity(&puf1).expect("derive 1");
        let identity2 = derive_master_identity(&puf2).expect("derive 2");

        assert_eq!(identity1.public_key, identity2.public_key);
        assert_eq!(identity1.fingerprint, identity2.fingerprint);
    }

    #[test]
    fn test_different_puf_produces_different_identity() {
        let puf1 = test_puf();
        let puf2 = different_puf();

        let identity1 = derive_master_identity(&puf1).expect("derive 1");
        let identity2 = derive_master_identity(&puf2).expect("derive 2");

        assert_ne!(identity1.public_key, identity2.public_key);
        assert_ne!(identity1.fingerprint, identity2.fingerprint);
    }

    #[test]
    fn test_session_sign_checkpoint_increments_ordinal() {
        let puf = test_puf();
        let mut session = start_session(&puf, [1u8; 32]).expect("start session");

        assert_eq!(session.current_ordinal(), 0);

        session.sign_checkpoint([1u8; 32]).expect("sign 1");
        assert_eq!(session.current_ordinal(), 1);

        session.sign_checkpoint([2u8; 32]).expect("sign 2");
        assert_eq!(session.current_ordinal(), 2);
    }

    #[test]
    fn test_session_end_wipes_ratchet() {
        let puf = test_puf();
        let mut session = start_session(&puf, [1u8; 32]).expect("start session");

        session.sign_checkpoint([1u8; 32]).expect("sign");
        session.end();

        let err = session.sign_checkpoint([2u8; 32]).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::RatchetWiped));
    }

    #[test]
    fn test_session_recovery_fails_with_wrong_puf() {
        let puf1 = test_puf();
        let puf2 = different_puf();
        let document_hash = [4u8; 32];

        let mut session = start_session(&puf1, document_hash).expect("start session");
        session.sign_checkpoint([1u8; 32]).expect("sign");
        let recovery = session.export_recovery_state(&puf1).expect("export");

        let err = recover_session(&puf2, &recovery, document_hash).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::SessionRecoveryFailed));
    }

    #[test]
    fn test_session_recovery_fails_with_wrong_document_hash() {
        let puf = test_puf();
        let original_hash = [4u8; 32];
        let wrong_hash = [5u8; 32];

        let mut session = start_session(&puf, original_hash).expect("start session");
        session.sign_checkpoint([1u8; 32]).expect("sign");
        let recovery = session.export_recovery_state(&puf).expect("export");

        let err = recover_session(&puf, &recovery, wrong_hash).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::SessionRecoveryFailed));
    }

    #[test]
    fn test_verify_checkpoint_signatures_ordinal_mismatch() {
        let puf = test_puf();
        let mut session = start_session(&puf, [1u8; 32]).expect("start session");
        session.sign_checkpoint([1u8; 32]).expect("sign");
        session.sign_checkpoint([2u8; 32]).expect("sign");

        let mut sigs = session.signatures();
        // Tamper with ordinal
        sigs[1].ordinal = 5; // Should be 1

        let err = verify_checkpoint_signatures(&sigs).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::OrdinalMismatch));
    }

    #[test]
    fn test_verify_checkpoint_signatures_invalid_signature() {
        let puf = test_puf();
        let mut session = start_session(&puf, [1u8; 32]).expect("start session");
        session.sign_checkpoint([1u8; 32]).expect("sign");

        let mut sigs = session.signatures();
        // Tamper with signature
        sigs[0].signature[0] ^= 0xFF;

        let err = verify_checkpoint_signatures(&sigs).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::SignatureFailed));
    }

    #[test]
    fn test_verify_ratchet_signature() {
        let puf = test_puf();
        let mut session = start_session(&puf, [1u8; 32]).expect("start session");
        let sig = session.sign_checkpoint([0xAAu8; 32]).expect("sign");

        verify_ratchet_signature(&sig.public_key, &sig.checkpoint_hash, &sig.signature)
            .expect("verify");
    }

    #[test]
    fn test_verify_ratchet_signature_invalid_public_key() {
        let err = verify_ratchet_signature(&[1u8; 16], &[2u8; 32], &[3u8; 64]).unwrap_err();
        assert!(err.contains("invalid ratchet public key size"));
    }

    #[test]
    fn test_verify_ratchet_signature_invalid_checkpoint_hash() {
        let err = verify_ratchet_signature(&[1u8; 32], &[2u8; 16], &[3u8; 64]).unwrap_err();
        assert!(err.contains("invalid checkpoint hash size"));
    }

    #[test]
    fn test_verify_ratchet_signature_invalid_signature_size() {
        let err = verify_ratchet_signature(&[1u8; 32], &[2u8; 32], &[3u8; 32]).unwrap_err();
        assert!(err.contains("invalid signature size"));
    }

    #[test]
    fn test_fingerprint_for_public_key() {
        let pubkey = [0xABu8; 32];
        let fingerprint = fingerprint_for_public_key(&pubkey);
        assert_eq!(fingerprint.len(), 16); // hex encoding of 8 bytes
    }

    #[test]
    fn test_same_pubkey_same_fingerprint() {
        let pubkey = [0xCDu8; 32];
        let fp1 = fingerprint_for_public_key(&pubkey);
        let fp2 = fingerprint_for_public_key(&pubkey);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_verify_session_certificate_bytes_invalid_session_pubkey() {
        let err = verify_session_certificate_bytes(&[1u8; 32], &[2u8; 16], &[3u8; 64]).unwrap_err();
        assert!(err.contains("invalid session public key size"));
    }

    #[test]
    fn test_verify_session_certificate_bytes_invalid_cert_signature() {
        let err = verify_session_certificate_bytes(&[1u8; 32], &[2u8; 32], &[3u8; 32]).unwrap_err();
        assert!(err.contains("invalid certificate signature size"));
    }

    #[test]
    fn test_session_export() {
        let puf = test_puf();
        let identity = derive_master_identity(&puf).expect("identity");
        let mut session = start_session(&puf, [1u8; 32]).expect("start");
        session.sign_checkpoint([1u8; 32]).expect("sign");
        session.sign_checkpoint([2u8; 32]).expect("sign");

        let evidence = session.export(&identity);

        assert_eq!(evidence.version, VERSION as i32);
        assert_eq!(evidence.master_fingerprint, identity.fingerprint);
        assert_eq!(evidence.master_public_key, identity.public_key);
        assert_eq!(evidence.ratchet_count, 2);
        assert_eq!(evidence.checkpoint_signatures.len(), 2);
        assert_eq!(evidence.ratchet_public_keys.len(), 2);
    }

    #[test]
    fn test_verify_key_hierarchy_invalid_cert() {
        let puf = test_puf();
        let identity = derive_master_identity(&puf).expect("identity");
        let mut session = start_session(&puf, [1u8; 32]).expect("start");
        session.sign_checkpoint([1u8; 32]).expect("sign");

        let mut evidence = session.export(&identity);
        // Tamper with session certificate signature
        evidence.session_certificate.as_mut().unwrap().signature[0] ^= 0xFF;

        let err = verify_key_hierarchy(&evidence).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::InvalidCert));
    }

    #[test]
    fn test_verify_key_hierarchy_fingerprint_mismatch() {
        let puf = test_puf();
        let identity = derive_master_identity(&puf).expect("identity");
        let mut session = start_session(&puf, [1u8; 32]).expect("start");
        session.sign_checkpoint([1u8; 32]).expect("sign");

        let mut evidence = session.export(&identity);
        // Tamper with fingerprint
        evidence.master_fingerprint = "wrong_fingerprint".to_string();

        let err = verify_key_hierarchy(&evidence).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::InvalidCert));
    }

    #[test]
    fn test_verify_key_hierarchy_ratchet_count_mismatch() {
        let puf = test_puf();
        let identity = derive_master_identity(&puf).expect("identity");
        let mut session = start_session(&puf, [1u8; 32]).expect("start");
        session.sign_checkpoint([1u8; 32]).expect("sign");

        let mut evidence = session.export(&identity);
        // Tamper with ratchet count
        evidence.ratchet_count = 999;

        let err = verify_key_hierarchy(&evidence).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::InvalidCert));
    }

    #[test]
    fn test_software_puf_new_with_path() {
        let dir = TempDir::new().expect("create temp dir");
        let seed_path = dir.path().join("test_puf_seed");

        let puf = SoftwarePUF::new_with_path(&seed_path).expect("create puf");
        assert_eq!(puf.seed().len(), 32);
        assert!(!puf.device_id().is_empty());
        assert_eq!(puf.seed_path(), seed_path);

        // Reopen should get same seed
        let puf2 = SoftwarePUF::new_with_path(&seed_path).expect("reopen puf");
        assert_eq!(puf.seed(), puf2.seed());
        assert_eq!(puf.device_id(), puf2.device_id());
    }

    #[test]
    fn test_software_puf_get_response() {
        let puf = test_puf();

        let challenge1 = b"challenge1";
        let challenge2 = b"challenge2";

        let response1 = puf.get_response(challenge1).expect("response 1");
        let response2 = puf.get_response(challenge2).expect("response 2");

        assert_eq!(response1.len(), 32);
        assert_eq!(response2.len(), 32);
        assert_ne!(response1, response2);

        // Same challenge should produce same response
        let response1_again = puf.get_response(challenge1).expect("response 1 again");
        assert_eq!(response1, response1_again);
    }

    #[test]
    fn test_empty_puf_fails() {
        let puf = SoftwarePUF::new_from_seed("device", vec![]);
        let err = puf.get_response(b"challenge").unwrap_err();
        assert!(matches!(err, KeyHierarchyError::SoftwarePUFInit));
    }

    #[test]
    fn test_session_recovery_no_data() {
        let puf = test_puf();
        let recovery = SessionRecoveryState {
            certificate: SessionCertificate {
                session_id: [0u8; 32], // Empty session ID
                session_pubkey: vec![],
                created_at: Utc::now(),
                document_hash: [0u8; 32],
                master_pubkey: vec![],
                signature: [0u8; 64],
                version: VERSION,
                start_quote: None,
                end_quote: None,
                start_counter: None,
                end_counter: None,
                start_reset_count: None,
                start_restart_count: None,
                end_reset_count: None,
                end_restart_count: None,
            },
            signatures: vec![],
            last_ratchet_state: vec![],
        };

        let err = recover_session(&puf, &recovery, [1u8; 32]).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::NoRecoveryData));
    }

    #[test]
    fn test_export_recovery_after_end_fails() {
        let puf = test_puf();
        let mut session = start_session(&puf, [1u8; 32]).expect("start");
        session.sign_checkpoint([1u8; 32]).expect("sign");
        session.end();

        let err = session.export_recovery_state(&puf).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::RatchetWiped));
    }

    #[test]
    fn test_signatures_returned_in_order() {
        let puf = test_puf();
        let mut session = start_session(&puf, [1u8; 32]).expect("start");

        for i in 0..5 {
            session.sign_checkpoint([(i + 1) as u8; 32]).expect("sign");
        }

        let sigs = session.signatures();
        for (i, sig) in sigs.iter().enumerate() {
            assert_eq!(sig.ordinal, i as u64);
        }
    }

    #[test]
    fn test_verify_session_certificate_tampered_pubkey() {
        let puf = test_puf();
        let mut session = start_session(&puf, [1u8; 32]).expect("start");
        session.certificate.session_pubkey[0] ^= 0xFF;

        let err = verify_session_certificate(&session.certificate).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::InvalidCert));
    }

    #[test]
    fn test_legacy_migration_verification() {
        let dir = TempDir::new().expect("create temp dir");
        let legacy_path = dir.path().join("legacy_key");
        let seed = [42u8; 32];
        fs::write(&legacy_path, &seed).expect("write legacy key");

        let puf = test_puf();
        let (migration, _identity) = migrate_from_legacy_key(&puf, &legacy_path).expect("migrate");

        verify_legacy_migration(&migration).expect("verify migration");
    }

    #[test]
    fn test_legacy_migration_invalid_sizes() {
        let migration = LegacyKeyMigration {
            legacy_public_key: vec![0u8; 16], // Should be 32
            new_master_public_key: vec![0u8; 32],
            migration_timestamp: Utc::now(),
            transition_signature: [0u8; 64],
            version: VERSION,
        };

        let err = verify_legacy_migration(&migration).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::InvalidMigration));
    }

    #[test]
    fn test_start_session_from_legacy_key() {
        let dir = TempDir::new().expect("create temp dir");
        let legacy_path = dir.path().join("legacy_key");
        let seed = [42u8; 32];
        fs::write(&legacy_path, &seed).expect("write legacy key");

        let session =
            start_session_from_legacy_key(&legacy_path, [1u8; 32]).expect("start from legacy");
        verify_session_certificate(&session.certificate).expect("verify cert");
    }

    #[test]
    fn test_legacy_key_64_bytes() {
        let dir = TempDir::new().expect("create temp dir");
        let legacy_path = dir.path().join("legacy_key_64");
        let key_data = [42u8; 64]; // 64 bytes (seed + public key format)
        fs::write(&legacy_path, &key_data).expect("write 64 byte key");

        let session = start_session_from_legacy_key(&legacy_path, [1u8; 32])
            .expect("start from 64-byte legacy");
        verify_session_certificate(&session.certificate).expect("verify cert");
    }

    #[test]
    fn test_legacy_key_not_found() {
        let err = start_session_from_legacy_key("/nonexistent/key", [1u8; 32]).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::Io(_)));
    }

    #[test]
    fn test_legacy_key_invalid_size() {
        let dir = TempDir::new().expect("create temp dir");
        let legacy_path = dir.path().join("invalid_key");
        fs::write(&legacy_path, &[1u8; 20]).expect("write invalid key");

        let err = start_session_from_legacy_key(&legacy_path, [1u8; 32]).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::LegacyKeyNotFound));
    }

    #[test]
    fn test_session_binding_no_quotes() {
        let puf = test_puf();
        let session = start_session(&puf, [1u8; 32]).expect("start");
        let report = verify_session_binding(&session.certificate).expect("verify binding");
        assert!(!report.has_start_quote);
        assert!(!report.has_end_quote);
        assert!(report.counter_delta.is_none());
        assert!(!report.reboot_detected);
        assert!(!report.restart_detected);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn test_session_binding_reboot_detected() {
        let puf = test_puf();
        let mut session = start_session(&puf, [1u8; 32]).expect("start");
        // Simulate TPM binding with reboot mid-session
        session.certificate.start_reset_count = Some(5);
        session.certificate.end_reset_count = Some(6);
        session.certificate.start_restart_count = Some(10);
        session.certificate.end_restart_count = Some(10);
        session.certificate.start_counter = Some(100);
        session.certificate.end_counter = Some(105);

        let report = verify_session_binding(&session.certificate).expect("verify binding");
        assert!(report.reboot_detected);
        assert!(!report.restart_detected);
        assert_eq!(report.counter_delta, Some(5));
        assert!(!report.warnings.is_empty());
    }

    #[test]
    fn test_session_binding_counter_rollback() {
        let puf = test_puf();
        let mut session = start_session(&puf, [1u8; 32]).expect("start");
        session.certificate.start_counter = Some(100);
        session.certificate.end_counter = Some(50); // Rollback!

        let err = verify_session_binding(&session.certificate).unwrap_err();
        assert!(matches!(err, KeyHierarchyError::Crypto(_)));
    }

    #[test]
    fn test_entangled_nonce_deterministic() {
        let session_id = [1u8; 32];
        let data_hash = [2u8; 32];
        let mmr_root = [3u8; 32];

        let nonce1 = compute_entangled_nonce(&session_id, &data_hash, &mmr_root);
        let nonce2 = compute_entangled_nonce(&session_id, &data_hash, &mmr_root);
        assert_eq!(nonce1, nonce2);

        // Different inputs produce different nonces
        let nonce3 = compute_entangled_nonce(&session_id, &data_hash, &[4u8; 32]);
        assert_ne!(nonce1, nonce3);
    }

    #[test]
    fn test_session_bind_start_quote_with_software_provider() {
        use crate::tpm::SoftwareProvider;

        let puf = test_puf();
        let mut session = start_session(&puf, [1u8; 32]).expect("start");
        let mmr_root = [5u8; 32];

        let provider = SoftwareProvider::new();
        session.bind_start_quote(&provider, &mmr_root);

        // Software provider still generates quotes (software-backed)
        assert!(session.certificate.start_quote.is_some());
        assert!(session.certificate.start_reset_count.is_some());
        assert!(session.certificate.start_restart_count.is_some());
    }

    #[test]
    fn test_session_end_with_provider() {
        use crate::tpm::SoftwareProvider;

        let puf = test_puf();
        let mut session = start_session(&puf, [1u8; 32]).expect("start");
        let mmr_root = [5u8; 32];

        let provider = SoftwareProvider::new();
        session.bind_start_quote(&provider, &mmr_root);
        session.sign_checkpoint([10u8; 32]).expect("sign");
        session.end_with_provider(&provider, &mmr_root);

        assert!(session.certificate.end_quote.is_some());
        assert!(session.certificate.end_reset_count.is_some());
        assert!(session.certificate.end_restart_count.is_some());

        // Verify no reboot detected (same provider throughout)
        let report = verify_session_binding(&session.certificate).expect("verify");
        assert!(!report.reboot_detected);
        assert!(!report.restart_detected);
    }
}
