// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::error::KeyHierarchyError;
use crate::serde_utils::serde_array_64;

pub const VERSION: u32 = 1;

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
    /// TPM quote at session start, bound via chain-entangled nonce
    #[serde(default)]
    pub start_quote: Option<Vec<u8>>,
    #[serde(default)]
    pub end_quote: Option<Vec<u8>>,
    #[serde(default)]
    pub start_counter: Option<u64>,
    #[serde(default)]
    pub end_counter: Option<u64>,
    /// TPM `ResetCount` at session start (reboot detection)
    #[serde(default)]
    pub start_reset_count: Option<u32>,
    #[serde(default)]
    pub start_restart_count: Option<u32>,
    #[serde(default)]
    pub end_reset_count: Option<u32>,
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
    /// Hardware monotonic counter at this checkpoint; `None` for software-only
    #[serde(default)]
    pub counter_value: Option<u64>,
    /// Delta from previous checkpoint's counter
    #[serde(default)]
    pub counter_delta: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct RatchetState {
    pub(crate) current: crate::crypto::ProtectedKey<32>,
    pub(crate) ordinal: u64,
    pub(crate) wiped: bool,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub certificate: SessionCertificate,
    pub(crate) ratchet: RatchetState,
    pub(crate) signatures: Vec<CheckpointSignature>,
}

pub trait PufProvider: Send + Sync {
    fn get_response(&self, challenge: &[u8]) -> Result<Vec<u8>, KeyHierarchyError>;
    fn device_id(&self) -> String;
}

/// Result of session TPM binding verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBindingReport {
    pub has_start_quote: bool,
    pub has_end_quote: bool,
    pub counter_delta: Option<u64>,
    pub reboot_detected: bool,
    pub restart_detected: bool,
    pub warnings: Vec<String>,
}

/// Hardware TPM binding evidence for a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareEvidence {
    /// e.g. "secure-enclave", "tpm2-windows", "software"
    pub provider_type: String,
    /// Attestation tier (T1--T4)
    pub attestation_tier: u8,
    pub hardware_bound: bool,
    /// TPM quote at session start, if available
    pub device_binding: Option<Vec<u8>>,
    /// Monotonic counter range over session lifetime
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
    /// Hardware attestation evidence; `None` for software-only sessions
    #[serde(default)]
    pub hardware_attestation: Option<HardwareEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecoveryState {
    pub certificate: SessionCertificate,
    pub signatures: Vec<CheckpointSignature>,
    pub last_ratchet_state: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyKeyMigration {
    pub legacy_public_key: Vec<u8>,
    pub new_master_public_key: Vec<u8>,
    pub migration_timestamp: DateTime<Utc>,
    #[serde(with = "serde_array_64")]
    pub transition_signature: [u8; 64],
    pub version: u32,
}
