use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::analysis::{calculate_hurst_rs, BehavioralFingerprint, ForgeryAnalysis};
use crate::anchors;
use crate::checkpoint;
use crate::codec::{self, Format, CBOR_TAG_PPP};
use crate::collaboration;
use crate::continuation;
use crate::declaration;
use crate::error::Error;
use crate::jitter;
use crate::keyhierarchy;
use crate::presence;
use crate::provenance;
use crate::rfc::{self, BiologyInvariantClaim, BiologyMeasurements, JitterBinding, TimeEvidence};
use crate::tpm;
use crate::vdf;

// Platform types for HID device enumeration
use crate::platform::types::HIDDeviceInfo;

// Serialization helpers for hex-encoded byte arrays

fn serialize_optional_nonce<S>(nonce: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match nonce {
        Some(n) => serializer.serialize_some(&hex::encode(n)),
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_nonce<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(hex_str) => {
            let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom("nonce must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

fn serialize_optional_signature<S>(sig: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match sig {
        Some(s) => serializer.serialize_some(&hex::encode(s)),
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_signature<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(hex_str) => {
            let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
            if bytes.len() != 64 {
                return Err(serde::de::Error::custom("signature must be 64 bytes"));
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

fn serialize_optional_pubkey<S>(key: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match key {
        Some(k) => serializer.serialize_some(&hex::encode(k)),
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_pubkey<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(hex_str) => {
            let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom("public key must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum Strength {
    Basic = 1,
    Standard = 2,
    Enhanced = 3,
    Maximum = 4,
}

impl Strength {
    pub fn as_str(&self) -> &'static str {
        match self {
            Strength::Basic => "basic",
            Strength::Standard => "standard",
            Strength::Enhanced => "enhanced",
            Strength::Maximum => "maximum",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub version: i32,
    pub exported_at: DateTime<Utc>,
    pub strength: Strength,
    pub provenance: Option<RecordProvenance>,
    pub document: DocumentInfo,
    pub checkpoints: Vec<CheckpointProof>,
    pub vdf_params: vdf::Parameters,
    pub chain_hash: String,
    pub declaration: Option<declaration::Declaration>,
    pub presence: Option<presence::Evidence>,
    pub hardware: Option<HardwareEvidence>,
    pub keystroke: Option<KeystrokeEvidence>,
    pub behavioral: Option<BehavioralEvidence>,
    pub contexts: Vec<ContextPeriod>,
    pub external: Option<ExternalAnchors>,
    pub key_hierarchy: Option<KeyHierarchyEvidencePacket>,
    /// RFC-compliant jitter binding (RFC Section: Jitter Binding).
    /// Contains entropy commitment, statistical summary, active probes, and labyrinth structure.
    pub jitter_binding: Option<JitterBinding>,
    /// RFC-compliant time evidence (RFC Section: Time Evidence).
    /// Contains TSA responses, blockchain anchors, and Roughtime samples.
    pub time_evidence: Option<TimeEvidence>,
    /// Cross-document provenance links (RFC Section: Provenance Links)
    pub provenance_links: Option<provenance::ProvenanceSection>,
    /// Multi-packet continuation info (RFC Section: Continuation Tokens)
    pub continuation: Option<continuation::ContinuationSection>,
    /// Collaborative authorship attestations (RFC Section: Collaborative Authorship)
    pub collaboration: Option<collaboration::CollaborationSection>,
    /// VDF aggregate proof for efficient verification (RFC Section: VDF Aggregation)
    pub vdf_aggregate: Option<vdf::VdfAggregateProof>,
    /// Verifier-provided freshness nonce for replay attack prevention.
    ///
    /// When a verifier requests evidence, they may provide a random 32-byte nonce.
    /// This nonce is incorporated into the packet signature to prove that the
    /// evidence was generated in response to a specific verification request,
    /// preventing replay of old evidence packets.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_nonce",
        deserialize_with = "deserialize_optional_nonce"
    )]
    pub verifier_nonce: Option<[u8; 32]>,
    /// Signature over the packet hash and verifier nonce (if present).
    ///
    /// This binds the entire evidence packet to the verifier's freshness challenge.
    /// Format: Ed25519(packet_hash || verifier_nonce) if nonce present,
    /// or Ed25519(packet_hash) if no nonce.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_signature",
        deserialize_with = "deserialize_optional_signature"
    )]
    pub packet_signature: Option<[u8; 64]>,
    /// Public key used for packet signature verification.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_pubkey",
        deserialize_with = "deserialize_optional_pubkey"
    )]
    pub signing_public_key: Option<[u8; 32]>,
    /// RFC-compliant biology invariant claim (RFC Section: Biology Invariant).
    /// Contains behavioral biometric evidence with millibits scoring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub biology_claim: Option<BiologyInvariantClaim>,
    pub claims: Vec<Claim>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHierarchyEvidencePacket {
    pub version: i32,
    pub master_fingerprint: String,
    pub master_public_key: String,
    pub device_id: String,
    pub session_id: String,
    pub session_public_key: String,
    pub session_started: DateTime<Utc>,
    pub session_certificate: String,
    pub ratchet_count: i32,
    pub ratchet_public_keys: Vec<String>,
    pub checkpoint_signatures: Vec<CheckpointSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointSignature {
    pub ordinal: u64,
    pub checkpoint_hash: String,
    pub ratchet_index: i32,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPeriod {
    #[serde(rename = "type")]
    pub period_type: String,
    pub note: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentInfo {
    pub title: String,
    pub path: String,
    pub final_hash: String,
    pub final_size: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordProvenance {
    pub device_id: String,
    pub signing_pubkey: String,
    pub key_source: String,
    pub hostname: String,
    pub os: String,
    pub os_version: Option<String>,
    pub architecture: String,
    pub session_id: String,
    pub session_started: DateTime<Utc>,
    pub input_devices: Vec<InputDeviceInfo>,
    pub access_control: Option<AccessControlInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDeviceInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub product_name: String,
    pub serial_number: Option<String>,
    pub connection_type: String,
    pub fingerprint: String,
}

impl From<HIDDeviceInfo> for InputDeviceInfo {
    fn from(hid: HIDDeviceInfo) -> Self {
        let transport = hid.transport_type();
        Self {
            vendor_id: hid.vendor_id as u16,
            product_id: hid.product_id as u16,
            product_name: hid.product_name.clone(),
            serial_number: hid.serial_number.clone(),
            connection_type: transport.as_str().to_string(),
            fingerprint: hid.fingerprint(),
        }
    }
}

impl From<&HIDDeviceInfo> for InputDeviceInfo {
    fn from(hid: &HIDDeviceInfo) -> Self {
        let transport = hid.transport_type();
        Self {
            vendor_id: hid.vendor_id as u16,
            product_id: hid.product_id as u16,
            product_name: hid.product_name.clone(),
            serial_number: hid.serial_number.clone(),
            connection_type: transport.as_str().to_string(),
            fingerprint: hid.fingerprint(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlInfo {
    pub captured_at: DateTime<Utc>,
    pub file_owner_uid: i32,
    pub file_owner_name: Option<String>,
    pub file_permissions: String,
    pub file_group_gid: Option<i32>,
    pub file_group_name: Option<String>,
    pub process_uid: i32,
    pub process_euid: i32,
    pub process_username: Option<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointProof {
    pub ordinal: u64,
    pub content_hash: String,
    pub content_size: i64,
    pub timestamp: DateTime<Utc>,
    pub message: Option<String>,
    pub vdf_input: Option<String>,
    pub vdf_output: Option<String>,
    pub vdf_iterations: Option<u64>,
    pub elapsed_time: Option<Duration>,
    pub previous_hash: String,
    pub hash: String,
    pub signature: Option<String>,
}

/// Hardware attestation evidence binding TPM/TEE state to session.
///
/// The attestation nonce is a 32-byte cryptographically secure random value
/// generated at session start. It binds the TPM quote to this specific session,
/// preventing replay attacks where an attacker might reuse a quote from a
/// different session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareEvidence {
    pub bindings: Vec<tpm::Binding>,
    pub device_id: String,
    /// Cryptographically secure 32-byte nonce generated at session start.
    /// Used as the nonce parameter in TPM quote operations to bind
    /// the attestation to this specific evidence session.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_nonce",
        deserialize_with = "deserialize_optional_nonce"
    )]
    pub attestation_nonce: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeEvidence {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub duration: Duration,
    pub total_keystrokes: u64,
    pub total_samples: i32,
    pub keystrokes_per_minute: f64,
    pub unique_doc_states: i32,
    pub chain_valid: bool,
    pub plausible_human_rate: bool,
    pub samples: Vec<jitter::Sample>,
    /// Ratio of samples using hardware entropy (0.0 to 1.0).
    /// Only set when using HybridJitterSession with physjitter feature.
    #[serde(default)]
    pub phys_ratio: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralEvidence {
    pub edit_topology: Vec<EditRegion>,
    pub metrics: Option<ForensicMetrics>,
    /// Behavioral fingerprint extracted from typing patterns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<BehavioralFingerprint>,
    /// Forgery detection analysis results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forgery_analysis: Option<ForgeryAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRegion {
    pub start_pct: f64,
    pub end_pct: f64,
    pub delta_sign: i32,
    pub byte_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMetrics {
    pub monotonic_append_ratio: f64,
    pub edit_entropy: f64,
    pub median_interval_seconds: f64,
    pub positive_negative_ratio: f64,
    pub deletion_clustering: f64,
    pub assessment: Option<String>,
    pub anomaly_count: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAnchors {
    pub opentimestamps: Vec<OTSProof>,
    pub rfc3161: Vec<RFC3161Proof>,
    pub proofs: Vec<AnchorProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTSProof {
    pub chain_hash: String,
    pub proof: String,
    pub status: String,
    pub block_height: Option<u64>,
    pub block_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RFC3161Proof {
    pub chain_hash: String,
    pub tsa_url: String,
    pub response: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorProof {
    pub provider: String,
    pub provider_name: String,
    pub legal_standing: String,
    pub regions: Vec<String>,
    pub hash: String,
    pub timestamp: DateTime<Utc>,
    pub status: String,
    pub raw_proof: String,
    pub blockchain: Option<BlockchainAnchorInfo>,
    pub verify_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainAnchorInfo {
    pub chain: String,
    pub block_height: u64,
    pub block_hash: Option<String>,
    pub block_time: DateTime<Utc>,
    pub tx_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    #[serde(rename = "type")]
    pub claim_type: ClaimType,
    pub description: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClaimType {
    #[serde(rename = "chain_integrity")]
    ChainIntegrity,
    #[serde(rename = "time_elapsed")]
    TimeElapsed,
    #[serde(rename = "process_declared")]
    ProcessDeclared,
    #[serde(rename = "presence_verified")]
    PresenceVerified,
    #[serde(rename = "keystrokes_verified")]
    KeystrokesVerified,
    #[serde(rename = "hardware_attested")]
    HardwareAttested,
    #[serde(rename = "behavior_analyzed")]
    BehaviorAnalyzed,
    #[serde(rename = "contexts_recorded")]
    ContextsRecorded,
    #[serde(rename = "external_anchored")]
    ExternalAnchored,
    #[serde(rename = "key_hierarchy")]
    KeyHierarchy,
}

pub struct Builder {
    packet: Packet,
    errors: Vec<String>,
}

impl Builder {
    pub fn new(title: &str, chain: &checkpoint::Chain) -> Self {
        let mut packet = Packet {
            version: 1,
            exported_at: Utc::now(),
            strength: Strength::Basic,
            provenance: None,
            document: DocumentInfo {
                title: title.to_string(),
                path: chain.document_path.clone(),
                final_hash: String::new(),
                final_size: 0,
            },
            checkpoints: Vec::new(),
            vdf_params: chain.vdf_params,
            chain_hash: String::new(),
            declaration: None,
            presence: None,
            hardware: None,
            keystroke: None,
            behavioral: None,
            contexts: Vec::new(),
            external: None,
            key_hierarchy: None,
            jitter_binding: None,
            time_evidence: None,
            provenance_links: None,
            continuation: None,
            collaboration: None,
            vdf_aggregate: None,
            verifier_nonce: None,
            packet_signature: None,
            signing_public_key: None,
            biology_claim: None,
            claims: Vec::new(),
            limitations: Vec::new(),
        };

        if let Some(latest) = chain.latest() {
            packet.document.final_hash = hex::encode(latest.content_hash);
            packet.document.final_size = latest.content_size;
        }

        for cp in &chain.checkpoints {
            let mut proof = CheckpointProof {
                ordinal: cp.ordinal,
                content_hash: hex::encode(cp.content_hash),
                content_size: cp.content_size,
                timestamp: cp.timestamp,
                message: cp.message.clone(),
                vdf_input: None,
                vdf_output: None,
                vdf_iterations: None,
                elapsed_time: None,
                previous_hash: hex::encode(cp.previous_hash),
                hash: hex::encode(cp.hash),
                signature: None,
            };

            if let Some(sig) = &cp.signature {
                proof.signature = Some(hex::encode(sig));
            }

            if let Some(vdf_proof) = &cp.vdf {
                proof.vdf_input = Some(hex::encode(vdf_proof.input));
                proof.vdf_output = Some(hex::encode(vdf_proof.output));
                proof.vdf_iterations = Some(vdf_proof.iterations);
                proof.elapsed_time = Some(vdf_proof.min_elapsed_time(chain.vdf_params));
            }

            packet.checkpoints.push(proof);
        }

        if let Some(latest) = chain.latest() {
            packet.chain_hash = hex::encode(latest.hash);
        }

        Self {
            packet,
            errors: Vec::new(),
        }
    }

    pub fn with_declaration(mut self, decl: &declaration::Declaration) -> Self {
        if !decl.verify() {
            self.errors
                .push("declaration signature invalid".to_string());
            return self;
        }
        self.packet.declaration = Some(decl.clone());
        self
    }

    pub fn with_presence(mut self, sessions: &[presence::Session]) -> Self {
        if sessions.is_empty() {
            return self;
        }
        let evidence = presence::compile_evidence(sessions);
        self.packet.presence = Some(evidence);
        if self.packet.strength < Strength::Standard {
            self.packet.strength = Strength::Standard;
        }
        self
    }

    /// Add hardware attestation evidence with TPM bindings.
    ///
    /// # Arguments
    /// * `bindings` - TPM binding chain for checkpoint attestation
    /// * `device_id` - Unique device identifier from TPM
    /// * `attestation_nonce` - Optional 32-byte nonce used for TPM quote freshness
    pub fn with_hardware(
        mut self,
        bindings: Vec<tpm::Binding>,
        device_id: String,
        attestation_nonce: Option<[u8; 32]>,
    ) -> Self {
        if bindings.is_empty() {
            return self;
        }
        self.packet.hardware = Some(HardwareEvidence {
            bindings,
            device_id,
            attestation_nonce,
        });
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    pub fn with_keystroke(mut self, evidence: &jitter::Evidence) -> Self {
        if evidence.statistics.total_keystrokes == 0 {
            return self;
        }
        if evidence.verify().is_err() {
            self.errors.push("keystroke evidence invalid".to_string());
            return self;
        }

        let keystroke = KeystrokeEvidence {
            session_id: evidence.session_id.clone(),
            started_at: evidence.started_at,
            ended_at: evidence.ended_at,
            duration: evidence.statistics.duration,
            total_keystrokes: evidence.statistics.total_keystrokes,
            total_samples: evidence.statistics.total_samples,
            keystrokes_per_minute: evidence.statistics.keystrokes_per_min,
            unique_doc_states: evidence.statistics.unique_doc_hashes,
            chain_valid: evidence.statistics.chain_valid,
            plausible_human_rate: evidence.is_plausible_human_typing(),
            samples: evidence.samples.clone(),
            phys_ratio: None,
        };

        self.packet.keystroke = Some(keystroke);
        if self.packet.strength < Strength::Standard {
            self.packet.strength = Strength::Standard;
        }
        self
    }

    /// Add hybrid keystroke evidence with hardware entropy metrics.
    ///
    /// If phys_ratio > 0.8 (80% hardware entropy), boosts evidence strength
    /// to Enhanced level, providing stronger assurance that keystrokes
    /// originated from real hardware rather than software injection.
    #[cfg(feature = "physjitter")]
    pub fn with_hybrid_keystroke(
        mut self,
        evidence: &crate::physjitter_bridge::HybridEvidence,
    ) -> Self {
        if evidence.statistics.total_keystrokes == 0 {
            return self;
        }
        if evidence.verify().is_err() {
            self.errors
                .push("hybrid keystroke evidence invalid".to_string());
            return self;
        }

        // Convert HybridSample to jitter::Sample for backward compatibility
        let samples: Vec<jitter::Sample> = evidence
            .samples
            .iter()
            .map(|hs| jitter::Sample {
                timestamp: hs.timestamp,
                keystroke_count: hs.keystroke_count,
                document_hash: hs.document_hash,
                jitter_micros: hs.jitter_micros,
                hash: hs.hash,
                previous_hash: hs.previous_hash,
            })
            .collect();

        let keystroke = KeystrokeEvidence {
            session_id: evidence.session_id.clone(),
            started_at: evidence.started_at,
            ended_at: evidence.ended_at,
            duration: evidence.statistics.duration,
            total_keystrokes: evidence.statistics.total_keystrokes,
            total_samples: evidence.statistics.total_samples,
            keystrokes_per_minute: evidence.statistics.keystrokes_per_min,
            unique_doc_states: evidence.statistics.unique_doc_hashes,
            chain_valid: evidence.statistics.chain_valid,
            plausible_human_rate: evidence.is_plausible_human_typing(),
            samples,
            phys_ratio: Some(evidence.entropy_quality.phys_ratio),
        };

        self.packet.keystroke = Some(keystroke);

        // Boost to Standard for any keystroke evidence
        if self.packet.strength < Strength::Standard {
            self.packet.strength = Strength::Standard;
        }

        // Boost to Enhanced if >80% hardware entropy
        // High hardware entropy strongly indicates genuine human input
        if evidence.entropy_quality.phys_ratio > 0.8 {
            if self.packet.strength < Strength::Enhanced {
                self.packet.strength = Strength::Enhanced;
            }
            self.packet.claims.push(Claim {
                claim_type: ClaimType::KeystrokesVerified,
                description: format!(
                    "Hardware entropy ratio {:.0}% - strong assurance of genuine input",
                    evidence.entropy_quality.phys_ratio * 100.0
                ),
                confidence: "high".to_string(),
            });
        }

        self
    }

    pub fn with_behavioral(
        mut self,
        regions: Vec<EditRegion>,
        metrics: Option<ForensicMetrics>,
    ) -> Self {
        if regions.is_empty() && metrics.is_none() {
            return self;
        }
        self.packet.behavioral = Some(BehavioralEvidence {
            edit_topology: regions,
            metrics,
            fingerprint: None,
            forgery_analysis: None,
        });
        if self.packet.strength < Strength::Maximum {
            self.packet.strength = Strength::Maximum;
        }
        self
    }

    /// Add behavioral evidence with full analysis including forgery detection.
    pub fn with_behavioral_full(
        mut self,
        regions: Vec<EditRegion>,
        metrics: Option<ForensicMetrics>,
        samples: &[jitter::SimpleJitterSample],
    ) -> Self {
        let fingerprint = if samples.len() >= 2 {
            Some(BehavioralFingerprint::from_samples(samples))
        } else {
            None
        };

        let forgery_analysis = if samples.len() >= 10 {
            Some(BehavioralFingerprint::detect_forgery(samples))
        } else {
            None
        };

        self.packet.behavioral = Some(BehavioralEvidence {
            edit_topology: regions,
            metrics,
            fingerprint,
            forgery_analysis,
        });

        if self.packet.strength < Strength::Maximum {
            self.packet.strength = Strength::Maximum;
        }
        self
    }

    pub fn with_contexts(mut self, contexts: Vec<ContextPeriod>) -> Self {
        if contexts.is_empty() {
            return self;
        }
        self.packet.contexts = contexts;
        self
    }

    pub fn with_provenance(mut self, prov: RecordProvenance) -> Self {
        self.packet.provenance = Some(prov);
        self
    }

    /// Populate input_devices in provenance from HID device enumeration.
    ///
    /// This converts a list of HIDDeviceInfo (from platform enumeration) into
    /// InputDeviceInfo records with transport type and fingerprint.
    ///
    /// # Arguments
    /// * `devices` - HID device information from keyboard enumeration
    pub fn with_input_devices(mut self, devices: &[HIDDeviceInfo]) -> Self {
        if let Some(ref mut prov) = self.packet.provenance {
            prov.input_devices = devices.iter().map(InputDeviceInfo::from).collect();
        } else {
            // Create minimal provenance with just input devices
            self.errors
                .push("with_input_devices requires with_provenance to be called first".to_string());
        }
        self
    }

    pub fn with_external_anchors(mut self, ots: Vec<OTSProof>, rfc: Vec<RFC3161Proof>) -> Self {
        if ots.is_empty() && rfc.is_empty() {
            return self;
        }
        self.packet.external = Some(ExternalAnchors {
            opentimestamps: ots,
            rfc3161: rfc,
            proofs: Vec::new(),
        });
        if self.packet.strength < Strength::Maximum {
            self.packet.strength = Strength::Maximum;
        }
        self
    }

    pub fn with_anchors(mut self, proofs: &[anchors::Proof]) -> Self {
        if proofs.is_empty() {
            return self;
        }

        if self.packet.external.is_none() {
            self.packet.external = Some(ExternalAnchors {
                opentimestamps: Vec::new(),
                rfc3161: Vec::new(),
                proofs: Vec::new(),
            });
        }

        let ext = self.packet.external.as_mut().unwrap();
        for proof in proofs {
            ext.proofs.push(convert_anchor_proof(proof));
        }

        if self.packet.strength < Strength::Maximum {
            self.packet.strength = Strength::Maximum;
        }
        self
    }

    pub fn with_key_hierarchy(mut self, evidence: &keyhierarchy::KeyHierarchyEvidence) -> Self {
        let packet = KeyHierarchyEvidencePacket {
            version: evidence.version,
            master_fingerprint: evidence.master_fingerprint.clone(),
            master_public_key: hex::encode(&evidence.master_public_key),
            device_id: evidence.device_id.clone(),
            session_id: evidence.session_id.clone(),
            session_public_key: hex::encode(&evidence.session_public_key),
            session_started: evidence.session_started,
            session_certificate: general_purpose::STANDARD
                .encode(&evidence.session_certificate_raw),
            ratchet_count: evidence.ratchet_count,
            ratchet_public_keys: evidence
                .ratchet_public_keys
                .iter()
                .map(hex::encode)
                .collect(),
            checkpoint_signatures: evidence
                .checkpoint_signatures
                .iter()
                .enumerate()
                .map(|(idx, sig)| CheckpointSignature {
                    ordinal: sig.ordinal,
                    checkpoint_hash: hex::encode(sig.checkpoint_hash),
                    ratchet_index: idx as i32,
                    signature: general_purpose::STANDARD.encode(sig.signature),
                })
                .collect(),
        };

        self.packet.key_hierarchy = Some(packet);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Add provenance links for cross-document relationships
    pub fn with_provenance_links(mut self, section: provenance::ProvenanceSection) -> Self {
        if section.parent_links.is_empty() {
            return self;
        }
        self.packet.provenance_links = Some(section);
        self
    }

    /// Add continuation section for multi-packet series
    pub fn with_continuation(mut self, section: continuation::ContinuationSection) -> Self {
        self.packet.continuation = Some(section);
        self
    }

    /// Add collaboration section for multi-author attestations
    pub fn with_collaboration(mut self, section: collaboration::CollaborationSection) -> Self {
        if section.participants.is_empty() {
            return self;
        }
        self.packet.collaboration = Some(section);
        self
    }

    /// Add VDF aggregate proof for efficient verification
    pub fn with_vdf_aggregate(mut self, proof: vdf::VdfAggregateProof) -> Self {
        self.packet.vdf_aggregate = Some(proof);
        self
    }

    /// Add RFC-compliant jitter binding for behavioral entropy evidence.
    ///
    /// Includes entropy commitment, statistical summary, active probes (Galton Invariant,
    /// Reflex Gate), and labyrinth structure (phase space topology).
    pub fn with_jitter_binding(mut self, binding: JitterBinding) -> Self {
        self.packet.jitter_binding = Some(binding);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Add RFC-compliant time evidence for temporal binding.
    ///
    /// Includes TSA responses, blockchain anchors, and Roughtime samples.
    pub fn with_time_evidence(mut self, evidence: TimeEvidence) -> Self {
        self.packet.time_evidence = Some(evidence);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Add RFC-compliant biology invariant claim.
    ///
    /// Contains behavioral biometric evidence with millibits scoring for
    /// Hurst exponent, pink noise (1/f), and error topology analysis.
    pub fn with_biology_claim(mut self, claim: BiologyInvariantClaim) -> Self {
        self.packet.biology_claim = Some(claim);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Build jitter binding from keystroke evidence.
    ///
    /// Automatically computes entropy commitment, statistical summary,
    /// Hurst exponent, and forgery analysis from raw samples.
    pub fn with_jitter_from_keystroke(
        mut self,
        keystroke: &KeystrokeEvidence,
        document_hash: &[u8; 32],
    ) -> Self {
        if keystroke.samples.len() < 10 {
            self.errors
                .push("insufficient jitter samples for binding".to_string());
            return self;
        }

        // Compute statistics from jitter_micros (already in microseconds)
        let intervals_us: Vec<f64> = keystroke
            .samples
            .iter()
            .map(|s| s.jitter_micros as f64)
            .filter(|&i| i > 0.0 && i < 5_000_000.0) // Filter outliers > 5s
            .collect();

        if intervals_us.is_empty() {
            self.errors
                .push("no valid jitter intervals found".to_string());
            return self;
        }

        let mean = intervals_us.iter().sum::<f64>() / intervals_us.len() as f64;
        let variance = intervals_us.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
            / intervals_us.len() as f64;
        let std_dev = variance.sqrt();
        let cv = if mean > 0.0 { std_dev / mean } else { 0.0 };

        // Compute percentiles
        let mut sorted = intervals_us.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let percentiles = if sorted.len() >= 10 {
            [
                sorted[sorted.len() / 10],
                sorted[sorted.len() / 4],
                sorted[sorted.len() / 2],
                sorted[3 * sorted.len() / 4],
                sorted[9 * sorted.len() / 10],
            ]
        } else {
            [mean; 5] // Fallback to mean for small samples
        };

        // Compute Hurst exponent (requires at least 20 samples)
        let hurst_exponent = if intervals_us.len() >= 20 {
            calculate_hurst_rs(&intervals_us).ok().map(|h| h.exponent)
        } else {
            None
        };

        // Compute entropy commitment using sample timestamps
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"witnessd-jitter-entropy-v1");
        for s in &keystroke.samples {
            hasher.update(s.timestamp.timestamp_nanos_opt().unwrap_or(0).to_be_bytes());
        }
        let entropy_hash: [u8; 32] = hasher.finalize().into();

        // Create binding MAC
        let timestamp_ms = chrono::Utc::now().timestamp_millis() as u64;
        let mut mac_hasher = sha2::Sha256::new();
        mac_hasher.update(document_hash);
        mac_hasher.update(keystroke.total_keystrokes.to_be_bytes());
        mac_hasher.update(timestamp_ms.to_be_bytes());
        mac_hasher.update(entropy_hash);
        let mac: [u8; 32] = mac_hasher.finalize().into();

        let binding = JitterBinding {
            entropy_commitment: rfc::EntropyCommitment {
                hash: entropy_hash,
                timestamp_ms,
                previous_hash: [0u8; 32],
            },
            sources: vec![rfc::jitter_binding::SourceDescriptor {
                source_type: "keyboard".to_string(),
                weight: 1000,
                device_fingerprint: None,
                transport_calibration: None,
            }],
            summary: rfc::JitterSummary {
                sample_count: keystroke.samples.len() as u64,
                mean_interval_us: mean,
                std_dev,
                coefficient_of_variation: cv,
                percentiles,
                entropy_bits: (keystroke.samples.len() as f64).log2() * 2.0, // Simplified
                hurst_exponent,
            },
            binding_mac: rfc::BindingMac {
                mac,
                document_hash: *document_hash,
                keystroke_count: keystroke.total_keystrokes,
                timestamp_ms,
            },
            raw_intervals: None,
            active_probes: None,
            labyrinth_structure: None,
        };

        self.packet.jitter_binding = Some(binding);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Attach active probes (Galton invariant and reflex gate) to jitter binding.
    ///
    /// Must be called after `with_jitter_from_keystroke` or `with_jitter_binding`.
    /// Active probes provide adversarial stimulus-response measurements.
    pub fn with_active_probes(
        mut self,
        probes: &crate::analysis::active_probes::ActiveProbeResults,
    ) -> Self {
        if let Some(ref mut binding) = self.packet.jitter_binding {
            binding.active_probes = Some(probes.into());
        } else {
            self.errors
                .push("jitter_binding required before active_probes".to_string());
        }
        self
    }

    /// Attach labyrinth structure (Takens embedding) to jitter binding.
    ///
    /// Must be called after `with_jitter_from_keystroke` or `with_jitter_binding`.
    /// Labyrinth structure captures topological properties of timing dynamics.
    pub fn with_labyrinth_structure(
        mut self,
        analysis: &crate::analysis::labyrinth::LabyrinthAnalysis,
    ) -> Self {
        if let Some(ref mut binding) = self.packet.jitter_binding {
            binding.labyrinth_structure = Some(analysis.into());
        } else {
            self.errors
                .push("jitter_binding required before labyrinth_structure".to_string());
        }
        self
    }

    /// Build biology invariant claim from analysis results.
    ///
    /// Creates an RFC-compliant biology claim with millibits scoring
    /// from Hurst exponent, pink noise, and error topology analyses.
    pub fn with_biology_from_analysis(
        mut self,
        measurements: BiologyMeasurements,
        hurst: Option<&crate::analysis::hurst::HurstAnalysis>,
        pink_noise: Option<&crate::analysis::pink_noise::PinkNoiseAnalysis>,
        error_topology: Option<&crate::analysis::error_topology::ErrorTopology>,
    ) -> Self {
        let claim =
            BiologyInvariantClaim::from_analysis(measurements, hurst, pink_noise, error_topology);
        self.packet.biology_claim = Some(claim);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    pub fn build(mut self) -> crate::error::Result<Packet> {
        if self.packet.declaration.is_none() {
            self.errors.push("declaration is required".to_string());
        }
        if !self.errors.is_empty() {
            return Err(Error::evidence(format!("build errors: {:?}", self.errors)));
        }
        self.generate_claims();
        self.generate_limitations();
        Ok(self.packet)
    }

    fn generate_claims(&mut self) {
        self.packet.claims.push(Claim {
            claim_type: ClaimType::ChainIntegrity,
            description: "Content states form an unbroken cryptographic chain".to_string(),
            confidence: "cryptographic".to_string(),
        });

        let mut total_time = Duration::from_secs(0);
        for cp in &self.packet.checkpoints {
            if let Some(elapsed) = cp.elapsed_time {
                total_time += elapsed;
            }
        }
        if total_time > Duration::from_secs(0) {
            self.packet.claims.push(Claim {
                claim_type: ClaimType::TimeElapsed,
                description: format!(
                    "At least {:?} elapsed during documented composition",
                    total_time
                ),
                confidence: "cryptographic".to_string(),
            });
        }

        if let Some(decl) = &self.packet.declaration {
            let ai_desc = if decl.has_ai_usage() {
                format!("AI assistance declared: {:?} extent", decl.max_ai_extent())
            } else {
                "No AI tools declared".to_string()
            };
            self.packet.claims.push(Claim {
                claim_type: ClaimType::ProcessDeclared,
                description: format!("Author signed declaration of creative process. {ai_desc}"),
                confidence: "attestation".to_string(),
            });
        }

        if let Some(presence) = &self.packet.presence {
            self.packet.claims.push(Claim {
                claim_type: ClaimType::PresenceVerified,
                description: format!(
                    "Author presence verified {:.0}% of challenged sessions",
                    presence.overall_rate * 100.0
                ),
                confidence: "cryptographic".to_string(),
            });
        }

        if let Some(keystroke) = &self.packet.keystroke {
            let mut desc = format!(
                "{} keystrokes recorded over {:?} ({:.0}/min)",
                keystroke.total_keystrokes, keystroke.duration, keystroke.keystrokes_per_minute
            );
            if keystroke.plausible_human_rate {
                desc.push_str(", consistent with human typing");
            }
            self.packet.claims.push(Claim {
                claim_type: ClaimType::KeystrokesVerified,
                description: desc,
                confidence: "cryptographic".to_string(),
            });
        }

        if self.packet.hardware.is_some() {
            self.packet.claims.push(Claim {
                claim_type: ClaimType::HardwareAttested,
                description: "TPM attests chain was not rolled back or modified".to_string(),
                confidence: "cryptographic".to_string(),
            });
        }

        if self.packet.behavioral.is_some() {
            self.packet.claims.push(Claim {
                claim_type: ClaimType::BehaviorAnalyzed,
                description: "Edit patterns captured for forensic analysis".to_string(),
                confidence: "statistical".to_string(),
            });
        }

        if !self.packet.contexts.is_empty() {
            let mut assisted = 0;
            let mut external = 0;
            for ctx in &self.packet.contexts {
                if ctx.period_type == "assisted" {
                    assisted += 1;
                }
                if ctx.period_type == "external" {
                    external += 1;
                }
            }
            let mut desc = format!("{} context periods recorded", self.packet.contexts.len());
            if assisted > 0 {
                desc.push_str(&format!(" ({assisted} AI-assisted)"));
            }
            if external > 0 {
                desc.push_str(&format!(" ({external} external)"));
            }
            self.packet.claims.push(Claim {
                claim_type: ClaimType::ContextsRecorded,
                description: desc,
                confidence: "attestation".to_string(),
            });
        }

        if let Some(external) = &self.packet.external {
            let count =
                external.opentimestamps.len() + external.rfc3161.len() + external.proofs.len();
            self.packet.claims.push(Claim {
                claim_type: ClaimType::ExternalAnchored,
                description: format!("Chain anchored to {count} external timestamp authorities"),
                confidence: "cryptographic".to_string(),
            });
        }

        if let Some(kh) = &self.packet.key_hierarchy {
            let mut desc = format!(
                "Identity {} with {} ratchet generations",
                if kh.master_fingerprint.len() > 16 {
                    format!("{}...", &kh.master_fingerprint[..16])
                } else {
                    kh.master_fingerprint.clone()
                },
                kh.ratchet_count
            );
            if !kh.checkpoint_signatures.is_empty() {
                desc.push_str(&format!(
                    ", {} checkpoint signatures",
                    kh.checkpoint_signatures.len()
                ));
            }
            self.packet.claims.push(Claim {
                claim_type: ClaimType::KeyHierarchy,
                description: desc,
                confidence: "cryptographic".to_string(),
            });
        }
    }

    fn generate_limitations(&mut self) {
        self.packet
            .limitations
            .push("Cannot prove cognitive origin of ideas".to_string());
        self.packet
            .limitations
            .push("Cannot prove absence of AI involvement in ideation".to_string());

        if self.packet.presence.is_none() {
            self.packet.limitations.push(
                "No presence verification - cannot confirm human was at keyboard".to_string(),
            );
        }

        if self.packet.keystroke.is_none() {
            self.packet
                .limitations
                .push("No keystroke evidence - cannot verify real typing occurred".to_string());
        }

        if self.packet.hardware.is_none() {
            self.packet
                .limitations
                .push("No hardware attestation - software-only security".to_string());
        }

        if let Some(decl) = &self.packet.declaration {
            if decl.has_ai_usage() {
                self.packet.limitations.push(
                    "Author declares AI tool usage - verify institutional policy compliance"
                        .to_string(),
                );
            }
        }
    }
}

pub fn convert_anchor_proof(proof: &anchors::Proof) -> AnchorProof {
    let provider = format!("{:?}", proof.provider).to_lowercase();
    let timestamp = proof.confirmed_at.unwrap_or(proof.submitted_at);
    let mut anchor = AnchorProof {
        provider: provider.clone(),
        provider_name: provider,
        legal_standing: String::new(),
        regions: Vec::new(),
        hash: hex::encode(proof.anchored_hash),
        timestamp,
        status: format!("{:?}", proof.status).to_lowercase(),
        raw_proof: general_purpose::STANDARD.encode(&proof.proof_data),
        blockchain: None,
        verify_url: proof.location.clone(),
    };

    if matches!(
        proof.provider,
        anchors::ProviderType::Bitcoin | anchors::ProviderType::Ethereum
    ) {
        let chain = match proof.provider {
            anchors::ProviderType::Bitcoin => "bitcoin",
            anchors::ProviderType::Ethereum => "ethereum",
            _ => "unknown",
        };
        let block_height = proof
            .extra
            .get("block_height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let block_hash = proof
            .extra
            .get("block_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let block_time = proof
            .extra
            .get("block_time")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or(timestamp);
        let tx_id = proof.location.clone();

        anchor.blockchain = Some(BlockchainAnchorInfo {
            chain: chain.to_string(),
            block_height,
            block_hash,
            block_time,
            tx_id,
        });
    }

    anchor
}

/// Compute a binding hash for a set of secure events.
pub fn compute_events_binding_hash(events: &[crate::store::SecureEvent]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-events-binding-v1");
    for e in events {
        hasher.update(&e.event_hash);
    }
    hasher.finalize().into()
}

impl Packet {
    pub fn verify(&self, _vdf_params: vdf::Parameters) -> crate::error::Result<()> {
        if let Some(last) = self.checkpoints.last() {
            let expected_chain_hash = last.hash.clone();
            if self.chain_hash != expected_chain_hash {
                return Err(Error::evidence("chain hash mismatch"));
            }
            if self.document.final_hash != last.content_hash {
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
                if cp.previous_hash != hex::encode([0u8; 32]) {
                    return Err(Error::evidence("checkpoint 0: non-zero previous hash"));
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
            let master_pub = hex::decode(&kh.master_public_key).unwrap_or_default();
            let session_pub = hex::decode(&kh.session_public_key).unwrap_or_default();
            let cert_raw = general_purpose::STANDARD
                .decode(&kh.session_certificate)
                .unwrap_or_default();

            if let Err(err) =
                keyhierarchy::verify_session_certificate_bytes(&master_pub, &session_pub, &cert_raw)
            {
                return Err(Error::evidence(format!(
                    "key hierarchy verification failed: {err}"
                )));
            }

            for sig in &kh.checkpoint_signatures {
                let ratchet_pub = kh
                    .ratchet_public_keys
                    .get(sig.ratchet_index as usize)
                    .map(|s| hex::decode(s).unwrap_or_default())
                    .unwrap_or_default();
                let checkpoint_hash = hex::decode(&sig.checkpoint_hash).unwrap_or_default();
                let signature = general_purpose::STANDARD
                    .decode(&sig.signature)
                    .unwrap_or_default();

                keyhierarchy::verify_ratchet_signature(&ratchet_pub, &checkpoint_hash, &signature)
                    .map_err(|e| {
                        Error::evidence(format!("key hierarchy verification failed: {e}"))
                    })?;
            }
        }

        Ok(())
    }

    pub fn total_elapsed_time(&self) -> Duration {
        let mut total = Duration::from_secs(0);
        for cp in &self.checkpoints {
            if let Some(elapsed) = cp.elapsed_time {
                total += elapsed;
            }
        }
        total
    }

    /// Encode the packet to CBOR with PPP semantic tag (RFC-compliant default).
    pub fn encode(&self) -> crate::error::Result<Vec<u8>> {
        codec::cbor::encode_ppp(self).map_err(|e| Error::evidence(format!("encode failed: {e}")))
    }

    /// Encode the packet in the specified format.
    pub fn encode_with_format(&self, format: Format) -> crate::error::Result<Vec<u8>> {
        match format {
            Format::Cbor => codec::cbor::encode_ppp(self)
                .map_err(|e| Error::evidence(format!("encode failed: {e}"))),
            Format::Json => serde_json::to_vec_pretty(self)
                .map_err(|e| Error::evidence(format!("encode failed: {e}"))),
        }
    }

    /// Decode a packet, auto-detecting format and validating CBOR tag.
    pub fn decode(data: &[u8]) -> crate::error::Result<Packet> {
        let format =
            Format::detect(data).ok_or_else(|| Error::evidence("unable to detect format"))?;

        match format {
            Format::Cbor => {
                // Validate PPP semantic tag is present
                if !codec::cbor::has_tag(data, CBOR_TAG_PPP) {
                    return Err(Error::evidence("missing or invalid CBOR PPP tag"));
                }
                codec::cbor::decode_ppp(data)
                    .map_err(|e| Error::evidence(format!("decode failed: {e}")))
            }
            Format::Json => serde_json::from_slice(data)
                .map_err(|e| Error::evidence(format!("decode failed: {e}"))),
        }
    }

    /// Decode a packet with explicit format (skips format detection).
    pub fn decode_with_format(data: &[u8], format: Format) -> crate::error::Result<Packet> {
        match format {
            Format::Cbor => {
                // Validate PPP semantic tag is present
                if !codec::cbor::has_tag(data, CBOR_TAG_PPP) {
                    return Err(Error::evidence("missing or invalid CBOR PPP tag"));
                }
                codec::cbor::decode_ppp(data)
                    .map_err(|e| Error::evidence(format!("decode failed: {e}")))
            }
            Format::Json => serde_json::from_slice(data)
                .map_err(|e| Error::evidence(format!("decode failed: {e}"))),
        }
    }

    /// Compute the deterministic hash of this packet using raw CBOR encoding.
    ///
    /// Uses untagged CBOR for deterministic, compact hashing (RFC 8949 Section 4.2).
    pub fn hash(&self) -> [u8; 32] {
        // Use raw CBOR (no tag) for deterministic hashing
        let data = codec::cbor::encode(self).unwrap_or_default();
        Sha256::digest(data).into()
    }

    /// Compute the hash used for verifier nonce binding.
    ///
    /// This creates a hash of the packet content excluding signature-related
    /// fields (verifier_nonce, packet_signature, signing_public_key) to prevent
    /// circular dependencies in the signature.
    pub fn content_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-packet-content-v1");
        hasher.update(self.version.to_be_bytes());
        hasher.update(
            self.exported_at
                .timestamp_nanos_opt()
                .unwrap_or(0)
                .to_be_bytes(),
        );
        hasher.update((self.strength as i32).to_be_bytes());
        hasher.update(self.document.final_hash.as_bytes());
        hasher.update(self.document.final_size.to_be_bytes());
        hasher.update(self.chain_hash.as_bytes());

        // Include checkpoint hashes
        hasher.update((self.checkpoints.len() as u64).to_be_bytes());
        for cp in &self.checkpoints {
            hasher.update(cp.hash.as_bytes());
        }

        // Include declaration if present
        if let Some(decl) = &self.declaration {
            hasher.update(b"decl");
            hasher.update(&decl.signature);
        }

        // Include VDF params
        hasher.update(self.vdf_params.iterations_per_second.to_be_bytes());
        hasher.update(self.vdf_params.min_iterations.to_be_bytes());

        hasher.finalize().into()
    }

    /// Compute the signing payload for verifier nonce binding.
    ///
    /// Returns SHA-256(content_hash || verifier_nonce) if nonce is present,
    /// or content_hash if no nonce.
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

    /// Set a verifier-provided freshness nonce.
    ///
    /// The nonce should be a random 32-byte value provided by the verifier
    /// to prove the evidence was generated in response to their specific request.
    pub fn set_verifier_nonce(&mut self, nonce: [u8; 32]) {
        self.verifier_nonce = Some(nonce);
        // Clear any existing signature since the payload has changed
        self.packet_signature = None;
        self.signing_public_key = None;
    }

    /// Sign the packet with the given signing key.
    ///
    /// This creates an Ed25519 signature over the signing payload, which includes
    /// the verifier nonce if one has been set. The signature proves that the
    /// evidence packet was generated by the holder of the signing key.
    ///
    /// If a verifier nonce is present, the signature proves the packet was
    /// created in response to that specific verification request.
    pub fn sign(&mut self, signing_key: &SigningKey) -> crate::error::Result<()> {
        let payload = self.signing_payload();
        let signature = signing_key.sign(&payload);
        self.packet_signature = Some(signature.to_bytes());
        self.signing_public_key = Some(signing_key.verifying_key().to_bytes());
        Ok(())
    }

    /// Sign the packet with a verifier-provided nonce.
    ///
    /// This is a convenience method that sets the nonce and signs in one call.
    pub fn sign_with_nonce(
        &mut self,
        signing_key: &SigningKey,
        nonce: [u8; 32],
    ) -> crate::error::Result<()> {
        self.set_verifier_nonce(nonce);
        self.sign(signing_key)
    }

    /// Verify the packet signature.
    ///
    /// Returns Ok(()) if the signature is valid, or an error describing
    /// why verification failed.
    ///
    /// If expected_nonce is provided, verification will fail if the packet's
    /// verifier_nonce doesn't match, preventing replay attacks.
    pub fn verify_signature(&self, expected_nonce: Option<&[u8; 32]>) -> crate::error::Result<()> {
        // Check nonce expectation
        match (expected_nonce, &self.verifier_nonce) {
            (Some(expected), Some(actual)) => {
                if expected != actual {
                    return Err(Error::Signature("verifier nonce mismatch".into()));
                }
            }
            (Some(_), None) => {
                return Err(Error::Signature(
                    "expected verifier nonce but none present".into(),
                ));
            }
            (None, Some(_)) => {
                // Verifier didn't expect a nonce but one is present - this is ok,
                // it just means the signature binds to that nonce
            }
            (None, None) => {
                // No nonce expected and none present - ok
            }
        }

        // Get signature and public key
        let signature_bytes = self
            .packet_signature
            .ok_or_else(|| Error::Signature("packet not signed".into()))?;
        let public_key_bytes = self
            .signing_public_key
            .ok_or_else(|| Error::Signature("missing signing public key".into()))?;

        // Parse public key
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| Error::Signature(format!("invalid public key: {e}")))?;

        // Parse signature
        let signature = Signature::from_bytes(&signature_bytes);

        // Verify
        let payload = self.signing_payload();
        public_key
            .verify(&payload, &signature)
            .map_err(|e| Error::Signature(format!("signature verification failed: {e}")))?;

        Ok(())
    }

    /// Check if this packet has a verifier nonce.
    pub fn has_verifier_nonce(&self) -> bool {
        self.verifier_nonce.is_some()
    }

    /// Check if this packet has been signed.
    pub fn is_signed(&self) -> bool {
        self.packet_signature.is_some() && self.signing_public_key.is_some()
    }

    /// Get the verifier nonce if present.
    pub fn get_verifier_nonce(&self) -> Option<&[u8; 32]> {
        self.verifier_nonce.as_ref()
    }

    /// Convert to RFC-compliant wire format.
    ///
    /// Creates a `PacketRfc` structure with integer keys suitable for
    /// compact CBOR encoding per the RATS specification.
    pub fn to_rfc(&self) -> rfc::PacketRfc {
        rfc::PacketRfc::from(self)
    }
}

// ============================================================================
// RFC Conversion Implementations
// ============================================================================
//
// These implementations convert between the internal Packet format (with
// string keys and human-readable field names) and the RFC-compliant PacketRfc
// format (with integer keys and fixed-point types for CBOR wire encoding).

impl From<&Packet> for rfc::PacketRfc {
    fn from(packet: &Packet) -> Self {
        // Convert VDF parameters to VdfStructure
        let vdf = rfc::VdfStructure {
            input: packet
                .checkpoints
                .first()
                .and_then(|cp| cp.vdf_input.as_ref())
                .map(|s| hex::decode(s).unwrap_or_default())
                .unwrap_or_default(),
            output: packet
                .checkpoints
                .last()
                .and_then(|cp| cp.vdf_output.as_ref())
                .map(|s| hex::decode(s).unwrap_or_default())
                .unwrap_or_default(),
            iterations: packet
                .checkpoints
                .iter()
                .filter_map(|cp| cp.vdf_iterations)
                .sum(),
            rdtsc_checkpoints: Vec::new(), // Not available in legacy format
            entropic_pulse: Vec::new(),    // Not available in legacy format
        };

        // Convert jitter binding to JitterSealStructure
        let jitter_seal = if let Some(jb) = &packet.jitter_binding {
            // Estimate entropy from sample count (approx 8 bits per sample)
            let entropy_estimate = jb.summary.sample_count as u32 * 8 * 1000;
            rfc::JitterSealStructure {
                lang: "en-US".to_string(), // Default, not tracked in legacy
                bucket_commitment: jb.entropy_commitment.hash.to_vec(),
                entropy_millibits: entropy_estimate.min(20_000_000), // Cap at 20k bits
                dp_epsilon_centibits: rfc::Centibits::from_float(0.5), // Default
                pink_noise_slope_decibits: rfc::SlopeDecibits::from_float(-1.0), // Default
            }
        } else {
            rfc::JitterSealStructure {
                lang: "en-US".to_string(),
                bucket_commitment: Vec::new(),
                entropy_millibits: 0,
                dp_epsilon_centibits: rfc::Centibits::from_float(0.5),
                pink_noise_slope_decibits: rfc::SlopeDecibits::from_float(-1.0),
            }
        };

        // Convert content hash tree
        let content_hash_tree = rfc::ContentHashTree {
            root: hex::decode(&packet.document.final_hash).unwrap_or_else(|_| vec![0u8; 32]),
            segment_count: packet.checkpoints.len().max(20) as u16,
        };

        // Convert correlation proof from behavioral evidence
        let correlation_proof = if let Some(behavioral) = &packet.behavioral {
            if let Some(fp) = &behavioral.fingerprint {
                // Use coefficient of variation as a proxy for correlation
                // Higher consistency = higher correlation
                let cv = fp.keystroke_interval_std / fp.keystroke_interval_mean.max(1.0);
                let rho = (1.0 - cv.min(1.0)).max(0.5); // Convert CV to correlation estimate
                rfc::CorrelationProof {
                    rho: rfc::RhoMillibits::from_float(rho),
                    threshold: 700,
                }
            } else {
                rfc::CorrelationProof::default()
            }
        } else {
            rfc::CorrelationProof::default()
        };

        // Convert error topology if available
        let error_topology = packet.behavioral.as_ref().and_then(|b| {
            b.fingerprint.as_ref().map(|fp| rfc::ErrorTopology {
                fractal_dimension_decibits: rfc::Decibits::from_float(fp.keystroke_interval_std),
                clustering_millibits: rfc::Millibits::from_float(
                    fp.keystroke_interval_mean / 1000.0,
                ),
                temporal_signature: Vec::new(),
            })
        });

        // Convert hardware enclave if available
        let enclave_vise = packet.hardware.as_ref().and_then(|hw| {
            hw.bindings.first().map(|binding| rfc::EnclaveVise {
                enclave_type: match binding.provider_type.as_str() {
                    "SecureEnclave" => 1,
                    "TPM2" => 16,
                    "SGX" => 17,
                    _ => 0,
                },
                attestation: binding.signature.clone(),
                timestamp: binding.timestamp.timestamp() as u64,
            })
        });

        // Determine profile tier
        let profile = Some(match packet.strength {
            Strength::Basic => rfc::ProfileDeclaration::core(),
            Strength::Standard => rfc::ProfileDeclaration::core(),
            Strength::Enhanced => rfc::ProfileDeclaration::enhanced(),
            Strength::Maximum => rfc::ProfileDeclaration::maximum(),
        });

        rfc::PacketRfc {
            version: 1,
            vdf,
            jitter_seal,
            content_hash_tree,
            correlation_proof,
            error_topology,
            enclave_vise,
            zk_verdict: None, // Not available in legacy format
            profile,
            privacy_budget: None, // Not available in legacy format
            key_rotation: None,   // Not available in legacy format
            extensions: std::collections::HashMap::new(),
        }
    }
}

impl From<Packet> for rfc::PacketRfc {
    fn from(packet: Packet) -> Self {
        rfc::PacketRfc::from(&packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declaration;
    use crate::vdf;
    use ed25519_dalek::SigningKey;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn temp_document_path() -> PathBuf {
        let name = format!("witnessd-evidence-test-{}.txt", uuid::Uuid::new_v4());
        std::env::temp_dir().join(name)
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn create_test_chain(dir: &TempDir) -> (checkpoint::Chain, PathBuf) {
        let path = dir.path().join("test_document.txt");
        fs::write(&path, b"test content").expect("write doc");
        let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
        chain.commit(None).expect("commit");
        (chain, path)
    }

    fn create_test_declaration(chain: &checkpoint::Chain) -> declaration::Declaration {
        let latest = chain.latest().expect("latest");
        let signing_key = test_signing_key();
        declaration::no_ai_declaration(
            latest.content_hash,
            latest.hash,
            "Test Doc",
            "I wrote this.",
        )
        .sign(&signing_key)
        .expect("sign declaration")
    }

    #[test]
    fn test_packet_roundtrip_and_verify() {
        let path = temp_document_path();
        fs::write(&path, b"hello witnessd").expect("write temp doc");

        let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
        chain.commit(None).expect("commit");

        let latest = chain.latest().expect("latest");
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let decl = declaration::no_ai_declaration(
            latest.content_hash,
            latest.hash,
            "Test Doc",
            "I wrote this.",
        )
        .sign(&signing_key)
        .expect("sign declaration");

        let packet = Builder::new("Test Doc", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build packet");

        packet.verify(chain.vdf_params).expect("verify packet");

        let encoded = packet.encode().expect("encode");
        let decoded = Packet::decode(&encoded).expect("decode");
        assert_eq!(decoded.document.title, packet.document.title);
        assert_eq!(decoded.checkpoints.len(), packet.checkpoints.len());
        assert_eq!(decoded.chain_hash, packet.chain_hash);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_builder_requires_declaration() {
        let path = temp_document_path();
        fs::write(&path, b"hello witnessd").expect("write temp doc");

        let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
        chain.commit(None).expect("commit");

        let err = Builder::new("Test Doc", &chain).build().unwrap_err();
        assert!(err.to_string().contains("declaration is required"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_strength_levels() {
        assert!(Strength::Basic < Strength::Standard);
        assert!(Strength::Standard < Strength::Enhanced);
        assert!(Strength::Enhanced < Strength::Maximum);

        assert_eq!(Strength::Basic.as_str(), "basic");
        assert_eq!(Strength::Standard.as_str(), "standard");
        assert_eq!(Strength::Enhanced.as_str(), "enhanced");
        assert_eq!(Strength::Maximum.as_str(), "maximum");
    }

    #[test]
    fn test_packet_with_multiple_checkpoints() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("doc.txt");
        fs::write(&path, b"initial").expect("write");

        let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");

        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 1");

        fs::write(&path, b"final").expect("final");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 2");

        let decl = create_test_declaration(&chain);
        let packet = Builder::new("Multi Checkpoint", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        assert_eq!(packet.checkpoints.len(), 3);
        packet.verify(chain.vdf_params).expect("verify");
    }

    #[test]
    fn test_packet_verify_chain_hash_mismatch() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        packet.chain_hash = "wrong_hash".to_string();

        let err = packet.verify(chain.vdf_params).unwrap_err();
        assert!(err.to_string().contains("chain hash mismatch"));
    }

    #[test]
    fn test_packet_verify_document_hash_mismatch() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        packet.document.final_hash = "wrong_hash".to_string();

        let err = packet.verify(chain.vdf_params).unwrap_err();
        assert!(err.to_string().contains("document final hash mismatch"));
    }

    #[test]
    fn test_packet_verify_document_size_mismatch() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        packet.document.final_size = 9999;

        let err = packet.verify(chain.vdf_params).unwrap_err();
        assert!(err.to_string().contains("document final size mismatch"));
    }

    #[test]
    fn test_packet_verify_broken_chain_link() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("doc.txt");
        fs::write(&path, b"initial").expect("write");

        let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");
        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 1");

        let decl = create_test_declaration(&chain);
        let mut packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        // Tamper with chain
        packet.checkpoints[1].previous_hash = "wrong".to_string();

        let err = packet.verify(chain.vdf_params).unwrap_err();
        assert!(err.to_string().contains("broken chain link"));
    }

    #[test]
    fn test_packet_verify_invalid_declaration() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let mut decl = create_test_declaration(&chain);

        // Tamper with declaration
        decl.signature[0] ^= 0xFF;

        let err = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("declaration signature invalid"));
    }

    #[test]
    fn test_packet_total_elapsed_time() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("doc.txt");
        fs::write(&path, b"initial").expect("write");

        let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");
        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(50))
            .expect("commit 1");

        let decl = create_test_declaration(&chain);
        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        let elapsed = packet.total_elapsed_time();
        assert!(elapsed > Duration::from_secs(0));
    }

    #[test]
    fn test_packet_hash() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        let hash = packet.hash();
        assert_ne!(hash, [0u8; 32]);

        // Same packet should have same hash
        let hash2 = packet.hash();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_builder_with_presence() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut verifier = presence::Verifier::new(presence::Config {
            enabled_challenges: vec![presence::ChallengeType::TypeWord],
            challenge_interval: Duration::from_secs(1),
            interval_variance: 0.0,
            response_window: Duration::from_secs(60),
        });
        verifier.start_session().expect("start");
        let challenge = verifier.issue_challenge().expect("issue");
        let word = challenge
            .prompt
            .strip_prefix("Type the word: ")
            .expect("prompt");
        verifier
            .respond_to_challenge(&challenge.id, word)
            .expect("respond");
        let session = verifier.end_session().expect("end");

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .with_presence(&[session])
            .build()
            .expect("build");

        assert!(packet.presence.is_some());
        assert!(packet.strength >= Strength::Standard);
    }

    #[test]
    fn test_builder_with_empty_presence() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .with_presence(&[])
            .build()
            .expect("build");

        assert!(packet.presence.is_none());
    }

    #[test]
    fn test_builder_with_contexts() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let contexts = vec![ContextPeriod {
            period_type: "focused".to_string(),
            note: Some("writing session".to_string()),
            start_time: Utc::now(),
            end_time: Utc::now(),
        }];

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .with_contexts(contexts)
            .build()
            .expect("build");

        assert_eq!(packet.contexts.len(), 1);
    }

    #[test]
    fn test_builder_with_behavioral() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let regions = vec![EditRegion {
            start_pct: 0.0,
            end_pct: 50.0,
            delta_sign: 1,
            byte_count: 100,
        }];

        let metrics = ForensicMetrics {
            monotonic_append_ratio: 0.8,
            edit_entropy: 0.5,
            median_interval_seconds: 2.0,
            positive_negative_ratio: 0.9,
            deletion_clustering: 0.1,
            assessment: Some("normal".to_string()),
            anomaly_count: Some(0),
        };

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .with_behavioral(regions, Some(metrics))
            .build()
            .expect("build");

        assert!(packet.behavioral.is_some());
        assert_eq!(packet.strength, Strength::Maximum);
    }

    #[test]
    fn test_builder_with_provenance() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let prov = RecordProvenance {
            device_id: "test-device".to_string(),
            signing_pubkey: "abc123".to_string(),
            key_source: "software".to_string(),
            hostname: "testhost".to_string(),
            os: "linux".to_string(),
            os_version: Some("5.0".to_string()),
            architecture: "x86_64".to_string(),
            session_id: "session-1".to_string(),
            session_started: Utc::now(),
            input_devices: vec![],
            access_control: None,
        };

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .with_provenance(prov)
            .build()
            .expect("build");

        assert!(packet.provenance.is_some());
        assert_eq!(packet.provenance.as_ref().unwrap().device_id, "test-device");
    }

    #[test]
    fn test_claims_generated() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        // Should have at least chain integrity and process declared claims
        assert!(packet
            .claims
            .iter()
            .any(|c| matches!(c.claim_type, ClaimType::ChainIntegrity)));
        assert!(packet
            .claims
            .iter()
            .any(|c| matches!(c.claim_type, ClaimType::ProcessDeclared)));
    }

    #[test]
    fn test_limitations_generated() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        // Should have cognitive origin limitation
        assert!(packet
            .limitations
            .iter()
            .any(|l| l.contains("cognitive origin")));
    }

    #[test]
    fn test_empty_chain() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("empty.txt");
        fs::write(&path, b"content").expect("write");

        let chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
        // No commits

        let signing_key = test_signing_key();
        let decl = declaration::no_ai_declaration([1u8; 32], [2u8; 32], "Empty Chain", "Test")
            .sign(&signing_key)
            .expect("sign");

        let packet = Builder::new("Empty", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        assert!(packet.checkpoints.is_empty());
        assert!(packet.chain_hash.is_empty());
    }

    #[test]
    fn test_packet_verify_first_checkpoint_nonzero_previous() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        packet.checkpoints[0].previous_hash = "nonzero".to_string();

        let err = packet.verify(chain.vdf_params).unwrap_err();
        assert!(err.to_string().contains("non-zero previous hash"));
    }

    #[test]
    fn test_ai_declaration_claims() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("doc.txt");
        fs::write(&path, b"content").expect("write");

        let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
        chain.commit(None).expect("commit");

        let latest = chain.latest().expect("latest");
        let signing_key = test_signing_key();
        let decl =
            declaration::ai_assisted_declaration(latest.content_hash, latest.hash, "AI Assisted")
                .add_modality(declaration::ModalityType::Keyboard, 80.0, None)
                .add_modality(declaration::ModalityType::Paste, 20.0, None)
                .add_ai_tool(
                    "ChatGPT",
                    None,
                    declaration::AIPurpose::Feedback,
                    None,
                    declaration::AIExtent::Moderate,
                )
                .with_statement("Used AI for feedback")
                .sign(&signing_key)
                .expect("sign");

        let packet = Builder::new("AI Doc", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        // Should have AI-related limitation
        assert!(packet
            .limitations
            .iter()
            .any(|l| l.contains("AI tool usage")));
    }

    #[test]
    fn test_document_info() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("doc.txt");
        fs::write(&path, b"hello world").expect("write");

        let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
        chain.commit(None).expect("commit");
        let decl = create_test_declaration(&chain);

        let packet = Builder::new("Test Doc", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        assert_eq!(packet.document.title, "Test Doc");
        assert!(packet.document.path.contains("doc.txt"));
        assert!(!packet.document.final_hash.is_empty());
        assert_eq!(packet.document.final_size, 11); // "hello world".len()
    }

    #[test]
    fn test_checkpoint_proof_fields() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("doc.txt");
        fs::write(&path, b"initial").expect("write");

        let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
        chain
            .commit_with_vdf_duration(Some("first commit".to_string()), Duration::from_millis(10))
            .expect("commit 0");
        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 1");

        let decl = create_test_declaration(&chain);
        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        let cp0 = &packet.checkpoints[0];
        assert_eq!(cp0.ordinal, 0);
        assert_eq!(cp0.message, Some("first commit".to_string()));
        assert!(!cp0.content_hash.is_empty());
        assert!(!cp0.hash.is_empty());

        let cp1 = &packet.checkpoints[1];
        assert_eq!(cp1.ordinal, 1);
        assert!(cp1.vdf_input.is_some());
        assert!(cp1.vdf_output.is_some());
        assert!(cp1.vdf_iterations.is_some());
    }

    #[test]
    fn test_external_anchors() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let ots = vec![OTSProof {
            chain_hash: "abc123".to_string(),
            proof: "base64proof".to_string(),
            status: "pending".to_string(),
            block_height: None,
            block_time: None,
        }];

        let rfc = vec![RFC3161Proof {
            chain_hash: "abc123".to_string(),
            tsa_url: "https://tsa.example.com".to_string(),
            response: "base64response".to_string(),
            timestamp: Utc::now(),
        }];

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .with_external_anchors(ots, rfc)
            .build()
            .expect("build");

        assert!(packet.external.is_some());
        let external = packet.external.unwrap();
        assert_eq!(external.opentimestamps.len(), 1);
        assert_eq!(external.rfc3161.len(), 1);
    }

    #[test]
    fn test_version() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        assert_eq!(packet.version, 1);
    }

    #[test]
    fn test_vdf_params_preserved() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        assert_eq!(
            packet.vdf_params.iterations_per_second,
            chain.vdf_params.iterations_per_second
        );
        assert_eq!(
            packet.vdf_params.min_iterations,
            chain.vdf_params.min_iterations
        );
        assert_eq!(
            packet.vdf_params.max_iterations,
            chain.vdf_params.max_iterations
        );
    }

    #[test]
    fn test_hardware_evidence_with_attestation_nonce() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        // Create a test attestation nonce
        let nonce: [u8; 32] = [0x42u8; 32];

        // Create a minimal binding for testing
        let binding = tpm::Binding {
            version: 1,
            provider_type: "software".to_string(),
            device_id: "test-device".to_string(),
            timestamp: Utc::now(),
            attested_hash: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            public_key: vec![7, 8, 9],
            monotonic_counter: None,
            safe_clock: Some(true),
            attestation: None,
        };

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .with_hardware(vec![binding], "test-device".to_string(), Some(nonce))
            .build()
            .expect("build");

        // Verify hardware evidence is present with nonce
        assert!(packet.hardware.is_some());
        let hw = packet.hardware.as_ref().unwrap();
        assert_eq!(hw.device_id, "test-device");
        assert!(hw.attestation_nonce.is_some());
        assert_eq!(hw.attestation_nonce.unwrap(), nonce);

        // Verify strength is Enhanced with hardware attestation
        assert!(packet.strength >= Strength::Enhanced);
    }

    #[test]
    fn test_hardware_evidence_without_nonce() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let binding = tpm::Binding {
            version: 1,
            provider_type: "software".to_string(),
            device_id: "test-device".to_string(),
            timestamp: Utc::now(),
            attested_hash: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            public_key: vec![7, 8, 9],
            monotonic_counter: None,
            safe_clock: Some(true),
            attestation: None,
        };

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .with_hardware(vec![binding], "test-device".to_string(), None)
            .build()
            .expect("build");

        // Verify hardware evidence is present without nonce
        assert!(packet.hardware.is_some());
        let hw = packet.hardware.as_ref().unwrap();
        assert!(hw.attestation_nonce.is_none());
    }

    #[test]
    fn test_hardware_evidence_nonce_serialization() {
        let nonce: [u8; 32] = [0xABu8; 32];
        let hw = HardwareEvidence {
            bindings: vec![],
            device_id: "test".to_string(),
            attestation_nonce: Some(nonce),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&hw).expect("serialize");

        // Verify nonce is hex-encoded
        assert!(json.contains(&hex::encode(nonce)));

        // Deserialize back
        let decoded: HardwareEvidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.attestation_nonce, Some(nonce));
    }

    #[test]
    fn test_hardware_evidence_nonce_none_serialization() {
        let hw = HardwareEvidence {
            bindings: vec![],
            device_id: "test".to_string(),
            attestation_nonce: None,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&hw).expect("serialize");

        // Verify attestation_nonce is not present (skip_serializing_if = "Option::is_none")
        assert!(!json.contains("attestation_nonce"));

        // Deserialize back
        let decoded: HardwareEvidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.attestation_nonce, None);
    }

    // =========================================================================
    // Verifier Nonce Tests (Replay Attack Prevention)
    // =========================================================================

    #[test]
    fn test_packet_sign_without_nonce() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        // Sign without nonce
        let signing_key = test_signing_key();
        packet.sign(&signing_key).expect("sign");

        assert!(packet.is_signed());
        assert!(!packet.has_verifier_nonce());
        assert!(packet.packet_signature.is_some());
        assert!(packet.signing_public_key.is_some());

        // Verify without expecting a nonce
        packet.verify_signature(None).expect("verify");
    }

    #[test]
    fn test_packet_sign_with_nonce() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        // Sign with nonce
        let signing_key = test_signing_key();
        let nonce: [u8; 32] = [0x42u8; 32];
        packet.sign_with_nonce(&signing_key, nonce).expect("sign");

        assert!(packet.is_signed());
        assert!(packet.has_verifier_nonce());
        assert_eq!(packet.get_verifier_nonce(), Some(&nonce));

        // Verify with the correct nonce
        packet.verify_signature(Some(&nonce)).expect("verify");
    }

    #[test]
    fn test_packet_verify_with_wrong_nonce() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        let signing_key = test_signing_key();
        let nonce: [u8; 32] = [0x42u8; 32];
        packet.sign_with_nonce(&signing_key, nonce).expect("sign");

        // Verify with wrong nonce should fail
        let wrong_nonce: [u8; 32] = [0x99u8; 32];
        let err = packet.verify_signature(Some(&wrong_nonce)).unwrap_err();
        assert!(err.to_string().contains("nonce mismatch"));
    }

    #[test]
    fn test_packet_verify_expects_nonce_but_none_present() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        // Sign without nonce
        let signing_key = test_signing_key();
        packet.sign(&signing_key).expect("sign");

        // Verify expecting a nonce should fail
        let expected_nonce: [u8; 32] = [0x42u8; 32];
        let err = packet.verify_signature(Some(&expected_nonce)).unwrap_err();
        assert!(err
            .to_string()
            .contains("expected verifier nonce but none present"));
    }

    #[test]
    fn test_packet_verify_not_signed() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        // Verify without signing should fail
        let err = packet.verify_signature(None).unwrap_err();
        assert!(err.to_string().contains("packet not signed"));
    }

    #[test]
    fn test_packet_nonce_replay_attack_prevention() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        let signing_key = test_signing_key();
        let nonce1: [u8; 32] = [0x11u8; 32];
        let nonce2: [u8; 32] = [0x22u8; 32];

        // Sign with first nonce
        packet.sign_with_nonce(&signing_key, nonce1).expect("sign");

        // Verify with first nonce passes
        packet
            .verify_signature(Some(&nonce1))
            .expect("verify nonce1");

        // Attempting to verify with second nonce fails (replay prevention)
        let err = packet.verify_signature(Some(&nonce2)).unwrap_err();
        assert!(err.to_string().contains("nonce mismatch"));
    }

    #[test]
    fn test_packet_nonce_serialization() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        let signing_key = test_signing_key();
        let nonce: [u8; 32] = [0xABu8; 32];
        packet.sign_with_nonce(&signing_key, nonce).expect("sign");

        // Encode to JSON
        let encoded = packet.encode().expect("encode");

        // Decode back
        let decoded = Packet::decode(&encoded).expect("decode");

        // Verify fields are preserved
        assert_eq!(decoded.verifier_nonce, packet.verifier_nonce);
        assert_eq!(decoded.packet_signature, packet.packet_signature);
        assert_eq!(decoded.signing_public_key, packet.signing_public_key);

        // Verify signature still works
        decoded
            .verify_signature(Some(&nonce))
            .expect("verify after roundtrip");
    }

    #[test]
    fn test_set_verifier_nonce_clears_signature() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        let signing_key = test_signing_key();
        let nonce1: [u8; 32] = [0x11u8; 32];

        // Sign with first nonce
        packet.sign_with_nonce(&signing_key, nonce1).expect("sign");
        assert!(packet.is_signed());

        // Setting a new nonce should clear the signature
        let nonce2: [u8; 32] = [0x22u8; 32];
        packet.set_verifier_nonce(nonce2);

        assert!(!packet.is_signed());
        assert!(packet.packet_signature.is_none());
        assert!(packet.signing_public_key.is_none());
        assert!(packet.has_verifier_nonce());
        assert_eq!(packet.get_verifier_nonce(), Some(&nonce2));
    }

    #[test]
    fn test_content_hash_stability() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        // Content hash should be consistent
        let hash1 = packet.content_hash();
        let hash2 = packet.content_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_signing_payload_without_nonce() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        // Without nonce, signing payload equals content hash
        let content = packet.content_hash();
        let payload = packet.signing_payload();
        assert_eq!(content, payload);
    }

    #[test]
    fn test_signing_payload_with_nonce() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        let nonce: [u8; 32] = [0x42u8; 32];
        packet.set_verifier_nonce(nonce);

        // With nonce, signing payload differs from content hash
        let content = packet.content_hash();
        let payload = packet.signing_payload();
        assert_ne!(content, payload);
    }

    #[test]
    fn test_different_nonces_produce_different_payloads() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let mut packet1 = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        let mut packet2 = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        let nonce1: [u8; 32] = [0x11u8; 32];
        let nonce2: [u8; 32] = [0x22u8; 32];

        packet1.set_verifier_nonce(nonce1);
        packet2.set_verifier_nonce(nonce2);

        // Different nonces should produce different signing payloads
        let payload1 = packet1.signing_payload();
        let payload2 = packet2.signing_payload();
        assert_ne!(payload1, payload2);
    }

    #[test]
    fn test_cbor_encoding_with_ppp_tag() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        // Default encode uses CBOR with PPP tag
        let encoded = packet.encode().expect("encode");

        // Verify it has the PPP semantic tag
        assert!(
            crate::codec::cbor::has_tag(&encoded, crate::codec::CBOR_TAG_PPP),
            "encoded packet should have PPP semantic tag"
        );

        // Verify format detection works
        let format = crate::codec::Format::detect(&encoded);
        assert_eq!(format, Some(crate::codec::Format::Cbor));

        // Verify roundtrip
        let decoded = Packet::decode(&encoded).expect("decode");
        assert_eq!(decoded.document.title, packet.document.title);
        assert_eq!(decoded.chain_hash, packet.chain_hash);
    }

    #[test]
    fn test_json_format_encoding() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        // Encode as JSON
        let encoded = packet
            .encode_with_format(crate::codec::Format::Json)
            .expect("encode json");

        // Verify format detection
        let format = crate::codec::Format::detect(&encoded);
        assert_eq!(format, Some(crate::codec::Format::Json));

        // Verify it starts with JSON object marker
        assert_eq!(encoded[0], b'{');

        // Verify roundtrip via auto-detect
        let decoded = Packet::decode(&encoded).expect("decode");
        assert_eq!(decoded.document.title, packet.document.title);
    }

    #[test]
    fn test_cbor_missing_tag_rejected() {
        let dir = TempDir::new().expect("temp dir");
        let (chain, _) = create_test_chain(&dir);
        let decl = create_test_declaration(&chain);

        let packet = Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        // Encode as raw CBOR (no tag)
        let untagged = crate::codec::cbor::encode(&packet).expect("encode untagged");

        // Decoding should fail due to missing PPP tag
        let result = Packet::decode(&untagged);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("missing or invalid CBOR PPP tag"));
    }
}
