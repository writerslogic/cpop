use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::anchors;
use crate::checkpoint;
use crate::declaration;
use crate::jitter;
use crate::keyhierarchy;
use crate::presence;
use crate::tpm;
use crate::vdf;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareEvidence {
    pub bindings: Vec<tpm::Binding>,
    pub device_id: String,
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

    pub fn with_hardware(mut self, bindings: Vec<tpm::Binding>, device_id: String) -> Self {
        if bindings.is_empty() {
            return self;
        }
        self.packet.hardware = Some(HardwareEvidence {
            bindings,
            device_id,
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

    pub fn build(mut self) -> Result<Packet, String> {
        if self.packet.declaration.is_none() {
            self.errors.push("declaration is required".to_string());
        }
        if !self.errors.is_empty() {
            return Err(format!("build errors: {:?}", self.errors));
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

impl Packet {
    pub fn verify(&self, _vdf_params: vdf::Parameters) -> Result<(), String> {
        if let Some(last) = self.checkpoints.last() {
            let expected_chain_hash = last.hash.clone();
            if self.chain_hash != expected_chain_hash {
                return Err("chain hash mismatch".to_string());
            }
            if self.document.final_hash != last.content_hash {
                return Err("document final hash mismatch".to_string());
            }
            if self.document.final_size != last.content_size {
                return Err("document final size mismatch".to_string());
            }
        } else if !self.chain_hash.is_empty() {
            return Err("chain hash present with no checkpoints".to_string());
        }

        let mut prev_hash = String::new();
        for (i, cp) in self.checkpoints.iter().enumerate() {
            if i == 0 {
                if cp.previous_hash != hex::encode([0u8; 32]) {
                    return Err("checkpoint 0: non-zero previous hash".to_string());
                }
            } else if cp.previous_hash != prev_hash {
                return Err(format!("checkpoint {i}: broken chain link"));
            }
            prev_hash = cp.hash.clone();

            if let (Some(iterations), Some(input_hex), Some(output_hex)) = (
                cp.vdf_iterations,
                cp.vdf_input.as_ref(),
                cp.vdf_output.as_ref(),
            ) {
                let input = hex::decode(input_hex).map_err(|e| e.to_string())?;
                let output = hex::decode(output_hex).map_err(|e| e.to_string())?;
                if input.len() != 32 || output.len() != 32 {
                    return Err(format!("checkpoint {i}: VDF input/output size mismatch"));
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
                    return Err(format!("checkpoint {i}: VDF verification failed"));
                }
            }
        }

        if let Some(decl) = &self.declaration {
            if !decl.verify() {
                return Err("declaration signature invalid".to_string());
            }
        }

        if let Some(hardware) = &self.hardware {
            if let Err(err) = tpm::verify_binding_chain(&hardware.bindings, &[]) {
                return Err(format!("hardware attestation invalid: {:?}", err));
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
                return Err(format!("key hierarchy verification failed: {err}"));
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
                    .map_err(|e| format!("key hierarchy verification failed: {e}"))?;
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

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec_pretty(self).map_err(|e| e.to_string())
    }

    pub fn decode(data: &[u8]) -> Result<Packet, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }

    pub fn hash(&self) -> [u8; 32] {
        let data = self.encode().unwrap_or_default();
        Sha256::digest(data).into()
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
        assert!(err.contains("declaration is required"));

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
        assert!(err.contains("chain hash mismatch"));
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
        assert!(err.contains("document final hash mismatch"));
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
        assert!(err.contains("document final size mismatch"));
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
        assert!(err.contains("broken chain link"));
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
        assert!(err.contains("declaration signature invalid"));
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
        assert!(err.contains("non-zero previous hash"));
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
}
