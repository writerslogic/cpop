// SPDX-License-Identifier: Apache-2.0

//! RFC-compliant evidence packet structure for CBOR encoding.
//!
//! Implements the evidence-packet CDDL structure from draft-condrey-rats-pop-schema-01:
//!
//! ```cddl
//! tagged-evidence-packet = #6.1129336645(evidence-packet)
//!
//! evidence-packet = {
//!     1 => uint,                      ; version (1)
//!     2 => vdf-structure,             ; VDF
//!     3 => jitter-seal-structure,     ; Jitter Seal
//!     4 => content-hash-tree,         ; Merkle for segments
//!     5 => correlation-proof,         ; Spearman Correlation
//!     ? 6 => error-topology,          ; Fractal Error Pattern
//!     ? 7 => enclave-vise,            ; Hardware Observation Post
//!     ? 8 => zk-process-verdict,      ; Process Consistency Verdict
//!     ? 9 => profile-declaration,     ; Profile tier and features
//!     ? 18 => privacy-budget-certificate,
//!     ? 19 => key-rotation-metadata,
//!     * tstr => any,                  ; extensions
//! }
//! ```
//!
//! CBOR Semantic Tag: 1129336645 (0x43504F45, "CPoE" per IANA)

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::fixed_point::{Centibits, Decibits, Millibits, RhoMillibits, SlopeDecibits};
use super::serde_helpers::{hex_bytes_vec, hex_bytes_vec_opt};

const MAX_EXTENSION_JSON_DEPTH: usize = 8;

/// RFC-compliant evidence packet structure.
///
/// Uses integer keys (1-19) for compact CBOR encoding per the CDDL schema.
/// The structure is designed for RATS (Remote ATtestation procedureS)
/// compatibility while maintaining privacy-by-construction principles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketRfc {
    /// Schema version (always 1 for this version).
    /// Key 1 in CDDL.
    #[serde(rename = "1")]
    pub version: u32,

    /// VDF structure proving minimum elapsed time.
    /// Key 2 in CDDL.
    #[serde(rename = "2")]
    pub vdf: VdfStructure,

    /// Jitter seal structure for behavioral entropy.
    /// Key 3 in CDDL.
    #[serde(rename = "3")]
    pub jitter_seal: JitterSealStructure,

    /// Content hash tree (Merkle structure).
    /// Key 4 in CDDL.
    #[serde(rename = "4")]
    pub content_hash_tree: ContentHashTree,

    /// Spearman correlation proof.
    /// Key 5 in CDDL.
    #[serde(rename = "5")]
    pub correlation_proof: CorrelationProof,

    /// Error topology analysis (fractal patterns).
    /// Key 6 in CDDL.
    #[serde(rename = "6", default, skip_serializing_if = "Option::is_none")]
    pub error_topology: Option<ErrorTopology>,

    /// Hardware observation post (enclave binding).
    /// Key 7 in CDDL.
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub enclave_vise: Option<EnclaveVise>,

    /// ZK process verdict for consistency.
    /// Key 8 in CDDL.
    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub zk_verdict: Option<ZkProcessVerdict>,

    /// Profile declaration (tier and features).
    /// Key 9 in CDDL.
    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileDeclaration>,

    /// Privacy budget certificate.
    /// Key 18 in CDDL.
    #[serde(rename = "18", default, skip_serializing_if = "Option::is_none")]
    pub privacy_budget: Option<PrivacyBudgetCertificate>,

    /// Key rotation metadata.
    /// Key 19 in CDDL.
    #[serde(rename = "19", default, skip_serializing_if = "Option::is_none")]
    pub key_rotation: Option<KeyRotationMetadata>,

    /// Vendor extensions (string keys).
    /// Uses `serde_json::Value` because this internal type is only serialized
    /// to JSON; CBOR wire encoding uses the separate `EvidencePacket` type.
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

/// VDF structure from CDDL.
///
/// ```cddl
/// vdf-structure = {
///     1 => bstr,           ; input: H(DST_CHAIN || content || jitter_seal)
///     2 => bstr,           ; output
///     3 => uint64,         ; iterations
///     4 => [* uint64],     ; rdtsc_checkpoints (Continuous)
///     5 => bstr,           ; entropic_pulse: HMAC(DST_CLOCK || SK, T ^ E)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdfStructure {
    /// Input: H(DST_CHAIN || content || jitter_seal).
    #[serde(rename = "1", with = "hex_bytes_vec")]
    pub input: Vec<u8>,

    /// VDF output.
    #[serde(rename = "2", with = "hex_bytes_vec")]
    pub output: Vec<u8>,

    /// Number of iterations.
    #[serde(rename = "3")]
    pub iterations: u64,

    /// RDTSC checkpoints for continuous verification.
    #[serde(rename = "4")]
    pub rdtsc_checkpoints: Vec<u64>,

    /// Entropic pulse: HMAC(DST_CLOCK || SK, T ^ E).
    #[serde(rename = "5", with = "hex_bytes_vec")]
    pub entropic_pulse: Vec<u8>,
}

/// Jitter seal structure from CDDL.
///
/// ```cddl
/// jitter-seal-structure = {
///     1 => tstr,                      ; lang (e.g., "en-US")
///     2 => bstr,                      ; bucket_commitment (ZK-Private)
///     3 => uint,                      ; entropy_millibits
///     4 => epsilon-centibits,         ; dp_epsilon_centibits
///     5 => slope-decibits,            ; pink_noise_slope_decibits
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterSealStructure {
    /// Language/locale identifier.
    #[serde(rename = "1")]
    pub lang: String,

    /// Bucket commitment (ZK-Private).
    #[serde(rename = "2", with = "hex_bytes_vec")]
    pub bucket_commitment: Vec<u8>,

    /// Entropy in millibits (CDDL: uint).
    #[serde(rename = "3")]
    pub entropy_millibits: u64,

    /// Differential privacy epsilon (scaled x10000).
    #[serde(rename = "4")]
    pub dp_epsilon_centibits: Centibits,

    /// Pink noise slope (scaled x10).
    #[serde(rename = "5")]
    pub pink_noise_slope_decibits: SlopeDecibits,
}

/// Content hash tree (Merkle structure).
///
/// ```cddl
/// content-hash-tree = {
///     1 => bstr,           ; root
///     2 => uint16 .ge 20,  ; segment_count
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentHashTree {
    /// Merkle root hash.
    #[serde(rename = "1", with = "hex_bytes_vec")]
    pub root: Vec<u8>,

    /// Number of segments.
    #[serde(rename = "2")]
    pub segment_count: u16,
}

impl ContentHashTree {
    /// Validate CDDL constraint: segment_count >= 20.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.root.is_empty() {
            errors.push("content hash tree root is empty".into());
        }
        if self.segment_count < 20 {
            errors.push(format!(
                "segment_count {} is below CDDL minimum 20",
                self.segment_count
            ));
        }
        errors
    }
}

/// Correlation proof from CDDL.
///
/// ```cddl
/// correlation-proof = {
///     1 => int16 .within -1000..1000, ; rho (Scaled: -1000..1000)
///     2 => 700,                        ; threshold (0.7 * 1000)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationProof {
    /// Spearman rho correlation coefficient (scaled x1000).
    #[serde(rename = "1")]
    pub rho: RhoMillibits,

    /// Threshold for acceptance (default 700 = 0.7).
    #[serde(rename = "2")]
    pub threshold: i16,
}

impl Default for CorrelationProof {
    fn default() -> Self {
        Self {
            rho: RhoMillibits::new(0),
            threshold: 700,
        }
    }
}

/// Error topology structure.
///
/// Captures fractal error patterns for behavioral analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorTopology {
    /// Fractal dimension of error patterns.
    #[serde(rename = "1")]
    pub fractal_dimension_decibits: Decibits,

    /// Error clustering coefficient.
    #[serde(rename = "2")]
    pub clustering_millibits: Millibits,

    /// Temporal distribution signature.
    #[serde(rename = "3", with = "hex_bytes_vec")]
    pub temporal_signature: Vec<u8>,
}

/// Hardware enclave binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveVise {
    /// Enclave type (1=Secure Enclave, 16=TPM 2.0, 17=SGX).
    #[serde(rename = "1")]
    pub enclave_type: u8,

    /// Attestation data from hardware.
    #[serde(rename = "2", with = "hex_bytes_vec")]
    pub attestation: Vec<u8>,

    /// Timestamp of attestation.
    #[serde(rename = "3")]
    pub timestamp: u64,
}

/// ZK process verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProcessVerdict {
    /// Verdict: 1=authentic, 2=suspicious, 3=inconclusive, 4=insufficient.
    #[serde(rename = "1")]
    pub verdict: u8,

    /// Confidence in millibits.
    #[serde(rename = "2")]
    pub confidence_millibits: Millibits,

    /// Proof data (optional, for STARK/SNARK).
    #[serde(
        rename = "3",
        default,
        skip_serializing_if = "Option::is_none",
        with = "hex_bytes_vec_opt"
    )]
    pub proof: Option<Vec<u8>>,
}

/// Profile declaration from CDDL.
///
/// ```cddl
/// profile-declaration = {
///     1 => profile-tier,              ; tier
///     2 => profile-uri,               ; uri
///     ? 3 => [+ feature-id],          ; enabled-features
///     ? 4 => tstr,                    ; implementation-id
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDeclaration {
    /// Profile tier: 1=core, 2=enhanced, 3=maximum.
    #[serde(rename = "1")]
    pub tier: u8,

    /// Profile URN.
    #[serde(rename = "2")]
    pub uri: String,

    /// Enabled features beyond MTI.
    #[serde(rename = "3", default, skip_serializing_if = "Option::is_none")]
    pub enabled_features: Option<Vec<u8>>,

    /// Implementation identifier.
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub implementation_id: Option<String>,
}

impl ProfileDeclaration {
    /// Create a Core tier profile.
    pub fn core() -> Self {
        Self {
            tier: 1,
            uri: "urn:ietf:params:pop:profile:1.0".to_string(),
            enabled_features: None,
            implementation_id: None,
        }
    }

    /// Create an Enhanced tier profile.
    pub fn enhanced() -> Self {
        Self {
            tier: 2,
            uri: "urn:ietf:params:pop:profile:1.0".to_string(),
            enabled_features: None,
            implementation_id: None,
        }
    }

    /// Create a Maximum tier profile.
    pub fn maximum() -> Self {
        Self {
            tier: 3,
            uri: "urn:ietf:params:pop:profile:1.0".to_string(),
            enabled_features: None,
            implementation_id: None,
        }
    }
}

/// Privacy budget certificate from CDDL.
///
/// Tracks differential privacy budget consumption per key period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyBudgetCertificate {
    /// Key generation method ("monthly", "weekly", "yearly").
    #[serde(rename = "1")]
    pub key_generation_method: String,

    /// Key valid from (Unix timestamp).
    #[serde(rename = "2")]
    pub key_valid_from: u64,

    /// Key valid until (Unix timestamp).
    #[serde(rename = "3")]
    pub key_valid_until: u64,

    /// Session epsilon in centibits.
    #[serde(rename = "4")]
    pub session_epsilon_centibits: Centibits,

    /// Cumulative epsilon before (fixed-point, 1e6 scale).
    #[serde(rename = "5")]
    pub cumulative_epsilon_micros_before: u64,

    /// Cumulative epsilon after (fixed-point, 1e6 scale).
    #[serde(rename = "6")]
    pub cumulative_epsilon_micros_after: u64,

    /// Sessions used with this key.
    #[serde(rename = "7")]
    pub sessions_used_this_key: u8,

    /// Maximum sessions recommended.
    #[serde(rename = "8")]
    pub max_sessions_recommended: u8,
}

/// Key rotation metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationMetadata {
    /// Rotation method ("monthly", "weekly", "yearly").
    #[serde(rename = "1")]
    pub rotation_method: String,

    /// Next rotation date (Unix timestamp).
    #[serde(rename = "2")]
    pub next_rotation_date: u64,

    /// Sessions remaining.
    #[serde(rename = "3")]
    pub sessions_remaining: u8,

    /// Cumulative epsilon (fixed-point, 1e6 scale).
    #[serde(rename = "4")]
    pub cumulative_epsilon_micros: u64,
}

impl PacketRfc {
    /// Create a minimal Core-tier packet.
    pub fn new_core(
        vdf: VdfStructure,
        jitter_seal: JitterSealStructure,
        content_hash_tree: ContentHashTree,
        correlation_proof: CorrelationProof,
    ) -> Self {
        Self {
            version: 1,
            vdf,
            jitter_seal,
            content_hash_tree,
            correlation_proof,
            error_topology: None,
            enclave_vise: None,
            zk_verdict: None,
            profile: Some(ProfileDeclaration::core()),
            privacy_budget: None,
            key_rotation: None,
            extensions: BTreeMap::new(),
        }
    }

    /// Validate the packet structure.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.version != 1 {
            errors.push(format!("unsupported version: {}", self.version));
        }

        if self.vdf.input.len() != 32 {
            errors.push(format!(
                "VDF input must be 32 bytes per CDDL, got {}",
                self.vdf.input.len()
            ));
        }

        if self.vdf.output.len() != 32 && self.vdf.output.len() != 64 {
            errors.push(format!(
                "VDF output must be 32 or 64 bytes per CDDL, got {}",
                self.vdf.output.len()
            ));
        }

        if self.vdf.iterations == 0 {
            errors.push("VDF iterations must be non-zero".into());
        }

        if self.content_hash_tree.root.is_empty() {
            errors.push("content hash tree root is empty".into());
        }

        if self.content_hash_tree.segment_count < 20 {
            errors.push(format!(
                "segment_count {} is below minimum 20",
                self.content_hash_tree.segment_count
            ));
        }

        if self.correlation_proof.threshold != 700 {
            errors.push(format!(
                "non-standard correlation threshold: {} (expected 700)",
                self.correlation_proof.threshold
            ));
        }

        const MAX_EXTENSIONS: usize = 32;
        const MAX_EXTENSION_KEY_LEN: usize = 128;
        const MAX_EXTENSION_VALUE_BYTES: usize = 4096;
        if self.extensions.len() > MAX_EXTENSIONS {
            errors.push(format!(
                "extensions count {} exceeds maximum {}",
                self.extensions.len(),
                MAX_EXTENSIONS
            ));
        }
        for (k, v) in &self.extensions {
            if k.is_empty() || k.len() > MAX_EXTENSION_KEY_LEN {
                errors.push(format!("extension key has invalid length {}", k.len()));
            }
            if k.bytes().any(|b| b < 0x20 || b == 0x7F) {
                errors.push(format!("extension key '{}' contains control characters", k));
            }
            let value_bytes = serde_json::to_vec(v).map(|b| b.len()).unwrap_or(usize::MAX);
            if value_bytes > MAX_EXTENSION_VALUE_BYTES {
                errors.push(format!(
                    "extension '{}' value exceeds {} bytes",
                    k, MAX_EXTENSION_VALUE_BYTES
                ));
            }
            if json_depth(v) > MAX_EXTENSION_JSON_DEPTH {
                errors.push(format!(
                    "extension '{}' value nesting exceeds maximum depth {}",
                    k, MAX_EXTENSION_JSON_DEPTH
                ));
            }
        }

        errors
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

fn json_depth(v: &serde_json::Value) -> usize {
    json_depth_bounded(v, 0)
}

fn json_depth_bounded(v: &serde_json::Value, current: usize) -> usize {
    if current > MAX_EXTENSION_JSON_DEPTH {
        return current;
    }
    match v {
        serde_json::Value::Array(arr) => {
            1 + arr
                .iter()
                .map(|item| json_depth_bounded(item, current + 1))
                .max()
                .unwrap_or(0)
        }
        serde_json::Value::Object(map) => {
            1 + map
                .values()
                .map(|item| json_depth_bounded(item, current + 1))
                .max()
                .unwrap_or(0)
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_packet() -> PacketRfc {
        PacketRfc::new_core(
            VdfStructure {
                input: vec![1u8; 32],
                output: vec![2u8; 64],
                iterations: 1_000_000,
                rdtsc_checkpoints: vec![1000, 2000, 3000],
                entropic_pulse: vec![3u8; 32],
            },
            JitterSealStructure {
                lang: "en-US".to_string(),
                bucket_commitment: vec![4u8; 32],
                entropy_millibits: 8500,
                dp_epsilon_centibits: Centibits::from_float(0.5),
                pink_noise_slope_decibits: SlopeDecibits::from_float(-1.0),
            },
            ContentHashTree {
                root: vec![5u8; 32],
                segment_count: 25,
            },
            CorrelationProof {
                rho: RhoMillibits::from_float(0.75),
                threshold: 700,
            },
        )
    }

    #[test]
    fn test_packet_creation() {
        let packet = create_test_packet();
        assert_eq!(packet.version, 1);
        assert!(packet.profile.is_some());
        assert_eq!(packet.profile.as_ref().unwrap().tier, 1);
    }

    #[test]
    fn test_packet_validation() {
        let packet = create_test_packet();
        let errors = packet.validate();
        assert!(errors.is_empty(), "errors: {:?}", errors);
    }

    #[test]
    fn test_packet_validation_empty_vdf() {
        let mut packet = create_test_packet();
        packet.vdf.input = vec![];
        let errors = packet.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("VDF input must be 32 bytes")));
    }

    #[test]
    fn test_packet_serialization() {
        let packet = create_test_packet();
        let json = serde_json::to_string(&packet).unwrap();

        assert!(json.contains("\"1\":1"));
        assert!(json.contains("\"2\":{"));
        assert!(json.contains("\"3\":{"));

        let decoded: PacketRfc = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.version, packet.version);
    }

    #[test]
    fn test_profile_tiers() {
        assert_eq!(ProfileDeclaration::core().tier, 1);
        assert_eq!(ProfileDeclaration::enhanced().tier, 2);
        assert_eq!(ProfileDeclaration::maximum().tier, 3);
    }
}
