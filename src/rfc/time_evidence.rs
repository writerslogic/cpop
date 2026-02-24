//! RFC-compliant time-evidence structure.
//!
//! Implements the time-evidence CDDL structure from draft-condrey-rats-pop-01
//! with tiered binding levels based on anchor diversity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Time binding tier based on anchor diversity.
///
/// CDDL Definition:
/// ```cddl
/// time-binding-tier = &(
///   maximum: 1,       ; 2+ blockchain + 2+ TSA
///   enhanced: 2,      ; 1+ blockchain + 1+ TSA OR Roughtime
///   standard: 3,      ; VDF + single external anchor
///   degraded: 4       ; VDF only
/// )
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
#[derive(Default)]
pub enum TimeBindingTier {
    /// Maximum tier: 2+ blockchain anchors + 2+ TSA responses.
    /// Provides strongest temporal assurance with multiple independent anchors.
    #[serde(rename = "maximum")]
    Maximum = 1,

    /// Enhanced tier: 1+ blockchain + 1+ TSA OR Roughtime samples.
    /// Strong temporal assurance with independent verification.
    #[serde(rename = "enhanced")]
    Enhanced = 2,

    /// Standard tier: VDF + single external anchor.
    /// Reasonable temporal assurance for most use cases.
    #[serde(rename = "standard")]
    Standard = 3,

    /// Degraded tier: VDF proof only, no external anchors.
    /// Basic temporal ordering, but no external verification.
    #[serde(rename = "degraded")]
    #[default]
    Degraded = 4,
}

impl TimeBindingTier {
    /// Returns the tier name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Maximum => "maximum",
            Self::Enhanced => "enhanced",
            Self::Standard => "standard",
            Self::Degraded => "degraded",
        }
    }

    /// Calculate the tier based on available anchors.
    pub fn calculate(
        blockchain_count: usize,
        tsa_count: usize,
        roughtime_count: usize,
        has_vdf: bool,
    ) -> Self {
        if blockchain_count >= 2 && tsa_count >= 2 {
            Self::Maximum
        } else if (blockchain_count >= 1 && tsa_count >= 1) || roughtime_count >= 2 {
            Self::Enhanced
        } else if has_vdf && (blockchain_count >= 1 || tsa_count >= 1 || roughtime_count >= 1) {
            Self::Standard
        } else {
            // Either has_vdf with no anchors, or no VDF at all
            Self::Degraded
        }
    }
}

/// RFC-compliant time-evidence structure.
///
/// CDDL Definition:
/// ```cddl
/// time-evidence = {
///   1: time-binding-tier,       ; Computed tier
///   ? 2: [* tsa-response],      ; RFC 3161 timestamps
///   ? 3: [* blockchain-anchor], ; Blockchain anchors
///   ? 4: [* roughtime-sample],  ; Roughtime samples
///   5: vdf-proof,               ; VDF proof (always present)
///   6: uint                     ; Evidence timestamp (Unix epoch ms)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeEvidence {
    /// Computed time binding tier (key 1).
    #[serde(rename = "1")]
    pub tier: TimeBindingTier,

    /// RFC 3161 timestamp authority responses (key 2).
    #[serde(rename = "2", skip_serializing_if = "Option::is_none")]
    pub tsa_responses: Option<Vec<TsaResponse>>,

    /// Blockchain anchor proofs (key 3).
    #[serde(rename = "3", skip_serializing_if = "Option::is_none")]
    pub blockchain_anchors: Option<Vec<BlockchainAnchor>>,

    /// Roughtime samples for secure timekeeping (key 4).
    #[serde(rename = "4", skip_serializing_if = "Option::is_none")]
    pub roughtime_samples: Option<Vec<RoughtimeSample>>,

    /// VDF proof reference (key 5).
    /// This is a hash reference to the VDF proof in the evidence packet.
    #[serde(rename = "5", with = "hex_bytes")]
    pub vdf_proof_hash: [u8; 32],

    /// Evidence timestamp in Unix epoch milliseconds (key 6).
    #[serde(rename = "6")]
    pub timestamp_ms: u64,
}

/// RFC 3161 Timestamp Authority response.
///
/// CDDL Definition:
/// ```cddl
/// tsa-response = {
///   1: tstr,                    ; TSA URL
///   2: tstr,                    ; TSA name/organization
///   3: bstr,                    ; DER-encoded timestamp token
///   4: uint,                    ; Response timestamp (Unix epoch ms)
///   5: bstr .size 32,           ; Hash that was timestamped
///   6: tstr                     ; Hash algorithm (e.g., "SHA-256")
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsaResponse {
    /// TSA service URL.
    #[serde(rename = "1")]
    pub tsa_url: String,

    /// TSA name or organization.
    #[serde(rename = "2")]
    pub tsa_name: String,

    /// DER-encoded RFC 3161 timestamp token.
    #[serde(rename = "3")]
    pub timestamp_token: Vec<u8>,

    /// Response timestamp in Unix epoch milliseconds.
    #[serde(rename = "4")]
    pub timestamp_ms: u64,

    /// Hash that was timestamped.
    #[serde(rename = "5", with = "hex_bytes")]
    pub timestamped_hash: [u8; 32],

    /// Hash algorithm used (e.g., "SHA-256").
    #[serde(rename = "6")]
    pub hash_algorithm: String,
}

/// Blockchain anchor proof.
///
/// CDDL Definition:
/// ```cddl
/// blockchain-anchor = {
///   1: tstr,                    ; Chain identifier (e.g., "bitcoin", "ethereum")
///   2: uint,                    ; Block height
///   3: bstr .size 32,           ; Block hash
///   4: uint,                    ; Block timestamp (Unix epoch sec)
///   ? 5: tstr,                  ; Transaction ID (optional)
///   6: bstr .size 32,           ; Merkle root or anchored hash
///   7: [* bstr .size 32],       ; Merkle proof path
///   8: tstr                     ; Anchor method (e.g., "opentimestamps", "direct")
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainAnchor {
    /// Chain identifier (e.g., "bitcoin", "ethereum", "polygon").
    #[serde(rename = "1")]
    pub chain: String,

    /// Block height at time of anchor.
    #[serde(rename = "2")]
    pub block_height: u64,

    /// Block hash.
    #[serde(rename = "3", with = "hex_bytes")]
    pub block_hash: [u8; 32],

    /// Block timestamp in Unix epoch seconds.
    #[serde(rename = "4")]
    pub block_timestamp: u64,

    /// Transaction ID (optional, for direct anchoring).
    #[serde(rename = "5", skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,

    /// Merkle root or anchored hash.
    #[serde(rename = "6", with = "hex_bytes")]
    pub anchored_hash: [u8; 32],

    /// Merkle proof path from anchored hash to block.
    #[serde(rename = "7")]
    pub merkle_proof: Vec<[u8; 32]>,

    /// Anchor method (e.g., "opentimestamps", "direct", "chainpoint").
    #[serde(rename = "8")]
    pub anchor_method: String,
}

/// Roughtime sample for Byzantine-resistant timekeeping.
///
/// CDDL Definition:
/// ```cddl
/// roughtime-sample = {
///   1: tstr,                    ; Server name/URL
///   2: bstr .size 32,           ; Server public key
///   3: uint,                    ; Midpoint timestamp (Unix epoch microseconds)
///   4: uint,                    ; Radius (uncertainty in microseconds)
///   5: bstr .size 64,           ; Server signature
///   6: bstr .size 32            ; Nonce used in request
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoughtimeSample {
    /// Roughtime server name or URL.
    #[serde(rename = "1")]
    pub server: String,

    /// Server's Ed25519 public key.
    #[serde(rename = "2", with = "hex_bytes")]
    pub public_key: [u8; 32],

    /// Midpoint timestamp in Unix epoch microseconds.
    #[serde(rename = "3")]
    pub midpoint_us: u64,

    /// Uncertainty radius in microseconds.
    #[serde(rename = "4")]
    pub radius_us: u32,

    /// Server's Ed25519 signature over the response.
    #[serde(rename = "5", with = "hex_bytes_64")]
    pub signature: [u8; 64],

    /// Nonce used in the request.
    #[serde(rename = "6", with = "hex_bytes")]
    pub nonce: [u8; 32],
}

impl TimeEvidence {
    /// Create a new TimeEvidence with only VDF proof (degraded tier).
    pub fn new_degraded(vdf_proof_hash: [u8; 32]) -> Self {
        Self {
            tier: TimeBindingTier::Degraded,
            tsa_responses: None,
            blockchain_anchors: None,
            roughtime_samples: None,
            vdf_proof_hash,
            timestamp_ms: Utc::now().timestamp_millis() as u64,
        }
    }

    /// Create TimeEvidence from components and auto-calculate tier.
    pub fn from_components(
        vdf_proof_hash: [u8; 32],
        tsa_responses: Vec<TsaResponse>,
        blockchain_anchors: Vec<BlockchainAnchor>,
        roughtime_samples: Vec<RoughtimeSample>,
    ) -> Self {
        let tier = TimeBindingTier::calculate(
            blockchain_anchors.len(),
            tsa_responses.len(),
            roughtime_samples.len(),
            true, // VDF always present
        );

        Self {
            tier,
            tsa_responses: if tsa_responses.is_empty() {
                None
            } else {
                Some(tsa_responses)
            },
            blockchain_anchors: if blockchain_anchors.is_empty() {
                None
            } else {
                Some(blockchain_anchors)
            },
            roughtime_samples: if roughtime_samples.is_empty() {
                None
            } else {
                Some(roughtime_samples)
            },
            vdf_proof_hash,
            timestamp_ms: Utc::now().timestamp_millis() as u64,
        }
    }

    /// Add a TSA response and recalculate tier.
    pub fn add_tsa_response(&mut self, response: TsaResponse) {
        if self.tsa_responses.is_none() {
            self.tsa_responses = Some(Vec::new());
        }
        self.tsa_responses.as_mut().unwrap().push(response);
        self.recalculate_tier();
    }

    /// Add a blockchain anchor and recalculate tier.
    pub fn add_blockchain_anchor(&mut self, anchor: BlockchainAnchor) {
        if self.blockchain_anchors.is_none() {
            self.blockchain_anchors = Some(Vec::new());
        }
        self.blockchain_anchors.as_mut().unwrap().push(anchor);
        self.recalculate_tier();
    }

    /// Add a Roughtime sample and recalculate tier.
    pub fn add_roughtime_sample(&mut self, sample: RoughtimeSample) {
        if self.roughtime_samples.is_none() {
            self.roughtime_samples = Some(Vec::new());
        }
        self.roughtime_samples.as_mut().unwrap().push(sample);
        self.recalculate_tier();
    }

    /// Recalculate the tier based on current anchors.
    pub fn recalculate_tier(&mut self) {
        self.tier = TimeBindingTier::calculate(
            self.blockchain_anchors.as_ref().map_or(0, |v| v.len()),
            self.tsa_responses.as_ref().map_or(0, |v| v.len()),
            self.roughtime_samples.as_ref().map_or(0, |v| v.len()),
            true,
        );
    }

    /// Get the earliest timestamp from all anchors.
    pub fn earliest_anchor_time(&self) -> Option<DateTime<Utc>> {
        let mut earliest: Option<u64> = None;

        if let Some(tsa) = &self.tsa_responses {
            for r in tsa {
                earliest = Some(earliest.map_or(r.timestamp_ms, |e| e.min(r.timestamp_ms)));
            }
        }

        if let Some(bc) = &self.blockchain_anchors {
            for a in bc {
                let ms = a.block_timestamp * 1000;
                earliest = Some(earliest.map_or(ms, |e| e.min(ms)));
            }
        }

        if let Some(rt) = &self.roughtime_samples {
            for s in rt {
                let ms = s.midpoint_us / 1000;
                earliest = Some(earliest.map_or(ms, |e| e.min(ms)));
            }
        }

        earliest.and_then(|ms| DateTime::from_timestamp_millis(ms as i64))
    }

    /// Get the latest timestamp from all anchors.
    pub fn latest_anchor_time(&self) -> Option<DateTime<Utc>> {
        let mut latest: Option<u64> = None;

        if let Some(tsa) = &self.tsa_responses {
            for r in tsa {
                latest = Some(latest.map_or(r.timestamp_ms, |l| l.max(r.timestamp_ms)));
            }
        }

        if let Some(bc) = &self.blockchain_anchors {
            for a in bc {
                let ms = a.block_timestamp * 1000;
                latest = Some(latest.map_or(ms, |l| l.max(ms)));
            }
        }

        if let Some(rt) = &self.roughtime_samples {
            for s in rt {
                let ms = s.midpoint_us / 1000;
                latest = Some(latest.map_or(ms, |l| l.max(ms)));
            }
        }

        latest.and_then(|ms| DateTime::from_timestamp_millis(ms as i64))
    }

    /// Count total number of independent anchors.
    pub fn anchor_count(&self) -> usize {
        self.tsa_responses.as_ref().map_or(0, |v| v.len())
            + self.blockchain_anchors.as_ref().map_or(0, |v| v.len())
            + self.roughtime_samples.as_ref().map_or(0, |v| v.len())
    }

    /// Validate the TimeEvidence structure and return a list of validation errors.
    ///
    /// Checks:
    /// - Tier is consistent with anchor counts
    /// - TSA responses have valid signatures (non-empty timestamp_token)
    /// - Blockchain anchors have valid tx_hash when present (non-empty)
    /// - Roughtime samples have valid server names (non-empty)
    /// - VDF proof hash is non-zero
    /// - Evidence timestamp_ms is non-zero
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Validate timestamp_ms is non-zero
        if self.timestamp_ms == 0 {
            errors.push("evidence_timestamp_ms must be non-zero".to_string());
        }

        // Validate VDF proof hash is non-zero
        if self.vdf_proof_hash == [0u8; 32] {
            errors.push("vdf_proof_hash must be non-zero".to_string());
        }

        // Calculate expected tier from anchor counts
        let blockchain_count = self.blockchain_anchors.as_ref().map_or(0, |v| v.len());
        let tsa_count = self.tsa_responses.as_ref().map_or(0, |v| v.len());
        let roughtime_count = self.roughtime_samples.as_ref().map_or(0, |v| v.len());
        let expected_tier =
            TimeBindingTier::calculate(blockchain_count, tsa_count, roughtime_count, true);

        if self.tier != expected_tier {
            errors.push(format!(
                "tier mismatch: declared {:?} but expected {:?} based on anchor counts \
                (blockchain={}, tsa={}, roughtime={})",
                self.tier, expected_tier, blockchain_count, tsa_count, roughtime_count
            ));
        }

        // Validate TSA responses
        if let Some(tsa_responses) = &self.tsa_responses {
            for (i, tsa) in tsa_responses.iter().enumerate() {
                if tsa.timestamp_token.is_empty() {
                    errors.push(format!(
                        "tsa_response[{}]: timestamp_token must be non-empty",
                        i
                    ));
                }
                if tsa.tsa_url.is_empty() {
                    errors.push(format!("tsa_response[{}]: tsa_url must be non-empty", i));
                }
                if tsa.tsa_name.is_empty() {
                    errors.push(format!("tsa_response[{}]: tsa_name must be non-empty", i));
                }
            }
        }

        // Validate blockchain anchors
        if let Some(blockchain_anchors) = &self.blockchain_anchors {
            for (i, anchor) in blockchain_anchors.iter().enumerate() {
                if let Some(tx_id) = &anchor.tx_id {
                    if tx_id.is_empty() {
                        errors.push(format!(
                            "blockchain_anchor[{}]: tx_id when present must be non-empty",
                            i
                        ));
                    }
                }
                if anchor.chain.is_empty() {
                    errors.push(format!("blockchain_anchor[{}]: chain must be non-empty", i));
                }
                if anchor.anchor_method.is_empty() {
                    errors.push(format!(
                        "blockchain_anchor[{}]: anchor_method must be non-empty",
                        i
                    ));
                }
            }
        }

        // Validate Roughtime samples
        if let Some(roughtime_samples) = &self.roughtime_samples {
            for (i, sample) in roughtime_samples.iter().enumerate() {
                if sample.server.is_empty() {
                    errors.push(format!(
                        "roughtime_sample[{}]: server name must be non-empty",
                        i
                    ));
                }
            }
        }

        errors
    }

    /// Returns true if the TimeEvidence is valid (no validation errors).
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

/// Serde helper for hex-encoded 32-byte arrays.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Serde helper for hex-encoded 64-byte arrays.
mod hex_bytes_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_calculation() {
        // Maximum: 2+ blockchain + 2+ TSA
        assert_eq!(
            TimeBindingTier::calculate(2, 2, 0, true),
            TimeBindingTier::Maximum
        );
        assert_eq!(
            TimeBindingTier::calculate(3, 2, 0, true),
            TimeBindingTier::Maximum
        );

        // Enhanced: 1+ blockchain + 1+ TSA OR 2+ Roughtime
        assert_eq!(
            TimeBindingTier::calculate(1, 1, 0, true),
            TimeBindingTier::Enhanced
        );
        assert_eq!(
            TimeBindingTier::calculate(0, 0, 2, true),
            TimeBindingTier::Enhanced
        );

        // Standard: VDF + single anchor
        assert_eq!(
            TimeBindingTier::calculate(1, 0, 0, true),
            TimeBindingTier::Standard
        );
        assert_eq!(
            TimeBindingTier::calculate(0, 1, 0, true),
            TimeBindingTier::Standard
        );
        assert_eq!(
            TimeBindingTier::calculate(0, 0, 1, true),
            TimeBindingTier::Standard
        );

        // Degraded: VDF only
        assert_eq!(
            TimeBindingTier::calculate(0, 0, 0, true),
            TimeBindingTier::Degraded
        );
    }

    #[test]
    fn test_time_evidence_serialization() {
        let evidence = TimeEvidence::new_degraded([1u8; 32]);

        let json = serde_json::to_string_pretty(&evidence).unwrap();
        let decoded: TimeEvidence = serde_json::from_str(&json).unwrap();

        assert_eq!(evidence.tier, decoded.tier);
        assert_eq!(evidence.vdf_proof_hash, decoded.vdf_proof_hash);
    }

    #[test]
    fn test_add_anchors_updates_tier() {
        let mut evidence = TimeEvidence::new_degraded([0u8; 32]);
        assert_eq!(evidence.tier, TimeBindingTier::Degraded);

        // Add TSA response
        evidence.add_tsa_response(TsaResponse {
            tsa_url: "https://tsa.example.com".to_string(),
            tsa_name: "Example TSA".to_string(),
            timestamp_token: vec![1, 2, 3],
            timestamp_ms: 1700000000000,
            timestamped_hash: [1u8; 32],
            hash_algorithm: "SHA-256".to_string(),
        });
        assert_eq!(evidence.tier, TimeBindingTier::Standard);

        // Add blockchain anchor
        evidence.add_blockchain_anchor(BlockchainAnchor {
            chain: "bitcoin".to_string(),
            block_height: 800000,
            block_hash: [2u8; 32],
            block_timestamp: 1700000000,
            tx_id: Some("abc123".to_string()),
            anchored_hash: [3u8; 32],
            merkle_proof: vec![],
            anchor_method: "opentimestamps".to_string(),
        });
        assert_eq!(evidence.tier, TimeBindingTier::Enhanced);

        // Add more anchors to reach Maximum
        evidence.add_tsa_response(TsaResponse {
            tsa_url: "https://tsa2.example.com".to_string(),
            tsa_name: "Example TSA 2".to_string(),
            timestamp_token: vec![4, 5, 6],
            timestamp_ms: 1700000001000,
            timestamped_hash: [4u8; 32],
            hash_algorithm: "SHA-256".to_string(),
        });
        evidence.add_blockchain_anchor(BlockchainAnchor {
            chain: "ethereum".to_string(),
            block_height: 18000000,
            block_hash: [5u8; 32],
            block_timestamp: 1700000012,
            tx_id: None,
            anchored_hash: [6u8; 32],
            merkle_proof: vec![],
            anchor_method: "direct".to_string(),
        });
        assert_eq!(evidence.tier, TimeBindingTier::Maximum);
    }

    #[test]
    fn test_validate_valid_evidence() {
        let mut evidence = TimeEvidence::new_degraded([1u8; 32]);
        // new_degraded sets a valid timestamp, but vdf_proof_hash is non-zero
        assert!(evidence.is_valid());

        // Add valid TSA response
        evidence.add_tsa_response(TsaResponse {
            tsa_url: "https://tsa.example.com".to_string(),
            tsa_name: "Example TSA".to_string(),
            timestamp_token: vec![1, 2, 3],
            timestamp_ms: 1700000000000,
            timestamped_hash: [1u8; 32],
            hash_algorithm: "SHA-256".to_string(),
        });
        assert!(evidence.is_valid());
    }

    #[test]
    fn test_validate_zero_vdf_hash() {
        let evidence = TimeEvidence::new_degraded([0u8; 32]);
        let errors = evidence.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("vdf_proof_hash must be non-zero")));
        assert!(!evidence.is_valid());
    }

    #[test]
    fn test_validate_zero_timestamp() {
        let mut evidence = TimeEvidence::new_degraded([1u8; 32]);
        evidence.timestamp_ms = 0;
        let errors = evidence.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("evidence_timestamp_ms must be non-zero")));
        assert!(!evidence.is_valid());
    }

    #[test]
    fn test_validate_tier_mismatch() {
        let mut evidence = TimeEvidence::new_degraded([1u8; 32]);
        // Force an incorrect tier without adding anchors
        evidence.tier = TimeBindingTier::Maximum;
        let errors = evidence.validate();
        assert!(errors.iter().any(|e| e.contains("tier mismatch")));
        assert!(!evidence.is_valid());
    }

    #[test]
    fn test_validate_empty_tsa_token() {
        let mut evidence = TimeEvidence::new_degraded([1u8; 32]);
        evidence.tsa_responses = Some(vec![TsaResponse {
            tsa_url: "https://tsa.example.com".to_string(),
            tsa_name: "Example TSA".to_string(),
            timestamp_token: vec![], // Empty - invalid
            timestamp_ms: 1700000000000,
            timestamped_hash: [1u8; 32],
            hash_algorithm: "SHA-256".to_string(),
        }]);
        evidence.recalculate_tier();
        let errors = evidence.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("timestamp_token must be non-empty")));
        assert!(!evidence.is_valid());
    }

    #[test]
    fn test_validate_empty_blockchain_tx_id() {
        let mut evidence = TimeEvidence::new_degraded([1u8; 32]);
        evidence.blockchain_anchors = Some(vec![BlockchainAnchor {
            chain: "bitcoin".to_string(),
            block_height: 800000,
            block_hash: [2u8; 32],
            block_timestamp: 1700000000,
            tx_id: Some("".to_string()), // Empty when present - invalid
            anchored_hash: [3u8; 32],
            merkle_proof: vec![],
            anchor_method: "opentimestamps".to_string(),
        }]);
        evidence.recalculate_tier();
        let errors = evidence.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("tx_id when present must be non-empty")));
        assert!(!evidence.is_valid());
    }

    #[test]
    fn test_validate_empty_roughtime_server() {
        let mut evidence = TimeEvidence::new_degraded([1u8; 32]);
        evidence.roughtime_samples = Some(vec![RoughtimeSample {
            server: "".to_string(), // Empty - invalid
            public_key: [0u8; 32],
            midpoint_us: 1700000000000000,
            radius_us: 1000,
            signature: [0u8; 64],
            nonce: [0u8; 32],
        }]);
        evidence.recalculate_tier();
        let errors = evidence.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("server name must be non-empty")));
        assert!(!evidence.is_valid());
    }

    #[test]
    fn test_validate_multiple_errors() {
        let evidence = TimeEvidence {
            tier: TimeBindingTier::Maximum, // Incorrect tier
            tsa_responses: Some(vec![TsaResponse {
                tsa_url: "".to_string(),  // Empty
                tsa_name: "".to_string(), // Empty
                timestamp_token: vec![],  // Empty
                timestamp_ms: 1700000000000,
                timestamped_hash: [1u8; 32],
                hash_algorithm: "SHA-256".to_string(),
            }]),
            blockchain_anchors: None,
            roughtime_samples: None,
            vdf_proof_hash: [0u8; 32], // Zero
            timestamp_ms: 0,           // Zero
        };
        let errors = evidence.validate();
        // Should have multiple errors
        assert!(errors.len() >= 4);
        assert!(!evidence.is_valid());
    }
}
