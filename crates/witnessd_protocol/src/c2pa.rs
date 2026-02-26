// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::rfc::EvidencePacket;
use serde::{Serialize, Deserialize};

/// C2PA-compliant assertion structure for Proof-of-Process (PoP).
#[derive(Debug, Serialize, Deserialize)]
pub struct PoPAssertion {
    /// C2PA label for this assertion.
    pub label: String,
    /// The PoP protocol version.
    pub version: u32,
    /// Unique identifier for the PoP evidence packet.
    pub evidence_id: String,
    /// Cryptographic digest of the original PoP evidence.
    pub evidence_hash: String,
    /// Mapping of jitter-based entropy seals to content checkpoints.
    pub jitter_seals: Vec<JitterSeal>,
}

/// A cryptographic seal derived from physical jitter entropy.
#[derive(Debug, Serialize, Deserialize)]
pub struct JitterSeal {
    pub sequence: u64,
    pub timestamp: u64,
    pub seal_hash: String,
}

impl PoPAssertion {
    /// Maps an EvidencePacket to a C2PA PoPAssertion.
    pub fn from_evidence(packet: &EvidencePacket, original_bytes: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(original_bytes);
        
        let jitter_seals = packet.checkpoints.iter().map(|cp| {
            JitterSeal {
                sequence: cp.sequence,
                timestamp: cp.timestamp,
                seal_hash: hex::encode(&cp.checkpoint_hash.digest),
            }
        }).collect();

        Self {
            label: "org.pop.evidence".to_string(),
            version: packet.version,
            evidence_id: hex::encode(&packet.packet_id),
            evidence_hash: hex::encode(hash),
            jitter_seals,
        }
    }

    /// Converts the assertion to JSON for C2PA metadata embedding.
    #[cfg(feature = "serde_json")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
