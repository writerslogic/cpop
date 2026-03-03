// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::rfc::EvidencePacket;
use serde::{Deserialize, Serialize};

/// C2PA-compliant assertion for Proof-of-Process evidence.
#[derive(Debug, Serialize, Deserialize)]
pub struct PoPAssertion {
    pub label: String,
    pub version: u32,
    pub evidence_id: String,
    /// Cryptographic digest of the original evidence (not the evidence itself).
    pub evidence_hash: String,
    pub jitter_seals: Vec<JitterSeal>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JitterSeal {
    pub sequence: u64,
    pub timestamp: u64,
    pub seal_hash: String,
}

impl PoPAssertion {
    pub fn from_evidence(packet: &EvidencePacket, original_bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(original_bytes);

        let jitter_seals = packet
            .checkpoints
            .iter()
            .map(|cp| JitterSeal {
                sequence: cp.sequence,
                timestamp: cp.timestamp,
                seal_hash: hex::encode(&cp.checkpoint_hash.digest),
            })
            .collect();

        Self {
            label: "org.pop.evidence".to_string(),
            version: packet.version,
            evidence_id: hex::encode(&packet.packet_id),
            evidence_hash: hex::encode(hash),
            jitter_seals,
        }
    }

    #[cfg(feature = "serde_json")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
