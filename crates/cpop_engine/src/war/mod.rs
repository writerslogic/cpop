// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! WAR (Written Authorship Report) block encoding and verification.
//!
//! PGP-style ASCII-armored evidence format -- human-readable and
//! independently verifiable.

pub mod appraisal;
pub mod common;
pub mod compat;
pub mod ear;
pub mod encoding;
pub mod profiles;
pub mod types;
pub mod verification;

#[cfg(test)]
mod tests;

pub use appraisal::appraise;
pub use ear::{Ar4siStatus, EarAppraisal, EarToken, SealClaims, TrustworthinessVector, VerifierId};
pub use encoding::word_wrap;
pub use types::{Block, CheckResult, ForensicDetails, Seal, VerificationReport, Version};
pub use verification::compute_seal;

use crate::evidence::Packet;
use crate::trust_policy::AppraisalPolicy;
use cpop_protocol::crypto::EvidenceSigner;

impl Block {
    /// Create from an evidence packet.
    pub fn from_packet(packet: &Packet) -> Result<Self, String> {
        let declaration = packet
            .declaration
            .as_ref()
            .ok_or("evidence packet missing declaration")?;

        let version = if declaration.has_jitter_seal() {
            Version::V1_1
        } else {
            Version::V1_0
        };

        let document_id = hex::decode(&packet.document.final_hash)
            .map_err(|e| format!("invalid document hash: {e}"))?;
        if document_id.len() != 32 {
            return Err("document hash must be 32 bytes".to_string());
        }
        let mut doc_id = [0u8; 32];
        doc_id.copy_from_slice(&document_id);

        let author = if declaration.author_public_key.len() == 32 {
            let fingerprint = &hex::encode(&declaration.author_public_key)[..16];
            format!("key:{}", fingerprint)
        } else {
            "unknown".to_string()
        };

        let seal = compute_seal(packet, declaration)?;

        // Tool declaration: structured from declaration.ai_tools
        let tool = if declaration.ai_tools.is_empty() {
            Some("none".to_string())
        } else {
            let t = &declaration.ai_tools[0];
            let extent = match t.extent {
                crate::declaration::AiExtent::None => "none",
                crate::declaration::AiExtent::Minimal => "minor",
                crate::declaration::AiExtent::Moderate => "moderate",
                crate::declaration::AiExtent::Substantial => "substantial",
            };
            Some(format!("ai:{}:{}", t.tool, extent))
        };

        // Evidence strength tier
        let tier = Some(
            match packet.strength {
                crate::evidence::Strength::Basic => "T1",
                crate::evidence::Strength::Standard => "T2",
                crate::evidence::Strength::Enhanced => "T3",
                crate::evidence::Strength::Maximum => "T4",
            }
            .to_string(),
        );

        let checkpoints = Some(packet.checkpoints.len() as u64);

        // Duration from first to last checkpoint
        let duration_secs = if packet.checkpoints.len() >= 2 {
            let first = packet.checkpoints.first().unwrap().timestamp;
            let last = packet.checkpoints.last().unwrap().timestamp;
            let delta = (last - first).num_seconds().max(0) as u64;
            Some(delta)
        } else {
            None
        };

        Ok(Self {
            version,
            author,
            document_id: doc_id,
            timestamp: packet.exported_at,
            statement: declaration.statement.clone(),
            seal,
            tool,
            tier,
            score: None, // Set during forensic analysis or export
            checkpoints,
            duration_secs,
            evidence: Some(Box::new(packet.clone())),
            signed: false,
            verifier_nonce: packet.verifier_nonce,
            ear: None,
        })
    }

    /// Create a signed WAR block from an evidence packet.
    pub fn from_packet_signed(
        packet: &Packet,
        signer: &dyn EvidenceSigner,
    ) -> Result<Self, String> {
        let mut block = Self::from_packet(packet)?;
        block.sign(signer)?;
        Ok(block)
    }

    /// Create a V2.0 WAR block from an evidence packet with EAR appraisal.
    pub fn from_packet_appraised(
        packet: &Packet,
        signer: &dyn EvidenceSigner,
        policy: &AppraisalPolicy,
    ) -> crate::error::Result<Self> {
        let mut block = Self::from_packet(packet)
            .map_err(|e| crate::error::Error::evidence(format!("block creation failed: {e}")))?;
        block
            .sign(signer)
            .map_err(|e| crate::error::Error::evidence(format!("signing failed: {e}")))?;

        let mut ear = appraisal::appraise(packet, policy)?;

        if let Some(appr) = ear.submods.get_mut("pop") {
            appr.pop_seal = Some(SealClaims {
                h1: block.seal.h1,
                h2: block.seal.h2,
                h3: block.seal.h3,
                signature: block.seal.signature,
                public_key: block.seal.public_key,
            });
        }

        block.version = Version::V2_0;
        block.ear = Some(ear);
        Ok(block)
    }

    /// Sign the WAR block's seal with the given signer (software or hardware).
    pub fn sign(&mut self, signer: &dyn EvidenceSigner) -> Result<(), String> {
        let signature_bytes = signer
            .sign(&self.seal.h3)
            .map_err(|e| format!("signing failed: {}", e))?;

        if signature_bytes.len() != 64 {
            return Err(format!(
                "invalid signature length: expected 64, got {}",
                signature_bytes.len()
            ));
        }

        self.seal.signature.copy_from_slice(&signature_bytes);
        self.signed = true;

        Ok(())
    }
}
