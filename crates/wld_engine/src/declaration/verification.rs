// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::Error;

use super::helpers::{
    ai_extent_str, ai_purpose_str, collaborator_role_str, extent_rank, hash_opt_bytes,
    hash_opt_str, hash_str, modality_type_str,
};
use super::types::{AIExtent, Declaration, DeclarationJitter, DeclarationSummary};

impl Declaration {
    pub fn verify(&self) -> bool {
        if self.author_public_key.len() != 32 || self.signature.len() != 64 {
            return false;
        }

        let pubkey_bytes: [u8; 32] = match self.author_public_key.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let sig_bytes: [u8; 64] = match self.signature.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&self.signing_payload(), &signature)
            .is_ok()
    }

    pub fn has_ai_usage(&self) -> bool {
        !self.ai_tools.is_empty()
    }

    pub fn max_ai_extent(&self) -> AIExtent {
        let mut max = AIExtent::None;
        for tool in &self.ai_tools {
            if extent_rank(&tool.extent) > extent_rank(&max) {
                max = tool.extent.clone();
            }
        }
        max
    }

    pub fn encode(&self) -> crate::error::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| Error::validation(format!("encode: {e}")))
    }

    pub fn decode(data: &[u8]) -> crate::error::Result<Declaration> {
        serde_json::from_slice(data).map_err(|e| Error::validation(format!("decode: {e}")))
    }

    pub fn summary(&self) -> DeclarationSummary {
        let tools: Vec<String> = self.ai_tools.iter().map(|t| t.tool.clone()).collect();

        DeclarationSummary {
            title: self.title.clone(),
            ai_usage: self.has_ai_usage(),
            ai_tools: tools,
            max_ai_extent: ai_extent_str(&self.max_ai_extent()).to_string(),
            collaborators: self.collaborators.len(),
            signature_valid: self.verify(),
        }
    }

    pub(crate) fn signing_payload(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        // v3: length-prefixed strings, millis timestamp, f64::to_bits, None/Some discriminants
        hasher.update(b"witnessd-declaration-v3");
        hasher.update(self.document_hash);
        hasher.update(self.chain_hash);
        hash_str(&mut hasher, &self.title);

        hasher.update((self.input_modalities.len() as u64).to_be_bytes());
        for modality in &self.input_modalities {
            hash_str(&mut hasher, modality_type_str(&modality.modality_type));
            hasher.update(modality.percentage.to_bits().to_be_bytes());
            hash_opt_str(&mut hasher, modality.note.as_deref());
        }

        hasher.update((self.ai_tools.len() as u64).to_be_bytes());
        for tool in &self.ai_tools {
            hash_str(&mut hasher, &tool.tool);
            hash_opt_str(&mut hasher, tool.version.as_deref());
            hash_str(&mut hasher, ai_purpose_str(&tool.purpose));
            hash_opt_str(&mut hasher, tool.interaction.as_deref());
            hash_str(&mut hasher, ai_extent_str(&tool.extent));
            hasher.update((tool.sections.len() as u64).to_be_bytes());
            for section in &tool.sections {
                hash_str(&mut hasher, section);
            }
        }

        hasher.update((self.collaborators.len() as u64).to_be_bytes());
        for collaborator in &self.collaborators {
            hash_str(&mut hasher, &collaborator.name);
            hash_str(&mut hasher, collaborator_role_str(&collaborator.role));
            hasher.update((collaborator.sections.len() as u64).to_be_bytes());
            for section in &collaborator.sections {
                hash_str(&mut hasher, section);
            }
            hash_opt_bytes(&mut hasher, collaborator.public_key.as_deref());
        }

        hash_str(&mut hasher, &self.statement);
        // Use timestamp_millis (safe until ~year 292M) instead of nanos (overflows ~2262)
        hasher.update(self.created_at.timestamp_millis().to_be_bytes());
        hasher.update(self.version.to_be_bytes());
        hasher.update((self.author_public_key.len() as u64).to_be_bytes());
        hasher.update(&self.author_public_key);

        // Include jitter seal in signing payload (WAR/1.1)
        if let Some(jitter) = &self.jitter_sealed {
            hasher.update(b"witnessd-jitter-seal-v1");
            hasher.update(jitter.jitter_hash);
            hasher.update(jitter.keystroke_count.to_be_bytes());
            hasher.update(jitter.duration_ms.to_be_bytes());
            hasher.update(jitter.avg_interval_ms.to_bits().to_be_bytes());
            hasher.update(jitter.entropy_bits.to_bits().to_be_bytes());
            hasher.update(if jitter.hardware_sealed {
                &[1u8]
            } else {
                &[0u8]
            });
        }

        hasher.finalize().to_vec()
    }

    pub fn has_jitter_seal(&self) -> bool {
        self.jitter_sealed.is_some()
    }
}

impl DeclarationJitter {
    /// Build from raw jitter timing samples (microseconds).
    pub fn from_samples(jitter_samples: &[u32], duration_ms: u64, hardware_sealed: bool) -> Self {
        let keystroke_count = jitter_samples.len() as u64;

        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-declaration-jitter-v1");
        hasher.update(keystroke_count.to_be_bytes());
        for sample in jitter_samples {
            hasher.update(sample.to_be_bytes());
        }
        let jitter_hash: [u8; 32] = hasher.finalize().into();

        let avg_interval_ms = if keystroke_count > 1 {
            duration_ms as f64 / (keystroke_count - 1) as f64
        } else if keystroke_count == 1 {
            duration_ms as f64
        } else {
            0.0
        };

        let entropy_bits = jitter_samples
            .iter()
            .map(|&j| {
                if j > 0 {
                    (j as f64).log2().clamp(0.5, 8.0)
                } else {
                    0.0
                }
            })
            .sum();

        Self {
            jitter_hash,
            keystroke_count,
            duration_ms,
            avg_interval_ms,
            entropy_bits,
            hardware_sealed,
        }
    }

    pub fn new(
        jitter_hash: [u8; 32],
        keystroke_count: u64,
        duration_ms: u64,
        avg_interval_ms: f64,
        entropy_bits: f64,
        hardware_sealed: bool,
    ) -> Self {
        Self {
            jitter_hash,
            keystroke_count,
            duration_ms,
            avg_interval_ms,
            entropy_bits,
            hardware_sealed,
        }
    }
}
