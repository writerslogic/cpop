// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::rfc::{self, TimeEvidence, VdfProofRfc};
use crate::vdf::{self, Parameters};

use super::types::*;

/// Mix an optional physics seed into a base VDF input.
///
/// When present, hashes the base input together with the physics seed to produce
/// a new VDF input that is bound to both the chain state and the physical context.
fn mix_physics_seed(base_input: [u8; 32], physics_seed: Option<[u8; 32]>) -> [u8; 32] {
    if let Some(seed) = physics_seed {
        let mut hasher = Sha256::new();
        hasher.update(base_input);
        hasher.update(seed);
        hasher.finalize().into()
    } else {
        base_input
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    pub document_id: String,
    pub document_path: String,
    pub created_at: DateTime<Utc>,
    pub checkpoints: Vec<Checkpoint>,
    pub vdf_params: Parameters,
    /// Entanglement mode for this chain (defaults to Legacy for backward compatibility)
    #[serde(default)]
    pub entanglement_mode: EntanglementMode,
    /// Signature policy for checkpoint verification.
    /// Legacy chains deserialize as Optional; new chains default to Required.
    #[serde(default)]
    pub signature_policy: SignaturePolicy,
    /// Signed chain metadata for anti-deletion verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ChainMetadata>,
    #[serde(skip)]
    storage_path: Option<PathBuf>,
}

impl Chain {
    pub fn new(document_path: impl AsRef<Path>, vdf_params: Parameters) -> Result<Self> {
        Self::new_with_mode(document_path, vdf_params, EntanglementMode::Legacy)
    }

    /// Set signature policy.
    pub fn with_signature_policy(mut self, policy: SignaturePolicy) -> Self {
        self.signature_policy = policy;
        self
    }

    /// Create a chain with specified entanglement mode.
    ///
    /// `EntanglementMode::Entangled` (WAR/1.1): each VDF is seeded by
    /// previous VDF output + jitter + document state.
    pub fn new_with_mode(
        document_path: impl AsRef<Path>,
        vdf_params: Parameters,
        entanglement_mode: EntanglementMode,
    ) -> Result<Self> {
        let abs_path = fs::canonicalize(document_path.as_ref())?;
        let path_bytes = abs_path.to_string_lossy();
        let path_hash = Sha256::digest(path_bytes.as_bytes());
        let document_id = hex::encode(&path_hash[0..8]);

        Ok(Self {
            document_id,
            document_path: abs_path.to_string_lossy().to_string(),
            created_at: Utc::now(),
            checkpoints: Vec::new(),
            vdf_params,
            entanglement_mode,
            signature_policy: SignaturePolicy::Required,
            metadata: None,
            storage_path: None,
        })
    }

    pub fn commit(&mut self, message: Option<String>) -> Result<Checkpoint> {
        let (content_hash, content_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.document_path))?;
        let ordinal = self.checkpoints.len() as u64;

        let mut previous_hash = [0u8; 32];
        let mut last_timestamp = None;
        if ordinal > 0 {
            if let Some(prev) = self.checkpoints.last() {
                previous_hash = prev.hash;
                last_timestamp = Some(prev.timestamp);
            }
        }

        let mut checkpoint =
            Checkpoint::new_base(ordinal, previous_hash, content_hash, content_size, message);
        let now = checkpoint.timestamp;

        if ordinal > 0 {
            let elapsed = now
                .signed_duration_since(last_timestamp.unwrap_or(now))
                .to_std()
                .unwrap_or(Duration::from_secs(0));
            let vdf_input = vdf::chain_input(content_hash, previous_hash, ordinal);
            let proof = vdf::compute(vdf_input, elapsed, self.vdf_params)?;
            checkpoint.vdf = Some(proof);
        }

        checkpoint.validate_timestamp()?;
        checkpoint.hash = checkpoint.compute_hash();
        self.checkpoints.push(checkpoint.clone());
        Ok(checkpoint)
    }

    pub fn commit_with_vdf_duration(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
    ) -> Result<Checkpoint> {
        let (content_hash, content_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.document_path))?;
        let ordinal = self.checkpoints.len() as u64;

        let previous_hash = self
            .checkpoints
            .last()
            .map(|cp| cp.hash)
            .unwrap_or([0u8; 32]);

        let mut checkpoint =
            Checkpoint::new_base(ordinal, previous_hash, content_hash, content_size, message);

        if ordinal > 0 {
            let vdf_input = vdf::chain_input(content_hash, previous_hash, ordinal);
            let proof = vdf::compute(vdf_input, vdf_duration, self.vdf_params)?;
            checkpoint.vdf = Some(proof);
        }

        checkpoint.validate_timestamp()?;
        checkpoint.hash = checkpoint.compute_hash();
        self.checkpoints.push(checkpoint.clone());
        Ok(checkpoint)
    }

    /// Commit with entangled VDF (WAR/1.1): VDF input = f(prev_vdf_output, jitter, content).
    ///
    /// Prevents precomputation since each VDF depends on the previous VDF's actual output.
    ///
    /// When `physics` is provided, a physics seed is derived from the content
    /// hash and physical context, then mixed into the VDF input for stronger
    /// non-repudiation binding to the local hardware environment.
    pub fn commit_entangled(
        &mut self,
        message: Option<String>,
        jitter_hash: [u8; 32],
        jitter_session_id: String,
        keystroke_count: u64,
        vdf_duration: Duration,
        physics: Option<&crate::PhysicalContext>,
    ) -> Result<Checkpoint> {
        if self.entanglement_mode != EntanglementMode::Entangled {
            return Err(Error::invalid_state(
                "commit_entangled requires EntanglementMode::Entangled",
            ));
        }

        let (content_hash, content_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.document_path))?;
        let ordinal = self.checkpoints.len() as u64;

        let last_cp = self.checkpoints.last();
        let previous_hash = last_cp.map(|cp| cp.hash).unwrap_or([0u8; 32]);

        let previous_vdf_output = last_cp
            .and_then(|cp| cp.vdf.as_ref())
            .map(|v| v.output)
            .unwrap_or([0u8; 32]);

        let physics_seed = physics
            .map(|ctx| crate::physics::entanglement::Entanglement::create_seed(content_hash, ctx));

        let mut checkpoint =
            Checkpoint::new_base(ordinal, previous_hash, content_hash, content_size, message);
        checkpoint.jitter_binding = Some(JitterBinding {
            jitter_hash,
            session_id: jitter_session_id,
            keystroke_count,
            physics_seed,
        });

        let base_input =
            vdf::chain_input_entangled(previous_vdf_output, jitter_hash, content_hash, ordinal);
        let vdf_input = mix_physics_seed(base_input, physics_seed);
        let proof = vdf::compute(vdf_input, vdf_duration, self.vdf_params)?;
        checkpoint.vdf = Some(proof);

        checkpoint.validate_timestamp()?;
        checkpoint.hash = checkpoint.compute_hash();
        self.checkpoints.push(checkpoint.clone());
        Ok(checkpoint)
    }

    /// Commit with full RFC-compliant structures (draft-condrey-rats-pop-01).
    ///
    /// Includes `VdfProofRfc`, `JitterBinding` (entropy + stats), and `TimeEvidence`.
    ///
    /// When `physics` is provided and the chain is in `Entangled` mode,
    /// the physics seed is mixed into the VDF input for stronger non-repudiation.
    pub fn commit_rfc(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
        rfc_jitter: Option<rfc::JitterBinding>,
        time_evidence: Option<TimeEvidence>,
        calibration: rfc::CalibrationAttestation,
        physics: Option<&crate::PhysicalContext>,
    ) -> Result<Checkpoint> {
        if matches!(self.entanglement_mode, EntanglementMode::Entangled) && rfc_jitter.is_none() {
            return Err(Error::checkpoint("entangled mode requires jitter data"));
        }

        let (content_hash, content_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.document_path))?;
        let ordinal = self.checkpoints.len() as u64;

        let last_cp = self.checkpoints.last();
        let previous_hash = last_cp.map(|cp| cp.hash).unwrap_or([0u8; 32]);

        let physics_seed = if self.entanglement_mode == EntanglementMode::Entangled {
            physics.map(|ctx| {
                crate::physics::entanglement::Entanglement::create_seed(content_hash, ctx)
            })
        } else {
            None
        };

        let vdf_input = match self.entanglement_mode {
            EntanglementMode::Legacy => vdf::chain_input(content_hash, previous_hash, ordinal),
            EntanglementMode::Entangled => {
                let previous_vdf_output = last_cp
                    .and_then(|cp| cp.vdf.as_ref())
                    .map(|v| v.output)
                    .unwrap_or([0u8; 32]);
                let jitter_hash = rfc_jitter
                    .as_ref()
                    .map(|j| j.entropy_commitment.hash)
                    .unwrap_or([0u8; 32]);
                let base_input = vdf::chain_input_entangled(
                    previous_vdf_output,
                    jitter_hash,
                    content_hash,
                    ordinal,
                );
                mix_physics_seed(base_input, physics_seed)
            }
        };

        let vdf_proof = if ordinal > 0 || self.entanglement_mode == EntanglementMode::Entangled {
            Some(vdf::compute(vdf_input, vdf_duration, self.vdf_params)?)
        } else {
            None
        };

        let rfc_vdf = vdf_proof.as_ref().map(|vdf| {
            let mut output = [0u8; 64];
            output[..32].copy_from_slice(&vdf.output);
            output[32..].copy_from_slice(&vdf.input);

            VdfProofRfc::new(
                vdf.input,
                output,
                vdf.iterations,
                vdf.duration.as_millis().min(u64::MAX as u128) as u64,
                calibration.clone(),
            )
        });

        // Backward-compat jitter binding from RFC structure
        let jitter_binding = rfc_jitter.as_ref().map(|rj| JitterBinding {
            jitter_hash: rj.entropy_commitment.hash,
            session_id: format!("rfc-{}", ordinal),
            keystroke_count: rj.summary.sample_count,
            physics_seed,
        });

        let mut checkpoint =
            Checkpoint::new_base(ordinal, previous_hash, content_hash, content_size, message);
        checkpoint.vdf = vdf_proof;
        checkpoint.jitter_binding = jitter_binding;
        checkpoint.rfc_vdf = rfc_vdf;
        checkpoint.rfc_jitter = rfc_jitter;
        checkpoint.time_evidence = time_evidence;

        checkpoint.validate_timestamp()?;
        checkpoint.hash = checkpoint.compute_hash();
        self.checkpoints.push(checkpoint.clone());
        Ok(checkpoint)
    }

    /// Verify the chain, returning `Err` on failure. See `verify_detailed()` for diagnostics.
    pub fn verify(&self) -> Result<()> {
        let report = self.verify_detailed();
        if report.valid {
            Ok(())
        } else {
            Err(Error::checkpoint(
                report.error.unwrap_or_else(|| "verification failed".into()),
            ))
        }
    }

    /// Full verification returning a `VerificationReport`.
    ///
    /// Lightweight hash-chain check (no VDF reverification). O(n) in checkpoints.
    pub fn verify_hash_chain(&self) -> bool {
        for (i, cp) in self.checkpoints.iter().enumerate() {
            if cp.compute_hash() != cp.hash {
                return false;
            }
            if i > 0 {
                if cp.previous_hash != self.checkpoints[i - 1].hash {
                    return false;
                }
            } else if cp.previous_hash != [0u8; 32] {
                return false;
            }
        }
        true
    }

    /// Checks hash integrity, chain linkage, ordinal contiguity, VDF proofs,
    /// signature policy, and metadata consistency.
    pub fn verify_detailed(&self) -> VerificationReport {
        let mut report = VerificationReport::new();

        for (i, checkpoint) in self.checkpoints.iter().enumerate() {
            if checkpoint.compute_hash() != checkpoint.hash {
                report.fail(format!("checkpoint {i}: hash mismatch"));
                return report;
            }

            if checkpoint.ordinal != i as u64 {
                report.ordinal_gaps.push((i as u64, checkpoint.ordinal));
                report.fail(format!(
                    "checkpoint {i}: ordinal gap (expected {i}, got {})",
                    checkpoint.ordinal
                ));
                return report;
            }

            if i > 0 {
                if checkpoint.previous_hash != self.checkpoints[i - 1].hash {
                    report.fail(format!("checkpoint {i}: broken chain link"));
                    return report;
                }
            } else if checkpoint.previous_hash != [0u8; 32] {
                report.fail("checkpoint 0: non-zero previous hash".into());
                return report;
            }

            match checkpoint.signature.as_ref() {
                None => {
                    report.unsigned_checkpoints.push(checkpoint.ordinal);
                    match self.signature_policy {
                        SignaturePolicy::Required => {
                            report.fail(format!(
                                "checkpoint {i}: unsigned (signature required by policy)"
                            ));
                            return report;
                        }
                        SignaturePolicy::Optional => {
                            report
                                .warnings
                                .push(format!("checkpoint {i}: unsigned (optional policy)"));
                        }
                    }
                }
                Some(sig) => {
                    // Structural format check only. Cryptographic signature
                    // verification in keyhierarchy/verification.rs
                    // (verify_checkpoint_signatures, lines 33-53).
                    if sig.is_empty() || sig.len() != 64 {
                        report.signature_failures.push(checkpoint.ordinal);
                        report.fail(format!(
                            "checkpoint {i}: invalid signature length {} (expected 64)",
                            sig.len()
                        ));
                        return report;
                    }
                }
            }

            match self.entanglement_mode {
                EntanglementMode::Legacy => {
                    if i > 0 {
                        let vdf = match checkpoint.vdf.as_ref() {
                            Some(v) => v,
                            None => {
                                report.fail(format!(
                                    "checkpoint {i}: missing VDF proof (required for time verification)"
                                ));
                                return report;
                            }
                        };
                        let expected_input = vdf::chain_input(
                            checkpoint.content_hash,
                            checkpoint.previous_hash,
                            checkpoint.ordinal,
                        );
                        if vdf.input != expected_input {
                            report.fail(format!("checkpoint {i}: VDF input mismatch"));
                            return report;
                        }
                        if !vdf::verify(vdf) {
                            report.fail(format!("checkpoint {i}: VDF verification failed"));
                            return report;
                        }
                    }
                }
                EntanglementMode::Entangled => {
                    let vdf = match checkpoint.vdf.as_ref() {
                        Some(v) => v,
                        None => {
                            report.fail(format!(
                                "checkpoint {i}: missing VDF proof (required for entangled verification)"
                            ));
                            return report;
                        }
                    };

                    let jitter_binding = match checkpoint.jitter_binding.as_ref() {
                        Some(j) => j,
                        None => {
                            report.fail(format!(
                                "checkpoint {i}: missing jitter binding (required for entangled mode)"
                            ));
                            return report;
                        }
                    };

                    let previous_vdf_output = if i > 0 {
                        match self.checkpoints[i - 1].vdf.as_ref() {
                            Some(v) => v.output,
                            None => {
                                report.fail(format!(
                                    "checkpoint {i}: previous checkpoint missing VDF (required for entangled chain)"
                                ));
                                return report;
                            }
                        }
                    } else {
                        [0u8; 32]
                    };

                    let base_input = vdf::chain_input_entangled(
                        previous_vdf_output,
                        jitter_binding.jitter_hash,
                        checkpoint.content_hash,
                        checkpoint.ordinal,
                    );
                    let expected_input = mix_physics_seed(base_input, jitter_binding.physics_seed);
                    if vdf.input != expected_input {
                        report.fail(format!("checkpoint {i}: VDF input mismatch (entangled)"));
                        return report;
                    }
                    if !vdf::verify(vdf) {
                        report.fail(format!("checkpoint {i}: VDF verification failed"));
                        return report;
                    }
                }
            }
        }

        if let Some(metadata) = &self.metadata {
            let actual_count = self.checkpoints.len() as u64;
            if metadata.checkpoint_count != actual_count {
                report.metadata_valid = false;
                report.fail(format!(
                    "metadata checkpoint count mismatch: metadata says {}, actual {}",
                    metadata.checkpoint_count, actual_count
                ));
                return report;
            }
            if metadata.mmr_leaf_count != actual_count {
                report.metadata_valid = false;
                report.fail(format!(
                    "metadata MMR leaf count mismatch: metadata says {}, actual {}",
                    metadata.mmr_leaf_count, actual_count
                ));
                return report;
            }

            // Format check only; full crypto verification at key_hierarchy level
            match &metadata.metadata_signature {
                None => {
                    report.metadata_valid = false;
                    report.warnings.push(
                        "metadata signature missing: anti-deletion protection is not active"
                            .to_string(),
                    );
                }
                Some(sig) if sig.len() != 64 => {
                    report.metadata_valid = false;
                    report.fail(format!(
                        "metadata signature invalid length {} (expected 64)",
                        sig.len()
                    ));
                    return report;
                }
                Some(_) => {}
            }
        }

        report
    }

    pub fn total_elapsed_time(&self) -> Duration {
        self.checkpoints
            .iter()
            .filter_map(|cp| cp.vdf.as_ref())
            .map(|v| v.min_elapsed_time(self.vdf_params))
            .fold(Duration::from_secs(0), |acc, v| acc + v)
    }

    pub fn summary(&self) -> ChainSummary {
        let mut summary = ChainSummary {
            document_path: self.document_path.clone(),
            checkpoint_count: self.checkpoints.len(),
            first_commit: None,
            last_commit: None,
            total_elapsed_time: self.total_elapsed_time(),
            final_content_hash: None,
            chain_valid: None,
        };

        if let Some(first) = self.checkpoints.first() {
            summary.first_commit = Some(first.timestamp);
        }
        if let Some(last) = self.checkpoints.last() {
            summary.last_commit = Some(last.timestamp);
            summary.final_content_hash = Some(hex::encode(last.content_hash));
        }

        summary
    }

    pub fn save(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        self.storage_path = Some(path.to_path_buf());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::checkpoint(format!("failed to marshal chain: {e}")))?;
        // Atomic write: tmp + rename to avoid corrupt chain on crash
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, data)?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let data = fs::read(path.as_ref())?;
        let mut chain: Chain = serde_json::from_slice(&data)
            .map_err(|e| Error::checkpoint(format!("failed to unmarshal chain: {e}")))?;
        chain.storage_path = Some(path.as_ref().to_path_buf());
        chain.validate_vdf_proofs()?;
        Ok(chain)
    }

    /// Validate VDF proofs embedded in checkpoints after deserialization.
    ///
    /// Re-derives expected VDF inputs from the chain state and re-computes
    /// each proof's hash chain to confirm the output matches. Returns an
    /// error on the first invalid proof encountered.
    fn validate_vdf_proofs(&self) -> Result<()> {
        for (i, checkpoint) in self.checkpoints.iter().enumerate() {
            let vdf = match checkpoint.vdf.as_ref() {
                Some(v) => v,
                None => continue,
            };

            let expected_input = match self.entanglement_mode {
                EntanglementMode::Legacy => vdf::chain_input(
                    checkpoint.content_hash,
                    checkpoint.previous_hash,
                    checkpoint.ordinal,
                ),
                EntanglementMode::Entangled => {
                    let previous_vdf_output = if i > 0 {
                        match self.checkpoints[i - 1].vdf.as_ref() {
                            Some(v) => v.output,
                            None => {
                                return Err(Error::checkpoint(format!(
                                    "checkpoint {i}: previous checkpoint missing VDF \
                                     (required for entangled chain)"
                                )));
                            }
                        }
                    } else {
                        [0u8; 32]
                    };

                    let jitter_binding = checkpoint.jitter_binding.as_ref().ok_or_else(|| {
                        Error::checkpoint(format!(
                            "checkpoint {i}: missing jitter binding \
                             (required for entangled mode)"
                        ))
                    })?;

                    let base_input = vdf::chain_input_entangled(
                        previous_vdf_output,
                        jitter_binding.jitter_hash,
                        checkpoint.content_hash,
                        checkpoint.ordinal,
                    );
                    mix_physics_seed(base_input, jitter_binding.physics_seed)
                }
            };

            if vdf.input != expected_input {
                return Err(Error::checkpoint(format!(
                    "checkpoint {i}: VDF input mismatch on deserialization"
                )));
            }

            if !vdf::verify(vdf) {
                return Err(Error::checkpoint(format!(
                    "checkpoint {i}: VDF proof invalid on deserialization"
                )));
            }
        }
        Ok(())
    }

    pub fn find_chain(
        document_path: impl AsRef<Path>,
        writerslogic_dir: impl AsRef<Path>,
    ) -> Result<PathBuf> {
        let abs_path = fs::canonicalize(document_path.as_ref())?;
        let path_hash = Sha256::digest(abs_path.to_string_lossy().as_bytes());
        let doc_id = hex::encode(&path_hash[0..8]);
        let chain_path = writerslogic_dir
            .as_ref()
            .join("chains")
            .join(format!("{doc_id}.json"));
        if !chain_path.exists() {
            return Err(Error::not_found(format!(
                "no chain found for {}",
                abs_path.to_string_lossy()
            )));
        }
        Ok(chain_path)
    }

    pub fn get_or_create_chain(
        document_path: impl AsRef<Path>,
        writerslogic_dir: impl AsRef<Path>,
        vdf_params: Parameters,
    ) -> Result<Self> {
        if let Ok(path) = Self::find_chain(&document_path, &writerslogic_dir) {
            return Self::load(path);
        }

        let mut chain = Self::new(&document_path, vdf_params)?;
        let abs_path = fs::canonicalize(document_path.as_ref())?;
        let path_hash = Sha256::digest(abs_path.to_string_lossy().as_bytes());
        let doc_id = hex::encode(&path_hash[0..8]);
        chain.storage_path = Some(
            writerslogic_dir
                .as_ref()
                .join("chains")
                .join(format!("{doc_id}.json")),
        );
        Ok(chain)
    }

    pub fn latest(&self) -> Option<&Checkpoint> {
        self.checkpoints.last()
    }

    pub fn at(&self, ordinal: u64) -> Result<&Checkpoint> {
        let index = usize::try_from(ordinal)
            .map_err(|_| Error::checkpoint("ordinal too large for this platform"))?;
        self.checkpoints
            .get(index)
            .ok_or_else(|| Error::not_found(format!("checkpoint ordinal {ordinal} out of range")))
    }

    pub fn storage_path(&self) -> Option<&Path> {
        self.storage_path.as_deref()
    }

    pub fn set_storage_path(&mut self, path: PathBuf) {
        self.storage_path = Some(path);
    }
}
