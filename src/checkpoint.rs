use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::rfc::{self, TimeEvidence, VdfProofRfc};
use crate::vdf::{self, Parameters, VdfProof};

/// Entanglement mode for checkpoint chain computation.
///
/// WAR/1.0 (Legacy): VDF input = hash(content_hash ‖ previous_checkpoint_hash ‖ ordinal)
/// WAR/1.1 (Entangled): VDF input = hash(previous_vdf_output ‖ jitter_hash ‖ content_hash ‖ ordinal)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EntanglementMode {
    /// Legacy mode (WAR/1.0): parallel computation possible
    #[default]
    Legacy,
    /// Entangled mode (WAR/1.1): each VDF depends on previous VDF output + jitter
    Entangled,
}

/// Jitter binding for entangled checkpoints.
///
/// This captures the jitter evidence hash at the time of checkpoint creation,
/// creating a cryptographic link between behavioral timing and the checkpoint chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterBinding {
    /// Hash of the jitter evidence structure at checkpoint time
    pub jitter_hash: [u8; 32],
    /// Session ID of the jitter session
    pub session_id: String,
    /// Number of keystrokes at checkpoint time
    pub keystroke_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub ordinal: u64,
    pub previous_hash: [u8; 32],
    pub hash: [u8; 32],
    pub content_hash: [u8; 32],
    pub content_size: i64,
    pub file_path: String,
    pub timestamp: DateTime<Utc>,
    pub message: Option<String>,
    pub vdf: Option<VdfProof>,
    pub tpm_binding: Option<TpmBinding>,
    pub signature: Option<Vec<u8>>,
    /// Jitter binding for entangled mode (WAR/1.1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter_binding: Option<JitterBinding>,

    // ============================================
    // RFC-compliant fields (draft-condrey-rats-pop-01)
    // ============================================
    /// RFC-compliant VDF proof with calibration attestation.
    /// Contains the CDDL-defined vdf-proof structure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc_vdf: Option<VdfProofRfc>,

    /// RFC-compliant jitter binding with full entropy chain.
    /// Contains entropy commitment, sources, summary, and optional active probes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc_jitter: Option<rfc::JitterBinding>,

    /// Time evidence binding with external time sources.
    /// Includes roughtime samples, TSA responses, and blockchain anchors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_evidence: Option<TimeEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmBinding {
    pub monotonic_counter: u64,
    pub clock_info: Vec<u8>,
    pub attestation: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
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
    #[serde(skip)]
    storage_path: Option<PathBuf>,
}

impl Chain {
    pub fn new(document_path: impl AsRef<Path>, vdf_params: Parameters) -> Result<Self> {
        Self::new_with_mode(document_path, vdf_params, EntanglementMode::Legacy)
    }

    /// Create a new chain with specified entanglement mode.
    ///
    /// Use `EntanglementMode::Entangled` for WAR/1.1 chains where each checkpoint's
    /// VDF is seeded by the previous checkpoint's VDF output + jitter + document state.
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
            storage_path: None,
        })
    }

    pub fn commit(&mut self, message: Option<String>) -> Result<Checkpoint> {
        let content = fs::read(&self.document_path)?;
        let content_hash: [u8; 32] = Sha256::digest(&content).into();
        let ordinal = self.checkpoints.len() as u64;

        let mut previous_hash = [0u8; 32];
        let mut last_timestamp = None;
        if ordinal > 0 {
            if let Some(prev) = self.checkpoints.last() {
                previous_hash = prev.hash;
                last_timestamp = Some(prev.timestamp);
            }
        }

        let now = Utc::now();
        let mut checkpoint = Checkpoint {
            ordinal,
            previous_hash,
            hash: [0u8; 32],
            content_hash,
            content_size: content.len() as i64,
            file_path: self.document_path.clone(),
            timestamp: now,
            message,
            vdf: None,
            tpm_binding: None,
            signature: None,
            jitter_binding: None,
            rfc_vdf: None,
            rfc_jitter: None,
            time_evidence: None,
        };

        if ordinal > 0 {
            let elapsed = now
                .signed_duration_since(last_timestamp.unwrap_or(now))
                .to_std()
                .unwrap_or(Duration::from_secs(0));
            let vdf_input = vdf::chain_input(content_hash, previous_hash, ordinal);
            let proof = vdf::compute(vdf_input, elapsed, self.vdf_params)?;
            checkpoint.vdf = Some(proof);
        }

        checkpoint.hash = checkpoint.compute_hash();
        self.checkpoints.push(checkpoint.clone());
        Ok(checkpoint)
    }

    pub fn commit_with_vdf_duration(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
    ) -> Result<Checkpoint> {
        let content = fs::read(&self.document_path)?;
        let content_hash: [u8; 32] = Sha256::digest(&content).into();
        let ordinal = self.checkpoints.len() as u64;

        let previous_hash = if ordinal > 0 {
            self.checkpoints[ordinal as usize - 1].hash
        } else {
            [0u8; 32]
        };

        let mut checkpoint = Checkpoint {
            ordinal,
            previous_hash,
            hash: [0u8; 32],
            content_hash,
            content_size: content.len() as i64,
            file_path: self.document_path.clone(),
            timestamp: Utc::now(),
            message,
            vdf: None,
            tpm_binding: None,
            signature: None,
            jitter_binding: None,
            rfc_vdf: None,
            rfc_jitter: None,
            time_evidence: None,
        };

        if ordinal > 0 {
            let vdf_input = vdf::chain_input(content_hash, previous_hash, ordinal);
            let proof = vdf::compute(vdf_input, vdf_duration, self.vdf_params)?;
            checkpoint.vdf = Some(proof);
        }

        checkpoint.hash = checkpoint.compute_hash();
        self.checkpoints.push(checkpoint.clone());
        Ok(checkpoint)
    }

    /// Commit with entangled VDF computation (WAR/1.1 mode).
    ///
    /// This creates a checkpoint where the VDF input is derived from:
    /// - Previous checkpoint's VDF output (or zeros for first checkpoint)
    /// - Current jitter evidence hash (behavioral timing entropy)
    /// - Current document content hash (content binding)
    ///
    /// This makes the checkpoint chain impossible to precompute, as each VDF
    /// depends on the actual computed output of the previous VDF.
    pub fn commit_entangled(
        &mut self,
        message: Option<String>,
        jitter_hash: [u8; 32],
        jitter_session_id: String,
        keystroke_count: u64,
        vdf_duration: Duration,
    ) -> Result<Checkpoint> {
        if self.entanglement_mode != EntanglementMode::Entangled {
            return Err(Error::invalid_state(
                "commit_entangled requires EntanglementMode::Entangled",
            ));
        }

        let content = fs::read(&self.document_path)?;
        let content_hash: [u8; 32] = Sha256::digest(&content).into();
        let ordinal = self.checkpoints.len() as u64;

        let previous_hash = if ordinal > 0 {
            self.checkpoints[ordinal as usize - 1].hash
        } else {
            [0u8; 32]
        };

        // For entangled mode, get the previous VDF output (or zeros for first checkpoint)
        let previous_vdf_output = if ordinal > 0 {
            self.checkpoints[ordinal as usize - 1]
                .vdf
                .as_ref()
                .map(|v| v.output)
                .unwrap_or([0u8; 32])
        } else {
            [0u8; 32]
        };

        let jitter_binding = JitterBinding {
            jitter_hash,
            session_id: jitter_session_id,
            keystroke_count,
        };

        let mut checkpoint = Checkpoint {
            ordinal,
            previous_hash,
            hash: [0u8; 32],
            content_hash,
            content_size: content.len() as i64,
            file_path: self.document_path.clone(),
            timestamp: Utc::now(),
            message,
            vdf: None,
            tpm_binding: None,
            signature: None,
            jitter_binding: Some(jitter_binding),
            rfc_vdf: None,
            rfc_jitter: None,
            time_evidence: None,
        };

        // Compute entangled VDF input
        let vdf_input =
            vdf::chain_input_entangled(previous_vdf_output, jitter_hash, content_hash, ordinal);
        let proof = vdf::compute(vdf_input, vdf_duration, self.vdf_params)?;
        checkpoint.vdf = Some(proof);

        checkpoint.hash = checkpoint.compute_hash();
        self.checkpoints.push(checkpoint.clone());
        Ok(checkpoint)
    }

    /// Commit with RFC-compliant structures (draft-condrey-rats-pop-01).
    ///
    /// Creates a checkpoint with full RFC compliance including:
    /// - VdfProofRfc with calibration attestation
    /// - JitterBinding with entropy commitment and statistical summary
    /// - TimeEvidence with external time source bindings
    ///
    /// This is the recommended method for production use cases requiring
    /// standards-compliant evidence output.
    pub fn commit_rfc(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
        rfc_jitter: Option<rfc::JitterBinding>,
        time_evidence: Option<TimeEvidence>,
        calibration: rfc::CalibrationAttestation,
    ) -> Result<Checkpoint> {
        let content = fs::read(&self.document_path)?;
        let content_hash: [u8; 32] = Sha256::digest(&content).into();
        let ordinal = self.checkpoints.len() as u64;

        let previous_hash = if ordinal > 0 {
            self.checkpoints[ordinal as usize - 1].hash
        } else {
            [0u8; 32]
        };

        // Compute VDF input based on mode
        let vdf_input = match self.entanglement_mode {
            EntanglementMode::Legacy => vdf::chain_input(content_hash, previous_hash, ordinal),
            EntanglementMode::Entangled => {
                // For entangled mode, use previous VDF output + jitter
                let previous_vdf_output = if ordinal > 0 {
                    self.checkpoints[ordinal as usize - 1]
                        .vdf
                        .as_ref()
                        .map(|v| v.output)
                        .unwrap_or([0u8; 32])
                } else {
                    [0u8; 32]
                };
                let jitter_hash = rfc_jitter
                    .as_ref()
                    .map(|j| j.entropy_commitment.hash)
                    .unwrap_or([0u8; 32]);
                vdf::chain_input_entangled(previous_vdf_output, jitter_hash, content_hash, ordinal)
            }
        };

        // Compute internal VDF proof
        let vdf_proof = if ordinal > 0 || self.entanglement_mode == EntanglementMode::Entangled {
            Some(vdf::compute(vdf_input, vdf_duration, self.vdf_params)?)
        } else {
            None
        };

        // Create RFC-compliant VDF proof
        let rfc_vdf = vdf_proof.as_ref().map(|vdf| {
            let mut output = [0u8; 64];
            output[..32].copy_from_slice(&vdf.output);
            output[32..].copy_from_slice(&vdf.input);

            VdfProofRfc::new(
                vdf.input,
                output,
                vdf.iterations,
                vdf.duration.as_millis() as u64,
                calibration.clone(),
            )
        });

        // Create simple jitter binding for backward compatibility
        let jitter_binding = rfc_jitter.as_ref().map(|rj| JitterBinding {
            jitter_hash: rj.entropy_commitment.hash,
            session_id: format!("rfc-{}", ordinal),
            keystroke_count: rj.summary.sample_count,
        });

        let mut checkpoint = Checkpoint {
            ordinal,
            previous_hash,
            hash: [0u8; 32],
            content_hash,
            content_size: content.len() as i64,
            file_path: self.document_path.clone(),
            timestamp: Utc::now(),
            message,
            vdf: vdf_proof,
            tpm_binding: None,
            signature: None,
            jitter_binding,
            rfc_vdf,
            rfc_jitter,
            time_evidence,
        };

        checkpoint.hash = checkpoint.compute_hash();
        self.checkpoints.push(checkpoint.clone());
        Ok(checkpoint)
    }

    pub fn verify(&self) -> Result<()> {
        for (i, checkpoint) in self.checkpoints.iter().enumerate() {
            if checkpoint.compute_hash() != checkpoint.hash {
                return Err(Error::checkpoint(format!("checkpoint {i}: hash mismatch")));
            }

            if i > 0 {
                if checkpoint.previous_hash != self.checkpoints[i - 1].hash {
                    return Err(Error::checkpoint(format!(
                        "checkpoint {i}: broken chain link"
                    )));
                }
            } else if checkpoint.previous_hash != [0u8; 32] {
                return Err(Error::checkpoint("checkpoint 0: non-zero previous hash"));
            }

            // VDF verification depends on entanglement mode
            match self.entanglement_mode {
                EntanglementMode::Legacy => {
                    // Legacy mode: VDF required for checkpoints after first
                    if i > 0 {
                        let vdf = checkpoint.vdf.as_ref().ok_or_else(|| {
                            Error::checkpoint(format!(
                                "checkpoint {i}: missing VDF proof (required for time verification)"
                            ))
                        })?;
                        let expected_input = vdf::chain_input(
                            checkpoint.content_hash,
                            checkpoint.previous_hash,
                            checkpoint.ordinal,
                        );
                        if vdf.input != expected_input {
                            return Err(Error::checkpoint(format!(
                                "checkpoint {i}: VDF input mismatch"
                            )));
                        }
                        if !vdf::verify(vdf) {
                            return Err(Error::checkpoint(format!(
                                "checkpoint {i}: VDF verification failed"
                            )));
                        }
                    }
                }
                EntanglementMode::Entangled => {
                    // Entangled mode: VDF required for ALL checkpoints, including first
                    let vdf = checkpoint.vdf.as_ref().ok_or_else(|| {
                        Error::checkpoint(format!(
                            "checkpoint {i}: missing VDF proof (required for entangled verification)"
                        ))
                    })?;

                    // Get jitter binding (required for entangled mode)
                    let jitter_binding = checkpoint.jitter_binding.as_ref().ok_or_else(|| {
                        Error::checkpoint(format!(
                            "checkpoint {i}: missing jitter binding (required for entangled mode)"
                        ))
                    })?;

                    // Get previous VDF output (zeros for first checkpoint)
                    let previous_vdf_output = if i > 0 {
                        self.checkpoints[i - 1]
                            .vdf
                            .as_ref()
                            .map(|v| v.output)
                            .unwrap_or([0u8; 32])
                    } else {
                        [0u8; 32]
                    };

                    let expected_input = vdf::chain_input_entangled(
                        previous_vdf_output,
                        jitter_binding.jitter_hash,
                        checkpoint.content_hash,
                        checkpoint.ordinal,
                    );
                    if vdf.input != expected_input {
                        return Err(Error::checkpoint(format!(
                            "checkpoint {i}: VDF input mismatch (entangled)"
                        )));
                    }
                    if !vdf::verify(vdf) {
                        return Err(Error::checkpoint(format!(
                            "checkpoint {i}: VDF verification failed"
                        )));
                    }
                }
            }
        }

        Ok(())
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
            chain_valid: self.verify().is_ok(),
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
        fs::write(path, data)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let data = fs::read(path.as_ref())?;
        let mut chain: Chain = serde_json::from_slice(&data)
            .map_err(|e| Error::checkpoint(format!("failed to unmarshal chain: {e}")))?;
        chain.storage_path = Some(path.as_ref().to_path_buf());
        Ok(chain)
    }

    pub fn find_chain(
        document_path: impl AsRef<Path>,
        witnessd_dir: impl AsRef<Path>,
    ) -> Result<PathBuf> {
        let abs_path = fs::canonicalize(document_path.as_ref())?;
        let path_hash = Sha256::digest(abs_path.to_string_lossy().as_bytes());
        let doc_id = hex::encode(&path_hash[0..8]);
        let chain_path = witnessd_dir
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
        witnessd_dir: impl AsRef<Path>,
        vdf_params: Parameters,
    ) -> Result<Self> {
        if let Ok(path) = Self::find_chain(&document_path, &witnessd_dir) {
            return Self::load(path);
        }

        let mut chain = Self::new(&document_path, vdf_params)?;
        let abs_path = fs::canonicalize(document_path.as_ref())?;
        let path_hash = Sha256::digest(abs_path.to_string_lossy().as_bytes());
        let doc_id = hex::encode(&path_hash[0..8]);
        chain.storage_path = Some(
            witnessd_dir
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
        self.checkpoints
            .get(ordinal as usize)
            .ok_or_else(|| Error::not_found(format!("checkpoint ordinal {ordinal} out of range")))
    }

    pub fn storage_path(&self) -> Option<&Path> {
        self.storage_path.as_deref()
    }
}

impl Checkpoint {
    fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Use v3 domain separator if RFC fields present, v2 for jitter, v1 for legacy
        if self.rfc_vdf.is_some() || self.rfc_jitter.is_some() || self.time_evidence.is_some() {
            hasher.update(b"witnessd-checkpoint-v3");
        } else if self.jitter_binding.is_some() {
            hasher.update(b"witnessd-checkpoint-v2");
        } else {
            hasher.update(b"witnessd-checkpoint-v1");
        }
        hasher.update(self.ordinal.to_be_bytes());
        hasher.update(self.previous_hash);
        hasher.update(self.content_hash);
        hasher.update((self.content_size as u64).to_be_bytes());

        let timestamp_nanos = self.timestamp.timestamp_nanos_opt().unwrap_or(0) as u64;
        hasher.update(timestamp_nanos.to_be_bytes());

        if let Some(vdf) = &self.vdf {
            hasher.update(vdf.encode());
        }

        // Include jitter binding in hash for entangled mode
        if let Some(jitter) = &self.jitter_binding {
            hasher.update(jitter.jitter_hash);
            hasher.update(jitter.session_id.as_bytes());
            hasher.update(jitter.keystroke_count.to_be_bytes());
        }

        // Include RFC fields in hash (v3)
        if let Some(rfc_vdf) = &self.rfc_vdf {
            hasher.update(rfc_vdf.challenge);
            hasher.update(rfc_vdf.output);
            hasher.update(rfc_vdf.iterations.to_be_bytes());
            hasher.update(rfc_vdf.duration_ms.to_be_bytes());
            hasher.update(rfc_vdf.calibration.iterations_per_second.to_be_bytes());
            hasher.update(rfc_vdf.calibration.hardware_class.as_bytes());
        }

        if let Some(rfc_jitter) = &self.rfc_jitter {
            hasher.update(rfc_jitter.entropy_commitment.hash);
            hasher.update(rfc_jitter.summary.sample_count.to_be_bytes());
            // Include Hurst exponent if present
            if let Some(hurst) = rfc_jitter.summary.hurst_exponent {
                hasher.update(hurst.to_be_bytes());
            }
        }

        if let Some(time_ev) = &self.time_evidence {
            hasher.update([time_ev.tier as u8]);
            hasher.update(time_ev.timestamp_ms.to_be_bytes());
        }

        hasher.finalize().into()
    }

    /// Set the RFC-compliant VDF proof.
    pub fn with_rfc_vdf(mut self, vdf_proof: VdfProofRfc) -> Self {
        self.rfc_vdf = Some(vdf_proof);
        self
    }

    /// Set the RFC-compliant jitter binding.
    pub fn with_rfc_jitter(mut self, jitter: rfc::JitterBinding) -> Self {
        self.rfc_jitter = Some(jitter);
        self
    }

    /// Set the time evidence binding.
    pub fn with_time_evidence(mut self, evidence: TimeEvidence) -> Self {
        self.time_evidence = Some(evidence);
        self
    }

    /// Convert internal VdfProof to RFC-compliant VdfProofRfc.
    ///
    /// Creates an RFC-compliant proof from the internal representation,
    /// using the provided calibration attestation.
    pub fn to_rfc_vdf(&self, calibration: rfc::CalibrationAttestation) -> Option<VdfProofRfc> {
        self.vdf.as_ref().map(|vdf| {
            // Expand 32-byte output to 64-byte for Wesolowski-style proof
            let mut output = [0u8; 64];
            output[..32].copy_from_slice(&vdf.output);
            output[32..].copy_from_slice(&vdf.input); // Use input as second half for integrity

            VdfProofRfc::new(
                vdf.input,
                output,
                vdf.iterations,
                vdf.duration.as_millis() as u64,
                calibration,
            )
        })
    }

    /// Recompute and update the checkpoint hash.
    ///
    /// Call this after modifying checkpoint fields to ensure hash integrity.
    pub fn recompute_hash(&mut self) {
        self.hash = self.compute_hash();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSummary {
    pub document_path: String,
    pub checkpoint_count: usize,
    pub first_commit: Option<DateTime<Utc>>,
    pub last_commit: Option<DateTime<Utc>>,
    pub total_elapsed_time: Duration,
    pub final_content_hash: Option<String>,
    pub chain_valid: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn temp_document() -> (TempDir, PathBuf) {
        let dir = TempDir::new().expect("create temp dir");
        // Canonicalize path to handle macOS /var -> /private/var symlink
        let canonical_dir = dir.path().canonicalize().expect("canonicalize temp dir");
        let path = canonical_dir.join("test_document.txt");
        fs::write(&path, b"initial content").expect("write initial content");
        (dir, path)
    }

    fn test_vdf_params() -> Parameters {
        Parameters {
            iterations_per_second: 1000,
            min_iterations: 10,
            max_iterations: 100_000,
        }
    }

    #[test]
    fn test_chain_creation() {
        let (_dir, path) = temp_document();
        let chain = Chain::new(&path, test_vdf_params()).expect("create chain");
        assert!(!chain.document_id.is_empty());
        assert!(chain.checkpoints.is_empty());
        assert_eq!(chain.document_path, path.to_string_lossy());
    }

    #[test]
    fn test_chain_creation_invalid_path() {
        let err = Chain::new("/nonexistent/path/to/file.txt", test_vdf_params()).unwrap_err();
        // Error is an IO error for nonexistent path (message varies by platform)
        let msg = err.to_string();
        assert!(
            msg.contains("No such file") || msg.contains("cannot find the path"),
            "Unexpected error: {}",
            msg
        );
    }

    #[test]
    fn test_single_commit() {
        let (_dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");
        let checkpoint = chain
            .commit(Some("first commit".to_string()))
            .expect("commit");

        assert_eq!(checkpoint.ordinal, 0);
        assert_eq!(checkpoint.previous_hash, [0u8; 32]);
        assert_eq!(checkpoint.message, Some("first commit".to_string()));
        assert!(checkpoint.vdf.is_none()); // First commit has no VDF
        assert_ne!(checkpoint.content_hash, [0u8; 32]);
        assert_ne!(checkpoint.hash, [0u8; 32]);
    }

    #[test]
    fn test_multiple_commits_with_vdf() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");

        // First commit
        let cp0 = chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");
        assert_eq!(cp0.ordinal, 0);
        assert!(cp0.vdf.is_none());

        // Update document
        fs::write(&path, b"updated content").expect("update content");

        // Second commit
        let cp1 = chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 1");
        assert_eq!(cp1.ordinal, 1);
        assert!(cp1.vdf.is_some());
        assert_eq!(cp1.previous_hash, cp0.hash);

        // Update document again
        fs::write(&path, b"final content").expect("update content again");

        // Third commit
        let cp2 = chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 2");
        assert_eq!(cp2.ordinal, 2);
        assert!(cp2.vdf.is_some());
        assert_eq!(cp2.previous_hash, cp1.hash);

        // Verify the chain
        chain.verify().expect("verify chain");

        drop(dir);
    }

    #[test]
    fn test_chain_verification_valid() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");

        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 1");

        chain.verify().expect("verification should pass");
        drop(dir);
    }

    #[test]
    fn test_chain_verification_hash_mismatch() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit");

        // Tamper with the checkpoint hash
        chain.checkpoints[0].hash = [0xFFu8; 32];

        let err = chain.verify().unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));
        drop(dir);
    }

    #[test]
    fn test_chain_verification_broken_chain_link() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");

        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 1");

        // Tamper with the previous_hash to break the chain
        chain.checkpoints[1].previous_hash = [0xFFu8; 32];
        // Recompute hash to pass hash check (but link is broken)
        chain.checkpoints[1].hash = chain.checkpoints[1].compute_hash();

        let err = chain.verify().unwrap_err();
        assert!(
            err.to_string().contains("broken chain link"),
            "Expected 'broken chain link', got: {}",
            err
        );
        drop(dir);
    }

    #[test]
    fn test_chain_verification_nonzero_first_previous_hash() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit");

        // Tamper with first checkpoint's previous_hash
        chain.checkpoints[0].previous_hash = [0x01u8; 32];
        // Recompute hash to pass hash check
        chain.checkpoints[0].hash = chain.checkpoints[0].compute_hash();

        let err = chain.verify().unwrap_err();
        assert!(err.to_string().contains("non-zero previous hash"));
        drop(dir);
    }

    #[test]
    fn test_save_and_load_chain() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");
        chain
            .commit_with_vdf_duration(Some("test".to_string()), Duration::from_millis(10))
            .expect("commit");

        let chain_path = dir.path().join("chain.json");
        chain.save(&chain_path).expect("save chain");

        let loaded = Chain::load(&chain_path).expect("load chain");
        assert_eq!(loaded.document_id, chain.document_id);
        assert_eq!(loaded.document_path, chain.document_path);
        assert_eq!(loaded.checkpoints.len(), chain.checkpoints.len());
        assert_eq!(loaded.checkpoints[0].hash, chain.checkpoints[0].hash);
        loaded.verify().expect("loaded chain should verify");

        drop(dir);
    }

    #[test]
    fn test_chain_summary() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");

        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 1");

        let summary = chain.summary();
        assert_eq!(summary.checkpoint_count, 2);
        assert!(summary.first_commit.is_some());
        assert!(summary.last_commit.is_some());
        assert!(summary.final_content_hash.is_some());
        assert!(summary.chain_valid);

        drop(dir);
    }

    #[test]
    fn test_chain_latest_and_at() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");
        assert!(chain.latest().is_none());

        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");
        assert!(chain.latest().is_some());
        assert_eq!(chain.latest().unwrap().ordinal, 0);

        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 1");
        assert_eq!(chain.latest().unwrap().ordinal, 1);

        assert_eq!(chain.at(0).unwrap().ordinal, 0);
        assert_eq!(chain.at(1).unwrap().ordinal, 1);
        assert!(chain.at(2).is_err());

        drop(dir);
    }

    #[test]
    fn test_total_elapsed_time() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");

        // First commit has no VDF, so no elapsed time
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");
        assert_eq!(chain.total_elapsed_time(), Duration::from_secs(0));

        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(50))
            .expect("commit 1");

        // Should have some elapsed time from VDF
        let elapsed = chain.total_elapsed_time();
        assert!(elapsed > Duration::from_secs(0));

        drop(dir);
    }

    #[test]
    fn test_get_or_create_chain() {
        let dir = TempDir::new().expect("create temp dir");
        let doc_path = dir.path().join("document.txt");
        let witnessd_dir = dir.path().join(".witnessd");

        fs::write(&doc_path, b"content").expect("write doc");

        // First call should create
        let chain1 = Chain::get_or_create_chain(&doc_path, &witnessd_dir, test_vdf_params())
            .expect("get_or_create");
        assert!(chain1.checkpoints.is_empty());

        drop(dir);
    }

    #[test]
    fn test_find_chain_not_found() {
        let dir = TempDir::new().expect("create temp dir");
        let doc_path = dir.path().join("document.txt");
        let witnessd_dir = dir.path().join(".witnessd");

        fs::write(&doc_path, b"content").expect("write doc");
        fs::create_dir_all(witnessd_dir.join("chains")).expect("create chains dir");

        let err = Chain::find_chain(&doc_path, &witnessd_dir).unwrap_err();
        assert!(err.to_string().contains("no chain found"));

        drop(dir);
    }

    #[test]
    fn test_commit_detects_content_changes() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");

        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");
        let hash0 = chain.checkpoints[0].content_hash;

        fs::write(&path, b"different content").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 1");
        let hash1 = chain.checkpoints[1].content_hash;

        assert_ne!(hash0, hash1);

        drop(dir);
    }

    #[test]
    fn test_vdf_verification_in_chain() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");

        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");
        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 1");

        // Tamper with VDF output
        if let Some(ref mut vdf) = chain.checkpoints[1].vdf {
            vdf.output = [0xFFu8; 32];
        }
        // Recompute hash to pass hash check (but VDF verification will fail)
        chain.checkpoints[1].hash = chain.checkpoints[1].compute_hash();

        let err = chain.verify().unwrap_err();
        assert!(
            err.to_string().contains("VDF verification failed"),
            "Expected 'VDF verification failed', got: {}",
            err
        );

        drop(dir);
    }

    #[test]
    fn test_vdf_input_mismatch_detection() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");

        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");
        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 1");

        // Tamper with VDF input
        if let Some(ref mut vdf) = chain.checkpoints[1].vdf {
            vdf.input = [0xAAu8; 32];
        }
        // Recompute hash to pass hash check (but VDF input check will fail)
        chain.checkpoints[1].hash = chain.checkpoints[1].compute_hash();

        let err = chain.verify().unwrap_err();
        assert!(
            err.to_string().contains("VDF input mismatch"),
            "Expected 'VDF input mismatch', got: {}",
            err
        );

        drop(dir);
    }

    // =========================================================================
    // Entangled mode tests (WAR/1.1)
    // =========================================================================

    #[test]
    fn test_entangled_chain_creation() {
        let (dir, path) = temp_document();
        let chain = Chain::new_with_mode(&path, test_vdf_params(), EntanglementMode::Entangled)
            .expect("create entangled chain");
        assert_eq!(chain.entanglement_mode, EntanglementMode::Entangled);
        assert!(chain.checkpoints.is_empty());
        drop(dir);
    }

    #[test]
    fn test_entangled_commit_requires_entangled_mode() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create legacy chain");

        let err = chain
            .commit_entangled(
                None,
                [1u8; 32],
                "session-1".to_string(),
                100,
                Duration::from_millis(10),
            )
            .unwrap_err();
        assert!(err.to_string().contains("EntanglementMode::Entangled"));
        drop(dir);
    }

    #[test]
    fn test_entangled_single_commit() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new_with_mode(&path, test_vdf_params(), EntanglementMode::Entangled)
            .expect("create chain");

        let jitter_hash = [0xABu8; 32];
        let checkpoint = chain
            .commit_entangled(
                Some("first entangled commit".to_string()),
                jitter_hash,
                "session-1".to_string(),
                50,
                Duration::from_millis(10),
            )
            .expect("commit entangled");

        assert_eq!(checkpoint.ordinal, 0);
        assert!(checkpoint.vdf.is_some()); // Entangled mode has VDF even on first commit
        assert!(checkpoint.jitter_binding.is_some());
        let binding = checkpoint.jitter_binding.as_ref().unwrap();
        assert_eq!(binding.jitter_hash, jitter_hash);
        assert_eq!(binding.session_id, "session-1");
        assert_eq!(binding.keystroke_count, 50);

        chain.verify().expect("verify entangled chain");
        drop(dir);
    }

    #[test]
    fn test_entangled_multiple_commits() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new_with_mode(&path, test_vdf_params(), EntanglementMode::Entangled)
            .expect("create chain");

        // First commit
        let cp0 = chain
            .commit_entangled(
                None,
                [1u8; 32],
                "session-1".to_string(),
                10,
                Duration::from_millis(10),
            )
            .expect("commit 0");

        // Update document and commit again
        fs::write(&path, b"updated content").expect("update");
        let cp1 = chain
            .commit_entangled(
                None,
                [2u8; 32],
                "session-1".to_string(),
                25,
                Duration::from_millis(10),
            )
            .expect("commit 1");

        // Update again
        fs::write(&path, b"final content").expect("final update");
        let cp2 = chain
            .commit_entangled(
                None,
                [3u8; 32],
                "session-1".to_string(),
                50,
                Duration::from_millis(10),
            )
            .expect("commit 2");

        assert_eq!(chain.checkpoints.len(), 3);
        assert_eq!(cp1.previous_hash, cp0.hash);
        assert_eq!(cp2.previous_hash, cp1.hash);

        // Verify the VDF chain - each VDF input depends on previous VDF output
        let vdf0 = cp0.vdf.as_ref().unwrap();
        let vdf1 = cp1.vdf.as_ref().unwrap();

        // The second checkpoint's VDF input should use first checkpoint's VDF output
        let expected_input1 =
            vdf::chain_input_entangled(vdf0.output, [2u8; 32], cp1.content_hash, 1);
        assert_eq!(vdf1.input, expected_input1);

        chain.verify().expect("verify entangled chain");
        drop(dir);
    }

    #[test]
    fn test_entangled_verify_detects_vdf_tampering() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new_with_mode(&path, test_vdf_params(), EntanglementMode::Entangled)
            .expect("create chain");

        chain
            .commit_entangled(
                None,
                [1u8; 32],
                "session-1".to_string(),
                10,
                Duration::from_millis(10),
            )
            .expect("commit 0");

        fs::write(&path, b"updated").expect("update");
        chain
            .commit_entangled(
                None,
                [2u8; 32],
                "session-1".to_string(),
                20,
                Duration::from_millis(10),
            )
            .expect("commit 1");

        // Tamper with VDF output (this breaks the entanglement chain)
        if let Some(ref mut vdf) = chain.checkpoints[0].vdf {
            vdf.output = [0xFFu8; 32];
        }
        chain.checkpoints[0].hash = chain.checkpoints[0].compute_hash();

        let err = chain.verify().unwrap_err();
        // The first checkpoint's VDF verification itself will fail
        assert!(
            err.to_string().contains("VDF verification failed"),
            "Expected VDF verification failure, got: {}",
            err
        );
        drop(dir);
    }

    #[test]
    fn test_entangled_verify_detects_jitter_tampering() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new_with_mode(&path, test_vdf_params(), EntanglementMode::Entangled)
            .expect("create chain");

        chain
            .commit_entangled(
                None,
                [1u8; 32],
                "session-1".to_string(),
                10,
                Duration::from_millis(10),
            )
            .expect("commit 0");

        // Tamper with jitter hash (but not VDF input - this should cause mismatch)
        chain.checkpoints[0]
            .jitter_binding
            .as_mut()
            .unwrap()
            .jitter_hash = [0xFFu8; 32];
        chain.checkpoints[0].hash = chain.checkpoints[0].compute_hash();

        let err = chain.verify().unwrap_err();
        assert!(
            err.to_string().contains("VDF input mismatch"),
            "Expected VDF input mismatch, got: {}",
            err
        );
        drop(dir);
    }

    #[test]
    fn test_entangled_verify_requires_jitter_binding() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new_with_mode(&path, test_vdf_params(), EntanglementMode::Entangled)
            .expect("create chain");

        chain
            .commit_entangled(
                None,
                [1u8; 32],
                "session-1".to_string(),
                10,
                Duration::from_millis(10),
            )
            .expect("commit 0");

        // Remove jitter binding
        chain.checkpoints[0].jitter_binding = None;
        chain.checkpoints[0].hash = chain.checkpoints[0].compute_hash();

        let err = chain.verify().unwrap_err();
        assert!(
            err.to_string().contains("missing jitter binding"),
            "Expected missing jitter binding error, got: {}",
            err
        );
        drop(dir);
    }

    #[test]
    fn test_entangled_chain_save_load() {
        let dir = TempDir::new().expect("create temp dir");
        let canonical_dir = dir.path().canonicalize().expect("canonicalize");
        let path = canonical_dir.join("test_doc.txt");
        fs::write(&path, b"test content").expect("write");

        let mut chain = Chain::new_with_mode(&path, test_vdf_params(), EntanglementMode::Entangled)
            .expect("create chain");

        chain
            .commit_entangled(
                Some("entangled test".to_string()),
                [0xABu8; 32],
                "session-test".to_string(),
                42,
                Duration::from_millis(10),
            )
            .expect("commit");

        let chain_path = canonical_dir.join("chain.json");
        chain.save(&chain_path).expect("save");

        let loaded = Chain::load(&chain_path).expect("load");
        assert_eq!(loaded.entanglement_mode, EntanglementMode::Entangled);
        assert_eq!(loaded.checkpoints.len(), 1);

        let binding = loaded.checkpoints[0].jitter_binding.as_ref().unwrap();
        assert_eq!(binding.jitter_hash, [0xABu8; 32]);
        assert_eq!(binding.session_id, "session-test");
        assert_eq!(binding.keystroke_count, 42);

        loaded.verify().expect("verify loaded chain");
        drop(dir);
    }

    #[test]
    fn test_legacy_mode_default() {
        let (dir, path) = temp_document();
        let chain = Chain::new(&path, test_vdf_params()).expect("create chain");
        assert_eq!(chain.entanglement_mode, EntanglementMode::Legacy);
        drop(dir);
    }

    // =========================================================================
    // RFC-compliant commit tests (draft-condrey-rats-pop-01)
    // =========================================================================

    #[test]
    fn test_commit_rfc_basic() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");

        let calibration = rfc::CalibrationAttestation::new(
            1_000_000, // 1M iterations per second
            "test-hardware".to_string(),
            vec![0u8; 64], // dummy signature
            1700000000,
        );

        let checkpoint = chain
            .commit_rfc(
                Some("RFC-compliant commit".to_string()),
                Duration::from_millis(10),
                None, // No jitter binding
                None, // No time evidence
                calibration,
            )
            .expect("commit_rfc");

        assert_eq!(checkpoint.ordinal, 0);
        // First commit has no VDF in legacy mode
        assert!(checkpoint.vdf.is_none());
        assert!(checkpoint.rfc_vdf.is_none());
        assert!(checkpoint.rfc_jitter.is_none());
        assert!(checkpoint.time_evidence.is_none());

        chain.verify().expect("verify chain");
        drop(dir);
    }

    #[test]
    fn test_commit_rfc_with_jitter_binding() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");

        // Create RFC-compliant jitter binding
        let entropy_commitment = rfc::jitter_binding::EntropyCommitment {
            hash: [0xABu8; 32],
            timestamp_ms: 1700000000000,
            previous_hash: [0u8; 32],
        };

        let sources = vec![rfc::jitter_binding::SourceDescriptor {
            source_type: "keyboard".to_string(),
            weight: 1000,
            device_fingerprint: None,
            transport_calibration: None,
        }];

        let summary = rfc::jitter_binding::JitterSummary {
            sample_count: 100,
            mean_interval_us: 150000.0,
            std_dev: 50000.0,
            coefficient_of_variation: 0.33,
            percentiles: [50000.0, 80000.0, 140000.0, 200000.0, 300000.0],
            entropy_bits: 8.5,
            hurst_exponent: Some(0.72),
        };

        let binding_mac = rfc::jitter_binding::BindingMac {
            mac: [0xCDu8; 32],
            document_hash: [0u8; 32],
            keystroke_count: 100,
            timestamp_ms: 1700000000000,
        };

        let rfc_jitter = rfc::JitterBinding::new(entropy_commitment, sources, summary, binding_mac);

        let calibration = rfc::CalibrationAttestation::new(
            1_000_000,
            "test-hardware".to_string(),
            vec![0u8; 64],
            1700000000,
        );

        // First commit
        chain
            .commit_rfc(
                None,
                Duration::from_millis(10),
                None,
                None,
                calibration.clone(),
            )
            .expect("commit 0");

        fs::write(&path, b"updated content").expect("update");

        // Second commit with RFC jitter
        let checkpoint = chain
            .commit_rfc(
                Some("With jitter".to_string()),
                Duration::from_millis(10),
                Some(rfc_jitter),
                None,
                calibration,
            )
            .expect("commit 1");

        assert_eq!(checkpoint.ordinal, 1);
        assert!(checkpoint.vdf.is_some());
        assert!(checkpoint.rfc_vdf.is_some());
        assert!(checkpoint.rfc_jitter.is_some());
        assert!(checkpoint.jitter_binding.is_some()); // Backward compat

        // Check RFC VDF structure
        let rfc_vdf = checkpoint.rfc_vdf.as_ref().unwrap();
        assert!(rfc_vdf.iterations > 0);
        // duration_ms can be 0 for very fast computations
        assert_eq!(rfc_vdf.calibration.hardware_class, "test-hardware");

        // Check RFC jitter structure
        let jitter = checkpoint.rfc_jitter.as_ref().unwrap();
        assert_eq!(jitter.entropy_commitment.hash, [0xABu8; 32]);
        assert_eq!(jitter.summary.hurst_exponent, Some(0.72));

        chain.verify().expect("verify chain");
        drop(dir);
    }

    #[test]
    fn test_commit_rfc_v3_domain_separator() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");

        let calibration =
            rfc::CalibrationAttestation::new(1_000_000, "test".to_string(), vec![], 1700000000);

        // First commit (no RFC fields yet)
        let cp0 = chain
            .commit_rfc(
                None,
                Duration::from_millis(10),
                None,
                None,
                calibration.clone(),
            )
            .expect("commit 0");

        // V1 domain separator (no jitter, no RFC)
        let expected_hash = cp0.compute_hash();
        assert_eq!(cp0.hash, expected_hash);

        fs::write(&path, b"updated").expect("update");

        // Create minimal RFC jitter to trigger v3
        let entropy_commitment = rfc::jitter_binding::EntropyCommitment {
            hash: [1u8; 32],
            timestamp_ms: 1700000000000,
            previous_hash: [0u8; 32],
        };
        let summary = rfc::jitter_binding::JitterSummary {
            sample_count: 10,
            mean_interval_us: 100000.0,
            std_dev: 10000.0,
            coefficient_of_variation: 0.1,
            percentiles: [0.0; 5],
            entropy_bits: 5.0,
            hurst_exponent: None,
        };
        let binding_mac = rfc::jitter_binding::BindingMac {
            mac: [0u8; 32],
            document_hash: [0u8; 32],
            keystroke_count: 10,
            timestamp_ms: 1700000000000,
        };
        let rfc_jitter = rfc::JitterBinding::new(entropy_commitment, vec![], summary, binding_mac);

        let cp1 = chain
            .commit_rfc(
                None,
                Duration::from_millis(10),
                Some(rfc_jitter),
                None,
                calibration,
            )
            .expect("commit 1");

        // Should use v3 domain separator
        assert!(cp1.rfc_jitter.is_some());
        let computed = cp1.compute_hash();
        assert_eq!(cp1.hash, computed);

        chain.verify().expect("verify chain");
        drop(dir);
    }

    #[test]
    fn test_checkpoint_to_rfc_vdf_conversion() {
        let (dir, path) = temp_document();
        let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");

        // Create checkpoint with internal VDF
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");
        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(50))
            .expect("commit 1");

        let checkpoint = &chain.checkpoints[1];
        assert!(checkpoint.vdf.is_some());

        // Convert to RFC VDF
        let calibration = rfc::CalibrationAttestation::new(
            test_vdf_params().iterations_per_second as u64,
            "test".to_string(),
            vec![],
            1700000000,
        );
        let rfc_vdf = checkpoint.to_rfc_vdf(calibration).unwrap();

        // Verify conversion
        let internal_vdf = checkpoint.vdf.as_ref().unwrap();
        assert_eq!(rfc_vdf.challenge, internal_vdf.input);
        assert_eq!(&rfc_vdf.output[..32], &internal_vdf.output[..]);
        assert_eq!(rfc_vdf.iterations, internal_vdf.iterations);
        assert_eq!(
            rfc_vdf.duration_ms,
            internal_vdf.duration.as_millis() as u64
        );

        drop(dir);
    }
}
