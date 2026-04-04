// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::vdf::{self, Parameters};
use cpop_protocol::rfc::wire_types::components::DocumentRef;
use cpop_protocol::rfc::wire_types::hash::HashValue;
use cpop_protocol::rfc::{self, TimeEvidence, VdfProofRfc};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use super::chain_helpers::{genesis_prev_hash, mix_physics_seed};
use super::types::*;

const MAX_CLOCK_DRIFT_SECS: i64 = 2;
const MAX_CHAIN_FILE_SIZE: u64 = 500 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMetadata {
    pub document_id: String,
    pub document_path: String,
    pub created_at: DateTime<Utc>,
    pub vdf_params: Parameters,
    pub entanglement_mode: EntanglementMode,
    #[serde(default)]
    pub signature_policy: SignaturePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    pub metadata: ChainMetadata,
    pub checkpoints: Vec<Checkpoint>,
    #[serde(skip)]
    storage_path: Option<PathBuf>,
}

impl Chain {
    pub fn new(document_path: impl AsRef<Path>, vdf_params: Parameters) -> Result<Self> {
        Self::new_with_mode(document_path, vdf_params, EntanglementMode::Legacy)
    }

    pub fn with_signature_policy(mut self, policy: SignaturePolicy) -> Self {
        self.metadata.signature_policy = policy;
        self
    }

    pub fn new_with_mode(
        document_path: impl AsRef<Path>,
        vdf_params: Parameters,
        entanglement_mode: EntanglementMode,
    ) -> Result<Self> {
        if fs::symlink_metadata(document_path.as_ref())?
            .file_type()
            .is_symlink()
        {
            return Err(Error::checkpoint(
                "Symlinks not supported for document paths",
            ));
        }

        let abs_path = fs::canonicalize(document_path.as_ref())?;
        let path_str = abs_path.to_string_lossy().to_string();
        let path_hash = Sha256::digest(path_str.as_bytes());
        let document_id = hex::encode(&path_hash[0..8]);

        Ok(Self {
            metadata: ChainMetadata {
                document_id,
                document_path: path_str,
                created_at: Utc::now(),
                vdf_params,
                entanglement_mode,
                signature_policy: SignaturePolicy::Required,
            },
            checkpoints: Vec::with_capacity(1024),
            storage_path: None,
        })
    }

    pub fn commit(&mut self, message: Option<String>) -> Result<Checkpoint> {
        self.commit_internal(message, None)
    }

    fn commit_internal(
        &mut self,
        message: Option<String>,
        vdf_duration: Option<Duration>,
    ) -> Result<Checkpoint> {
        let lock_file = fs::File::open(&self.metadata.document_path)?;
        Self::acquire_lock(&lock_file)?;
        let _guard = scopeguard::guard(&lock_file, Self::release_lock);
        self.commit_internal_locked(message, vdf_duration)
    }

    fn commit_internal_locked(
        &mut self,
        message: Option<String>,
        vdf_duration: Option<Duration>,
    ) -> Result<Checkpoint> {
        let (content_hash, content_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.metadata.document_path))?;

        let ordinal = self.checkpoints.len() as u64;
        let last_cp = self.checkpoints.last();
        let previous_hash = match last_cp {
            Some(cp) => cp.hash,
            None => genesis_prev_hash(
                content_hash,
                content_size,
                &self.metadata.document_path,
            )?,
        };

        let mut checkpoint = Checkpoint::new_base(
            ordinal,
            previous_hash,
            content_hash,
            content_size,
            message,
        );

        if ordinal > 0 {
            let duration = vdf_duration.unwrap_or_else(|| {
                let delta = checkpoint
                    .timestamp
                    .signed_duration_since(last_cp.unwrap().timestamp);
                delta.to_std().unwrap_or_else(|_| {
                    if delta.num_seconds().abs() > MAX_CLOCK_DRIFT_SECS {
                        log::warn!(
                            "Clock regression of {}s detected",
                            delta.num_seconds().abs()
                        );
                    }
                    Duration::from_secs(0)
                })
            });
            let vdf_input = vdf::chain_input(content_hash, previous_hash, ordinal);
            checkpoint.vdf =
                Some(vdf::compute(vdf_input, duration, self.metadata.vdf_params)?);
        }

        self.commit_finish(checkpoint)
    }

    fn commit_finish(&mut self, mut checkpoint: Checkpoint) -> Result<Checkpoint> {
        checkpoint.validate_timestamp()?;
        if checkpoint.explicit_hash_version.is_none() {
            checkpoint.explicit_hash_version = Some(checkpoint.hash_domain_version());
        }
        checkpoint.hash = checkpoint.compute_hash();
        let result = checkpoint.clone();
        self.checkpoints.push(checkpoint);
        Ok(result)
    }

    pub fn save(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        self.storage_path = Some(path.to_path_buf());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::checkpoint(format!("failed to marshal chain: {e}")))?;
        let rand_suffix: String = format!("{:016x}", rand::random::<u64>());
        let tmp_name = format!(
            "{}.{}.tmp",
            path.display(),
            &rand_suffix[..8.min(rand_suffix.len())]
        );
        let tmp_path = PathBuf::from(tmp_name);
        fs::write(&tmp_path, &data)?;
        fs::File::open(&tmp_path)?.sync_all()?;
        fs::rename(&tmp_path, path)?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file_len = fs::metadata(path)?.len();
        if file_len > MAX_CHAIN_FILE_SIZE {
            return Err(Error::checkpoint("Chain file exceeds safety limit"));
        }
        let data = fs::read(path)?;
        let mut chain: Chain = serde_json::from_slice(&data)
            .map_err(|e| Error::checkpoint(format!("failed to deserialize chain: {e}")))?;
        chain.storage_path = Some(path.to_path_buf());
        Ok(chain)
    }

    #[cfg(unix)]
    fn acquire_lock(file: &fs::File) -> Result<()> {
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            return Err(Error::checkpoint(
                "Concurrent commit blocked by file lock",
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn release_lock(file: &fs::File) {
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_UN);
        }
    }

    #[cfg(not(unix))]
    fn acquire_lock(_file: &fs::File) -> Result<()> {
        Ok(())
    }

    #[cfg(not(unix))]
    fn release_lock(_file: &fs::File) {}

    pub fn latest(&self) -> Option<&Checkpoint> {
        self.checkpoints.last()
    }

    pub fn total_elapsed_time(&self) -> Duration {
        self.checkpoints
            .iter()
            .filter_map(|cp| cp.vdf.as_ref())
            .map(|v| v.min_elapsed_time(self.metadata.vdf_params))
            .sum()
    }

    pub fn commit_with_vdf_duration(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
    ) -> Result<Checkpoint> {
        self.commit_internal(message, Some(vdf_duration))
    }

    pub fn commit_entangled(
        &mut self,
        message: Option<String>,
        jitter_hash: [u8; 32],
        jitter_session_id: String,
        keystroke_count: u64,
        vdf_duration: Duration,
        physics: Option<&crate::PhysicalContext>,
    ) -> Result<Checkpoint> {
        let lock_file = fs::File::open(&self.metadata.document_path)?;
        Self::acquire_lock(&lock_file)?;
        let _guard = scopeguard::guard(&lock_file, Self::release_lock);
        self.commit_entangled_locked(
            message,
            jitter_hash,
            jitter_session_id,
            keystroke_count,
            vdf_duration,
            physics,
        )
    }

    fn commit_entangled_locked(
        &mut self,
        message: Option<String>,
        jitter_hash: [u8; 32],
        jitter_session_id: String,
        keystroke_count: u64,
        vdf_duration: Duration,
        physics: Option<&crate::PhysicalContext>,
    ) -> Result<Checkpoint> {
        if self.metadata.entanglement_mode != EntanglementMode::Entangled {
            return Err(Error::invalid_state(
                "commit_entangled requires EntanglementMode::Entangled",
            ));
        }
        if jitter_session_id.is_empty() {
            return Err(Error::checkpoint("empty jitter_session_id"));
        }

        let (content_hash, content_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.metadata.document_path))?;
        let ordinal = u64::try_from(self.checkpoints.len())
            .map_err(|_| Error::checkpoint("checkpoint count exceeds u64"))?;

        let last_cp = self.checkpoints.last();
        let previous_hash = match last_cp {
            Some(cp) => cp.hash,
            None => genesis_prev_hash(
                content_hash,
                content_size,
                &self.metadata.document_path,
            )?,
        };

        let previous_vdf_output = last_cp
            .and_then(|cp| cp.vdf.as_ref())
            .map(|v| v.output)
            .unwrap_or([0u8; 32]);

        let physics_seed = physics.map(|ctx| {
            crate::physics::entanglement::Entanglement::create_seed(content_hash, ctx)
        });

        let mut checkpoint =
            Checkpoint::new_base(ordinal, previous_hash, content_hash, content_size, message);
        checkpoint.jitter_binding = Some(JitterBinding {
            jitter_hash,
            session_id: jitter_session_id,
            keystroke_count,
            physics_seed,
        });

        let base_input = vdf::chain_input_entangled(
            previous_vdf_output,
            jitter_hash,
            content_hash,
            ordinal,
        );
        let vdf_input = mix_physics_seed(base_input, physics_seed);
        let proof = vdf::compute(vdf_input, vdf_duration, self.metadata.vdf_params)?;
        checkpoint.vdf = Some(proof);

        self.commit_finish(checkpoint)
    }

    pub fn set_storage_path(&mut self, path: PathBuf) {
        self.storage_path = Some(path);
    }

    pub fn find_chain(
        document_path: impl AsRef<Path>,
        writersproof_dir: impl AsRef<Path>,
    ) -> Result<PathBuf> {
        let abs_path = fs::canonicalize(document_path.as_ref())?;
        let path_hash = Sha256::digest(abs_path.to_string_lossy().as_bytes());
        let doc_id = hex::encode(&path_hash[0..8]);
        let chain_path = writersproof_dir
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
        writersproof_dir: impl AsRef<Path>,
        vdf_params: Parameters,
    ) -> Result<Self> {
        if let Ok(path) = Self::find_chain(&document_path, &writersproof_dir) {
            return Self::load(path);
        }

        let mut chain = Self::new(&document_path, vdf_params)?;
        let abs_path = fs::canonicalize(document_path.as_ref())?;
        let path_hash = Sha256::digest(abs_path.to_string_lossy().as_bytes());
        let doc_id = hex::encode(&path_hash[0..8]);
        chain.storage_path = Some(
            writersproof_dir
                .as_ref()
                .join("chains")
                .join(format!("{doc_id}.json")),
        );
        Ok(chain)
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

    pub fn summary(&self) -> ChainSummary {
        let mut summary = ChainSummary {
            document_path: self.metadata.document_path.clone(),
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

    pub fn commit_rfc(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
        rfc_jitter: Option<rfc::JitterBinding>,
        time_evidence: Option<TimeEvidence>,
        calibration: rfc::CalibrationAttestation,
        physics: Option<&crate::PhysicalContext>,
    ) -> Result<Checkpoint> {
        let lock_file = fs::File::open(&self.metadata.document_path)?;
        Self::acquire_lock(&lock_file)?;
        let _guard = scopeguard::guard(&lock_file, Self::release_lock);
        self.commit_rfc_locked(
            message,
            vdf_duration,
            rfc_jitter,
            time_evidence,
            calibration,
            physics,
        )
    }

    fn commit_rfc_locked(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
        rfc_jitter: Option<rfc::JitterBinding>,
        time_evidence: Option<TimeEvidence>,
        calibration: rfc::CalibrationAttestation,
        physics: Option<&crate::PhysicalContext>,
    ) -> Result<Checkpoint> {
        if matches!(self.metadata.entanglement_mode, EntanglementMode::Entangled)
            && rfc_jitter.is_none()
        {
            return Err(Error::checkpoint("entangled mode requires jitter data"));
        }

        let (content_hash, content_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.metadata.document_path))?;
        let ordinal = u64::try_from(self.checkpoints.len())
            .map_err(|_| Error::checkpoint("checkpoint count exceeds u64"))?;

        let last_cp = self.checkpoints.last();
        let previous_hash = match last_cp {
            Some(cp) => cp.hash,
            None => genesis_prev_hash(
                content_hash,
                content_size,
                &self.metadata.document_path,
            )?,
        };

        let physics_seed =
            if self.metadata.entanglement_mode == EntanglementMode::Entangled {
                physics.map(|ctx| {
                    crate::physics::entanglement::Entanglement::create_seed(content_hash, ctx)
                })
            } else {
                None
            };

        let vdf_input = match self.metadata.entanglement_mode {
            EntanglementMode::Legacy => {
                vdf::chain_input(content_hash, previous_hash, ordinal)
            }
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

        let vdf_proof =
            if ordinal > 0 || self.metadata.entanglement_mode == EntanglementMode::Entangled {
                Some(vdf::compute(
                    vdf_input,
                    vdf_duration,
                    self.metadata.vdf_params,
                )?)
            } else {
                None
            };

        let rfc_vdf = vdf_proof.as_ref().map(|vdf| {
            use super::types::{
                VDF_RFC_FIELD_SIZE, VDF_RFC_INPUT_END, VDF_RFC_INPUT_OFFSET,
                VDF_RFC_OUTPUT_END, VDF_RFC_OUTPUT_OFFSET,
            };
            let mut output = [0u8; VDF_RFC_FIELD_SIZE];
            output[VDF_RFC_OUTPUT_OFFSET..VDF_RFC_OUTPUT_END]
                .copy_from_slice(&vdf.output);
            output[VDF_RFC_INPUT_OFFSET..VDF_RFC_INPUT_END]
                .copy_from_slice(&vdf.input);

            VdfProofRfc::new(
                vdf.input,
                output,
                vdf.iterations,
                vdf.duration.as_millis().min(u64::MAX as u128) as u64,
                calibration.clone(),
            )
        });

        let jitter_binding = rfc_jitter.as_ref().map(|rj| JitterBinding {
            jitter_hash: rj.entropy_commitment.hash,
            session_id: format!("rfc-{}", ordinal),
            keystroke_count: rj.summary.sample_count,
            physics_seed,
        });

        let swf_seed = if ordinal == 0 {
            let doc_ref = DocumentRef {
                content_hash: HashValue::try_sha256(content_hash.to_vec())
                    .expect("content_hash is 32 bytes"),
                filename: std::path::Path::new(&self.metadata.document_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string()),
                byte_length: content_size,
                char_count: content_size,
                salt_mode: None,
                salt_commitment: None,
            };
            let doc_cbor = cpop_protocol::codec::cbor::encode(&doc_ref)
                .map_err(|e| Error::checkpoint(format!("genesis doc-ref CBOR: {e}")))?;
            let jitter_or_nonce = rfc_jitter
                .as_ref()
                .map(|j| j.entropy_commitment.hash)
                .unwrap_or(content_hash);
            vdf::swf_seed_genesis(&doc_cbor, &jitter_or_nonce)
        } else if let Some(ref jb) = rfc_jitter {
            let intervals_cbor =
                cpop_protocol::codec::cbor::encode(&jb.summary.sample_count)
                    .map_err(|e| Error::checkpoint(format!("SWF intervals CBOR: {e}")))?;
            let phys_cbor = match physics {
                Some(p) => {
                    cpop_protocol::codec::cbor::encode(&p.combined_hash.to_vec())
                        .map_err(|e| Error::checkpoint(format!("SWF physics CBOR: {e}")))?
                }
                None => vec![],
            };
            vdf::swf_seed_enhanced(&previous_hash, &intervals_cbor, &phys_cbor)
        } else {
            vdf::swf_seed_core(&previous_hash, &content_hash)
        };

        let argon2_swf = {
            let swf_params = vdf::swf_argon2::Argon2SwfParams {
                iterations: self.metadata.vdf_params.min_iterations.max(3),
                ..vdf::swf_argon2::Argon2SwfParams::default()
            };
            Some(
                vdf::swf_argon2::compute(swf_seed, swf_params)
                    .map_err(|e| Error::checkpoint(format!("Argon2id SWF: {e}")))?,
            )
        };

        let mut checkpoint = Checkpoint::new_base(
            ordinal,
            previous_hash,
            content_hash,
            content_size,
            message,
        );
        checkpoint.vdf = vdf_proof;
        checkpoint.jitter_binding = jitter_binding;
        checkpoint.rfc_vdf = rfc_vdf;
        checkpoint.rfc_jitter = rfc_jitter;
        checkpoint.time_evidence = time_evidence;
        checkpoint.argon2_swf = argon2_swf;

        self.commit_finish(checkpoint)
    }
}
