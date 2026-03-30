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

/// Hard upper bound on checkpoint count to reject malformed chain files.
const MAX_CHECKPOINTS: usize = 1_000_000;

/// Append-only checkpoint chain with VDF time proofs for a single document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    pub document_id: String,
    pub document_path: String,
    pub created_at: DateTime<Utc>,
    pub checkpoints: Vec<Checkpoint>,
    pub vdf_params: Parameters,
    #[serde(default)]
    pub entanglement_mode: EntanglementMode,
    /// Legacy chains deserialize as Optional; new chains default to Required.
    #[serde(default)]
    pub signature_policy: SignaturePolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ChainMetadata>,
    #[serde(skip)]
    storage_path: Option<PathBuf>,
}

impl Chain {
    /// Create a new chain in Legacy entanglement mode.
    pub fn new(document_path: impl AsRef<Path>, vdf_params: Parameters) -> Result<Self> {
        Self::new_with_mode(document_path, vdf_params, EntanglementMode::Legacy)
    }

    /// Set the signature policy (Required or Optional) for this chain.
    pub fn with_signature_policy(mut self, policy: SignaturePolicy) -> Self {
        self.signature_policy = policy;
        self
    }

    /// `EntanglementMode::Entangled` (WAR/1.1): each VDF is seeded by
    /// previous VDF output + jitter + document state.
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

    /// Commit a new checkpoint, hashing the document and computing VDF proof.
    pub fn commit(&mut self, message: Option<String>) -> Result<Checkpoint> {
        self.commit_internal(message, None)
    }

    /// Commit with an explicit VDF duration instead of elapsed time since last checkpoint.
    pub fn commit_with_vdf_duration(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
    ) -> Result<Checkpoint> {
        self.commit_internal(message, Some(vdf_duration))
    }

    /// If `vdf_duration` is None, elapsed time since the last checkpoint is used.
    fn commit_internal(
        &mut self,
        message: Option<String>,
        vdf_duration: Option<Duration>,
    ) -> Result<Checkpoint> {
        // H-014: Acquire advisory file lock to prevent concurrent commits
        let lock_file = fs::File::open(&self.document_path)?;
        Self::acquire_lock(&lock_file)?;
        let _guard = scopeguard::guard(&lock_file, Self::release_lock);
        self.commit_internal_locked(message, vdf_duration)
    }

    /// Inner commit logic, called while holding the file lock.
    // TODO(M-119): commit_internal_locked, commit_entangled_locked, and
    // commit_rfc_locked share significant duplication (content hashing,
    // ordinal computation, genesis prev-hash, timestamp validation, hash
    // computation, push). Extract a shared commit_finish() helper once the
    // interface stabilises.
    fn commit_internal_locked(
        &mut self,
        message: Option<String>,
        vdf_duration: Option<Duration>,
    ) -> Result<Checkpoint> {
        let (content_hash, content_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.document_path))?;
        let ordinal = u64::try_from(self.checkpoints.len()).expect("checkpoint count exceeds u64");

        let last_cp = self.checkpoints.last();
        let previous_hash = match last_cp {
            Some(cp) => cp.hash,
            None => genesis_prev_hash(content_hash, content_size, &self.document_path)?,
        };

        let mut checkpoint =
            Checkpoint::new_base(ordinal, previous_hash, content_hash, content_size, message);

        // H-001: Genesis checkpoint (ordinal 0) intentionally skips VDF in Legacy
        // mode for backward compatibility. Entangled mode (the default for new
        // chains) computes VDF for genesis via commit_rfc_locked.
        if ordinal > 0 {
            let duration = vdf_duration.unwrap_or_else(|| {
                let now = checkpoint.timestamp;
                let last_ts = last_cp.map(|cp| cp.timestamp).unwrap_or(now);
                now.signed_duration_since(last_ts)
                    .to_std()
                    .unwrap_or_else(|_| {
                        log::warn!("System clock regression detected; using zero VDF duration");
                        Duration::from_secs(0)
                    })
            });
            let vdf_input = vdf::chain_input(content_hash, previous_hash, ordinal);
            let proof = vdf::compute(vdf_input, duration, self.vdf_params)?;
            checkpoint.vdf = Some(proof);
        }

        checkpoint.validate_timestamp()?;
        checkpoint.hash = checkpoint.compute_hash();
        self.checkpoints.push(checkpoint);
        Ok(self.checkpoints.last().expect("just pushed").clone())
    }

    /// Acquire an exclusive advisory lock on the document file (non-blocking).
    #[cfg(unix)]
    fn acquire_lock(file: &fs::File) -> Result<()> {
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            return Err(Error::checkpoint(
                "concurrent commit: could not acquire file lock",
            ));
        }
        Ok(())
    }

    /// Release the advisory lock.
    #[cfg(unix)]
    fn release_lock(file: &fs::File) {
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_UN);
        }
    }

    /// Acquire an exclusive advisory lock on the document file (Windows).
    ///
    /// Uses `LockFileEx` with `LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY`
    /// to get a non-blocking exclusive byte-range lock, matching the Unix `flock`
    /// semantics on the other platform branch.
    #[cfg(not(unix))]
    fn acquire_lock(file: &fs::File) -> Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
        };
        use windows::Win32::System::IO::OVERLAPPED;

        let handle = HANDLE(file.as_raw_handle());
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        unsafe {
            LockFileEx(
                handle,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1, // lock 1 byte
                0,
                &mut overlapped,
            )
        }
        .map_err(|_| Error::checkpoint("concurrent commit: could not acquire file lock"))?;
        Ok(())
    }

    /// Release the advisory lock (Windows).
    #[cfg(not(unix))]
    fn release_lock(file: &fs::File) {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::UnlockFileEx;
        use windows::Win32::System::IO::OVERLAPPED;

        let handle = HANDLE(file.as_raw_handle());
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        let _ = unsafe { UnlockFileEx(handle, 0, 1, 0, &mut overlapped) };
    }

    /// Commit with entangled VDF (WAR/1.1): VDF input = f(prev_vdf_output, jitter, content).
    /// Prevents precomputation since each VDF depends on the previous VDF's actual output.
    pub fn commit_entangled(
        &mut self,
        message: Option<String>,
        jitter_hash: [u8; 32],
        jitter_session_id: String,
        keystroke_count: u64,
        vdf_duration: Duration,
        physics: Option<&crate::PhysicalContext>,
    ) -> Result<Checkpoint> {
        let lock_file = fs::File::open(&self.document_path)?;
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
        if self.entanglement_mode != EntanglementMode::Entangled {
            return Err(Error::invalid_state(
                "commit_entangled requires EntanglementMode::Entangled",
            ));
        }
        if jitter_session_id.is_empty() {
            return Err(Error::checkpoint("empty jitter_session_id"));
        }

        let (content_hash, content_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.document_path))?;
        let ordinal = u64::try_from(self.checkpoints.len())
            .map_err(|_| Error::checkpoint("checkpoint count exceeds u64"))?;

        let last_cp = self.checkpoints.last();
        let previous_hash = match last_cp {
            Some(cp) => cp.hash,
            None => genesis_prev_hash(content_hash, content_size, &self.document_path)?,
        };

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
        self.checkpoints.push(checkpoint);
        Ok(self.checkpoints.last().expect("just pushed").clone())
    }

    /// Commit with full RFC-compliant structures (draft-condrey-rats-pop-01).
    pub fn commit_rfc(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
        rfc_jitter: Option<rfc::JitterBinding>,
        time_evidence: Option<TimeEvidence>,
        calibration: rfc::CalibrationAttestation,
        physics: Option<&crate::PhysicalContext>,
    ) -> Result<Checkpoint> {
        let lock_file = fs::File::open(&self.document_path)?;
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
        if matches!(self.entanglement_mode, EntanglementMode::Entangled) && rfc_jitter.is_none() {
            return Err(Error::checkpoint("entangled mode requires jitter data"));
        }

        let (content_hash, content_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.document_path))?;
        let ordinal = u64::try_from(self.checkpoints.len())
            .map_err(|_| Error::checkpoint("checkpoint count exceeds u64"))?;

        let last_cp = self.checkpoints.last();
        let previous_hash = match last_cp {
            Some(cp) => cp.hash,
            None => genesis_prev_hash(content_hash, content_size, &self.document_path)?,
        };

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
            use super::types::{
                VDF_RFC_FIELD_SIZE, VDF_RFC_INPUT_END, VDF_RFC_INPUT_OFFSET, VDF_RFC_OUTPUT_END,
                VDF_RFC_OUTPUT_OFFSET,
            };
            let mut output = [0u8; VDF_RFC_FIELD_SIZE];
            output[VDF_RFC_OUTPUT_OFFSET..VDF_RFC_OUTPUT_END].copy_from_slice(&vdf.output);
            output[VDF_RFC_INPUT_OFFSET..VDF_RFC_INPUT_END].copy_from_slice(&vdf.input);

            // The `output` parameter is the concatenated Wesolowski-style format
            // (output[0..32] || input[0..32] = 64 bytes), not the raw 32-byte VDF output.
            // Layout is defined by the VDF_RFC_* constants in checkpoint/types.rs.
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

        // SWF seed derivation per draft-condrey-rats-pop
        let swf_seed = if ordinal == 0 {
            let doc_ref = DocumentRef {
                content_hash: HashValue::try_sha256(content_hash.to_vec())
                    .expect("content_hash is 32 bytes"),
                filename: std::path::Path::new(&self.document_path)
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
                .unwrap_or_else(|| content_hash);
            vdf::swf_seed_genesis(&doc_cbor, &jitter_or_nonce)
        } else if let Some(ref jb) = rfc_jitter {
            let intervals_cbor = cpop_protocol::codec::cbor::encode(&jb.summary.sample_count)
                .map_err(|e| Error::checkpoint(format!("SWF intervals CBOR: {e}")))?;
            // PhysicalContext isn't Serialize; use combined_hash as stand-in
            let phys_cbor = match physics {
                Some(p) => cpop_protocol::codec::cbor::encode(&p.combined_hash.to_vec())
                    .map_err(|e| Error::checkpoint(format!("SWF physics CBOR: {e}")))?,
                None => vec![],
            };
            vdf::swf_seed_enhanced(&previous_hash, &intervals_cbor, &phys_cbor)
        } else {
            vdf::swf_seed_core(&previous_hash, &content_hash)
        };

        // Argon2id SWF proof per draft-condrey-rats-pop (algorithm=20).
        // vdf_params.min_iterations reused as Argon2id time cost for simplicity;
        // dedicated parameter would be cleaner but not worth the breaking change.
        let argon2_swf = {
            let swf_params = vdf::swf_argon2::Argon2SwfParams {
                iterations: self.vdf_params.min_iterations.max(3),
                ..vdf::swf_argon2::Argon2SwfParams::default()
            };
            Some(
                vdf::swf_argon2::compute(swf_seed, swf_params)
                    .map_err(|e| Error::checkpoint(format!("Argon2id SWF: {e}")))?,
            )
        };

        let mut checkpoint =
            Checkpoint::new_base(ordinal, previous_hash, content_hash, content_size, message);
        checkpoint.vdf = vdf_proof;
        checkpoint.jitter_binding = jitter_binding;
        checkpoint.rfc_vdf = rfc_vdf;
        checkpoint.rfc_jitter = rfc_jitter;
        checkpoint.time_evidence = time_evidence;
        checkpoint.argon2_swf = argon2_swf;

        checkpoint.validate_timestamp()?;
        checkpoint.hash = checkpoint.compute_hash();
        self.checkpoints.push(checkpoint);
        Ok(self.checkpoints.last().expect("just pushed").clone())
    }

    /// Sum the minimum elapsed time across all VDF proofs in the chain.
    pub fn total_elapsed_time(&self) -> Duration {
        self.checkpoints
            .iter()
            .filter_map(|cp| cp.vdf.as_ref())
            .map(|v| v.min_elapsed_time(self.vdf_params))
            .fold(Duration::from_secs(0), |acc, v| acc + v)
    }

    /// Generate a human-readable summary of the chain state.
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

    /// Persist the chain to disk using atomic tmp+rename.
    pub fn save(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        self.storage_path = Some(path.to_path_buf());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::checkpoint(format!("failed to marshal chain: {e}")))?;
        // Atomic write: tmp + fsync + rename to avoid corrupt chain on crash
        let rand_suffix: String = format!("{:016x}", rand::random::<u64>());
        let tmp_name = format!(
            "{}.{}.tmp",
            path.display(),
            &rand_suffix[..8.min(rand_suffix.len())]
        );
        let tmp_path = PathBuf::from(tmp_name);
        fs::write(&tmp_path, &data)?;
        // H-015: fsync before rename to ensure data is durable on disk
        fs::File::open(&tmp_path)?.sync_all()?;
        fs::rename(&tmp_path, path)?;
        // L-009: fsync parent directory to ensure rename is durable
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    /// Load and validate a chain from disk, rejecting tampered VDF proofs.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        // M-117: Reject excessively large chain files (>100 MB) before reading.
        let metadata = fs::metadata(path)?;
        const MAX_CHAIN_FILE_SIZE: u64 = 100 * 1024 * 1024;
        if metadata.len() > MAX_CHAIN_FILE_SIZE {
            return Err(Error::checkpoint(format!(
                "chain file too large: {} bytes (max {})",
                metadata.len(),
                MAX_CHAIN_FILE_SIZE
            )));
        }
        let data = fs::read(path)?;
        let mut chain: Chain = serde_json::from_slice(&data)
            .map_err(|e| Error::checkpoint(format!("failed to unmarshal chain: {e}")))?;
        if chain.checkpoints.len() > MAX_CHECKPOINTS {
            return Err(Error::checkpoint(format!(
                "checkpoint count {} exceeds maximum ({})",
                chain.checkpoints.len(),
                MAX_CHECKPOINTS
            )));
        }
        chain.storage_path = Some(path.to_path_buf());
        chain.validate_vdf_proofs()?;
        Ok(chain)
    }

    /// Locate the chain file for a document in the writersproof directory.
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

    /// Load an existing chain or create a new one for the given document.
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

    /// Return the most recent checkpoint, if any.
    pub fn latest(&self) -> Option<&Checkpoint> {
        self.checkpoints.last()
    }

    /// Return the checkpoint at the given ordinal, or error if out of range.
    pub fn at(&self, ordinal: u64) -> Result<&Checkpoint> {
        let index = usize::try_from(ordinal)
            .map_err(|_| Error::checkpoint("ordinal too large for this platform"))?;
        self.checkpoints
            .get(index)
            .ok_or_else(|| Error::not_found(format!("checkpoint ordinal {ordinal} out of range")))
    }

    /// Return the filesystem path where this chain is persisted, if set.
    pub fn storage_path(&self) -> Option<&Path> {
        self.storage_path.as_deref()
    }

    /// Override the storage path for subsequent `save` calls.
    pub fn set_storage_path(&mut self, path: PathBuf) {
        self.storage_path = Some(path);
    }
}
