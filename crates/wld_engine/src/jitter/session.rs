// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Jitter chain (Layer 4a) - Go parity.
//!
//! Contains the core jitter session types: `Parameters`, `Sample`, `Session`,
//! `Evidence`, `Statistics`, and `SessionData`, plus the seeded
//! `compute_jitter_value()` HMAC function.

use crate::error::Error;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::timestamp_nanos_u64;

pub(crate) const MIN_JITTER: u32 = 500; // microseconds
pub(crate) const MAX_JITTER: u32 = 3000; // microseconds
pub(crate) const JITTER_RANGE: u32 = MAX_JITTER - MIN_JITTER;
pub(crate) const INTERVAL_BUCKET_SIZE_MS: i64 = 50;
pub(crate) const NUM_INTERVAL_BUCKETS: i64 = 10;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Parameters {
    pub min_jitter_micros: u32,
    pub max_jitter_micros: u32,
    pub sample_interval: u64,
    pub inject_enabled: bool,
}

pub fn default_parameters() -> Parameters {
    Parameters {
        min_jitter_micros: 500,
        max_jitter_micros: 3000,
        sample_interval: 50,
        inject_enabled: true,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub timestamp: DateTime<Utc>,
    pub keystroke_count: u64,
    pub document_hash: [u8; 32],
    pub jitter_micros: u32,
    pub hash: [u8; 32],
    pub previous_hash: [u8; 32],
}

impl Sample {
    pub(super) fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-jitter-sample-v1");
        hasher.update(timestamp_nanos_u64(self.timestamp).to_be_bytes());
        hasher.update(self.keystroke_count.to_be_bytes());
        hasher.update(self.document_hash);
        hasher.update(self.jitter_micros.to_be_bytes());
        hasher.update(self.previous_hash);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub document_path: String,
    #[serde(skip)]
    pub(crate) seed: [u8; 32],
    pub params: Parameters,
    pub samples: Vec<Sample>,
    keystroke_count: u64,
    last_jitter: u32,
    #[serde(skip)]
    last_mtime: Option<SystemTime>,
    #[serde(skip)]
    last_size: Option<u64>,
    #[serde(skip)]
    last_doc_hash: Option<[u8; 32]>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl Session {
    pub fn new(document_path: impl AsRef<Path>, params: Parameters) -> crate::error::Result<Self> {
        if params.sample_interval == 0 {
            return Err(Error::validation("sample_interval must be > 0"));
        }
        let abs_path = fs::canonicalize(document_path.as_ref())
            .map_err(|e| Error::validation(format!("invalid document path: {e}")))?;

        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        Ok(Self {
            id: hex::encode(rand::random::<[u8; 8]>()),
            started_at: Utc::now(),
            ended_at: None,
            document_path: abs_path.to_string_lossy().to_string(),
            seed,
            params,
            samples: Vec::new(),
            keystroke_count: 0,
            last_jitter: 0,
            last_mtime: None,
            last_size: None,
            last_doc_hash: None,
        })
    }

    pub fn new_with_id(
        document_path: impl AsRef<Path>,
        params: Parameters,
        session_id: impl Into<String>,
    ) -> crate::error::Result<Self> {
        if params.sample_interval == 0 {
            return Err(Error::validation("sample_interval must be > 0"));
        }
        let abs_path = fs::canonicalize(document_path.as_ref())
            .map_err(|e| Error::validation(format!("invalid document path: {e}")))?;

        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);

        Ok(Self {
            id: session_id.into(),
            started_at: Utc::now(),
            ended_at: None,
            document_path: abs_path.to_string_lossy().to_string(),
            seed,
            params,
            samples: Vec::new(),
            keystroke_count: 0,
            last_jitter: 0,
            last_mtime: None,
            last_size: None,
            last_doc_hash: None,
        })
    }

    pub fn record_keystroke(&mut self) -> crate::error::Result<(u32, bool)> {
        self.keystroke_count = self.keystroke_count.saturating_add(1);
        if !self
            .keystroke_count
            .checked_rem(self.params.sample_interval)
            .is_some_and(|r| r == 0)
        {
            return Ok((0, false));
        }

        let doc_hash = self.hash_document()?;
        let now = Utc::now();
        let previous_hash = self.samples.last().map(|s| s.hash).unwrap_or([0u8; 32]);
        let jitter = compute_jitter_value(
            &self.seed,
            doc_hash,
            self.keystroke_count,
            now,
            previous_hash,
            self.params,
        );

        let mut sample = Sample {
            timestamp: now,
            keystroke_count: self.keystroke_count,
            document_hash: doc_hash,
            jitter_micros: jitter,
            hash: [0u8; 32],
            previous_hash,
        };
        sample.hash = sample.compute_hash();

        self.samples.push(sample);
        self.last_jitter = jitter;

        Ok((jitter, true))
    }

    pub fn end(&mut self) {
        self.ended_at = Some(Utc::now());
    }

    pub fn keystroke_count(&self) -> u64 {
        self.keystroke_count
    }

    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    pub fn duration(&self) -> Duration {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        end.signed_duration_since(self.started_at)
            .to_std()
            .unwrap_or(Duration::from_secs(0))
    }

    pub fn export(&self) -> Evidence {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        let mut evidence = Evidence {
            session_id: self.id.clone(),
            started_at: self.started_at,
            ended_at: end,
            document_path: self.document_path.clone(),
            params: self.params,
            samples: self.samples.clone(),
            statistics: Statistics::default(),
        };
        evidence.statistics = self.compute_stats();
        evidence
    }

    #[allow(clippy::field_reassign_with_default)]
    fn compute_stats(&self) -> Statistics {
        let mut stats = Statistics::default();
        stats.total_keystrokes = self.keystroke_count;
        stats.total_samples = self.samples.len().min(i32::MAX as usize) as i32;

        let end = self.ended_at.unwrap_or_else(Utc::now);
        stats.duration = end
            .signed_duration_since(self.started_at)
            .to_std()
            .unwrap_or(Duration::from_secs(0));

        if stats.duration.as_secs_f64() > 0.0 {
            let minutes = stats.duration.as_secs_f64() / 60.0;
            if minutes > 0.0 {
                stats.keystrokes_per_min = self.keystroke_count as f64 / minutes;
            }
        }

        let mut seen = std::collections::HashSet::new();
        for sample in &self.samples {
            seen.insert(sample.document_hash);
        }
        stats.unique_doc_hashes = seen.len().min(i32::MAX as usize) as i32;
        stats.chain_valid = self.verify_chain().is_ok();

        stats
    }

    pub(crate) fn verify_chain(&self) -> crate::error::Result<()> {
        for (i, sample) in self.samples.iter().enumerate() {
            if sample.compute_hash().ct_eq(&sample.hash).unwrap_u8() == 0 {
                return Err(Error::validation(format!("sample {i}: hash mismatch")));
            }
            if i > 0 {
                if sample
                    .previous_hash
                    .ct_eq(&self.samples[i - 1].hash)
                    .unwrap_u8()
                    == 0
                {
                    return Err(Error::validation(format!("sample {i}: broken chain link")));
                }
            } else if sample.previous_hash.ct_eq(&[0u8; 32]).unwrap_u8() == 0 {
                return Err(Error::validation("sample 0: non-zero previous hash"));
            }
        }
        Ok(())
    }

    pub fn save(&self, path: impl AsRef<Path>) -> crate::error::Result<()> {
        let mut data = SessionData {
            id: self.id.clone(),
            started_at: self.started_at,
            ended_at: self.ended_at,
            document_path: self.document_path.clone(),
            seed: hex::encode(self.seed),
            params: self.params,
            samples: self.samples.clone(),
            keystroke_count: self.keystroke_count,
            last_jitter: self.last_jitter,
        };

        let mut bytes =
            serde_json::to_vec_pretty(&data).map_err(|e| Error::validation(e.to_string()))?;
        data.seed.zeroize();

        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).map_err(|e| Error::validation(e.to_string()))?;
        }

        // Atomic write: write to .tmp then rename for crash safety
        let tmp_path = path.as_ref().with_extension("tmp");
        let write_result = fs::write(&tmp_path, &bytes);
        bytes.zeroize();
        write_result.map_err(|e| Error::validation(e.to_string()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&tmp_path, perms)
                .map_err(|e| Error::validation(e.to_string()))?;
        }

        fs::rename(&tmp_path, path.as_ref()).map_err(|e| Error::validation(e.to_string()))?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> crate::error::Result<Self> {
        let bytes = fs::read(path).map_err(|e| Error::validation(e.to_string()))?;
        let mut data: SessionData =
            serde_json::from_slice(&bytes).map_err(|e| Error::validation(e.to_string()))?;
        let mut seed_bytes =
            hex::decode(&data.seed).map_err(|e| Error::validation(e.to_string()))?;
        data.seed.zeroize();
        if seed_bytes.len() != 32 {
            seed_bytes.zeroize();
            return Err(Error::validation("seed must be 32 bytes"));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        seed_bytes.zeroize();

        Ok(Self {
            id: data.id,
            started_at: data.started_at,
            ended_at: data.ended_at,
            document_path: data.document_path,
            seed,
            params: data.params,
            samples: data.samples,
            keystroke_count: data.keystroke_count,
            last_jitter: data.last_jitter,
            last_mtime: None,
            last_size: None,
            last_doc_hash: None,
        })
    }

    fn hash_document(&mut self) -> crate::error::Result<[u8; 32]> {
        let metadata =
            fs::metadata(&self.document_path).map_err(|e| Error::validation(e.to_string()))?;
        let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let size = metadata.len();

        if let (Some(last_mtime), Some(last_size), Some(last_hash)) =
            (self.last_mtime, self.last_size, self.last_doc_hash)
        {
            if mtime == last_mtime && size == last_size {
                return Ok(last_hash);
            }
        }

        // Use hash_file_with_size to get hash and actual byte count from the
        // same read pass, avoiding TOCTOU between metadata and hash.
        let (hash, actual_size) =
            crate::crypto::hash_file_with_size(Path::new(&self.document_path))
                .map_err(|e| Error::validation(e.to_string()))?;

        self.last_mtime = Some(mtime);
        self.last_size = Some(actual_size);
        self.last_doc_hash = Some(hash);

        Ok(hash)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub document_path: String,
    pub params: Parameters,
    pub samples: Vec<Sample>,
    pub statistics: Statistics,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Statistics {
    pub total_keystrokes: u64,
    pub total_samples: i32,
    pub duration: Duration,
    pub keystrokes_per_min: f64,
    pub unique_doc_hashes: i32,
    pub chain_valid: bool,
}

impl Evidence {
    pub fn verify(&self) -> crate::error::Result<()> {
        for (i, sample) in self.samples.iter().enumerate() {
            if sample.compute_hash().ct_eq(&sample.hash).unwrap_u8() == 0 {
                return Err(Error::validation(format!("sample {i}: hash mismatch")));
            }
            if i > 0 {
                if sample
                    .previous_hash
                    .ct_eq(&self.samples[i - 1].hash)
                    .unwrap_u8()
                    == 0
                {
                    return Err(Error::validation(format!("sample {i}: broken chain link")));
                }
            } else if sample.previous_hash.ct_eq(&[0u8; 32]).unwrap_u8() == 0 {
                return Err(Error::validation("sample 0: non-zero previous hash"));
            }
            if i > 0 && sample.timestamp <= self.samples[i - 1].timestamp {
                return Err(Error::validation(format!(
                    "sample {i}: timestamp not monotonic"
                )));
            }
            if i > 0 && sample.keystroke_count <= self.samples[i - 1].keystroke_count {
                return Err(Error::validation(format!(
                    "sample {i}: keystroke count not monotonic"
                )));
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> crate::error::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| Error::validation(e.to_string()))
    }

    pub fn decode(data: &[u8]) -> crate::error::Result<Evidence> {
        serde_json::from_slice(data).map_err(|e| Error::validation(e.to_string()))
    }

    pub fn typing_rate(&self) -> f64 {
        if self.statistics.duration.as_secs_f64() > 0.0 {
            self.statistics.total_keystrokes as f64
                / (self.statistics.duration.as_secs_f64() / 60.0)
        } else {
            0.0
        }
    }

    pub fn document_evolution(&self) -> i32 {
        self.statistics.unique_doc_hashes
    }

    pub fn is_plausible_human_typing(&self) -> bool {
        let rate = self.typing_rate();
        if rate < 10.0 && self.statistics.total_keystrokes > 100 {
            return false;
        }
        if rate > 1000.0 {
            return false;
        }
        if self.statistics.unique_doc_hashes < 2 && self.statistics.total_keystrokes > 500 {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub document_path: String,
    pub(crate) seed: String,
    pub params: Parameters,
    pub samples: Vec<Sample>,
    pub keystroke_count: u64,
    pub last_jitter: u32,
}

pub(super) fn compute_jitter_value(
    seed: &[u8],
    doc_hash: [u8; 32],
    keystroke_count: u64,
    timestamp: DateTime<Utc>,
    prev_jitter: [u8; 32],
    params: Parameters,
) -> u32 {
    let mut mac = Hmac::<Sha256>::new_from_slice(seed).expect("hmac key");
    mac.update(&doc_hash);
    mac.update(&keystroke_count.to_be_bytes());
    mac.update(&timestamp_nanos_u64(timestamp).to_be_bytes());
    mac.update(&prev_jitter);

    let hash = mac.finalize().into_bytes();
    let raw = u32::from_be_bytes(hash[0..4].try_into().unwrap());
    let jitter_range = params
        .max_jitter_micros
        .saturating_sub(params.min_jitter_micros);
    if jitter_range == 0 {
        return params.min_jitter_micros;
    }
    params.min_jitter_micros + (raw % jitter_range)
}
