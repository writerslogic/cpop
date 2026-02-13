use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

// =============================================================================
// Simple jitter session (legacy capture used by platform hooks)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleJitterSample {
    pub timestamp_ns: i64,
    pub duration_since_last_ns: u64,
    pub zone: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleJitterSession {
    pub id: String,
    pub start_time: DateTime<Utc>,
    pub samples: Vec<SimpleJitterSample>,
}

impl Default for SimpleJitterSession {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleJitterSession {
    pub fn new() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            start_time: Utc::now(),
            samples: Vec::new(),
        }
    }

    pub fn add_sample(&mut self, timestamp_ns: i64, zone: u8) {
        let last_ts = self
            .samples
            .last()
            .map(|s| s.timestamp_ns)
            .unwrap_or(self.start_time.timestamp_nanos_opt().unwrap_or(0));
        let duration = if timestamp_ns > last_ts {
            (timestamp_ns - last_ts) as u64
        } else {
            0
        };

        self.samples.push(SimpleJitterSample {
            timestamp_ns,
            duration_since_last_ns: duration,
            zone,
        });
    }
}

// =============================================================================
// Jitter chain (Layer 4a) - Go parity
// =============================================================================

const MIN_JITTER: u32 = 500; // microseconds
const MAX_JITTER: u32 = 3000; // microseconds
const JITTER_RANGE: u32 = MAX_JITTER - MIN_JITTER;
const INTERVAL_BUCKET_SIZE_MS: i64 = 50;
const NUM_INTERVAL_BUCKETS: i64 = 10;

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
    fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-jitter-sample-v1");
        hasher.update(
            self.timestamp
                .timestamp_nanos_opt()
                .unwrap_or(0)
                .to_be_bytes(),
        );
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
    seed: [u8; 32],
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

impl Session {
    pub fn new(document_path: impl AsRef<Path>, params: Parameters) -> Result<Self, String> {
        if params.sample_interval == 0 {
            return Err("sample_interval must be > 0".to_string());
        }
        let abs_path = fs::canonicalize(document_path.as_ref())
            .map_err(|e| format!("invalid document path: {e}"))?;

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
    ) -> Result<Self, String> {
        if params.sample_interval == 0 {
            return Err("sample_interval must be > 0".to_string());
        }
        let abs_path = fs::canonicalize(document_path.as_ref())
            .map_err(|e| format!("invalid document path: {e}"))?;

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

    pub fn record_keystroke(&mut self) -> Result<(u32, bool), String> {
        self.keystroke_count += 1;
        if !self
            .keystroke_count
            .is_multiple_of(self.params.sample_interval)
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
        stats.total_samples = self.samples.len() as i32;

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
        stats.unique_doc_hashes = seen.len() as i32;
        stats.chain_valid = self.verify_chain().is_ok();

        stats
    }

    fn verify_chain(&self) -> Result<(), String> {
        for (i, sample) in self.samples.iter().enumerate() {
            if sample.compute_hash() != sample.hash {
                return Err(format!("sample {i}: hash mismatch"));
            }
            if i > 0 {
                if sample.previous_hash != self.samples[i - 1].hash {
                    return Err(format!("sample {i}: broken chain link"));
                }
            } else if sample.previous_hash != [0u8; 32] {
                return Err("sample 0: non-zero previous hash".to_string());
            }
        }
        Ok(())
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let data = SessionData {
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

        let bytes = serde_json::to_vec_pretty(&data).map_err(|e| e.to_string())?;
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(path, bytes).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        let data: SessionData = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let seed_bytes = hex::decode(data.seed).map_err(|e| e.to_string())?;
        if seed_bytes.len() != 32 {
            return Err("seed must be 32 bytes".to_string());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

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

    fn hash_document(&mut self) -> Result<[u8; 32], String> {
        let metadata = fs::metadata(&self.document_path).map_err(|e| e.to_string())?;
        let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let size = metadata.len();

        if let (Some(last_mtime), Some(last_size), Some(last_hash)) =
            (self.last_mtime, self.last_size, self.last_doc_hash)
        {
            if mtime == last_mtime && size == last_size {
                return Ok(last_hash);
            }
        }

        let content = fs::read(&self.document_path).map_err(|e| e.to_string())?;
        let hash: [u8; 32] = Sha256::digest(&content).into();

        self.last_mtime = Some(mtime);
        self.last_size = Some(size);
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
    pub fn verify(&self) -> Result<(), String> {
        for (i, sample) in self.samples.iter().enumerate() {
            if sample.compute_hash() != sample.hash {
                return Err(format!("sample {i}: hash mismatch"));
            }
            if i > 0 {
                if sample.previous_hash != self.samples[i - 1].hash {
                    return Err(format!("sample {i}: broken chain link"));
                }
            } else if sample.previous_hash != [0u8; 32] {
                return Err("sample 0: non-zero previous hash".to_string());
            }
            if i > 0 && sample.timestamp <= self.samples[i - 1].timestamp {
                return Err(format!("sample {i}: timestamp not monotonic"));
            }
            if i > 0 && sample.keystroke_count <= self.samples[i - 1].keystroke_count {
                return Err(format!("sample {i}: keystroke count not monotonic"));
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec_pretty(self).map_err(|e| e.to_string())
    }

    pub fn decode(data: &[u8]) -> Result<Evidence, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
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
    pub seed: String,
    pub params: Parameters,
    pub samples: Vec<Sample>,
    pub keystroke_count: u64,
    pub last_jitter: u32,
}

// =============================================================================
// Verification helpers (seeded chain)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub samples_verified: i32,
    pub errors: Vec<String>,
}

pub fn verify_chain(samples: &[Sample], seed: &[u8], params: Parameters) -> Result<(), String> {
    if samples.is_empty() {
        return Err("empty sample chain".to_string());
    }
    if seed.is_empty() {
        return Err("seed is nil or empty".to_string());
    }

    for (i, sample) in samples.iter().enumerate() {
        let prev = if i > 0 { Some(&samples[i - 1]) } else { None };
        verify_sample(sample, prev, seed, params).map_err(|e| format!("sample {i}: {e}"))?;
    }

    Ok(())
}

pub fn verify_sample(
    sample: &Sample,
    prev_sample: Option<&Sample>,
    seed: &[u8],
    params: Parameters,
) -> Result<(), String> {
    if seed.is_empty() {
        return Err("seed is nil or empty".to_string());
    }

    if sample.compute_hash() != sample.hash {
        return Err("sample hash mismatch".to_string());
    }

    if let Some(prev) = prev_sample {
        if sample.previous_hash != prev.hash {
            return Err("chain link broken".to_string());
        }
        if sample.timestamp <= prev.timestamp {
            return Err("timestamp not monotonically increasing".to_string());
        }
        if sample.keystroke_count <= prev.keystroke_count {
            return Err("keystroke count not monotonically increasing".to_string());
        }
    } else if sample.previous_hash != [0u8; 32] {
        return Err("first sample has non-zero previous hash".to_string());
    }

    let prev_jitter = prev_sample.map(|p| p.hash).unwrap_or([0u8; 32]);
    let expected = compute_jitter_value(
        seed,
        sample.document_hash,
        sample.keystroke_count,
        sample.timestamp,
        prev_jitter,
        params,
    );
    if expected != sample.jitter_micros {
        return Err("jitter value mismatch".to_string());
    }

    Ok(())
}

pub fn verify_chain_detailed(
    samples: &[Sample],
    seed: &[u8],
    params: Parameters,
) -> VerificationResult {
    let mut result = VerificationResult {
        valid: true,
        samples_verified: 0,
        errors: Vec::new(),
    };

    if samples.is_empty() {
        result.valid = false;
        result.errors.push("empty sample chain".to_string());
        return result;
    }
    if seed.is_empty() {
        result.valid = false;
        result.errors.push("seed is nil or empty".to_string());
        return result;
    }

    for (i, sample) in samples.iter().enumerate() {
        let prev = if i > 0 { Some(&samples[i - 1]) } else { None };
        if let Err(err) = verify_sample(sample, prev, seed, params) {
            result.valid = false;
            result.errors.push(format!("sample {i}: {err}"));
        } else {
            result.samples_verified += 1;
        }
    }

    result
}

pub fn verify_chain_with_seed(
    samples: &[Sample],
    seed: [u8; 32],
    params: Parameters,
) -> Result<(), String> {
    verify_chain(samples, &seed, params)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainData {
    pub version: i32,
    pub params: Parameters,
    pub samples: Vec<Sample>,
    pub created_at: DateTime<Utc>,
}

pub fn encode_chain(samples: &[Sample], params: Parameters) -> Result<Vec<u8>, String> {
    let data = ChainData {
        version: 1,
        params,
        samples: samples.to_vec(),
        created_at: Utc::now(),
    };
    serde_json::to_vec(&data).map_err(|e| e.to_string())
}

pub fn decode_chain(data: &[u8]) -> Result<(Vec<Sample>, Parameters), String> {
    let chain: ChainData = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    if chain.version != 1 {
        return Err(format!("unsupported chain version: {}", chain.version));
    }
    Ok((chain.samples, chain.params))
}

pub fn encode_sample_binary(sample: &Sample) -> Vec<u8> {
    let mut buf = vec![0u8; 116];
    let mut offset = 0usize;

    buf[offset..offset + 8].copy_from_slice(
        &(sample.timestamp.timestamp_nanos_opt().unwrap_or(0) as u64).to_be_bytes(),
    );
    offset += 8;
    buf[offset..offset + 8].copy_from_slice(&sample.keystroke_count.to_be_bytes());
    offset += 8;
    buf[offset..offset + 32].copy_from_slice(&sample.document_hash);
    offset += 32;
    buf[offset..offset + 4].copy_from_slice(&sample.jitter_micros.to_be_bytes());
    offset += 4;
    buf[offset..offset + 32].copy_from_slice(&sample.hash);
    offset += 32;
    buf[offset..offset + 32].copy_from_slice(&sample.previous_hash);

    buf
}

pub fn decode_sample_binary(data: &[u8]) -> Result<Sample, String> {
    if data.len() != 116 {
        return Err(format!(
            "invalid sample data length: expected 116, got {}",
            data.len()
        ));
    }

    let mut offset = 0usize;
    let timestamp_nanos = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let keystroke_count = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let mut document_hash = [0u8; 32];
    document_hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let jitter_micros = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let mut previous_hash = [0u8; 32];
    previous_hash.copy_from_slice(&data[offset..offset + 32]);

    Ok(Sample {
        timestamp: DateTime::<Utc>::from(
            SystemTime::UNIX_EPOCH + Duration::from_nanos(timestamp_nanos),
        ),
        keystroke_count,
        document_hash,
        jitter_micros,
        hash,
        previous_hash,
    })
}

pub fn encode_chain_binary(samples: &[Sample], params: Parameters) -> Result<Vec<u8>, String> {
    let header_size = 1 + 13 + 4;
    let total_size = header_size + samples.len() * 116;
    let mut buf = vec![0u8; total_size];
    let mut offset = 0usize;

    buf[offset] = 1;
    offset += 1;
    buf[offset..offset + 4].copy_from_slice(&params.min_jitter_micros.to_be_bytes());
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&params.max_jitter_micros.to_be_bytes());
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&(params.sample_interval as u32).to_be_bytes());
    offset += 4;
    buf[offset] = if params.inject_enabled { 1 } else { 0 };
    offset += 1;
    buf[offset..offset + 4].copy_from_slice(&(samples.len() as u32).to_be_bytes());
    offset += 4;

    for sample in samples {
        let bytes = encode_sample_binary(sample);
        buf[offset..offset + 116].copy_from_slice(&bytes);
        offset += 116;
    }

    Ok(buf)
}

pub fn decode_chain_binary(data: &[u8]) -> Result<(Vec<Sample>, Parameters), String> {
    if data.len() < 18 {
        return Err("data too short for chain header".to_string());
    }

    let mut offset = 0usize;
    let version = data[offset];
    if version != 1 {
        return Err(format!("unsupported chain version: {version}"));
    }
    offset += 1;

    let min_jitter_micros = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let max_jitter_micros = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let sample_interval = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as u64;
    offset += 4;
    let inject_enabled = data[offset] == 1;
    offset += 1;

    let sample_count = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;

    let expected_len = 18 + sample_count * 116;
    if data.len() != expected_len {
        return Err(format!(
            "invalid data length: expected {expected_len}, got {}",
            data.len()
        ));
    }

    let mut samples = Vec::with_capacity(sample_count);
    for i in 0..sample_count {
        let start = offset + i * 116;
        let end = start + 116;
        let sample = decode_sample_binary(&data[start..end])
            .map_err(|e| format!("failed to decode sample {i}: {e}"))?;
        samples.push(sample);
    }

    Ok((
        samples,
        Parameters {
            min_jitter_micros,
            max_jitter_micros,
            sample_interval,
            inject_enabled,
        },
    ))
}

pub fn compare_chains(a: &[Sample], b: &[Sample]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if !compare_samples(&a[i], &b[i]) {
            return false;
        }
    }
    true
}

pub fn compare_samples(a: &Sample, b: &Sample) -> bool {
    a.timestamp == b.timestamp
        && a.keystroke_count == b.keystroke_count
        && a.document_hash == b.document_hash
        && a.jitter_micros == b.jitter_micros
        && a.hash == b.hash
        && a.previous_hash == b.previous_hash
}

pub fn find_chain_divergence(a: &[Sample], b: &[Sample]) -> i32 {
    let min_len = a.len().min(b.len());
    for i in 0..min_len {
        if !compare_samples(&a[i], &b[i]) {
            return i as i32;
        }
    }
    if a.len() != b.len() {
        return min_len as i32;
    }
    -1
}

pub fn extract_chain_hashes(samples: &[Sample]) -> Vec<[u8; 32]> {
    samples.iter().map(|s| s.hash).collect()
}

pub fn verify_chain_continuity(
    existing_samples: &[Sample],
    new_samples: &[Sample],
    seed: &[u8],
    params: Parameters,
) -> Result<(), String> {
    if new_samples.is_empty() {
        return Ok(());
    }
    if seed.is_empty() {
        return Err("seed is nil or empty".to_string());
    }

    let last_existing = existing_samples.last();
    if let Some(last) = last_existing {
        let first_new = &new_samples[0];
        if first_new.previous_hash != last.hash {
            return Err("new samples don't chain from existing".to_string());
        }
        if first_new.timestamp <= last.timestamp {
            return Err("timestamp not monotonically increasing".to_string());
        }
        if first_new.keystroke_count <= last.keystroke_count {
            return Err("keystroke count not monotonically increasing".to_string());
        }
    }

    for i in 0..new_samples.len() {
        let prev = if i > 0 {
            Some(&new_samples[i - 1])
        } else {
            last_existing
        };
        verify_sample(&new_samples[i], prev, seed, params)
            .map_err(|e| format!("new sample {i}: {e}"))?;
    }

    Ok(())
}

pub fn hash_chain_root(samples: &[Sample]) -> [u8; 32] {
    samples.last().map(|s| s.hash).unwrap_or([0u8; 32])
}

pub fn validate_sample_format(sample: &Sample) -> Result<(), String> {
    if sample.timestamp.timestamp() == 0 {
        return Err("timestamp is zero".to_string());
    }
    if sample.timestamp > Utc::now() + chrono::Duration::hours(24) {
        return Err("timestamp is in the future".to_string());
    }
    if sample.hash == [0u8; 32] {
        return Err("sample hash is zero".to_string());
    }
    Ok(())
}

pub fn marshal_sample_for_signing(sample: &Sample) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"witnessd-sample-v1\n");
    buf.extend_from_slice(
        &(sample.timestamp.timestamp_nanos_opt().unwrap_or(0) as u64).to_be_bytes(),
    );
    buf.extend_from_slice(&sample.keystroke_count.to_be_bytes());
    buf.extend_from_slice(&sample.document_hash);
    buf.extend_from_slice(&sample.jitter_micros.to_be_bytes());
    buf.extend_from_slice(&sample.previous_hash);
    buf.extend_from_slice(&sample.hash);
    buf
}

fn compute_jitter_value(
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
    mac.update(&(timestamp.timestamp_nanos_opt().unwrap_or(0) as u64).to_be_bytes());
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

// =============================================================================
// Zone-committed jitter engine
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterSample {
    pub ordinal: u64,
    pub timestamp: DateTime<Utc>,
    pub doc_hash: [u8; 32],
    pub zone_transition: u8,
    pub interval_bucket: u8,
    pub jitter_micros: u32,
    pub sample_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TypingProfile {
    pub same_finger_hist: [u32; 10],
    pub same_hand_hist: [u32; 10],
    pub alternating_hist: [u32; 10],
    pub hand_alternation: f32,
    pub total_transitions: u64,
    #[serde(skip)]
    alternating_count: u64,
}

pub struct JitterEngine {
    secret: [u8; 32],
    ordinal: u64,
    prev_jitter: u32,
    prev_zone: i32,
    prev_time: DateTime<Utc>,
    profile: TypingProfile,
}

impl JitterEngine {
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret,
            ordinal: 0,
            prev_jitter: 0,
            prev_zone: -1,
            prev_time: Utc::now(),
            profile: TypingProfile::default(),
        }
    }

    pub fn on_keystroke(
        &mut self,
        key_code: u16,
        doc_hash: [u8; 32],
    ) -> (u32, Option<JitterSample>) {
        let now = Utc::now();
        let zone = keycode_to_zone(key_code);
        if zone < 0 {
            return (0, None);
        }

        let mut zone_transition = 0xFF;
        let mut interval_bucket = 0u8;

        if self.prev_zone >= 0 {
            zone_transition = encode_zone_transition(self.prev_zone, zone);
            let interval = now.signed_duration_since(self.prev_time);
            interval_bucket =
                interval_to_bucket(interval.to_std().unwrap_or(Duration::from_secs(0)));
            self.update_profile(self.prev_zone, zone, interval_bucket);
        }

        let jitter = self.compute_jitter(doc_hash, zone_transition, interval_bucket, now);
        self.ordinal += 1;
        let mut sample = JitterSample {
            ordinal: self.ordinal,
            timestamp: now,
            doc_hash,
            zone_transition,
            interval_bucket,
            jitter_micros: jitter,
            sample_hash: [0u8; 32],
        };
        sample.sample_hash = compute_jitter_sample_hash(&sample);

        self.prev_zone = zone;
        self.prev_time = now;
        self.prev_jitter = jitter;

        (jitter, Some(sample))
    }

    pub fn profile(&self) -> TypingProfile {
        self.profile.clone()
    }

    fn compute_jitter(
        &self,
        doc_hash: [u8; 32],
        zone_transition: u8,
        interval_bucket: u8,
        timestamp: DateTime<Utc>,
    ) -> u32 {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).expect("hmac key");
        mac.update(&self.ordinal.to_be_bytes());
        mac.update(&doc_hash);
        mac.update(&(timestamp.timestamp_nanos_opt().unwrap_or(0) as u64).to_be_bytes());
        mac.update(&[zone_transition]);
        mac.update(&[interval_bucket]);
        mac.update(&self.prev_jitter.to_be_bytes());
        let hash = mac.finalize().into_bytes();
        let raw = u32::from_be_bytes(hash[0..4].try_into().unwrap());
        MIN_JITTER + (raw % JITTER_RANGE)
    }

    fn update_profile(&mut self, from_zone: i32, to_zone: i32, bucket: u8) {
        let trans = ZoneTransition {
            from: from_zone,
            to: to_zone,
        };
        if trans.is_same_finger() {
            self.profile.same_finger_hist[bucket as usize] += 1;
        } else if trans.is_same_hand() {
            self.profile.same_hand_hist[bucket as usize] += 1;
        } else {
            self.profile.alternating_hist[bucket as usize] += 1;
            self.profile.alternating_count += 1;
        }

        self.profile.total_transitions += 1;
        if self.profile.total_transitions > 0 {
            self.profile.hand_alternation =
                self.profile.alternating_count as f32 / self.profile.total_transitions as f32;
        }
    }
}

pub fn interval_to_bucket(duration: Duration) -> u8 {
    let ms = duration.as_millis() as i64;
    let mut bucket = ms / INTERVAL_BUCKET_SIZE_MS;
    if bucket >= NUM_INTERVAL_BUCKETS {
        bucket = NUM_INTERVAL_BUCKETS - 1;
    }
    if bucket < 0 {
        bucket = 0;
    }
    bucket as u8
}

pub fn compare_profiles(a: TypingProfile, b: TypingProfile) -> f64 {
    if a.total_transitions == 0 || b.total_transitions == 0 {
        return 0.0;
    }

    let same_finger = histogram_cosine_similarity(&a.same_finger_hist, &b.same_finger_hist);
    let same_hand = histogram_cosine_similarity(&a.same_hand_hist, &b.same_hand_hist);
    let alternating = histogram_cosine_similarity(&a.alternating_hist, &b.alternating_hist);

    let hand_alt_diff = (a.hand_alternation - b.hand_alternation).abs() as f64;
    let hand_alt_sim = 1.0 - hand_alt_diff;

    0.3 * same_finger + 0.3 * same_hand + 0.3 * alternating + 0.1 * hand_alt_sim
}

fn histogram_cosine_similarity(a: &[u32; 10], b: &[u32; 10]) -> f64 {
    let mut dot = 0.0;
    let mut norm_a = 0.0;
    let mut norm_b = 0.0;
    for i in 0..10 {
        let fa = a[i] as f64;
        let fb = b[i] as f64;
        dot += fa * fb;
        norm_a += fa * fa;
        norm_b += fb * fb;
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    dot / (sqrt(norm_a) * sqrt(norm_b))
}

fn sqrt(x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut z = x / 2.0;
    for _ in 0..10 {
        z = z - (z * z - x) / (2.0 * z);
    }
    z
}

pub fn is_human_plausible(profile: TypingProfile) -> bool {
    if profile.total_transitions < 10 {
        return true;
    }

    if profile.hand_alternation < 0.15 || profile.hand_alternation > 0.85 {
        return false;
    }

    let mut same_finger_total = 0u64;
    let mut same_hand_total = 0u64;
    let mut alternating_total = 0u64;
    for i in 0..10 {
        same_finger_total += profile.same_finger_hist[i] as u64;
        same_hand_total += profile.same_hand_hist[i] as u64;
        alternating_total += profile.alternating_hist[i] as u64;
    }

    let total = same_finger_total + same_hand_total + alternating_total;
    if total == 0 {
        return true;
    }

    let same_finger_ratio = same_finger_total as f64 / total as f64;
    if same_finger_ratio > 0.30 {
        return false;
    }

    let mut non_zero = 0;
    for i in 0..10 {
        if profile.same_finger_hist[i] > 0
            || profile.same_hand_hist[i] > 0
            || profile.alternating_hist[i] > 0
        {
            non_zero += 1;
        }
    }
    if non_zero < 3 && total > 100 {
        return false;
    }

    let max_bucket_pct = max_histogram_concentration(&profile);
    if max_bucket_pct > 0.80 && total > 50 {
        return false;
    }

    true
}

fn max_histogram_concentration(profile: &TypingProfile) -> f64 {
    let mut total = 0u64;
    let mut max_bucket = 0u64;
    for i in 0..10 {
        let bucket_total = profile.same_finger_hist[i] as u64
            + profile.same_hand_hist[i] as u64
            + profile.alternating_hist[i] as u64;
        total += bucket_total;
        if bucket_total > max_bucket {
            max_bucket = bucket_total;
        }
    }
    if total == 0 {
        return 0.0;
    }
    max_bucket as f64 / total as f64
}

pub fn profile_distance(a: TypingProfile, b: TypingProfile) -> f64 {
    let a_norm = normalize_histograms(&a);
    let b_norm = normalize_histograms(&b);

    let mut sum = 0.0;
    for i in 0..10 {
        let diff = a_norm.same_finger[i] - b_norm.same_finger[i];
        sum += diff * diff;
    }
    for i in 0..10 {
        let diff = a_norm.same_hand[i] - b_norm.same_hand[i];
        sum += diff * diff;
    }
    for i in 0..10 {
        let diff = a_norm.alternating[i] - b_norm.alternating[i];
        sum += diff * diff;
    }

    let diff = a.hand_alternation as f64 - b.hand_alternation as f64;
    sum += diff * diff;

    sqrt(sum)
}

struct NormalizedProfile {
    same_finger: [f64; 10],
    same_hand: [f64; 10],
    alternating: [f64; 10],
}

fn normalize_histograms(profile: &TypingProfile) -> NormalizedProfile {
    let mut same_finger_total = 0u64;
    let mut same_hand_total = 0u64;
    let mut alternating_total = 0u64;
    for i in 0..10 {
        same_finger_total += profile.same_finger_hist[i] as u64;
        same_hand_total += profile.same_hand_hist[i] as u64;
        alternating_total += profile.alternating_hist[i] as u64;
    }

    let mut out = NormalizedProfile {
        same_finger: [0.0; 10],
        same_hand: [0.0; 10],
        alternating: [0.0; 10],
    };

    for i in 0..10 {
        if same_finger_total > 0 {
            out.same_finger[i] = profile.same_finger_hist[i] as f64 / same_finger_total as f64;
        }
        if same_hand_total > 0 {
            out.same_hand[i] = profile.same_hand_hist[i] as f64 / same_hand_total as f64;
        }
        if alternating_total > 0 {
            out.alternating[i] = profile.alternating_hist[i] as f64 / alternating_total as f64;
        }
    }

    out
}

pub fn quick_verify_profile(profile: TypingProfile) -> Vec<String> {
    let mut issues = Vec::new();
    if !is_human_plausible(profile.clone()) {
        issues.push("profile fails human plausibility check".to_string());
    }
    if profile.total_transitions > 50 {
        if profile.hand_alternation < 0.25 {
            issues.push("hand alternation too low (< 25%)".to_string());
        }
        if profile.hand_alternation > 0.75 {
            issues.push("hand alternation too high (> 75%)".to_string());
        }
    }

    let bucket0 = profile.same_finger_hist[0] as u64
        + profile.same_hand_hist[0] as u64
        + profile.alternating_hist[0] as u64;
    if profile.total_transitions > 0 && bucket0 == profile.total_transitions {
        issues.push("all transitions in fastest bucket (robotic timing)".to_string());
    }

    issues
}

// =============================================================================
// Zone-committed verification
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentVerificationResult {
    pub valid: bool,
    pub chain_valid: bool,
    pub zones_compatible: bool,
    pub profile_plausible: bool,
    pub zone_divergence: f64,
    pub transition_divergence: f64,
    pub profile_score: f64,
    pub recorded_profile: TypingProfile,
    pub expected_profile: TypingProfile,
    pub recorded_transitions: ZoneTransitionHistogram,
    pub expected_transitions: ZoneTransitionHistogram,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn verify_with_content(samples: &[JitterSample], content: &[u8]) -> ContentVerificationResult {
    let mut result = ContentVerificationResult {
        valid: true,
        chain_valid: true,
        zones_compatible: false,
        profile_plausible: true,
        zone_divergence: 0.0,
        transition_divergence: 0.0,
        profile_score: 0.0,
        recorded_profile: TypingProfile::default(),
        expected_profile: TypingProfile::default(),
        recorded_transitions: ZoneTransitionHistogram::default(),
        expected_transitions: ZoneTransitionHistogram::default(),
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    if samples.is_empty() {
        result.valid = false;
        result.errors.push("no samples to verify".to_string());
        return result;
    }

    if let Err(err) = verify_jitter_chain(samples) {
        result.chain_valid = false;
        result.valid = false;
        result.errors.push(format!("chain integrity: {err}"));
    }

    let expected = analyze_document_zones(content);
    let recorded = extract_recorded_zones(samples);

    result.expected_profile = expected.clone();
    result.recorded_profile = recorded.clone();
    result.zone_divergence = zone_kl_divergence(expected.clone(), recorded.clone());

    result.expected_transitions = expected_transition_histogram(content);
    result.recorded_transitions = extract_transition_histogram(samples);
    result.transition_divergence =
        transition_histogram_divergence(result.expected_transitions, result.recorded_transitions);

    if result.transition_divergence > 0.3 {
        result.zones_compatible = false;
        result.warnings.push(format!(
            "zone transition divergence {:.4} exceeds threshold 0.3",
            result.transition_divergence
        ));
    } else {
        result.zones_compatible = true;
    }

    result.profile_plausible = is_human_plausible(recorded.clone());
    if !result.profile_plausible {
        result
            .warnings
            .push("typing profile does not appear human-plausible".to_string());
    }

    result.profile_score = compare_profiles(expected, recorded);
    result.valid = result.chain_valid && result.zones_compatible;
    result
}

pub fn verify_with_secret(samples: &[JitterSample], secret: [u8; 32]) -> Result<(), String> {
    if samples.is_empty() {
        return Err("empty sample chain".to_string());
    }

    let mut engine = VerificationEngine {
        secret,
        ordinal: 0,
        prev_jitter: 0,
    };

    for (i, sample) in samples.iter().enumerate() {
        let expected = engine.compute_expected_jitter(
            sample.doc_hash,
            sample.zone_transition,
            sample.interval_bucket,
            sample.timestamp,
        );

        if sample.jitter_micros != expected {
            return Err(format!(
                "sample {i}: jitter mismatch (expected {expected}, got {})",
                sample.jitter_micros
            ));
        }

        let expected_hash = compute_jitter_sample_hash(sample);
        if sample.sample_hash != expected_hash {
            return Err(format!("sample {i}: hash mismatch"));
        }

        engine.prev_jitter = sample.jitter_micros;
        engine.ordinal += 1;
    }

    Ok(())
}

fn compute_jitter_sample_hash(sample: &JitterSample) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(sample.ordinal.to_be_bytes());
    hasher.update(
        sample
            .timestamp
            .timestamp_nanos_opt()
            .unwrap_or(0)
            .to_be_bytes(),
    );
    hasher.update(sample.doc_hash);
    hasher.update([sample.zone_transition, sample.interval_bucket]);
    hasher.update(sample.jitter_micros.to_be_bytes());
    hasher.finalize().into()
}

struct VerificationEngine {
    secret: [u8; 32],
    ordinal: u64,
    prev_jitter: u32,
}

impl VerificationEngine {
    fn compute_expected_jitter(
        &self,
        doc_hash: [u8; 32],
        zone_transition: u8,
        interval_bucket: u8,
        timestamp: DateTime<Utc>,
    ) -> u32 {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).expect("hmac key");
        mac.update(&self.ordinal.to_be_bytes());
        mac.update(&doc_hash);
        mac.update(&(timestamp.timestamp_nanos_opt().unwrap_or(0) as u64).to_be_bytes());
        mac.update(&[zone_transition]);
        mac.update(&[interval_bucket]);
        mac.update(&self.prev_jitter.to_be_bytes());
        let hash = mac.finalize().into_bytes();
        let raw = u32::from_be_bytes(hash[0..4].try_into().unwrap());
        MIN_JITTER + (raw % JITTER_RANGE)
    }
}

pub fn analyze_document_zones(content: &[u8]) -> TypingProfile {
    let transitions = text_to_zone_sequence(&String::from_utf8_lossy(content));
    let mut profile = TypingProfile::default();

    for trans in transitions {
        let bucket = 5u8;
        if trans.is_same_finger() {
            profile.same_finger_hist[bucket as usize] += 1;
        } else if trans.is_same_hand() {
            profile.same_hand_hist[bucket as usize] += 1;
        } else {
            profile.alternating_hist[bucket as usize] += 1;
            profile.alternating_count += 1;
        }
        profile.total_transitions += 1;
    }

    if profile.total_transitions > 0 {
        profile.hand_alternation =
            profile.alternating_count as f32 / profile.total_transitions as f32;
    }

    profile
}

pub fn extract_recorded_zones(samples: &[JitterSample]) -> TypingProfile {
    let mut profile = TypingProfile::default();

    for sample in samples {
        if sample.zone_transition == 0xFF {
            continue;
        }
        let (from, to) = decode_zone_transition(sample.zone_transition);
        let trans = ZoneTransition { from, to };
        let mut bucket = sample.interval_bucket;
        if bucket >= 10 {
            bucket = 9;
        }

        if trans.is_same_finger() {
            profile.same_finger_hist[bucket as usize] += 1;
        } else if trans.is_same_hand() {
            profile.same_hand_hist[bucket as usize] += 1;
        } else {
            profile.alternating_hist[bucket as usize] += 1;
            profile.alternating_count += 1;
        }
        profile.total_transitions += 1;
    }

    if profile.total_transitions > 0 {
        profile.hand_alternation =
            profile.alternating_count as f32 / profile.total_transitions as f32;
    }

    profile
}

pub fn zone_kl_divergence(expected: TypingProfile, recorded: TypingProfile) -> f64 {
    let mut exp_same_finger = 0u64;
    let mut exp_same_hand = 0u64;
    let mut exp_alternating = 0u64;
    let mut rec_same_finger = 0u64;
    let mut rec_same_hand = 0u64;
    let mut rec_alternating = 0u64;

    for i in 0..10 {
        exp_same_finger += expected.same_finger_hist[i] as u64;
        exp_same_hand += expected.same_hand_hist[i] as u64;
        exp_alternating += expected.alternating_hist[i] as u64;
        rec_same_finger += recorded.same_finger_hist[i] as u64;
        rec_same_hand += recorded.same_hand_hist[i] as u64;
        rec_alternating += recorded.alternating_hist[i] as u64;
    }

    let exp_total = (exp_same_finger + exp_same_hand + exp_alternating) as f64;
    let rec_total = (rec_same_finger + rec_same_hand + rec_alternating) as f64;

    if exp_total == 0.0 || rec_total == 0.0 {
        if exp_total == 0.0 && rec_total == 0.0 {
            return 0.0;
        }
        return 10.0;
    }

    let epsilon = 0.001;
    let exp = [
        (exp_same_finger as f64 + epsilon) / (exp_total + 3.0 * epsilon),
        (exp_same_hand as f64 + epsilon) / (exp_total + 3.0 * epsilon),
        (exp_alternating as f64 + epsilon) / (exp_total + 3.0 * epsilon),
    ];
    let rec = [
        (rec_same_finger as f64 + epsilon) / (rec_total + 3.0 * epsilon),
        (rec_same_hand as f64 + epsilon) / (rec_total + 3.0 * epsilon),
        (rec_alternating as f64 + epsilon) / (rec_total + 3.0 * epsilon),
    ];

    let mut kl = 0.0;
    for i in 0..3 {
        if rec[i] > 0.0 {
            kl += rec[i] * safe_log(rec[i] / exp[i]);
        }
    }

    kl
}

#[derive(Debug, Clone, Copy)]
pub struct ZoneTransitionHistogram(pub [u32; 64]);

impl Default for ZoneTransitionHistogram {
    fn default() -> Self {
        ZoneTransitionHistogram([0u32; 64])
    }
}

impl Serialize for ZoneTransitionHistogram {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ZoneTransitionHistogram {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = Vec::<u32>::deserialize(deserializer)?;
        if values.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 histogram entries, got {}",
                values.len()
            )));
        }
        let mut array = [0u32; 64];
        array.copy_from_slice(&values);
        Ok(ZoneTransitionHistogram(array))
    }
}

pub fn extract_transition_histogram(samples: &[JitterSample]) -> ZoneTransitionHistogram {
    let mut hist = [0u32; 64];
    for sample in samples {
        if sample.zone_transition != 0xFF {
            hist[sample.zone_transition as usize] += 1;
        }
    }
    ZoneTransitionHistogram(hist)
}

pub fn expected_transition_histogram(content: &[u8]) -> ZoneTransitionHistogram {
    let mut hist = [0u32; 64];
    for trans in text_to_zone_sequence(&String::from_utf8_lossy(content)) {
        let encoded = encode_zone_transition(trans.from, trans.to);
        if encoded != 0xFF {
            hist[encoded as usize] += 1;
        }
    }
    ZoneTransitionHistogram(hist)
}

pub fn transition_histogram_divergence(
    expected: ZoneTransitionHistogram,
    recorded: ZoneTransitionHistogram,
) -> f64 {
    let mut exp_total = 0.0;
    let mut rec_total = 0.0;
    for i in 0..64 {
        exp_total += expected.0[i] as f64;
        rec_total += recorded.0[i] as f64;
    }

    if exp_total == 0.0 || rec_total == 0.0 {
        return 10.0;
    }

    let epsilon = 0.001 / 64.0;
    let mut js = 0.0;
    for i in 0..64 {
        let p_exp = (expected.0[i] as f64 + epsilon) / (exp_total + epsilon * 64.0);
        let p_rec = (recorded.0[i] as f64 + epsilon) / (rec_total + epsilon * 64.0);
        let p_mid = (p_exp + p_rec) / 2.0;
        if p_exp > 0.0 {
            js += 0.5 * p_exp * safe_log(p_exp / p_mid);
        }
        if p_rec > 0.0 {
            js += 0.5 * p_rec * safe_log(p_rec / p_mid);
        }
    }

    js
}

fn safe_log(x: f64) -> f64 {
    if x <= 0.0 {
        -1e10
    } else {
        x.ln()
    }
}

pub fn verify_jitter_chain(samples: &[JitterSample]) -> Result<(), String> {
    if samples.is_empty() {
        return Err("empty sample chain".to_string());
    }

    for i in 0..samples.len() {
        let sample = &samples[i];
        let expected = compute_jitter_sample_hash(sample);
        if sample.sample_hash != expected {
            return Err(format!("sample {i}: sample hash mismatch"));
        }
        if i > 0 {
            if sample.timestamp <= samples[i - 1].timestamp {
                return Err(format!(
                    "sample {i}: timestamp not monotonically increasing"
                ));
            }
            if sample.ordinal <= samples[i - 1].ordinal {
                return Err(format!("sample {i}: ordinal not increasing"));
            }
        }
    }

    Ok(())
}

// =============================================================================
// Zones
// =============================================================================

pub fn keycode_to_zone(key_code: u16) -> i32 {
    match key_code {
        0x0C | 0x00 | 0x06 => 0,
        0x0D | 0x01 | 0x07 => 1,
        0x0E | 0x02 | 0x08 => 2,
        0x0F | 0x11 | 0x03 | 0x05 | 0x09 | 0x0B => 3,
        0x10 | 0x20 | 0x04 | 0x26 | 0x2D | 0x2E => 4,
        0x22 | 0x28 | 0x2B => 5,
        0x1F | 0x25 | 0x2F => 6,
        0x23 | 0x29 | 0x2C => 7,
        _ => -1,
    }
}

pub fn char_to_zone(c: char) -> i32 {
    match c {
        'q' | 'Q' | 'a' | 'A' | 'z' | 'Z' => 0,
        'w' | 'W' | 's' | 'S' | 'x' | 'X' => 1,
        'e' | 'E' | 'd' | 'D' | 'c' | 'C' => 2,
        'r' | 'R' | 't' | 'T' | 'f' | 'F' | 'g' | 'G' | 'v' | 'V' | 'b' | 'B' => 3,
        'y' | 'Y' | 'u' | 'U' | 'h' | 'H' | 'j' | 'J' | 'n' | 'N' | 'm' | 'M' => 4,
        'i' | 'I' | 'k' | 'K' | ',' | '<' => 5,
        'o' | 'O' | 'l' | 'L' | '.' | '>' => 6,
        'p' | 'P' | ';' | ':' | '/' | '?' => 7,
        _ => -1,
    }
}

pub fn encode_zone_transition(from: i32, to: i32) -> u8 {
    if !(0..=7).contains(&from) || !(0..=7).contains(&to) {
        return 0xFF;
    }
    ((from << 3) | to) as u8
}

pub fn decode_zone_transition(encoded: u8) -> (i32, i32) {
    let from = (encoded >> 3) as i32;
    let to = (encoded & 0x07) as i32;
    (from, to)
}

pub fn is_valid_zone_transition(encoded: u8) -> bool {
    encoded != 0xFF && (encoded >> 3) < 8
}

pub fn text_to_zone_sequence(text: &str) -> Vec<ZoneTransition> {
    let mut transitions = Vec::new();
    let mut prev_zone = -1;
    for c in text.chars() {
        let zone = char_to_zone(c);
        if zone >= 0 {
            if prev_zone >= 0 {
                transitions.push(ZoneTransition {
                    from: prev_zone,
                    to: zone,
                });
            }
            prev_zone = zone;
        }
    }
    transitions
}

#[derive(Debug, Clone, Copy)]
pub struct ZoneTransition {
    pub from: i32,
    pub to: i32,
}

impl ZoneTransition {
    pub fn is_same_finger(&self) -> bool {
        self.from == self.to
    }

    pub fn is_same_hand(&self) -> bool {
        (self.from < 4) == (self.to < 4)
    }

    pub fn is_alternating(&self) -> bool {
        !self.is_same_hand()
    }
}

#[cfg(test)]
#[allow(clippy::manual_range_contains)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn temp_document_path() -> PathBuf {
        let name = format!("witnessd-jitter-test-{}.txt", uuid::Uuid::new_v4());
        std::env::temp_dir().join(name)
    }

    fn test_params() -> Parameters {
        Parameters {
            min_jitter_micros: 500,
            max_jitter_micros: 3000,
            sample_interval: 1,
            inject_enabled: true,
        }
    }

    #[test]
    fn test_session_chain_and_roundtrip() {
        let path = temp_document_path();
        fs::write(&path, b"hello jitter").expect("write temp doc");

        let params = Parameters {
            min_jitter_micros: 500,
            max_jitter_micros: 3000,
            sample_interval: 1,
            inject_enabled: true,
        };

        let mut session = Session::new(&path, params).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }
        session.end();
        session.verify_chain().expect("verify chain");

        let evidence = session.export();
        evidence.verify().expect("evidence verify");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_sample_binary_roundtrip() {
        let path = temp_document_path();
        fs::write(&path, b"hello jitter").expect("write temp doc");

        let params = Parameters {
            min_jitter_micros: 500,
            max_jitter_micros: 3000,
            sample_interval: 1,
            inject_enabled: true,
        };
        let mut session = Session::new(&path, params).expect("session");
        session.record_keystroke().expect("keystroke");
        let sample = session.samples.first().expect("sample");

        let encoded = encode_sample_binary(sample);
        let decoded = decode_sample_binary(&encoded).expect("decode");
        assert_eq!(decoded.hash, sample.hash);
        assert_eq!(decoded.previous_hash, sample.previous_hash);
        assert_eq!(decoded.document_hash, sample.document_hash);
        assert_eq!(decoded.jitter_micros, sample.jitter_micros);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_verify_chain_with_seed() {
        let path = temp_document_path();
        fs::write(&path, b"hello jitter").expect("write temp doc");

        let params = Parameters {
            min_jitter_micros: 500,
            max_jitter_micros: 3000,
            sample_interval: 1,
            inject_enabled: true,
        };

        let mut session = Session::new(&path, params).expect("session");
        for _ in 0..2 {
            session.record_keystroke().expect("keystroke");
        }

        verify_chain(&session.samples, &session.seed, session.params).expect("verify chain");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_reject_zero_sample_interval() {
        let path = temp_document_path();
        fs::write(&path, b"hello jitter").expect("write temp doc");

        let params = Parameters {
            min_jitter_micros: 500,
            max_jitter_micros: 3000,
            sample_interval: 0,
            inject_enabled: true,
        };

        let err = Session::new(&path, params).unwrap_err();
        assert!(err.contains("sample_interval"));

        let _ = fs::remove_file(&path);
    }

    // Additional tests for jitter.rs

    #[test]
    fn test_session_new_with_id() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let session = Session::new_with_id(&path, test_params(), "custom-id-123").expect("session");
        assert_eq!(session.id, "custom-id-123");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_session_invalid_path() {
        let err = Session::new("/nonexistent/path.txt", test_params()).unwrap_err();
        assert!(err.contains("invalid document path"));
    }

    #[test]
    fn test_keystroke_count_and_sample_count() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut params = test_params();
        params.sample_interval = 5;

        let mut session = Session::new(&path, params).expect("session");

        for _ in 0..12 {
            session.record_keystroke().expect("keystroke");
        }

        assert_eq!(session.keystroke_count(), 12);
        assert_eq!(session.sample_count(), 2); // 12 / 5 = 2 samples

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_session_duration() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        std::thread::sleep(Duration::from_millis(10));
        session.end();

        assert!(session.duration() >= Duration::from_millis(10));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_session_save_and_load() {
        let dir = TempDir::new().expect("temp dir");
        let doc_path = dir.path().join("doc.txt");
        let session_path = dir.path().join("session.json");

        fs::write(&doc_path, b"test content").expect("write doc");

        let mut session = Session::new(&doc_path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }
        session.save(&session_path).expect("save");

        let loaded = Session::load(&session_path).expect("load");
        assert_eq!(loaded.id, session.id);
        assert_eq!(loaded.samples.len(), session.samples.len());
        assert_eq!(loaded.keystroke_count(), session.keystroke_count());
    }

    #[test]
    fn test_evidence_verify_hash_mismatch() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        session.record_keystroke().expect("keystroke");
        session.record_keystroke().expect("keystroke");

        let mut evidence = session.export();
        // Tamper with sample hash
        evidence.samples[0].hash[0] ^= 0xFF;

        let err = evidence.verify().unwrap_err();
        assert!(err.contains("hash mismatch"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_evidence_verify_broken_chain() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        session.record_keystroke().expect("keystroke");
        session.record_keystroke().expect("keystroke");

        let mut evidence = session.export();
        // Tamper with previous_hash
        evidence.samples[1].previous_hash[0] ^= 0xFF;
        // Recompute hash to pass hash check (but chain link is broken)
        evidence.samples[1].hash = evidence.samples[1].compute_hash();

        let err = evidence.verify().unwrap_err();
        assert!(
            err.contains("broken chain link"),
            "Expected 'broken chain link', got: {}",
            err
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_evidence_is_plausible_human_typing() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        // Simulate realistic typing at ~200 wpm (1000 chars/min = ~17 chars/sec)
        // So ~60ms per keystroke
        for _ in 0..10 {
            session.record_keystroke().expect("keystroke");
            std::thread::sleep(Duration::from_millis(60));
        }
        session.end();

        let evidence = session.export();
        // With normal timing and limited keystrokes, should be plausible
        // Rate should be ~1000 keystrokes per minute or less
        let rate = evidence.typing_rate();
        assert!(rate <= 1000.0, "typing rate {} is too high", rate);
        assert!(
            evidence.is_plausible_human_typing(),
            "typing should be plausible, rate={}",
            rate
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_encode_decode_chain() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..5 {
            session.record_keystroke().expect("keystroke");
        }

        let encoded = encode_chain(&session.samples, session.params).expect("encode");
        let (decoded_samples, decoded_params) = decode_chain(&encoded).expect("decode");

        assert_eq!(decoded_samples.len(), session.samples.len());
        assert_eq!(
            decoded_params.min_jitter_micros,
            session.params.min_jitter_micros
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_encode_decode_chain_binary() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }

        let encoded = encode_chain_binary(&session.samples, session.params).expect("encode");
        let (decoded_samples, decoded_params) = decode_chain_binary(&encoded).expect("decode");

        assert!(compare_chains(&session.samples, &decoded_samples));
        assert_eq!(
            decoded_params.sample_interval,
            session.params.sample_interval
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_decode_sample_binary_invalid_length() {
        let short_data = vec![0u8; 50];
        let err = decode_sample_binary(&short_data).unwrap_err();
        assert!(err.contains("invalid sample data length"));
    }

    #[test]
    fn test_decode_chain_binary_invalid_version() {
        let mut data = vec![0u8; 20];
        data[0] = 99; // Invalid version
        let err = decode_chain_binary(&data).unwrap_err();
        assert!(err.contains("unsupported chain version"));
    }

    #[test]
    fn test_compare_samples() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        session.record_keystroke().expect("keystroke");

        let sample = &session.samples[0];
        assert!(compare_samples(sample, sample));

        let mut different = sample.clone();
        different.jitter_micros += 1;
        assert!(!compare_samples(sample, &different));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_find_chain_divergence() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..5 {
            session.record_keystroke().expect("keystroke");
        }

        let samples1 = session.samples.clone();
        let mut samples2 = session.samples.clone();
        samples2[3].jitter_micros += 1;

        assert_eq!(find_chain_divergence(&samples1, &samples2), 3);
        assert_eq!(find_chain_divergence(&samples1, &samples1), -1);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_extract_chain_hashes() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }

        let hashes = extract_chain_hashes(&session.samples);
        assert_eq!(hashes.len(), 3);
        for (i, hash) in hashes.iter().enumerate() {
            assert_eq!(*hash, session.samples[i].hash);
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_hash_chain_root() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }

        let root = hash_chain_root(&session.samples);
        assert_eq!(root, session.samples.last().unwrap().hash);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_hash_chain_root_empty() {
        assert_eq!(hash_chain_root(&[]), [0u8; 32]);
    }

    #[test]
    fn test_verify_chain_empty() {
        let err = verify_chain(&[], &[1u8; 32], test_params()).unwrap_err();
        assert!(err.contains("empty sample chain"));
    }

    #[test]
    fn test_verify_chain_empty_seed() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        session.record_keystroke().expect("keystroke");

        let err = verify_chain(&session.samples, &[], session.params).unwrap_err();
        assert!(err.contains("seed is nil or empty"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_verify_chain_detailed() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }

        let result = verify_chain_detailed(&session.samples, &session.seed, session.params);
        assert!(result.valid);
        assert_eq!(result.samples_verified, 3);
        assert!(result.errors.is_empty());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_verify_chain_continuity() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }
        let existing = session.samples.clone();

        for _ in 0..2 {
            session.record_keystroke().expect("keystroke");
        }
        let new_samples = session.samples[3..].to_vec();

        verify_chain_continuity(&existing, &new_samples, &session.seed, session.params)
            .expect("verify continuity");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_validate_sample_format() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        session.record_keystroke().expect("keystroke");

        validate_sample_format(&session.samples[0]).expect("valid format");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_validate_sample_format_zero_timestamp() {
        let sample = Sample {
            timestamp: DateTime::<Utc>::from(SystemTime::UNIX_EPOCH),
            keystroke_count: 1,
            document_hash: [0u8; 32],
            jitter_micros: 1000,
            hash: [1u8; 32],
            previous_hash: [0u8; 32],
        };

        let err = validate_sample_format(&sample).unwrap_err();
        assert!(err.contains("timestamp is zero"));
    }

    #[test]
    fn test_validate_sample_format_zero_hash() {
        let sample = Sample {
            timestamp: Utc::now(),
            keystroke_count: 1,
            document_hash: [0u8; 32],
            jitter_micros: 1000,
            hash: [0u8; 32],
            previous_hash: [0u8; 32],
        };

        let err = validate_sample_format(&sample).unwrap_err();
        assert!(err.contains("sample hash is zero"));
    }

    // Zone and typing profile tests

    #[test]
    fn test_char_to_zone() {
        assert_eq!(char_to_zone('q'), 0);
        assert_eq!(char_to_zone('w'), 1);
        assert_eq!(char_to_zone('e'), 2);
        assert_eq!(char_to_zone('r'), 3);
        assert_eq!(char_to_zone('y'), 4);
        assert_eq!(char_to_zone('i'), 5);
        assert_eq!(char_to_zone('o'), 6);
        assert_eq!(char_to_zone('p'), 7);
        assert_eq!(char_to_zone('1'), -1); // Unknown
    }

    #[test]
    fn test_encode_decode_zone_transition() {
        for from in 0..8 {
            for to in 0..8 {
                let encoded = encode_zone_transition(from, to);
                let (decoded_from, decoded_to) = decode_zone_transition(encoded);
                assert_eq!(decoded_from, from);
                assert_eq!(decoded_to, to);
            }
        }
    }

    #[test]
    fn test_encode_zone_transition_invalid() {
        assert_eq!(encode_zone_transition(-1, 0), 0xFF);
        assert_eq!(encode_zone_transition(0, 8), 0xFF);
    }

    #[test]
    fn test_is_valid_zone_transition() {
        assert!(is_valid_zone_transition(encode_zone_transition(0, 0)));
        assert!(is_valid_zone_transition(encode_zone_transition(3, 5)));
        assert!(!is_valid_zone_transition(0xFF));
    }

    #[test]
    fn test_zone_transition_types() {
        let same_finger = ZoneTransition { from: 2, to: 2 };
        assert!(same_finger.is_same_finger());
        assert!(same_finger.is_same_hand());
        assert!(!same_finger.is_alternating());

        let same_hand = ZoneTransition { from: 0, to: 2 };
        assert!(!same_hand.is_same_finger());
        assert!(same_hand.is_same_hand());
        assert!(!same_hand.is_alternating());

        let alternating = ZoneTransition { from: 1, to: 5 };
        assert!(!alternating.is_same_finger());
        assert!(!alternating.is_same_hand());
        assert!(alternating.is_alternating());
    }

    #[test]
    fn test_text_to_zone_sequence() {
        let text = "hello";
        let transitions = text_to_zone_sequence(text);
        assert!(!transitions.is_empty());
    }

    #[test]
    fn test_interval_to_bucket() {
        assert_eq!(interval_to_bucket(Duration::from_millis(0)), 0);
        assert_eq!(interval_to_bucket(Duration::from_millis(25)), 0);
        assert_eq!(interval_to_bucket(Duration::from_millis(50)), 1);
        assert_eq!(interval_to_bucket(Duration::from_millis(100)), 2);
        assert_eq!(interval_to_bucket(Duration::from_secs(1)), 9); // Max bucket
    }

    #[test]
    fn test_jitter_engine() {
        let secret = [42u8; 32];
        let mut engine = JitterEngine::new(secret);

        let doc_hash = [1u8; 32];
        let (jitter1, sample1) = engine.on_keystroke(0x0C, doc_hash); // 'q'

        assert!(jitter1 >= MIN_JITTER && jitter1 <= MAX_JITTER);
        assert!(sample1.is_some());

        let (jitter2, sample2) = engine.on_keystroke(0x0D, doc_hash); // 'w'
        assert!(jitter2 >= MIN_JITTER && jitter2 <= MAX_JITTER);
        assert!(sample2.is_some());
    }

    #[test]
    fn test_jitter_engine_invalid_keycode() {
        let mut engine = JitterEngine::new([1u8; 32]);
        let (jitter, sample) = engine.on_keystroke(0xFF, [0u8; 32]); // Invalid
        assert_eq!(jitter, 0);
        assert!(sample.is_none());
    }

    #[test]
    fn test_typing_profile() {
        let mut engine = JitterEngine::new([42u8; 32]);
        let doc_hash = [1u8; 32];

        // Simulate some keystrokes
        for keycode in [0x0C, 0x0D, 0x0E, 0x0F, 0x10] {
            engine.on_keystroke(keycode, doc_hash);
        }

        let profile = engine.profile();
        assert!(profile.total_transitions > 0);
    }

    #[test]
    fn test_is_human_plausible() {
        let mut profile = TypingProfile::default();
        // Very few transitions - should be plausible
        profile.total_transitions = 5;
        profile.hand_alternation = 0.5;
        assert!(is_human_plausible(profile));

        // Extreme hand alternation
        let mut profile2 = TypingProfile::default();
        profile2.total_transitions = 100;
        profile2.hand_alternation = 0.05; // Too low
        assert!(!is_human_plausible(profile2));
    }

    #[test]
    fn test_compare_profiles() {
        let profile1 = TypingProfile {
            same_finger_hist: [10, 20, 30, 10, 5, 3, 2, 1, 0, 0],
            same_hand_hist: [5, 15, 25, 20, 10, 5, 3, 2, 1, 0],
            alternating_hist: [20, 30, 25, 15, 8, 5, 3, 2, 1, 0],
            hand_alternation: 0.45,
            total_transitions: 100,
            alternating_count: 45,
        };

        let similarity = compare_profiles(profile1.clone(), profile1.clone());
        assert!((similarity - 1.0).abs() < 0.001); // Same profile should be ~1.0
    }

    #[test]
    fn test_compare_profiles_empty() {
        let empty = TypingProfile::default();
        let similarity = compare_profiles(empty.clone(), empty);
        assert_eq!(similarity, 0.0);
    }

    #[test]
    fn test_profile_distance() {
        let profile1 = TypingProfile {
            same_finger_hist: [10, 20, 30, 10, 5, 3, 2, 1, 0, 0],
            same_hand_hist: [5, 15, 25, 20, 10, 5, 3, 2, 1, 0],
            alternating_hist: [20, 30, 25, 15, 8, 5, 3, 2, 1, 0],
            hand_alternation: 0.45,
            total_transitions: 100,
            alternating_count: 45,
        };

        let distance = profile_distance(profile1.clone(), profile1.clone());
        assert!(distance < 0.001); // Same profile should have ~0 distance
    }

    #[test]
    fn test_quick_verify_profile() {
        let mut profile = TypingProfile::default();
        profile.total_transitions = 100;
        profile.hand_alternation = 0.10; // Too low

        let issues = quick_verify_profile(profile);
        assert!(!issues.is_empty());
    }

    #[test]
    fn test_analyze_document_zones() {
        let content = b"hello world";
        let profile = analyze_document_zones(content);
        assert!(profile.total_transitions > 0);
    }

    #[test]
    fn test_verify_jitter_chain() {
        let secret = [42u8; 32];
        let mut engine = JitterEngine::new(secret);
        let doc_hash = [1u8; 32];

        let mut samples = Vec::new();
        for keycode in [0x0C, 0x0D, 0x0E] {
            if let (_, Some(sample)) = engine.on_keystroke(keycode, doc_hash) {
                samples.push(sample);
            }
        }

        verify_jitter_chain(&samples).expect("verify chain");
    }

    #[test]
    fn test_verify_jitter_chain_empty() {
        let err = verify_jitter_chain(&[]).unwrap_err();
        assert!(err.contains("empty sample chain"));
    }

    #[test]
    fn test_verify_with_secret() {
        let secret = [42u8; 32];
        let mut engine = JitterEngine::new(secret);
        let doc_hash = [1u8; 32];

        let mut samples = Vec::new();
        for keycode in [0x0C, 0x0D, 0x0E] {
            if let (_, Some(sample)) = engine.on_keystroke(keycode, doc_hash) {
                samples.push(sample);
            }
        }

        verify_with_secret(&samples, secret).expect("verify with secret");
    }

    #[test]
    fn test_verify_with_content() {
        let secret = [42u8; 32];
        let mut engine = JitterEngine::new(secret);
        let content = b"hello";
        let doc_hash: [u8; 32] = Sha256::digest(content).into();

        let mut samples = Vec::new();
        // Simulate typing "hello" - h=4, e=2, l=6, l=6, o=6
        for keycode in [0x04, 0x0E, 0x25, 0x25, 0x1F] {
            if let (_, Some(sample)) = engine.on_keystroke(keycode, doc_hash) {
                samples.push(sample);
            }
        }

        let result = verify_with_content(&samples, content);
        assert!(result.chain_valid);
    }

    #[test]
    fn test_simple_jitter_session() {
        let mut session = SimpleJitterSession::new();
        assert!(session.samples.is_empty());

        let ts1 = session.start_time.timestamp_nanos_opt().unwrap_or(0) + 1_000_000;
        session.add_sample(ts1, 1);
        assert_eq!(session.samples.len(), 1);

        let ts2 = ts1 + 500_000;
        session.add_sample(ts2, 2);
        assert_eq!(session.samples.len(), 2);
        assert_eq!(session.samples[1].duration_since_last_ns, 500_000);
    }

    #[test]
    fn test_marshal_sample_for_signing() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        session.record_keystroke().expect("keystroke");

        let marshaled = marshal_sample_for_signing(&session.samples[0]);
        assert!(marshaled.starts_with(b"witnessd-sample-v1\n"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_evidence_encode_decode() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }
        session.end();

        let evidence = session.export();
        let encoded = evidence.encode().expect("encode");
        let decoded = Evidence::decode(&encoded).expect("decode");

        assert_eq!(decoded.session_id, evidence.session_id);
        assert_eq!(decoded.samples.len(), evidence.samples.len());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_evidence_typing_rate() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..60 {
            session.record_keystroke().expect("keystroke");
        }
        std::thread::sleep(Duration::from_millis(100));
        session.end();

        let evidence = session.export();
        let rate = evidence.typing_rate();
        assert!(rate > 0.0);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_evidence_document_evolution() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..5 {
            session.record_keystroke().expect("keystroke");
        }
        session.end();

        let evidence = session.export();
        // All samples have same document hash in this test
        assert_eq!(evidence.document_evolution(), 1);

        let _ = fs::remove_file(&path);
    }
}
