//! Bridge module integrating physjitter crate with witnessd's zone-aware typing profiles.
//!
//! This module provides [`HybridJitterSession`] which combines:
//! - physjitter's hardware entropy (PhysJitter) with automatic fallback (HybridEngine)
//! - witnessd's unique zone-aware typing profiles and biometric analysis
//! - Document tracking and chain verification
//!
//! # Example
//!
//! ```rust,ignore
//! use witnessd_core::physjitter_bridge::HybridJitterSession;
//!
//! let mut session = HybridJitterSession::new("/path/to/document.txt", None)?;
//!
//! // Record keystrokes - automatically samples physjitter + zones
//! session.record_keystroke(0x0C)?; // 'q' key
//!
//! // Get physics coverage ratio
//! let phys_ratio = session.phys_ratio();
//!
//! // Export evidence
//! let evidence = session.export();
//! ```

use chrono::{DateTime, Utc};
use physjitter::{
    derive_session_secret, EvidenceChain as PhysEvidenceChain, Session as PhysSession,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::jitter::{
    encode_zone_transition, keycode_to_zone, Evidence, Parameters, Sample, Statistics,
    TypingProfile, ZoneTransition,
};

// =============================================================================
// Zone Tracking Engine
// =============================================================================

/// Standalone zone tracking engine extracted from JitterEngine.
///
/// Tracks keyboard zone transitions and builds typing profiles for
/// biometric analysis, independent of jitter computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTrackingEngine {
    prev_zone: i32,
    profile: TypingProfile,
    prev_time: DateTime<Utc>,
}

impl Default for ZoneTrackingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ZoneTrackingEngine {
    /// Create a new zone tracking engine.
    pub fn new() -> Self {
        Self {
            prev_zone: -1,
            profile: TypingProfile::default(),
            prev_time: Utc::now(),
        }
    }

    /// Record a zone transition from a keycode.
    ///
    /// Returns the encoded zone transition (0xFF if invalid/first keystroke).
    pub fn record_keycode(&mut self, keycode: u16) -> u8 {
        let zone = keycode_to_zone(keycode);
        self.record_zone(zone)
    }

    /// Record a zone transition from a zone value.
    ///
    /// Returns the encoded zone transition (0xFF if invalid/first keystroke).
    pub fn record_zone(&mut self, zone: i32) -> u8 {
        if zone < 0 {
            return 0xFF;
        }

        let now = Utc::now();
        let zone_transition = if self.prev_zone >= 0 {
            let encoded = encode_zone_transition(self.prev_zone, zone);
            let interval = now.signed_duration_since(self.prev_time);
            let bucket = interval_to_bucket(interval.to_std().unwrap_or(Duration::from_secs(0)));
            self.update_profile(self.prev_zone, zone, bucket);
            encoded
        } else {
            0xFF
        };

        self.prev_zone = zone;
        self.prev_time = now;
        zone_transition
    }

    /// Get the current typing profile.
    pub fn profile(&self) -> &TypingProfile {
        &self.profile
    }

    /// Get the previous zone.
    pub fn prev_zone(&self) -> i32 {
        self.prev_zone
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
        }

        self.profile.total_transitions += 1;
        if self.profile.total_transitions > 0 {
            // Count alternating transitions for hand_alternation calculation
            let alternating_count: u64 = self
                .profile
                .alternating_hist
                .iter()
                .map(|&x| x as u64)
                .sum();
            self.profile.hand_alternation =
                alternating_count as f32 / self.profile.total_transitions as f32;
        }
    }
}

// =============================================================================
// Document Tracker
// =============================================================================

/// Tracks document state for hash computation.
#[derive(Debug)]
struct DocumentTracker {
    path: String,
    last_mtime: Option<SystemTime>,
    last_size: Option<u64>,
    last_hash: Option<[u8; 32]>,
}

impl DocumentTracker {
    fn new(path: impl AsRef<Path>) -> Result<Self, String> {
        let abs_path =
            fs::canonicalize(path.as_ref()).map_err(|e| format!("invalid document path: {e}"))?;

        Ok(Self {
            path: abs_path.to_string_lossy().to_string(),
            last_mtime: None,
            last_size: None,
            last_hash: None,
        })
    }

    #[allow(dead_code)]
    fn path(&self) -> &str {
        &self.path
    }

    fn hash(&mut self) -> Result<[u8; 32], String> {
        let metadata = fs::metadata(&self.path).map_err(|e| e.to_string())?;
        let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let size = metadata.len();

        if let (Some(last_mtime), Some(last_size), Some(last_hash)) =
            (self.last_mtime, self.last_size, self.last_hash)
        {
            if mtime == last_mtime && size == last_size {
                return Ok(last_hash);
            }
        }

        let content = fs::read(&self.path).map_err(|e| e.to_string())?;
        let hash: [u8; 32] = Sha256::digest(&content).into();

        self.last_mtime = Some(mtime);
        self.last_size = Some(size);
        self.last_hash = Some(hash);

        Ok(hash)
    }
}

// =============================================================================
// Hybrid Sample
// =============================================================================

/// Extended sample combining physjitter evidence with zone tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSample {
    /// Timestamp of the sample.
    pub timestamp: DateTime<Utc>,
    /// Keystroke ordinal within session.
    pub keystroke_count: u64,
    /// Document hash at time of sample.
    pub document_hash: [u8; 32],
    /// Jitter value in microseconds.
    pub jitter_micros: u32,
    /// Zone transition (0xFF if first keystroke or invalid zone).
    pub zone_transition: u8,
    /// Sample hash for chain integrity.
    pub hash: [u8; 32],
    /// Previous sample hash.
    pub previous_hash: [u8; 32],
    /// Whether this sample used hardware entropy.
    pub is_phys: bool,
}

impl HybridSample {
    fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-hybrid-sample-v1");
        hasher.update(
            self.timestamp
                .timestamp_nanos_opt()
                .unwrap_or(0)
                .to_be_bytes(),
        );
        hasher.update(self.keystroke_count.to_be_bytes());
        hasher.update(self.document_hash);
        hasher.update(self.jitter_micros.to_be_bytes());
        hasher.update([self.zone_transition]);
        hasher.update([if self.is_phys { 1 } else { 0 }]);
        hasher.update(self.previous_hash);
        hasher.finalize().into()
    }
}

// =============================================================================
// Hybrid Jitter Session
// =============================================================================

/// Quality metrics for entropy used in the session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EntropyQuality {
    /// Ratio of samples using hardware entropy (0.0 to 1.0).
    pub phys_ratio: f64,
    /// Total number of samples.
    pub total_samples: usize,
    /// Number of samples using hardware entropy.
    pub phys_samples: usize,
    /// Number of samples using pure HMAC fallback.
    pub pure_samples: usize,
}

/// Hybrid jitter session combining physjitter with witnessd's zone tracking.
///
/// This session type uses physjitter's hardware entropy when available,
/// automatically falling back to HMAC-based jitter in virtualized environments,
/// while preserving witnessd's unique zone-aware typing profiles.
#[derive(Debug)]
pub struct HybridJitterSession {
    /// Underlying physjitter session.
    physjitter_session: PhysSession,
    /// Zone tracking engine for typing profiles.
    zone_engine: ZoneTrackingEngine,
    /// Document tracker for hash computation.
    document_tracker: DocumentTracker,
    /// Session ID.
    pub id: String,
    /// Document path.
    pub document_path: String,
    /// Session start time.
    pub started_at: DateTime<Utc>,
    /// Session end time.
    pub ended_at: Option<DateTime<Utc>>,
    /// Parameters (for compatibility).
    pub params: Parameters,
    /// Extended samples with zone info.
    samples: Vec<HybridSample>,
    /// Keystroke count.
    keystroke_count: u64,
    /// Last jitter value.
    last_jitter: u32,
}

impl HybridJitterSession {
    /// Create a new hybrid jitter session.
    ///
    /// # Arguments
    ///
    /// * `document_path` - Path to the document being tracked.
    /// * `params` - Optional jitter parameters. If None, uses defaults.
    pub fn new(
        document_path: impl AsRef<Path>,
        params: Option<Parameters>,
    ) -> Result<Self, String> {
        let params = params.unwrap_or_else(crate::jitter::default_parameters);

        if params.sample_interval == 0 {
            return Err("sample_interval must be > 0".to_string());
        }

        let document_tracker = DocumentTracker::new(document_path.as_ref())?;
        let document_path_str = document_tracker.path.clone();

        // Generate random key material and derive session secret using HKDF
        let mut key_material = [0u8; 32];
        getrandom::getrandom(&mut key_material)
            .map_err(|e| format!("failed to generate key material: {e}"))?;
        let secret = derive_session_secret(&key_material, b"witnessd-hybrid-session-v1");

        let physjitter_session = PhysSession::new(secret);

        Ok(Self {
            physjitter_session,
            zone_engine: ZoneTrackingEngine::new(),
            document_tracker,
            id: hex::encode(rand::random::<[u8; 8]>()),
            document_path: document_path_str,
            started_at: Utc::now(),
            ended_at: None,
            params,
            samples: Vec::new(),
            keystroke_count: 0,
            last_jitter: 0,
        })
    }

    /// Create a new session with a specific ID.
    pub fn new_with_id(
        document_path: impl AsRef<Path>,
        params: Option<Parameters>,
        session_id: impl Into<String>,
    ) -> Result<Self, String> {
        let mut session = Self::new(document_path, params)?;
        session.id = session_id.into();
        Ok(session)
    }

    /// Record a keystroke and compute jitter.
    ///
    /// Returns `(jitter_micros, sampled)` where sampled is true if this
    /// keystroke resulted in a new sample (based on sample_interval).
    pub fn record_keystroke(&mut self, keycode: u16) -> Result<(u32, bool), String> {
        self.keystroke_count += 1;

        // Check if we should sample
        if !self
            .keystroke_count
            .is_multiple_of(self.params.sample_interval)
        {
            // Still record zone for profile tracking
            self.zone_engine.record_keycode(keycode);
            return Ok((0, false));
        }

        // Get document hash
        let doc_hash = self.document_tracker.hash()?;
        let now = Utc::now();

        // Record zone transition
        let zone_transition = self.zone_engine.record_keycode(keycode);

        // Build input for physjitter (combines keystroke context)
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(&self.keystroke_count.to_be_bytes());
        input.extend_from_slice(&doc_hash);
        input.extend_from_slice(&[zone_transition]);
        input.extend_from_slice(&now.timestamp_nanos_opt().unwrap_or(0).to_be_bytes());

        // Sample from physjitter
        let jitter = self
            .physjitter_session
            .sample(&input)
            .map_err(|e| format!("physjitter sample failed: {e}"))?;

        // Check if this sample used hardware entropy
        let is_phys = self
            .physjitter_session
            .evidence()
            .records
            .last()
            .map(|e| e.is_phys())
            .unwrap_or(false);

        // Create hybrid sample
        let previous_hash = self.samples.last().map(|s| s.hash).unwrap_or([0u8; 32]);
        let mut sample = HybridSample {
            timestamp: now,
            keystroke_count: self.keystroke_count,
            document_hash: doc_hash,
            jitter_micros: jitter,
            zone_transition,
            hash: [0u8; 32],
            previous_hash,
            is_phys,
        };
        sample.hash = sample.compute_hash();

        self.samples.push(sample);
        self.last_jitter = jitter;

        Ok((jitter, true))
    }

    /// End the session.
    pub fn end(&mut self) {
        self.ended_at = Some(Utc::now());
    }

    /// Get keystroke count.
    pub fn keystroke_count(&self) -> u64 {
        self.keystroke_count
    }

    /// Get sample count.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Get session duration.
    pub fn duration(&self) -> Duration {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        end.signed_duration_since(self.started_at)
            .to_std()
            .unwrap_or(Duration::from_secs(0))
    }

    /// Get physics coverage ratio (0.0 to 1.0).
    ///
    /// This indicates what fraction of samples used hardware entropy.
    pub fn phys_ratio(&self) -> f64 {
        self.physjitter_session.phys_ratio()
    }

    /// Get detailed entropy quality metrics.
    pub fn entropy_quality(&self) -> EntropyQuality {
        let evidence = self.physjitter_session.evidence();
        let phys_samples = evidence.phys_count();
        let pure_samples = evidence.pure_count();

        EntropyQuality {
            phys_ratio: evidence.phys_ratio(),
            total_samples: evidence.records.len(),
            phys_samples,
            pure_samples,
        }
    }

    /// Get the typing profile.
    pub fn profile(&self) -> &TypingProfile {
        self.zone_engine.profile()
    }

    /// Get hybrid samples.
    pub fn samples(&self) -> &[HybridSample] {
        &self.samples
    }

    /// Verify the internal chain integrity.
    pub fn verify_chain(&self) -> Result<(), String> {
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

    /// Export evidence in witnessd's standard format.
    ///
    /// Converts hybrid samples to witnessd's Evidence format for
    /// backward compatibility.
    pub fn export(&self) -> HybridEvidence {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        let statistics = self.compute_stats();
        let entropy_quality = self.entropy_quality();

        HybridEvidence {
            session_id: self.id.clone(),
            started_at: self.started_at,
            ended_at: end,
            document_path: self.document_path.clone(),
            params: self.params,
            samples: self.samples.clone(),
            statistics,
            entropy_quality,
            typing_profile: self.profile().clone(),
            physjitter_evidence: self.physjitter_session.export_json().ok(),
        }
    }

    /// Export as standard witnessd Evidence (without hybrid extensions).
    pub fn export_standard(&self) -> Evidence {
        let end = self.ended_at.unwrap_or_else(Utc::now);

        let samples: Vec<Sample> = self
            .samples
            .iter()
            .map(|hs| Sample {
                timestamp: hs.timestamp,
                keystroke_count: hs.keystroke_count,
                document_hash: hs.document_hash,
                jitter_micros: hs.jitter_micros,
                hash: hs.hash,
                previous_hash: hs.previous_hash,
            })
            .collect();

        Evidence {
            session_id: self.id.clone(),
            started_at: self.started_at,
            ended_at: end,
            document_path: self.document_path.clone(),
            params: self.params,
            samples,
            statistics: self.compute_stats(),
        }
    }

    fn compute_stats(&self) -> Statistics {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        let duration = end
            .signed_duration_since(self.started_at)
            .to_std()
            .unwrap_or(Duration::from_secs(0));

        let keystrokes_per_min = if duration.as_secs_f64() > 0.0 {
            let minutes = duration.as_secs_f64() / 60.0;
            if minutes > 0.0 {
                self.keystroke_count as f64 / minutes
            } else {
                0.0
            }
        } else {
            0.0
        };

        let mut seen = std::collections::HashSet::new();
        for sample in &self.samples {
            seen.insert(sample.document_hash);
        }

        Statistics {
            total_keystrokes: self.keystroke_count,
            total_samples: self.samples.len() as i32,
            duration,
            keystrokes_per_min,
            unique_doc_hashes: seen.len() as i32,
            chain_valid: self.verify_chain().is_ok(),
        }
    }

    /// Save session to disk.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let data = HybridSessionData {
            id: self.id.clone(),
            started_at: self.started_at,
            ended_at: self.ended_at,
            document_path: self.document_path.clone(),
            params: self.params,
            samples: self.samples.clone(),
            keystroke_count: self.keystroke_count,
            last_jitter: self.last_jitter,
            zone_engine: self.zone_engine.clone(),
            physjitter_evidence: self.physjitter_session.export_json().ok(),
        };

        let bytes = serde_json::to_vec_pretty(&data).map_err(|e| e.to_string())?;
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(path, bytes).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Load session from disk.
    ///
    /// Note: The physjitter session is recreated with a new secret,
    /// so the evidence chain will not be continuous with the original.
    /// Use this for viewing/exporting only.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        let data: HybridSessionData = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;

        // We can't restore the exact physjitter session, but we can recreate one
        // using HKDF-derived secret for consistency
        let mut key_material = [0u8; 32];
        getrandom::getrandom(&mut key_material)
            .map_err(|e| format!("failed to generate key material: {e}"))?;
        let secret = derive_session_secret(&key_material, b"witnessd-hybrid-session-v1");

        let document_tracker = DocumentTracker {
            path: data.document_path.clone(),
            last_mtime: None,
            last_size: None,
            last_hash: None,
        };

        Ok(Self {
            physjitter_session: PhysSession::new(secret),
            zone_engine: data.zone_engine,
            document_tracker,
            id: data.id,
            document_path: data.document_path,
            started_at: data.started_at,
            ended_at: data.ended_at,
            params: data.params,
            samples: data.samples,
            keystroke_count: data.keystroke_count,
            last_jitter: data.last_jitter,
        })
    }
}

// =============================================================================
// Serialization Types
// =============================================================================

/// Serializable session data for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HybridSessionData {
    id: String,
    started_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    document_path: String,
    params: Parameters,
    samples: Vec<HybridSample>,
    keystroke_count: u64,
    last_jitter: u32,
    zone_engine: ZoneTrackingEngine,
    physjitter_evidence: Option<String>,
}

/// Extended evidence format including physjitter metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridEvidence {
    /// Session identifier.
    pub session_id: String,
    /// Session start time.
    pub started_at: DateTime<Utc>,
    /// Session end time.
    pub ended_at: DateTime<Utc>,
    /// Document path.
    pub document_path: String,
    /// Jitter parameters.
    pub params: Parameters,
    /// Hybrid samples with zone and phys info.
    pub samples: Vec<HybridSample>,
    /// Aggregate statistics.
    pub statistics: Statistics,
    /// Entropy quality metrics.
    pub entropy_quality: EntropyQuality,
    /// Typing profile for biometric analysis.
    pub typing_profile: TypingProfile,
    /// Raw physjitter evidence (JSON string).
    pub physjitter_evidence: Option<String>,
}

impl HybridEvidence {
    /// Verify the evidence chain including embedded physjitter evidence.
    ///
    /// This verifies:
    /// - Hash integrity for each sample
    /// - Chain link integrity (previous_hash matches)
    /// - Timestamp monotonicity
    /// - Keystroke count monotonicity
    /// - Physjitter evidence sequence and timestamp ordering (if present)
    pub fn verify(&self) -> Result<(), String> {
        // Verify witnessd hybrid sample chain
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

        // Verify embedded physjitter evidence chain (if present)
        if let Some(ref physjitter_json) = self.physjitter_evidence {
            self.verify_physjitter_evidence(physjitter_json)?;
        }

        Ok(())
    }

    /// Verify the embedded physjitter evidence chain.
    fn verify_physjitter_evidence(&self, json: &str) -> Result<(), String> {
        let chain: PhysEvidenceChain = serde_json::from_str(json)
            .map_err(|e| format!("physjitter evidence parse error: {e}"))?;

        // Validate sequence numbers are monotonic (0, 1, 2, ...)
        if !chain.validate_sequences() {
            return Err("physjitter evidence: sequence numbers not monotonic".to_string());
        }

        // Validate timestamps are monotonic
        if !chain.validate_timestamps() {
            return Err("physjitter evidence: timestamps not monotonic".to_string());
        }

        Ok(())
    }

    /// Encode evidence as JSON.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec_pretty(self).map_err(|e| e.to_string())
    }

    /// Decode evidence from JSON.
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }

    /// Get typing rate (keystrokes per minute).
    pub fn typing_rate(&self) -> f64 {
        if self.statistics.duration.as_secs_f64() > 0.0 {
            self.statistics.total_keystrokes as f64
                / (self.statistics.duration.as_secs_f64() / 60.0)
        } else {
            0.0
        }
    }

    /// Check if typing patterns are plausible for human typing.
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

    /// Get the entropy source description.
    pub fn entropy_source(&self) -> &'static str {
        if self.entropy_quality.phys_ratio > 0.9 {
            "hardware (TSC-based)"
        } else if self.entropy_quality.phys_ratio > 0.5 {
            "hybrid (hardware + HMAC)"
        } else if self.entropy_quality.phys_ratio > 0.0 {
            "mostly HMAC (limited hardware)"
        } else {
            "pure HMAC (no hardware entropy)"
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

const INTERVAL_BUCKET_SIZE_MS: i64 = 50;
const NUM_INTERVAL_BUCKETS: i64 = 10;

fn interval_to_bucket(duration: Duration) -> u8 {
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jitter::decode_zone_transition;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_doc() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "test content for hybrid jitter").unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_zone_tracking_engine() {
        let mut engine = ZoneTrackingEngine::new();

        // First keystroke - no transition
        let trans = engine.record_keycode(0x0C); // 'q' -> zone 0
        assert_eq!(trans, 0xFF);

        // Second keystroke - has transition
        let trans = engine.record_keycode(0x0D); // 'w' -> zone 1
        assert_ne!(trans, 0xFF);

        let (from, to) = decode_zone_transition(trans);
        assert_eq!(from, 0);
        assert_eq!(to, 1);

        assert!(engine.profile().total_transitions > 0);
    }

    #[test]
    fn test_hybrid_session_creation() {
        let doc = create_temp_doc();
        let session = HybridJitterSession::new(doc.path(), None);
        assert!(session.is_ok());

        let session = session.unwrap();
        assert!(!session.id.is_empty());
        assert_eq!(session.keystroke_count(), 0);
    }

    #[test]
    fn test_hybrid_session_record_keystroke() {
        let doc = create_temp_doc();
        let mut session = HybridJitterSession::new(
            doc.path(),
            Some(crate::jitter::Parameters {
                sample_interval: 1, // Sample every keystroke
                ..crate::jitter::default_parameters()
            }),
        )
        .unwrap();

        // Record keystroke
        let result = session.record_keystroke(0x0C); // 'q'
        assert!(result.is_ok());

        let (jitter, sampled) = result.unwrap();
        assert!(sampled);
        assert!(jitter >= 500);
        assert!(jitter < 3000);

        assert_eq!(session.keystroke_count(), 1);
        assert_eq!(session.sample_count(), 1);
    }

    #[test]
    fn test_hybrid_session_export() {
        let doc = create_temp_doc();
        let mut session = HybridJitterSession::new(
            doc.path(),
            Some(crate::jitter::Parameters {
                sample_interval: 1,
                ..crate::jitter::default_parameters()
            }),
        )
        .unwrap();

        // Record some keystrokes
        for keycode in [0x0C, 0x0D, 0x0E] {
            // q, w, e
            session.record_keystroke(keycode).unwrap();
        }

        session.end();
        let evidence = session.export();

        assert_eq!(evidence.samples.len(), 3);
        assert!(evidence.verify().is_ok());
        assert!(evidence.entropy_quality.phys_ratio >= 0.0);
        assert!(evidence.entropy_quality.phys_ratio <= 1.0);
    }

    #[test]
    fn test_phys_ratio() {
        let doc = create_temp_doc();
        let mut session = HybridJitterSession::new(
            doc.path(),
            Some(crate::jitter::Parameters {
                sample_interval: 1,
                ..crate::jitter::default_parameters()
            }),
        )
        .unwrap();

        // Record keystrokes
        for _ in 0..10 {
            session.record_keystroke(0x0C).unwrap();
        }

        let ratio = session.phys_ratio();
        // Ratio should be between 0 and 1
        assert!(ratio >= 0.0);
        assert!(ratio <= 1.0);
    }

    #[test]
    fn test_entropy_quality() {
        let doc = create_temp_doc();
        let mut session = HybridJitterSession::new(
            doc.path(),
            Some(crate::jitter::Parameters {
                sample_interval: 1,
                ..crate::jitter::default_parameters()
            }),
        )
        .unwrap();

        for _ in 0..5 {
            session.record_keystroke(0x0C).unwrap();
        }

        let quality = session.entropy_quality();
        assert_eq!(quality.total_samples, 5);
        assert_eq!(quality.phys_samples + quality.pure_samples, 5);
    }
}
