//! Author Fingerprinting Module
//!
//! This module provides authorship verification through behavioral biometrics:
//!
//! - **ActivityFingerprint**: Typing dynamics (cadence, rhythm, zones) - DEFAULT ON
//! - **VoiceFingerprint**: Writing style analysis - DEFAULT OFF, requires consent
//!
//! # Privacy Model
//!
//! - Activity fingerprints capture *how* you type, not *what* you type
//! - Voice fingerprints require explicit opt-in consent
//! - All fingerprint data is stored encrypted locally
//! - No raw keystroke data is stored after processing
//!
//! # Usage
//!
//! ```rust,ignore
//! use witnessd_core::fingerprint::{ActivityFingerprint, FingerprintManager};
//!
//! let mut manager = FingerprintManager::new()?;
//!
//! // Activity fingerprinting is enabled by default
//! manager.record_activity_sample(&sample);
//!
//! // Voice fingerprinting requires consent
//! if manager.request_voice_consent()? {
//!     manager.enable_voice_fingerprinting()?;
//! }
//! ```

pub mod activity;
pub mod comparison;
pub mod consent;
pub mod storage;
pub mod voice;

pub use activity::{ActivityFingerprint, ActivityFingerprintAccumulator, ZoneProfile};
pub use comparison::{FingerprintComparison, ProfileMatcher};
pub use consent::{ConsentManager, ConsentRecord, ConsentStatus};
pub use storage::{FingerprintStorage, StoredProfile};
pub use voice::{VoiceCollector, VoiceFingerprint};

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

// =============================================================================
// Core Types
// =============================================================================

/// Unique identifier for a fingerprint profile.
pub type ProfileId = String;

/// Combined author fingerprint with both activity and optional voice data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorFingerprint {
    /// Unique profile ID
    pub id: ProfileId,
    /// Human-readable name (optional)
    pub name: Option<String>,
    /// When this profile was created
    pub created_at: DateTime<Utc>,
    /// When this profile was last updated
    pub updated_at: DateTime<Utc>,
    /// Activity fingerprint (always present)
    pub activity: ActivityFingerprint,
    /// Voice fingerprint (only if consent given)
    pub voice: Option<VoiceFingerprint>,
    /// Total samples contributing to this profile
    pub sample_count: u64,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
}

impl AuthorFingerprint {
    /// Create a new author fingerprint with just activity data.
    pub fn new(activity: ActivityFingerprint) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            activity,
            voice: None,
            sample_count: 0,
            confidence: 0.0,
        }
    }

    /// Create with a specific ID.
    pub fn with_id(id: ProfileId, activity: ActivityFingerprint) -> Self {
        Self {
            id,
            name: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            activity,
            voice: None,
            sample_count: 0,
            confidence: 0.0,
        }
    }

    /// Add voice fingerprint.
    pub fn with_voice(mut self, voice: VoiceFingerprint) -> Self {
        self.voice = Some(voice);
        self
    }

    /// Update confidence based on sample count.
    pub fn update_confidence(&mut self) {
        // Confidence increases with more samples, asymptotic to 1.0
        // 100 samples ≈ 0.5 confidence, 1000 samples ≈ 0.9 confidence
        self.confidence = 1.0 - 1.0 / (1.0 + self.sample_count as f64 / 100.0);
    }

    /// Merge another fingerprint into this one.
    pub fn merge(&mut self, other: &AuthorFingerprint) {
        self.activity.merge(&other.activity);
        if let Some(other_voice) = &other.voice {
            if let Some(ref mut voice) = self.voice {
                voice.merge(other_voice);
            } else {
                self.voice = Some(other_voice.clone());
            }
        }
        self.sample_count += other.sample_count;
        self.updated_at = Utc::now();
        self.update_confidence();
    }
}

// Re-export config::FingerprintConfig for convenience
pub use crate::config::FingerprintConfig;

// =============================================================================
// Fingerprint Manager
// =============================================================================

/// Manager for author fingerprinting operations.
pub struct FingerprintManager {
    config: FingerprintConfig,
    storage: FingerprintStorage,
    consent_manager: ConsentManager,
    activity_accumulator: ActivityFingerprintAccumulator,
    voice_collector: Option<VoiceCollector>,
    current_profile_id: Option<ProfileId>,
}

impl FingerprintManager {
    /// Create a new fingerprint manager with the given storage path.
    pub fn new(storage_path: &Path) -> Result<Self> {
        let storage = FingerprintStorage::new(storage_path)?;
        let consent_manager = ConsentManager::new(storage_path)?;

        Ok(Self {
            config: FingerprintConfig::default(),
            storage,
            consent_manager,
            activity_accumulator: ActivityFingerprintAccumulator::new(),
            voice_collector: None,
            current_profile_id: None,
        })
    }

    /// Create a new fingerprint manager with custom configuration.
    pub fn with_config(config: FingerprintConfig) -> Result<Self> {
        let storage = FingerprintStorage::new(&config.storage_path)?;
        let consent_manager = ConsentManager::new(&config.storage_path)?;

        let voice_collector = if config.voice_enabled && consent_manager.has_voice_consent()? {
            Some(VoiceCollector::new())
        } else {
            None
        };

        Ok(Self {
            config,
            storage,
            consent_manager,
            activity_accumulator: ActivityFingerprintAccumulator::new(),
            voice_collector,
            current_profile_id: None,
        })
    }

    /// Get the current configuration.
    pub fn config(&self) -> &FingerprintConfig {
        &self.config
    }

    /// Check if activity fingerprinting is enabled.
    pub fn is_activity_enabled(&self) -> bool {
        self.config.activity_enabled
    }

    /// Check if voice fingerprinting is enabled and has consent.
    pub fn is_voice_enabled(&self) -> bool {
        self.config.voice_enabled && self.voice_collector.is_some()
    }

    /// Enable activity fingerprinting.
    pub fn enable_activity(&mut self) {
        self.config.activity_enabled = true;
    }

    /// Disable activity fingerprinting.
    pub fn disable_activity(&mut self) {
        self.config.activity_enabled = false;
    }

    /// Request voice fingerprinting consent.
    pub fn request_voice_consent(&mut self) -> Result<bool> {
        let granted = self.consent_manager.request_consent()?;
        if granted {
            self.enable_voice_internal()?;
        }
        Ok(granted)
    }

    /// Enable voice fingerprinting (requires prior consent).
    pub fn enable_voice(&mut self) -> Result<()> {
        if !self.consent_manager.has_voice_consent()? {
            return Err(anyhow::anyhow!(
                "Voice fingerprinting requires consent. Call request_voice_consent() first."
            ));
        }
        self.enable_voice_internal()
    }

    fn enable_voice_internal(&mut self) -> Result<()> {
        self.config.voice_enabled = true;
        if self.voice_collector.is_none() {
            self.voice_collector = Some(VoiceCollector::new());
        }
        Ok(())
    }

    /// Disable voice fingerprinting and delete all voice data.
    pub fn disable_voice(&mut self) -> Result<()> {
        self.config.voice_enabled = false;
        self.voice_collector = None;
        self.consent_manager.revoke_consent()?;
        self.storage.delete_all_voice_data()?;
        Ok(())
    }

    /// Record an activity sample (keystroke timing).
    pub fn record_activity_sample(&mut self, sample: &crate::jitter::SimpleJitterSample) {
        if !self.config.activity_enabled {
            return;
        }
        self.activity_accumulator.add_sample(sample);
    }

    /// Record a keystroke for voice fingerprinting (if enabled).
    pub fn record_keystroke_for_voice(&mut self, keycode: u16, char_value: Option<char>) {
        if let Some(ref mut collector) = self.voice_collector {
            collector.record_keystroke(keycode, char_value);
        }
    }

    /// Get the current activity fingerprint snapshot.
    pub fn current_activity_fingerprint(&self) -> ActivityFingerprint {
        self.activity_accumulator.current_fingerprint()
    }

    /// Get the current voice fingerprint snapshot (if enabled).
    pub fn current_voice_fingerprint(&self) -> Option<VoiceFingerprint> {
        self.voice_collector
            .as_ref()
            .map(|c| c.current_fingerprint())
    }

    /// Get or create the current author fingerprint.
    pub fn current_author_fingerprint(&self) -> AuthorFingerprint {
        let activity = self.current_activity_fingerprint();
        let mut fingerprint = if let Some(ref id) = self.current_profile_id {
            AuthorFingerprint::with_id(id.clone(), activity)
        } else {
            AuthorFingerprint::new(activity)
        };

        if let Some(voice) = self.current_voice_fingerprint() {
            fingerprint = fingerprint.with_voice(voice);
        }

        fingerprint.sample_count = self.activity_accumulator.sample_count() as u64;
        fingerprint.update_confidence();
        fingerprint
    }

    /// Save the current fingerprint to storage.
    pub fn save_current(&mut self) -> Result<ProfileId> {
        let fingerprint = self.current_author_fingerprint();
        let id = fingerprint.id.clone();
        self.storage.save(&fingerprint)?;
        self.current_profile_id = Some(id.clone());
        Ok(id)
    }

    /// Load a fingerprint by ID.
    pub fn load(&self, id: &ProfileId) -> Result<AuthorFingerprint> {
        self.storage.load(id)
    }

    /// List all stored fingerprint profiles.
    pub fn list_profiles(&self) -> Result<Vec<StoredProfile>> {
        self.storage.list_profiles()
    }

    /// Compare two fingerprints.
    pub fn compare(&self, id1: &ProfileId, id2: &ProfileId) -> Result<FingerprintComparison> {
        let fp1 = self.storage.load(id1)?;
        let fp2 = self.storage.load(id2)?;
        Ok(comparison::compare_fingerprints(&fp1, &fp2))
    }

    /// Delete a fingerprint profile.
    pub fn delete(&mut self, id: &ProfileId) -> Result<()> {
        self.storage.delete(id)?;
        if self.current_profile_id.as_ref() == Some(id) {
            self.current_profile_id = None;
        }
        Ok(())
    }

    /// Reset current session data.
    pub fn reset_session(&mut self) {
        self.activity_accumulator.reset();
        if let Some(ref mut collector) = self.voice_collector {
            collector.reset();
        }
    }

    /// Get the current author fingerprint with hardware entropy ratio.
    ///
    /// Use this when integrating with HybridJitterSession to include
    /// the phys_ratio in the fingerprint.
    #[cfg(feature = "physjitter")]
    pub fn current_author_fingerprint_with_phys_ratio(&self, phys_ratio: f64) -> AuthorFingerprint {
        let mut activity = self.current_activity_fingerprint();
        activity.set_phys_ratio(phys_ratio);

        let mut fingerprint = if let Some(ref id) = self.current_profile_id {
            AuthorFingerprint::with_id(id.clone(), activity)
        } else {
            AuthorFingerprint::new(activity)
        };

        if let Some(voice) = self.current_voice_fingerprint() {
            fingerprint = fingerprint.with_voice(voice);
        }

        fingerprint.sample_count = self.activity_accumulator.sample_count() as u64;
        fingerprint.update_confidence();
        fingerprint
    }

    /// Get fingerprint status information.
    pub fn status(&self) -> FingerprintStatus {
        FingerprintStatus {
            activity_enabled: self.config.activity_enabled,
            voice_enabled: self.config.voice_enabled,
            voice_consent: self.consent_manager.has_voice_consent().unwrap_or(false),
            current_profile_id: self.current_profile_id.clone(),
            activity_samples: self.activity_accumulator.sample_count(),
            voice_samples: self
                .voice_collector
                .as_ref()
                .map(|c| c.sample_count())
                .unwrap_or(0),
            confidence: self.current_author_fingerprint().confidence,
            phys_ratio: None, // Set externally when using HybridJitterSession
        }
    }

    /// Get fingerprint status with hardware entropy ratio.
    ///
    /// Use this when integrating with HybridJitterSession.
    #[cfg(feature = "physjitter")]
    pub fn status_with_phys_ratio(&self, phys_ratio: f64) -> FingerprintStatus {
        let mut status = self.status();
        status.phys_ratio = Some(phys_ratio);
        status
    }
}

/// Status information about fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintStatus {
    pub activity_enabled: bool,
    pub voice_enabled: bool,
    pub voice_consent: bool,
    pub current_profile_id: Option<ProfileId>,
    pub activity_samples: usize,
    pub voice_samples: usize,
    pub confidence: f64,
    /// Hardware entropy ratio if using physjitter.
    /// Only set when HybridJitterSession is in use.
    #[serde(default)]
    pub phys_ratio: Option<f64>,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_author_fingerprint_creation() {
        let activity = ActivityFingerprint::default();
        let fp = AuthorFingerprint::new(activity);
        assert!(!fp.id.is_empty());
        assert_eq!(fp.sample_count, 0);
        assert_eq!(fp.confidence, 0.0);
    }

    #[test]
    fn test_confidence_calculation() {
        let mut fp = AuthorFingerprint::new(ActivityFingerprint::default());
        fp.sample_count = 100;
        fp.update_confidence();
        assert!(fp.confidence > 0.4 && fp.confidence < 0.6);

        fp.sample_count = 1000;
        fp.update_confidence();
        assert!(fp.confidence > 0.85);
    }

    #[test]
    fn test_default_config() {
        let config = FingerprintConfig::default();
        assert!(config.activity_enabled);
        assert!(!config.voice_enabled);
        assert_eq!(config.retention_days, 365);
    }
}
