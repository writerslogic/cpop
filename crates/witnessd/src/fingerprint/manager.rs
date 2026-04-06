// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::config::FingerprintConfig;
use crate::fingerprint::activity::{ActivityFingerprint, ActivityFingerprintAccumulator};
use crate::fingerprint::author::{AuthorFingerprint, ProfileId};
use crate::fingerprint::comparison::{self, FingerprintComparison};
use crate::fingerprint::consent::ConsentManager;
use crate::fingerprint::storage::{FingerprintStorage, StoredProfile};
use crate::fingerprint::voice::{VoiceCollector, VoiceFingerprint};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct FingerprintManager {
    pub(crate) config: FingerprintConfig,
    pub(crate) storage: FingerprintStorage,
    pub(crate) consent_manager: ConsentManager,
    pub(crate) activity_accumulator: ActivityFingerprintAccumulator,
    pub(crate) voice_collector: Option<VoiceCollector>,
    pub(crate) current_profile_id: Option<ProfileId>,
}

impl FingerprintManager {
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

    pub fn config(&self) -> &FingerprintConfig {
        &self.config
    }

    pub fn is_activity_enabled(&self) -> bool {
        self.config.activity_enabled
    }

    pub fn is_voice_enabled(&self) -> bool {
        self.config.voice_enabled && self.voice_collector.is_some()
    }

    pub fn enable_activity(&mut self) {
        self.config.activity_enabled = true;
    }

    pub fn disable_activity(&mut self) {
        self.config.activity_enabled = false;
    }

    pub fn request_voice_consent(&mut self) -> Result<bool> {
        let granted = self.consent_manager.begin_consent_request()?;
        if granted {
            self.enable_voice_internal()?;
        }
        Ok(granted)
    }

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
        if let Some(ref mut collector) = self.voice_collector {
            collector.set_consent(true);
        }
        Ok(())
    }

    pub fn disable_voice(&mut self) -> Result<()> {
        self.config.voice_enabled = false;
        self.voice_collector = None;
        self.consent_manager.revoke_consent()?;
        self.storage.delete_all_voice_data()?;
        Ok(())
    }

    pub fn record_activity_sample(&mut self, sample: &crate::jitter::SimpleJitterSample) {
        if !self.config.activity_enabled {
            return;
        }
        self.activity_accumulator.add_sample(sample);
    }

    pub fn record_keystroke_for_voice(&mut self, keycode: u16, char_value: Option<char>) {
        if let Some(ref mut collector) = self.voice_collector {
            collector.record_keystroke(keycode, char_value);
        }
    }

    pub fn current_activity_fingerprint(&self) -> ActivityFingerprint {
        self.activity_accumulator.current_fingerprint()
    }

    pub fn current_voice_fingerprint(&self) -> Option<VoiceFingerprint> {
        self.voice_collector
            .as_ref()
            .map(|c| c.current_fingerprint())
    }

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

    pub fn save_current(&mut self) -> Result<ProfileId> {
        let fingerprint = self.current_author_fingerprint();
        let id = fingerprint.id.clone();
        self.storage.save(&fingerprint)?;
        self.current_profile_id = Some(id.clone());
        Ok(id)
    }

    pub fn load(&self, id: &ProfileId) -> Result<AuthorFingerprint> {
        self.storage.load(id)
    }

    pub fn list_profiles(&self) -> Result<Vec<StoredProfile>> {
        self.storage.list_profiles()
    }

    pub fn compare(&self, id1: &ProfileId, id2: &ProfileId) -> Result<FingerprintComparison> {
        let fp1 = self.storage.load(id1)?;
        let fp2 = self.storage.load(id2)?;
        Ok(comparison::compare_fingerprints(&fp1, &fp2))
    }

    pub fn delete(&mut self, id: &ProfileId) -> Result<()> {
        self.storage.delete(id)?;
        if self.current_profile_id.as_ref() == Some(id) {
            self.current_profile_id = None;
        }
        Ok(())
    }

    pub fn reset_session(&mut self) {
        self.activity_accumulator.reset();
        if let Some(ref mut collector) = self.voice_collector {
            collector.reset();
        }
    }

    #[cfg(feature = "cpop_jitter")]
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
            phys_ratio: None,
        }
    }

    #[cfg(feature = "cpop_jitter")]
    pub fn status_with_phys_ratio(&self, phys_ratio: f64) -> FingerprintStatus {
        let mut status = self.status();
        status.phys_ratio = Some(phys_ratio);
        status
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintStatus {
    pub activity_enabled: bool,
    pub voice_enabled: bool,
    pub voice_consent: bool,
    pub current_profile_id: Option<ProfileId>,
    pub activity_samples: usize,
    pub voice_samples: usize,
    pub confidence: f64,
    #[serde(default)]
    pub phys_ratio: Option<f64>,
}
