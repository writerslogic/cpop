// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! FFI bindings for fingerprint management — status, consent, export.

use super::helpers::get_data_dir;
use super::types::{FfiConsentResult, FfiFingerprintStatus, FfiFingerprintSummary, FfiResult};
use crate::fingerprint::manager::FingerprintManager;
use std::sync::Mutex;

static FINGERPRINT_MANAGER: std::sync::OnceLock<Mutex<Option<FingerprintManager>>> =
    std::sync::OnceLock::new();

fn manager_lock() -> &'static Mutex<Option<FingerprintManager>> {
    FINGERPRINT_MANAGER.get_or_init(|| Mutex::new(None))
}

fn with_manager<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce(&mut FingerprintManager) -> Result<T, String>,
{
    let mut guard = manager_lock()
        .lock()
        .map_err(|e| format!("Lock poisoned: {e}"))?;

    if guard.is_none() {
        let data_dir = get_data_dir().ok_or("Cannot determine data directory")?;
        let fp_dir = data_dir.join("fingerprints");
        std::fs::create_dir_all(&fp_dir)
            .map_err(|e| format!("Failed to create fingerprint directory: {e}"))?;
        let mgr = FingerprintManager::new(&fp_dir)
            .map_err(|e| format!("Failed to initialize fingerprint manager: {e}"))?;
        *guard = Some(mgr);
    }

    f(guard.as_mut().unwrap())
}

/// Return fingerprint status: enabled flags, sample counts, confidence, quality score.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_fingerprint_status() -> FfiFingerprintStatus {
    match with_manager(|mgr| {
        let status = mgr.status();

        // Quality score: activity saturates at ~500 samples, voice at ~100
        let activity_quality = (status.activity_samples as f64 / 500.0).min(1.0);
        let voice_quality = (status.voice_samples as f64 / 100.0).min(1.0);
        let quality_score = if status.voice_enabled {
            activity_quality * 0.4 + voice_quality * 0.6
        } else {
            activity_quality
        };

        Ok(FfiFingerprintStatus {
            success: true,
            activity_enabled: status.activity_enabled,
            voice_enabled: status.voice_enabled,
            voice_consent: status.voice_consent,
            activity_samples: status.activity_samples as u64,
            voice_samples: status.voice_samples as u64,
            confidence: status.confidence,
            quality_score,
            current_profile_id: status.current_profile_id,
            error_message: None,
        })
    }) {
        Ok(s) => s,
        Err(e) => FfiFingerprintStatus {
            success: false,
            activity_enabled: false,
            voice_enabled: false,
            voice_consent: false,
            activity_samples: 0,
            voice_samples: 0,
            confidence: 0.0,
            quality_score: 0.0,
            current_profile_id: None,
            error_message: Some(e),
        },
    }
}

/// Return human-readable fingerprint dimensions plus serialized JSON for cloud sync.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_fingerprint_summary() -> FfiFingerprintSummary {
    match with_manager(|mgr| {
        let activity = mgr.current_activity_fingerprint();
        let voice = mgr.current_voice_fingerprint();

        let avg_wpm = activity.session_signature.mean_typing_speed;
        let iki_mean = activity.iki_distribution.mean;
        let iki_std_dev = activity.iki_distribution.std_dev;
        let dominant_zone = activity.zone_profile.dominant_zone();

        // Peak hour from circadian pattern
        let peak_hour = activity
            .circadian_pattern
            .hourly_activity
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i as u8)
            .unwrap_or(0);

        // Pause patterns
        let sentence_pause_mean = activity.pause_signature.sentence_pause_mean;
        let thinking_pause_mean = activity.pause_signature.thinking_pause_mean;

        // Voice dimensions (optional)
        let (avg_word_length, correction_rate, top_punctuation) = if let Some(ref v) = voice {
            let avg_wl = v.avg_word_length();
            let cr = v.correction_rate;
            // Top 5 punctuation marks
            let mut punct: Vec<(char, f32)> = v
                .punctuation_signature
                .char_frequencies
                .iter()
                .map(|(c, f)| (*c, *f))
                .collect();
            punct.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            punct.truncate(5);
            let punct_str = punct
                .iter()
                .map(|(c, f)| format!("{c}:{f:.2}"))
                .collect::<Vec<_>>()
                .join(",");
            (Some(avg_wl), Some(cr), Some(punct_str))
        } else {
            (None, None, None)
        };

        // Serialize full fingerprint to JSON for cloud sync
        let author_fp = mgr.current_author_fingerprint();
        let serialized_json =
            serde_json::to_string(&author_fp).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));

        Ok(FfiFingerprintSummary {
            success: true,
            avg_wpm,
            iki_mean_ms: iki_mean,
            iki_std_dev_ms: iki_std_dev,
            dominant_zone,
            peak_hour,
            sentence_pause_mean_ms: sentence_pause_mean,
            thinking_pause_mean_ms: thinking_pause_mean,
            avg_word_length,
            correction_rate,
            top_punctuation,
            serialized_json,
            error_message: None,
        })
    }) {
        Ok(s) => s,
        Err(e) => FfiFingerprintSummary {
            success: false,
            avg_wpm: 0.0,
            iki_mean_ms: 0.0,
            iki_std_dev_ms: 0.0,
            dominant_zone: String::new(),
            peak_hour: 0,
            sentence_pause_mean_ms: 0.0,
            thinking_pause_mean_ms: 0.0,
            avg_word_length: None,
            correction_rate: None,
            top_punctuation: None,
            serialized_json: String::new(),
            error_message: Some(e),
        },
    }
}

/// Grant voice consent — calls ConsentManager::grant_consent().
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_grant_voice_consent() -> FfiConsentResult {
    match with_manager(|mgr| {
        mgr.consent_manager
            .grant_consent()
            .map_err(|e| format!("Failed to grant consent: {e}"))?;
        mgr.enable_voice()
            .map_err(|e| format!("Failed to enable voice: {e}"))?;

        let explanation = mgr.consent_manager.get_explanation().to_string();
        let version = mgr.consent_manager.get_version().to_string();
        Ok(FfiConsentResult {
            success: true,
            granted: true,
            consent_version: version,
            explanation,
            error_message: None,
        })
    }) {
        Ok(r) => r,
        Err(e) => FfiConsentResult {
            success: false,
            granted: false,
            consent_version: String::new(),
            explanation: String::new(),
            error_message: Some(e),
        },
    }
}

/// Revoke voice consent — calls FingerprintManager::disable_voice().
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_revoke_voice_consent() -> FfiResult {
    match with_manager(|mgr| {
        mgr.disable_voice()
            .map_err(|e| format!("Failed to revoke consent: {e}"))?;
        Ok(FfiResult {
            success: true,
            message: Some("Voice fingerprinting disabled and data deleted".into()),
            error_message: None,
        })
    }) {
        Ok(r) => r,
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(e),
        },
    }
}

/// Reset all fingerprint data (activity + voice).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_reset_fingerprint() -> FfiResult {
    match with_manager(|mgr| {
        mgr.reset_session();
        // Delete all stored profiles
        let profiles = mgr
            .list_profiles()
            .map_err(|e| format!("Failed to list profiles: {e}"))?;
        for p in profiles {
            mgr.delete(&p.id)
                .map_err(|e| format!("Failed to delete profile {}: {e}", p.id))?;
        }
        Ok(FfiResult {
            success: true,
            message: Some("All fingerprint data reset".into()),
            error_message: None,
        })
    }) {
        Ok(r) => r,
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(e),
        },
    }
}

/// Export fingerprint as JSON for cloud upload.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_fingerprint_json() -> FfiResult {
    match with_manager(|mgr| {
        let author_fp = mgr.current_author_fingerprint();
        let json = serde_json::to_string_pretty(&author_fp)
            .map_err(|e| format!("Serialization failed: {e}"))?;
        Ok(FfiResult {
            success: true,
            message: Some(json),
            error_message: None,
        })
    }) {
        Ok(r) => r,
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(e),
        },
    }
}
