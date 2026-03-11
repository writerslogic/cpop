// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::ffi::helpers::open_store;
use crate::ffi::types::{FfiCalibrationResult, FfiForensicResult, FfiProcessScore};
use std::time::Duration;

/// Weights for composite process score (sum = 1.0).
///
/// Per draft-condrey-rats-pop §6.2 (informative), the process score is:
///   PS = w_r * regularity + w_s * swf-strength + w_b * behavioral-consistency
/// with configurable weights summing to 1.0. Our mapping:
///   - WEIGHT_RESIDENCY (w_r=0.3): event regularity / minimum event count
///   - WEIGHT_SEQUENCE  (w_s=0.3): edit entropy + non-monotonic ratio (SWF-strength proxy)
///   - WEIGHT_BEHAVIORAL(w_b=0.4): forensic assessment consistency
///
/// Behavioral consistency receives the largest weight because the forensic
/// engine's `Assessment::Consistent` verdict integrates the most evidence
/// signals (anomaly detection, cross-modal coherence, cadence analysis).
const WEIGHT_RESIDENCY: f64 = 0.3;
const WEIGHT_SEQUENCE: f64 = 0.3;
const WEIGHT_BEHAVIORAL: f64 = 0.4;
/// Minimum composite score to pass verification.
const COMPOSITE_PASS_THRESHOLD: f64 = 0.9;

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_forensics(path: String) -> FfiForensicResult {
    let path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => {
            return FfiForensicResult {
                success: false,
                assessment_score: 0.0,
                risk_level: "unknown".to_string(),
                anomaly_count: 0,
                monotonic_append_ratio: 0.0,
                edit_entropy: 0.0,
                median_interval: 0.0,
                error_message: Some(e),
            };
        }
    };

    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiForensicResult {
                success: false,
                assessment_score: 0.0,
                risk_level: "unknown".to_string(),
                anomaly_count: 0,
                monotonic_append_ratio: 0.0,
                edit_entropy: 0.0,
                median_interval: 0.0,
                error_message: Some(e),
            };
        }
    };

    let events = match store.get_events_for_file(&path) {
        Ok(e) => e,
        Err(e) => {
            return FfiForensicResult {
                success: false,
                assessment_score: 0.0,
                risk_level: "unknown".to_string(),
                anomaly_count: 0,
                monotonic_append_ratio: 0.0,
                edit_entropy: 0.0,
                median_interval: 0.0,
                error_message: Some(format!("Failed to load events: {}", e)),
            };
        }
    };

    if events.is_empty() {
        return FfiForensicResult {
            success: false,
            assessment_score: 0.0,
            risk_level: "unknown".to_string(),
            anomaly_count: 0,
            monotonic_append_ratio: 0.0,
            edit_entropy: 0.0,
            median_interval: 0.0,
            error_message: Some("No events found for this file".to_string()),
        };
    }

    let profile = crate::forensics::ForensicEngine::evaluate_authorship(&path, &events);

    let event_data: Vec<crate::forensics::EventData> = events
        .iter()
        .map(|e| crate::forensics::EventData {
            id: e.id.unwrap_or(0),
            timestamp_ns: e.timestamp_ns,
            file_size: e.file_size,
            size_delta: e.size_delta,
            file_path: e.file_path.clone(),
        })
        .collect();
    let mut regions = std::collections::HashMap::new();
    for e in &events {
        if let Some(id) = e.id {
            let delta = e.size_delta;
            let sign = if delta > 0 {
                1
            } else if delta < 0 {
                -1
            } else {
                0
            };
            regions.insert(
                id,
                vec![crate::forensics::RegionData {
                    start_pct: 1.0,
                    end_pct: 1.0,
                    delta_sign: sign,
                    byte_count: delta.abs(),
                }],
            );
        }
    }
    let forensic_metrics =
        crate::forensics::analyze_forensics(&event_data, &regions, None, None, None);

    FfiForensicResult {
        success: true,
        assessment_score: forensic_metrics.assessment_score,
        risk_level: profile.assessment.to_string().to_lowercase(),
        anomaly_count: profile.anomalies.len() as u32,
        monotonic_append_ratio: profile.metrics.monotonic_append_ratio,
        edit_entropy: profile.metrics.edit_entropy,
        median_interval: profile.metrics.median_interval,
        error_message: None,
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_compute_process_score(path: String) -> FfiProcessScore {
    let path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => {
            return FfiProcessScore {
                success: false,
                residency: 0.0,
                sequence: 0.0,
                behavioral: 0.0,
                composite: 0.0,
                meets_threshold: false,
                error_message: Some(e),
            };
        }
    };

    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiProcessScore {
                success: false,
                residency: 0.0,
                sequence: 0.0,
                behavioral: 0.0,
                composite: 0.0,
                meets_threshold: false,
                error_message: Some(e),
            };
        }
    };

    let events = match store.get_events_for_file(&path) {
        Ok(e) => e,
        Err(e) => {
            return FfiProcessScore {
                success: false,
                residency: 0.0,
                sequence: 0.0,
                behavioral: 0.0,
                composite: 0.0,
                meets_threshold: false,
                error_message: Some(format!("Failed to load events: {}", e)),
            };
        }
    };

    if events.is_empty() {
        return FfiProcessScore {
            success: false,
            residency: 0.0,
            sequence: 0.0,
            behavioral: 0.0,
            composite: 0.0,
            meets_threshold: false,
            error_message: Some("No events found for this file".to_string()),
        };
    }

    let profile = crate::forensics::ForensicEngine::evaluate_authorship(&path, &events);

    let residency = if events.len() >= 5 {
        1.0
    } else {
        events.len() as f64 / 5.0
    };

    let sequence = (profile.metrics.edit_entropy.min(3.0) / 3.0 * 0.5)
        + ((1.0 - profile.metrics.monotonic_append_ratio) * 0.5);

    let behavioral = if profile.assessment == crate::forensics::Assessment::Consistent {
        1.0
    } else {
        0.3
    };

    let composite =
        WEIGHT_RESIDENCY * residency + WEIGHT_SEQUENCE * sequence + WEIGHT_BEHAVIORAL * behavioral;
    let meets_threshold = composite >= COMPOSITE_PASS_THRESHOLD;

    FfiProcessScore {
        success: true,
        residency,
        sequence,
        behavioral,
        composite,
        meets_threshold,
        error_message: None,
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_calibrate_swf() -> FfiCalibrationResult {
    match crate::vdf::calibrate(Duration::from_secs(1)) {
        Ok(params) => FfiCalibrationResult {
            success: true,
            iterations_per_second: params.iterations_per_second,
            error_message: None,
        },
        Err(e) => FfiCalibrationResult {
            success: false,
            iterations_per_second: 0,
            error_message: Some(format!("Calibration failed: {}", e)),
        },
    }
}
