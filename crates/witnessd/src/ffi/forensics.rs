// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial


use crate::ffi::types::{FfiCalibrationResult, FfiProcessScore};
use crate::vdf::Parameters;
use std::sync::Mutex;
use std::time::Duration;

static CALIBRATED_PARAMS: Mutex<Option<Parameters>> = Mutex::new(None);

pub(crate) fn calibrated_params() -> Option<Parameters> {
    *CALIBRATED_PARAMS.lock().unwrap_or_else(|e| {
        log::error!("calibrated params mutex poisoned: {e}");
        e.into_inner()
    })
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_compute_process_score(path: String) -> FfiProcessScore {
    let (_path, _store, events) = match crate::ffi::helpers::load_events_for_path(&path) {
        Ok(v) => v,
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

    let residency = if events.len() >= crate::forensics::MIN_EVENTS_FOR_RESIDENCY {
        1.0
    } else {
        events.len() as f64 / crate::forensics::MIN_EVENTS_FOR_RESIDENCY as f64
    };

    let sequence = (profile.metrics.edit_entropy.min(3.0) / 3.0 * 0.5)
        + ((1.0 - profile.metrics.monotonic_append_ratio.get()) * 0.5);

    let behavioral = if profile.assessment == crate::forensics::Assessment::Consistent {
        1.0
    } else {
        0.3
    };

    let composite = crate::forensics::PROCESS_SCORE_WEIGHT_RESIDENCY * residency
        + crate::forensics::PROCESS_SCORE_WEIGHT_SEQUENCE * sequence
        + crate::forensics::PROCESS_SCORE_WEIGHT_BEHAVIORAL * behavioral;
    let meets_threshold = composite >= crate::forensics::PROCESS_SCORE_PASS_THRESHOLD;

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
        Ok(params) => {
            // Defense-in-depth: validate even though calibrate() now checks internally.
            let ips = params.iterations_per_second;
            let valid_range = crate::vdf::CALIBRATION_MIN_ITERS_PER_SEC
                ..=crate::vdf::CALIBRATION_MAX_ITERS_PER_SEC;
            if !valid_range.contains(&ips) {
                return FfiCalibrationResult {
                    success: false,
                    iterations_per_second: 0,
                    error_message: Some(format!(
                        "Calibration result out of bounds: {ips} iter/s \
                         (expected {}..={})",
                        crate::vdf::CALIBRATION_MIN_ITERS_PER_SEC,
                        crate::vdf::CALIBRATION_MAX_ITERS_PER_SEC,
                    )),
                };
            }
            {
                let mut cached = CALIBRATED_PARAMS.lock().unwrap_or_else(|e| {
                    log::error!("calibrated params mutex poisoned: {e}");
                    e.into_inner()
                });
                *cached = Some(params);
            }
            FfiCalibrationResult {
                success: true,
                iterations_per_second: ips,
                error_message: None,
            }
        }
        Err(e) => FfiCalibrationResult {
            success: false,
            iterations_per_second: 0,
            error_message: Some(format!("Calibration failed: {}", e)),
        },
    }
}
