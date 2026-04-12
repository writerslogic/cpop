// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Synthetic event detection and dual-layer HID validation.

use super::ffi::*;
use super::EventVerificationResult;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

use crate::RwLockRecover;

use super::DualLayerValidation;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyntheticEventStats {
    pub total_events: u64,
    pub verified_hardware: u64,
    pub rejected_synthetic: u64,
    pub suspicious_accepted: u64,
    pub rejected_bad_source_state: u64,
    pub rejected_bad_keyboard_type: u64,
    pub rejected_non_kernel_pid: u64,
    pub rejected_zero_timestamp: u64,
}

static SYNTHETIC_STATS: RwLock<SyntheticEventStats> = RwLock::new(SyntheticEventStats {
    total_events: 0,
    verified_hardware: 0,
    rejected_synthetic: 0,
    suspicious_accepted: 0,
    rejected_bad_source_state: 0,
    rejected_bad_keyboard_type: 0,
    rejected_non_kernel_pid: 0,
    rejected_zero_timestamp: 0,
});

static STRICT_MODE: AtomicBool = AtomicBool::new(true);

/// In strict mode suspicious events are rejected; in permissive mode they're accepted but flagged.
pub fn set_strict_mode(strict: bool) {
    STRICT_MODE.store(strict, Ordering::SeqCst);
}

pub fn get_strict_mode() -> bool {
    STRICT_MODE.load(Ordering::SeqCst)
}

pub fn get_synthetic_stats() -> SyntheticEventStats {
    SYNTHETIC_STATS.read_recover().clone()
}

pub fn reset_synthetic_stats() {
    let mut stats = SYNTHETIC_STATS.write_recover();
    *stats = SyntheticEventStats::default();
}

/// Detects CGEventPost injection by checking source state, keyboard type, and PID.
///
/// # Safety
///
/// `event` must be a valid `CGEventRef` obtained from a CGEventTap callback.
pub unsafe fn verify_event_source(event: *mut std::ffi::c_void) -> EventVerificationResult {
    let strict = STRICT_MODE.load(Ordering::SeqCst);

    let source_state_id = CGEventGetIntegerValueField(event, K_CG_EVENT_SOURCE_STATE_ID);
    let keyboard_type = CGEventGetIntegerValueField(event, K_CG_KEYBOARD_EVENT_KEYBOARD_TYPE);
    let source_pid = CGEventGetIntegerValueField(event, K_CG_EVENT_SOURCE_UNIX_PROCESS_ID);

    let mut suspicious = false;

    // Private source state = programmatic injection
    if source_state_id == K_CG_EVENT_SOURCE_STATE_PRIVATE {
        let mut stats = SYNTHETIC_STATS.write_recover();
        stats.total_events += 1;
        stats.rejected_synthetic += 1;
        stats.rejected_bad_source_state += 1;
        return EventVerificationResult::Synthetic;
    }

    if source_state_id != K_CG_EVENT_SOURCE_STATE_HID_SYSTEM {
        suspicious = true;
    }

    // Real keyboards report type (ANSI=40, ISO=41, JIS=42); synthetic events use 0
    if keyboard_type == 0 {
        if strict {
            let mut stats = SYNTHETIC_STATS.write_recover();
            stats.total_events += 1;
            stats.rejected_synthetic += 1;
            stats.rejected_bad_keyboard_type += 1;
            return EventVerificationResult::Synthetic;
        }
        suspicious = true;
    }

    if keyboard_type > 100 {
        let mut stats = SYNTHETIC_STATS.write_recover();
        stats.total_events += 1;
        stats.rejected_synthetic += 1;
        stats.rejected_bad_keyboard_type += 1;
        return EventVerificationResult::Synthetic;
    }

    // Hardware events have PID 0 (kernel); CGEventPost carries the injector's PID
    if source_pid != 0 {
        if strict {
            let mut stats = SYNTHETIC_STATS.write_recover();
            stats.total_events += 1;
            stats.rejected_synthetic += 1;
            stats.rejected_non_kernel_pid += 1;
            return EventVerificationResult::Synthetic;
        }
        suspicious = true;
    }

    let mut stats = SYNTHETIC_STATS.write_recover();
    stats.total_events += 1;
    if suspicious {
        stats.suspicious_accepted += 1;
        EventVerificationResult::Suspicious
    } else {
        stats.verified_hardware += 1;
        EventVerificationResult::Hardware
    }
}

/// Compares CGEventTap count against IOKit HID count to detect injected events.
///
/// When `hid_count` is 0 (HID capture not running), returns `synthetic_detected: false`
/// since there is no ground truth to compare against.
pub fn validate_dual_layer(cg_count: u64, hid_count: u64) -> DualLayerValidation {
    if hid_count == 0 {
        return DualLayerValidation {
            high_level_count: cg_count,
            low_level_count: 0,
            synthetic_detected: false,
            discrepancy: 0,
        };
    }

    let cg_i64 = i64::try_from(cg_count).unwrap_or(i64::MAX);
    let hid_i64 = i64::try_from(hid_count).unwrap_or(i64::MAX);
    let discrepancy = cg_i64.saturating_sub(hid_i64);

    // Small discrepancies are normal due to timing; flag only >10% excess
    let synthetic_detected =
        discrepancy > 5 && (discrepancy as f64 / hid_count.max(1) as f64) > 0.1;

    DualLayerValidation {
        high_level_count: cg_count,
        low_level_count: hid_count,
        synthetic_detected,
        discrepancy,
    }
}
