// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};

/// Counters for synthetic event detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyntheticStats {
    pub total_events: u64,
    pub verified_hardware: u64,
    pub rejected_synthetic: u64,
    pub suspicious_accepted: u64,
    pub rejection_reasons: RejectionReasons,
}

impl SyntheticStats {
    pub fn hardware_ratio(&self) -> f64 {
        if self.total_events == 0 {
            1.0
        } else {
            self.verified_hardware as f64 / self.total_events as f64
        }
    }

    pub fn synthetic_ratio(&self) -> f64 {
        if self.total_events == 0 {
            0.0
        } else {
            self.rejected_synthetic as f64 / self.total_events as f64
        }
    }

    pub fn injection_detected(&self) -> bool {
        self.rejected_synthetic > 0
    }

    pub fn merge(&mut self, other: &SyntheticStats) {
        self.total_events += other.total_events;
        self.verified_hardware += other.verified_hardware;
        self.rejected_synthetic += other.rejected_synthetic;
        self.suspicious_accepted += other.suspicious_accepted;
        self.rejection_reasons.merge(&other.rejection_reasons);
    }
}

/// Per-category rejection counters for synthetic event analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RejectionReasons {
    pub bad_source_state: u64,
    pub bad_keyboard_type: u64,
    pub non_kernel_pid: u64,
    pub zero_timestamp: u64,
    pub virtual_device: u64,
    pub empty_phys_path: u64,
    pub invalid_vid_pid: u64,
    pub injected_flag: u64,
    pub statistical_robotic: u64,
    pub statistical_superhuman: u64,
    pub statistical_replay: u64,
}

impl RejectionReasons {
    pub fn merge(&mut self, other: &RejectionReasons) {
        self.bad_source_state += other.bad_source_state;
        self.bad_keyboard_type += other.bad_keyboard_type;
        self.non_kernel_pid += other.non_kernel_pid;
        self.zero_timestamp += other.zero_timestamp;
        self.virtual_device += other.virtual_device;
        self.empty_phys_path += other.empty_phys_path;
        self.invalid_vid_pid += other.invalid_vid_pid;
        self.injected_flag += other.injected_flag;
        self.statistical_robotic += other.statistical_robotic;
        self.statistical_superhuman += other.statistical_superhuman;
        self.statistical_replay += other.statistical_replay;
    }
}

/// Classification of an event's origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventVerificationResult {
    Hardware,
    Synthetic,
    Suspicious,
}

impl EventVerificationResult {
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Hardware | Self::Suspicious)
    }

    pub fn is_hardware(&self) -> bool {
        matches!(self, Self::Hardware)
    }
}

/// Dual-layer (high-level API vs low-level HID) keystroke count comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualLayerValidation {
    pub high_level_count: u64,
    pub low_level_count: u64,
    pub synthetic_detected: bool,
    pub discrepancy: i64,
}

impl DualLayerValidation {
    pub fn discrepancy_ratio(&self) -> f64 {
        if self.low_level_count == 0 {
            if self.high_level_count == 0 {
                0.0
            } else {
                1.0
            }
        } else {
            self.discrepancy.abs() as f64 / self.low_level_count as f64
        }
    }
}
