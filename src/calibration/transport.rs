//! Transport-specific calibration for per-transport baseline latency.
//!
//! This module provides calibration functionality to measure and store
//! baseline latency characteristics for different input transport types
//! (USB, Bluetooth, internal, etc.).

use crate::platform::types::TransportType;
use crate::rfc::jitter_binding::TransportCalibration;
use std::collections::HashMap;

/// Calibrator for measuring per-transport baseline latency.
///
/// Collects interval samples and computes baseline metrics for each
/// transport type encountered during keystroke capture.
pub struct TransportCalibrator {
    /// Samples per transport type (intervals in microseconds).
    samples: HashMap<TransportType, Vec<u64>>,
    /// Minimum samples required for valid calibration.
    min_samples: usize,
    /// Maximum samples to retain per transport.
    max_samples: usize,
}

impl TransportCalibrator {
    /// Create a new transport calibrator.
    ///
    /// # Arguments
    /// * `min_samples` - Minimum samples required before calibration is valid
    /// * `max_samples` - Maximum samples to retain per transport (rolling window)
    pub fn new(min_samples: usize, max_samples: usize) -> Self {
        Self {
            samples: HashMap::new(),
            min_samples,
            max_samples,
        }
    }

    /// Create a calibrator with default settings.
    pub fn with_defaults() -> Self {
        Self::new(50, 1000)
    }

    /// Record an interval sample for a transport type.
    ///
    /// # Arguments
    /// * `transport` - The transport type for this sample
    /// * `interval_us` - The keystroke interval in microseconds
    pub fn record_sample(&mut self, transport: TransportType, interval_us: u64) {
        let samples = self.samples.entry(transport).or_default();
        samples.push(interval_us);

        // Trim to max_samples (keep most recent)
        if samples.len() > self.max_samples {
            let excess = samples.len() - self.max_samples;
            samples.drain(0..excess);
        }
    }

    /// Check if calibration is available for a transport type.
    pub fn is_calibrated(&self, transport: TransportType) -> bool {
        self.samples
            .get(&transport)
            .is_some_and(|s| s.len() >= self.min_samples)
    }

    /// Get calibration data for a transport type.
    ///
    /// Returns None if insufficient samples are available.
    pub fn get_calibration(&self, transport: TransportType) -> Option<TransportCalibration> {
        let samples = self.samples.get(&transport)?;
        if samples.len() < self.min_samples {
            return None;
        }

        // Baseline = minimum observed interval
        let baseline = *samples.iter().min()?;

        // Calculate variance
        let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / samples.len() as f64;
        let variance: f64 = samples
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / samples.len() as f64;
        let std_dev = variance.sqrt();

        let now_ms = chrono::Utc::now().timestamp_millis() as u64;

        Some(TransportCalibration {
            transport: transport.as_str().to_string(),
            baseline_latency_us: baseline,
            latency_variance_us: std_dev as u64,
            calibrated_at_ms: now_ms,
        })
    }

    /// Get all available calibrations.
    pub fn all_calibrations(&self) -> HashMap<TransportType, TransportCalibration> {
        self.samples
            .keys()
            .filter_map(|&transport| self.get_calibration(transport).map(|cal| (transport, cal)))
            .collect()
    }

    /// Get the number of samples for a transport type.
    pub fn sample_count(&self, transport: TransportType) -> usize {
        self.samples.get(&transport).map_or(0, |s| s.len())
    }

    /// Clear all samples for a transport type.
    pub fn clear(&mut self, transport: TransportType) {
        self.samples.remove(&transport);
    }

    /// Clear all samples.
    pub fn clear_all(&mut self) {
        self.samples.clear();
    }
}

impl Default for TransportCalibrator {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calibrator_basic() {
        let mut cal = TransportCalibrator::new(5, 100);

        // Not enough samples yet
        assert!(!cal.is_calibrated(TransportType::Usb));
        assert!(cal.get_calibration(TransportType::Usb).is_none());

        // Add samples
        for interval in [10000, 15000, 12000, 11000, 13000] {
            cal.record_sample(TransportType::Usb, interval);
        }

        assert!(cal.is_calibrated(TransportType::Usb));
        let calib = cal.get_calibration(TransportType::Usb).unwrap();

        assert_eq!(calib.transport, "usb");
        assert_eq!(calib.baseline_latency_us, 10000); // Minimum
    }

    #[test]
    fn test_calibrator_multiple_transports() {
        let mut cal = TransportCalibrator::new(3, 100);

        // USB samples
        for interval in [10000, 11000, 12000] {
            cal.record_sample(TransportType::Usb, interval);
        }

        // Bluetooth samples (typically higher latency)
        for interval in [20000, 22000, 21000] {
            cal.record_sample(TransportType::Bluetooth, interval);
        }

        let usb_cal = cal.get_calibration(TransportType::Usb).unwrap();
        let bt_cal = cal.get_calibration(TransportType::Bluetooth).unwrap();

        assert_eq!(usb_cal.baseline_latency_us, 10000);
        assert_eq!(bt_cal.baseline_latency_us, 20000);

        // Bluetooth should have higher baseline
        assert!(bt_cal.baseline_latency_us > usb_cal.baseline_latency_us);
    }

    #[test]
    fn test_calibrator_rolling_window() {
        let mut cal = TransportCalibrator::new(2, 5);

        // Add 10 samples
        for i in 0..10 {
            cal.record_sample(TransportType::Internal, i * 1000);
        }

        // Should only retain last 5
        assert_eq!(cal.sample_count(TransportType::Internal), 5);

        // Baseline should be from the retained samples (5000-9000)
        let calib = cal.get_calibration(TransportType::Internal).unwrap();
        assert_eq!(calib.baseline_latency_us, 5000);
    }

    #[test]
    fn test_transport_type_parsing() {
        assert_eq!(
            TransportType::from_linux_phys(Some("usb-0000:00:14.0-4/input0")),
            TransportType::Usb
        );
        assert_eq!(
            TransportType::from_linux_phys(Some("bluetooth")),
            TransportType::Bluetooth
        );
        assert_eq!(
            TransportType::from_linux_phys(Some("isa0060/serio0/input0")),
            TransportType::Internal
        );
        assert_eq!(TransportType::from_linux_phys(None), TransportType::Virtual);
    }
}
