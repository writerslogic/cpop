//! Cross-platform statistical synthetic event detection.
//!
//! This module provides statistical analysis methods to detect synthetic
//! (automated/injected) keystrokes that may bypass platform-specific checks.
//!
//! Detection methods:
//! - Coefficient of Variation (CV) analysis - robotic timing detection
//! - Inter-Key Interval (IKI) analysis - superhuman speed detection
//! - Timing pattern analysis - replay attack detection

use super::types::{KeystrokeEvent, RejectionReasons, SyntheticStats};
use std::collections::VecDeque;

// =============================================================================
// Constants
// =============================================================================

/// Minimum coefficient of variation for human typing (below this is robotic)
const MIN_HUMAN_CV: f64 = 0.15;

/// Minimum inter-key interval in milliseconds (below this is superhuman)
const MIN_HUMAN_IKI_MS: f64 = 20.0;

/// Maximum inter-key interval for burst analysis (milliseconds)
#[allow(dead_code)]
const MAX_BURST_IKI_MS: f64 = 500.0;

/// Window size for statistical analysis
const ANALYSIS_WINDOW_SIZE: usize = 50;

/// Minimum samples needed for reliable analysis
const MIN_SAMPLES_FOR_ANALYSIS: usize = 10;

/// Replay detection: maximum allowed timing pattern repetition ratio
const MAX_PATTERN_REPETITION_RATIO: f64 = 0.8;

// =============================================================================
// Statistical Anomaly Detector
// =============================================================================

/// Statistical anomaly detector for synthetic event detection.
pub struct StatisticalAnomalyDetector {
    /// Recent inter-key intervals (in milliseconds)
    iki_window: VecDeque<f64>,
    /// Baseline mean IKI (learned from initial samples)
    baseline_mean: Option<f64>,
    /// Baseline standard deviation
    baseline_std: Option<f64>,
    /// Last event timestamp
    last_timestamp_ns: Option<i64>,
    /// Statistics
    stats: SyntheticStats,
    /// Rejection reasons
    rejection_reasons: RejectionReasons,
}

impl StatisticalAnomalyDetector {
    /// Create a new statistical anomaly detector.
    pub fn new() -> Self {
        Self {
            iki_window: VecDeque::with_capacity(ANALYSIS_WINDOW_SIZE),
            baseline_mean: None,
            baseline_std: None,
            last_timestamp_ns: None,
            stats: SyntheticStats::default(),
            rejection_reasons: RejectionReasons::default(),
        }
    }

    /// Analyze a keystroke event and return whether it appears synthetic.
    pub fn analyze(&mut self, event: &KeystrokeEvent) -> StatisticalResult {
        self.stats.total_events += 1;

        // Calculate IKI if we have a previous timestamp
        let iki_ms = if let Some(last_ts) = self.last_timestamp_ns {
            let delta_ns = event.timestamp_ns - last_ts;
            if delta_ns <= 0 {
                // Timestamp error or same event
                self.last_timestamp_ns = Some(event.timestamp_ns);
                return StatisticalResult::Insufficient;
            }
            delta_ns as f64 / 1_000_000.0
        } else {
            self.last_timestamp_ns = Some(event.timestamp_ns);
            return StatisticalResult::Insufficient;
        };

        self.last_timestamp_ns = Some(event.timestamp_ns);

        // Add to window
        if self.iki_window.len() >= ANALYSIS_WINDOW_SIZE {
            self.iki_window.pop_front();
        }
        self.iki_window.push_back(iki_ms);

        // Not enough data yet
        if self.iki_window.len() < MIN_SAMPLES_FOR_ANALYSIS {
            return StatisticalResult::Insufficient;
        }

        // Perform analysis
        let mut flags = AnomalyFlags::default();

        // Check 1: Superhuman speed
        if iki_ms < MIN_HUMAN_IKI_MS {
            flags.superhuman_speed = true;
            self.rejection_reasons.statistical_superhuman += 1;
        }

        // Check 2: Calculate CV for the window
        let (mean, std) = self.calculate_mean_std();
        let cv = if mean > 0.0 { std / mean } else { 0.0 };

        // Update baseline if not set
        if self.baseline_mean.is_none() && self.iki_window.len() >= ANALYSIS_WINDOW_SIZE / 2 {
            self.baseline_mean = Some(mean);
            self.baseline_std = Some(std);
        }

        if cv < MIN_HUMAN_CV {
            flags.robotic_timing = true;
            self.rejection_reasons.statistical_robotic += 1;
        }

        // Check 3: Replay pattern detection
        if self.detect_replay_pattern() {
            flags.replay_pattern = true;
            self.rejection_reasons.statistical_replay += 1;
        }

        // Determine result
        if flags.has_critical_anomaly() {
            self.stats.rejected_synthetic += 1;
            StatisticalResult::Synthetic(flags)
        } else if flags.has_any_anomaly() {
            self.stats.suspicious_accepted += 1;
            StatisticalResult::Suspicious(flags)
        } else {
            self.stats.verified_hardware += 1;
            StatisticalResult::Normal
        }
    }

    /// Calculate mean and standard deviation of the IKI window.
    fn calculate_mean_std(&self) -> (f64, f64) {
        if self.iki_window.is_empty() {
            return (0.0, 0.0);
        }

        let n = self.iki_window.len() as f64;
        let mean = self.iki_window.iter().sum::<f64>() / n;
        let variance = self
            .iki_window
            .iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>()
            / n;
        let std = variance.sqrt();

        (mean, std)
    }

    /// Detect replay attack patterns (repeated timing sequences).
    fn detect_replay_pattern(&self) -> bool {
        if self.iki_window.len() < 20 {
            return false;
        }

        // Look for repeated subsequences
        let ikis: Vec<f64> = self.iki_window.iter().copied().collect();
        let tolerance_ms = 5.0; // Allow 5ms tolerance for matching

        // Check for repeating patterns of length 5-10
        for pattern_len in 5..=10 {
            if ikis.len() < pattern_len * 2 {
                continue;
            }

            let pattern = &ikis[..pattern_len];
            let mut matches = 0;
            let mut checks = 0;

            for i in (pattern_len..ikis.len()).step_by(pattern_len) {
                if i + pattern_len > ikis.len() {
                    break;
                }

                checks += 1;
                let candidate = &ikis[i..i + pattern_len];

                if pattern
                    .iter()
                    .zip(candidate.iter())
                    .all(|(a, b)| (a - b).abs() < tolerance_ms)
                {
                    matches += 1;
                }
            }

            if checks > 0 && (matches as f64 / checks as f64) > MAX_PATTERN_REPETITION_RATIO {
                return true;
            }
        }

        false
    }

    /// Get current statistics.
    pub fn stats(&self) -> &SyntheticStats {
        &self.stats
    }

    /// Get rejection reasons.
    pub fn rejection_reasons(&self) -> &RejectionReasons {
        &self.rejection_reasons
    }

    /// Reset the detector state.
    pub fn reset(&mut self) {
        self.iki_window.clear();
        self.baseline_mean = None;
        self.baseline_std = None;
        self.last_timestamp_ns = None;
        self.stats = SyntheticStats::default();
        self.rejection_reasons = RejectionReasons::default();
    }

    /// Get the current coefficient of variation.
    pub fn current_cv(&self) -> Option<f64> {
        if self.iki_window.len() < MIN_SAMPLES_FOR_ANALYSIS {
            return None;
        }
        let (mean, std) = self.calculate_mean_std();
        if mean > 0.0 {
            Some(std / mean)
        } else {
            None
        }
    }

    /// Get the mean IKI in milliseconds.
    pub fn mean_iki_ms(&self) -> Option<f64> {
        if self.iki_window.is_empty() {
            None
        } else {
            Some(self.iki_window.iter().sum::<f64>() / self.iki_window.len() as f64)
        }
    }
}

impl Default for StatisticalAnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Analysis Results
// =============================================================================

/// Result of statistical analysis.
#[derive(Debug, Clone)]
pub enum StatisticalResult {
    /// Not enough data for analysis
    Insufficient,
    /// Event appears normal (human)
    Normal,
    /// Event has suspicious characteristics but not conclusively synthetic
    Suspicious(AnomalyFlags),
    /// Event appears synthetic
    Synthetic(AnomalyFlags),
}

impl StatisticalResult {
    /// Check if the event should be accepted.
    pub fn is_accepted(&self) -> bool {
        matches!(
            self,
            Self::Insufficient | Self::Normal | Self::Suspicious(_)
        )
    }

    /// Check if the event appears synthetic.
    pub fn is_synthetic(&self) -> bool {
        matches!(self, Self::Synthetic(_))
    }
}

/// Flags indicating detected anomalies.
#[derive(Debug, Clone, Default)]
pub struct AnomalyFlags {
    /// Superhuman typing speed (IKI < 20ms)
    pub superhuman_speed: bool,
    /// Robotic timing (CV < 0.15)
    pub robotic_timing: bool,
    /// Replay pattern detected
    pub replay_pattern: bool,
}

impl AnomalyFlags {
    /// Check if any critical anomaly is present.
    pub fn has_critical_anomaly(&self) -> bool {
        self.superhuman_speed || (self.robotic_timing && self.replay_pattern)
    }

    /// Check if any anomaly is present.
    pub fn has_any_anomaly(&self) -> bool {
        self.superhuman_speed || self.robotic_timing || self.replay_pattern
    }
}

// =============================================================================
// Combined Synthetic Detector
// =============================================================================

/// Combined synthetic event detector using platform-specific and statistical methods.
pub struct SyntheticDetector {
    /// Statistical anomaly detector
    statistical: StatisticalAnomalyDetector,
    /// Whether to use strict mode
    strict_mode: bool,
}

impl SyntheticDetector {
    /// Create a new combined synthetic detector.
    pub fn new() -> Self {
        Self {
            statistical: StatisticalAnomalyDetector::new(),
            strict_mode: true,
        }
    }

    /// Analyze a keystroke event.
    ///
    /// This combines platform-specific verification (from `event.is_hardware`)
    /// with statistical analysis.
    pub fn analyze(&mut self, event: &KeystrokeEvent) -> DetectionResult {
        // Platform-level check
        let platform_result = if event.is_hardware {
            PlatformResult::Hardware
        } else {
            PlatformResult::Synthetic
        };

        // Statistical analysis
        let statistical_result = self.statistical.analyze(event);

        // Combine results
        match (&platform_result, &statistical_result) {
            // Both agree it's good
            (PlatformResult::Hardware, StatisticalResult::Normal) => DetectionResult::Verified,
            (PlatformResult::Hardware, StatisticalResult::Insufficient) => {
                DetectionResult::Verified
            }

            // Platform says synthetic
            (PlatformResult::Synthetic, _) => DetectionResult::Synthetic {
                reason: SyntheticReason::PlatformDetected,
            },

            // Statistical says synthetic
            (_, StatisticalResult::Synthetic(flags)) => {
                if self.strict_mode {
                    DetectionResult::Synthetic {
                        reason: if flags.superhuman_speed {
                            SyntheticReason::SuperhumanSpeed
                        } else if flags.robotic_timing {
                            SyntheticReason::RoboticTiming
                        } else {
                            SyntheticReason::ReplayPattern
                        },
                    }
                } else {
                    DetectionResult::Suspicious {
                        flags: flags.clone(),
                    }
                }
            }

            // Suspicious
            (_, StatisticalResult::Suspicious(flags)) => DetectionResult::Suspicious {
                flags: flags.clone(),
            },
        }
    }

    /// Set strict mode.
    pub fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }

    /// Get strict mode.
    pub fn get_strict_mode(&self) -> bool {
        self.strict_mode
    }

    /// Get combined statistics.
    pub fn stats(&self) -> SyntheticStats {
        let mut stats = self.statistical.stats().clone();
        stats.rejection_reasons = self.statistical.rejection_reasons().clone();
        stats
    }

    /// Reset the detector.
    pub fn reset(&mut self) {
        self.statistical.reset();
    }
}

impl Default for SyntheticDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Platform-level verification result.
#[derive(Debug, Clone)]
enum PlatformResult {
    Hardware,
    Synthetic,
}

/// Combined detection result.
#[derive(Debug, Clone)]
pub enum DetectionResult {
    /// Event is verified as human-generated
    Verified,
    /// Event is suspicious but accepted
    Suspicious { flags: AnomalyFlags },
    /// Event is detected as synthetic
    Synthetic { reason: SyntheticReason },
}

impl DetectionResult {
    /// Check if the event should be accepted.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Verified | Self::Suspicious { .. })
    }
}

/// Reason for synthetic detection.
#[derive(Debug, Clone)]
pub enum SyntheticReason {
    /// Platform-specific detection (CGEventTap, evdev, etc.)
    PlatformDetected,
    /// Superhuman typing speed
    SuperhumanSpeed,
    /// Robotic (too regular) timing
    RoboticTiming,
    /// Replay attack pattern detected
    ReplayPattern,
}

// =============================================================================
// Typing Rhythm Analyzer
// =============================================================================

/// Analyzer for typing rhythm to detect anomalies over longer periods.
pub struct TypingRhythmAnalyzer {
    /// IKI samples bucketed by time of day (24 buckets)
    hourly_ikis: [Vec<f64>; 24],
    /// Session IKIs
    session_ikis: Vec<f64>,
    /// Total keystroke count
    total_keystrokes: u64,
}

impl TypingRhythmAnalyzer {
    /// Create a new typing rhythm analyzer.
    pub fn new() -> Self {
        Self {
            hourly_ikis: Default::default(),
            session_ikis: Vec::new(),
            total_keystrokes: 0,
        }
    }

    /// Add a keystroke with its IKI.
    pub fn add_sample(&mut self, iki_ms: f64, hour: u8) {
        self.total_keystrokes += 1;
        self.session_ikis.push(iki_ms);
        if hour < 24 {
            self.hourly_ikis[hour as usize].push(iki_ms);
        }
    }

    /// Calculate typing speed in WPM (words per minute).
    pub fn calculate_wpm(&self) -> Option<f64> {
        if self.session_ikis.is_empty() {
            return None;
        }

        let mean_iki_ms = self.session_ikis.iter().sum::<f64>() / self.session_ikis.len() as f64;
        if mean_iki_ms <= 0.0 {
            return None;
        }

        // Average word = 5 characters
        // WPM = (chars/min) / 5 = (60000 / mean_iki_ms) / 5
        Some(12000.0 / mean_iki_ms)
    }

    /// Get fatigue indicator (speed change over session).
    pub fn fatigue_indicator(&self) -> Option<f64> {
        if self.session_ikis.len() < 100 {
            return None;
        }

        let first_quarter_len = self.session_ikis.len() / 4;
        let last_quarter_start = self.session_ikis.len() - first_quarter_len;

        let first_mean: f64 =
            self.session_ikis[..first_quarter_len].iter().sum::<f64>() / first_quarter_len as f64;
        let last_mean: f64 =
            self.session_ikis[last_quarter_start..].iter().sum::<f64>() / first_quarter_len as f64;

        // Positive = slowing down (fatigue), negative = speeding up
        Some((last_mean - first_mean) / first_mean)
    }

    /// Reset session data.
    pub fn reset_session(&mut self) {
        self.session_ikis.clear();
    }
}

impl Default for TypingRhythmAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(timestamp_ns: i64, keycode: u16, is_hardware: bool) -> KeystrokeEvent {
        KeystrokeEvent {
            timestamp_ns,
            keycode,
            zone: 0,
            char_value: None,
            is_hardware,
            device_id: None,
        }
    }

    #[test]
    fn test_insufficient_data() {
        let mut detector = StatisticalAnomalyDetector::new();

        // First event - no IKI yet
        let result = detector.analyze(&make_event(1_000_000_000, 0x04, true));
        assert!(matches!(result, StatisticalResult::Insufficient));

        // Second event - only 1 IKI
        let result = detector.analyze(&make_event(1_100_000_000, 0x05, true));
        assert!(matches!(result, StatisticalResult::Insufficient));
    }

    #[test]
    fn test_normal_typing() {
        let mut detector = StatisticalAnomalyDetector::new();

        // Simulate normal typing with variable IKIs (100-300ms)
        let base = 0i64;
        let ikis = [120, 180, 150, 200, 170, 130, 190, 160, 220, 140, 180, 150];

        let mut ts = base;
        for iki in &ikis {
            ts += *iki * 1_000_000;
            let result = detector.analyze(&make_event(ts, 0x04, true));
            // After enough samples, should be Normal
            if detector.iki_window.len() >= MIN_SAMPLES_FOR_ANALYSIS {
                assert!(
                    matches!(result, StatisticalResult::Normal),
                    "Expected Normal, got {:?}",
                    result
                );
            }
        }
    }

    #[test]
    fn test_robotic_timing() {
        let mut detector = StatisticalAnomalyDetector::new();

        // Simulate robotic typing with very regular intervals (100ms +/- 1ms)
        let mut ts = 0i64;
        for i in 0..20 {
            // Alternate between 99ms and 101ms
            ts += if i % 2 == 0 { 99_000_000 } else { 101_000_000 };
            let _ = detector.analyze(&make_event(ts, 0x04, true));
        }

        // Should detect as robotic (low CV)
        let cv = detector.current_cv();
        assert!(cv.is_some());
        assert!(cv.unwrap() < MIN_HUMAN_CV, "CV should be below threshold");
    }

    #[test]
    fn test_superhuman_speed() {
        let mut detector = StatisticalAnomalyDetector::new();

        // First, establish some normal samples
        let mut ts = 0i64;
        for _ in 0..15 {
            ts += 150_000_000; // 150ms
            let _ = detector.analyze(&make_event(ts, 0x04, true));
        }

        // Now send a superhuman fast keystroke (5ms)
        ts += 5_000_000;
        let result = detector.analyze(&make_event(ts, 0x04, true));

        // Should flag as suspicious or synthetic
        assert!(
            matches!(
                result,
                StatisticalResult::Suspicious(_) | StatisticalResult::Synthetic(_)
            ),
            "Expected suspicious or synthetic for 5ms IKI"
        );
    }

    #[test]
    fn test_combined_detector() {
        let mut detector = SyntheticDetector::new();
        detector.set_strict_mode(false);

        // Hardware event with normal timing
        let result = detector.analyze(&make_event(100_000_000, 0x04, true));
        assert!(result.is_accepted());

        // Non-hardware event
        let result = detector.analyze(&make_event(200_000_000, 0x04, false));
        assert!(!result.is_accepted());
    }

    #[test]
    fn test_typing_rhythm_wpm() {
        let mut analyzer = TypingRhythmAnalyzer::new();

        // Add samples at 200ms average (300 WPM)
        for _ in 0..100 {
            analyzer.add_sample(200.0, 12);
        }

        let wpm = analyzer.calculate_wpm().unwrap();
        // 12000 / 200 = 60 WPM
        assert!((wpm - 60.0).abs() < 1.0);
    }
}
