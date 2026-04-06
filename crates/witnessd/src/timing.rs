// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Behavioral checkpoint timing for WAR/1.1 evidence.
//!
//! This module provides checkpoint triggers based on typing behavior and entropy
//! accumulation, rather than fixed time intervals. This creates checkpoints that
//! are naturally entangled with the authorship process.
//!
//! Triggers include:
//! - Keystroke count thresholds
//! - Typing pause detection (natural break points)
//! - Entropy accumulation thresholds
//! - Document size delta thresholds

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Per-tier entropy thresholds from draft-condrey-rats-pop.
pub const ENTROPY_THRESHOLD_BASIC: f64 = 2.0;
/// Standard tier entropy threshold (bits).
pub const ENTROPY_THRESHOLD_STANDARD: f64 = 3.0;
/// Enhanced tier entropy threshold (bits).
pub const ENTROPY_THRESHOLD_ENHANCED: f64 = 3.0;

/// Configuration for behavioral checkpoint timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub min_keystroke_interval: u64,
    pub max_keystroke_interval: u64,
    pub pause_threshold_secs: f64,
    pub entropy_threshold_bits: f64,
    pub size_delta_threshold: i64,
    pub max_time_interval_secs: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_keystroke_interval: 50,
            max_keystroke_interval: 500,
            pause_threshold_secs: 5.0,
            entropy_threshold_bits: ENTROPY_THRESHOLD_STANDARD,
            size_delta_threshold: 256,
            max_time_interval_secs: 300.0,
        }
    }
}

/// Reason a checkpoint was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriggerReason {
    /// Keystroke count exceeded the maximum interval.
    MaxKeystrokes,
    /// Typing pause exceeded the threshold duration.
    TypingPause,
    /// Accumulated entropy exceeded the bit threshold.
    EntropyThreshold,
    /// Document size delta exceeded the threshold.
    SizeDelta,
    /// Maximum time interval since last checkpoint elapsed.
    MaxTimeInterval,
    /// Manually requested by the user or caller.
    Manual,
    /// Session ended, forcing a final checkpoint.
    SessionEnd,
}

/// A checkpoint trigger event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerEvent {
    pub timestamp: DateTime<Utc>,
    pub reason: TriggerReason,
    pub keystroke_count: u64,
    pub entropy_bits: f64,
    pub document_size: i64,
    pub elapsed_since_last: Duration,
}

/// Number of recent jitter samples used for windowed entropy estimation.
const JITTER_WINDOW_SIZE: usize = 16;

/// Tracks typing behavior and determines when to create checkpoints.
pub struct CheckpointTrigger {
    config: Config,
    keystrokes_since_checkpoint: u64,
    total_keystrokes: u64,
    accumulated_entropy: f64,
    last_keystroke: Option<Instant>,
    last_checkpoint: Instant,
    last_checkpoint_size: i64,
    entropy_hash: [u8; 32],
    jitter_window: [u32; JITTER_WINDOW_SIZE],
    jitter_window_pos: usize,
    jitter_window_len: usize,
}

impl CheckpointTrigger {
    /// Create a trigger with default configuration.
    pub fn new() -> Self {
        Self::with_config(Config::default())
    }

    /// Create a trigger with the given configuration.
    pub fn with_config(config: Config) -> Self {
        Self {
            config,
            keystrokes_since_checkpoint: 0,
            total_keystrokes: 0,
            accumulated_entropy: 0.0,
            last_keystroke: None,
            last_checkpoint: Instant::now(),
            last_checkpoint_size: 0,
            entropy_hash: [0u8; 32],
            jitter_window: [0u32; JITTER_WINDOW_SIZE],
            jitter_window_pos: 0,
            jitter_window_len: 0,
        }
    }

    /// Record a keystroke and return a trigger event if a checkpoint threshold is met.
    pub fn record_keystroke(
        &mut self,
        jitter_micros: u32,
        current_doc_size: i64,
    ) -> Option<TriggerEvent> {
        let now = Instant::now();
        self.total_keystrokes += 1;
        self.keystrokes_since_checkpoint += 1;
        self.accumulate_entropy(jitter_micros);

        let prev_keystroke = self.last_keystroke;
        self.last_keystroke = Some(now);

        if let Some(last) = prev_keystroke {
            let pause = now.duration_since(last);
            if pause.as_secs_f64() >= self.config.pause_threshold_secs
                && self.keystrokes_since_checkpoint >= self.config.min_keystroke_interval
            {
                return Some(self.create_trigger(TriggerReason::TypingPause, current_doc_size));
            }
        }

        if self.keystrokes_since_checkpoint >= self.config.max_keystroke_interval {
            return Some(self.create_trigger(TriggerReason::MaxKeystrokes, current_doc_size));
        }

        if self.keystrokes_since_checkpoint >= self.config.min_keystroke_interval
            && self.accumulated_entropy >= self.config.entropy_threshold_bits
        {
            return Some(self.create_trigger(TriggerReason::EntropyThreshold, current_doc_size));
        }

        let size_delta = (current_doc_size - self.last_checkpoint_size).abs();
        if self.keystrokes_since_checkpoint >= self.config.min_keystroke_interval
            && size_delta >= self.config.size_delta_threshold
        {
            return Some(self.create_trigger(TriggerReason::SizeDelta, current_doc_size));
        }

        let elapsed = now.duration_since(self.last_checkpoint);
        if elapsed.as_secs_f64() >= self.config.max_time_interval_secs {
            return Some(self.create_trigger(TriggerReason::MaxTimeInterval, current_doc_size));
        }

        None
    }

    /// Check if the max time interval has elapsed and trigger if so.
    pub fn check_time_trigger(&mut self, current_doc_size: i64) -> Option<TriggerEvent> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_checkpoint);

        if elapsed.as_secs_f64() >= self.config.max_time_interval_secs
            && self.keystrokes_since_checkpoint > 0
        {
            return Some(self.create_trigger(TriggerReason::MaxTimeInterval, current_doc_size));
        }

        None
    }

    /// Force a manual checkpoint trigger.
    pub fn manual_trigger(&mut self, current_doc_size: i64) -> TriggerEvent {
        self.create_trigger(TriggerReason::Manual, current_doc_size)
    }

    /// Create a trigger event for session end.
    pub fn session_end_trigger(&mut self, current_doc_size: i64) -> TriggerEvent {
        self.create_trigger(TriggerReason::SessionEnd, current_doc_size)
    }

    /// Return the rolling entropy hash accumulator.
    pub fn entropy_hash(&self) -> [u8; 32] {
        self.entropy_hash
    }

    /// Return the number of keystrokes since the last checkpoint.
    pub fn keystrokes_since_checkpoint(&self) -> u64 {
        self.keystrokes_since_checkpoint
    }

    /// Return the total keystroke count across all checkpoints.
    pub fn total_keystrokes(&self) -> u64 {
        self.total_keystrokes
    }

    /// Return the accumulated entropy bits since the last checkpoint.
    pub fn accumulated_entropy(&self) -> f64 {
        self.accumulated_entropy
    }

    /// Reset keystroke and entropy counters after a checkpoint is created.
    pub fn reset_for_checkpoint(&mut self, doc_size: i64) {
        self.keystrokes_since_checkpoint = 0;
        self.accumulated_entropy = 0.0;
        self.last_checkpoint = Instant::now();
        self.last_checkpoint_size = doc_size;
        // Don't reset entropy_hash - it's a rolling accumulator
    }

    fn create_trigger(&mut self, reason: TriggerReason, doc_size: i64) -> TriggerEvent {
        let elapsed = Instant::now().duration_since(self.last_checkpoint);
        let event = TriggerEvent {
            timestamp: Utc::now(),
            reason,
            keystroke_count: self.keystrokes_since_checkpoint,
            entropy_bits: self.accumulated_entropy,
            document_size: doc_size,
            elapsed_since_last: elapsed,
        };
        self.reset_for_checkpoint(doc_size);
        event
    }

    fn accumulate_entropy(&mut self, jitter_micros: u32) {
        // Rolling hash for chain-of-custody (independent of entropy estimation).
        let mut hasher = Sha256::new();
        hasher.update(self.entropy_hash);
        hasher.update(jitter_micros.to_be_bytes());
        hasher.update(self.total_keystrokes.to_be_bytes());
        self.entropy_hash = hasher.finalize().into();

        // Add to ring buffer.
        self.jitter_window[self.jitter_window_pos] = jitter_micros;
        self.jitter_window_pos = (self.jitter_window_pos + 1) % JITTER_WINDOW_SIZE;
        if self.jitter_window_len < JITTER_WINDOW_SIZE {
            self.jitter_window_len += 1;
        }

        self.accumulated_entropy += self.windowed_entropy_estimate();
    }

    /// Estimate per-keystroke entropy from the coefficient of variation (CV)
    /// of recent jitter values. CV measures timing variability: 0 for perfectly
    /// uniform input (automated), >0 for natural human typing. Returns
    /// `log2(1 + CV)`, clamped to [0.0, 1.0].
    fn windowed_entropy_estimate(&self) -> f64 {
        if self.jitter_window_len < 4 {
            return 0.0;
        }
        let samples = &self.jitter_window[..self.jitter_window_len];
        let n = samples.len() as f64;
        let mean = samples.iter().map(|&v| v as f64).sum::<f64>() / n;
        if mean < 1.0 {
            return 0.0;
        }
        let variance = samples
            .iter()
            .map(|&v| (v as f64 - mean).powi(2))
            .sum::<f64>()
            / n;
        let cv = variance.sqrt() / mean;
        (1.0 + cv).log2().clamp(0.0, 1.0)
    }
}

impl Default for CheckpointTrigger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.min_keystroke_interval, 50);
        assert_eq!(config.max_keystroke_interval, 500);
        assert_eq!(config.pause_threshold_secs, 5.0);
    }

    #[test]
    fn test_trigger_on_max_keystrokes() {
        let config = Config {
            min_keystroke_interval: 5,
            max_keystroke_interval: 10,
            entropy_threshold_bits: 10000.0,
            size_delta_threshold: 10000,
            ..Default::default()
        };
        let mut trigger = CheckpointTrigger::with_config(config);

        for i in 0..9 {
            let result = trigger.record_keystroke(10, 100);
            assert!(
                result.is_none(),
                "Unexpected trigger at keystroke {}",
                i + 1
            );
        }

        let result = trigger.record_keystroke(10, 100);
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.reason, TriggerReason::MaxKeystrokes);
        assert_eq!(event.keystroke_count, 10);
    }

    #[test]
    fn test_trigger_on_entropy_threshold() {
        let config = Config {
            min_keystroke_interval: 5,
            max_keystroke_interval: 1000,
            entropy_threshold_bits: 3.0,
            size_delta_threshold: 100_000,
            ..Default::default()
        };
        let mut trigger = CheckpointTrigger::with_config(config);

        // Alternating jitter values produce high CV, accumulating entropy.
        let jitters = [
            500, 5000, 800, 4000, 600, 5500, 700, 4200, 550, 5100, 900, 3800, 650, 4500, 750, 4800,
            500, 5200, 850, 3900,
        ];
        for (i, &j) in jitters.iter().enumerate() {
            let result = trigger.record_keystroke(j, 100);
            if let Some(event) = result {
                assert_eq!(event.reason, TriggerReason::EntropyThreshold);
                assert!(i >= 5, "Should need at least a few keystrokes");
                return;
            }
        }

        panic!(
            "Expected EntropyThreshold trigger within 20 keystrokes, got entropy={}",
            trigger.accumulated_entropy()
        );
    }

    #[test]
    fn test_trigger_on_size_delta() {
        let config = Config {
            min_keystroke_interval: 5,
            max_keystroke_interval: 1000,
            size_delta_threshold: 100,
            entropy_threshold_bits: 10000.0,
            ..Default::default()
        };
        let mut trigger = CheckpointTrigger::with_config(config);

        for i in 0..10 {
            let result = trigger.record_keystroke(10, i * 5); // Size grows slowly, low jitter
            assert!(
                result.is_none(),
                "Unexpected trigger at keystroke {}",
                i + 1
            );
        }

        let result = trigger.record_keystroke(10, 500);
        assert!(result.is_some());
        assert_eq!(result.unwrap().reason, TriggerReason::SizeDelta);
    }

    #[test]
    fn test_manual_trigger() {
        let mut trigger = CheckpointTrigger::new();
        trigger.record_keystroke(1000, 100);

        let event = trigger.manual_trigger(150);
        assert_eq!(event.reason, TriggerReason::Manual);
        assert_eq!(event.document_size, 150);
    }

    #[test]
    fn test_session_end_trigger() {
        let mut trigger = CheckpointTrigger::new();
        trigger.record_keystroke(1000, 100);

        let event = trigger.session_end_trigger(200);
        assert_eq!(event.reason, TriggerReason::SessionEnd);
    }

    #[test]
    fn test_entropy_accumulation() {
        let mut trigger = CheckpointTrigger::new();

        assert_eq!(trigger.accumulated_entropy(), 0.0);

        // First 3 samples return 0 (window needs >= 4 entries).
        trigger.record_keystroke(1000, 100);
        trigger.record_keystroke(2000, 100);
        trigger.record_keystroke(500, 100);
        assert_eq!(trigger.accumulated_entropy(), 0.0);

        // 4th sample with variable jitter starts producing entropy.
        trigger.record_keystroke(3000, 100);
        assert!(trigger.accumulated_entropy() > 0.0);

        let e1 = trigger.accumulated_entropy();
        trigger.record_keystroke(800, 100);
        assert!(trigger.accumulated_entropy() > e1);
    }

    #[test]
    fn test_reset_for_checkpoint() {
        let mut trigger = CheckpointTrigger::new();

        // Variable jitter to produce non-zero entropy.
        for i in 0..10 {
            let j = if i % 2 == 0 { 500 } else { 5000 };
            trigger.record_keystroke(j, 100);
        }

        assert!(trigger.keystrokes_since_checkpoint() > 0);
        assert!(trigger.accumulated_entropy() > 0.0);

        trigger.reset_for_checkpoint(200);

        assert_eq!(trigger.keystrokes_since_checkpoint(), 0);
        assert_eq!(trigger.accumulated_entropy(), 0.0);
        assert_eq!(trigger.total_keystrokes(), 10);
    }

    #[test]
    fn test_entropy_hash_changes() {
        let mut trigger = CheckpointTrigger::new();
        let initial_hash = trigger.entropy_hash();

        trigger.record_keystroke(1000, 100);
        let hash1 = trigger.entropy_hash();
        assert_ne!(initial_hash, hash1);

        trigger.record_keystroke(2000, 100);
        let hash2 = trigger.entropy_hash();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_uniform_jitter_yields_zero_entropy() {
        let mut trigger = CheckpointTrigger::new();
        // Perfectly uniform jitter (CV=0) should produce no entropy.
        for _ in 0..20 {
            trigger.record_keystroke(1000, 100);
        }
        assert_eq!(trigger.accumulated_entropy(), 0.0);
    }

    #[test]
    fn test_variable_jitter_yields_more_entropy() {
        let mut uniform = CheckpointTrigger::new();
        let mut variable = CheckpointTrigger::new();
        // Same number of keystrokes, different variability.
        for i in 0..20 {
            uniform.record_keystroke(1000, 100);
            // Alternate between 500 and 5000 for high CV.
            let j = if i % 2 == 0 { 500 } else { 5000 };
            variable.record_keystroke(j, 100);
        }
        assert!(
            variable.accumulated_entropy() > uniform.accumulated_entropy(),
            "Variable jitter ({}) should yield more entropy than uniform ({})",
            variable.accumulated_entropy(),
            uniform.accumulated_entropy()
        );
    }

    #[test]
    fn test_trigger_event_fields() {
        let mut trigger = CheckpointTrigger::new();
        // Variable jitter over enough samples to produce entropy.
        for j in [500, 3000, 800, 4000, 600] {
            trigger.record_keystroke(j, 100);
        }

        let event = trigger.manual_trigger(150);

        assert!(event.timestamp <= Utc::now());
        assert_eq!(event.keystroke_count, 5);
        assert!(event.entropy_bits > 0.0);
        assert_eq!(event.document_size, 150);
    }
}
