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

/// Configuration for behavioral checkpoint timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Minimum keystrokes between checkpoints
    pub min_keystroke_interval: u64,
    /// Maximum keystrokes between checkpoints (force checkpoint)
    pub max_keystroke_interval: u64,
    /// Minimum pause duration to trigger checkpoint (seconds)
    pub pause_threshold_secs: f64,
    /// Minimum entropy bits to trigger checkpoint
    pub entropy_threshold_bits: f64,
    /// Minimum document size change (bytes) to trigger checkpoint
    pub size_delta_threshold: i64,
    /// Maximum time between checkpoints (seconds)
    pub max_time_interval_secs: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_keystroke_interval: 50,
            max_keystroke_interval: 500,
            pause_threshold_secs: 5.0,
            entropy_threshold_bits: 32.0,
            size_delta_threshold: 256,
            max_time_interval_secs: 300.0, // 5 minutes max
        }
    }
}

/// Reason a checkpoint was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriggerReason {
    /// Reached maximum keystroke count
    MaxKeystrokes,
    /// Detected typing pause
    TypingPause,
    /// Accumulated sufficient entropy
    EntropyThreshold,
    /// Document size changed significantly
    SizeDelta,
    /// Maximum time interval reached
    MaxTimeInterval,
    /// Manual checkpoint request
    Manual,
    /// Session ended
    SessionEnd,
}

/// A checkpoint trigger event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerEvent {
    /// When the trigger occurred
    pub timestamp: DateTime<Utc>,
    /// Why the checkpoint was triggered
    pub reason: TriggerReason,
    /// Keystroke count at trigger time
    pub keystroke_count: u64,
    /// Accumulated entropy at trigger time (bits)
    pub entropy_bits: f64,
    /// Document size at trigger time
    pub document_size: i64,
    /// Time since last checkpoint
    pub elapsed_since_last: Duration,
}

/// Tracks typing behavior and determines when to create checkpoints.
pub struct CheckpointTrigger {
    config: Config,
    /// Keystrokes since last checkpoint
    keystrokes_since_checkpoint: u64,
    /// Total keystrokes in session
    total_keystrokes: u64,
    /// Accumulated entropy (in bits)
    accumulated_entropy: f64,
    /// Last keystroke timestamp
    last_keystroke: Option<Instant>,
    /// Last checkpoint timestamp
    last_checkpoint: Instant,
    /// Document size at last checkpoint
    last_checkpoint_size: i64,
    /// Entropy accumulator state
    entropy_hash: [u8; 32],
}

impl CheckpointTrigger {
    /// Create a new checkpoint trigger with default configuration.
    pub fn new() -> Self {
        Self::with_config(Config::default())
    }

    /// Create a new checkpoint trigger with custom configuration.
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
        }
    }

    /// Record a keystroke and return trigger event if checkpoint should be created.
    ///
    /// The `jitter_micros` parameter is the timing jitter from the keystroke,
    /// which contributes to entropy accumulation.
    pub fn record_keystroke(
        &mut self,
        jitter_micros: u32,
        current_doc_size: i64,
    ) -> Option<TriggerEvent> {
        let now = Instant::now();
        self.total_keystrokes += 1;
        self.keystrokes_since_checkpoint += 1;

        // Add jitter to entropy accumulator
        self.accumulate_entropy(jitter_micros);

        // Check for typing pause
        if let Some(last) = self.last_keystroke {
            let pause = now.duration_since(last);
            if pause.as_secs_f64() >= self.config.pause_threshold_secs
                && self.keystrokes_since_checkpoint >= self.config.min_keystroke_interval
            {
                return Some(self.create_trigger(TriggerReason::TypingPause, current_doc_size));
            }
        }

        self.last_keystroke = Some(now);

        // Check max keystrokes
        if self.keystrokes_since_checkpoint >= self.config.max_keystroke_interval {
            return Some(self.create_trigger(TriggerReason::MaxKeystrokes, current_doc_size));
        }

        // Check entropy threshold (only if we have minimum keystrokes)
        if self.keystrokes_since_checkpoint >= self.config.min_keystroke_interval
            && self.accumulated_entropy >= self.config.entropy_threshold_bits
        {
            return Some(self.create_trigger(TriggerReason::EntropyThreshold, current_doc_size));
        }

        // Check size delta
        let size_delta = (current_doc_size - self.last_checkpoint_size).abs();
        if self.keystrokes_since_checkpoint >= self.config.min_keystroke_interval
            && size_delta >= self.config.size_delta_threshold
        {
            return Some(self.create_trigger(TriggerReason::SizeDelta, current_doc_size));
        }

        // Check max time interval
        let elapsed = now.duration_since(self.last_checkpoint);
        if elapsed.as_secs_f64() >= self.config.max_time_interval_secs {
            return Some(self.create_trigger(TriggerReason::MaxTimeInterval, current_doc_size));
        }

        None
    }

    /// Check if checkpoint should be created based on time alone (for idle detection).
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

    /// Trigger checkpoint due to session end.
    pub fn session_end_trigger(&mut self, current_doc_size: i64) -> TriggerEvent {
        self.create_trigger(TriggerReason::SessionEnd, current_doc_size)
    }

    /// Get current entropy hash for checkpoint binding.
    pub fn entropy_hash(&self) -> [u8; 32] {
        self.entropy_hash
    }

    /// Get keystrokes since last checkpoint.
    pub fn keystrokes_since_checkpoint(&self) -> u64 {
        self.keystrokes_since_checkpoint
    }

    /// Get total keystrokes in session.
    pub fn total_keystrokes(&self) -> u64 {
        self.total_keystrokes
    }

    /// Get accumulated entropy in bits.
    pub fn accumulated_entropy(&self) -> f64 {
        self.accumulated_entropy
    }

    /// Reset after checkpoint is created.
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
        // Mix jitter into entropy hash
        let mut hasher = Sha256::new();
        hasher.update(self.entropy_hash);
        hasher.update(jitter_micros.to_be_bytes());
        hasher.update(self.total_keystrokes.to_be_bytes());
        self.entropy_hash = hasher.finalize().into();

        // Estimate entropy from jitter timing
        // Assuming jitter has ~8 bits of entropy per sample (conservative)
        // This is a simplified model; real entropy estimation is more complex
        self.accumulated_entropy += estimate_jitter_entropy(jitter_micros);
    }
}

impl Default for CheckpointTrigger {
    fn default() -> Self {
        Self::new()
    }
}

/// Estimate entropy bits from jitter timing.
///
/// This is a simplified model based on the jitter range.
/// Real implementations might use more sophisticated entropy estimation.
fn estimate_jitter_entropy(jitter_micros: u32) -> f64 {
    // Conservative estimate: ~4 bits per keystroke from timing jitter
    // The actual entropy depends on the jitter distribution and hardware
    if jitter_micros == 0 {
        0.0
    } else {
        // Log2 of jitter range gives approximate entropy
        // Clamp to reasonable range
        let entropy = (jitter_micros as f64).log2();
        entropy.clamp(0.5, 8.0)
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
            entropy_threshold_bits: 10000.0, // High to avoid entropy trigger
            size_delta_threshold: 10000,     // High to avoid size trigger
            ..Default::default()
        };
        let mut trigger = CheckpointTrigger::with_config(config);

        // Record keystrokes up to max (use low jitter to minimize entropy)
        for i in 0..9 {
            let result = trigger.record_keystroke(10, 100);
            assert!(
                result.is_none(),
                "Unexpected trigger at keystroke {}",
                i + 1
            );
        }

        // 10th keystroke should trigger
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
            entropy_threshold_bits: 20.0, // Low threshold for testing
            ..Default::default()
        };
        let mut trigger = CheckpointTrigger::with_config(config);

        // Record keystrokes with high jitter (high entropy)
        for _ in 0..10 {
            let result = trigger.record_keystroke(50000, 100); // High jitter = more entropy
            if let Some(event) = result {
                assert_eq!(event.reason, TriggerReason::EntropyThreshold);
                return;
            }
        }

        // Should have triggered by entropy
        assert!(
            trigger.accumulated_entropy() >= 20.0,
            "Expected entropy >= 20, got {}",
            trigger.accumulated_entropy()
        );
    }

    #[test]
    fn test_trigger_on_size_delta() {
        let config = Config {
            min_keystroke_interval: 5,
            max_keystroke_interval: 1000,
            size_delta_threshold: 100,
            entropy_threshold_bits: 10000.0, // High to avoid entropy trigger
            ..Default::default()
        };
        let mut trigger = CheckpointTrigger::with_config(config);

        // Record keystrokes with very slowly increasing doc size (use low jitter)
        for i in 0..10 {
            let result = trigger.record_keystroke(10, i * 5); // Size grows slowly, low jitter
            assert!(
                result.is_none(),
                "Unexpected trigger at keystroke {}",
                i + 1
            );
        }

        // Now jump doc size significantly (from ~45 to 500, delta > 100)
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

        trigger.record_keystroke(1000, 100);
        assert!(trigger.accumulated_entropy() > 0.0);

        let e1 = trigger.accumulated_entropy();
        trigger.record_keystroke(2000, 100);
        assert!(trigger.accumulated_entropy() > e1);
    }

    #[test]
    fn test_reset_for_checkpoint() {
        let mut trigger = CheckpointTrigger::new();

        for _ in 0..10 {
            trigger.record_keystroke(1000, 100);
        }

        assert!(trigger.keystrokes_since_checkpoint() > 0);
        assert!(trigger.accumulated_entropy() > 0.0);

        trigger.reset_for_checkpoint(200);

        assert_eq!(trigger.keystrokes_since_checkpoint(), 0);
        assert_eq!(trigger.accumulated_entropy(), 0.0);
        // Total keystrokes should not reset
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
    fn test_estimate_jitter_entropy() {
        assert_eq!(estimate_jitter_entropy(0), 0.0);
        assert!(estimate_jitter_entropy(100) > 0.0);
        assert!(estimate_jitter_entropy(1000) > estimate_jitter_entropy(100));
        // Should be clamped to max 8 bits
        assert!(estimate_jitter_entropy(1_000_000) <= 8.0);
    }

    #[test]
    fn test_trigger_event_fields() {
        let mut trigger = CheckpointTrigger::new();
        trigger.record_keystroke(1000, 100);

        let event = trigger.manual_trigger(150);

        assert!(event.timestamp <= Utc::now());
        assert_eq!(event.keystroke_count, 1);
        assert!(event.entropy_bits > 0.0);
        assert_eq!(event.document_size, 150);
    }
}
