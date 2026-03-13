// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Audio transcription metadata collection.
//!
//! This module provides privacy-safe collection of audio transcription evidence.
//! Following WritersLogic's core principle of content-agnosticism:
//!
//! - NO audio content is stored
//! - NO transcript text is stored
//! - Only timing characteristics and metadata are captured
//!
//! The collected data provides evidence of dictation activity while preserving
//! complete privacy of the actual content being dictated.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Transcription metadata for privacy-safe dictation evidence.
///
/// Captures timing and structural characteristics of audio transcription
/// without storing any content or audio data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionMetadata {
    pub engine: String,
    pub word_count: u64,
    pub audio_duration_ms: u64,
    pub confidence: f64,

    #[serde(with = "crate::rfc::serde_helpers::hex_bytes")]
    pub audio_fingerprint: [u8; 32],
    pub timestamp_ms: u64,
}

/// Aggregates word timing into a content-free fingerprint.
pub struct TranscriptionCollector {
    engine: String,
    word_intervals_us: Vec<u64>,
    total_duration_ms: u64,
    confidence_sum: f64,
    confidence_count: u64,
}

impl TranscriptionCollector {
    pub fn new(engine: &str) -> Self {
        Self {
            engine: engine.to_string(),
            word_intervals_us: Vec::new(),
            total_duration_ms: 0,
            confidence_sum: 0.0,
            confidence_count: 0,
        }
    }

    pub fn record_word_interval(&mut self, interval_us: u64) {
        self.word_intervals_us.push(interval_us);
    }

    pub fn record_confidence(&mut self, confidence: f64) {
        self.confidence_sum += confidence.clamp(0.0, 1.0);
        self.confidence_count += 1;
    }

    pub fn set_duration(&mut self, duration_ms: u64) {
        self.total_duration_ms = duration_ms;
    }

    fn compute_fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(self.word_intervals_us.len().to_le_bytes());

        for interval in &self.word_intervals_us {
            let quantized = interval / 10_000;
            hasher.update(quantized.to_le_bytes());
        }

        hasher.update(self.total_duration_ms.to_le_bytes());
        hasher.finalize().into()
    }

    pub fn finalize(self) -> TranscriptionMetadata {
        let word_count = self.word_intervals_us.len() as u64;
        let confidence = if self.confidence_count > 0 {
            self.confidence_sum / self.confidence_count as f64
        } else {
            0.0
        };
        let fingerprint = self.compute_fingerprint();
        let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;

        TranscriptionMetadata {
            engine: self.engine,
            word_count,
            audio_duration_ms: self.total_duration_ms,
            confidence,
            audio_fingerprint: fingerprint,
            timestamp_ms: now_ms,
        }
    }

    pub fn reset(&mut self) {
        self.word_intervals_us.clear();
        self.total_duration_ms = 0;
        self.confidence_sum = 0.0;
        self.confidence_count = 0;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionTimingStats {
    pub mean_interval_us: f64,
    pub std_dev_us: f64,
    pub min_interval_us: u64,
    pub max_interval_us: u64,
    pub words_per_minute: f64,
}

impl TranscriptionTimingStats {
    pub fn from_intervals(intervals: &[u64]) -> Option<Self> {
        if intervals.is_empty() {
            return None;
        }

        let n = intervals.len() as f64;
        let sum: u64 = intervals.iter().sum();
        let mean = sum as f64 / n;

        let variance: f64 = intervals
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / n;
        let std_dev = variance.sqrt();

        let min = *intervals.iter().min()?;
        let max = *intervals.iter().max()?;

        let wpm = if mean > 0.0 { 60_000_000.0 / mean } else { 0.0 };

        Some(Self {
            mean_interval_us: mean,
            std_dev_us: std_dev,
            min_interval_us: min,
            max_interval_us: max,
            words_per_minute: wpm,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_basic() {
        let mut collector = TranscriptionCollector::new("whisper");

        collector.record_word_interval(200_000);
        collector.record_word_interval(150_000);
        collector.record_word_interval(180_000);
        collector.record_confidence(0.95);
        collector.record_confidence(0.92);
        collector.record_confidence(0.88);
        collector.set_duration(5000); // 5 seconds

        let meta = collector.finalize();

        assert_eq!(meta.engine, "whisper");
        assert_eq!(meta.word_count, 3);
        assert_eq!(meta.audio_duration_ms, 5000);
        assert!((meta.confidence - 0.9166).abs() < 0.01);
        assert_ne!(meta.audio_fingerprint, [0u8; 32]);
    }

    #[test]
    fn test_fingerprint_determinism() {
        let mut c1 = TranscriptionCollector::new("test");
        let mut c2 = TranscriptionCollector::new("test");

        for interval in [100_000, 200_000, 150_000] {
            c1.record_word_interval(interval);
            c2.record_word_interval(interval);
        }
        c1.set_duration(1000);
        c2.set_duration(1000);

        let m1 = c1.finalize();
        let m2 = c2.finalize();

        assert_eq!(m1.audio_fingerprint, m2.audio_fingerprint);
    }

    #[test]
    fn test_fingerprint_sensitivity() {
        let mut c1 = TranscriptionCollector::new("test");
        let mut c2 = TranscriptionCollector::new("test");

        c1.record_word_interval(100_000);
        c2.record_word_interval(200_000); // Different!

        let m1 = c1.finalize();
        let m2 = c2.finalize();

        assert_ne!(m1.audio_fingerprint, m2.audio_fingerprint);
    }

    #[test]
    fn test_timing_stats() {
        let intervals = vec![100_000, 200_000, 150_000, 180_000];
        let stats = TranscriptionTimingStats::from_intervals(&intervals).unwrap();

        assert_eq!(stats.min_interval_us, 100_000);
        assert_eq!(stats.max_interval_us, 200_000);
        assert!((stats.mean_interval_us - 157_500.0).abs() < 1.0);
        assert!(stats.words_per_minute > 0.0);
    }

    #[test]
    fn test_empty_intervals() {
        let stats = TranscriptionTimingStats::from_intervals(&[]);
        assert!(stats.is_none());
    }
}
