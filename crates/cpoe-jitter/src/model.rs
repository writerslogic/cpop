// SPDX-License-Identifier: Apache-2.0

//! Statistical model for human typing validation (Aalto 136M keystroke baseline).

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

use serde::{Deserialize, Serialize};

#[inline]
fn sqrt(x: f64) -> f64 {
    #[cfg(feature = "std")]
    {
        x.sqrt()
    }
    #[cfg(not(feature = "std"))]
    {
        libm::sqrt(x)
    }
}

use crate::{Evidence, Jitter};

const MIN_STD_DEV_THRESHOLD: f64 = 50.0;
const MIN_IKI_STD_DEV_THRESHOLD: f64 = 5000.0;
const CONFIDENCE_PENALTY_PER_ANOMALY: f64 = 0.25;
const MIN_HUMAN_CONFIDENCE: f64 = 0.5;
const REPEATING_PATTERN_THRESHOLD: f64 = 0.8;
const MIN_PATTERN_CHECKS_EXCLUSIVE: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanModel {
    pub iki_min_us: u32,
    pub iki_max_us: u32,
    pub iki_mean_us: u32,
    pub iki_std_us: u32,
    pub jitter_min_us: u32,
    pub jitter_max_us: u32,
    pub min_sequence_length: usize,
    pub max_perfect_ratio: f64,
}

impl Default for HumanModel {
    fn default() -> Self {
        Self {
            iki_min_us: 30_000,
            iki_max_us: 2_000_000,
            iki_mean_us: 200_000,
            iki_std_us: 80_000,
            jitter_min_us: 500,
            jitter_max_us: 3000,
            min_sequence_length: 20,
            max_perfect_ratio: 0.05,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_human: bool,
    pub confidence: f64,
    pub anomalies: Vec<Anomaly>,
    pub stats: SequenceStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub kind: AnomalyKind,
    pub position: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyKind {
    PerfectTiming,
    OutOfRange,
    /// Sequence too short for meaningful analysis.
    InsufficientData,
    /// Detected a short repeating pattern (length 2-5).
    RepeatingPattern,
    LowVariance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceStats {
    pub count: usize,
    pub mean: f64,
    /// Population standard deviation.
    pub std_dev: f64,
    pub min: Jitter,
    pub max: Jitter,
}

/// Single-pass out-of-range scan over an iterator returning count and first position
fn out_of_range_anomaly<I, T>(
    values: I,
    pred: impl Fn(&T) -> bool,
    min_label: u64,
    max_label: u64,
    name: &str,
) -> Option<Anomaly>
where
    I: Iterator<Item = T>,
{
    let mut count = 0usize;
    let mut first = 0usize;
    for (i, v) in values.enumerate() {
        if pred(&v) {
            if count == 0 {
                first = i;
            }
            count += 1;
        }
    }
    if count > 0 {
        Some(Anomaly {
            kind: AnomalyKind::OutOfRange,
            position: first,
            detail: format!(
                "{} {} values outside [{}, {}]\u{00b5}s range",
                count, name, min_label, max_label
            ),
        })
    } else {
        None
    }
}

impl HumanModel {
    #[cfg(feature = "std")]
    pub fn baseline() -> Result<Self, serde_json::Error> {
        const BASELINE: &str = include_str!("baseline.json");
        serde_json::from_str(BASELINE)
    }

    #[cfg(feature = "std")]
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[cfg(feature = "std")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn validate(&self, jitters: &[Jitter]) -> ValidationResult {
        let oor = out_of_range_anomaly(
            jitters.iter().copied(),
            |&j| j < self.jitter_min_us || j > self.jitter_max_us,
            self.jitter_min_us as u64,
            self.jitter_max_us as u64,
            "jitter",
        );
        let perfect_ratio = self.compute_perfect_ratio_jitters(jitters);
        let pattern = self.detect_repeating_pattern_jitters(jitters);
        self.validate_inner(
            jitters.len(),
            self.compute_stats(jitters.iter().copied()),
            oor,
            perfect_ratio,
            pattern,
            MIN_STD_DEV_THRESHOLD,
        )
    }

    /// Zero-allocation validation directly from the Evidence slice.
    pub fn validate_records(&self, records: &[Evidence]) -> ValidationResult {
        let oor = out_of_range_anomaly(
            records.iter().map(|e| e.jitter()),
            |&j| j < self.jitter_min_us || j > self.jitter_max_us,
            self.jitter_min_us as u64,
            self.jitter_max_us as u64,
            "jitter",
        );
        let perfect_ratio = self.compute_perfect_ratio_records(records);
        let pattern = self.detect_repeating_pattern_records(records);
        self.validate_inner(
            records.len(),
            self.compute_stats(records.iter().map(|e| e.jitter())),
            oor,
            perfect_ratio,
            pattern,
            MIN_STD_DEV_THRESHOLD,
        )
    }

    pub fn validate_iki(&self, intervals_us: &[u64]) -> ValidationResult {
        let oor = out_of_range_anomaly(
            intervals_us.iter().copied(),
            |&iki| iki < self.iki_min_us as u64 || iki > self.iki_max_us as u64,
            self.iki_min_us as u64,
            self.iki_max_us as u64,
            "IKI",
        );
        let capped: Vec<u32> = intervals_us
            .iter()
            .map(|&v| v.min(u32::MAX as u64) as u32)
            .collect();

        let perfect_ratio = self.compute_perfect_ratio_jitters(&capped);
        let pattern = self.detect_repeating_pattern_jitters(&capped);

        self.validate_inner(
            capped.len(),
            self.compute_stats(capped.into_iter()),
            oor,
            perfect_ratio,
            pattern,
            MIN_IKI_STD_DEV_THRESHOLD,
        )
    }

    fn validate_inner(
        &self,
        len: usize,
        stats: SequenceStats,
        out_of_range: Option<Anomaly>,
        perfect_ratio: f64,
        repeating_pattern_len: Option<usize>,
        std_dev_threshold: f64,
    ) -> ValidationResult {
        if len < self.min_sequence_length {
            return ValidationResult {
                is_human: false,
                confidence: 0.0,
                anomalies: vec![Anomaly {
                    kind: AnomalyKind::InsufficientData,
                    position: 0,
                    detail: format!("Sequence too short: {} < {}", len, self.min_sequence_length),
                }],
                stats,
            };
        }

        let mut anomalies = Vec::new();

        if stats.std_dev < std_dev_threshold {
            anomalies.push(Anomaly {
                kind: AnomalyKind::LowVariance,
                position: 0,
                detail: format!("Variance too low: std_dev={:.2}", stats.std_dev),
            });
        }

        if perfect_ratio > self.max_perfect_ratio {
            anomalies.push(Anomaly {
                kind: AnomalyKind::PerfectTiming,
                position: 0,
                detail: format!("Too many perfect timings: {:.1}%", perfect_ratio * 100.0),
            });
        }

        if let Some(pattern_len) = repeating_pattern_len {
            anomalies.push(Anomaly {
                kind: AnomalyKind::RepeatingPattern,
                position: 0,
                detail: format!("Repeating pattern of length {}", pattern_len),
            });
        }

        anomalies.extend(out_of_range);

        let base_confidence = 1.0 - (anomalies.len() as f64 * CONFIDENCE_PENALTY_PER_ANOMALY);
        let confidence = base_confidence.clamp(0.0, 1.0);

        ValidationResult {
            is_human: anomalies.is_empty() && confidence > MIN_HUMAN_CONFIDENCE,
            confidence,
            anomalies,
            stats,
        }
    }

    fn compute_stats<I: Iterator<Item = Jitter>>(&self, mut jitters: I) -> SequenceStats {
        let first = match jitters.next() {
            Some(j) => j,
            None => {
                return SequenceStats {
                    count: 0,
                    mean: 0.0,
                    std_dev: 0.0,
                    min: 0,
                    max: 0,
                };
            }
        };

        // Single-pass Welford's with min/max tracking
        let mut n: u64 = 1;
        let mut m = first as f64;
        let mut s = 0.0_f64;
        let mut lo = first;
        let mut hi = first;

        for j in jitters {
            n += 1;
            let x = j as f64;
            let delta = x - m;
            m += delta / n as f64;
            s += delta * (x - m);
            if j < lo {
                lo = j;
            }
            if j > hi {
                hi = j;
            }
        }

        SequenceStats {
            count: n as usize,
            mean: m,
            std_dev: sqrt(s / n as f64),
            min: lo,
            max: hi,
        }
    }

    fn compute_perfect_ratio_jitters(&self, jitters: &[Jitter]) -> f64 {
        let perfect_count = jitters.windows(2).filter(|w| w[0] == w[1]).count();
        if jitters.len() > 1 {
            perfect_count as f64 / (jitters.len() - 1) as f64
        } else {
            0.0
        }
    }

    fn compute_perfect_ratio_records(&self, records: &[Evidence]) -> f64 {
        let perfect_count = records
            .windows(2)
            .filter(|w| w[0].jitter() == w[1].jitter())
            .count();
        if records.len() > 1 {
            perfect_count as f64 / (records.len() - 1) as f64
        } else {
            0.0
        }
    }

    fn detect_repeating_pattern_jitters(&self, jitters: &[Jitter]) -> Option<usize> {
        if jitters.len() < 6 {
            return None;
        }

        for pattern_len in 2..=5 {
            if jitters.len() < pattern_len * 3 {
                continue;
            }

            let pattern = &jitters[..pattern_len];
            let mut matches = 0;
            let mut checks = 0;

            for chunk in jitters.chunks(pattern_len) {
                if chunk.len() == pattern_len {
                    checks += 1;
                    if chunk == pattern {
                        matches += 1;
                    }
                }
            }

            if checks > MIN_PATTERN_CHECKS_EXCLUSIVE
                && matches as f64 / checks as f64 > REPEATING_PATTERN_THRESHOLD
            {
                return Some(pattern_len);
            }
        }
        None
    }

    fn detect_repeating_pattern_records(&self, records: &[Evidence]) -> Option<usize> {
        if records.len() < 6 {
            return None;
        }

        for pattern_len in 2..=5 {
            if records.len() < pattern_len * 3 {
                continue;
            }

            let pattern = &records[..pattern_len];
            let mut matches = 0;
            let mut checks = 0;

            for chunk in records.chunks(pattern_len) {
                if chunk.len() == pattern_len {
                    checks += 1;
                    let is_match = chunk
                        .iter()
                        .zip(pattern.iter())
                        .all(|(c, p)| c.jitter() == p.jitter());
                    if is_match {
                        matches += 1;
                    }
                }
            }

            if checks > MIN_PATTERN_CHECKS_EXCLUSIVE
                && matches as f64 / checks as f64 > REPEATING_PATTERN_THRESHOLD
            {
                return Some(pattern_len);
            }
        }
        None
    }
}
