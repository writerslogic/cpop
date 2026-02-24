//! Error topology analysis for human behavioral verification.
//!
//! Analyzes the spatial and temporal distribution of errors (backspaces,
//! corrections, deletions) in typing sessions. Human error patterns exhibit
//! characteristic topological features that are difficult to simulate.
//!
//! RFC draft-condrey-rats-pop-01 specifies the error topology score:
//!
//!   S = 0.4 × ρ_gap + 0.4 × H + 0.2 × adj_phys
//!
//! Where:
//! - ρ_gap: Gap correlation (pauses before/after errors)
//! - H: Hurst exponent of error timing
//! - adj_phys: Physical adjacency correlation (keyboard layout)
//!
//! A score ≥ 0.75 indicates biologically plausible error patterns.

use serde::{Deserialize, Serialize};

/// Result of error topology analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorTopology {
    /// Gap correlation score (ρ_gap).
    /// Measures correlation between pauses and error events.
    pub gap_correlation: f64,

    /// Hurst exponent of error timing sequence.
    pub error_hurst: f64,

    /// Physical adjacency correlation.
    /// How often errors involve adjacent keys.
    pub adjacency_correlation: f64,

    /// Combined topology score.
    /// S = 0.4 × ρ_gap + 0.4 × H + 0.2 × adj_phys
    pub score: f64,

    /// Whether the score passes RFC threshold (≥ 0.75).
    pub is_valid: bool,

    /// Total number of errors detected.
    pub error_count: usize,

    /// Error rate (errors per 100 events).
    pub error_rate: f64,

    /// Breakdown of error types.
    pub error_distribution: ErrorDistribution,
}

/// Distribution of error types in the session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorDistribution {
    /// Immediate corrections (within 500ms).
    pub immediate_corrections: usize,
    /// Delayed corrections (500ms - 2s).
    pub delayed_corrections: usize,
    /// Long-delayed corrections (> 2s).
    pub long_delayed_corrections: usize,
    /// Burst errors (multiple in quick succession).
    pub burst_errors: usize,
    /// Isolated errors (surrounded by normal typing).
    pub isolated_errors: usize,
}

impl ErrorTopology {
    /// RFC threshold for valid error topology.
    pub const VALIDITY_THRESHOLD: f64 = 0.75;

    /// Weight for gap correlation in score.
    pub const WEIGHT_GAP: f64 = 0.4;
    /// Weight for Hurst exponent in score.
    pub const WEIGHT_HURST: f64 = 0.4;
    /// Weight for adjacency correlation in score.
    pub const WEIGHT_ADJACENCY: f64 = 0.2;

    /// Calculate the combined score from components.
    pub fn calculate_score(
        gap_correlation: f64,
        error_hurst: f64,
        adjacency_correlation: f64,
    ) -> f64 {
        Self::WEIGHT_GAP * gap_correlation
            + Self::WEIGHT_HURST * error_hurst
            + Self::WEIGHT_ADJACENCY * adjacency_correlation
    }

    /// Check if error patterns are biologically plausible.
    pub fn is_biologically_plausible(&self) -> bool {
        self.score >= Self::VALIDITY_THRESHOLD
    }

    /// Check if error rate is within human range (1-10%).
    pub fn is_error_rate_plausible(&self) -> bool {
        self.error_rate >= 1.0 && self.error_rate <= 10.0
    }
}

/// Event type for error analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Normal keystroke.
    Normal,
    /// Backspace/delete (error correction).
    Correction,
    /// Word deletion.
    WordDelete,
    /// Line deletion.
    LineDelete,
}

/// A single event for error topology analysis.
#[derive(Debug, Clone)]
pub struct TopologyEvent {
    /// Timestamp in nanoseconds.
    pub timestamp_ns: i64,
    /// Event type.
    pub event_type: EventType,
    /// Optional key code (for adjacency analysis).
    pub key_code: Option<u16>,
    /// Duration since last event (nanoseconds).
    pub gap_ns: u64,
}

/// Analyze error topology from a sequence of events.
///
/// # Arguments
/// * `events` - Sequence of typed events with timestamps and types
///
/// # Returns
/// * `ErrorTopology` analysis result
pub fn analyze_error_topology(events: &[TopologyEvent]) -> Result<ErrorTopology, String> {
    if events.len() < 20 {
        return Err("Insufficient events for error topology analysis (minimum 20)".to_string());
    }

    // Identify error events
    let error_indices: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            matches!(
                e.event_type,
                EventType::Correction | EventType::WordDelete | EventType::LineDelete
            )
        })
        .map(|(i, _)| i)
        .collect();

    let error_count = error_indices.len();
    if error_count < 3 {
        // Not enough errors for meaningful topology analysis
        return Ok(ErrorTopology {
            gap_correlation: 0.0,
            error_hurst: 0.5,
            adjacency_correlation: 0.0,
            score: 0.0,
            is_valid: false,
            error_count,
            error_rate: (error_count as f64 / events.len() as f64) * 100.0,
            error_distribution: ErrorDistribution::default(),
        });
    }

    // Calculate gap correlation
    let gap_correlation = calculate_gap_correlation(events, &error_indices);

    // Calculate Hurst exponent of error timing
    let error_hurst = calculate_error_hurst(events, &error_indices);

    // Calculate adjacency correlation
    let adjacency_correlation = calculate_adjacency_correlation(events, &error_indices);

    // Calculate combined score
    let score = ErrorTopology::calculate_score(gap_correlation, error_hurst, adjacency_correlation);
    let is_valid = score >= ErrorTopology::VALIDITY_THRESHOLD;

    // Calculate error distribution
    let error_distribution = calculate_error_distribution(events, &error_indices);

    let error_rate = (error_count as f64 / events.len() as f64) * 100.0;

    Ok(ErrorTopology {
        gap_correlation,
        error_hurst,
        adjacency_correlation,
        score,
        is_valid,
        error_count,
        error_rate,
        error_distribution,
    })
}

/// Calculate gap correlation (ρ_gap).
///
/// Measures the correlation between pause duration and error probability.
/// Human typing shows longer pauses before errors (hesitation) and
/// shorter pauses after (quick correction).
fn calculate_gap_correlation(events: &[TopologyEvent], error_indices: &[usize]) -> f64 {
    if error_indices.is_empty() || events.len() < 3 {
        return 0.0;
    }

    // Collect gaps before and after errors
    let mut pre_error_gaps = Vec::new();
    let mut post_error_gaps = Vec::new();
    let mut normal_gaps = Vec::new();

    for (i, event) in events.iter().enumerate() {
        let gap_ms = event.gap_ns as f64 / 1_000_000.0;

        if error_indices.contains(&i) {
            // This is an error event - record gap before it
            pre_error_gaps.push(gap_ms);
        } else if i > 0 && error_indices.contains(&(i - 1)) {
            // Previous event was an error - record gap after error
            post_error_gaps.push(gap_ms);
        } else {
            normal_gaps.push(gap_ms);
        }
    }

    if normal_gaps.is_empty() || pre_error_gaps.is_empty() {
        return 0.0;
    }

    // Calculate means
    let normal_mean: f64 = normal_gaps.iter().sum::<f64>() / normal_gaps.len() as f64;
    let pre_error_mean: f64 = pre_error_gaps.iter().sum::<f64>() / pre_error_gaps.len() as f64;
    let post_error_mean: f64 = if !post_error_gaps.is_empty() {
        post_error_gaps.iter().sum::<f64>() / post_error_gaps.len() as f64
    } else {
        normal_mean
    };

    // Gap correlation:
    // - Pre-error gaps should be longer than normal (hesitation)
    // - Post-error gaps should be shorter than normal (quick correction)
    let pre_ratio = if normal_mean > 0.0 {
        (pre_error_mean / normal_mean).min(3.0)
    } else {
        1.0
    };

    let post_ratio = if normal_mean > 0.0 {
        (normal_mean / post_error_mean.max(1.0)).min(3.0)
    } else {
        1.0
    };

    // Normalize to 0-1 range
    // Expect pre_ratio > 1 (longer before error) and post_ratio > 1 (faster after)

    ((pre_ratio - 1.0).max(0.0) * 0.5 + (post_ratio - 1.0).max(0.0) * 0.5).min(1.0)
}

/// Calculate Hurst exponent of error timing.
///
/// Uses simplified R/S analysis on the inter-error intervals.
fn calculate_error_hurst(events: &[TopologyEvent], error_indices: &[usize]) -> f64 {
    if error_indices.len() < 5 {
        return 0.5; // Default to white noise if insufficient errors
    }

    // Calculate inter-error intervals
    let mut intervals = Vec::new();
    for i in 1..error_indices.len() {
        let prev_idx = error_indices[i - 1];
        let curr_idx = error_indices[i];

        if curr_idx > prev_idx {
            let time_diff = events[curr_idx].timestamp_ns - events[prev_idx].timestamp_ns;
            if time_diff > 0 {
                intervals.push(time_diff as f64);
            }
        }
    }

    if intervals.len() < 4 {
        return 0.5;
    }

    // Simplified Hurst estimation using variance ratio
    let n = intervals.len();
    let mean: f64 = intervals.iter().sum::<f64>() / n as f64;
    let variance: f64 = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n as f64;

    // Calculate range
    let mut cumsum = 0.0;
    let mut max_cumsum = f64::NEG_INFINITY;
    let mut min_cumsum = f64::INFINITY;

    for &x in &intervals {
        cumsum += x - mean;
        max_cumsum = max_cumsum.max(cumsum);
        min_cumsum = min_cumsum.min(cumsum);
    }

    let range = max_cumsum - min_cumsum;
    let std_dev = variance.sqrt();

    if std_dev > 0.0 && range > 0.0 {
        // R/S ratio
        let rs = range / std_dev;
        // Estimate Hurst: H ≈ log(R/S) / log(n)

        (rs.ln() / (n as f64).ln()).clamp(0.0, 1.0)
    } else {
        0.5
    }
}

/// Calculate physical adjacency correlation.
///
/// Measures how often error corrections involve adjacent keys on
/// the keyboard layout.
fn calculate_adjacency_correlation(events: &[TopologyEvent], error_indices: &[usize]) -> f64 {
    if error_indices.is_empty() {
        return 0.0;
    }

    let mut adjacent_errors = 0;
    let mut total_with_keys = 0;

    for &error_idx in error_indices {
        // Look at the key before the correction
        if error_idx > 0 {
            let prev_event = &events[error_idx - 1];
            let curr_event = &events[error_idx];

            if let (Some(prev_key), Some(curr_key)) = (prev_event.key_code, curr_event.key_code) {
                total_with_keys += 1;
                if are_keys_adjacent(prev_key, curr_key) {
                    adjacent_errors += 1;
                }
            }
        }
    }

    if total_with_keys > 0 {
        // Human typing errors are often adjacent key mistakes
        // Expected adjacency rate for humans: ~20-40%
        let adjacency_rate = adjacent_errors as f64 / total_with_keys as f64;

        // Normalize: too low suggests random errors, too high suggests simulation
        if (0.15..=0.50).contains(&adjacency_rate) {
            1.0
        } else if adjacency_rate < 0.15 {
            adjacency_rate / 0.15
        } else {
            (1.0 - (adjacency_rate - 0.50) / 0.50).max(0.0)
        }
    } else {
        // No key code data available - neutral score
        0.5
    }
}

/// Check if two key codes are adjacent on a QWERTY keyboard.
///
/// This is a simplified check using common key code mappings.
fn are_keys_adjacent(key1: u16, key2: u16) -> bool {
    // Define QWERTY keyboard adjacency (US layout)
    // Key codes vary by platform; this is a simplified heuristic

    // Group keys by row and check horizontal/vertical adjacency
    let pos1 = key_to_position(key1);
    let pos2 = key_to_position(key2);

    if let (Some((r1, c1)), Some((r2, c2))) = (pos1, pos2) {
        let row_diff = (r1 as i32 - r2 as i32).abs();
        let col_diff = (c1 as i32 - c2 as i32).abs();

        // Adjacent if within 1 row and 1 column
        row_diff <= 1 && col_diff <= 1 && (row_diff + col_diff) > 0
    } else {
        false
    }
}

/// Map key code to approximate (row, column) position.
///
/// Returns None for unknown key codes.
fn key_to_position(key: u16) -> Option<(u8, u8)> {
    // Simplified mapping for common ASCII letters
    // Row 0: number row, Row 1: QWERTY, Row 2: ASDF, Row 3: ZXCV
    match key as u8 as char {
        '1'..='9' => Some((0, (key - '1' as u16) as u8)),
        '0' => Some((0, 9)),
        'q' | 'Q' => Some((1, 0)),
        'w' | 'W' => Some((1, 1)),
        'e' | 'E' => Some((1, 2)),
        'r' | 'R' => Some((1, 3)),
        't' | 'T' => Some((1, 4)),
        'y' | 'Y' => Some((1, 5)),
        'u' | 'U' => Some((1, 6)),
        'i' | 'I' => Some((1, 7)),
        'o' | 'O' => Some((1, 8)),
        'p' | 'P' => Some((1, 9)),
        'a' | 'A' => Some((2, 0)),
        's' | 'S' => Some((2, 1)),
        'd' | 'D' => Some((2, 2)),
        'f' | 'F' => Some((2, 3)),
        'g' | 'G' => Some((2, 4)),
        'h' | 'H' => Some((2, 5)),
        'j' | 'J' => Some((2, 6)),
        'k' | 'K' => Some((2, 7)),
        'l' | 'L' => Some((2, 8)),
        'z' | 'Z' => Some((3, 0)),
        'x' | 'X' => Some((3, 1)),
        'c' | 'C' => Some((3, 2)),
        'v' | 'V' => Some((3, 3)),
        'b' | 'B' => Some((3, 4)),
        'n' | 'N' => Some((3, 5)),
        'm' | 'M' => Some((3, 6)),
        _ => None,
    }
}

/// Calculate error distribution statistics.
fn calculate_error_distribution(
    events: &[TopologyEvent],
    error_indices: &[usize],
) -> ErrorDistribution {
    let mut dist = ErrorDistribution::default();

    for (i, &error_idx) in error_indices.iter().enumerate() {
        let event = &events[error_idx];
        let gap_ms = event.gap_ns as f64 / 1_000_000.0;

        // Classify by timing
        if gap_ms < 500.0 {
            dist.immediate_corrections += 1;
        } else if gap_ms < 2000.0 {
            dist.delayed_corrections += 1;
        } else {
            dist.long_delayed_corrections += 1;
        }

        // Check for bursts (multiple errors within 1 second)
        let is_burst = if i > 0 {
            let prev_idx = error_indices[i - 1];
            let time_diff = (events[error_idx].timestamp_ns - events[prev_idx].timestamp_ns) as f64
                / 1_000_000_000.0;
            time_diff < 1.0
        } else {
            false
        };

        if is_burst {
            dist.burst_errors += 1;
        } else {
            dist.isolated_errors += 1;
        }
    }

    dist
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_events(pattern: &[(i64, EventType, u64)]) -> Vec<TopologyEvent> {
        let mut events = Vec::new();
        let mut timestamp = 0i64;

        for &(gap_ms, event_type, _) in pattern {
            timestamp += gap_ms * 1_000_000; // Convert to ns
            events.push(TopologyEvent {
                timestamp_ns: timestamp,
                event_type,
                key_code: None,
                gap_ns: (gap_ms * 1_000_000) as u64,
            });
        }

        events
    }

    #[test]
    fn test_error_topology_basic() {
        // Create realistic typing pattern with some errors
        let pattern: Vec<(i64, EventType, u64)> = vec![
            (200, EventType::Normal, 0),
            (150, EventType::Normal, 0),
            (180, EventType::Normal, 0),
            (400, EventType::Correction, 0), // Pause before error
            (100, EventType::Normal, 0),     // Quick recovery
            (200, EventType::Normal, 0),
            (150, EventType::Normal, 0),
            (350, EventType::Correction, 0),
            (120, EventType::Normal, 0),
            (200, EventType::Normal, 0),
            (180, EventType::Normal, 0),
            (420, EventType::Correction, 0),
            (110, EventType::Normal, 0),
            (200, EventType::Normal, 0),
            (150, EventType::Normal, 0),
            (200, EventType::Normal, 0),
            (180, EventType::Normal, 0),
            (200, EventType::Normal, 0),
            (150, EventType::Normal, 0),
            (200, EventType::Normal, 0),
        ];

        let events = create_test_events(&pattern);
        let result = analyze_error_topology(&events).unwrap();

        assert_eq!(result.error_count, 3);
        assert!(result.error_rate > 0.0);
    }

    #[test]
    fn test_insufficient_events() {
        let pattern: Vec<(i64, EventType, u64)> =
            vec![(200, EventType::Normal, 0), (150, EventType::Normal, 0)];

        let events = create_test_events(&pattern);
        let result = analyze_error_topology(&events);

        assert!(result.is_err());
    }

    #[test]
    fn test_score_calculation() {
        let score = ErrorTopology::calculate_score(0.8, 0.7, 0.6);
        let expected = 0.4 * 0.8 + 0.4 * 0.7 + 0.2 * 0.6;
        assert!((score - expected).abs() < 0.001);
    }

    #[test]
    fn test_key_adjacency() {
        // Q and W should be adjacent
        assert!(are_keys_adjacent('q' as u16, 'w' as u16));
        // Q and A should be adjacent (diagonal)
        assert!(are_keys_adjacent('q' as u16, 'a' as u16));
        // Q and Z should not be adjacent
        assert!(!are_keys_adjacent('q' as u16, 'z' as u16));
    }

    #[test]
    fn test_error_distribution() {
        let pattern: Vec<(i64, EventType, u64)> = vec![
            (200, EventType::Normal, 0),
            (100, EventType::Correction, 0), // Immediate
            (200, EventType::Normal, 0),
            (800, EventType::Correction, 0), // Delayed
            (200, EventType::Normal, 0),
            (3000, EventType::Correction, 0), // Long-delayed
        ];

        // Pad with more events to meet minimum
        let mut full_pattern = pattern.clone();
        for _ in 0..15 {
            full_pattern.push((200, EventType::Normal, 0));
        }

        let events = create_test_events(&full_pattern);
        let result = analyze_error_topology(&events).unwrap();

        assert_eq!(result.error_distribution.immediate_corrections, 1);
        assert_eq!(result.error_distribution.delayed_corrections, 1);
        assert_eq!(result.error_distribution.long_delayed_corrections, 1);
    }
}
