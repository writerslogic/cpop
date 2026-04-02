// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Content-keystroke correlation analysis.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::types::{DEFAULT_EDIT_RATIO, INCONSISTENT_RATIO_THRESHOLD, SUSPICIOUS_RATIO_THRESHOLD};

/// Input parameters for content-keystroke correlation.
#[derive(Debug, Clone, Default)]
pub struct CorrelationInput {
    pub document_length: i64,
    pub total_keystrokes: i64,
    pub detected_paste_chars: i64,
    pub detected_paste_count: i64,
    pub autocomplete_chars: i64,
    pub suspicious_bursts: usize,
    /// Override for estimated edit ratio (fraction of keystrokes that are deletions).
    pub actual_edit_ratio: Option<f64>,
}

/// Result of content-keystroke correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub document_length: i64,
    pub total_keystrokes: i64,
    pub detected_paste_chars: i64,
    pub detected_paste_count: i64,
    pub effective_keystrokes: i64,
    pub expected_content: i64,
    pub discrepancy: i64,
    pub discrepancy_ratio: f64,
    pub autocomplete_chars: i64,
    pub suspicious_bursts: usize,
    pub status: CorrelationStatus,
    pub explanation: String,
    pub flags: Vec<CorrelationFlag>,
}

/// Content-keystroke correlation verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationStatus {
    Consistent,
    Suspicious,
    Inconsistent,
    Insufficient,
}

impl fmt::Display for CorrelationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CorrelationStatus::Consistent => write!(f, "consistent"),
            CorrelationStatus::Suspicious => write!(f, "suspicious"),
            CorrelationStatus::Inconsistent => write!(f, "inconsistent"),
            CorrelationStatus::Insufficient => write!(f, "insufficient"),
        }
    }
}

/// Flags raised during correlation analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationFlag {
    ExcessContent,
    UndetectedPaste,
    Autocomplete,
    NoKeystrokes,
    HighEditRatio,
    ExternalGenerated,
}

impl fmt::Display for CorrelationFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CorrelationFlag::ExcessContent => write!(f, "excess_content"),
            CorrelationFlag::UndetectedPaste => write!(f, "undetected_paste"),
            CorrelationFlag::Autocomplete => write!(f, "autocomplete"),
            CorrelationFlag::NoKeystrokes => write!(f, "no_keystrokes"),
            CorrelationFlag::HighEditRatio => write!(f, "high_edit_ratio"),
            CorrelationFlag::ExternalGenerated => write!(f, "external_generated"),
        }
    }
}

/// Configurable content-keystroke correlator with tunable thresholds.
#[derive(Debug, Clone)]
pub struct ContentKeystrokeCorrelator {
    suspicious_ratio_threshold: f64,
    inconsistent_ratio_threshold: f64,
    estimated_edit_ratio: f64,
    min_keystrokes: i64,
    min_document_length: i64,
}

impl Default for ContentKeystrokeCorrelator {
    fn default() -> Self {
        Self {
            suspicious_ratio_threshold: SUSPICIOUS_RATIO_THRESHOLD,
            inconsistent_ratio_threshold: INCONSISTENT_RATIO_THRESHOLD,
            estimated_edit_ratio: DEFAULT_EDIT_RATIO,
            min_keystrokes: 10,
            min_document_length: 50,
        }
    }
}

impl ContentKeystrokeCorrelator {
    /// Create with default thresholds.
    pub fn new() -> Self {
        Self::default()
    }

    /// Run correlation analysis.
    pub fn analyze(&self, input: &CorrelationInput) -> CorrelationResult {
        let mut result = CorrelationResult {
            document_length: input.document_length,
            total_keystrokes: input.total_keystrokes,
            detected_paste_chars: input.detected_paste_chars,
            detected_paste_count: input.detected_paste_count,
            effective_keystrokes: 0,
            expected_content: 0,
            discrepancy: 0,
            discrepancy_ratio: 0.0,
            autocomplete_chars: input.autocomplete_chars,
            suspicious_bursts: input.suspicious_bursts,
            status: CorrelationStatus::Insufficient,
            explanation: String::new(),
            flags: Vec::new(),
        };

        if input.total_keystrokes < self.min_keystrokes
            && input.document_length < self.min_document_length
        {
            result.explanation =
                "Insufficient data for meaningful correlation analysis".to_string();
            return result;
        }

        let edit_ratio = input.actual_edit_ratio.unwrap_or(self.estimated_edit_ratio);
        result.effective_keystrokes = (input.total_keystrokes as f64 * (1.0 - edit_ratio)) as i64;

        result.expected_content =
            result.effective_keystrokes + input.detected_paste_chars + input.autocomplete_chars;

        if result.expected_content <= 0 {
            if input.document_length > 0 {
                result.status = CorrelationStatus::Inconsistent;
                result.explanation =
                    "Document has content but no keystroke/paste activity detected".to_string();
                result.flags.push(CorrelationFlag::NoKeystrokes);
                result.flags.push(CorrelationFlag::ExternalGenerated);
            } else {
                result.status = CorrelationStatus::Consistent;
                result.explanation = "Empty document with no activity".to_string();
            }
            return result;
        }

        result.discrepancy = input.document_length - result.expected_content;
        result.discrepancy_ratio = result.discrepancy as f64 / result.expected_content as f64;
        if !result.discrepancy_ratio.is_finite() {
            result.discrepancy_ratio = 0.0;
        }

        self.assess_discrepancy(&mut result, input);

        result
    }

    fn assess_discrepancy(&self, result: &mut CorrelationResult, input: &CorrelationInput) {
        let abs_ratio = result.discrepancy_ratio.abs();

        if input.suspicious_bursts > 0 {
            result.flags.push(CorrelationFlag::Autocomplete);
        }

        if result.discrepancy > 0 {
            if abs_ratio >= self.inconsistent_ratio_threshold {
                result.status = CorrelationStatus::Inconsistent;
                result.flags.push(CorrelationFlag::ExcessContent);

                let unexplained = result.discrepancy;
                if unexplained > 100 && input.detected_paste_count == 0 {
                    result.flags.push(CorrelationFlag::UndetectedPaste);
                    result.explanation = format!(
                        "Content exceeds expected by {} bytes ({:.0}%); likely undetected paste or external generation",
                        result.discrepancy, abs_ratio * 100.0
                    );
                } else if input.suspicious_bursts > 3 {
                    result.flags.push(CorrelationFlag::ExternalGenerated);
                    result.explanation = format!(
                        "Content exceeds expected by {} bytes ({:.0}%) with {} suspicious velocity bursts",
                        result.discrepancy, abs_ratio * 100.0, input.suspicious_bursts
                    );
                } else {
                    result.explanation = format!(
                        "Content exceeds expected by {} bytes ({:.0}%)",
                        result.discrepancy,
                        abs_ratio * 100.0
                    );
                }
            } else if abs_ratio >= self.suspicious_ratio_threshold {
                result.status = CorrelationStatus::Suspicious;
                result.explanation = format!(
                    "Minor discrepancy: content exceeds expected by {} bytes ({:.0}%)",
                    result.discrepancy,
                    abs_ratio * 100.0
                );
            } else {
                result.status = CorrelationStatus::Consistent;
                result.explanation =
                    "Content length is consistent with keystroke activity".to_string();
            }
            return;
        }

        if result.discrepancy < 0 {
            if abs_ratio >= self.suspicious_ratio_threshold {
                result.status = CorrelationStatus::Suspicious;
                result.flags.push(CorrelationFlag::HighEditRatio);
                result.explanation = format!(
                    "Document is {} bytes shorter than expected; indicates heavy editing ({:.0}% edit ratio)",
                    -result.discrepancy, abs_ratio * 100.0
                );
            } else {
                result.status = CorrelationStatus::Consistent;
                result.explanation =
                    "Content length is consistent with keystroke activity (normal editing)"
                        .to_string();
            }
            return;
        }

        result.status = CorrelationStatus::Consistent;
        result.explanation =
            "Content length exactly matches expected keystroke activity".to_string();
    }
}
