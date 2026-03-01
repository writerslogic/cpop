// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Transcription Attack Detector for Proof-of-Process evidence.
//!
//! Detects the "Copy-Type" attack where a human transcribes AI-generated
//! text from a second screen. Based on the statistical divergence between
//! creative composition (high cognitive load, non-linear) and transcription
//! (low cognitive load, linear).
//!
//! Key insight from arXiv:2601.17280: authentic writing is a dynamic process
//! of monitoring and revising. Transcription is surprisingly linear — the
//! typist is translating visual symbols into motor signals, not composing.

use serde::{Deserialize, Serialize};

/// Raw data for transcription analysis, extracted from checkpoint metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionData {
    /// Total keystrokes captured across all checkpoints.
    pub total_keystrokes: usize,
    /// Number of deletion keystrokes (backspace/delete).
    pub deletions: usize,
    /// Number of non-sequential insertions (cursor repositioned before typing).
    pub insertions: usize,
    /// Average keystrokes between pauses > 2 seconds.
    pub avg_burst_length: f64,
    /// Number of distinct editing positions (cursor jumps).
    pub cursor_repositions: usize,
    /// Final document character count.
    pub final_char_count: usize,
}

/// Analyzes writing patterns to distinguish composition from transcription.
pub struct TranscriptionDetector {
    data: TranscriptionData,
}

impl TranscriptionDetector {
    pub fn from_data(data: &TranscriptionData) -> Self {
        Self { data: data.clone() }
    }

    /// Linearity Score: ratio of net progress to total keystrokes.
    ///
    /// Composition: 0.60–0.80 (revisions reduce the ratio).
    /// Transcription: > 0.92 (almost no backtracking).
    /// Perfect transcription: ~1.0 (zero deletions).
    pub fn calculate_linearity_score(&self) -> f64 {
        if self.data.total_keystrokes == 0 {
            return 1.0;
        }

        let revision_effort = self.data.deletions + self.data.insertions;
        (self.data.total_keystrokes as f64 - revision_effort as f64)
            / self.data.total_keystrokes as f64
    }

    /// Revision Density: deletions per 100 keystrokes.
    ///
    /// Composition: typically 8–25 deletions per 100 keystrokes.
    /// Transcription: typically < 3 deletions per 100 keystrokes.
    pub fn calculate_revision_density(&self) -> f64 {
        if self.data.total_keystrokes == 0 {
            return 0.0;
        }
        (self.data.deletions as f64 / self.data.total_keystrokes as f64) * 100.0
    }

    /// Non-Linearity Index: cursor repositions per 1000 characters.
    ///
    /// Composition: frequent cursor movement (going back to fix earlier text).
    /// Transcription: minimal cursor movement (sequential left-to-right).
    pub fn calculate_nonlinearity_index(&self) -> f64 {
        if self.data.final_char_count == 0 {
            return 0.0;
        }
        (self.data.cursor_repositions as f64 / self.data.final_char_count as f64) * 1000.0
    }

    /// Combined transcription attack detection.
    ///
    /// Returns true if the writing pattern is consistent with transcription
    /// rather than composition. Requires multiple signals to converge.
    pub fn is_transcription_attack(&self) -> bool {
        let linearity = self.calculate_linearity_score();
        let revision_density = self.calculate_revision_density();
        let nonlinearity = self.calculate_nonlinearity_index();

        // Primary signal: high linearity + long uninterrupted bursts
        let linear_typing = linearity > 0.92 && self.data.avg_burst_length > 15.0;

        // Secondary signal: very few revisions
        let no_revisions = revision_density < 3.0;

        // Tertiary signal: no cursor jumping
        let no_jumping = nonlinearity < 2.0;

        // Require at least 2 of 3 signals to flag
        let signals = [linear_typing, no_revisions, no_jumping];
        signals.iter().filter(|&&s| s).count() >= 2
    }

    /// Detailed analysis result for UI display.
    pub fn analyze(&self) -> TranscriptionAnalysis {
        let linearity = self.calculate_linearity_score();
        let revision_density = self.calculate_revision_density();
        let nonlinearity = self.calculate_nonlinearity_index();
        let is_attack = self.is_transcription_attack();

        let explanation = if is_attack {
            format!(
                "Writing pattern consistent with transcription: \
                 linearity={:.3} (threshold: 0.92), \
                 revision_density={:.1}/100ks (threshold: 3.0), \
                 cursor_repositions={:.1}/1000ch (threshold: 2.0)",
                linearity, revision_density, nonlinearity
            )
        } else {
            format!(
                "Writing pattern consistent with composition: \
                 linearity={:.3}, revision_density={:.1}/100ks, \
                 cursor_repositions={:.1}/1000ch",
                linearity, revision_density, nonlinearity
            )
        };

        TranscriptionAnalysis {
            linearity_score: linearity,
            revision_density,
            nonlinearity_index: nonlinearity,
            avg_burst_length: self.data.avg_burst_length,
            is_transcription: is_attack,
            explanation,
        }
    }
}

/// Detailed transcription analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionAnalysis {
    pub linearity_score: f64,
    pub revision_density: f64,
    pub nonlinearity_index: f64,
    pub avg_burst_length: f64,
    pub is_transcription: bool,
    pub explanation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genuine_composition() {
        let data = TranscriptionData {
            total_keystrokes: 5000,
            deletions: 600,  // 12% revision rate — typical composition
            insertions: 150, // Cursor-based insertions
            avg_burst_length: 8.5,
            cursor_repositions: 85,
            final_char_count: 4200,
        };
        let detector = TranscriptionDetector::from_data(&data);
        assert!(!detector.is_transcription_attack());
        assert!(detector.calculate_linearity_score() < 0.92);
    }

    #[test]
    fn test_transcription_detected() {
        let data = TranscriptionData {
            total_keystrokes: 5000,
            deletions: 50, // Only 1% revision — transcription
            insertions: 10,
            avg_burst_length: 22.0, // Long unbroken bursts
            cursor_repositions: 3,
            final_char_count: 4900,
        };
        let detector = TranscriptionDetector::from_data(&data);
        assert!(detector.is_transcription_attack());
        assert!(detector.calculate_linearity_score() > 0.92);
    }

    #[test]
    fn test_edge_case_fast_typist() {
        // Fast but genuine typist: high burst length but normal revisions
        let data = TranscriptionData {
            total_keystrokes: 5000,
            deletions: 400, // 8% — lower end but still human
            insertions: 100,
            avg_burst_length: 18.0, // Fast typist
            cursor_repositions: 45,
            final_char_count: 4500,
        };
        let detector = TranscriptionDetector::from_data(&data);
        // Should NOT flag — revision rate is too high for transcription
        assert!(!detector.is_transcription_attack());
    }
}
