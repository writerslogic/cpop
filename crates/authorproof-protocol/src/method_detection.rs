// SPDX-License-Identifier: Apache-2.0

//! Authorship method detection and classification.
//!
//! Determines whether evidence indicates human composition, AI prompt generation,
//! human-in-the-loop collaboration, or insufficient signal for classification.
//!
//! All detections are conservative: confidence ≥0.85 for auto-detection,
//! <0.70 defaults to `Undetermined` with author attestation fallback.

use serde::{Deserialize, Serialize};

/// Authorship method classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorshipMethod {
    /// Human writing without AI assistance.
    HumanComposition,
    /// AI model generated, minimal human editing.
    PromptGeneration,
    /// Human + AI collaboration (iterative back-and-forth).
    HumanInTheLoop,
    /// Mostly AI-generated with sparse human refinement.
    HumanAssistedGeneration,
    /// Insufficient signal for classification.
    Undetermined,
}

impl AuthorshipMethod {
    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            AuthorshipMethod::HumanComposition => "Human Composition",
            AuthorshipMethod::PromptGeneration => "Prompt Generation",
            AuthorshipMethod::HumanInTheLoop => "Human-in-the-Loop",
            AuthorshipMethod::HumanAssistedGeneration => "Human-Assisted Generation",
            AuthorshipMethod::Undetermined => "Method Undetermined",
        }
    }
}

/// Origin of method classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodOrigin {
    /// Auto-detected from forensic signals (high confidence).
    AutoDetected,
    /// User corrected or confirmed a borderline detection.
    UserCorrected,
    /// Author attested (low confidence or insufficient signals).
    AuthorAttested,
}

/// Forensic signals that contributed to method classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalSet {
    /// Number of editing passes (clusters of revisions).
    pub revision_clusters: Option<u32>,
    /// Coefficient of variation of keystroke speeds (0.0-1.0).
    /// Low CV (<0.15) indicates transcription/pasting.
    /// High CV (>0.4) indicates human thinking/pausing.
    pub keystroke_variance: Option<f64>,
    /// Count of paste events detected from IKI patterns.
    pub paste_events: Option<u32>,
    /// Average typing speed in words per minute.
    pub typing_speed_wpm: Option<f64>,
    /// Number of application focus transitions.
    pub focus_transitions: Option<u32>,
    /// CV of typing speeds within bursts.
    /// <0.15 = robotic (transcription), >0.25 = human (cognitive).
    pub burst_speed_cv: Option<f64>,
    /// Count of inter-keystroke interval windows with near-zero variance.
    /// Indicates suspiciously regular timing (paste or generation).
    pub zero_variance_windows: Option<u32>,
    /// Fraction of keystrokes that are deletions/backspaces.
    /// High = human revision, low = AI-generated or transcribed.
    pub correction_ratio: Option<f64>,
    /// CV of keystroke speeds immediately following pauses >1s.
    /// Indicates post-thinking typing patterns (human).
    pub post_pause_cv: Option<f64>,
    /// Fraction of edits that append to document end.
    /// >0.95 = mostly append-only (generation), <0.7 = mixed (human).
    pub monotonic_append_ratio: Option<f64>,
}

impl SignalSet {
    /// Create an empty signal set (all None).
    pub fn empty() -> Self {
        SignalSet {
            revision_clusters: None,
            keystroke_variance: None,
            paste_events: None,
            typing_speed_wpm: None,
            focus_transitions: None,
            burst_speed_cv: None,
            zero_variance_windows: None,
            correction_ratio: None,
            post_pause_cv: None,
            monotonic_append_ratio: None,
        }
    }

    /// Count of signals that were populated.
    pub fn signal_count(&self) -> usize {
        [
            self.revision_clusters.is_some(),
            self.keystroke_variance.is_some(),
            self.paste_events.is_some(),
            self.typing_speed_wpm.is_some(),
            self.focus_transitions.is_some(),
            self.burst_speed_cv.is_some(),
            self.zero_variance_windows.is_some(),
            self.correction_ratio.is_some(),
            self.post_pause_cv.is_some(),
            self.monotonic_append_ratio.is_some(),
        ]
        .iter()
        .filter(|&&x| x)
        .count()
    }
}

/// Result of authorship method detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodDetectionResult {
    /// Detected authorship method.
    pub method: AuthorshipMethod,
    /// Confidence score [0.0, 1.0].
    /// ≥0.85: high confidence (auto-detect)
    /// 0.70–0.85: uncertain (user confirmation recommended)
    /// <0.70: insufficient signal (default to undetermined)
    pub confidence: f64,
    /// Origin of classification.
    pub origin: MethodOrigin,
    /// Forensic signals that contributed.
    pub signals: SignalSet,
    /// Names of signals that most influenced the decision.
    pub dominant_signals: Vec<String>,
}

impl MethodDetectionResult {
    /// Create a high-confidence detection.
    pub fn auto_detected(
        method: AuthorshipMethod,
        confidence: f64,
        signals: SignalSet,
        dominant_signals: Vec<String>,
    ) -> Self {
        MethodDetectionResult {
            method,
            confidence,
            origin: MethodOrigin::AutoDetected,
            signals,
            dominant_signals,
        }
    }

    /// Create a low-confidence/uncertain detection (user attestation fallback).
    pub fn author_attested(signals: SignalSet) -> Self {
        MethodDetectionResult {
            method: AuthorshipMethod::Undetermined,
            confidence: 0.0,
            origin: MethodOrigin::AuthorAttested,
            signals,
            dominant_signals: vec![],
        }
    }

    /// Check if this detection should auto-fill UI (confidence ≥0.85).
    pub fn should_auto_fill(&self) -> bool {
        self.confidence >= 0.85
    }

    /// Check if user confirmation is recommended (0.70 ≤ confidence < 0.85).
    pub fn should_confirm(&self) -> bool {
        self.confidence >= 0.70 && self.confidence < 0.85
    }

    /// Check if insufficient signal for classification (confidence < 0.70).
    pub fn insufficient_signal(&self) -> bool {
        self.confidence < 0.70
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorship_method_display() {
        assert_eq!(
            AuthorshipMethod::HumanComposition.display_name(),
            "Human Composition"
        );
        assert_eq!(
            AuthorshipMethod::PromptGeneration.display_name(),
            "Prompt Generation"
        );
        assert_eq!(
            AuthorshipMethod::HumanInTheLoop.display_name(),
            "Human-in-the-Loop"
        );
    }

    #[test]
    fn test_signal_set_empty() {
        let signals = SignalSet::empty();
        assert_eq!(signals.signal_count(), 0);
    }

    #[test]
    fn test_signal_set_count() {
        let mut signals = SignalSet::empty();
        signals.keystroke_variance = Some(0.35);
        signals.paste_events = Some(5);
        assert_eq!(signals.signal_count(), 2);
    }

    #[test]
    fn test_auto_detected_high_confidence() {
        let result = MethodDetectionResult::auto_detected(
            AuthorshipMethod::HumanComposition,
            0.92,
            SignalSet::empty(),
            vec!["keystroke_variance".to_string()],
        );
        assert!(result.should_auto_fill());
        assert!(!result.should_confirm());
        assert!(!result.insufficient_signal());
    }

    #[test]
    fn test_uncertain_detection() {
        let result = MethodDetectionResult::auto_detected(
            AuthorshipMethod::HumanInTheLoop,
            0.75,
            SignalSet::empty(),
            vec!["burst_speed_cv".to_string()],
        );
        assert!(!result.should_auto_fill());
        assert!(result.should_confirm());
        assert!(!result.insufficient_signal());
    }

    #[test]
    fn test_insufficient_signal() {
        let result = MethodDetectionResult::author_attested(SignalSet::empty());
        assert!(!result.should_auto_fill());
        assert!(!result.should_confirm());
        assert!(result.insufficient_signal());
        assert_eq!(result.method, AuthorshipMethod::Undetermined);
    }

    #[test]
    fn test_serde_round_trip() {
        let result = MethodDetectionResult::auto_detected(
            AuthorshipMethod::HumanComposition,
            0.88,
            SignalSet::empty(),
            vec!["keystroke_variance".to_string()],
        );
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: MethodDetectionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.method, result.method);
        assert_eq!(deserialized.confidence, result.confidence);
    }
}
