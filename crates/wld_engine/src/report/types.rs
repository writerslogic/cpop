// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// ENFSI verbal equivalence scale for likelihood ratios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnfsiTier {
    /// LR < 1 — evidence supports the alternative hypothesis
    Against,
    /// LR 1–10
    Weak,
    /// LR 10–100
    Moderate,
    /// LR 100–1,000
    ModeratelyStrong,
    /// LR 1,000–10,000
    Strong,
    /// LR >= 10,000
    VeryStrong,
}

impl EnfsiTier {
    pub fn from_lr(lr: f64) -> Self {
        if lr < 1.0 {
            Self::Against
        } else if lr < 10.0 {
            Self::Weak
        } else if lr < 100.0 {
            Self::Moderate
        } else if lr < 1_000.0 {
            Self::ModeratelyStrong
        } else if lr < 10_000.0 {
            Self::Strong
        } else {
            Self::VeryStrong
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Against => "Against",
            Self::Weak => "Weak support",
            Self::Moderate => "Moderate support",
            Self::ModeratelyStrong => "Moderately strong",
            Self::Strong => "Strong support",
            Self::VeryStrong => "Very strong support",
        }
    }
}

/// Verdict classification based on assessment score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    VerifiedHuman,
    LikelyHuman,
    Inconclusive,
    Suspicious,
    LikelySynthetic,
}

impl Verdict {
    pub fn from_score(score: u32) -> Self {
        match score {
            80..=100 => Self::VerifiedHuman,
            60..=79 => Self::LikelyHuman,
            40..=59 => Self::Inconclusive,
            20..=39 => Self::Suspicious,
            _ => Self::LikelySynthetic,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::VerifiedHuman => "VERIFIED HUMAN",
            Self::LikelyHuman => "LIKELY HUMAN",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::Suspicious => "SUSPICIOUS",
            Self::LikelySynthetic => "LIKELY SYNTHETIC",
        }
    }

    pub fn subtitle(&self) -> &'static str {
        match self {
            Self::VerifiedHuman => "Strong Constraint Indicators",
            Self::LikelyHuman => "Moderate Constraint Indicators",
            Self::Inconclusive => "Insufficient Evidence",
            Self::Suspicious => "Anomalous Patterns Detected",
            Self::LikelySynthetic => "Synthetic Generation Indicators",
        }
    }

    pub fn css_color(&self) -> &'static str {
        match self {
            Self::VerifiedHuman => "#2e7d32",
            Self::LikelyHuman => "#558b2f",
            Self::Inconclusive => "#f57f17",
            Self::Suspicious => "#e65100",
            Self::LikelySynthetic => "#b71c1c",
        }
    }
}

/// A single checkpoint in the evidence chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportCheckpoint {
    pub ordinal: u64,
    pub timestamp: DateTime<Utc>,
    pub content_hash: String,
    pub content_size: u64,
    pub vdf_iterations: Option<u64>,
    pub elapsed_ms: Option<u64>,
}

/// Session summary for the timeline section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSession {
    pub index: usize,
    pub start: DateTime<Utc>,
    pub duration_min: f64,
    pub event_count: usize,
    pub words_drafted: Option<u64>,
    pub device: Option<String>,
    pub summary: String,
}

/// Process evidence metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessEvidence {
    pub revision_intensity: Option<f64>,
    pub revision_baseline: Option<String>,
    pub pause_median_sec: Option<f64>,
    pub pause_p95_sec: Option<f64>,
    pub pause_max_sec: Option<f64>,
    pub paste_ratio_pct: Option<f64>,
    pub paste_operations: Option<u64>,
    pub paste_max_chars: Option<u64>,
    pub iki_cv: Option<f64>,
    pub bigram_consistency: Option<f64>,
    pub total_keystrokes: Option<u64>,
    pub deletion_sequences: Option<u64>,
    pub avg_deletion_length: Option<f64>,
    pub select_delete_ops: Option<u64>,
    pub swf_checkpoints: Option<u64>,
    pub swf_avg_compute_ms: Option<u64>,
    pub swf_chain_verified: bool,
    pub swf_backdating_hours: Option<f64>,
}

/// An anomaly or flag detected during analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFlag {
    pub category: String,
    pub flag: String,
    pub detail: String,
    pub signal: FlagSignal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlagSignal {
    Human,
    Neutral,
    Synthetic,
}

impl FlagSignal {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Human => "Human",
            Self::Neutral => "Neutral",
            Self::Synthetic => "Synthetic",
        }
    }

    pub fn css_color(&self) -> &'static str {
        match self {
            Self::Human => "#2e7d32",
            Self::Neutral => "#757575",
            Self::Synthetic => "#c62828",
        }
    }
}

/// Forgery resistance info for the report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForgeryInfo {
    pub tier: String,
    pub estimated_forge_time_sec: f64,
    pub weakest_link: Option<String>,
    pub components: Vec<ForgeryComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeryComponent {
    pub name: String,
    pub present: bool,
    pub cost_cpu_sec: f64,
    pub explanation: String,
}

/// The complete WAR report data structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarReport {
    // Header
    pub report_id: String,
    pub algorithm_version: String,
    pub generated_at: DateTime<Utc>,
    pub schema_version: String,
    pub is_sample: bool,

    // Verdict
    pub score: u32,
    pub verdict: Verdict,
    pub verdict_description: String,
    pub likelihood_ratio: f64,
    pub enfsi_tier: EnfsiTier,

    // Chain of custody
    pub document_hash: String,
    pub signing_key_fingerprint: String,
    pub document_words: Option<u64>,
    pub document_chars: Option<u64>,
    pub document_sentences: Option<u64>,
    pub document_paragraphs: Option<u64>,
    pub evidence_bundle_version: String,
    pub session_count: usize,
    pub total_duration_min: f64,
    pub revision_events: u64,
    pub device_attestation: String,
    pub blockchain_anchor: Option<String>,

    // Checkpoints
    pub checkpoints: Vec<ReportCheckpoint>,

    // Sessions
    pub sessions: Vec<ReportSession>,

    // Process evidence
    pub process: ProcessEvidence,

    // Flags
    pub flags: Vec<ReportFlag>,

    // Forgery resistance
    pub forgery: ForgeryInfo,

    // Scope
    pub limitations: Vec<String>,

    // Analyzed text
    pub analyzed_text: Option<String>,
}

impl WarReport {
    /// Generate a report ID in the format WAR-XXXXXXXX.
    pub fn generate_id() -> String {
        let mut bytes = [0u8; 4];
        let _ = getrandom::getrandom(&mut bytes);
        let hex = hex::encode(bytes).to_uppercase();
        format!("WAR-{}", hex)
    }
}
