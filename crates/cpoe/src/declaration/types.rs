// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Signed author declaration binding document hash, AI usage, and input modalities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Declaration {
    pub document_hash: [u8; 32],
    pub chain_hash: [u8; 32],
    pub title: String,
    pub input_modalities: Vec<InputModality>,
    pub ai_tools: Vec<AiToolUsage>,
    pub collaborators: Vec<Collaborator>,
    pub statement: String,
    pub created_at: DateTime<Utc>,
    pub version: u64,
    pub author_public_key: Vec<u8>,
    pub signature: Vec<u8>,
    /// Hardware-sealed typing proof binding declaration to live human presence (WAR/1.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter_sealed: Option<DeclarationJitter>,
}

/// Jitter evidence captured during interactive declaration typing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclarationJitter {
    /// SHA-256 hash of the jitter samples collected during declaration typing
    pub jitter_hash: [u8; 32],
    pub keystroke_count: u64,
    pub duration_ms: u64,
    pub avg_interval_ms: f64,
    pub entropy_bits: f64,
    pub hardware_sealed: bool,
}

/// Input method with its percentage share of total content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputModality {
    #[serde(rename = "type")]
    pub modality_type: ModalityType,
    pub percentage: f64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModalityType {
    /// Physical keyboard typing.
    Keyboard,
    /// Voice-to-text dictation.
    Dictation,
    /// Stylus or handwriting recognition.
    Handwriting,
    /// Clipboard paste from external source.
    Paste,
    /// File or data import.
    Import,
    /// Combination of multiple modalities.
    Mixed,
    /// Unclassified input method.
    Other,
}

/// Record of a specific AI tool's role and extent in content creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiToolUsage {
    pub tool: String,
    pub version: Option<String>,
    pub purpose: AiPurpose,
    pub interaction: Option<String>,
    pub extent: AiExtent,
    pub sections: Vec<String>,
}

/// How an AI tool was used in the authoring process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiPurpose {
    /// Brainstorming or generating ideas.
    Ideation,
    /// Structuring or outlining content.
    Outline,
    /// Generating draft text.
    Drafting,
    /// Providing feedback on existing text.
    Feedback,
    /// Editing or revising content.
    Editing,
    /// Gathering or summarizing research material.
    Research,
    /// Layout, styling, or formatting assistance.
    Formatting,
    /// Unclassified AI purpose.
    Other,
}

/// Degree of AI involvement in content creation, ordered from least to most.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum AiExtent {
    /// No AI involvement.
    None = 0,
    /// Minor AI assistance (e.g., spell-check, single suggestions).
    Minimal = 1,
    /// Moderate AI use (e.g., paragraph-level drafting or editing).
    Moderate = 2,
    /// Heavy AI reliance (e.g., majority of content AI-generated).
    Substantial = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collaborator {
    pub name: String,
    pub role: CollaboratorRole,
    pub sections: Vec<String>,
    pub public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CollaboratorRole {
    /// Equal co-author with shared ownership.
    #[serde(rename = "co-author")]
    CoAuthor,
    /// Edited or revised existing content.
    #[serde(rename = "editor")]
    Editor,
    /// Gathered or provided research material.
    #[serde(rename = "research_assistant")]
    ResearchAssistant,
    /// Reviewed and provided feedback.
    #[serde(rename = "reviewer")]
    Reviewer,
    /// Transcribed spoken or handwritten content.
    #[serde(rename = "transcriber")]
    Transcriber,
    /// Unclassified collaborator role.
    #[serde(rename = "other")]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclarationSummary {
    pub title: String,
    pub ai_usage: bool,
    pub ai_tools: Vec<String>,
    pub max_ai_extent: String,
    pub collaborators: usize,
    pub signature_valid: bool,
}
