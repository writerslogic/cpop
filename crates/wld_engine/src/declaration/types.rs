// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Declaration {
    pub document_hash: [u8; 32],
    pub chain_hash: [u8; 32],
    pub title: String,
    pub input_modalities: Vec<InputModality>,
    pub ai_tools: Vec<AIToolUsage>,
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
    Keyboard,
    Dictation,
    Handwriting,
    Paste,
    Import,
    Mixed,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIToolUsage {
    pub tool: String,
    pub version: Option<String>,
    pub purpose: AIPurpose,
    pub interaction: Option<String>,
    pub extent: AIExtent,
    pub sections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AIPurpose {
    Ideation,
    Outline,
    Drafting,
    Feedback,
    Editing,
    Research,
    Formatting,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum AIExtent {
    None = 0,
    Minimal = 1,
    Moderate = 2,
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
    #[serde(rename = "co-author")]
    CoAuthor,
    #[serde(rename = "editor")]
    Editor,
    #[serde(rename = "research_assistant")]
    ResearchAssistant,
    #[serde(rename = "reviewer")]
    Reviewer,
    #[serde(rename = "transcriber")]
    Transcriber,
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
