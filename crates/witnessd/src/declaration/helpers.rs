// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use sha2::Sha256;

use super::types::{AiExtent, AiPurpose, CollaboratorRole, ModalityType};

pub(super) fn extent_rank(extent: &AiExtent) -> i32 {
    extent.clone() as i32
}

pub(super) fn modality_type_str(modality: &ModalityType) -> &'static str {
    match modality {
        ModalityType::Keyboard => "keyboard",
        ModalityType::Dictation => "dictation",
        ModalityType::Handwriting => "handwriting",
        ModalityType::Paste => "paste",
        ModalityType::Import => "import",
        ModalityType::Mixed => "mixed",
        ModalityType::Other => "other",
    }
}

pub(super) fn ai_purpose_str(purpose: &AiPurpose) -> &'static str {
    match purpose {
        AiPurpose::Ideation => "ideation",
        AiPurpose::Outline => "outline",
        AiPurpose::Drafting => "drafting",
        AiPurpose::Feedback => "feedback",
        AiPurpose::Editing => "editing",
        AiPurpose::Research => "research",
        AiPurpose::Formatting => "formatting",
        AiPurpose::Other => "other",
    }
}

pub(crate) fn ai_extent_str(extent: &AiExtent) -> &'static str {
    match extent {
        AiExtent::None => "none",
        AiExtent::Minimal => "minimal",
        AiExtent::Moderate => "moderate",
        AiExtent::Substantial => "substantial",
    }
}

pub(super) fn collaborator_role_str(role: &CollaboratorRole) -> &'static str {
    match role {
        CollaboratorRole::CoAuthor => "co-author",
        CollaboratorRole::Editor => "editor",
        CollaboratorRole::ResearchAssistant => "research_assistant",
        CollaboratorRole::Reviewer => "reviewer",
        CollaboratorRole::Transcriber => "transcriber",
        CollaboratorRole::Other => "other",
    }
}

/// Hash a length-prefixed string to prevent concatenation ambiguity.
pub(super) fn hash_str(hasher: &mut Sha256, s: &str) {
    use sha2::Digest;
    hasher.update((s.len() as u64).to_be_bytes());
    hasher.update(s.as_bytes());
}

/// Hash an optional string with a discriminant byte (0=None, 1=Some).
pub(super) fn hash_opt_str(hasher: &mut Sha256, opt: Option<&str>) {
    use sha2::Digest;
    match opt {
        Some(s) => {
            hasher.update([1u8]);
            hash_str(hasher, s);
        }
        None => {
            hasher.update([0u8]);
        }
    }
}

/// Hash optional bytes with a discriminant byte (0=None, 1=Some).
pub(super) fn hash_opt_bytes(hasher: &mut Sha256, opt: Option<&[u8]>) {
    use sha2::Digest;
    match opt {
        Some(b) => {
            hasher.update([1u8]);
            hasher.update((b.len() as u64).to_be_bytes());
            hasher.update(b);
        }
        None => {
            hasher.update([0u8]);
        }
    }
}
