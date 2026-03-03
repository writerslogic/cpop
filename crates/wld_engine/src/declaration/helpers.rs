// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use sha2::Sha256;

use super::types::{AIExtent, AIPurpose, CollaboratorRole, ModalityType};

pub(super) fn extent_rank(extent: &AIExtent) -> i32 {
    match extent {
        AIExtent::None => 0,
        AIExtent::Minimal => 1,
        AIExtent::Moderate => 2,
        AIExtent::Substantial => 3,
    }
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

pub(super) fn ai_purpose_str(purpose: &AIPurpose) -> &'static str {
    match purpose {
        AIPurpose::Ideation => "ideation",
        AIPurpose::Outline => "outline",
        AIPurpose::Drafting => "drafting",
        AIPurpose::Feedback => "feedback",
        AIPurpose::Editing => "editing",
        AIPurpose::Research => "research",
        AIPurpose::Formatting => "formatting",
        AIPurpose::Other => "other",
    }
}

pub(crate) fn ai_extent_str(extent: &AIExtent) -> &'static str {
    match extent {
        AIExtent::None => "none",
        AIExtent::Minimal => "minimal",
        AIExtent::Moderate => "moderate",
        AIExtent::Substantial => "substantial",
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
