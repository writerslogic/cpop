// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Author declarations: AI usage, input modalities, collaborators, and jitter seals.

mod builder;
mod helpers;
mod types;
mod verification;

pub use builder::{ai_assisted_declaration, no_ai_declaration, Builder};
pub(crate) use helpers::ai_extent_str;
pub use types::{
    AiExtent, AiPurpose, AiToolUsage, Collaborator, CollaboratorRole, Declaration,
    DeclarationJitter, DeclarationSummary, InputModality, ModalityType,
};

#[cfg(test)]
mod tests;
