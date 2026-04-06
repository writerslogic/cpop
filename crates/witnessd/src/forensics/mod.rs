// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Forensic authorship analysis: edit topology, keystroke cadence, and profile correlation.
//!
//! # Boundary with `analysis/`
//!
//! - **forensics/** = Domain-specific orchestration, scoring, and verdict logic
//!   for authorship evidence. Calls into `analysis/` for reusable algorithms.
//! - **analysis/** = Pure statistical algorithms (Hurst exponent, Lyapunov,
//!   SNR, perplexity, etc.) that are domain-agnostic and could be used outside
//!   forensics.
//!
//! The dependency is one-directional: `forensics -> analysis`.

pub(crate) mod analysis;
mod assessment;
mod cadence;
mod comparison;
mod correlation;
pub mod cross_modal;
pub mod dictation;
mod engine;
pub mod error;
pub mod event_validation;
pub mod forgery_cost;
mod report;
pub(crate) mod scoring;
mod topology;
pub mod types;
mod velocity;
pub mod writing_mode;

pub use analysis::*;
pub use assessment::*;
pub use cadence::*;
pub use comparison::*;
pub use correlation::*;
pub use cross_modal::{
    analyze_cross_modal, CrossModalCheck, CrossModalInput, CrossModalResult, CrossModalVerdict,
};
pub use engine::*;
pub use error::*;
pub use event_validation::{
    validate_keystroke_event, EventValidationFlags, EventValidationResult, EventValidationState,
};
pub use forgery_cost::{
    estimate_forgery_cost, ComponentCost, ForgeryCostEstimate, ForgeryCostInput,
    ForgeryResistanceTier,
};
pub use report::*;
pub use scoring::{cadence_score_from_samples, compute_focus_penalty, session_forensic_score};
pub use topology::*;
pub use types::*;
pub use velocity::*;
pub use writing_mode::{classify_writing_mode, RevisionPattern, WritingMode, WritingModeAnalysis};

#[cfg(test)]
mod tests;
