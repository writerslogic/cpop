// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Forensic authorship analysis: edit topology, keystroke cadence, and profile correlation.

mod analysis;
mod assessment;
mod cadence;
mod comparison;
mod correlation;
pub mod cross_modal;
pub mod dictation;
mod engine;
pub mod error;
pub mod forgery_cost;
mod report;
mod topology;
pub mod types;
mod velocity;

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
pub use forgery_cost::{
    estimate_forgery_cost, ComponentCost, ForgeryCostEstimate, ForgeryCostInput,
    ForgeryResistanceTier,
};
pub use report::*;
pub use topology::*;
pub use types::*;
pub use velocity::*;

#[cfg(test)]
mod tests;
