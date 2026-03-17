// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Quantified trust policies per the WritersLogic RFC.
//!
//! Relying Parties configure an [`AppraisalPolicy`] with weighted
//! [`TrustFactor`]s and [`TrustThreshold`]s. Supported computation models:
//!
//! - **Weighted average** -- `sum(factor * weight)`, normalized
//! - **Minimum of factors** -- score limited by weakest factor
//! - **Geometric mean** -- balanced penalty for outliers

mod evaluation;
pub mod profiles;
mod types;

#[cfg(test)]
mod tests;

pub use types::{
    AppraisalPolicy, EvidenceMetrics, FactorEvidence, FactorType, PolicyMetadata, ThresholdType,
    TrustComputation, TrustFactor, TrustThreshold,
};
