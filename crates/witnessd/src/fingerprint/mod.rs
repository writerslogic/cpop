// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Author Fingerprinting Module

pub mod activity;
pub mod activity_analysis;
pub mod activity_collection;
pub mod author;
pub mod comparison;
pub mod consent;
pub mod manager;
pub mod storage;
pub mod voice;

#[cfg(test)]
mod tests;

pub use activity::{
    ActivityFingerprint, ActivityFingerprintAccumulator, WeightedDistribution, ZoneProfile,
};
pub use author::{AuthorFingerprint, ProfileId};
pub use comparison::{FingerprintComparison, ProfileMatcher};
pub use consent::{ConsentManager, ConsentRecord, ConsentStatus};
pub use manager::{FingerprintManager, FingerprintStatus};
pub use storage::{FingerprintStorage, StoredProfile};
pub use voice::{VoiceCollector, VoiceFingerprint};

pub use crate::config::FingerprintConfig;
