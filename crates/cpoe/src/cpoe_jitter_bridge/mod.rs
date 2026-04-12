// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Bridge module integrating jitter crate with CPoE's zone-aware typing profiles.

pub mod doc_tracker;
pub mod helpers;
pub mod session;
pub mod types;
pub mod zone_engine;

#[cfg(test)]
mod tests;

pub use session::HybridJitterSession;
pub use types::{EntropyQuality, HybridEvidence, HybridSample};
pub use zone_engine::ZoneTrackingEngine;
