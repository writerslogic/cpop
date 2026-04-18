// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Bridge module integrating jitter crate with CPoE's zone-aware typing profiles.

pub(crate) mod doc_tracker;
pub(crate) mod helpers;
pub(crate) mod session;
pub(crate) mod types;
pub(crate) mod zone_engine;

#[cfg(test)]
mod tests;

pub use session::HybridJitterSession;
pub use types::{EntropyQuality, HybridEvidence, HybridSample};
pub use zone_engine::ZoneTrackingEngine;
