// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

pub mod digest;
pub mod streaming;
pub mod verification;

pub use digest::{compute_initial_digest, update_digest_in_place};
pub use streaming::StreamingStatsExt;
pub use verification::verify_against_baseline;

#[cfg(test)]
mod tests;
