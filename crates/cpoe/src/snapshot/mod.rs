// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

pub mod crypto;
pub mod diff;
pub mod store;
pub mod types;

#[cfg(test)]
mod tests;

pub use diff::word_diff;
pub use store::SnapshotStore;
pub use types::{DiffOp, DiffTag, SnapshotEntry, SnapshotMeta, StoreSizeInfo};
