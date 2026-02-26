// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! WritersProof attestation client and offline queue.
//!
//! Provides integration with the WritersProof external trust anchor service
//! for remote attestation of evidence packets. When offline, attestation
//! requests are queued to disk and submitted when connectivity is restored.

pub mod client;
pub mod queue;
pub mod types;

pub use client::WritersProofClient;
pub use queue::OfflineQueue;
pub use types::*;
