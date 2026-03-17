// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Steganographic document binding via zero-width Unicode characters.
//!
//! Embeds cryptographic proof markers (ZWCs encoding HMAC bits derived from
//! the MMR root) into document text at deterministic positions, creating
//! self-authenticating documents.

mod embedding;
mod extraction;
mod types;

#[cfg(test)]
mod tests;

pub use embedding::ZwcEmbedder;
pub use extraction::ZwcExtractor;
pub use types::{ZwcBinding, ZwcParams, ZwcVerification};
