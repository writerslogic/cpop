// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Persistent TPM-sealed identity key storage with anti-rollback protection.
//!
//! This module bridges the key hierarchy (which derives keys from PUF providers)
//! with the TPM module (which can seal/unseal data to hardware). The master
//! identity seed is sealed to the device's TPM, preventing extraction or
//! migration to another machine.

mod store;
mod types;

pub use store::SealedIdentityStore;
pub use types::SealedIdentityError;

#[cfg(test)]
mod tests;
