// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! wld_protocol: Core Rust implementation of the Proof-of-Process (PoP) Protocol.
//!
//! This crate provides the foundational types and cryptographic logic for the PoP protocol,
//! ensuring compliance with IETF Rats working group specifications.

pub mod baseline;
pub mod c2pa;
pub mod codec;
pub mod crypto;
pub mod error;
pub mod evidence;
pub mod forensics;
pub mod identity;
pub mod rfc;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use crate::error::{Error, Result};

/// Current PoP protocol version number.
pub const PROTOCOL_VERSION: u32 = 1;
