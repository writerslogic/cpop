// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

#[cfg(target_os = "macos")]
pub mod apple;
pub mod bridge;
pub mod did_configuration;
pub mod did_document;
pub mod mnemonic;
pub mod openid4vc;
pub mod orcid;
pub mod presentation_exchange;
pub mod secure_storage;

#[cfg(feature = "did-webvh")]
pub mod did_webvh;

pub use did_document::did_key_from_public;
pub use mnemonic::MnemonicHandler;
pub use secure_storage::SecureStorage;
