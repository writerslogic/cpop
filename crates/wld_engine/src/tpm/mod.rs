// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub mod signer;
mod software;
mod types;
mod verification;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod secure_enclave;
#[cfg(target_os = "windows")]
mod windows;

pub use signer::TpmSigner;
pub use software::SoftwareProvider;
pub use types::*;
pub use verification::{verify_binding_chain, verify_quote};

use std::sync::Arc;

pub trait Provider: Send + Sync {
    fn capabilities(&self) -> Capabilities;
    fn device_id(&self) -> String;
    fn public_key(&self) -> Vec<u8>;
    /// The COSE signing algorithm this provider uses.
    fn algorithm(&self) -> coset::iana::Algorithm;
    fn quote(&self, nonce: &[u8], pcrs: &[u32]) -> Result<Quote, TPMError>;
    fn bind(&self, data: &[u8]) -> Result<Binding, TPMError>;
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TPMError>;
    fn verify(&self, binding: &Binding) -> Result<(), TPMError>;
    fn seal(&self, data: &[u8], policy: &[u8]) -> Result<Vec<u8>, TPMError>;
    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, TPMError>;
    fn clock_info(&self) -> Result<ClockInfo, TPMError>;
}

pub type ProviderHandle = Arc<dyn Provider + Send + Sync>;

/// Build the canonical binding payload: data_hash || timestamp_nanos || device_id.
pub(crate) fn build_binding_payload(
    data_hash: &[u8],
    timestamp: &chrono::DateTime<chrono::Utc>,
    device_id: &str,
) -> Vec<u8> {
    use crate::DateTimeNanosExt;
    let mut payload = Vec::new();
    payload.extend_from_slice(data_hash);
    payload.extend_from_slice(&timestamp.timestamp_nanos_safe().to_le_bytes());
    payload.extend_from_slice(device_id.as_bytes());
    payload
}

/// Parse a sealed blob into (public_bytes, private_bytes).
///
/// Format: [pub_len:u32be][pub_bytes][priv_len:u32be][priv_bytes]
#[allow(dead_code)] // Used by cfg-gated windows.rs and linux.rs
pub(crate) fn parse_sealed_blob(sealed: &[u8]) -> Result<(&[u8], &[u8]), TPMError> {
    if sealed.len() < 8 {
        return Err(TPMError::SealedDataTooShort);
    }
    let pub_len = u32::from_be_bytes([sealed[0], sealed[1], sealed[2], sealed[3]]) as usize;
    if sealed.len() < 4 + pub_len + 4 {
        return Err(TPMError::SealedCorrupted);
    }
    let pub_bytes = &sealed[4..4 + pub_len];
    let offset = 4 + pub_len;
    let priv_len = u32::from_be_bytes([
        sealed[offset],
        sealed[offset + 1],
        sealed[offset + 2],
        sealed[offset + 3],
    ]) as usize;
    if sealed.len() < offset + 4 + priv_len {
        return Err(TPMError::SealedCorrupted);
    }
    let priv_bytes = &sealed[offset + 4..offset + 4 + priv_len];
    Ok((pub_bytes, priv_bytes))
}

pub fn generate_attestation_report(
    provider: &dyn Provider,
    verifier_nonce: &[u8],
    attestation_nonce: &[u8],
    evidence_hash: [u8; 32],
) -> Result<AttestationReport, TPMError> {
    // 1. Combine nonces and hash for the quote
    let mut quote_payload = Vec::new();
    quote_payload.extend_from_slice(verifier_nonce);
    quote_payload.extend_from_slice(attestation_nonce);
    quote_payload.extend_from_slice(&evidence_hash);

    // 2. Request hardware quote (using the combined payload as the nonce for the TPM quote)
    // In TPM terms, we often hash this payload to fit in the nonce field (usually 32 bytes).
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&quote_payload);
    let quote_nonce = hasher.finalize();

    let quote = provider.quote(&quote_nonce, &[0, 4, 7])?;

    // 3. Create the report
    Ok(AttestationReport {
        report_id: uuid::Uuid::new_v4().to_string(),
        verifier_nonce: verifier_nonce.to_vec(),
        attestation_nonce: attestation_nonce.to_vec(),
        evidence_hash,
        hardware_quote: quote,
        signature: Vec::new(), // The quote itself contains the hardware signature
    })
}

pub fn detect_provider() -> ProviderHandle {
    #[cfg(target_os = "macos")]
    if let Some(provider) = secure_enclave::try_init() {
        log::info!("Initialized macOS Secure Enclave provider");
        return Arc::new(provider);
    }

    #[cfg(target_os = "windows")]
    if let Some(provider) = windows::try_init() {
        log::info!("Initialized Windows TPM 2.0 provider");
        return Arc::new(provider);
    }

    #[cfg(target_os = "linux")]
    if let Some(provider) = linux::try_init() {
        log::info!("Initialized Linux TPM 2.0 provider");
        return Arc::new(provider);
    }

    log::warn!("No hardware TPM available, using software provider");
    Arc::new(SoftwareProvider::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_provider_binding_chain() {
        let provider = SoftwareProvider::new();
        let binding1 = provider.bind(b"checkpoint-1").expect("bind");
        let binding2 = provider.bind(b"checkpoint-2").expect("bind");
        verify_binding_chain(&[binding1, binding2], &[]).expect("verify chain");
    }

    #[test]
    fn test_verify_quote_valid() {
        let provider = SoftwareProvider::new();
        let quote = provider.quote(b"nonce-a", &[]).expect("quote");
        assert!(verify_quote(&quote).is_ok());
    }
}
