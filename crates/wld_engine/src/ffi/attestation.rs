// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use base64::Engine;

use crate::ffi::helpers::{detect_attestation_tier_info, get_data_dir};
use crate::ffi::types::{FfiAttestationInfo, FfiAttestationResponse, FfiDeviceKey, FfiResult};
use crate::rfc::wire_types::AttestationTier;

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_attestation_info() -> FfiAttestationInfo {
    let (_, tier_num, tier_label) = detect_attestation_tier_info();

    let provider = crate::tpm::detect_provider();
    let caps = provider.capabilities();
    FfiAttestationInfo {
        tier: tier_num,
        tier_label,
        provider_type: provider.device_id(),
        hardware_bound: caps.hardware_backed && caps.supports_sealing,
        supports_sealing: caps.supports_sealing,
        has_monotonic_counter: caps.monotonic_counter,
        has_secure_clock: caps.secure_clock,
        device_id: provider.device_id(),
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_reseal_identity() -> FfiResult {
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Could not determine data directory".to_string()),
            };
        }
    };

    let store = crate::sealed_identity::SealedIdentityStore::auto_detect(&data_dir);

    if !store.is_bound() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some("No sealed identity found on this device".to_string()),
        };
    }

    let puf_seed_path = data_dir.join("puf_seed");
    let puf = match crate::keyhierarchy::SoftwarePUF::new_with_path(&puf_seed_path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to initialize PUF: {}", e)),
            };
        }
    };

    match store.reseal(&puf) {
        Ok(()) => FfiResult {
            success: true,
            message: Some("Identity re-sealed under current platform state".to_string()),
            error_message: None,
        },
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Reseal failed: {}", e)),
        },
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_is_hardware_bound() -> bool {
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => return false,
    };

    let store = crate::sealed_identity::SealedIdentityStore::auto_detect(&data_dir);
    if !store.is_bound() {
        return false;
    }

    store.attestation_tier() == AttestationTier::HardwareBound
        || store.attestation_tier() == AttestationTier::HardwareHardened
}

/// Sign a server-issued attestation challenge with the device key.
///
/// Returns both the raw signature and a COSE_Sign1 envelope per
/// draft-condrey-rats-pop §4.3 (device attestation uses COSE_Sign1 with the
/// platform attestation object as payload).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sign_attestation_challenge(challenge_b64: String) -> FfiAttestationResponse {
    let challenge = match base64::engine::general_purpose::STANDARD.decode(&challenge_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return FfiAttestationResponse {
                success: false,
                signature_b64: String::new(),
                public_key_b64: String::new(),
                cose_sign1_b64: String::new(),
                device_id: String::new(),
                model: String::new(),
                os_version: String::new(),
                error_message: Some(format!("Invalid base64 challenge: {e}")),
            };
        }
    };

    let provider = crate::tpm::detect_provider();

    let signature = match provider.sign(&challenge) {
        Ok(sig) => sig,
        Err(e) => {
            return FfiAttestationResponse {
                success: false,
                signature_b64: String::new(),
                public_key_b64: String::new(),
                cose_sign1_b64: String::new(),
                device_id: provider.device_id(),
                model: get_model(),
                os_version: get_os_version(),
                error_message: Some(format!("Signing failed: {e}")),
            };
        }
    };

    let public_key = provider.public_key();
    let b64 = &base64::engine::general_purpose::STANDARD;

    // Build COSE_Sign1 envelope wrapping the challenge as payload.
    let tpm_signer = crate::tpm::TpmSigner::new(provider.clone());
    let cose_sign1_b64 = match wld_protocol::crypto::sign_evidence_cose(&challenge, &tpm_signer) {
        Ok(cose_bytes) => b64.encode(&cose_bytes),
        Err(e) => {
            return FfiAttestationResponse {
                success: false,
                signature_b64: b64.encode(&signature),
                public_key_b64: b64.encode(&public_key),
                cose_sign1_b64: String::new(),
                device_id: provider.device_id(),
                model: get_model(),
                os_version: get_os_version(),
                error_message: Some(format!("COSE_Sign1 envelope creation failed: {e}")),
            };
        }
    };

    FfiAttestationResponse {
        success: true,
        signature_b64: b64.encode(&signature),
        public_key_b64: b64.encode(&public_key),
        cose_sign1_b64,
        device_id: provider.device_id(),
        model: get_model(),
        os_version: get_os_version(),
        error_message: None,
    }
}

/// Get the device public key for attestation.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_device_public_key() -> FfiDeviceKey {
    let provider = crate::tpm::detect_provider();
    let caps = provider.capabilities();
    let public_key = provider.public_key();

    FfiDeviceKey {
        public_key_b64: base64::engine::general_purpose::STANDARD.encode(&public_key),
        device_id: provider.device_id(),
        hardware_bound: caps.hardware_backed && caps.supports_sealing,
    }
}

fn get_model() -> String {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("sysctl")
            .args(["-n", "hw.model"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "Mac".to_string())
    }
    #[cfg(target_os = "windows")]
    {
        "Windows PC".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        "Linux PC".to_string()
    }
}

fn get_os_version() -> String {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("sw_vers")
            .args(["-productVersion"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| format!("macOS {}", s.trim()))
            .unwrap_or_else(|| "macOS".to_string())
    }
    #[cfg(target_os = "windows")]
    {
        "Windows".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        "Linux".to_string()
    }
}
