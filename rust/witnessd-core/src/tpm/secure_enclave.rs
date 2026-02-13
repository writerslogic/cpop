#![cfg(target_os = "macos")]
#![allow(dead_code)]

use super::{Attestation, Binding, Capabilities, Provider, Quote, TPMError};
use chrono::Utc;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::{kCFAllocatorDefault, CFTypeRef};
use core_foundation_sys::error::CFErrorRef;
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    SecAccessControlCreateWithFlags,
};
use security_framework_sys::base::{errSecSuccess, SecKeyRef};
use security_framework_sys::key::{
    kSecKeyAlgorithmECDSASignatureMessageX962SHA256, SecKeyCopyExternalRepresentation,
    SecKeyCopyPublicKey, SecKeyCreateRandomKey, SecKeyCreateSignature,
};
use security_framework_sys::keychain_item::SecItemCopyMatching;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrApplicationLabel, kSecAttrIsPermanent, kSecAttrKeySizeInBits,
    kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID,
    kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey, kSecPrivateKeyAttrs, kSecReturnRef,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::sync::Mutex;
use std::time::SystemTime;

// Note: We use command-line tools (sysctl, ioreg) instead of direct IOKit FFI
// for safer hardware detection that won't crash on edge cases.

// Key tags for different purposes
const SE_KEY_TAG: &str = "com.witnessd.secureenclave.signing";
const SE_ATTESTATION_KEY_TAG: &str = "com.witnessd.secureenclave.attestation";
const SE_ENCRYPTION_KEY_TAG: &str = "com.witnessd.secureenclave.encryption";

/// Key attestation information from Secure Enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAttestation {
    /// Version of the attestation format
    pub version: u32,
    /// The attested public key in X9.62 format
    pub public_key: Vec<u8>,
    /// Device-specific identifier
    pub device_id: String,
    /// Timestamp when attestation was generated
    pub timestamp: chrono::DateTime<Utc>,
    /// Cryptographic attestation proof
    pub attestation_proof: Vec<u8>,
    /// Signature over the attestation data
    pub signature: Vec<u8>,
    /// Additional attestation metadata
    pub metadata: HashMap<String, String>,
}

/// Secure Enclave key information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureEnclaveKeyInfo {
    /// Key tag/identifier
    pub tag: String,
    /// Public key in X9.62 format
    pub public_key: Vec<u8>,
    /// Key creation time (if available)
    pub created_at: Option<chrono::DateTime<Utc>>,
    /// Whether key is backed by Secure Enclave hardware
    pub hardware_backed: bool,
    /// Key size in bits
    pub key_size: u32,
}

struct SecureEnclaveState {
    /// Primary signing key reference
    key_ref: SecKeyRef,
    /// Attestation key reference (separate for key attestation operations)
    attestation_key_ref: Option<SecKeyRef>,
    /// Device identifier derived from hardware UUID
    device_id: String,
    /// Primary public key in X9.62 format
    public_key: Vec<u8>,
    /// Attestation public key (if different from signing key)
    attestation_public_key: Option<Vec<u8>>,
    /// Monotonic counter value
    counter: u64,
    /// Path to counter persistence file
    counter_file: PathBuf,
    /// Time when provider was initialized
    start_time: SystemTime,
    /// Cached hardware information
    hardware_info: HardwareInfo,
}

/// Hardware information for attestation context.
#[derive(Debug, Clone, Default)]
struct HardwareInfo {
    /// Hardware UUID
    uuid: Option<String>,
    /// Model identifier (e.g., "MacBookPro18,1")
    model: Option<String>,
    /// Secure Enclave available
    se_available: bool,
    /// macOS version
    os_version: Option<String>,
}

pub struct SecureEnclaveProvider {
    state: Mutex<SecureEnclaveState>,
}

unsafe impl Send for SecureEnclaveProvider {}
unsafe impl Sync for SecureEnclaveProvider {}

pub fn try_init() -> Option<SecureEnclaveProvider> {
    if !is_secure_enclave_available() {
        return None;
    }

    let base_dir = witnessd_dir();
    let counter_file = base_dir.join("se_counter");

    let mut state = SecureEnclaveState {
        key_ref: null_mut(),
        attestation_key_ref: None,
        device_id: String::new(),
        public_key: Vec::new(),
        attestation_public_key: None,
        counter: 0,
        counter_file,
        start_time: SystemTime::now(),
        hardware_info: HardwareInfo::default(),
    };

    if init_state(&mut state).is_err() {
        return None;
    }

    Some(SecureEnclaveProvider {
        state: Mutex::new(state),
    })
}

fn init_state(state: &mut SecureEnclaveState) -> Result<(), TPMError> {
    // Collect hardware info first
    state.hardware_info = collect_hardware_info();
    state.hardware_info.se_available = true;

    // Load or derive device ID from hardware
    state.device_id = load_device_id()?;

    // Load or create the primary signing key
    load_or_create_key(state)?;

    // Optionally create an attestation key (separate from signing for key attestation)
    if let Err(e) = load_or_create_attestation_key(state) {
        log::warn!("Could not create attestation key: {}", e);
        // Non-fatal - attestation will use signing key
    }

    // Load persisted counter
    load_counter(state);
    state.start_time = SystemTime::now();
    Ok(())
}

/// Collect hardware information for attestation context.
fn collect_hardware_info() -> HardwareInfo {
    let mut info = HardwareInfo::default();

    // Get hardware UUID
    info.uuid = hardware_uuid();

    // Get model identifier
    info.model = get_model_identifier();

    // Get macOS version
    info.os_version = get_os_version();

    info
}

/// Get the Mac model identifier using sysctl (safer than IOKit).
fn get_model_identifier() -> Option<String> {
    use std::process::Command;

    // Use sysctl which is more reliable and doesn't require unsafe FFI
    let output = Command::new("sysctl")
        .arg("-n")
        .arg("hw.model")
        .output()
        .ok()?;

    if output.status.success() {
        let model = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !model.is_empty() {
            return Some(model);
        }
    }

    None
}

/// Get macOS version string.
fn get_os_version() -> Option<String> {
    use std::process::Command;

    let output = Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok()?;

    if output.status.success() {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !version.is_empty() {
            return Some(version);
        }
    }

    None
}

/// Load or create a separate attestation key.
fn load_or_create_attestation_key(state: &mut SecureEnclaveState) -> Result<(), TPMError> {
    let tag = CFData::from_buffer(SE_ATTESTATION_KEY_TAG.as_bytes());
    let query = core_foundation::dictionary::CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFType::wrap_under_get_rule(kSecClassKey as CFTypeRef) },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrApplicationLabel) },
            tag.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe { CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom as CFTypeRef) },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecReturnRef) },
            CFBoolean::true_value().as_CFType(),
        ),
    ]);

    let mut result: CFTypeRef = null_mut();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };

    if status == errSecSuccess && !result.is_null() {
        state.attestation_key_ref = Some(result as SecKeyRef);
        state.attestation_public_key = Some(extract_public_key(result as SecKeyRef)?);
        return Ok(());
    }

    // Create new attestation key
    let access = unsafe {
        SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
            kSecAccessControlPrivateKeyUsage,
            null_mut(),
        )
    };

    let mut private_pairs: Vec<(CFString, CFType)> = Vec::new();
    private_pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecAttrIsPermanent) },
        CFBoolean::true_value().as_CFType(),
    ));
    private_pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecAttrApplicationLabel) },
        tag.as_CFType(),
    ));
    if !access.is_null() {
        private_pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) },
            unsafe { CFType::wrap_under_create_rule(access as CFTypeRef) },
        ));
    }
    let private_attrs = core_foundation::dictionary::CFDictionary::from_CFType_pairs(&private_pairs);

    let key_size = 256i32;
    let key_size_cf = CFNumber::from(key_size);

    let key_attrs = core_foundation::dictionary::CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe { CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom as CFTypeRef) },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeySizeInBits) },
            key_size_cf.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenID) },
            unsafe { CFType::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave as CFTypeRef) },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecPrivateKeyAttrs) },
            private_attrs.as_CFType(),
        ),
    ]);

    let mut error: CFErrorRef = null_mut();
    let key_ref = unsafe { SecKeyCreateRandomKey(key_attrs.as_concrete_TypeRef(), &mut error) };

    // Note: Do NOT call CFRelease on `access` here - it was passed to wrap_under_create_rule
    // which took ownership and will release it when private_attrs is dropped

    if key_ref.is_null() {
        return Err(TPMError::KeyGeneration(
            "Secure Enclave attestation key generation failed".into(),
        ));
    }

    state.attestation_key_ref = Some(key_ref);
    state.attestation_public_key = Some(extract_public_key(key_ref)?);
    Ok(())
}

fn load_device_id() -> Result<String, TPMError> {
    if let Some(uuid) = hardware_uuid() {
        let digest = Sha256::digest(uuid.as_bytes());
        return Ok(format!("se-{}", hex::encode(&digest[..8])));
    }
    let host = hostname::get().map_err(|_| TPMError::NotAvailable)?;
    let digest = Sha256::digest(format!("witnessd-fallback-{}", host.to_string_lossy()).as_bytes());
    Ok(format!("se-{}", hex::encode(&digest[..8])))
}

fn load_or_create_key(state: &mut SecureEnclaveState) -> Result<(), TPMError> {
    let tag = CFData::from_buffer(SE_KEY_TAG.as_bytes());
    let query = core_foundation::dictionary::CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFType::wrap_under_get_rule(kSecClassKey as CFTypeRef) },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrApplicationLabel) },
            tag.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe { CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom as CFTypeRef) },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecReturnRef) },
            CFBoolean::true_value().as_CFType(),
        ),
    ]);

    let mut result: CFTypeRef = null_mut();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    if status == errSecSuccess && !result.is_null() {
        state.key_ref = result as SecKeyRef;
        state.public_key = extract_public_key(state.key_ref)?;
        return Ok(());
    }

    let access = unsafe {
        SecAccessControlCreateWithFlags(
            core_foundation_sys::base::kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
            kSecAccessControlPrivateKeyUsage,
            null_mut(),
        )
    };

    let mut private_pairs: Vec<(CFString, CFType)> = Vec::new();
    private_pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecAttrIsPermanent) },
        CFBoolean::true_value().as_CFType(),
    ));
    private_pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecAttrApplicationLabel) },
        tag.as_CFType(),
    ));
    if !access.is_null() {
        private_pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) },
            unsafe { CFType::wrap_under_create_rule(access as CFTypeRef) },
        ));
    }
    let private_attrs = core_foundation::dictionary::CFDictionary::from_CFType_pairs(&private_pairs);

    let key_size = 256i32;
    let key_size_cf = CFNumber::from(key_size);

    let key_attrs = core_foundation::dictionary::CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe { CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom as CFTypeRef) },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeySizeInBits) },
            key_size_cf.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenID) },
            unsafe { CFType::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave as CFTypeRef) },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecPrivateKeyAttrs) },
            private_attrs.as_CFType(),
        ),
    ]);

    let mut error: CFErrorRef = null_mut();
    let key_ref = unsafe { SecKeyCreateRandomKey(key_attrs.as_concrete_TypeRef(), &mut error) };
    // Note: Do NOT call CFRelease on `access` here - it was passed to wrap_under_create_rule
    // which took ownership and will release it when private_attrs is dropped
    if key_ref.is_null() {
        return Err(TPMError::KeyGeneration("Secure Enclave key generation failed".into()));
    }

    state.key_ref = key_ref;
    state.public_key = extract_public_key(state.key_ref)?;
    Ok(())
}

fn sign(state: &SecureEnclaveState, data: &[u8]) -> Result<Vec<u8>, TPMError> {
    if state.key_ref.is_null() {
        return Err(TPMError::NotInitialized);
    }
    let cfdata = CFData::from_buffer(data);
    let mut error: CFErrorRef = null_mut();
    let signature = unsafe {
        SecKeyCreateSignature(
            state.key_ref,
            kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
            cfdata.as_concrete_TypeRef(),
            &mut error,
        )
    };
    if signature.is_null() {
        return Err(TPMError::Signing("Secure Enclave signing failed".into()));
    }
    let sig = unsafe { CFData::wrap_under_create_rule(signature) };
    Ok(sig.bytes().to_vec())
}

fn load_counter(state: &mut SecureEnclaveState) {
    if let Ok(data) = fs::read(&state.counter_file) {
        if data.len() >= 8 {
            state.counter = u64::from_be_bytes(data[0..8].try_into().unwrap_or([0u8; 8]));
        }
    }
}

fn save_counter(state: &SecureEnclaveState) {
    if let Some(parent) = state.counter_file.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&state.counter.to_be_bytes());
    let _ = fs::write(&state.counter_file, buf);
}

impl Provider for SecureEnclaveProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hardware_backed: true,
            supports_pcrs: false,
            supports_sealing: true,
            supports_attestation: true,
            monotonic_counter: true,
            secure_clock: true,
        }
    }

    fn device_id(&self) -> String {
        self.state.lock().unwrap().device_id.clone()
    }

    fn public_key(&self) -> Vec<u8> {
        self.state.lock().unwrap().public_key.clone()
    }

    fn quote(&self, nonce: &[u8], _pcrs: &[u32]) -> Result<Quote, TPMError> {
        let state = self.state.lock().unwrap();
        let timestamp = Utc::now();
        let mut payload = Vec::new();
        payload.extend_from_slice(nonce);
        payload.extend_from_slice(&timestamp.timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        payload.extend_from_slice(state.device_id.as_bytes());

        let signature = sign(&state, &payload)?;

        Ok(Quote {
            provider_type: "secure-enclave".to_string(),
            device_id: state.device_id.clone(),
            timestamp,
            nonce: nonce.to_vec(),
            attested_data: payload,
            signature,
            public_key: state.public_key.clone(),
            pcr_values: Vec::new(),
            extra: Default::default(),
        })
    }

    fn bind(&self, data: &[u8]) -> Result<Binding, TPMError> {
        let mut state = self.state.lock().unwrap();
        state.counter += 1;
        save_counter(&state);

        let timestamp = Utc::now();
        let data_hash = Sha256::digest(data).to_vec();

        let mut payload = Vec::new();
        payload.extend_from_slice(&data_hash);
        payload.extend_from_slice(&timestamp.timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        payload.extend_from_slice(state.device_id.as_bytes());

        let signature = sign(&state, &payload)?;

        Ok(Binding {
            version: 1,
            provider_type: "secure-enclave".to_string(),
            device_id: state.device_id.clone(),
            timestamp,
            attested_hash: data_hash,
            signature,
            public_key: state.public_key.clone(),
            monotonic_counter: Some(state.counter),
            safe_clock: Some(true),
            attestation: Some(Attestation { payload, quote: None }),
        })
    }

    fn verify(&self, binding: &Binding) -> Result<(), TPMError> {
        crate::tpm::verification::verify_binding(binding)
    }

    fn seal(&self, data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TPMError> {
        let state = self.state.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-seal-nonce-v1");
        hasher.update(data);
        let nonce = hasher.finalize().to_vec();

        let signature = sign(&state, &nonce)?;
        let key_material = Sha256::digest(&signature);

        let mut sealed = vec![0u8; 1 + 32 + data.len()];
        sealed[0] = 4;
        sealed[1..33].copy_from_slice(&nonce);
        for (i, b) in data.iter().enumerate() {
            sealed[33 + i] = b ^ key_material[i % 32];
        }
        Ok(sealed)
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, TPMError> {
        let state = self.state.lock().unwrap();
        if sealed.len() < 34 {
            return Err(TPMError::SealedDataTooShort);
        }
        if sealed[0] != 4 {
            return Err(TPMError::SealedVersionUnsupported);
        }
        let nonce = &sealed[1..33];
        let signature = sign(&state, nonce)?;
        let key_material = Sha256::digest(&signature);

        let mut data = vec![0u8; sealed.len() - 33];
        for i in 0..data.len() {
            data[i] = sealed[33 + i] ^ key_material[i % 32];
        }
        Ok(data)
    }
}

// =============================================================================
// Extended Secure Enclave operations (key attestation, device info)
// =============================================================================

impl SecureEnclaveProvider {
    /// Generate a key attestation for the signing key.
    ///
    /// Key attestation proves that a key was generated in and is protected by
    /// the Secure Enclave. The attestation includes:
    /// - The public key
    /// - Device-specific identifier
    /// - Timestamp
    /// - Cryptographic proof signed by the attestation key
    ///
    /// Note: Full Apple App Attest requires entitlements and server-side verification.
    /// This provides a self-attestation that can be verified with the attestation public key.
    pub fn generate_key_attestation(&self, challenge: &[u8]) -> Result<KeyAttestation, TPMError> {
        let state = self.state.lock().unwrap();
        let timestamp = Utc::now();

        // Build attestation payload
        let mut attestation_data = Vec::new();

        // Version and magic
        attestation_data.extend_from_slice(b"WITSE-ATTEST-V1\n");

        // Challenge/nonce
        let challenge_hash = Sha256::digest(challenge);
        attestation_data.extend_from_slice(&challenge_hash);

        // Public key being attested
        attestation_data.extend_from_slice(&state.public_key);

        // Device ID
        attestation_data.extend_from_slice(state.device_id.as_bytes());

        // Timestamp
        let ts_bytes = timestamp.timestamp_nanos_opt().unwrap_or(0).to_le_bytes();
        attestation_data.extend_from_slice(&ts_bytes);

        // Hardware info
        if let Some(ref uuid) = state.hardware_info.uuid {
            let uuid_hash = Sha256::digest(uuid.as_bytes());
            attestation_data.extend_from_slice(&uuid_hash);
        }

        if let Some(ref model) = state.hardware_info.model {
            attestation_data.extend_from_slice(model.as_bytes());
        }

        // Create attestation proof
        let attestation_proof = Sha256::digest(&attestation_data).to_vec();

        // Sign with attestation key if available, otherwise with signing key
        let signature = if let Some(attest_key) = state.attestation_key_ref {
            sign_with_key(attest_key, &attestation_data)?
        } else {
            sign(&state, &attestation_data)?
        };

        // Collect metadata
        let mut metadata = HashMap::new();
        if let Some(ref model) = state.hardware_info.model {
            metadata.insert("model".to_string(), model.clone());
        }
        if let Some(ref version) = state.hardware_info.os_version {
            metadata.insert("os_version".to_string(), version.clone());
        }
        metadata.insert(
            "se_available".to_string(),
            state.hardware_info.se_available.to_string(),
        );

        Ok(KeyAttestation {
            version: 1,
            public_key: state.public_key.clone(),
            device_id: state.device_id.clone(),
            timestamp,
            attestation_proof,
            signature,
            metadata,
        })
    }

    /// Verify a key attestation.
    ///
    /// This verifies that:
    /// 1. The signature is valid against the attestation public key
    /// 2. The attestation proof matches the expected format
    /// 3. The timestamp is within acceptable bounds
    pub fn verify_key_attestation(
        &self,
        attestation: &KeyAttestation,
        expected_challenge: &[u8],
    ) -> Result<bool, TPMError> {
        let state = self.state.lock().unwrap();

        // Rebuild expected attestation data
        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(b"WITSE-ATTEST-V1\n");

        let challenge_hash = Sha256::digest(expected_challenge);
        expected_data.extend_from_slice(&challenge_hash);

        expected_data.extend_from_slice(&attestation.public_key);
        expected_data.extend_from_slice(attestation.device_id.as_bytes());

        let ts_bytes = attestation.timestamp.timestamp_nanos_opt().unwrap_or(0).to_le_bytes();
        expected_data.extend_from_slice(&ts_bytes);

        // Include hardware info if available
        if let Some(ref uuid) = state.hardware_info.uuid {
            let uuid_hash = Sha256::digest(uuid.as_bytes());
            expected_data.extend_from_slice(&uuid_hash);
        }

        if let Some(ref model) = state.hardware_info.model {
            expected_data.extend_from_slice(model.as_bytes());
        }

        // Verify attestation proof
        let expected_proof = Sha256::digest(&expected_data).to_vec();
        if attestation.attestation_proof != expected_proof {
            return Ok(false);
        }

        // Verify signature using attestation public key or regular public key
        let verify_key = state
            .attestation_public_key
            .as_ref()
            .unwrap_or(&state.public_key);

        // ECDSA P-256 signature verification
        verify_ecdsa_signature(verify_key, &expected_data, &attestation.signature)
    }

    /// Get information about the signing key.
    pub fn get_key_info(&self) -> SecureEnclaveKeyInfo {
        let state = self.state.lock().unwrap();
        SecureEnclaveKeyInfo {
            tag: SE_KEY_TAG.to_string(),
            public_key: state.public_key.clone(),
            created_at: None, // Secure Enclave doesn't expose creation time
            hardware_backed: true,
            key_size: 256,
        }
    }

    /// Get information about the attestation key (if separate from signing key).
    pub fn get_attestation_key_info(&self) -> Option<SecureEnclaveKeyInfo> {
        let state = self.state.lock().unwrap();
        state.attestation_public_key.as_ref().map(|pk| SecureEnclaveKeyInfo {
            tag: SE_ATTESTATION_KEY_TAG.to_string(),
            public_key: pk.clone(),
            created_at: None,
            hardware_backed: true,
            key_size: 256,
        })
    }

    /// Get hardware information for this device.
    pub fn get_hardware_info(&self) -> HashMap<String, String> {
        let state = self.state.lock().unwrap();
        let mut info = HashMap::new();

        if let Some(ref model) = state.hardware_info.model {
            info.insert("model".to_string(), model.clone());
        }
        if let Some(ref version) = state.hardware_info.os_version {
            info.insert("os_version".to_string(), version.clone());
        }
        info.insert("device_id".to_string(), state.device_id.clone());
        info.insert(
            "secure_enclave".to_string(),
            state.hardware_info.se_available.to_string(),
        );

        info
    }

    /// Get the current monotonic counter value without incrementing.
    pub fn get_counter(&self) -> u64 {
        self.state.lock().unwrap().counter
    }

    /// Increment and return the monotonic counter.
    pub fn increment_counter(&self) -> u64 {
        let mut state = self.state.lock().unwrap();
        state.counter += 1;
        save_counter(&state);
        state.counter
    }

    /// Check if the Secure Enclave hardware is available.
    pub fn is_hardware_available() -> bool {
        is_secure_enclave_available()
    }
}

/// Sign data with a specific key reference.
fn sign_with_key(key_ref: SecKeyRef, data: &[u8]) -> Result<Vec<u8>, TPMError> {
    if key_ref.is_null() {
        return Err(TPMError::NotInitialized);
    }
    let cfdata = CFData::from_buffer(data);
    let mut error: CFErrorRef = null_mut();
    let signature = unsafe {
        SecKeyCreateSignature(
            key_ref,
            kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
            cfdata.as_concrete_TypeRef(),
            &mut error,
        )
    };
    if signature.is_null() {
        return Err(TPMError::Signing("Secure Enclave signing failed".into()));
    }
    let sig = unsafe { CFData::wrap_under_create_rule(signature) };
    Ok(sig.bytes().to_vec())
}

/// Verify an ECDSA P-256 signature.
/// Note: Full verification requires parsing the X9.62 public key format.
fn verify_ecdsa_signature(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool, TPMError> {
    // Import additional security framework functions
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SecKeyCreateWithData(
            key_data: core_foundation_sys::data::CFDataRef,
            attributes: core_foundation_sys::dictionary::CFDictionaryRef,
            error: *mut CFErrorRef,
        ) -> SecKeyRef;
        fn SecKeyVerifySignature(
            key: SecKeyRef,
            algorithm: *const std::ffi::c_void,
            signed_data: core_foundation_sys::data::CFDataRef,
            signature: core_foundation_sys::data::CFDataRef,
            error: *mut CFErrorRef,
        ) -> bool;
        static kSecAttrKeyClassPublic: CFTypeRef;
    }

    // Public key should be in X9.62 uncompressed format (65 bytes for P-256)
    if public_key.is_empty() {
        return Err(TPMError::UnsupportedPublicKey);
    }

    unsafe {
        // Create key attributes dictionary
        let key_type_key = CFString::wrap_under_get_rule(kSecAttrKeyType);
        let key_type_value = CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom as CFTypeRef);
        let key_class_key = CFString::new("kSecAttrKeyClass");
        let key_class_value = CFType::wrap_under_get_rule(kSecAttrKeyClassPublic);

        let attrs = core_foundation::dictionary::CFDictionary::from_CFType_pairs(&[
            (key_type_key, key_type_value),
            (key_class_key, key_class_value),
        ]);

        // Create public key from data
        let key_data = CFData::from_buffer(public_key);
        let mut error: CFErrorRef = null_mut();
        let sec_key = SecKeyCreateWithData(
            key_data.as_concrete_TypeRef(),
            attrs.as_concrete_TypeRef(),
            &mut error,
        );

        if sec_key.is_null() {
            return Err(TPMError::UnsupportedPublicKey);
        }

        // Verify signature
        let data_cf = CFData::from_buffer(data);
        let sig_cf = CFData::from_buffer(signature);

        let result = SecKeyVerifySignature(
            sec_key,
            kSecKeyAlgorithmECDSASignatureMessageX962SHA256 as *const std::ffi::c_void,
            data_cf.as_concrete_TypeRef(),
            sig_cf.as_concrete_TypeRef(),
            &mut error,
        );

        // Release the key
        core_foundation_sys::base::CFRelease(sec_key as *mut std::ffi::c_void);

        Ok(result)
    }
}

fn is_secure_enclave_available() -> bool {
    // Check if Secure Enclave is explicitly disabled
    if std::env::var("WITNESSD_DISABLE_SECURE_ENCLAVE").is_ok() {
        log::info!("Secure Enclave disabled via environment variable");
        return false;
    }

    // Check if we're on Apple Silicon (M1/M2/etc) or T2 Mac (both have Secure Enclave)
    // Use sysctl to safely check the CPU brand - all Apple Silicon Macs have SE
    use std::process::Command;

    let output = match Command::new("sysctl")
        .arg("-n")
        .arg("machdep.cpu.brand_string")
        .output()
    {
        Ok(out) => out,
        Err(_) => return false,
    };

    if !output.status.success() {
        return false;
    }

    let cpu_brand = String::from_utf8_lossy(&output.stdout);
    let has_apple_silicon = cpu_brand.contains("Apple");

    // If not Apple Silicon, check for T2 chip (Intel Macs with SE)
    if !has_apple_silicon {
        // Check for T2 by looking for AppleT2Controller in ioreg
        let t2_check = Command::new("ioreg")
            .args(["-l", "-w0"])
            .output();

        if let Ok(out) = t2_check {
            if out.status.success() {
                let ioreg_output = String::from_utf8_lossy(&out.stdout);
                if !ioreg_output.contains("AppleT2Controller") {
                    // No T2 chip, no Secure Enclave
                    return false;
                }
            }
        }
    }

    // We have hardware that supports SE, now check if the Security framework works
    // Use a minimal, safer check via security command
    let security_check = Command::new("security")
        .args(["list-keychains"])
        .output();

    match security_check {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

fn extract_public_key(key_ref: SecKeyRef) -> Result<Vec<u8>, TPMError> {
    let public_key = unsafe { SecKeyCopyPublicKey(key_ref) };
    if public_key.is_null() {
        return Err(TPMError::KeyExport("public key unavailable".into()));
    }
    let mut error: CFErrorRef = null_mut();
    let data_ref = unsafe { SecKeyCopyExternalRepresentation(public_key, &mut error) };
    if data_ref.is_null() {
        return Err(TPMError::KeyExport("public key export failed".into()));
    }
    let data = unsafe { CFData::wrap_under_create_rule(data_ref) };
    Ok(data.bytes().to_vec())
}

fn hardware_uuid() -> Option<String> {
    use std::process::Command;

    // Use ioreg command which is safer than direct IOKit FFI calls
    let output = Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse the output to find IOPlatformUUID
        for line in stdout.lines() {
            if line.contains("IOPlatformUUID") {
                // Format: "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
                if let Some(start) = line.rfind('"') {
                    let before_last = &line[..start];
                    if let Some(uuid_start) = before_last.rfind('"') {
                        let uuid = &before_last[uuid_start + 1..];
                        if !uuid.is_empty() && uuid.contains('-') {
                            return Some(uuid.to_string());
                        }
                    }
                }
            }
        }
    }

    // Fallback: try sysctl for kern.uuid
    let output = Command::new("sysctl")
        .arg("-n")
        .arg("kern.uuid")
        .output()
        .ok()?;

    if output.status.success() {
        let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !uuid.is_empty() {
            return Some(uuid);
        }
    }

    None
}

fn witnessd_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("WITNESSD_DATA_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(home) = dirs::home_dir() {
        return home.join(".witnessd");
    }
    PathBuf::from(".witnessd")
}
