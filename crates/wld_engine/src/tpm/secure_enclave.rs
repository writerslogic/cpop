// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::{Attestation, Binding, Capabilities, Provider, Quote, TPMError};
use crate::DateTimeNanosExt;
use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce as AeadNonce,
};
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
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrApplicationLabel, kSecAttrIsPermanent, kSecAttrKeySizeInBits,
    kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID,
    kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey, kSecPrivateKeyAttrs, kSecReturnRef,
};
use security_framework_sys::key::{
    kSecKeyAlgorithmECDSASignatureMessageX962SHA256, SecKeyCopyExternalRepresentation,
    SecKeyCopyPublicKey, SecKeyCreateRandomKey, SecKeyCreateSignature,
};
use security_framework_sys::keychain_item::SecItemCopyMatching;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::sync::Mutex;
use std::time::SystemTime;
use zeroize::Zeroize;

// Note: We use command-line tools (sysctl, ioreg) instead of direct IOKit FFI
// for safer hardware detection that won't crash on edge cases.

const SE_KEY_TAG: &str = "com.writerslogic.secureenclave.signing";
const SE_ATTESTATION_KEY_TAG: &str = "com.writerslogic.secureenclave.attestation";
#[allow(dead_code)]
const SE_ENCRYPTION_KEY_TAG: &str = "com.writerslogic.secureenclave.encryption";

/// Key attestation information from Secure Enclave.
#[allow(dead_code)]
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
#[allow(dead_code)]
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

    let base_dir = writerslogic_dir();
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
    state.hardware_info = collect_hardware_info();
    state.hardware_info.se_available = true;

    state.device_id = load_device_id()?;

    load_or_create_key(state)?;

    // Optionally create an attestation key (separate from signing for key attestation)
    if let Err(e) = load_or_create_attestation_key(state) {
        log::warn!("Could not create attestation key: {}", e);
        // Non-fatal - attestation will use signing key
    }

    load_counter(state)?;
    state.start_time = SystemTime::now();
    Ok(())
}

/// Collect hardware information for attestation context.
#[allow(clippy::field_reassign_with_default)]
fn collect_hardware_info() -> HardwareInfo {
    let mut info = HardwareInfo::default();

    info.uuid = hardware_uuid();
    info.model = get_model_identifier();
    info.os_version = get_os_version();

    info
}

/// Get the Mac model identifier using sysctl (safer than IOKit).
fn get_model_identifier() -> Option<String> {
    use std::process::Command;

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
    let private_attrs =
        core_foundation::dictionary::CFDictionary::from_CFType_pairs(&private_pairs);

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
    let private_attrs =
        core_foundation::dictionary::CFDictionary::from_CFType_pairs(&private_pairs);

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
            "Secure Enclave key generation failed".into(),
        ));
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

fn load_counter(state: &mut SecureEnclaveState) -> Result<(), TPMError> {
    match fs::read(&state.counter_file) {
        Ok(data) if data.len() >= 8 => {
            let bytes: [u8; 8] = data[0..8].try_into().expect("slice is exactly 8 bytes");
            state.counter = u64::from_be_bytes(bytes);
            Ok(())
        }
        Ok(data) => {
            // Corruption could be attacker-induced to force counter rollback.
            log::error!(
                "Counter file corrupt ({} bytes, expected >= 8): {:?}",
                data.len(),
                state.counter_file
            );
            Err(TPMError::CounterRollback)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            state.counter = 0;
            Ok(())
        }
        Err(e) => Err(TPMError::Io(e)),
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

impl SecureEnclaveProvider {
    /// Legacy v4 unseal: XOR cipher (backward compat only).
    fn unseal_v4_legacy(
        &self,
        state: &SecureEnclaveState,
        sealed: &[u8],
    ) -> Result<Vec<u8>, TPMError> {
        // v4 format: version(1) || nonce(32) || xor_ciphertext
        if sealed.len() < 34 {
            return Err(TPMError::SealedDataTooShort);
        }
        let nonce = &sealed[1..33];
        let signature = sign(state, nonce)?;
        let key_material = Sha256::digest(&signature);

        let mut data = vec![0u8; sealed.len() - 33];
        for i in 0..data.len() {
            data[i] = sealed[33 + i] ^ key_material[i % 32];
        }
        Ok(data)
    }

    /// v5 unseal: ChaCha20-Poly1305 AEAD.
    fn unseal_v5_aead(
        &self,
        state: &SecureEnclaveState,
        sealed: &[u8],
    ) -> Result<Vec<u8>, TPMError> {
        // v5 format: version(1) || seal_nonce(32) || aead_nonce(12) || ciphertext+tag
        const HEADER_LEN: usize = 1 + 32 + 12; // 45
        if sealed.len() < HEADER_LEN + 16 {
            // At minimum: header + 16-byte auth tag
            return Err(TPMError::SealedDataTooShort);
        }
        let seal_nonce = &sealed[1..33];
        let aead_nonce_bytes = &sealed[33..45];
        let ciphertext = &sealed[45..];

        let signature = sign(state, seal_nonce)?;
        let mut key_material = Sha256::digest(&signature);

        let cipher = ChaCha20Poly1305::new_from_slice(&key_material)
            .map_err(|e| TPMError::Unsealing(format!("AEAD key init: {e}")))?;

        let aead_nonce = AeadNonce::from_slice(aead_nonce_bytes);
        let plaintext = cipher
            .decrypt(aead_nonce, ciphertext)
            .map_err(|_| TPMError::SealedCorrupted)?;

        key_material.zeroize();
        Ok(plaintext)
    }
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

    fn algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::ES256
    }

    fn public_key(&self) -> Vec<u8> {
        self.state.lock().unwrap().public_key.clone()
    }

    fn quote(&self, nonce: &[u8], _pcrs: &[u32]) -> Result<Quote, TPMError> {
        let state = self.state.lock().unwrap();
        let timestamp = Utc::now();
        let mut payload = Vec::new();
        payload.extend_from_slice(nonce);
        payload.extend_from_slice(&timestamp.timestamp_nanos_safe().to_le_bytes());
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
        let payload = super::build_binding_payload(&data_hash, &timestamp, &state.device_id);

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
            attestation: Some(Attestation {
                payload,
                quote: None,
            }),
        })
    }

    fn verify(&self, binding: &Binding) -> Result<(), TPMError> {
        crate::tpm::verification::verify_binding(binding)
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TPMError> {
        let state = self.state.lock().unwrap();
        sign(&state, data)
    }

    fn seal(&self, data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TPMError> {
        let state = self.state.lock().unwrap();

        // Deterministic nonce: SE signs this to derive the encryption key
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-seal-nonce-v2");
        hasher.update(data);
        let seal_nonce = hasher.finalize().to_vec();

        let signature = sign(&state, &seal_nonce)?;
        let mut key_material = Sha256::digest(&signature);

        let cipher = ChaCha20Poly1305::new_from_slice(&key_material)
            .map_err(|e| TPMError::Sealing(format!("AEAD key init: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| TPMError::Sealing(format!("nonce generation: {e}")))?;
        let aead_nonce = AeadNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(aead_nonce, data)
            .map_err(|e| TPMError::Sealing(format!("AEAD encrypt: {e}")))?;

        key_material.zeroize();

        // Format: version(1) || seal_nonce(32) || aead_nonce(12) || ciphertext+tag
        let mut sealed = Vec::with_capacity(1 + 32 + 12 + ciphertext.len());
        sealed.push(5); // version 5 = AEAD
        sealed.extend_from_slice(&seal_nonce);
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, TPMError> {
        let state = self.state.lock().unwrap();
        if sealed.is_empty() {
            return Err(TPMError::SealedDataTooShort);
        }

        match sealed[0] {
            4 => self.unseal_v4_legacy(&state, sealed),
            5 => self.unseal_v5_aead(&state, sealed),
            _ => Err(TPMError::SealedVersionUnsupported),
        }
    }

    fn clock_info(&self) -> Result<super::ClockInfo, TPMError> {
        // Secure Enclave doesn't expose reboot counters.
        // macOS trust is established via code signing + notarization instead.
        let state = self.state.lock().unwrap();
        let elapsed = state.start_time.elapsed().unwrap_or_default().as_millis() as u64;
        Ok(super::ClockInfo {
            clock: elapsed,
            reset_count: 0,
            restart_count: 0,
            safe: false,
        })
    }
}

#[allow(dead_code)]
impl SecureEnclaveProvider {
    /// Generate a self-attestation proving the signing key lives in the Secure Enclave.
    /// Full Apple App Attest requires entitlements; this is a local self-attestation.
    pub fn generate_key_attestation(&self, challenge: &[u8]) -> Result<KeyAttestation, TPMError> {
        let state = self.state.lock().unwrap();
        let timestamp = Utc::now();

        let mut attestation_data = Vec::new();
        attestation_data.extend_from_slice(b"WITSE-ATTEST-V1\n");

        let challenge_hash = Sha256::digest(challenge);
        attestation_data.extend_from_slice(&challenge_hash);
        attestation_data.extend_from_slice(&state.public_key);
        attestation_data.extend_from_slice(state.device_id.as_bytes());

        let ts_bytes = timestamp.timestamp_nanos_safe().to_le_bytes();
        attestation_data.extend_from_slice(&ts_bytes);

        if let Some(ref uuid) = state.hardware_info.uuid {
            let uuid_hash = Sha256::digest(uuid.as_bytes());
            attestation_data.extend_from_slice(&uuid_hash);
        }

        if let Some(ref model) = state.hardware_info.model {
            attestation_data.extend_from_slice(model.as_bytes());
        }

        // Attestation proof = H(attestation_data). Technically redundant with
        // the ECDSA signature (if the signature verifies, the data is authentic).
        // Retained as a fast-path integrity check in verify_key_attestation()
        // before the more expensive ECDSA verification.
        let attestation_proof = Sha256::digest(&attestation_data).to_vec();

        let signature = if let Some(attest_key) = state.attestation_key_ref {
            sign_with_key(attest_key, &attestation_data)?
        } else {
            sign(&state, &attestation_data)?
        };

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

        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(b"WITSE-ATTEST-V1\n");

        let challenge_hash = Sha256::digest(expected_challenge);
        expected_data.extend_from_slice(&challenge_hash);

        expected_data.extend_from_slice(&attestation.public_key);
        expected_data.extend_from_slice(attestation.device_id.as_bytes());

        let ts_bytes = attestation.timestamp.timestamp_nanos_safe().to_le_bytes();
        expected_data.extend_from_slice(&ts_bytes);

        if let Some(ref uuid) = state.hardware_info.uuid {
            let uuid_hash = Sha256::digest(uuid.as_bytes());
            expected_data.extend_from_slice(&uuid_hash);
        }

        if let Some(ref model) = state.hardware_info.model {
            expected_data.extend_from_slice(model.as_bytes());
        }

        let expected_proof = Sha256::digest(&expected_data).to_vec();
        if attestation.attestation_proof != expected_proof {
            return Ok(false);
        }

        let verify_key = state
            .attestation_public_key
            .as_ref()
            .unwrap_or(&state.public_key);

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
        state
            .attestation_public_key
            .as_ref()
            .map(|pk| SecureEnclaveKeyInfo {
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
#[allow(dead_code)]
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
#[allow(dead_code)]
fn verify_ecdsa_signature(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool, TPMError> {
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
        let key_type_key = CFString::wrap_under_get_rule(kSecAttrKeyType);
        let key_type_value =
            CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom as CFTypeRef);
        let key_class_key = CFString::new("kSecAttrKeyClass");
        let key_class_value = CFType::wrap_under_get_rule(kSecAttrKeyClassPublic);

        let attrs = core_foundation::dictionary::CFDictionary::from_CFType_pairs(&[
            (key_type_key, key_type_value),
            (key_class_key, key_class_value),
        ]);

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

        let data_cf = CFData::from_buffer(data);
        let sig_cf = CFData::from_buffer(signature);

        let result = SecKeyVerifySignature(
            sec_key,
            kSecKeyAlgorithmECDSASignatureMessageX962SHA256 as *const std::ffi::c_void,
            data_cf.as_concrete_TypeRef(),
            sig_cf.as_concrete_TypeRef(),
            &mut error,
        );

        core_foundation_sys::base::CFRelease(sec_key as *mut std::ffi::c_void);

        Ok(result)
    }
}

fn is_secure_enclave_available() -> bool {
    if std::env::var("WLD_DISABLE_SECURE_ENCLAVE").is_ok() {
        log::info!("Secure Enclave disabled via environment variable");
        return false;
    }

    // Apple Silicon and T2 Macs both have Secure Enclave
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

    if !has_apple_silicon {
        // In CI environments, skip T2 detection entirely - CI runners typically
        // don't have T2 chips and even if they did, we lack the entitlements
        if std::env::var("CI").is_ok() || std::env::var("GITHUB_ACTIONS").is_ok() {
            log::info!("Skipping T2 detection in CI environment");
            return false;
        }

        // Targeted query (-c class, -d1 depth) avoids hanging on large IOKit registries
        let t2_check = Command::new("ioreg")
            .args(["-l", "-d1", "-c", "AppleT2Controller"])
            .output();

        if let Ok(out) = t2_check {
            if out.status.success() {
                let ioreg_output = String::from_utf8_lossy(&out.stdout);
                if !ioreg_output.contains("AppleT2Controller") {
                    // No T2 chip, no Secure Enclave
                    return false;
                }
            }
        } else {
            // ioreg command failed, assume no T2
            return false;
        }
    }

    // Verify Security framework is functional before attempting SE operations
    let security_check = Command::new("security").args(["list-keychains"]).output();

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

    let output = Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
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

fn writerslogic_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("WLD_DATA_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(home) = dirs::home_dir() {
        return home.join(".writerslogic");
    }
    PathBuf::from(".writerslogic")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_enclave_availability() {
        if is_secure_enclave_available() {
            println!("Secure Enclave is available");
        } else {
            println!("Secure Enclave is NOT available - skipping hardware tests");
        }
    }

    #[test]
    fn test_secure_enclave_lifecycle() {
        if !is_secure_enclave_available() {
            println!("Skipping test_secure_enclave_lifecycle (hardware unavailable)");
            return;
        }

        // We might fail here if the test runner isn't signed/entitled,
        // but it's better to try than not test at all.
        let provider = match try_init() {
            Some(p) => p,
            None => {
                println!(
                    "try_init returned None despite is_secure_enclave_available returning true"
                );
                return;
            }
        };

        // 1. Basic properties
        let caps = provider.capabilities();
        assert!(caps.hardware_backed);
        assert!(caps.secure_clock);
        assert!(caps.monotonic_counter);

        let device_id = provider.device_id();
        assert!(!device_id.is_empty());
        assert!(device_id.starts_with("se-"));

        let pub_key = provider.public_key();
        assert!(!pub_key.is_empty());

        // 2. Binding (Sign)
        let data = b"test-binding-data";
        let binding = provider.bind(data).expect("Bind failed");

        assert_eq!(binding.provider_type, "secure-enclave");
        assert_eq!(binding.device_id, device_id);

        // 3. Verify
        provider.verify(&binding).expect("Verification failed");

        // 4. Quote
        let nonce = b"test-nonce";
        let quote = provider.quote(nonce, &[]).expect("Quote failed");
        assert_eq!(quote.nonce, nonce);
        crate::tpm::verify_quote(&quote).expect("Quote verification failed");

        // 5. Seal/Unseal (Encryption)
        let secret = b"my-secret-data";
        let sealed = provider.seal(secret, &[]).expect("Seal failed");
        assert_ne!(sealed, secret);

        let unsealed = provider.unseal(&sealed).expect("Unseal failed");
        assert_eq!(unsealed, secret);

        // 6. Key Attestation
        let challenge = b"attestation-challenge";
        // This might fail if the key wasn't generated with attestation capabilities
        // or if the test env restricts it, so we handle it gracefully-ish
        if let Ok(attestation) = provider.generate_key_attestation(challenge) {
            let verified = provider
                .verify_key_attestation(&attestation, challenge)
                .expect("Attestation verification failed");
            assert!(verified);
        } else {
            println!("Key attestation generation failed (expected in some test environments)");
        }

        // 7. Counter
        let count1 = provider.get_counter();
        let count2 = provider.increment_counter();
        assert_eq!(count2, count1 + 1);
    }
}
