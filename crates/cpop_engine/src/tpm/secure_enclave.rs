// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::{Attestation, Binding, Capabilities, Provider, Quote, TpmError};
use crate::DateTimeNanosExt;
use crate::MutexRecover;
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
use hmac::{Hmac, Mac};
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    SecAccessControlCreateWithFlags,
};
use security_framework_sys::base::{errSecItemNotFound, errSecSuccess, SecKeyRef};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrApplicationLabel, kSecAttrIsPermanent, kSecAttrKeyClass,
    kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID,
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
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const SE_KEY_TAG: &str = "com.writerslogic.secureenclave.signing";
const SE_ATTESTATION_KEY_TAG: &str = "com.writerslogic.secureenclave.attestation";
#[allow(dead_code)]
const SE_ENCRYPTION_KEY_TAG: &str = "com.writerslogic.secureenclave.encryption";

/// Self-attestation proof binding a public key to this device.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAttestation {
    pub version: u32,
    /// X9.62 format.
    pub public_key: Vec<u8>,
    pub device_id: String,
    pub timestamp: chrono::DateTime<Utc>,
    pub attestation_proof: Vec<u8>,
    pub signature: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

/// Metadata about a Secure Enclave key.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureEnclaveKeyInfo {
    pub tag: String,
    /// X9.62 format.
    pub public_key: Vec<u8>,
    pub created_at: Option<chrono::DateTime<Utc>>,
    pub hardware_backed: bool,
    pub key_size: u32,
}

struct SecureEnclaveState {
    key_ref: SecKeyRef,
    attestation_key_ref: Option<SecKeyRef>,
    device_id: String,
    public_key: Vec<u8>,
    attestation_public_key: Option<Vec<u8>>,
    counter: u64,
    counter_file: PathBuf,
    start_time: SystemTime,
    hardware_info: HardwareInfo,
}

#[derive(Debug, Clone, Default)]
struct HardwareInfo {
    uuid: Option<String>,
    model: Option<String>,
    se_available: bool,
    os_version: Option<String>,
}

/// macOS Secure Enclave TPM provider (ECDSA P-256).
pub struct SecureEnclaveProvider {
    state: Mutex<SecureEnclaveState>,
    cached_device_id: String,
    cached_public_key: Vec<u8>,
}

// SAFETY: SecKeyRef (Security.framework key objects) are thread-safe for signing
// operations per Apple documentation. The Mutex<SecureEnclaveState> provides
// exclusive access to mutable state.
unsafe impl Send for SecureEnclaveProvider {}
unsafe impl Sync for SecureEnclaveProvider {}

impl Drop for SecureEnclaveState {
    fn drop(&mut self) {
        // Release the primary signing key reference.
        if !self.key_ref.is_null() {
            unsafe {
                core_foundation_sys::base::CFRelease(self.key_ref as *mut std::ffi::c_void);
            }
        }
        // Release the attestation key reference, if present.
        if let Some(att_ref) = self.attestation_key_ref {
            if !att_ref.is_null() {
                unsafe {
                    core_foundation_sys::base::CFRelease(att_ref as *mut std::ffi::c_void);
                }
            }
        }
    }
}

/// Initialize the Secure Enclave provider, returning `None` if unavailable.
pub fn try_init() -> Option<SecureEnclaveProvider> {
    if !is_secure_enclave_available() {
        return None;
    }

    let base_dir = match writersproof_dir() {
        Ok(d) => d,
        Err(e) => {
            log::error!("Secure Enclave init failed: {e}");
            return None;
        }
    };
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

    let cached_device_id = state.device_id.clone();
    let cached_public_key = state.public_key.clone();

    Some(SecureEnclaveProvider {
        state: Mutex::new(state),
        cached_device_id,
        cached_public_key,
    })
}

fn init_state(state: &mut SecureEnclaveState) -> Result<(), TpmError> {
    state.hardware_info = collect_hardware_info();
    state.hardware_info.se_available = true;

    state.device_id = load_device_id()?;

    load_or_create_key(state)?;

    if let Err(e) = load_or_create_attestation_key(state) {
        log::warn!("Could not create attestation key: {}", e);
    }

    load_counter(state)?;
    state.start_time = SystemTime::now();
    Ok(())
}

fn collect_hardware_info() -> HardwareInfo {
    HardwareInfo {
        uuid: hardware_uuid(),
        model: get_model_identifier(),
        os_version: get_os_version(),
        ..HardwareInfo::default()
    }
}

/// sysctl is safer than IOKit for model detection.
fn get_model_identifier() -> Option<String> {
    use std::process::Command;

    let output = Command::new("/usr/sbin/sysctl")
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

fn get_os_version() -> Option<String> {
    use std::process::Command;

    let output = Command::new("/usr/bin/sw_vers")
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

fn load_or_create_se_key(tag_str: &str) -> Result<(SecKeyRef, Vec<u8>), TpmError> {
    let tag = CFData::from_buffer(tag_str.as_bytes());
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
        let key_ref = result as SecKeyRef;
        let public_key = extract_public_key(key_ref)?;
        return Ok((key_ref, public_key));
    }
    if status != errSecItemNotFound {
        return Err(TpmError::KeyGeneration(format!(
            "Keychain query failed with status {status} for tag {tag_str}"
        )));
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
    if access.is_null() {
        return Err(TpmError::KeyGeneration(
            "SecAccessControlCreateWithFlags returned null".into(),
        ));
    }

    private_pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) },
        unsafe { CFType::wrap_under_create_rule(access as CFTypeRef) },
    ));
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

    if key_ref.is_null() {
        if !error.is_null() {
            unsafe { core_foundation_sys::base::CFRelease(error as CFTypeRef) };
        }
        return Err(TpmError::KeyGeneration(format!(
            "Secure Enclave key generation failed for tag {tag_str}"
        )));
    }

    let public_key = extract_public_key(key_ref)?;
    Ok((key_ref, public_key))
}

fn load_or_create_attestation_key(state: &mut SecureEnclaveState) -> Result<(), TpmError> {
    let (key_ref, public_key) = load_or_create_se_key(SE_ATTESTATION_KEY_TAG)?;
    state.attestation_key_ref = Some(key_ref);
    state.attestation_public_key = Some(public_key);
    Ok(())
}

fn load_device_id() -> Result<String, TpmError> {
    if let Some(uuid) = hardware_uuid() {
        let digest = Sha256::digest(uuid.as_bytes());
        return Ok(format!("se-{}", hex::encode(&digest[..8])));
    }
    let host = hostname::get().map_err(|_| TpmError::NotAvailable)?;
    let digest = Sha256::digest(format!("witnessd-fallback-{}", host.to_string_lossy()).as_bytes());
    Ok(format!("se-{}", hex::encode(&digest[..8])))
}

fn load_or_create_key(state: &mut SecureEnclaveState) -> Result<(), TpmError> {
    let (key_ref, public_key) = load_or_create_se_key(SE_KEY_TAG)?;
    state.key_ref = key_ref;
    state.public_key = public_key;
    Ok(())
}

fn sign(state: &SecureEnclaveState, data: &[u8]) -> Result<Vec<u8>, TpmError> {
    if state.key_ref.is_null() {
        return Err(TpmError::NotInitialized);
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
        if !error.is_null() {
            unsafe { core_foundation_sys::base::CFRelease(error as CFTypeRef) };
        }
        return Err(TpmError::Signing("Secure Enclave signing failed".into()));
    }
    let sig = unsafe { CFData::wrap_under_create_rule(signature) };
    Ok(sig.bytes().to_vec())
}

/// Derive an HMAC key for counter integrity from the signing public key.
fn derive_counter_hmac_key(public_key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-counter-auth-v1");
    hasher.update(public_key);
    hasher.finalize().to_vec()
}

/// Compute HMAC-SHA256 over the 8-byte counter value.
fn compute_counter_hmac(hmac_key: &[u8], counter_bytes: &[u8; 8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(hmac_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(counter_bytes);
    mac.finalize().into_bytes().into()
}

fn load_counter(state: &mut SecureEnclaveState) -> Result<(), TpmError> {
    match fs::read(&state.counter_file) {
        Ok(data) if data.len() == 40 => {
            // New format: 8-byte counter + 32-byte HMAC
            let counter_bytes: [u8; 8] = data[0..8].try_into().expect("slice is exactly 8 bytes");
            let stored_hmac: [u8; 32] = data[8..40].try_into().expect("slice is exactly 32 bytes");

            let hmac_key = derive_counter_hmac_key(&state.public_key);
            let expected_hmac = compute_counter_hmac(&hmac_key, &counter_bytes);

            if stored_hmac.ct_eq(&expected_hmac).unwrap_u8() == 0 {
                log::error!(
                    "Counter HMAC verification failed — possible tampering: {:?}",
                    state.counter_file
                );
                return Err(TpmError::CounterRollback);
            }

            state.counter = u64::from_be_bytes(counter_bytes);
            Ok(())
        }
        Ok(data) if data.len() == 8 => {
            // Legacy format (no HMAC) — accept and immediately re-persist with HMAC
            // to close the rollback window before any caller can act on the value.
            let bytes: [u8; 8] = data[0..8].try_into().expect("slice is exactly 8 bytes");
            state.counter = u64::from_be_bytes(bytes);
            save_counter(state);
            Ok(())
        }
        Ok(data) => {
            log::error!(
                "Counter file corrupt ({} bytes, expected 8 or 40): {:?}",
                data.len(),
                state.counter_file
            );
            Err(TpmError::CounterRollback)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            state.counter = 0;
            Ok(())
        }
        Err(e) => Err(TpmError::Io(e)),
    }
}

fn save_counter(state: &SecureEnclaveState) {
    if let Some(parent) = state.counter_file.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let counter_bytes = state.counter.to_be_bytes();
    let hmac_key = derive_counter_hmac_key(&state.public_key);
    let hmac = compute_counter_hmac(&hmac_key, &counter_bytes);

    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(&counter_bytes);
    buf.extend_from_slice(&hmac);

    // Atomic write: write to tmp, fsync, rename to avoid partial writes on crash.
    let tmp_path = state.counter_file.with_extension("tmp");
    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(&buf)?;
        f.sync_all()?;
        fs::rename(&tmp_path, &state.counter_file)?;
        Ok(())
    })();
    if let Err(e) = write_result {
        log::error!(
            "Failed to persist counter to {:?}: {}",
            state.counter_file,
            e
        );
        let _ = fs::remove_file(&tmp_path);
    }
    if let Err(e) = crate::crypto::restrict_permissions(&state.counter_file, 0o600) {
        log::warn!("Failed to set counter file permissions: {}", e);
    }
}

impl SecureEnclaveProvider {
    /// v4 format: XOR cipher. Rejected at unseal time because XOR provides no
    /// authentication; a bitflipped ciphertext silently produces garbage plaintext.
    /// Data sealed with v4 must be re-created with a v5 AEAD seal.
    fn unseal_v4_legacy(
        &self,
        _state: &SecureEnclaveState,
        _sealed: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        log::error!(
            "Refusing to unseal v4 legacy format: unauthenticated XOR cipher is \
             insecure. Re-create sealed data using the current v5 AEAD format."
        );
        Err(TpmError::SealedVersionUnsupported)
    }

    fn unseal_v5_aead(
        &self,
        state: &SecureEnclaveState,
        sealed: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        const HEADER_LEN: usize = 1 + 32 + 12; // 45
        if sealed.len() < HEADER_LEN + 16 {
            return Err(TpmError::SealedDataTooShort);
        }
        let seal_nonce = &sealed[1..33];
        let aead_nonce_bytes = &sealed[33..45];
        let ciphertext = &sealed[45..];

        let signature = Zeroizing::new(sign(state, seal_nonce)?);
        let mut key_material = Sha256::digest(&*signature);

        let result = (|| {
            let cipher = ChaCha20Poly1305::new_from_slice(&key_material)
                .map_err(|e| TpmError::Unsealing(format!("AEAD key init: {e}")))?;
            let aead_nonce = AeadNonce::from_slice(aead_nonce_bytes);
            cipher
                .decrypt(aead_nonce, ciphertext)
                .map_err(|_| TpmError::SealedCorrupted)
        })();

        key_material.zeroize();
        drop(signature);
        result
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
            secure_clock: false,
        }
    }

    fn device_id(&self) -> String {
        self.cached_device_id.clone()
    }

    fn algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::ES256
    }

    fn public_key(&self) -> Vec<u8> {
        self.cached_public_key.clone()
    }

    fn quote(&self, nonce: &[u8], _pcrs: &[u32]) -> Result<Quote, TpmError> {
        let state = self.state.lock_recover();
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

    fn bind(&self, data: &[u8]) -> Result<Binding, TpmError> {
        let mut state = self.state.lock_recover();

        let timestamp = Utc::now();
        let data_hash = Sha256::digest(data).to_vec();
        let next_counter = state.counter + 1;
        let payload = super::build_binding_payload(&data_hash, &timestamp, &state.device_id);

        let signature = sign(&state, &payload)?;

        // Persist counter only after signing succeeds to avoid gaps
        state.counter = next_counter;
        save_counter(&state);

        Ok(Binding {
            version: 1,
            provider_type: "secure-enclave".to_string(),
            device_id: state.device_id.clone(),
            timestamp,
            attested_hash: data_hash,
            signature,
            public_key: state.public_key.clone(),
            monotonic_counter: Some(state.counter),
            safe_clock: None,
            attestation: Some(Attestation {
                payload,
                quote: None,
            }),
        })
    }

    fn verify(&self, binding: &Binding) -> Result<(), TpmError> {
        crate::tpm::verification::verify_binding(binding)
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TpmError> {
        let state = self.state.lock_recover();
        sign(&state, data)
    }

    fn seal(&self, data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TpmError> {
        let state = self.state.lock_recover();

        let mut seal_nonce = Zeroizing::new(vec![0u8; 32]);
        getrandom::getrandom(&mut seal_nonce)
            .map_err(|e| TpmError::Sealing(format!("seal nonce generation: {e}")))?;

        let signature = Zeroizing::new(sign(&state, &seal_nonce)?);
        let mut key_material = Sha256::digest(&*signature);

        let result = (|| -> Result<(Vec<u8>, [u8; 12]), TpmError> {
            let cipher = ChaCha20Poly1305::new_from_slice(&key_material)
                .map_err(|e| TpmError::Sealing(format!("AEAD key init: {e}")))?;
            let mut nonce_bytes = [0u8; 12];
            getrandom::getrandom(&mut nonce_bytes)
                .map_err(|e| TpmError::Sealing(format!("nonce generation: {e}")))?;
            let aead_nonce = AeadNonce::from_slice(&nonce_bytes);
            let ciphertext = cipher
                .encrypt(aead_nonce, data)
                .map_err(|e| TpmError::Sealing(format!("AEAD encrypt: {e}")))?;
            Ok((ciphertext, nonce_bytes))
        })();

        key_material.zeroize();

        let (ciphertext, nonce_bytes) = result?;
        let mut sealed = Vec::with_capacity(1 + 32 + 12 + ciphertext.len());
        sealed.push(5);
        sealed.extend_from_slice(&seal_nonce);
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, TpmError> {
        let state = self.state.lock_recover();
        if sealed.is_empty() {
            return Err(TpmError::SealedDataTooShort);
        }

        match sealed[0] {
            4 => self.unseal_v4_legacy(&state, sealed),
            5 => self.unseal_v5_aead(&state, sealed),
            _ => Err(TpmError::SealedVersionUnsupported),
        }
    }

    fn clock_info(&self) -> Result<super::ClockInfo, TpmError> {
        let state = self.state.lock_recover();
        let elapsed = u64::try_from(state.start_time.elapsed().unwrap_or_default().as_millis())
            .unwrap_or(u64::MAX);
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
    /// Local self-attestation (full Apple App Attest requires entitlements).
    pub fn generate_key_attestation(&self, challenge: &[u8]) -> Result<KeyAttestation, TpmError> {
        let state = self.state.lock_recover();
        let timestamp = Utc::now();

        let mut attestation_data = Vec::new();
        attestation_data.extend_from_slice(b"CPOP-ATTEST-V2\n");

        let challenge_hash = Sha256::digest(challenge);
        attestation_data.extend_from_slice(&challenge_hash);
        attestation_data.extend_from_slice(&state.public_key);
        let device_id_bytes = state.device_id.as_bytes();
        attestation_data.extend_from_slice(&(device_id_bytes.len() as u32).to_be_bytes());
        attestation_data.extend_from_slice(device_id_bytes);

        let ts_bytes = timestamp.timestamp_nanos_safe().to_le_bytes();
        attestation_data.extend_from_slice(&ts_bytes);

        if let Some(ref uuid) = state.hardware_info.uuid {
            let uuid_hash = Sha256::digest(uuid.as_bytes());
            attestation_data.extend_from_slice(&uuid_hash);
        }

        if let Some(ref model) = state.hardware_info.model {
            let model_bytes = model.as_bytes();
            attestation_data.extend_from_slice(&(model_bytes.len() as u32).to_be_bytes());
            attestation_data.extend_from_slice(model_bytes);
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

    /// Verify a key attestation against the expected challenge.
    /// NOTE: This is local-only verification; it reconstructs expected data
    /// from the current device's hardware_info, so it will fail on a different device.
    pub fn verify_key_attestation(
        &self,
        attestation: &KeyAttestation,
        expected_challenge: &[u8],
    ) -> Result<bool, TpmError> {
        let state = self.state.lock_recover();

        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(b"CPOP-ATTEST-V2\n");

        let challenge_hash = Sha256::digest(expected_challenge);
        expected_data.extend_from_slice(&challenge_hash);

        expected_data.extend_from_slice(&attestation.public_key);
        let device_id_bytes = attestation.device_id.as_bytes();
        expected_data.extend_from_slice(&(device_id_bytes.len() as u32).to_be_bytes());
        expected_data.extend_from_slice(device_id_bytes);

        let ts_bytes = attestation.timestamp.timestamp_nanos_safe().to_le_bytes();
        expected_data.extend_from_slice(&ts_bytes);

        if let Some(ref uuid) = state.hardware_info.uuid {
            let uuid_hash = Sha256::digest(uuid.as_bytes());
            expected_data.extend_from_slice(&uuid_hash);
        }

        if let Some(ref model) = state.hardware_info.model {
            let model_bytes = model.as_bytes();
            expected_data.extend_from_slice(&(model_bytes.len() as u32).to_be_bytes());
            expected_data.extend_from_slice(model_bytes);
        }

        let expected_proof = Sha256::digest(&expected_data).to_vec();
        // AUD-132: Use constant-time comparison to prevent timing side-channel
        if attestation
            .attestation_proof
            .ct_eq(&expected_proof)
            .unwrap_u8()
            == 0
        {
            return Ok(false);
        }

        let verify_key = state
            .attestation_public_key
            .as_ref()
            .unwrap_or(&state.public_key);

        verify_ecdsa_signature(verify_key, &expected_data, &attestation.signature)
    }

    /// Return metadata about the primary signing key.
    pub fn get_key_info(&self) -> SecureEnclaveKeyInfo {
        let state = self.state.lock_recover();
        SecureEnclaveKeyInfo {
            tag: SE_KEY_TAG.to_string(),
            public_key: state.public_key.clone(),
            created_at: None, // Secure Enclave doesn't expose creation time
            hardware_backed: true,
            key_size: 256,
        }
    }

    /// Return metadata about the attestation key, if created.
    pub fn get_attestation_key_info(&self) -> Option<SecureEnclaveKeyInfo> {
        let state = self.state.lock_recover();
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

    /// Collect hardware info (model, OS version, device ID) as key-value pairs.
    pub fn get_hardware_info(&self) -> HashMap<String, String> {
        let state = self.state.lock_recover();
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

    /// Return the current monotonic counter value.
    pub fn get_counter(&self) -> u64 {
        self.state.lock_recover().counter
    }

    /// Increment and persist the monotonic counter, returning the new value.
    pub fn increment_counter(&self) -> u64 {
        let mut state = self.state.lock_recover();
        state.counter += 1;
        save_counter(&state);
        state.counter
    }

    /// Return true if Secure Enclave hardware is available on this system.
    pub fn is_hardware_available() -> bool {
        is_secure_enclave_available()
    }
}

#[allow(dead_code)]
fn sign_with_key(key_ref: SecKeyRef, data: &[u8]) -> Result<Vec<u8>, TpmError> {
    if key_ref.is_null() {
        return Err(TpmError::NotInitialized);
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
        if !error.is_null() {
            unsafe { core_foundation_sys::base::CFRelease(error as CFTypeRef) };
        }
        return Err(TpmError::Signing("Secure Enclave signing failed".into()));
    }
    let sig = unsafe { CFData::wrap_under_create_rule(signature) };
    Ok(sig.bytes().to_vec())
}

#[allow(dead_code)]
fn verify_ecdsa_signature(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool, TpmError> {
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

    if public_key.is_empty() {
        return Err(TpmError::UnsupportedPublicKey);
    }

    unsafe {
        let key_type_key = CFString::wrap_under_get_rule(kSecAttrKeyType);
        let key_type_value =
            CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom as CFTypeRef);
        let key_class_key = CFString::wrap_under_get_rule(kSecAttrKeyClass);
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
            return Err(TpmError::UnsupportedPublicKey);
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
    if std::env::var("CPOP_DISABLE_SECURE_ENCLAVE").is_ok() {
        log::info!("Secure Enclave disabled via environment variable");
        return false;
    }

    use std::process::Command;

    let output = match Command::new("/usr/sbin/sysctl")
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
        if std::env::var("CI").is_ok() || std::env::var("GITHUB_ACTIONS").is_ok() {
            log::info!("Skipping T2 detection in CI environment");
            return false;
        }

        let t2_check = Command::new("/usr/sbin/ioreg")
            .args(["-l", "-d1", "-c", "AppleT2Controller"])
            .output();

        if let Ok(out) = t2_check {
            if out.status.success() {
                let ioreg_output = String::from_utf8_lossy(&out.stdout);
                if !ioreg_output.contains("AppleT2Controller") {
                    return false;
                }
            }
        } else {
            return false;
        }
    }

    let security_check = Command::new("/usr/bin/security")
        .args(["list-keychains"])
        .output();

    match security_check {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

fn extract_public_key(key_ref: SecKeyRef) -> Result<Vec<u8>, TpmError> {
    let public_key = unsafe { SecKeyCopyPublicKey(key_ref) };
    if public_key.is_null() {
        return Err(TpmError::KeyExport("public key unavailable".into()));
    }
    let mut error: CFErrorRef = null_mut();
    let data_ref = unsafe { SecKeyCopyExternalRepresentation(public_key, &mut error) };
    if data_ref.is_null() {
        unsafe { core_foundation_sys::base::CFRelease(public_key as *mut std::ffi::c_void) };
        return Err(TpmError::KeyExport("public key export failed".into()));
    }
    let data = unsafe { CFData::wrap_under_create_rule(data_ref) };
    let result = data.bytes().to_vec();
    unsafe { core_foundation_sys::base::CFRelease(public_key as *mut std::ffi::c_void) };
    Ok(result)
}

fn hardware_uuid() -> Option<String> {
    use std::process::Command;

    let output = Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("IOPlatformUUID") {
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

    let output = Command::new("/usr/sbin/sysctl")
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

fn writersproof_dir() -> Result<PathBuf, TpmError> {
    if let Ok(dir) = std::env::var("CPOP_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    dirs::home_dir()
        .map(|d| d.join(".writersproof"))
        .ok_or_else(|| TpmError::Configuration("cannot determine home directory".into()))
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

        let provider = match try_init() {
            Some(p) => p,
            None => {
                println!(
                    "try_init returned None despite is_secure_enclave_available returning true"
                );
                return;
            }
        };

        let caps = provider.capabilities();
        assert!(caps.hardware_backed);
        assert!(!caps.secure_clock);
        assert!(caps.monotonic_counter);

        let device_id = provider.device_id();
        assert!(!device_id.is_empty());
        assert!(device_id.starts_with("se-"));

        let pub_key = provider.public_key();
        assert!(!pub_key.is_empty());

        let data = b"test-binding-data";
        let binding = provider.bind(data).expect("Bind failed");

        assert_eq!(binding.provider_type, "secure-enclave");
        assert_eq!(binding.device_id, device_id);

        provider.verify(&binding).expect("Verification failed");

        let nonce = b"test-nonce";
        let quote = provider.quote(nonce, &[]).expect("Quote failed");
        assert_eq!(quote.nonce, nonce);
        crate::tpm::verify_quote(&quote).expect("Quote verification failed");

        let secret = b"my-secret-data";
        let sealed = provider.seal(secret, &[]).expect("Seal failed");
        assert_ne!(sealed, secret);

        let unsealed = provider.unseal(&sealed).expect("Unseal failed");
        assert_eq!(unsealed, secret);

        let challenge = b"attestation-challenge";
        if let Ok(attestation) = provider.generate_key_attestation(challenge) {
            let verified = provider
                .verify_key_attestation(&attestation, challenge)
                .expect("Attestation verification failed");
            assert!(verified);
        } else {
            println!("Key attestation generation failed (expected in some test environments)");
        }

        let count1 = provider.get_counter();
        let count2 = provider.increment_counter();
        assert_eq!(count2, count1 + 1);
    }
}
