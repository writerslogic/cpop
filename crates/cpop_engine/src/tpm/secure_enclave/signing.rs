// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::types::SecureEnclaveState;
use crate::tpm::TpmError;
use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::string::CFString;
use core_foundation_sys::base::CFTypeRef;
use core_foundation_sys::error::CFErrorRef;
use security_framework_sys::base::SecKeyRef;
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
};
use security_framework_sys::key::{
    kSecKeyAlgorithmECDSASignatureMessageX962SHA256, SecKeyCreateSignature,
};
use std::ptr::null_mut;

pub(super) fn sign(state: &SecureEnclaveState, data: &[u8]) -> Result<Vec<u8>, TpmError> {
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

#[allow(dead_code)]
pub(super) fn sign_with_key(key_ref: SecKeyRef, data: &[u8]) -> Result<Vec<u8>, TpmError> {
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
pub(super) fn verify_ecdsa_signature(
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
