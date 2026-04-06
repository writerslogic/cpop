// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::signing::sign;
use super::types::{SecureEnclaveProvider, SecureEnclaveState};
use crate::tpm::TpmError;
use crate::MutexRecover;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce as AeadNonce,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

impl SecureEnclaveProvider {
    /// v4 format: XOR cipher. Rejected at unseal time because XOR provides no
    /// authentication; a bitflipped ciphertext silently produces garbage plaintext.
    /// Data sealed with v4 must be re-created with a v5 AEAD seal.
    pub(super) fn unseal_v4_legacy(
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

    pub(super) fn unseal_v5_aead(
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
        result
    }

    pub(super) fn seal_impl(&self, data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TpmError> {
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

    pub(super) fn unseal_impl(&self, sealed: &[u8]) -> Result<Vec<u8>, TpmError> {
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
}
