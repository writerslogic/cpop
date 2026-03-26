// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce as AeadNonce,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::crypto::{hkdf_expand, RATCHET_INIT_DOMAIN};
use super::error::KeyHierarchyError;
use super::identity::derive_master_identity;
use super::types::{PufProvider, RatchetState, Session, SessionRecoveryState};
use super::verification::verify_session_certificate;

pub fn recover_session(
    puf: &dyn PufProvider,
    recovery: &SessionRecoveryState,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    if recovery.certificate.session_id == [0u8; 32] {
        return Err(KeyHierarchyError::NoRecoveryData);
    }

    verify_session_certificate(&recovery.certificate)?;

    if recovery.certificate.document_hash != document_hash {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    let identity = derive_master_identity(puf)?;
    if identity.public_key != recovery.certificate.master_pubkey {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    if !recovery.last_ratchet_state.is_empty() {
        return recover_session_with_ratchet(puf, recovery);
    }

    recover_session_with_new_ratchet(puf, recovery)
}

fn recover_session_with_ratchet(
    puf: &dyn PufProvider,
    recovery: &SessionRecoveryState,
) -> Result<Session, KeyHierarchyError> {
    let data = &recovery.last_ratchet_state;
    if data.is_empty() {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    match data[0] {
        0x02 => recover_ratchet_v2_aead(puf, recovery),
        _ => recover_ratchet_v1_legacy(puf, recovery),
    }
}

/// Legacy v1 ratchet recovery: XOR cipher (no version byte, backward compat).
fn recover_ratchet_v1_legacy(
    puf: &dyn PufProvider,
    recovery: &SessionRecoveryState,
) -> Result<Session, KeyHierarchyError> {
    let challenge = Sha256::digest(b"witnessd-ratchet-recovery-v1");
    let response = puf.get_response(&challenge)?;
    let mut key = hkdf_expand(&response, b"ratchet-recovery-key", &[])?;

    if recovery.last_ratchet_state.len() < 40 {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    let mut ratchet_state = [0u8; 32];
    for i in 0..32 {
        ratchet_state[i] = recovery.last_ratchet_state[i] ^ key[i % 32];
    }
    let ordinal = u64::from_be_bytes(
        recovery.last_ratchet_state[32..40]
            .try_into()
            .map_err(|_| KeyHierarchyError::SessionRecoveryFailed)?,
    );
    key.zeroize();

    let protected = crate::crypto::ProtectedKey::new(ratchet_state);
    ratchet_state.zeroize();
    Ok(Session {
        certificate: recovery.certificate.clone(),
        ratchet: RatchetState {
            current: protected,
            ordinal,
            wiped: false,
        },
        signatures: recovery.signatures.clone(),
    })
}

/// v2 ratchet recovery: ChaCha20-Poly1305 AEAD.
fn recover_ratchet_v2_aead(
    puf: &dyn PufProvider,
    recovery: &SessionRecoveryState,
) -> Result<Session, KeyHierarchyError> {
    // Format: version(1) || aead_nonce(12) || ciphertext+tag
    const HEADER_LEN: usize = 1 + 12; // 13
    let data = &recovery.last_ratchet_state;
    if data.len() < HEADER_LEN + 16 {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    let nonce_bytes = &data[1..13];
    let ciphertext = &data[13..];

    let challenge = Sha256::digest(b"witnessd-ratchet-recovery-v2");
    let response = puf.get_response(&challenge)?;
    let key = Zeroizing::new(hkdf_expand(&response, b"ratchet-recovery-key-v2", &[])?);

    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| KeyHierarchyError::SessionRecoveryFailed)?;
    let aead_nonce = AeadNonce::from_slice(nonce_bytes);

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(aead_nonce, ciphertext)
            .map_err(|_| KeyHierarchyError::SessionRecoveryFailed)?,
    );
    drop(key);

    if plaintext.len() < 40 {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    let mut ratchet_state = [0u8; 32];
    ratchet_state.copy_from_slice(&plaintext[..32]);
    let ordinal = u64::from_be_bytes(
        plaintext[32..40]
            .try_into()
            .map_err(|_| KeyHierarchyError::SessionRecoveryFailed)?,
    );

    let protected = crate::crypto::ProtectedKey::new(ratchet_state);
    ratchet_state.zeroize();
    Ok(Session {
        certificate: recovery.certificate.clone(),
        ratchet: RatchetState {
            current: protected,
            ordinal,
            wiped: false,
        },
        signatures: recovery.signatures.clone(),
    })
}

fn recover_session_with_new_ratchet(
    puf: &dyn PufProvider,
    recovery: &SessionRecoveryState,
) -> Result<Session, KeyHierarchyError> {
    let mut next_ordinal = 0u64;
    if let Some(last) = recovery.signatures.last() {
        next_ordinal = last.ordinal + 1;
    }

    let challenge = Sha256::digest(b"witnessd-ratchet-continuation-v1");
    let response = puf.get_response(&challenge)?;

    let mut last_hash = [0u8; 32];
    if let Some(last) = recovery.signatures.last() {
        last_hash = last.checkpoint_hash;
    }

    let mut continuation_input = Zeroizing::new(Vec::new());
    continuation_input.extend_from_slice(&response);
    continuation_input.extend_from_slice(&last_hash);
    continuation_input.extend_from_slice(&recovery.certificate.session_id);

    let ratchet_init = hkdf_expand(
        &continuation_input,
        RATCHET_INIT_DOMAIN.as_bytes(),
        b"continuation",
    )?;
    drop(continuation_input);

    Ok(Session {
        certificate: recovery.certificate.clone(),
        ratchet: RatchetState {
            current: crate::crypto::ProtectedKey::new(ratchet_init),
            ordinal: next_ordinal,
            wiped: false,
        },
        signatures: recovery.signatures.clone(),
    })
}
