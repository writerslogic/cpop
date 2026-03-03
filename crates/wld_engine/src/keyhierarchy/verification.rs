// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::crypto::{build_cert_data, fingerprint_for_public_key};
use super::error::KeyHierarchyError;
use super::types::{
    CheckpointSignature, KeyHierarchyEvidence, SessionBindingReport, SessionCertificate,
};

pub fn verify_session_certificate(cert: &SessionCertificate) -> Result<(), KeyHierarchyError> {
    let cert_data = build_cert_data(
        cert.session_id,
        &cert.session_pubkey,
        cert.created_at,
        cert.document_hash,
    );

    let pubkey = VerifyingKey::from_bytes(
        cert.master_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| KeyHierarchyError::InvalidCert)?,
    )
    .map_err(|_| KeyHierarchyError::InvalidCert)?;

    let signature = Signature::from_bytes(&cert.signature);
    pubkey
        .verify(&cert_data, &signature)
        .map_err(|_| KeyHierarchyError::InvalidCert)
}

pub fn verify_checkpoint_signatures(
    signatures: &[CheckpointSignature],
) -> Result<(), KeyHierarchyError> {
    let mut prev_counter: Option<u64> = None;

    for (i, sig) in signatures.iter().enumerate() {
        if sig.ordinal != i as u64 {
            return Err(KeyHierarchyError::OrdinalMismatch);
        }

        let pubkey = VerifyingKey::from_bytes(
            sig.public_key
                .as_slice()
                .try_into()
                .map_err(|_| KeyHierarchyError::SignatureFailed)?,
        )
        .map_err(|_| KeyHierarchyError::SignatureFailed)?;
        let signature = Signature::from_bytes(&sig.signature);
        pubkey
            .verify(&sig.checkpoint_hash, &signature)
            .map_err(|_| KeyHierarchyError::SignatureFailed)?;

        // Validate hardware counter monotonicity
        if let Some(current) = sig.counter_value {
            if let Some(prev) = prev_counter {
                if current < prev {
                    return Err(KeyHierarchyError::Crypto(format!(
                        "counter rollback at ordinal {}: {} < {}",
                        sig.ordinal, current, prev,
                    )));
                }
                // Validate delta matches actual difference
                if let Some(delta) = sig.counter_delta {
                    if delta != current - prev {
                        return Err(KeyHierarchyError::Crypto(format!(
                            "counter delta mismatch at ordinal {}: delta {} != {} - {}",
                            sig.ordinal, delta, current, prev,
                        )));
                    }
                }
            }
            prev_counter = Some(current);
        }
    }
    Ok(())
}

/// Verify session TPM binding: checks that reboot counters haven't changed
/// mid-session (time-travel detection) and that counter deltas are consistent.
pub fn verify_session_binding(
    cert: &SessionCertificate,
) -> Result<SessionBindingReport, KeyHierarchyError> {
    let mut report = SessionBindingReport {
        has_start_quote: cert.start_quote.is_some(),
        has_end_quote: cert.end_quote.is_some(),
        counter_delta: None,
        reboot_detected: false,
        restart_detected: false,
        warnings: Vec::new(),
    };

    // Check counter progression
    if let (Some(start), Some(end)) = (cert.start_counter, cert.end_counter) {
        if end < start {
            return Err(KeyHierarchyError::Crypto(format!(
                "session counter rollback: end {} < start {}",
                end, start,
            )));
        }
        report.counter_delta = Some(end - start);
    }

    // Check for reboot mid-session (reset_count changed)
    if let (Some(start_rc), Some(end_rc)) = (cert.start_reset_count, cert.end_reset_count) {
        if end_rc != start_rc {
            report.reboot_detected = true;
            report.warnings.push(format!(
                "TPM ResetCount changed mid-session: {} -> {} (machine was rebooted)",
                start_rc, end_rc,
            ));
        }
    }

    // Check for restart mid-session (restart_count changed)
    if let (Some(start_rst), Some(end_rst)) = (cert.start_restart_count, cert.end_restart_count) {
        if end_rst != start_rst {
            report.restart_detected = true;
            report.warnings.push(format!(
                "TPM RestartCount changed mid-session: {} -> {} (TPM was restarted)",
                start_rst, end_rst,
            ));
        }
    }

    Ok(report)
}

pub fn verify_key_hierarchy(evidence: &KeyHierarchyEvidence) -> Result<(), KeyHierarchyError> {
    let cert = evidence
        .session_certificate
        .as_ref()
        .ok_or(KeyHierarchyError::InvalidCert)?;
    verify_session_certificate(cert)?;

    if let Some(identity) = &evidence.master_identity {
        if identity.public_key != cert.master_pubkey {
            return Err(KeyHierarchyError::InvalidCert);
        }
    }

    if !evidence.master_public_key.is_empty() {
        let expected = fingerprint_for_public_key(&evidence.master_public_key);
        if expected != evidence.master_fingerprint {
            return Err(KeyHierarchyError::InvalidCert);
        }
    }

    if evidence.ratchet_count != evidence.checkpoint_signatures.len() as i32 {
        return Err(KeyHierarchyError::InvalidCert);
    }

    verify_checkpoint_signatures(&evidence.checkpoint_signatures)
}

/// Validate Ed25519 byte lengths and verify the certificate signature.
///
/// Checks that `master_pubkey` is 32 bytes, `session_pubkey` is 32 bytes,
/// and `cert_signature` is 64 bytes, then performs Ed25519 signature
/// verification of `session_pubkey` against `master_pubkey`.
pub fn validate_cert_byte_lengths(
    master_pubkey: &[u8],
    session_pubkey: &[u8],
    cert_signature: &[u8],
) -> Result<(), String> {
    if master_pubkey.len() != 32 {
        return Err("invalid master public key size".to_string());
    }
    if session_pubkey.len() != 32 {
        return Err("invalid session public key size".to_string());
    }
    if cert_signature.len() != 64 {
        return Err("invalid certificate signature size".to_string());
    }

    let vk = VerifyingKey::from_bytes(master_pubkey.try_into().unwrap())
        .map_err(|e| format!("invalid master public key: {e}"))?;
    let sig = Signature::from_bytes(cert_signature.try_into().unwrap());
    vk.verify(session_pubkey, &sig)
        .map_err(|e| format!("certificate signature verification failed: {e}"))?;

    Ok(())
}

pub fn verify_ratchet_signature(
    ratchet_pubkey: &[u8],
    checkpoint_hash: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    if ratchet_pubkey.len() != 32 {
        return Err("invalid ratchet public key size".to_string());
    }
    if checkpoint_hash.len() != 32 {
        return Err("invalid checkpoint hash size".to_string());
    }
    if signature.len() != 64 {
        return Err("invalid signature size".to_string());
    }

    let pubkey = VerifyingKey::from_bytes(
        ratchet_pubkey
            .try_into()
            .map_err(|_| "invalid ratchet public key size".to_string())?,
    )
    .map_err(|_| "invalid ratchet public key".to_string())?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| "invalid signature size".to_string())?;
    let sig = Signature::from_bytes(&sig_bytes);
    pubkey
        .verify(checkpoint_hash, &sig)
        .map_err(|_| "signature verification failed".to_string())
}
