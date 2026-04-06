// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Verification logic for checkpoint chains.

use crate::error::{Error, Result};
use crate::vdf;

use super::chain::Chain;
use super::chain_helpers::{genesis_prev_hash, mix_physics_seed};
use super::types::*;

impl Chain {
    /// Verify the chain, returning `Err` on failure.
    pub fn verify(&self) -> Result<()> {
        let report = self.verify_detailed();
        if report.valid {
            Ok(())
        } else {
            Err(Error::checkpoint(if report.errors.is_empty() {
                "verification failed".to_string()
            } else {
                report.errors.join("; ")
            }))
        }
    }

    /// Lightweight hash-chain check (no VDF reverification).
    ///
    /// Genesis checkpoint: accepts both legacy all-zeros `previous_hash` and
    /// spec-correct `H(document-ref)` for backward compatibility with chains
    /// created before the genesis hash computation was standardized.
    pub fn verify_hash_chain(&self) -> Result<()> {
        for (i, cp) in self.checkpoints.iter().enumerate() {
            if cp.compute_hash() != cp.hash {
                return Err(Error::checkpoint(format!(
                    "checkpoint {i}: computed hash does not match stored hash"
                )));
            }
            if i > 0 {
                if cp.previous_hash != self.checkpoints[i - 1].hash {
                    return Err(Error::checkpoint(format!(
                        "checkpoint {i}: previous_hash does not match checkpoint {}'s hash",
                        i - 1
                    )));
                }
            } else {
                // Genesis: accept legacy all-zeros OR spec-correct H(document-ref)
                let is_legacy_zeros = cp.previous_hash == [0u8; 32];
                let is_spec_genesis =
                    genesis_prev_hash(cp.content_hash, cp.content_size, &self.metadata.document_path)
                        .map(|h| cp.previous_hash == h)
                        .unwrap_or(false);
                if is_legacy_zeros {
                    log::warn!("Legacy all-zeros genesis hash accepted; consider re-chaining");
                } else if !is_spec_genesis {
                    return Err(Error::checkpoint(
                        "checkpoint 0: invalid genesis previous_hash \
                         (neither all-zeros nor spec-correct H(document-ref))"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Verify the chain and return a detailed report with warnings and failures.
    ///
    /// This performs structural verification only: hash linkage, ordinal sequence,
    /// genesis prev-hash, and timestamp sanity. Cryptographic signature verification
    /// of individual checkpoints is deferred to the caller (see `unsigned_checkpoints`
    /// in the returned report for checkpoints that lack signatures).
    pub fn verify_detailed(&self) -> VerificationReport {
        let mut report = VerificationReport::new();

        for (i, checkpoint) in self.checkpoints.iter().enumerate() {
            if let Err(e) = checkpoint.validate_timestamp() {
                report.fail(format!("checkpoint {i}: {e}"));
                return report;
            }

            // H-002: Non-monotonic timestamps indicate clock manipulation or
            // system clock regression. Allow up to 1 second of drift tolerance
            // for NTP corrections; reject larger regressions as evidence of
            // backdating or tampering.
            if i > 0 {
                let prev_ts = self.checkpoints[i - 1].timestamp;
                if checkpoint.timestamp < prev_ts {
                    let drift = prev_ts
                        .signed_duration_since(checkpoint.timestamp)
                        .num_seconds();
                    if drift > 1 {
                        report.fail(format!(
                            "checkpoint {i}: timestamp backdated by {drift}s \
                             (before previous checkpoint)"
                        ));
                        return report;
                    }
                    report
                        .warnings
                        .push(format!("checkpoint {i}: minor clock drift ({drift}s)"));
                }
            }

            if checkpoint.compute_hash() != checkpoint.hash {
                report.fail(format!("checkpoint {i}: hash mismatch"));
                return report;
            }

            if checkpoint.ordinal != i as u64 {
                report.ordinal_gaps.push((i as u64, checkpoint.ordinal));
                report.fail(format!(
                    "checkpoint {i}: ordinal gap (expected {i}, got {})",
                    checkpoint.ordinal
                ));
                return report;
            }

            if i > 0 {
                if checkpoint.previous_hash != self.checkpoints[i - 1].hash {
                    report.fail(format!("checkpoint {i}: broken chain link"));
                    return report;
                }
            } else {
                // Genesis: accept legacy all-zeros OR spec-correct H(document-ref)
                let is_legacy_zeros = checkpoint.previous_hash == [0u8; 32];
                let is_spec_genesis = genesis_prev_hash(
                    checkpoint.content_hash,
                    checkpoint.content_size,
                    &self.metadata.document_path,
                )
                .map(|h| checkpoint.previous_hash == h)
                .unwrap_or(false);
                if is_legacy_zeros {
                    log::warn!("Legacy all-zeros genesis hash accepted; consider re-chaining");
                } else if !is_spec_genesis {
                    report.fail("checkpoint 0: invalid genesis prev-hash".into());
                    return report;
                }
            }

            match checkpoint.signature.as_ref() {
                None => {
                    report.unsigned_checkpoints.push(checkpoint.ordinal);
                    match self.metadata.signature_policy {
                        SignaturePolicy::Required => {
                            report.fail(format!(
                                "checkpoint {i}: unsigned (signature required by policy)"
                            ));
                            return report;
                        }
                        SignaturePolicy::Optional => {
                            report
                                .warnings
                                .push(format!("checkpoint {i}: unsigned (optional policy)"));
                        }
                    }
                }
                Some(sig) => {
                    // H-004: Intentionally structural-only; we verify Ed25519
                    // signature length but defer cryptographic verification to
                    // keyhierarchy/verification.rs (verify_checkpoint_signatures)
                    // which has access to the session's public key. The Chain
                    // struct never holds key material by design.
                    if sig.len() != 64 {
                        report.signature_failures.push(checkpoint.ordinal);
                        report.fail(format!(
                            "checkpoint {i}: invalid Ed25519 signature length {} \
                             (expected 64 bytes; cryptographic verification deferred \
                             to keyhierarchy)",
                            sig.len()
                        ));
                        return report;
                    }
                    report.warnings.push(format!(
                        "checkpoint {i}: Ed25519 signature present but not \
                         cryptographically verified (no verifying key in chain; \
                         use keyhierarchy::verify_checkpoint_signatures for full check)"
                    ));
                }
            }

            match self.metadata.entanglement_mode {
                EntanglementMode::Legacy => {
                    let require_vdf = i > 0;
                    match checkpoint.vdf.as_ref() {
                        None if require_vdf => {
                            report.fail(format!(
                                "checkpoint {i}: missing VDF proof (required for time verification)"
                            ));
                            return report;
                        }
                        None => {
                            // Genesis without VDF: legacy chain predates genesis-VDF requirement.
                            report.warnings.push(format!(
                                "checkpoint 0: no VDF proof; chain predates genesis-VDF requirement"
                            ));
                        }
                        Some(vdf) => {
                            let expected_input = vdf::chain_input(
                                checkpoint.content_hash,
                                checkpoint.previous_hash,
                                checkpoint.ordinal,
                            );
                            if vdf.input != expected_input {
                                report.fail(format!("checkpoint {i}: VDF input mismatch"));
                                return report;
                            }
                            if !vdf::verify(vdf) {
                                report.fail(format!("checkpoint {i}: VDF verification failed"));
                                return report;
                            }
                        }
                    }
                }
                EntanglementMode::Entangled => {
                    let vdf = match checkpoint.vdf.as_ref() {
                        Some(v) => v,
                        None => {
                            report.fail(format!(
                                "checkpoint {i}: missing VDF proof (required for entangled verification)"
                            ));
                            return report;
                        }
                    };

                    let jitter_binding = match checkpoint.jitter_binding.as_ref() {
                        Some(j) => j,
                        None => {
                            report.fail(format!(
                                "checkpoint {i}: missing jitter binding (required for entangled mode)"
                            ));
                            return report;
                        }
                    };

                    let previous_vdf_output = if i > 0 {
                        match self.checkpoints[i - 1].vdf.as_ref() {
                            Some(v) => v.output,
                            None => {
                                report.fail(format!(
                                    "checkpoint {i}: previous checkpoint missing VDF (required for entangled chain)"
                                ));
                                return report;
                            }
                        }
                    } else {
                        [0u8; 32]
                    };

                    let base_input = vdf::chain_input_entangled(
                        previous_vdf_output,
                        jitter_binding.jitter_hash,
                        checkpoint.content_hash,
                        checkpoint.ordinal,
                    );
                    let expected_input = mix_physics_seed(base_input, jitter_binding.physics_seed);
                    if vdf.input != expected_input {
                        report.fail(format!("checkpoint {i}: VDF input mismatch (entangled)"));
                        return report;
                    }
                    if !vdf::verify(vdf) {
                        report.fail(format!("checkpoint {i}: VDF verification failed"));
                        return report;
                    }
                }
            }

            if let Some(rfc_vdf) = &checkpoint.rfc_vdf {
                use super::types::{VDF_RFC_INPUT_END, VDF_RFC_INPUT_OFFSET};
                // The 64-byte output field encodes [vdf_output || vdf_input].
                // Verify the input half matches the challenge field.
                if rfc_vdf.output[VDF_RFC_INPUT_OFFSET..VDF_RFC_INPUT_END] != rfc_vdf.challenge {
                    report.fail(format!(
                        "checkpoint {i}: rfc_vdf layout mismatch \
                         (input half of output != challenge)"
                    ));
                    return report;
                }
            }

            // H-003: Argon2 SWF verification checks internal consistency only
            // (Merkle proof over the Argon2id output). Verifying that the SWF
            // input was correctly derived requires the session context, which
            // is not available during standalone chain verification.
            if let Some(swf) = &checkpoint.argon2_swf {
                match vdf::swf_argon2::verify(swf) {
                    Ok(true) => {}
                    Ok(false) => {
                        report.fail(format!(
                            "checkpoint {i}: Argon2id SWF Merkle verification failed"
                        ));
                        return report;
                    }
                    Err(e) => {
                        report.fail(format!("checkpoint {i}: Argon2id SWF error: {e}"));
                        return report;
                    }
                }
            }
        }

        // Integrity metadata (checkpoint_count, mmr_root, metadata_signature)
        // is verified externally via CheckpointMmr, not stored on Chain.

        report
    }

    /// Validate VDF proofs after deserialization to reject tampered chain files.
    #[allow(dead_code)]
    pub(crate) fn validate_vdf_proofs(&self) -> Result<()> {
        for (i, checkpoint) in self.checkpoints.iter().enumerate() {
            let vdf = match checkpoint.vdf.as_ref() {
                Some(v) => v,
                None => continue,
            };

            let expected_input = match self.metadata.entanglement_mode {
                EntanglementMode::Legacy => vdf::chain_input(
                    checkpoint.content_hash,
                    checkpoint.previous_hash,
                    checkpoint.ordinal,
                ),
                EntanglementMode::Entangled => {
                    let previous_vdf_output = if i > 0 {
                        match self.checkpoints[i - 1].vdf.as_ref() {
                            Some(v) => v.output,
                            None => {
                                return Err(Error::checkpoint(format!(
                                    "checkpoint {i}: previous checkpoint missing VDF \
                                     (required for entangled chain)"
                                )));
                            }
                        }
                    } else {
                        [0u8; 32]
                    };

                    let jitter_binding = checkpoint.jitter_binding.as_ref().ok_or_else(|| {
                        Error::checkpoint(format!(
                            "checkpoint {i}: missing jitter binding \
                             (required for entangled mode)"
                        ))
                    })?;

                    let base_input = vdf::chain_input_entangled(
                        previous_vdf_output,
                        jitter_binding.jitter_hash,
                        checkpoint.content_hash,
                        checkpoint.ordinal,
                    );
                    mix_physics_seed(base_input, jitter_binding.physics_seed)
                }
            };

            if vdf.input != expected_input {
                return Err(Error::checkpoint(format!(
                    "checkpoint {i}: VDF input mismatch on deserialization"
                )));
            }

            if !vdf::verify(vdf) {
                return Err(Error::checkpoint(format!(
                    "checkpoint {i}: VDF proof invalid on deserialization"
                )));
            }
        }
        Ok(())
    }
}
