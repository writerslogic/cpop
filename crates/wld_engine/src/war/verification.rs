// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::declaration::Declaration;
use crate::evidence::Packet;
use crate::vdf;
use crate::war::types::{Block, CheckResult, ForensicDetails, Seal, VerificationReport, Version};
use ed25519_dalek::{Signature, VerifyingKey};
use hex;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

impl Block {
    /// Verify the WAR block and produce a verification report.
    pub fn verify(&self) -> VerificationReport {
        let mut checks = Vec::new();
        let mut all_passed = true;

        let sig_check = self.verify_signature();
        if !sig_check.passed {
            all_passed = false;
        }
        checks.push(sig_check);

        if let Some(evidence) = &self.evidence {
            let chain_check = verify_hash_chain(&self.seal, evidence, self.version);
            if !chain_check.passed {
                all_passed = false;
            }
            checks.push(chain_check);

            let vdf_check = verify_vdf_proofs(evidence);
            if !vdf_check.passed {
                all_passed = false;
            }
            checks.push(vdf_check);

            let decl_check = verify_declaration(evidence);
            if !decl_check.passed {
                all_passed = false;
            }
            checks.push(decl_check);
        } else {
            checks.push(CheckResult {
                name: "hash_chain".to_string(),
                passed: false,
                message: "Cannot verify hash chain without full evidence".to_string(),
            });
        }

        let summary = if all_passed {
            format!(
                "WAR block VALID: {} evidence for document {}",
                self.version.as_str(),
                &hex::encode(self.document_id)[..16]
            )
        } else {
            let failed: Vec<_> = checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| c.name.as_str())
                .collect();
            format!("WAR block INVALID: failed checks: {}", failed.join(", "))
        };

        let details = self.build_forensic_details();

        VerificationReport {
            valid: all_passed,
            checks,
            summary,
            details,
        }
    }

    /// Verify the Ed25519 seal signature over H3.
    pub fn verify_signature(&self) -> CheckResult {
        if !self.signed {
            return CheckResult {
                name: "seal_signature".to_string(),
                passed: false,
                message: "Seal unsigned: block lacks cryptographic seal signature".to_string(),
            };
        }

        let public_key = match VerifyingKey::from_bytes(&self.seal.public_key) {
            Ok(key) => key,
            Err(e) => {
                return CheckResult {
                    name: "seal_signature".to_string(),
                    passed: false,
                    message: format!("Invalid public key: {e}"),
                };
            }
        };

        let signature = Signature::from_bytes(&self.seal.signature);
        match public_key.verify_strict(&self.seal.h3, &signature) {
            Ok(()) => CheckResult {
                name: "seal_signature".to_string(),
                passed: true,
                message: "Ed25519 seal signature valid (H3 signed)".to_string(),
            },
            Err(e) => CheckResult {
                name: "seal_signature".to_string(),
                passed: false,
                message: format!("Seal signature verification failed: {e}"),
            },
        }
    }

    /// Build detailed forensic information from the block and its evidence.
    pub fn build_forensic_details(&self) -> ForensicDetails {
        let mut components = vec!["document".to_string(), "declaration".to_string()];

        let (elapsed_time_secs, checkpoint_count, keystroke_count, has_jitter_seal, has_hw) =
            if let Some(evidence) = &self.evidence {
                let elapsed = evidence.total_elapsed_time().as_secs_f64();
                let cp_count = evidence.checkpoints.len();
                let ks_count = evidence.keystroke.as_ref().map(|k| k.total_keystrokes);

                if evidence.keystroke.is_some() {
                    components.push("keystroke_evidence".to_string());
                }
                if evidence.presence.is_some() {
                    components.push("presence".to_string());
                }
                if evidence.hardware.is_some() {
                    components.push("hardware_attestation".to_string());
                }
                if evidence.behavioral.is_some() {
                    components.push("behavioral".to_string());
                }

                let has_jitter = evidence
                    .declaration
                    .as_ref()
                    .map(|d| d.has_jitter_seal())
                    .unwrap_or(false);
                let has_hw_attest = evidence.hardware.is_some();

                (
                    Some(elapsed),
                    Some(cp_count),
                    ks_count,
                    has_jitter,
                    has_hw_attest,
                )
            } else {
                (
                    None,
                    None,
                    None,
                    matches!(self.version, Version::V1_1 | Version::V2_0),
                    false,
                )
            };

        ForensicDetails {
            version: self.version.as_str().to_string(),
            author: self.author.clone(),
            document_id: hex::encode(self.document_id),
            timestamp: self.timestamp,
            components,
            elapsed_time_secs,
            checkpoint_count,
            keystroke_count,
            has_jitter_seal,
            has_hardware_attestation: has_hw,
            has_verifier_nonce: self.verifier_nonce.is_some(),
            verifier_nonce: self.verifier_nonce.map(hex::encode),
        }
    }
}

/// Compute the cryptographic seal for an evidence packet.
pub fn compute_seal(packet: &Packet, declaration: &Declaration) -> Result<Seal, String> {
    let doc_hash = hex::decode(&packet.document.final_hash)
        .map_err(|e| format!("invalid document hash: {e}"))?;

    let checkpoint_root =
        hex::decode(&packet.chain_hash).map_err(|e| format!("invalid chain hash: {e}"))?;

    let jitter_hash = declaration
        .jitter_sealed
        .as_ref()
        .map(|j| j.jitter_hash)
        .unwrap_or([0u8; 32]);

    let vdf_output = packet
        .checkpoints
        .iter()
        .rev()
        .find_map(|cp| cp.vdf_output.as_ref())
        .and_then(|o| hex::decode(o).ok())
        .unwrap_or_else(|| vec![0u8; 32]);

    let declaration_bytes = declaration
        .encode()
        .map_err(|e| format!("failed to encode declaration: {e}"))?;
    let declaration_hash = Sha256::digest(&declaration_bytes);
    let mut h1_hasher = Sha256::new();
    h1_hasher.update(b"witnessd-seal-h1-v1");
    h1_hasher.update(&doc_hash);
    h1_hasher.update(&checkpoint_root);
    h1_hasher.update(declaration_hash);
    let h1: [u8; 32] = h1_hasher.finalize().into();

    let mut h2_hasher = Sha256::new();
    h2_hasher.update(b"witnessd-seal-h2-v1");
    h2_hasher.update(h1);
    h2_hasher.update(jitter_hash);
    h2_hasher.update(&declaration.author_public_key);
    let h2: [u8; 32] = h2_hasher.finalize().into();

    let mut h3_hasher = Sha256::new();
    h3_hasher.update(b"witnessd-seal-h3-v1");
    h3_hasher.update(h2);
    h3_hasher.update(&vdf_output);
    h3_hasher.update(&doc_hash);
    let h3: [u8; 32] = h3_hasher.finalize().into();

    let mut public_key = [0u8; 32];
    if declaration.author_public_key.len() == 32 {
        public_key.copy_from_slice(&declaration.author_public_key);
    }

    Ok(Seal {
        h1,
        h2,
        h3,
        signature: [0u8; 64],
        public_key,
    })
}

/// Verify the H1/H2/H3 hash chain against the evidence packet.
pub fn verify_hash_chain(seal: &Seal, evidence: &Packet, version: Version) -> CheckResult {
    let declaration = match &evidence.declaration {
        Some(d) => d,
        None => {
            return CheckResult {
                name: "hash_chain".to_string(),
                passed: false,
                message: "Missing declaration".to_string(),
            };
        }
    };

    match compute_seal(evidence, declaration) {
        Ok(computed) => {
            if !bool::from(computed.h1.ct_eq(&seal.h1)) {
                return CheckResult {
                    name: "hash_chain".to_string(),
                    passed: false,
                    message: "H1 mismatch: document/checkpoint binding failed".to_string(),
                };
            }
            if !bool::from(computed.h2.ct_eq(&seal.h2)) {
                return CheckResult {
                    name: "hash_chain".to_string(),
                    passed: false,
                    message: "H2 mismatch: jitter/identity binding failed".to_string(),
                };
            }
            if !bool::from(computed.h3.ct_eq(&seal.h3)) {
                return CheckResult {
                    name: "hash_chain".to_string(),
                    passed: false,
                    message: "H3 mismatch: VDF binding failed".to_string(),
                };
            }
            CheckResult {
                name: "hash_chain".to_string(),
                passed: true,
                message: format!("Hash chain valid ({} mode)", version.as_str()),
            }
        }
        Err(e) => CheckResult {
            name: "hash_chain".to_string(),
            passed: false,
            message: format!("Failed to compute seal: {e}"),
        },
    }
}

/// Maximum VDF iterations accepted during verification (1 hour at default rate).
const MAX_VERIFICATION_ITERATIONS: u64 = 3_600_000_000;

/// Verify all VDF proofs in the evidence packet's checkpoints.
pub fn verify_vdf_proofs(evidence: &Packet) -> CheckResult {
    let mut verified = 0;
    let mut total = 0;

    for (i, cp) in evidence.checkpoints.iter().enumerate() {
        if let (Some(input_hex), Some(output_hex), Some(iterations)) =
            (&cp.vdf_input, &cp.vdf_output, cp.vdf_iterations)
        {
            total += 1;
            if iterations > MAX_VERIFICATION_ITERATIONS {
                return CheckResult {
                    name: "vdf_proofs".to_string(),
                    passed: false,
                    message: format!(
                        "VDF iterations at checkpoint {i} exceed maximum: {iterations} > {MAX_VERIFICATION_ITERATIONS}"
                    ),
                };
            }
            let input = match hex::decode(input_hex) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                Ok(b) => {
                    return CheckResult {
                        name: "vdf_proofs".to_string(),
                        passed: false,
                        message: format!(
                            "VDF input at checkpoint {i} has invalid length: {} (expected 32)",
                            b.len()
                        ),
                    };
                }
                Err(e) => {
                    return CheckResult {
                        name: "vdf_proofs".to_string(),
                        passed: false,
                        message: format!("VDF input at checkpoint {i} decode error: {e}"),
                    };
                }
            };
            let output = match hex::decode(output_hex) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                Ok(b) => {
                    return CheckResult {
                        name: "vdf_proofs".to_string(),
                        passed: false,
                        message: format!(
                            "VDF output at checkpoint {i} has invalid length: {} (expected 32)",
                            b.len()
                        ),
                    };
                }
                Err(e) => {
                    return CheckResult {
                        name: "vdf_proofs".to_string(),
                        passed: false,
                        message: format!("VDF output at checkpoint {i} decode error: {e}"),
                    };
                }
            };

            let proof = vdf::VdfProof {
                input,
                output,
                iterations,
                duration: std::time::Duration::from_secs(0),
            };

            if proof.verify() {
                verified += 1;
            } else {
                return CheckResult {
                    name: "vdf_proofs".to_string(),
                    passed: false,
                    message: format!("VDF proof at checkpoint {i} failed verification"),
                };
            }
        }
    }

    if total == 0 {
        CheckResult {
            name: "vdf_proofs".to_string(),
            passed: true,
            message: "No VDF proofs to verify (first checkpoint only)".to_string(),
        }
    } else {
        CheckResult {
            name: "vdf_proofs".to_string(),
            passed: true,
            message: format!("All {verified}/{total} VDF proofs verified"),
        }
    }
}

/// Verify the declaration signature in the evidence packet.
pub fn verify_declaration(evidence: &Packet) -> CheckResult {
    match &evidence.declaration {
        Some(decl) => {
            if decl.verify() {
                CheckResult {
                    name: "declaration".to_string(),
                    passed: true,
                    message: "Declaration signature valid".to_string(),
                }
            } else {
                CheckResult {
                    name: "declaration".to_string(),
                    passed: false,
                    message: "Declaration signature invalid".to_string(),
                }
            }
        }
        None => CheckResult {
            name: "declaration".to_string(),
            passed: false,
            message: "Missing declaration".to_string(),
        },
    }
}
