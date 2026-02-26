// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! WebAssembly bindings for pop-crate.
//!
//! Exports verification and forensic analysis logic for use in Cloudflare
//! Workers via wasm-bindgen.
//!
//! Build with: wasm-pack build --target web --features wasm

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use crate::evidence::PoPVerifier;
#[cfg(feature = "wasm")]
use crate::forensics::{ForensicVerdict, ForensicsEngine};
#[cfg(feature = "wasm")]
use ed25519_dalek::VerifyingKey;

/// Result of PoP evidence verification with forensic analysis, returned to JavaScript.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct VerificationResult {
    is_valid: bool,
    forensic_verdict: String,
    checkpoint_count: u32,
    chain_duration_secs: u64,
    coefficient_of_variation: f64,
    hurst_exponent: f64,    // -1.0 if not computed
    linearity_score: f64,   // -1.0 if not computed
    error_message: String,
    explanation: String,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl VerificationResult {
    #[wasm_bindgen(getter)]
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    #[wasm_bindgen(getter)]
    pub fn forensic_verdict(&self) -> String {
        self.forensic_verdict.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn checkpoint_count(&self) -> u32 {
        self.checkpoint_count
    }

    #[wasm_bindgen(getter)]
    pub fn chain_duration_secs(&self) -> u64 {
        self.chain_duration_secs
    }

    #[wasm_bindgen(getter)]
    pub fn coefficient_of_variation(&self) -> f64 {
        self.coefficient_of_variation
    }

    #[wasm_bindgen(getter)]
    pub fn hurst_exponent(&self) -> f64 {
        self.hurst_exponent
    }

    #[wasm_bindgen(getter)]
    pub fn linearity_score(&self) -> f64 {
        self.linearity_score
    }

    #[wasm_bindgen(getter)]
    pub fn error_message(&self) -> String {
        self.error_message.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn explanation(&self) -> String {
        self.explanation.clone()
    }
}

/// Verify a COSE-signed PoP evidence packet and run forensic analysis.
///
/// This is the main entry point called from the Cloudflare Worker.
/// It performs:
/// 1. COSE_Sign1 Ed25519 signature verification
/// 2. CBOR tag validation (0x434F5050)
/// 3. Causality chain (HMAC) verification
/// 4. Adversarial Collapse detection (timing uniformity)
/// 5. δ-Analysis (Coefficient of Variation)
/// 6. Hurst exponent estimation (if enough data)
///
/// # Arguments
/// * `evidence_bytes` - Raw COSE_Sign1 bytes from the pop-crate client
/// * `public_key_bytes` - 32-byte Ed25519 public key of the signer
///
/// # Returns
/// A `VerificationResult` with forensic verdict V1–V5 and analysis metrics.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_pop_evidence(evidence_bytes: &[u8], public_key_bytes: &[u8]) -> VerificationResult {
    // Parse the Ed25519 public key
    let key_bytes: [u8; 32] = match public_key_bytes.try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            return VerificationResult {
                is_valid: false,
                forensic_verdict: ForensicVerdict::V5ConfirmedForgery.as_str().to_string(),
                checkpoint_count: 0,
                chain_duration_secs: 0,
                coefficient_of_variation: 0.0,
                hurst_exponent: -1.0,
                linearity_score: -1.0,
                error_message: "Public key must be exactly 32 bytes".to_string(),
                explanation: String::new(),
            };
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        Err(e) => {
            return VerificationResult {
                is_valid: false,
                forensic_verdict: ForensicVerdict::V5ConfirmedForgery.as_str().to_string(),
                checkpoint_count: 0,
                chain_duration_secs: 0,
                coefficient_of_variation: 0.0,
                hurst_exponent: -1.0,
                linearity_score: -1.0,
                error_message: format!("Invalid public key: {}", e),
                explanation: String::new(),
            };
        }
    };

    let verifier = PoPVerifier::new(verifying_key);

    // Step 1: Cryptographic verification (COSE + causality chain)
    match verifier.verify(evidence_bytes) {
        Ok(packet) => {
            // Step 2: Forensic analysis on the verified packet
            let timestamps: Vec<u64> = std::iter::once(packet.created)
                .chain(packet.checkpoints.iter().map(|cp| cp.timestamp))
                .collect();

            let engine = ForensicsEngine::from_timestamps(&timestamps, true);
            let analysis = engine.analyze();

            VerificationResult {
                is_valid: analysis.verdict.is_verified(),
                forensic_verdict: analysis.verdict.as_str().to_string(),
                checkpoint_count: analysis.checkpoint_count as u32,
                chain_duration_secs: analysis.chain_duration_secs,
                coefficient_of_variation: analysis.coefficient_of_variation,
                hurst_exponent: analysis.hurst_exponent.unwrap_or(-1.0),
                linearity_score: analysis.linearity_score.unwrap_or(-1.0),
                error_message: String::new(),
                explanation: analysis.explanation,
            }
        }
        Err(e) => {
            // Map crypto/chain errors to forensic verdicts
            let verdict = match &e {
                crate::error::Error::Validation(msg) if msg.contains("Adversarial collapse") => {
                    ForensicVerdict::V4LikelySynthetic
                }
                crate::error::Error::Validation(msg) if msg.contains("Temporal anomaly") => {
                    ForensicVerdict::V3Suspicious
                }
                crate::error::Error::Validation(msg) if msg.contains("Causality chain") => {
                    ForensicVerdict::V5ConfirmedForgery
                }
                crate::error::Error::Crypto(_) => ForensicVerdict::V5ConfirmedForgery,
                _ => ForensicVerdict::V3Suspicious,
            };

            VerificationResult {
                is_valid: false,
                forensic_verdict: verdict.as_str().to_string(),
                checkpoint_count: 0,
                chain_duration_secs: 0,
                coefficient_of_variation: 0.0,
                hurst_exponent: -1.0,
                linearity_score: -1.0,
                error_message: e.to_string(),
                explanation: format!("Verification failed: {}", e),
            }
        }
    }
}
