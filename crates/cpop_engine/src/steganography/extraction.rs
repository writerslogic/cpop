// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use subtle::ConstantTimeEq;

use super::embedding::compute_watermark_tag;
use super::types::{ZwcBinding, ZwcParams, ZwcVerification, ZWC_ALPHABET};

/// Extracts and verifies zero-width character watermarks from document text.
pub struct ZwcExtractor {
    params: ZwcParams,
}

impl ZwcExtractor {
    /// Create an extractor with the given parameters.
    pub fn new(params: ZwcParams) -> Self {
        Self { params }
    }

    /// Strip all ZWC characters from text, returning clean text.
    pub fn strip_zwc(text: &str) -> String {
        text.chars().filter(|c| !ZWC_ALPHABET.contains(c)).collect()
    }

    /// Extract the steganographic tag from watermarked text.
    ///
    /// Returns the 2-bit values in document order.
    pub fn extract_tag(&self, watermarked_text: &str) -> Vec<u8> {
        watermarked_text
            .chars()
            .filter_map(|c| {
                ZWC_ALPHABET
                    .iter()
                    .position(|&zwc| zwc == c)
                    .map(|pos| pos as u8)
            })
            .collect()
    }

    /// Verify a watermark against a known MMR root and HMAC key.
    pub fn verify(
        &self,
        watermarked_text: &str,
        mmr_root: &[u8; 32],
        key: &[u8; 32],
    ) -> ZwcVerification {
        let extracted = self.extract_tag(watermarked_text);
        let clean_text = Self::strip_zwc(watermarked_text);
        let doc_hash = sha2_hash(clean_text.as_bytes());

        let expected = compute_watermark_tag(key, mmr_root, &doc_hash, self.params.zwc_count);

        let valid = extracted.len() == expected.len() && extracted.ct_eq(&expected).into();

        ZwcVerification {
            valid,
            zwc_found: extracted.len(),
            zwc_expected: self.params.zwc_count,
            extracted_tag: hex::encode(&extracted),
            // AUD-151: Only reveal expected tag on success to prevent forgery
            expected_tag: if valid {
                Some(hex::encode(&expected))
            } else {
                None
            },
        }
    }

    /// Verify against a stored binding record (without needing the HMAC key).
    ///
    /// Checks structural consistency: correct ZWC count, correct positions.
    pub fn verify_binding(&self, watermarked_text: &str, binding: &ZwcBinding) -> ZwcVerification {
        let extracted = self.extract_tag(watermarked_text);
        let stored_tag: Vec<u8> = match hex::decode(&binding.tag_hex) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("ZWC binding tag_hex is invalid hex: {e}");
                return ZwcVerification {
                    valid: false,
                    zwc_found: extracted.len(),
                    zwc_expected: binding.zwc_count,
                    extracted_tag: hex::encode(&extracted),
                    // AUD-151: Don't leak expected tag on failure
                    expected_tag: None,
                };
            }
        };

        let valid = extracted.len() == binding.zwc_count
            && extracted.len() == stored_tag.len()
            && extracted.ct_eq(&stored_tag).into();

        ZwcVerification {
            valid,
            zwc_found: extracted.len(),
            zwc_expected: binding.zwc_count,
            extracted_tag: hex::encode(&extracted),
            // AUD-151: Only reveal expected tag on success
            expected_tag: if valid {
                Some(binding.tag_hex.clone())
            } else {
                None
            },
        }
    }

    pub fn has_watermark(text: &str) -> bool {
        text.chars().any(|c| ZWC_ALPHABET.contains(&c))
    }

    /// Count ZWC characters in text.
    pub fn count_zwc(text: &str) -> usize {
        text.chars().filter(|c| ZWC_ALPHABET.contains(c)).count()
    }
}

fn sha2_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
