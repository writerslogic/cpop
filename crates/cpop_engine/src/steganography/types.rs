// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};

/// Zero-width characters used for encoding (2 bits each).
pub(super) const ZWC_ALPHABET: [char; 4] = [
    '\u{200B}', // ZERO WIDTH SPACE        → 0b00
    '\u{200C}', // ZERO WIDTH NON-JOINER   → 0b01
    '\u{200D}', // ZERO WIDTH JOINER       → 0b10
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SP  → 0b11
];

/// Default number of ZWC characters to embed (2 bits each → 64-bit tag).
pub(super) const DEFAULT_ZWC_COUNT: usize = 32;

/// Domain separation string for the watermark HMAC.
pub(super) const DST_WATERMARK: &[u8] = b"witnessd-stego-watermark-v1";

/// Domain separation string for the position PRNG seed.
pub(super) const DST_POSITIONS: &[u8] = b"witnessd-stego-positions-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZwcParams {
    /// Number of ZWC characters to embed (default: 32 → 64-bit tag).
    pub zwc_count: usize,
    pub min_word_count: usize,
}

impl Default for ZwcParams {
    fn default() -> Self {
        Self {
            zwc_count: DEFAULT_ZWC_COUNT,
            min_word_count: 64,
        }
    }
}

/// A steganographic binding between a document and its evidence chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZwcBinding {
    /// Truncated HMAC tag encoded as ZWCs (hex for serialization).
    pub tag_hex: String,
    /// Number of ZWC characters embedded.
    pub zwc_count: usize,
    /// SHA-256 hash of the document text (before embedding).
    pub document_hash: String,
    /// MMR root hash that the watermark is bound to.
    pub mmr_root: String,
    /// Word boundary indices where ZWCs were placed.
    pub positions: Vec<usize>,
}

/// Result of verifying a steganographic watermark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZwcVerification {
    /// Whether the extracted tag matches the expected tag.
    pub valid: bool,
    /// Number of ZWC characters found.
    pub zwc_found: usize,
    /// Number of ZWC characters expected.
    pub zwc_expected: usize,
    /// The extracted tag (hex).
    pub extracted_tag: String,
    /// The expected tag (hex, if MMR root was provided).
    pub expected_tag: Option<String>,
}
