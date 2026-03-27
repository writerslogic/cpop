// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::types::{ZwcBinding, ZwcParams, DST_POSITIONS, DST_WATERMARK, ZWC_ALPHABET};
use crate::error::{Error, Result};

/// Embed zero-width character watermarks into document text.
pub struct ZwcEmbedder {
    params: ZwcParams,
}

impl ZwcEmbedder {
    /// Create an embedder with the given parameters.
    pub fn new(params: ZwcParams) -> Self {
        Self { params }
    }

    /// Embed a ZWC watermark into document text, returning watermarked text and binding.
    pub fn embed(
        &self,
        text: &str,
        mmr_root: &[u8; 32],
        key: &[u8; 32],
    ) -> Result<(String, ZwcBinding)> {
        let word_boundaries = find_word_boundaries(text);
        if word_boundaries.len() < self.params.min_word_count {
            return Err(Error::validation(format!(
                "document has {} words, minimum {} required for steganographic embedding",
                word_boundaries.len(),
                self.params.min_word_count
            )));
        }

        let doc_hash = sha2_hash(text.as_bytes());
        let tag = compute_watermark_tag(key, mmr_root, &doc_hash, self.params.zwc_count);
        let positions = compute_positions(
            &doc_hash,
            mmr_root,
            word_boundaries.len(),
            self.params.zwc_count,
        );

        let mut result = String::with_capacity(text.len() + self.params.zwc_count * 3);
        let mut tag_idx = 0;
        let mut boundary_idx = 0;
        let mut last_pos = 0;

        let mut sorted_positions: Vec<usize> = positions.clone();
        sorted_positions.sort_unstable();
        let mut pos_iter = sorted_positions.iter().peekable();

        for (byte_offset, _) in text.char_indices() {
            while boundary_idx < word_boundaries.len()
                && word_boundaries[boundary_idx] < byte_offset
            {
                boundary_idx += 1;
            }

            if boundary_idx < word_boundaries.len() && word_boundaries[boundary_idx] == byte_offset
            {
                if let Some(&&pos) = pos_iter.peek() {
                    if pos == boundary_idx && tag_idx < tag.len() {
                        result.push_str(&text[last_pos..byte_offset]);
                        result.push(ZWC_ALPHABET[tag[tag_idx] as usize]);
                        last_pos = byte_offset;
                        tag_idx += 1;
                        pos_iter.next();
                    }
                }
            }
        }
        result.push_str(&text[last_pos..]);

        let binding = ZwcBinding {
            tag_hex: hex::encode(&tag),
            zwc_count: self.params.zwc_count,
            document_hash: hex::encode(doc_hash),
            mmr_root: hex::encode(mmr_root),
            positions: sorted_positions,
        };

        Ok((result, binding))
    }
}

/// Counter-based HMAC-SHA256 expansion for watermark tags.
///
/// AUD-148: Uses counter-mode HMAC to generate unique bytes for any zwc_count,
/// preventing the tag repetition that occurred with the old modular indexing.
pub(super) fn compute_watermark_tag(
    key: &[u8; 32],
    mmr_root: &[u8; 32],
    doc_hash: &[u8; 32],
    zwc_count: usize,
) -> Vec<u8> {
    // Generate enough HMAC blocks to cover all ZWCs (4 ZWCs per byte, 32 bytes per block)
    let bytes_needed = zwc_count / 4 + 1;
    let mut expanded = Vec::with_capacity(bytes_needed);
    let mut counter: u32 = 0;
    while expanded.len() < bytes_needed {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        mac.update(DST_WATERMARK);
        mac.update(mmr_root);
        mac.update(doc_hash);
        mac.update(&counter.to_be_bytes());
        let block = mac.finalize().into_bytes();
        expanded.extend_from_slice(&block);
        counter += 1;
    }

    let mut tag = Vec::with_capacity(zwc_count);
    for i in 0..zwc_count {
        let byte_idx = i / 4;
        let bit_offset = (i % 4) * 2;
        let two_bits = (expanded[byte_idx] >> bit_offset) & 0x03;
        tag.push(two_bits);
    }

    tag
}

/// Compute deterministic word-boundary positions for ZWC placement.
///
/// Uses HMAC-SHA256(doc_hash || mmr_root, DST_POSITIONS) as PRNG seed,
/// then Fisher-Yates partial shuffle to select `count` unique positions.
pub(super) fn compute_positions(
    doc_hash: &[u8; 32],
    mmr_root: &[u8; 32],
    num_boundaries: usize,
    count: usize,
) -> Vec<usize> {
    let count = count.min(num_boundaries);
    if count == 0 {
        return Vec::new();
    }

    let mut mac =
        Hmac::<Sha256>::new_from_slice(doc_hash).expect("HMAC-SHA256 accepts any key length");
    mac.update(DST_POSITIONS);
    mac.update(mmr_root);
    let initial = mac.finalize().into_bytes();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&initial);

    let mut indices: Vec<usize> = (0..num_boundaries).collect();
    let mut seed_offset = 0;

    for i in 0..count {
        let remaining = num_boundaries - i;
        let rand_bytes = [
            seed[seed_offset],
            seed[seed_offset + 1],
            seed[seed_offset + 2],
            seed[seed_offset + 3],
        ];
        let rand_val = u32::from_le_bytes(rand_bytes) as usize;
        let j = i + (rand_val % remaining);

        indices.swap(i, j);
        seed_offset += 4;

        if seed_offset + 4 > 32 {
            let mut mac2 =
                Hmac::<Sha256>::new_from_slice(&seed).expect("HMAC-SHA256 accepts any key length");
            mac2.update(&(i as u64).to_le_bytes());
            let new = mac2.finalize().into_bytes();
            seed.copy_from_slice(&new);
            seed_offset = 0;
        }
    }

    indices[..count].to_vec()
}

/// Byte offsets just before each word start.
pub(super) fn find_word_boundaries(text: &str) -> Vec<usize> {
    let mut boundaries = Vec::new();
    let mut in_word = false;

    for (idx, ch) in text.char_indices() {
        if ch.is_alphanumeric() {
            if !in_word {
                boundaries.push(idx);
                in_word = true;
            }
        } else {
            in_word = false;
        }
    }

    boundaries
}

fn sha2_hash(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
