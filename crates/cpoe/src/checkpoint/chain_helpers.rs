// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Helper functions for checkpoint chain operations.

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use authorproof_protocol::rfc::wire_types::components::DocumentRef;
use authorproof_protocol::rfc::wire_types::hash::HashValue;

/// Domain separation tag for genesis prev-hash computation.
const GENESIS_DST: &[u8] = b"witnessd-genesis-v1";

/// Domain separation tag for physics seed mixing.
const PHYSICS_MIX_DST: &[u8] = b"witnessd-physics-mix-v1";

/// Compute the genesis checkpoint prev-hash per draft-condrey-rats-pop
/// (https://datatracker.ietf.org/doc/draft-condrey-rats-pop/):
/// `prev_hash = SHA-256(DST || CBOR-encode(document-ref))`.
///
/// For the genesis (ordinal-0) checkpoint, instead of all-zeros the
/// previous hash is bound to the initial document state.
///
/// `char_count` is the actual UTF-8 character count of the document content.
/// When `None`, falls back to `content_size` (byte length). Callers should
/// provide the real character count for interoperability with other
/// implementations of the spec, where `char_count` (CBOR key 4) is defined
/// as the number of Unicode scalar values, not bytes.
pub(crate) fn genesis_prev_hash(
    content_hash: [u8; 32],
    content_size: u64,
    document_path: &str,
    char_count: Option<u64>,
) -> Result<[u8; 32]> {
    let filename = std::path::Path::new(document_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string());

    let doc_ref = DocumentRef {
        content_hash: HashValue::try_sha256(content_hash.to_vec()).map_err(Error::checkpoint)?,
        filename,
        byte_length: content_size,
        char_count: char_count.unwrap_or(content_size),
        salt_mode: None,
        salt_commitment: None,
    };

    let cbor_bytes = authorproof_protocol::codec::cbor::encode(&doc_ref)
        .map_err(|e| Error::checkpoint(format!("genesis CBOR encode: {e}")))?;

    let mut hasher = Sha256::new();
    hasher.update(GENESIS_DST);
    hasher.update(&cbor_bytes);
    Ok(hasher.finalize().into())
}

/// Mix an optional physics seed into a base VDF input, binding the chain
/// state to the physical context.
pub(crate) fn mix_physics_seed(base_input: [u8; 32], physics_seed: Option<[u8; 32]>) -> [u8; 32] {
    if let Some(seed) = physics_seed {
        let mut hasher = Sha256::new();
        hasher.update(PHYSICS_MIX_DST);
        hasher.update(base_input);
        hasher.update(seed);
        hasher.finalize().into()
    } else {
        base_input
    }
}
