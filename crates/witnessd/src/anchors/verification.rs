// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::{AnchorError, Proof};

/// Check structural validity (non-empty data, non-zero hash).
///
/// Does NOT verify cryptographic proof against the anchor provider.
pub fn verify_proof_format(proof: &Proof) -> Result<bool, AnchorError> {
    if proof.proof_data.is_empty() {
        return Err(AnchorError::InvalidFormat("empty proof data".into()));
    }
    if proof.anchored_hash.iter().all(|b| *b == 0) {
        return Err(AnchorError::HashMismatch);
    }
    Ok(true)
}
