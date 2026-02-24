use super::{AnchorError, Proof};

pub fn verify_proof(proof: &Proof) -> Result<bool, AnchorError> {
    if proof.proof_data.is_empty() {
        return Err(AnchorError::InvalidFormat("empty proof data".into()));
    }
    if proof.anchored_hash.iter().all(|b| *b == 0) {
        return Err(AnchorError::HashMismatch);
    }
    Ok(true)
}
