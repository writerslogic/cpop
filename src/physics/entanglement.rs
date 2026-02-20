use crate::vdf;
use crate::PhysicalContext;
use crate::VdfProof;
use sha2::Digest;
use std::time::Duration;

/// Entangles physical landscape noise with the Arrow of Time.
/// This creates a non-repudiable anchor that Root cannot forge offline.
pub struct Entanglement;

impl Entanglement {
    /// Creates a checkpoint seed by binding the physical context to the content hash.
    pub fn create_seed(content_hash: [u8; 32], physics: &PhysicalContext) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"witnessd-entanglement-v1");
        sha2::Digest::update(&mut hasher, content_hash);
        sha2::Digest::update(&mut hasher, physics.combined_hash);

        let result = sha2::Digest::finalize(hasher);
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Performs the "Work" of entanglement.
    /// This proves that the document state existed on THIS silicon for AT LEAST the target duration.
    pub fn entangle(seed: [u8; 32], duration: Duration) -> Result<VdfProof, String> {
        vdf::compute(seed, duration, vdf::default_parameters())
    }
}
