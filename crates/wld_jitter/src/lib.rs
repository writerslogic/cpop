// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Proof-of-process primitive using timing jitter for human authorship verification.
//!
//! Two engines: [`PureJitter`] (HMAC-based, economic security) and
//! [`PhysJitter`] (hardware entropy, physics security). [`HybridEngine`] selects
//! the best available source with automatic fallback.
//!
//! ```rust
//! use wld_jitter::{HybridEngine, PureJitter, PhysJitter, Evidence};
//!
//! let engine = HybridEngine::new(PhysJitter::default(), PureJitter::default());
//! let secret = [0u8; 32];
//! let (jitter, evidence) = engine.sample(&secret, b"keystroke data").unwrap();
//! println!("Jitter: {}us, Physics: {}", jitter, evidence.is_phys());
//! ```
//!
//! Supports `no_std` via [`PureJitter`] with explicit timestamps. The `std` feature
//! enables [`HybridEngine`], [`PhysJitter`], and [`Session`].

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "hardware"), forbid(unsafe_code))]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
use zeroize::Zeroizing;

pub mod evidence;
pub mod model;
#[cfg(feature = "std")]
pub mod phys;
pub mod pure;
pub mod traits;

pub use evidence::{Evidence, EvidenceChain, MAX_EVIDENCE_RECORDS};
pub use model::{Anomaly, AnomalyKind, HumanModel, SequenceStats, ValidationResult};
#[cfg(feature = "std")]
pub use phys::PhysJitter;
pub use pure::PureJitter;
#[cfg(feature = "std")]
pub use traits::EntropySource;
pub use traits::JitterEngine;

/// Derive a session secret from a master key and context via HKDF-SHA256.
pub fn derive_session_secret(master_key: &[u8], context: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut output = [0u8; 32];
    hk.expand(context, &mut output)
        .expect("32 bytes is a valid output length for HKDF-SHA256");
    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PhysHash {
    pub hash: [u8; 32],
    pub entropy_bits: u8,
}

impl From<[u8; 32]> for PhysHash {
    fn from(hash: [u8; 32]) -> Self {
        Self {
            hash,
            entropy_bits: 0,
        }
    }
}

pub type Jitter = u32;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    #[cfg_attr(
        feature = "std",
        error("Insufficient entropy: required {required} bits, found {found}")
    )]
    InsufficientEntropy { required: u8, found: u8 },

    #[cfg_attr(feature = "std", error("Hardware entropy not available: {reason}"))]
    HardwareUnavailable {
        #[cfg(feature = "std")]
        reason: String,
        #[cfg(not(feature = "std"))]
        reason: &'static str,
    },

    #[cfg_attr(feature = "std", error("Invalid input: {0}"))]
    InvalidInput(
        #[cfg(feature = "std")] String,
        #[cfg(not(feature = "std"))] &'static str,
    ),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InsufficientEntropy { required, found } => {
                write!(
                    f,
                    "Insufficient entropy: required {} bits, found {}",
                    required, found
                )
            }
            Error::HardwareUnavailable { reason } => {
                write!(f, "Hardware entropy not available: {}", reason)
            }
            Error::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
        }
    }
}

/// Combines physics and pure jitter with automatic fallback (requires `std`).
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct HybridEngine<P = PhysJitter, F = PureJitter>
where
    P: EntropySource + JitterEngine,
    F: JitterEngine,
{
    phys: P,
    fallback: F,
    min_phys_entropy: u8,
}

#[cfg(feature = "std")]
impl Default for HybridEngine<PhysJitter, PureJitter> {
    fn default() -> Self {
        Self::new(PhysJitter::default(), PureJitter::default())
    }
}

#[cfg(feature = "std")]
impl<P, F> HybridEngine<P, F>
where
    P: EntropySource + JitterEngine,
    F: JitterEngine,
{
    pub fn new(phys: P, fallback: F) -> Self {
        Self {
            phys,
            fallback,
            min_phys_entropy: 8,
        }
    }

    pub fn with_min_entropy(mut self, bits: u8) -> Self {
        self.min_phys_entropy = bits;
        self
    }

    pub fn sample(&self, secret: &[u8; 32], inputs: &[u8]) -> Result<(Jitter, Evidence), Error> {
        match self.phys.sample(inputs) {
            Ok(entropy)
                if entropy.entropy_bits >= self.min_phys_entropy && self.phys.validate(entropy) =>
            {
                let jitter = self.phys.compute_jitter(secret, inputs, entropy);
                Ok((jitter, Evidence::phys(entropy, jitter)))
            }
            _ => {
                let jitter = self
                    .fallback
                    .compute_jitter(secret, inputs, [0u8; 32].into());
                Ok((jitter, Evidence::pure(jitter)))
            }
        }
    }

    pub fn phys_available(&self) -> bool {
        self.phys.sample(b"probe").is_ok()
    }
}

/// Session manager for tracking jitter evidence over a document (requires `std`).
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct Session {
    secret: Zeroizing<[u8; 32]>,
    engine: HybridEngine,
    evidence: EvidenceChain,
    model: HumanModel,
}

#[cfg(feature = "std")]
impl Session {
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            engine: HybridEngine::default(),
            evidence: EvidenceChain::with_secret(secret),
            model: HumanModel::default(),
        }
    }

    pub fn with_engine(secret: [u8; 32], engine: HybridEngine) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            engine,
            evidence: EvidenceChain::with_secret(secret),
            model: HumanModel::default(),
        }
    }

    #[cfg(feature = "rand")]
    pub fn random() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self::new(secret)
    }

    pub fn sample(&mut self, inputs: &[u8]) -> Result<Jitter, Error> {
        let (jitter, evidence) = self.engine.sample(&self.secret, inputs)?;
        self.evidence.append(evidence);
        Ok(jitter)
    }

    pub fn evidence(&self) -> &EvidenceChain {
        &self.evidence
    }

    pub fn validate(&self) -> ValidationResult {
        let jitters: Vec<Jitter> = self.evidence.records.iter().map(|e| e.jitter()).collect();
        self.model.validate(&jitters)
    }

    pub fn phys_ratio(&self) -> f64 {
        self.evidence.phys_ratio()
    }

    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.evidence)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_engine_default() {
        let engine = HybridEngine::default();
        let secret = [42u8; 32];
        let inputs = b"test input";

        let result = engine.sample(&secret, inputs);
        assert!(result.is_ok());

        let (jitter, evidence) = result.unwrap();
        assert!(jitter >= 500);
        assert!(jitter < 3000);
        assert!(evidence.jitter() == jitter);
    }

    #[test]
    fn test_session_workflow() {
        let secret = [1u8; 32];
        let mut session = Session::new(secret);

        for i in 0..30 {
            let input = format!("keystroke {}", i);
            let jitter = session.sample(input.as_bytes()).unwrap();
            assert!(jitter >= 500);
        }

        assert_eq!(session.evidence().records.len(), 30);
        let validation = session.validate();
        println!("Validation: {:?}", validation);
    }

    #[test]
    fn test_evidence_serialization() {
        let secret = [2u8; 32];
        let mut session = Session::new(secret);

        for i in 0..10 {
            session.sample(format!("key{}", i).as_bytes()).unwrap();
        }

        let json = session.export_json().unwrap();
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"records\""));
    }

    #[test]
    fn test_pure_jitter_determinism() {
        let engine = PureJitter::default();
        let secret = [99u8; 32];
        let inputs = b"deterministic test";
        let entropy: PhysHash = [0u8; 32].into();

        let j1 = engine.compute_jitter(&secret, inputs, entropy);
        let j2 = engine.compute_jitter(&secret, inputs, entropy);

        assert_eq!(j1, j2, "Pure jitter should be deterministic");
    }

    #[test]
    fn test_empty_inputs() {
        let engine = HybridEngine::default();
        let secret = [42u8; 32];

        let result = engine.sample(&secret, b"");
        assert!(result.is_ok());
    }

    #[test]
    fn test_large_inputs() {
        let engine = HybridEngine::default();
        let secret = [42u8; 32];
        let large_input = vec![0u8; 10000];
        let result = engine.sample(&secret, &large_input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_min_phys_entropy_enforced() {
        let engine = HybridEngine::default().with_min_entropy(255);
        let secret = [42u8; 32];

        let (_, evidence) = engine.sample(&secret, b"test").unwrap();
        assert!(
            !evidence.is_phys(),
            "Should have fallen back to pure jitter"
        );
    }
}

#[cfg(test)]
mod no_std_compatible_tests {
    use super::*;

    #[test]
    fn test_pure_jitter_determinism_no_std() {
        let engine = PureJitter::default();
        let secret = [99u8; 32];
        let inputs = b"deterministic test";
        let entropy: PhysHash = [0u8; 32].into();

        let j1 = engine.compute_jitter(&secret, inputs, entropy);
        let j2 = engine.compute_jitter(&secret, inputs, entropy);

        assert_eq!(j1, j2, "Pure jitter should be deterministic");
    }

    #[test]
    fn test_phys_hash_from_array() {
        let hash: PhysHash = [42u8; 32].into();
        assert_eq!(hash.entropy_bits, 0);
        assert_eq!(hash.hash, [42u8; 32]);
    }

    #[test]
    fn test_derive_session_secret() {
        let master = [1u8; 32];
        let secret1 = derive_session_secret(&master, b"context1");
        let secret2 = derive_session_secret(&master, b"context2");
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_evidence_with_timestamp() {
        let evidence = Evidence::pure_with_timestamp(1500, 12345);
        assert_eq!(evidence.jitter(), 1500);
        assert_eq!(evidence.timestamp_us(), 12345);
        assert!(!evidence.is_phys());

        let phys_hash: PhysHash = [1u8; 32].into();
        let phys_evidence = Evidence::phys_with_timestamp(phys_hash, 2000, 67890);
        assert_eq!(phys_evidence.jitter(), 2000);
        assert_eq!(phys_evidence.timestamp_us(), 67890);
        assert!(phys_evidence.is_phys());
    }
}
