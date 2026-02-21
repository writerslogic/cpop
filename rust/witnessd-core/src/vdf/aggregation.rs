//! VDF Proof Aggregation
//!
//! This module implements VDF proof aggregation as defined in the witnessd RFC.
//! Aggregation enables O(1) or O(log n) verification of entire checkpoint chains
//! that would otherwise require O(n) sequential VDF recomputation.
//!
//! # Aggregation Methods
//!
//! - **Merkle VDF Tree**: O(log n) verification via Merkle inclusion proofs
//! - **SNARK**: O(1) verification using succinct proofs (requires trusted setup)
//! - **STARK**: O(log n) verification without trusted setup
//!
//! # Security Model
//!
//! Aggregation provides a trade-off between verification efficiency and trust:
//! - Full VDF recomputation: Zero trust required, O(n) time
//! - Merkle + sampling: Statistical trust, O(k log n) time
//! - SNARK: Trusted setup required, O(1) time

use serde::{Deserialize, Serialize};

/// Method used for VDF aggregation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationMethod {
    /// Merkle tree over VDF outputs
    MerkleVdfTree,
    /// Groth16 SNARK proof
    SnarkGroth16,
    /// PLONK SNARK proof
    SnarkPlonk,
    /// STARK proof
    Stark,
    /// Recursive SNARK composition
    RecursiveSnark,
}

/// SNARK proof scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnarkScheme {
    /// Groth16 on BN254 curve
    Groth16Bn254,
    /// Groth16 on BLS12-381 curve
    Groth16Bls12381,
    /// PLONK on BN254 curve
    PlonkBn254,
    /// PLONK on BLS12-381 curve
    PlonkBls12381,
}

/// Metadata about the aggregation proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateMetadata {
    /// Version of the prover used
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prover_version: Option<String>,

    /// Time taken to generate proof (milliseconds)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_generation_time_ms: Option<u64>,

    /// Size of the proof in bytes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_size_bytes: Option<u32>,

    /// Identifier for verification key (if not included)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_key_id: Option<String>,

    /// Full verification key (if not well-known)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_key: Option<Vec<u8>>,
}

/// Sample from Merkle tree with proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleSample {
    /// Index of the checkpoint sampled
    pub checkpoint_index: u32,

    /// Merkle proof path (hashes from leaf to root)
    pub merkle_path: Vec<String>,

    /// Whether the VDF was verified by the aggregator
    pub vdf_verified: bool,
}

/// Merkle VDF tree proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleVdfProof {
    /// Root hash of the Merkle tree
    pub root_hash: String,

    /// Total iterations across all checkpoints
    pub total_iterations: u64,

    /// Number of checkpoints covered
    pub checkpoint_count: u32,

    /// Sampled proofs (for probabilistic verification)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sampled_proofs: Vec<MerkleSample>,

    /// Signature from aggregator (optional trusted party)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregator_signature: Option<String>,
}

/// SNARK VDF proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnarkVdfProof {
    /// SNARK scheme used
    pub scheme: SnarkScheme,

    /// The proof bytes
    pub proof_bytes: Vec<u8>,

    /// Verification key (ID or full key)
    pub verification_key: String,

    /// Public inputs to the circuit
    pub public_inputs: Vec<Vec<u8>>,

    /// Circuit version (for compatibility checking)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_version: Option<String>,

    /// Hash of the trusted setup ceremony (for auditability)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_ceremony_hash: Option<Vec<u8>>,
}

/// VDF aggregate proof (polymorphic over method)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdfAggregateProof {
    /// Number of checkpoints covered by this proof
    pub checkpoints_covered: u32,

    /// Aggregation method used
    pub method: AggregationMethod,

    /// The actual proof data (serialized)
    pub aggregate_proof: Vec<u8>,

    /// Metadata about proof generation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AggregateMetadata>,
}

impl VdfAggregateProof {
    /// Create a Merkle-based aggregate proof
    pub fn from_merkle(proof: MerkleVdfProof) -> Result<Self, serde_json::Error> {
        let proof_bytes = serde_json::to_vec(&proof)?;
        Ok(Self {
            checkpoints_covered: proof.checkpoint_count,
            method: AggregationMethod::MerkleVdfTree,
            aggregate_proof: proof_bytes,
            metadata: None,
        })
    }

    /// Create a SNARK-based aggregate proof
    pub fn from_snark(
        proof: SnarkVdfProof,
        checkpoint_count: u32,
    ) -> Result<Self, serde_json::Error> {
        let method = match proof.scheme {
            SnarkScheme::Groth16Bn254 | SnarkScheme::Groth16Bls12381 => {
                AggregationMethod::SnarkGroth16
            }
            SnarkScheme::PlonkBn254 | SnarkScheme::PlonkBls12381 => AggregationMethod::SnarkPlonk,
        };
        let proof_bytes = serde_json::to_vec(&proof)?;
        Ok(Self {
            checkpoints_covered: checkpoint_count,
            method,
            aggregate_proof: proof_bytes,
            metadata: None,
        })
    }

    /// Add metadata to the proof
    pub fn with_metadata(mut self, metadata: AggregateMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Extract Merkle proof (if applicable)
    pub fn as_merkle(&self) -> Result<MerkleVdfProof, AggregateError> {
        if self.method != AggregationMethod::MerkleVdfTree {
            return Err(AggregateError::WrongMethod);
        }
        serde_json::from_slice(&self.aggregate_proof)
            .map_err(|_| AggregateError::DeserializationError)
    }

    /// Extract SNARK proof (if applicable)
    pub fn as_snark(&self) -> Result<SnarkVdfProof, AggregateError> {
        match self.method {
            AggregationMethod::SnarkGroth16 | AggregationMethod::SnarkPlonk => {
                serde_json::from_slice(&self.aggregate_proof)
                    .map_err(|_| AggregateError::DeserializationError)
            }
            _ => Err(AggregateError::WrongMethod),
        }
    }

    /// Get verification complexity description
    pub fn verification_complexity(&self) -> &'static str {
        match self.method {
            AggregationMethod::MerkleVdfTree => "O(k * log n) where k = samples",
            AggregationMethod::SnarkGroth16 => "O(1) constant time",
            AggregationMethod::SnarkPlonk => "O(1) constant time",
            AggregationMethod::Stark => "O(log n) polylogarithmic",
            AggregationMethod::RecursiveSnark => "O(1) constant time",
        }
    }

    /// Check if this method requires trusted setup
    pub fn requires_trusted_setup(&self) -> bool {
        matches!(
            self.method,
            AggregationMethod::SnarkGroth16 | AggregationMethod::RecursiveSnark
        )
    }
}

/// Errors for aggregate proof operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregateError {
    /// Attempted to extract wrong proof type
    WrongMethod,
    /// Proof deserialization failed
    DeserializationError,
    /// Verification failed
    VerificationFailed,
    /// Invalid Merkle path
    InvalidMerklePath,
    /// SNARK verification key not found
    MissingVerificationKey,
}

impl std::fmt::Display for AggregateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongMethod => write!(f, "Attempted to extract wrong proof type"),
            Self::DeserializationError => write!(f, "Failed to deserialize proof"),
            Self::VerificationFailed => write!(f, "Proof verification failed"),
            Self::InvalidMerklePath => write!(f, "Invalid Merkle path"),
            Self::MissingVerificationKey => write!(f, "Verification key not found"),
        }
    }
}

impl std::error::Error for AggregateError {}

/// Builder for creating Merkle VDF proofs
pub struct MerkleVdfBuilder {
    leaf_hashes: Vec<String>,
    total_iterations: u64,
}

impl MerkleVdfBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            leaf_hashes: Vec::new(),
            total_iterations: 0,
        }
    }

    /// Add a VDF proof to the tree
    ///
    /// The leaf hash should be H(VDF_input || VDF_output || iterations)
    pub fn add_vdf(&mut self, leaf_hash: String, iterations: u64) {
        self.leaf_hashes.push(leaf_hash);
        self.total_iterations += iterations;
    }

    /// Build the Merkle tree and return the proof
    pub fn build(self) -> MerkleVdfProof {
        let root_hash = self.compute_merkle_root();
        MerkleVdfProof {
            root_hash,
            total_iterations: self.total_iterations,
            checkpoint_count: self.leaf_hashes.len() as u32,
            sampled_proofs: Vec::new(),
            aggregator_signature: None,
        }
    }

    /// Compute Merkle root from leaf hashes
    fn compute_merkle_root(&self) -> String {
        if self.leaf_hashes.is_empty() {
            return String::new();
        }

        if self.leaf_hashes.len() == 1 {
            return self.leaf_hashes[0].clone();
        }

        // Simple Merkle tree computation
        let mut level = self.leaf_hashes.clone();
        while level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    format!("{}{}", chunk[0], chunk[1])
                } else {
                    chunk[0].clone()
                };
                // In production, use SHA-256 here
                let hash = format!("H({})", combined);
                next_level.push(hash);
            }
            level = next_level;
        }

        level.pop().unwrap_or_default()
    }
}

impl Default for MerkleVdfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Verification mode for aggregate proofs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMode {
    /// Recompute all VDFs - maximum assurance
    Full,
    /// Randomly sample and verify k proofs
    Sampled { sample_count: u32 },
    /// Trust the aggregator, verify signature only
    TrustedAggregator,
    /// Verify SNARK proof only
    SnarkOnly,
}

impl VerificationMode {
    /// Get trust assumptions for this mode
    pub fn trust_assumptions(&self) -> &'static str {
        match self {
            Self::Full => "None - cryptographically verified",
            Self::Sampled { .. } => "Statistical - high probability all VDFs valid",
            Self::TrustedAggregator => "Trusted aggregator - rely on third party",
            Self::SnarkOnly => "Trusted setup ceremony - cryptographic assumptions",
        }
    }

    /// Suggested use case for this mode
    pub fn suggested_use_case(&self) -> &'static str {
        match self {
            Self::Full => "Litigation, forensics, maximum assurance",
            Self::Sampled { .. } => "Academic review, publication verification",
            Self::TrustedAggregator => "Real-time display, low-stakes checks",
            Self::SnarkOnly => "High-volume processing, enterprise verification",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_builder() {
        let mut builder = MerkleVdfBuilder::new();
        builder.add_vdf("leaf1".to_string(), 1000);
        builder.add_vdf("leaf2".to_string(), 2000);
        builder.add_vdf("leaf3".to_string(), 3000);

        let proof = builder.build();
        assert_eq!(proof.checkpoint_count, 3);
        assert_eq!(proof.total_iterations, 6000);
        assert!(!proof.root_hash.is_empty());
    }

    #[test]
    fn test_aggregate_from_merkle() {
        let merkle = MerkleVdfProof {
            root_hash: "root".to_string(),
            total_iterations: 1000,
            checkpoint_count: 5,
            sampled_proofs: vec![],
            aggregator_signature: None,
        };

        let aggregate = VdfAggregateProof::from_merkle(merkle).unwrap();
        assert_eq!(aggregate.method, AggregationMethod::MerkleVdfTree);
        assert_eq!(aggregate.checkpoints_covered, 5);
    }

    #[test]
    fn test_aggregate_roundtrip() {
        let merkle = MerkleVdfProof {
            root_hash: "test_root".to_string(),
            total_iterations: 5000,
            checkpoint_count: 10,
            sampled_proofs: vec![MerkleSample {
                checkpoint_index: 3,
                merkle_path: vec!["h1".to_string(), "h2".to_string()],
                vdf_verified: true,
            }],
            aggregator_signature: Some("sig".to_string()),
        };

        let aggregate = VdfAggregateProof::from_merkle(merkle.clone()).unwrap();
        let extracted = aggregate.as_merkle().unwrap();

        assert_eq!(extracted.root_hash, merkle.root_hash);
        assert_eq!(extracted.total_iterations, merkle.total_iterations);
    }

    #[test]
    fn test_wrong_method_error() {
        let merkle = MerkleVdfProof {
            root_hash: "root".to_string(),
            total_iterations: 100,
            checkpoint_count: 1,
            sampled_proofs: vec![],
            aggregator_signature: None,
        };

        let aggregate = VdfAggregateProof::from_merkle(merkle).unwrap();
        let result = aggregate.as_snark();
        assert_eq!(result.unwrap_err(), AggregateError::WrongMethod);
    }

    #[test]
    fn test_verification_mode_metadata() {
        let full = VerificationMode::Full;
        assert!(full.trust_assumptions().contains("None"));

        let sampled = VerificationMode::Sampled { sample_count: 10 };
        assert!(sampled.trust_assumptions().contains("Statistical"));
    }

    #[test]
    fn test_trusted_setup_check() {
        let snark = VdfAggregateProof {
            checkpoints_covered: 10,
            method: AggregationMethod::SnarkGroth16,
            aggregate_proof: vec![],
            metadata: None,
        };
        assert!(snark.requires_trusted_setup());

        let merkle = VdfAggregateProof {
            checkpoints_covered: 10,
            method: AggregationMethod::MerkleVdfTree,
            aggregate_proof: vec![],
            metadata: None,
        };
        assert!(!merkle.requires_trusted_setup());
    }

    #[test]
    fn test_serialization() {
        let proof = VdfAggregateProof {
            checkpoints_covered: 50,
            method: AggregationMethod::Stark,
            aggregate_proof: vec![1, 2, 3],
            metadata: Some(AggregateMetadata {
                prover_version: Some("1.0".to_string()),
                proof_generation_time_ms: Some(5000),
                proof_size_bytes: Some(1024),
                verification_key_id: None,
                verification_key: None,
            }),
        };

        let json = serde_json::to_string(&proof).unwrap();
        let parsed: VdfAggregateProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.method, AggregationMethod::Stark);
    }
}
