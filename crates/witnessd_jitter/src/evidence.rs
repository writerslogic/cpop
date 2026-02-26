// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Serializable evidence types for proof-of-process records.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Jitter, PhysHash};

/// Evidence of a jitter computation, serializable for storage/verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Evidence {
    /// Physics-bound evidence with hardware entropy.
    Phys {
        /// Hash of hardware entropy samples.
        phys_hash: PhysHash,
        /// Computed jitter delay in microseconds.
        jitter: Jitter,
        /// Timestamp of capture (Unix micros).
        timestamp_us: u64,
        /// Sequence number within the chain (monotonically increasing).
        #[serde(default)]
        sequence: u64,
    },
    /// Pure HMAC-based evidence (economic security).
    Pure {
        /// Computed jitter delay in microseconds.
        jitter: Jitter,
        /// Timestamp of capture (Unix micros).
        timestamp_us: u64,
        /// Sequence number within the chain (monotonically increasing).
        #[serde(default)]
        sequence: u64,
    },
}

impl Evidence {
    /// Create physics-bound evidence with sequence number.
    ///
    /// The sequence number should be set by the EvidenceChain when appending.
    /// When creating evidence directly, pass 0 and let the chain assign the correct sequence.
    #[cfg(feature = "std")]
    pub fn phys(phys_hash: PhysHash, jitter: Jitter) -> Self {
        Self::Phys {
            phys_hash,
            jitter,
            timestamp_us: current_timestamp_us(),
            sequence: 0,
        }
    }

    /// Create pure HMAC evidence with sequence number.
    ///
    /// The sequence number should be set by the EvidenceChain when appending.
    /// When creating evidence directly, pass 0 and let the chain assign the correct sequence.
    #[cfg(feature = "std")]
    pub fn pure(jitter: Jitter) -> Self {
        Self::Pure {
            jitter,
            timestamp_us: current_timestamp_us(),
            sequence: 0,
        }
    }

    /// Create pure HMAC evidence with explicit timestamp (for no_std environments).
    ///
    /// Use this when you need to provide a timestamp from an external source.
    pub fn pure_with_timestamp(jitter: Jitter, timestamp_us: u64) -> Self {
        Self::Pure {
            jitter,
            timestamp_us,
            sequence: 0,
        }
    }

    /// Create physics-bound evidence with explicit timestamp (for no_std environments).
    ///
    /// Use this when you need to provide a timestamp from an external source.
    pub fn phys_with_timestamp(phys_hash: PhysHash, jitter: Jitter, timestamp_us: u64) -> Self {
        Self::Phys {
            phys_hash,
            jitter,
            timestamp_us,
            sequence: 0,
        }
    }

    /// Get the sequence number.
    pub fn sequence(&self) -> u64 {
        match self {
            Evidence::Phys { sequence, .. } => *sequence,
            Evidence::Pure { sequence, .. } => *sequence,
        }
    }

    /// Update hasher with binary representation of evidence.
    ///
    /// Provides a stable, canonical representation for cryptographic hashing.
    /// Includes sequence number for tamper detection.
    pub fn hash_into(&self, hasher: &mut sha2::Sha256) {
        use sha2::Digest;
        match self {
            Evidence::Phys {
                phys_hash,
                jitter,
                timestamp_us,
                sequence,
            } => {
                hasher.update([0u8]); // Type tag
                hasher.update(phys_hash.hash);
                hasher.update([phys_hash.entropy_bits]);
                hasher.update(jitter.to_le_bytes());
                hasher.update(timestamp_us.to_le_bytes());
                hasher.update(sequence.to_le_bytes());
            }
            Evidence::Pure {
                jitter,
                timestamp_us,
                sequence,
            } => {
                hasher.update([1u8]); // Type tag
                hasher.update(jitter.to_le_bytes());
                hasher.update(timestamp_us.to_le_bytes());
                hasher.update(sequence.to_le_bytes());
            }
        }
    }

    /// Update HMAC with binary representation of evidence.
    ///
    /// Provides a stable, canonical representation for keyed MAC computation.
    /// Includes sequence number for tamper detection.
    pub fn hash_into_mac(&self, mac: &mut hmac::Hmac<sha2::Sha256>) {
        use hmac::Mac;
        match self {
            Evidence::Phys {
                phys_hash,
                jitter,
                timestamp_us,
                sequence,
            } => {
                mac.update(&[0u8]); // Type tag
                mac.update(&phys_hash.hash);
                mac.update(&[phys_hash.entropy_bits]);
                mac.update(&jitter.to_le_bytes());
                mac.update(&timestamp_us.to_le_bytes());
                mac.update(&sequence.to_le_bytes());
            }
            Evidence::Pure {
                jitter,
                timestamp_us,
                sequence,
            } => {
                mac.update(&[1u8]); // Type tag
                mac.update(&jitter.to_le_bytes());
                mac.update(&timestamp_us.to_le_bytes());
                mac.update(&sequence.to_le_bytes());
            }
        }
    }

    /// Get the jitter value regardless of evidence type.
    pub fn jitter(&self) -> Jitter {
        match self {
            Evidence::Phys { jitter, .. } => *jitter,
            Evidence::Pure { jitter, .. } => *jitter,
        }
    }

    /// Check if this is physics-bound evidence.
    pub fn is_phys(&self) -> bool {
        matches!(self, Evidence::Phys { .. })
    }

    /// Get timestamp in microseconds.
    pub fn timestamp_us(&self) -> u64 {
        match self {
            Evidence::Phys { timestamp_us, .. } => *timestamp_us,
            Evidence::Pure { timestamp_us, .. } => *timestamp_us,
        }
    }

    /// Recompute jitter from components and verify it matches stored value.
    ///
    /// This allows validation that a stored evidence record was correctly
    /// computed from the given secret and inputs.
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify<E: crate::JitterEngine>(
        &self,
        secret: &[u8; 32],
        inputs: &[u8],
        engine: &E,
    ) -> bool {
        use subtle::ConstantTimeEq;
        match self {
            Evidence::Phys {
                phys_hash, jitter, ..
            } => {
                let recomputed = engine.compute_jitter(secret, inputs, *phys_hash);
                recomputed.to_le_bytes().ct_eq(&jitter.to_le_bytes()).into()
            }
            Evidence::Pure { jitter, .. } => {
                let recomputed = engine.compute_jitter(secret, inputs, PhysHash::from([0u8; 32]));
                recomputed.to_le_bytes().ct_eq(&jitter.to_le_bytes()).into()
            }
        }
    }
}

/// Aggregated evidence for a session or document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChain {
    /// Version of evidence format.
    pub version: u8,
    /// Individual evidence records.
    pub records: Vec<Evidence>,
    /// HMAC of the chain for tamper detection (keyed with session secret).
    pub chain_mac: [u8; 32],
    /// Next sequence number for evidence records.
    #[serde(default)]
    next_sequence: u64,
    /// Session secret for HMAC (not serialized).
    #[serde(skip)]
    secret: Option<Zeroizing<[u8; 32]>>,
}

impl Default for EvidenceChain {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for EvidenceChain {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.records == other.records
            && self.chain_mac == other.chain_mac
    }
}

impl Eq for EvidenceChain {}

impl EvidenceChain {
    /// Create a new empty evidence chain (legacy/convenience mode, unkeyed).
    pub fn new() -> Self {
        Self {
            version: 1,
            records: Vec::new(),
            chain_mac: [0u8; 32],
            next_sequence: 0,
            secret: None,
        }
    }

    /// Create a new empty evidence chain with a secret for keyed HMAC.
    pub fn with_secret(secret: [u8; 32]) -> Self {
        Self {
            version: 1,
            records: Vec::new(),
            chain_mac: [0u8; 32],
            next_sequence: 0,
            secret: Some(Zeroizing::new(secret)),
        }
    }

    /// Append evidence and update chain MAC.
    ///
    /// The sequence number is automatically assigned based on the chain's
    /// internal counter, ensuring monotonically increasing sequence numbers.
    pub fn append(&mut self, mut evidence: Evidence) {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        // Set sequence number before hashing
        match &mut evidence {
            Evidence::Phys { sequence, .. } => *sequence = self.next_sequence,
            Evidence::Pure { sequence, .. } => *sequence = self.next_sequence,
        }
        self.next_sequence += 1;

        if let Some(secret) = &self.secret {
            // Keyed MAC for tamper evidence
            let mut mac =
                HmacSha256::new_from_slice(secret.as_ref()).expect("HMAC accepts any key size");
            mac.update(&self.chain_mac);
            evidence.hash_into_mac(&mut mac);
            let result = mac.finalize().into_bytes();
            self.chain_mac.copy_from_slice(&result);
        } else {
            // Unkeyed hash (legacy/convenience mode)
            use sha2::Digest;
            let mut hasher = Sha256::new();
            hasher.update(self.chain_mac);
            evidence.hash_into(&mut hasher);
            let result = hasher.finalize();
            self.chain_mac.copy_from_slice(&result);
        }

        self.records.push(evidence);
    }

    /// Verify the integrity of the chain using the provided secret.
    ///
    /// Recomputes the HMAC from all records and compares it to the stored chain_mac.
    /// Uses constant-time comparison to prevent timing attacks.
    ///
    /// **Note**: Empty chains (with no records) will verify successfully with any secret,
    /// as both the computed and stored MACs are initialized to zeros. Applications should
    /// check `!chain.records.is_empty()` if this behavior is undesirable.
    pub fn verify_integrity(&self, secret: &[u8; 32]) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        use subtle::ConstantTimeEq;

        type HmacSha256 = Hmac<Sha256>;

        let mut expected_mac = [0u8; 32];

        for evidence in &self.records {
            let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
            mac.update(&expected_mac);
            evidence.hash_into_mac(&mut mac);
            let result = mac.finalize().into_bytes();
            expected_mac.copy_from_slice(&result);
        }

        // Constant-time comparison
        expected_mac.ct_eq(&self.chain_mac).into()
    }

    /// Validate that timestamps are monotonically increasing.
    ///
    /// Returns `true` if all timestamps are in non-decreasing order,
    /// `false` if any timestamp goes backwards (potential manipulation).
    ///
    /// An empty chain or single-record chain is considered valid.
    pub fn validate_timestamps(&self) -> bool {
        self.records
            .windows(2)
            .all(|w| w[0].timestamp_us() <= w[1].timestamp_us())
    }

    /// Validate sequence numbers are correct (0, 1, 2, ...).
    ///
    /// Returns `true` if all sequence numbers match their position in the chain,
    /// `false` if any sequence number is out of order (potential manipulation).
    ///
    /// An empty chain is considered valid.
    pub fn validate_sequences(&self) -> bool {
        self.records
            .iter()
            .enumerate()
            .all(|(i, e)| e.sequence() == i as u64)
    }

    /// Get count of physics-bound records.
    pub fn phys_count(&self) -> usize {
        self.records.iter().filter(|e| e.is_phys()).count()
    }

    /// Get count of pure HMAC records.
    pub fn pure_count(&self) -> usize {
        self.records.iter().filter(|e| !e.is_phys()).count()
    }

    /// Calculate physics coverage ratio (0.0 to 1.0).
    pub fn phys_ratio(&self) -> f64 {
        if self.records.is_empty() {
            0.0
        } else {
            self.phys_count() as f64 / self.records.len() as f64
        }
    }

    /// Verify entire chain given secret and input sequence.
    ///
    /// Returns true only if all evidence records can be recomputed
    /// from the corresponding inputs.
    pub fn verify_chain<E: crate::JitterEngine>(
        &self,
        secret: &[u8; 32],
        inputs: &[&[u8]],
        engine: &E,
    ) -> bool {
        if inputs.len() != self.records.len() {
            return false;
        }
        self.records
            .iter()
            .zip(inputs.iter())
            .all(|(evidence, input)| evidence.verify(secret, input, engine))
    }
}

/// Get current timestamp in microseconds since Unix epoch.
///
/// # Returns
///
/// Microseconds since 1970-01-01 00:00:00 UTC.
/// Returns 0 if the system clock is set before the Unix epoch
/// (which should not occur on properly configured systems).
///
/// # Note
///
/// The returned `u64` can represent timestamps until approximately
/// year 586,912 CE, so overflow is not a practical concern.
#[cfg(feature = "std")]
fn current_timestamp_us() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::JitterEngine;

    #[test]
    fn test_evidence_serialization() {
        let evidence = Evidence::phys([1u8; 32].into(), 1500);
        let json = serde_json::to_string(&evidence).unwrap();
        let parsed: Evidence = serde_json::from_str(&json).unwrap();

        assert_eq!(evidence.jitter(), parsed.jitter());
        assert!(parsed.is_phys());
    }

    #[test]
    fn test_evidence_chain() {
        let mut chain = EvidenceChain::new();
        assert_eq!(chain.records.len(), 0);

        chain.append(Evidence::phys([1u8; 32].into(), 1000));
        chain.append(Evidence::pure(1500));
        chain.append(Evidence::phys([2u8; 32].into(), 2000));

        assert_eq!(chain.records.len(), 3);
        assert_eq!(chain.phys_count(), 2);
        assert_eq!(chain.pure_count(), 1);
        assert!((chain.phys_ratio() - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_evidence_verification() {
        use crate::PureJitter;

        let engine = PureJitter::default();
        let secret = [42u8; 32];
        let inputs = b"test input";

        let jitter = engine.compute_jitter(&secret, inputs, [0u8; 32].into());
        let evidence = Evidence::pure(jitter);

        assert!(evidence.verify(&secret, inputs, &engine));
        assert!(!evidence.verify(&secret, b"wrong input", &engine));
    }

    #[test]
    fn test_phys_evidence_verification() {
        use crate::PhysJitter;

        let engine = PhysJitter::new(0);
        let secret = [42u8; 32];
        let inputs = b"test input";
        let phys_hash = [99u8; 32].into();

        let jitter = engine.compute_jitter(&secret, inputs, phys_hash);
        let evidence = Evidence::phys(phys_hash, jitter);

        assert!(evidence.verify(&secret, inputs, &engine));
        assert!(!evidence.verify(&secret, b"wrong input", &engine));
    }

    #[test]
    fn test_chain_verification() {
        use crate::PureJitter;

        let engine = PureJitter::default();
        let secret = [42u8; 32];
        let inputs: Vec<&[u8]> = vec![b"input1", b"input2", b"input3"];

        let mut chain = EvidenceChain::new();
        for input in &inputs {
            let jitter = engine.compute_jitter(&secret, input, [0u8; 32].into());
            chain.append(Evidence::pure(jitter));
        }

        // Should verify with correct inputs
        assert!(chain.verify_chain(&secret, &inputs, &engine));

        // Should fail with wrong inputs
        let wrong_inputs: Vec<&[u8]> = vec![b"wrong1", b"wrong2", b"wrong3"];
        assert!(!chain.verify_chain(&secret, &wrong_inputs, &engine));

        // Should fail with mismatched length
        let short_inputs: Vec<&[u8]> = vec![b"input1", b"input2"];
        assert!(!chain.verify_chain(&secret, &short_inputs, &engine));
    }

    #[test]
    fn test_evidence_equality() {
        // Test phys evidence with same hash and jitter
        let hash = [1u8; 32].into();
        let p1 = Evidence::Phys {
            phys_hash: hash,
            jitter: 1000,
            timestamp_us: 100,
            sequence: 0,
        };
        let p2 = Evidence::Phys {
            phys_hash: hash,
            jitter: 1000,
            timestamp_us: 100,
            sequence: 0,
        };
        let p3 = Evidence::Phys {
            phys_hash: hash,
            jitter: 2000,
            timestamp_us: 100,
            sequence: 0,
        };
        assert_eq!(p1, p2);
        assert_ne!(p1, p3);

        // Test pure evidence equality
        let pure1 = Evidence::Pure {
            jitter: 1500,
            timestamp_us: 200,
            sequence: 0,
        };
        let pure2 = Evidence::Pure {
            jitter: 1500,
            timestamp_us: 200,
            sequence: 0,
        };
        assert_eq!(pure1, pure2);
    }

    #[test]
    fn test_empty_chain_verification() {
        use crate::PureJitter;

        let engine = PureJitter::default();
        let secret = [42u8; 32];
        let chain = EvidenceChain::new();
        let inputs: Vec<&[u8]> = vec![];

        // Empty chain with empty inputs should verify
        assert!(chain.verify_chain(&secret, &inputs, &engine));
    }

    #[test]
    fn test_chain_phys_ratio_empty() {
        let chain = EvidenceChain::new();
        assert_eq!(chain.phys_ratio(), 0.0);
    }

    #[test]
    fn test_keyed_chain_integrity_verification() {
        let secret = [42u8; 32];
        let mut chain = EvidenceChain::with_secret(secret);

        chain.append(Evidence::phys([1u8; 32].into(), 1000));
        chain.append(Evidence::pure(1500));
        chain.append(Evidence::phys([2u8; 32].into(), 2000));

        // Should verify with correct secret
        assert!(chain.verify_integrity(&secret));

        // Should fail with wrong secret
        let wrong_secret = [99u8; 32];
        assert!(!chain.verify_integrity(&wrong_secret));
    }

    #[test]
    fn test_keyed_chain_tamper_detection() {
        let secret = [42u8; 32];
        let mut chain = EvidenceChain::with_secret(secret);

        chain.append(Evidence::phys([1u8; 32].into(), 1000));
        chain.append(Evidence::pure(1500));
        chain.append(Evidence::phys([2u8; 32].into(), 2000));

        // Verify original chain
        assert!(chain.verify_integrity(&secret));

        // Tamper with a record
        if let Some(Evidence::Pure { jitter, .. }) = chain.records.get_mut(1) {
            *jitter = 9999; // Modify the jitter value
        }

        // Should now fail verification
        assert!(!chain.verify_integrity(&secret));
    }

    #[test]
    fn test_keyed_chain_mac_differs_from_unkeyed() {
        let secret = [42u8; 32];

        // Create keyed chain
        let mut keyed_chain = EvidenceChain::with_secret(secret);
        keyed_chain.append(Evidence::pure(1000));

        // Create unkeyed chain with same evidence
        let mut unkeyed_chain = EvidenceChain::new();
        unkeyed_chain.append(Evidence::Pure {
            jitter: 1000,
            timestamp_us: keyed_chain.records[0].timestamp_us(),
            sequence: 0,
        });

        // MACs should differ (keyed vs unkeyed)
        assert_ne!(keyed_chain.chain_mac, unkeyed_chain.chain_mac);
    }

    #[test]
    fn test_empty_keyed_chain_verification() {
        let secret = [42u8; 32];
        let chain = EvidenceChain::with_secret(secret);

        // Empty chain should verify with correct secret
        assert!(chain.verify_integrity(&secret));

        // Empty chain should fail with wrong secret (both start at zero MAC)
        // Actually, for an empty chain, expected_mac stays at [0; 32] and chain_mac is [0; 32]
        // so it will pass regardless of secret. This is expected behavior.
        let wrong_secret = [99u8; 32];
        assert!(chain.verify_integrity(&wrong_secret)); // Both produce [0; 32] for empty chain
    }

    #[test]
    fn test_keyed_chain_serialization_excludes_secret() {
        let secret = [42u8; 32];
        let mut chain = EvidenceChain::with_secret(secret);
        chain.append(Evidence::pure(1000));

        // Serialize and deserialize
        let json = serde_json::to_string(&chain).unwrap();
        let deserialized: EvidenceChain = serde_json::from_str(&json).unwrap();

        // Secret should not be in serialized output
        assert!(!json.contains("secret"));

        // Records and MAC should match
        assert_eq!(chain.records.len(), deserialized.records.len());
        assert_eq!(chain.chain_mac, deserialized.chain_mac);

        // Deserialized chain should still verify with correct secret
        assert!(deserialized.verify_integrity(&secret));
    }

    #[test]
    fn test_keyed_chain_different_secrets_produce_different_macs() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];

        let mut chain1 = EvidenceChain::with_secret(secret1);
        let mut chain2 = EvidenceChain::with_secret(secret2);

        // Add same evidence (with same timestamp for determinism)
        let evidence = Evidence::Pure {
            jitter: 1000,
            timestamp_us: 12345,
            sequence: 0,
        };
        chain1.append(evidence.clone());
        chain2.append(evidence);

        // MACs should be different due to different secrets
        assert_ne!(chain1.chain_mac, chain2.chain_mac);

        // Each should verify with its own secret
        assert!(chain1.verify_integrity(&secret1));
        assert!(chain2.verify_integrity(&secret2));

        // Each should fail with the other's secret
        assert!(!chain1.verify_integrity(&secret2));
        assert!(!chain2.verify_integrity(&secret1));
    }

    #[test]
    fn test_sequence_number_assignment() {
        let mut chain = EvidenceChain::new();

        chain.append(Evidence::pure(1000));
        chain.append(Evidence::phys([1u8; 32].into(), 1500));
        chain.append(Evidence::pure(2000));

        // Check that sequence numbers are correctly assigned
        assert_eq!(chain.records[0].sequence(), 0);
        assert_eq!(chain.records[1].sequence(), 1);
        assert_eq!(chain.records[2].sequence(), 2);
    }

    #[test]
    fn test_validate_sequences_valid() {
        let mut chain = EvidenceChain::new();

        chain.append(Evidence::pure(1000));
        chain.append(Evidence::phys([1u8; 32].into(), 1500));
        chain.append(Evidence::pure(2000));

        assert!(chain.validate_sequences());
    }

    #[test]
    fn test_validate_sequences_invalid() {
        let mut chain = EvidenceChain::new();

        chain.append(Evidence::pure(1000));
        chain.append(Evidence::pure(1500));
        chain.append(Evidence::pure(2000));

        // Tamper with sequence number
        if let Some(Evidence::Pure { sequence, .. }) = chain.records.get_mut(1) {
            *sequence = 99; // Wrong sequence
        }

        assert!(!chain.validate_sequences());
    }

    #[test]
    fn test_validate_sequences_empty_chain() {
        let chain = EvidenceChain::new();
        assert!(chain.validate_sequences());
    }

    #[test]
    fn test_validate_timestamps_valid() {
        let secret = [42u8; 32];
        let mut chain = EvidenceChain::with_secret(secret);

        // Add records with increasing timestamps
        chain.append(Evidence::pure(1000));
        std::thread::sleep(std::time::Duration::from_millis(1));
        chain.append(Evidence::pure(1500));
        std::thread::sleep(std::time::Duration::from_millis(1));
        chain.append(Evidence::pure(2000));

        assert!(chain.validate_timestamps());
    }

    #[test]
    fn test_validate_timestamps_invalid() {
        let mut chain = EvidenceChain::new();

        // Create evidence with manually set timestamps in wrong order
        chain.append(Evidence::Pure {
            jitter: 1000,
            timestamp_us: 300,
            sequence: 0,
        });
        chain.append(Evidence::Pure {
            jitter: 1500,
            timestamp_us: 100, // Earlier than previous - manipulation!
            sequence: 0,
        });

        // Note: The chain's append() will override sequence, but not timestamp
        // So we need to directly manipulate after appending
        if let Some(Evidence::Pure { timestamp_us, .. }) = chain.records.get_mut(1) {
            *timestamp_us = 100; // Set to earlier timestamp
        }

        assert!(!chain.validate_timestamps());
    }

    #[test]
    fn test_validate_timestamps_empty_chain() {
        let chain = EvidenceChain::new();
        assert!(chain.validate_timestamps());
    }

    #[test]
    fn test_validate_timestamps_single_record() {
        let mut chain = EvidenceChain::new();
        chain.append(Evidence::pure(1000));
        assert!(chain.validate_timestamps());
    }

    #[test]
    fn test_sequence_tamper_detection() {
        let secret = [42u8; 32];
        let mut chain = EvidenceChain::with_secret(secret);

        chain.append(Evidence::pure(1000));
        chain.append(Evidence::pure(1500));
        chain.append(Evidence::pure(2000));

        // Verify original chain
        assert!(chain.verify_integrity(&secret));
        assert!(chain.validate_sequences());

        // Tamper with sequence number
        if let Some(Evidence::Pure { sequence, .. }) = chain.records.get_mut(1) {
            *sequence = 5; // Wrong sequence
        }

        // Should fail both validations
        assert!(!chain.verify_integrity(&secret));
        assert!(!chain.validate_sequences());
    }

    #[test]
    fn test_sequence_serialization_roundtrip() {
        let secret = [42u8; 32];
        let mut chain = EvidenceChain::with_secret(secret);

        chain.append(Evidence::pure(1000));
        chain.append(Evidence::phys([1u8; 32].into(), 1500));
        chain.append(Evidence::pure(2000));

        // Serialize and deserialize
        let json = serde_json::to_string(&chain).unwrap();
        let deserialized: EvidenceChain = serde_json::from_str(&json).unwrap();

        // Check sequence numbers are preserved
        assert_eq!(deserialized.records[0].sequence(), 0);
        assert_eq!(deserialized.records[1].sequence(), 1);
        assert_eq!(deserialized.records[2].sequence(), 2);

        // Deserialized chain should still validate
        assert!(deserialized.verify_integrity(&secret));
        assert!(deserialized.validate_sequences());
    }
}
