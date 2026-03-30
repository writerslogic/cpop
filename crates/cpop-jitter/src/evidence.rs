// SPDX-License-Identifier: Apache-2.0

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Jitter, PhysHash};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Evidence {
    Phys {
        phys_hash: PhysHash,
        jitter: Jitter,
        timestamp_us: u64,
        #[serde(default)]
        sequence: u64,
    },
    Pure {
        jitter: Jitter,
        timestamp_us: u64,
        #[serde(default)]
        sequence: u64,
    },
}

impl Evidence {
    pub fn phys_with_timestamp(phys_hash: PhysHash, jitter: Jitter, timestamp_us: u64) -> Self {
        Self::Phys {
            phys_hash,
            jitter,
            timestamp_us,
            sequence: 0,
        }
    }

    pub fn pure_with_timestamp(jitter: Jitter, timestamp_us: u64) -> Self {
        Self::Pure {
            jitter,
            timestamp_us,
            sequence: 0,
        }
    }

    #[cfg(feature = "std")]
    pub fn phys(phys_hash: PhysHash, jitter: Jitter) -> Self {
        Self::phys_with_timestamp(phys_hash, jitter, current_timestamp_us())
    }

    #[cfg(feature = "std")]
    pub fn pure(jitter: Jitter) -> Self {
        Self::pure_with_timestamp(jitter, current_timestamp_us())
    }
    #[inline]
    pub fn sequence(&self) -> u64 {
        match self {
            Evidence::Phys { sequence, .. } => *sequence,
            Evidence::Pure { sequence, .. } => *sequence,
        }
    }

    fn write_fields(&self, mut f: impl FnMut(&[u8])) {
        match self {
            Evidence::Phys {
                phys_hash,
                jitter,
                timestamp_us,
                sequence,
            } => {
                f(&[0u8]);
                f(&phys_hash.hash);
                f(&[phys_hash.entropy_bits]);
                f(&jitter.to_le_bytes());
                f(&timestamp_us.to_le_bytes());
                f(&sequence.to_le_bytes());
            }
            Evidence::Pure {
                jitter,
                timestamp_us,
                sequence,
            } => {
                f(&[1u8]);
                f(&jitter.to_le_bytes());
                f(&timestamp_us.to_le_bytes());
                f(&sequence.to_le_bytes());
            }
        }
    }

    pub fn hash_into(&self, hasher: &mut sha2::Sha256) {
        use sha2::Digest;
        self.write_fields(|bytes| hasher.update(bytes));
    }

    pub fn hash_into_mac(&self, mac: &mut hmac::Hmac<sha2::Sha256>) {
        use hmac::Mac;
        self.write_fields(|bytes| mac.update(bytes));
    }
    #[inline]
    pub fn jitter(&self) -> Jitter {
        match self {
            Evidence::Phys { jitter, .. } => *jitter,
            Evidence::Pure { jitter, .. } => *jitter,
        }
    }
    #[inline]
    pub fn is_phys(&self) -> bool {
        matches!(self, Evidence::Phys { .. })
    }
    #[inline]
    pub fn timestamp_us(&self) -> u64 {
        match self {
            Evidence::Phys { timestamp_us, .. } => *timestamp_us,
            Evidence::Pure { timestamp_us, .. } => *timestamp_us,
        }
    }

    /// Constant-time recomputation check.
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

/// Prevents unbounded allocation on deserialization of untrusted data.
pub const MAX_EVIDENCE_RECORDS: usize = 100_000;

/// Append-only chain of evidence records with HMAC integrity protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "EvidenceChainRaw")]
pub struct EvidenceChain {
    /// Wire format version (currently 1).
    pub version: u8,
    /// Direct mutation invalidates `chain_mac`. Use `append()` to add
    /// records, or `records()` for read-only access.
    pub records: Vec<Evidence>,
    /// Running HMAC-SHA256 (keyed) or SHA-256 (unkeyed) over all records.
    pub chain_mac: [u8; 32],
    #[serde(default)]
    next_sequence: u64,
    #[serde(skip)]
    secret: Option<Zeroizing<[u8; 32]>>,
}

/// Raw deserialization target for [`EvidenceChain`].
/// Bounds are validated via [`TryFrom`] so untrusted input cannot allocate
/// more than [`MAX_EVIDENCE_RECORDS`] entries.
#[derive(Deserialize)]
struct EvidenceChainRaw {
    version: u8,
    records: Vec<Evidence>,
    chain_mac: [u8; 32],
    #[serde(default)]
    next_sequence: u64,
}

impl TryFrom<EvidenceChainRaw> for EvidenceChain {
    type Error = &'static str;

    fn try_from(raw: EvidenceChainRaw) -> core::result::Result<Self, Self::Error> {
        if raw.version != 1 {
            return Err("unsupported evidence chain version");
        }
        if raw.records.len() > MAX_EVIDENCE_RECORDS {
            return Err("evidence chain exceeds MAX_EVIDENCE_RECORDS");
        }
        if raw.next_sequence != raw.records.len() as u64 {
            return Err("next_sequence does not match record count");
        }
        // Validate per-record sequence numbers match their index.
        for (i, record) in raw.records.iter().enumerate() {
            if record.sequence() != i as u64 {
                return Err("record sequence number does not match index");
            }
        }
        // MAC verification deferred to verify_integrity(); TryFrom only validates structure.
        Ok(Self {
            version: raw.version,
            records: raw.records,
            chain_mac: raw.chain_mac,
            next_sequence: raw.next_sequence,
            secret: None,
        })
    }
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
            && self.next_sequence == other.next_sequence
    }
}

impl Eq for EvidenceChain {}

impl EvidenceChain {
    /// Read-only access to the evidence records.
    ///
    /// Prefer this over direct field access. Modifying records directly
    /// (via the `records` field) will invalidate the chain MAC.
    pub fn records(&self) -> &[Evidence] {
        &self.records
    }

    /// Read-only access to the chain MAC.
    pub fn chain_mac(&self) -> &[u8; 32] {
        &self.chain_mac
    }

    /// Number of evidence records in the chain.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if the chain contains no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Create an empty unkeyed evidence chain (SHA-256 integrity).
    pub fn new() -> Self {
        Self {
            version: 1,
            records: Vec::new(),
            chain_mac: [0u8; 32],
            next_sequence: 0,
            secret: None,
        }
    }

    /// Create an empty keyed evidence chain (HMAC-SHA256 integrity).
    pub fn with_secret(secret: &[u8; 32]) -> Self {
        Self {
            version: 1,
            records: Vec::new(),
            chain_mac: [0u8; 32],
            next_sequence: 0,
            secret: Some(Zeroizing::new(*secret)),
        }
    }

    /// Check whether the chain exceeds [`MAX_EVIDENCE_RECORDS`].
    /// This is enforced automatically during serde deserialization via
    /// `#[serde(try_from)]`. This method remains public for manual checks
    /// on chains built programmatically.
    pub fn validate_bounds(&self) -> bool {
        self.records.len() <= MAX_EVIDENCE_RECORDS
    }

    /// Append an evidence record, assigning its sequence number and updating the chain MAC.
    ///
    /// Returns `Error::EvidenceOverflow` if the chain already has
    /// [`MAX_EVIDENCE_RECORDS`] entries.
    pub fn append(&mut self, mut evidence: Evidence) -> core::result::Result<(), crate::Error> {
        if self.records.len() >= MAX_EVIDENCE_RECORDS {
            return Err(crate::Error::EvidenceOverflow(MAX_EVIDENCE_RECORDS));
        }

        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        match &mut evidence {
            Evidence::Phys { sequence, .. } | Evidence::Pure { sequence, .. } => {
                *sequence = self.next_sequence;
            }
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(crate::Error::EvidenceOverflow(MAX_EVIDENCE_RECORDS))?;

        if let Some(secret) = &self.secret {
            let mut mac =
                HmacSha256::new_from_slice(secret.as_ref()).expect("HMAC accepts any key size");
            mac.update(&self.chain_mac);
            evidence.hash_into_mac(&mut mac);
            let result = mac.finalize().into_bytes();
            self.chain_mac.copy_from_slice(&result);
        } else {
            use sha2::Digest;
            let mut hasher = Sha256::new();
            hasher.update(self.chain_mac);
            evidence.hash_into(&mut hasher);
            let result = hasher.finalize();
            self.chain_mac.copy_from_slice(&result);
        }

        self.records.push(evidence);
        Ok(())
    }

    pub fn verify_integrity(&self, secret: &[u8; 32]) -> bool {
        use hmac::{Hmac, Mac};
        use subtle::ConstantTimeEq;

        type HmacSha256 = Hmac<sha2::Sha256>;

        let mut expected_mac = [0u8; 32];
        for evidence in &self.records {
            let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
            mac.update(&expected_mac);
            evidence.hash_into_mac(&mut mac);
            let result = mac.finalize().into_bytes();
            expected_mac.copy_from_slice(&result);
        }

        expected_mac.ct_eq(&self.chain_mac).into()
    }

    pub fn verify_integrity_unkeyed(&self) -> bool {
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;

        let mut expected_mac = [0u8; 32];
        for evidence in &self.records {
            let mut hasher = Sha256::new();
            hasher.update(expected_mac);
            evidence.hash_into(&mut hasher);
            let result = hasher.finalize();
            expected_mac.copy_from_slice(&result);
        }

        expected_mac.ct_eq(&self.chain_mac).into()
    }
    /// Check that record timestamps are non-decreasing.
    ///
    /// - **Keyed chains**: timestamps are integrity-protected via the HMAC (the
    ///   sequence number is included in the MAC input), so reordering records
    ///   will also break `verify_integrity()`.
    /// - **Unkeyed chains**: timestamps provide append-ordering evidence but no
    ///   cryptographic ordering guarantee; an adversary who can modify records
    ///   can also rewrite timestamps.
    /// - **Recommendation**: always use keyed chains (`with_secret`) for
    ///   security-sensitive applications.
    pub fn validate_timestamps(&self) -> bool {
        self.records
            .windows(2)
            .all(|w| w[0].timestamp_us() <= w[1].timestamp_us())
    }
    pub fn validate_sequences(&self) -> bool {
        self.records
            .iter()
            .enumerate()
            .all(|(i, e)| e.sequence() == i as u64)
    }

    pub fn phys_count(&self) -> usize {
        self.records.iter().filter(|e| e.is_phys()).count()
    }

    pub fn pure_count(&self) -> usize {
        self.records.len() - self.phys_count()
    }
    pub fn phys_ratio(&self) -> f64 {
        if self.records.is_empty() {
            0.0
        } else {
            self.phys_count() as f64 / self.records.len() as f64
        }
    }

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

/// Returns current time as microseconds since UNIX epoch.
/// The u128->u64 truncation covers ~584,542 years; safe for all practical timestamps.
#[cfg(feature = "std")]
fn current_timestamp_us() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
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

        chain
            .append(Evidence::phys([1u8; 32].into(), 1000))
            .unwrap();
        chain.append(Evidence::pure(1500)).unwrap();
        chain
            .append(Evidence::phys([2u8; 32].into(), 2000))
            .unwrap();

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
            chain.append(Evidence::pure(jitter)).unwrap();
        }

        assert!(chain.verify_chain(&secret, &inputs, &engine));

        let wrong_inputs: Vec<&[u8]> = vec![b"wrong1", b"wrong2", b"wrong3"];
        assert!(!chain.verify_chain(&secret, &wrong_inputs, &engine));

        let short_inputs: Vec<&[u8]> = vec![b"input1", b"input2"];
        assert!(!chain.verify_chain(&secret, &short_inputs, &engine));
    }

    #[test]
    fn test_evidence_equality() {
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
        let mut chain = EvidenceChain::with_secret(&secret);

        chain
            .append(Evidence::phys([1u8; 32].into(), 1000))
            .unwrap();
        chain.append(Evidence::pure(1500)).unwrap();
        chain
            .append(Evidence::phys([2u8; 32].into(), 2000))
            .unwrap();

        assert!(chain.verify_integrity(&secret));

        let wrong_secret = [99u8; 32];
        assert!(!chain.verify_integrity(&wrong_secret));
    }

    #[test]
    fn test_keyed_chain_tamper_detection() {
        let secret = [42u8; 32];
        let mut chain = EvidenceChain::with_secret(&secret);

        chain
            .append(Evidence::phys([1u8; 32].into(), 1000))
            .unwrap();
        chain.append(Evidence::pure(1500)).unwrap();
        chain
            .append(Evidence::phys([2u8; 32].into(), 2000))
            .unwrap();

        assert!(chain.verify_integrity(&secret));

        if let Some(Evidence::Pure { jitter, .. }) = chain.records.get_mut(1) {
            *jitter = 9999;
        }

        assert!(!chain.verify_integrity(&secret));
    }

    #[test]
    fn test_keyed_chain_mac_differs_from_unkeyed() {
        let secret = [42u8; 32];
        let mut keyed_chain = EvidenceChain::with_secret(&secret);
        keyed_chain.append(Evidence::pure(1000)).unwrap();

        let mut unkeyed_chain = EvidenceChain::new();
        unkeyed_chain
            .append(Evidence::Pure {
                jitter: 1000,
                timestamp_us: keyed_chain.records[0].timestamp_us(),
                sequence: 0,
            })
            .unwrap();

        assert_ne!(keyed_chain.chain_mac, unkeyed_chain.chain_mac);
    }

    #[test]
    fn test_empty_keyed_chain_verification() {
        let secret = [42u8; 32];
        let chain = EvidenceChain::with_secret(&secret);

        assert!(chain.verify_integrity(&secret));

        // Empty chain: both MACs are [0; 32], so any secret passes
        let wrong_secret = [99u8; 32];
        assert!(chain.verify_integrity(&wrong_secret));
    }

    #[test]
    fn test_keyed_chain_serialization_excludes_secret() {
        let secret = [42u8; 32];
        let mut chain = EvidenceChain::with_secret(&secret);
        chain.append(Evidence::pure(1000)).unwrap();

        let json = serde_json::to_string(&chain).unwrap();
        let deserialized: EvidenceChain = serde_json::from_str(&json).unwrap();

        assert!(!json.contains("secret"));
        assert_eq!(chain.records.len(), deserialized.records.len());
        assert_eq!(chain.chain_mac, deserialized.chain_mac);
        assert!(deserialized.verify_integrity(&secret));
    }

    #[test]
    fn test_keyed_chain_different_secrets_produce_different_macs() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];

        let mut chain1 = EvidenceChain::with_secret(&secret1);
        let mut chain2 = EvidenceChain::with_secret(&secret2);

        let evidence = Evidence::Pure {
            jitter: 1000,
            timestamp_us: 12345,
            sequence: 0,
        };
        chain1.append(evidence.clone()).unwrap();
        chain2.append(evidence).unwrap();

        assert_ne!(chain1.chain_mac, chain2.chain_mac);
        assert!(chain1.verify_integrity(&secret1));
        assert!(chain2.verify_integrity(&secret2));
        assert!(!chain1.verify_integrity(&secret2));
        assert!(!chain2.verify_integrity(&secret1));
    }

    #[test]
    fn test_sequence_number_assignment() {
        let mut chain = EvidenceChain::new();

        chain.append(Evidence::pure(1000)).unwrap();
        chain
            .append(Evidence::phys([1u8; 32].into(), 1500))
            .unwrap();
        chain.append(Evidence::pure(2000)).unwrap();

        assert_eq!(chain.records[0].sequence(), 0);
        assert_eq!(chain.records[1].sequence(), 1);
        assert_eq!(chain.records[2].sequence(), 2);
    }

    #[test]
    fn test_validate_sequences_valid() {
        let mut chain = EvidenceChain::new();

        chain.append(Evidence::pure(1000)).unwrap();
        chain
            .append(Evidence::phys([1u8; 32].into(), 1500))
            .unwrap();
        chain.append(Evidence::pure(2000)).unwrap();

        assert!(chain.validate_sequences());
    }

    #[test]
    fn test_validate_sequences_invalid() {
        let mut chain = EvidenceChain::new();

        chain.append(Evidence::pure(1000)).unwrap();
        chain.append(Evidence::pure(1500)).unwrap();
        chain.append(Evidence::pure(2000)).unwrap();

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
        let mut chain = EvidenceChain::with_secret(&secret);

        chain.append(Evidence::pure(1000)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        chain.append(Evidence::pure(1500)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        chain.append(Evidence::pure(2000)).unwrap();

        assert!(chain.validate_timestamps());
    }

    #[test]
    fn test_validate_timestamps_invalid() {
        let mut chain = EvidenceChain::new();

        chain
            .append(Evidence::Pure {
                jitter: 1000,
                timestamp_us: 300,
                sequence: 0,
            })
            .unwrap();
        chain
            .append(Evidence::Pure {
                jitter: 1500,
                timestamp_us: 100,
                sequence: 0,
            })
            .unwrap();

        if let Some(Evidence::Pure { timestamp_us, .. }) = chain.records.get_mut(1) {
            *timestamp_us = 100;
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
        chain.append(Evidence::pure(1000)).unwrap();
        assert!(chain.validate_timestamps());
    }

    #[test]
    fn test_sequence_tamper_detection() {
        let secret = [42u8; 32];
        let mut chain = EvidenceChain::with_secret(&secret);

        chain.append(Evidence::pure(1000)).unwrap();
        chain.append(Evidence::pure(1500)).unwrap();
        chain.append(Evidence::pure(2000)).unwrap();

        assert!(chain.verify_integrity(&secret));
        assert!(chain.validate_sequences());

        if let Some(Evidence::Pure { sequence, .. }) = chain.records.get_mut(1) {
            *sequence = 5;
        }

        assert!(!chain.verify_integrity(&secret));
        assert!(!chain.validate_sequences());
    }

    #[test]
    fn test_unkeyed_chain_verify_integrity() {
        let mut chain = EvidenceChain::new();

        chain.append(Evidence::pure(1000)).unwrap();
        chain
            .append(Evidence::phys([1u8; 32].into(), 1500))
            .unwrap();
        chain.append(Evidence::pure(2000)).unwrap();
        chain
            .append(Evidence::phys([2u8; 32].into(), 2500))
            .unwrap();
        chain.append(Evidence::pure(3000)).unwrap();

        assert!(chain.verify_integrity_unkeyed());
    }

    #[test]
    fn test_unkeyed_chain_keyed_verify_fails() {
        let mut chain = EvidenceChain::new();

        chain.append(Evidence::pure(1000)).unwrap();
        chain
            .append(Evidence::phys([1u8; 32].into(), 1500))
            .unwrap();
        chain.append(Evidence::pure(2000)).unwrap();

        assert!(!chain.verify_integrity(&[0u8; 32]));
    }

    #[test]
    fn test_tampered_chain_fails_verification() {
        let secret = [42u8; 32];
        let mut chain = EvidenceChain::with_secret(&secret);

        chain.append(Evidence::pure(1000)).unwrap();
        chain.append(Evidence::pure(1500)).unwrap();
        chain.append(Evidence::pure(2000)).unwrap();

        assert!(chain.verify_integrity(&secret));

        // Tamper with jitter in record[1]
        if let Some(Evidence::Pure { jitter, .. }) = chain.records.get_mut(1) {
            *jitter = 42_000;
        }

        assert!(!chain.verify_integrity(&secret));
    }

    #[test]
    fn test_sequence_serialization_roundtrip() {
        let secret = [42u8; 32];
        let mut chain = EvidenceChain::with_secret(&secret);

        chain.append(Evidence::pure(1000)).unwrap();
        chain
            .append(Evidence::phys([1u8; 32].into(), 1500))
            .unwrap();
        chain.append(Evidence::pure(2000)).unwrap();

        let json = serde_json::to_string(&chain).unwrap();
        let deserialized: EvidenceChain = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.records[0].sequence(), 0);
        assert_eq!(deserialized.records[1].sequence(), 1);
        assert_eq!(deserialized.records[2].sequence(), 2);
        assert!(deserialized.verify_integrity(&secret));
        assert!(deserialized.validate_sequences());
    }

    #[test]
    fn test_append_overflow_at_max_records() {
        let mut chain = EvidenceChain::new();
        // Add one record so we can clone it for bulk fill
        chain.append(Evidence::pure(1000)).unwrap();
        // Fill to capacity by resizing (avoids 100k iterations in test)
        chain
            .records
            .resize(MAX_EVIDENCE_RECORDS, chain.records[0].clone());
        chain.next_sequence = MAX_EVIDENCE_RECORDS as u64;
        // The next append should fail with EvidenceOverflow
        let result = chain.append(Evidence::pure(1000));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::Error::EvidenceOverflow(_)
        ));
    }

    #[test]
    fn test_deserialization_rejects_invalid_version() {
        let json = r#"{"version":2,"records":[],"chain_mac":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"next_sequence":0}"#;
        let result: core::result::Result<EvidenceChain, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialization_rejects_sequence_mismatch() {
        let json = r#"{"version":1,"records":[],"chain_mac":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"next_sequence":5}"#;
        let result: core::result::Result<EvidenceChain, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_unkeyed_chain_tamper_detection() {
        let mut chain = EvidenceChain::new();
        chain.append(Evidence::pure(1000)).unwrap();
        chain.append(Evidence::pure(1500)).unwrap();
        chain.append(Evidence::pure(2000)).unwrap();

        assert!(chain.verify_integrity_unkeyed());

        // Tamper with a record's jitter
        if let Some(Evidence::Pure { jitter, .. }) = chain.records.get_mut(1) {
            *jitter = 9999;
        }

        assert!(!chain.verify_integrity_unkeyed());
    }

    #[test]
    fn test_accessor_methods() {
        let mut chain = EvidenceChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);

        chain.append(Evidence::pure(1000)).unwrap();
        assert!(!chain.is_empty());
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.records().len(), 1);
        assert_eq!(*chain.chain_mac(), chain.chain_mac);
    }
}
