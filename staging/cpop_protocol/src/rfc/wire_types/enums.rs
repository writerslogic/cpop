// SPDX-License-Identifier: Apache-2.0

//! CDDL-defined enumerations for draft-condrey-rats-pop wire format.

use serde::{Deserialize, Serialize};

/// Hash algorithm identifier per CDDL `hash-algorithm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashAlgorithm {
    /// SHA-256 (32-byte digest)
    Sha256 = 1,
    /// SHA-384 (48-byte digest)
    Sha384 = 2,
    /// SHA-512 (64-byte digest)
    Sha512 = 3,
}

/// Attestation tier per CDDL `attestation-tier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AttestationTier {
    /// T1: Software-only (AAL1)
    SoftwareOnly = 1,
    /// T2: Attested software (AAL2)
    AttestedSoftware = 2,
    /// T3: Hardware-bound (AAL3)
    HardwareBound = 3,
    /// T4: Hardware-hardened (LoA4)
    HardwareHardened = 4,
}

/// Content tier per CDDL `content-tier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentTier {
    /// Core evidence tier.
    Core = 1,
    /// Enhanced evidence tier.
    Enhanced = 2,
    /// Maximum evidence tier.
    Maximum = 3,
}

/// Proof algorithm identifier per CDDL `proof-algorithm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProofAlgorithm {
    /// swf-sha256 (10): Iterated SHA-256 sequential work function
    SwfSha256 = 10,
    /// swf-argon2id (20): Argon2id + Merkle tree + Fiat-Shamir
    SwfArgon2id = 20,
    /// swf-argon2id-entangled (21): Argon2id with jitter entanglement
    SwfArgon2idEntangled = 21,
}

/// Appraisal verdict per CDDL `verdict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Verdict {
    /// Evidence supports authentic human authorship.
    Authentic = 1,
    /// Insufficient evidence to determine.
    Inconclusive = 2,
    /// Evidence indicates potential forgery.
    Suspicious = 3,
    /// Evidence is structurally invalid.
    Invalid = 4,
}

/// Feature identifier per CDDL `feature-id`.
///
/// Used in `profile-declaration` to declare enabled features beyond MTI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FeatureId {
    /// SWF with Argon2id + SHA-256 (MTI for all tiers)
    SwfArgon2idSha256 = 1,
    /// Content binding (document hash in checkpoint chain)
    ContentBinding = 2,
    /// Checkpoint chain with chained hashes
    CheckpointChain = 4,
    /// Behavioral entropy analysis
    BehavioralEntropy = 50,
    /// Assistive technology mode
    AssistiveMode = 60,
    /// Edit graph hash
    EditGraphHash = 51,
    /// Edit graph histograms
    EditGraphHistograms = 52,
    /// Hardware attestation (TPM/Secure Enclave)
    HardwareAttestation = 105,
}

/// Hash salt mode per CDDL `hash-salt-mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashSaltMode {
    /// No salt applied.
    Unsalted = 0,
    /// Author-provided salt for privacy.
    AuthorSalted = 1,
}

/// Cost unit for forgery estimates per CDDL `cost-unit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CostUnit {
    /// US dollars.
    Usd = 1,
    /// CPU-hours.
    CpuHours = 2,
}

/// Absence claim type per CDDL `absence-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AbsenceType {
    /// Bound by computational cost.
    ComputationallyBound = 1,
    /// Dependent on monitoring infrastructure.
    MonitoringDependent = 2,
    /// Environmental constraint.
    Environmental = 3,
}

/// Active probe type per CDDL `probe-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProbeType {
    /// Binomial absorption test.
    GaltonBoard = 1,
    /// Backspace-after-typo latency test.
    ReflexGate = 2,
    /// Spatial targeting accuracy test.
    SpatialTarget = 3,
}

/// Channel binding type per CDDL `binding-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BindingType {
    /// TLS Exporter Key Material (RFC 5705).
    TlsExporter = 1,
}

/// Confidence tier for baseline digests per CDDL `confidence-tier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConfidenceTier {
    /// Population reference baseline.
    PopulationReference = 1,
    /// Emerging per-author baseline.
    Emerging = 2,
    /// Established per-author baseline.
    Established = 3,
    /// Mature per-author baseline.
    Mature = 4,
}
