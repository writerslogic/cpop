// SPDX-License-Identifier: Apache-2.0

//! CDDL-defined enumerations for draft-condrey-rats-pop wire format.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Hash algorithm identifier per CDDL `hash-algorithm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashSaltMode {
    /// No salt applied.
    Unsalted = 0,
    /// Author-provided salt for privacy.
    AuthorSalted = 1,
}

/// Cost unit for forgery estimates per CDDL `cost-unit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CostUnit {
    /// US dollars.
    Usd = 1,
    /// CPU-hours.
    CpuHours = 2,
}

/// Absence claim type per CDDL `absence-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BindingType {
    /// TLS Exporter Key Material (RFC 5705).
    TlsExporter = 1,
}

/// Confidence tier for baseline digests per CDDL `confidence-tier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

impl TryFrom<u8> for ConfidenceTier {
    type Error = String;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::PopulationReference),
            2 => Ok(Self::Emerging),
            3 => Ok(Self::Established),
            4 => Ok(Self::Mature),
            other => Err(format!(
                "confidence_tier out of range: {} (must be 1..=4)",
                other
            )),
        }
    }
}

// --- Display implementations ---

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => f.write_str("SHA-256"),
            Self::Sha384 => f.write_str("SHA-384"),
            Self::Sha512 => f.write_str("SHA-512"),
        }
    }
}

impl fmt::Display for AttestationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SoftwareOnly => f.write_str("software-only"),
            Self::AttestedSoftware => f.write_str("attested-software"),
            Self::HardwareBound => f.write_str("hardware-bound"),
            Self::HardwareHardened => f.write_str("hardware-hardened"),
        }
    }
}

impl fmt::Display for ContentTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core => f.write_str("core"),
            Self::Enhanced => f.write_str("enhanced"),
            Self::Maximum => f.write_str("maximum"),
        }
    }
}

impl fmt::Display for ProofAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SwfSha256 => f.write_str("swf-sha256"),
            Self::SwfArgon2id => f.write_str("swf-argon2id"),
            Self::SwfArgon2idEntangled => f.write_str("swf-argon2id-entangled"),
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentic => f.write_str("authentic"),
            Self::Inconclusive => f.write_str("inconclusive"),
            Self::Suspicious => f.write_str("suspicious"),
            Self::Invalid => f.write_str("invalid"),
        }
    }
}

impl fmt::Display for FeatureId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SwfArgon2idSha256 => f.write_str("swf-argon2id-sha256"),
            Self::ContentBinding => f.write_str("content-binding"),
            Self::CheckpointChain => f.write_str("checkpoint-chain"),
            Self::BehavioralEntropy => f.write_str("behavioral-entropy"),
            Self::AssistiveMode => f.write_str("assistive-mode"),
            Self::EditGraphHash => f.write_str("edit-graph-hash"),
            Self::EditGraphHistograms => f.write_str("edit-graph-histograms"),
            Self::HardwareAttestation => f.write_str("hardware-attestation"),
        }
    }
}

impl fmt::Display for HashSaltMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsalted => f.write_str("unsalted"),
            Self::AuthorSalted => f.write_str("author-salted"),
        }
    }
}

impl fmt::Display for CostUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usd => f.write_str("USD"),
            Self::CpuHours => f.write_str("CPU-hours"),
        }
    }
}

impl fmt::Display for AbsenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ComputationallyBound => f.write_str("computationally-bound"),
            Self::MonitoringDependent => f.write_str("monitoring-dependent"),
            Self::Environmental => f.write_str("environmental"),
        }
    }
}

impl fmt::Display for ProbeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GaltonBoard => f.write_str("galton-board"),
            Self::ReflexGate => f.write_str("reflex-gate"),
            Self::SpatialTarget => f.write_str("spatial-target"),
        }
    }
}

impl fmt::Display for BindingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsExporter => f.write_str("tls-exporter"),
        }
    }
}

impl fmt::Display for ConfidenceTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PopulationReference => f.write_str("population-reference"),
            Self::Emerging => f.write_str("emerging"),
            Self::Established => f.write_str("established"),
            Self::Mature => f.write_str("mature"),
        }
    }
}
