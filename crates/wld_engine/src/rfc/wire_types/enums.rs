// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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
    Core = 1,
    Enhanced = 2,
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
    Authentic = 1,
    Inconclusive = 2,
    Suspicious = 3,
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
    /// Hardware attestation (TPM/Secure Enclave)
    HardwareAttestation = 105,
}

/// Hash salt mode per CDDL `hash-salt-mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashSaltMode {
    Unsalted = 0,
    AuthorSalted = 1,
}

/// Cost unit for forgery estimates per CDDL `cost-unit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CostUnit {
    Usd = 1,
    CpuHours = 2,
}

/// Absence claim type per CDDL `absence-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AbsenceType {
    ComputationallyBound = 1,
    MonitoringDependent = 2,
    Environmental = 3,
}

/// Active probe type per CDDL `probe-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProbeType {
    GaltonBoard = 1,
    ReflexGate = 2,
    SpatialTarget = 3,
}

/// Channel binding type per CDDL `binding-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BindingType {
    TlsExporter = 1,
}
