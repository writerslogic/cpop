// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! RFC-compliant data structures for Proof-of-Process evidence.
//!
//! This module implements the CDDL-defined structures from draft-condrey-rats-pop-01
//! and draft-condrey-rats-pop-schema-01. All structures support both CBOR and JSON
//! serialization for backwards compatibility.
//!
//! # Module Organization
//!
//! - `fixed_point`: Fixed-point integer types for cross-platform reproducibility
//! - `checkpoint`: RFC-compliant checkpoint structure with integer keys
//! - `packet`: RFC-compliant evidence packet structure with integer keys
//! - `vdf`: VDF proof structures with calibration attestation
//! - `jitter_binding`: Behavioral entropy binding structures
//! - `biology`: Biology-invariant claim structures
//! - `time_evidence`: Time binding and external anchor structures

pub mod biology;
pub mod checkpoint;
pub mod fixed_point;
pub mod jitter_binding;
pub mod packet;
pub(crate) mod serde_helpers;
pub mod time_evidence;
pub mod vdf;
pub mod wire_types;

pub use biology::{
    BiologyInvariantClaim, BiologyMeasurements, BiologyScoringParameters, ValidationStatus,
};
pub use checkpoint::{BioBinding, CheckpointRfc, SaVdfProof};
pub use fixed_point::{
    Centibits, DeciWpm, Decibits, Microdollars, Millibits, RhoMillibits, SlopeDecibits,
};
pub use jitter_binding::{
    ActiveProbes, BindingMac, EntropyCommitment, GaltonInvariant, JitterBinding, JitterSummary,
    LabyrinthStructure, ReflexGate,
};
pub use packet::{
    ContentHashTree, CorrelationProof, EnclaveVise, ErrorTopology, JitterSealStructure,
    KeyRotationMetadata, PacketRfc, PrivacyBudgetCertificate, ProfileDeclaration, VdfStructure,
    ZkProcessVerdict, CBOR_TAG_EVIDENCE_PACKET,
};
pub use time_evidence::{
    BlockchainAnchor, RoughtimeSample, TimeBindingTier, TimeEvidence, TsaResponse,
};
pub use vdf::{CalibrationAttestation, VdfProofRfc};
pub use wire_types::{
    AbsenceClaim, AbsenceType, ActiveProbe, AttestationResultWire,
    AttestationTier as WireAttestationTier, BindingType, ChannelBinding, CheckpointWire,
    CompactRef as WireCompactRef, ContentTier, CostUnit, DocumentRef, EditDelta, EntropyReport,
    EvidencePacketWire, FeatureId, ForensicFlag, ForensicSummary, ForgeryCostEstimate,
    HashAlgorithm, HashSaltMode, HashValue, JitterBindingWire, MerkleProof as WireMerkleProof,
    PhysicalLiveness, PhysicalState, PresenceChallenge, ProbeType, ProcessProof,
    ProfileDeclarationWire, ProofAlgorithm, ProofParams, SelfReceipt, TimeWindow, Verdict,
    CBOR_TAG_ATTESTATION_RESULT, CBOR_TAG_EVIDENCE_PACKET as CBOR_TAG_EVIDENCE_PACKET_WIRE,
    SWF_MAX_DURATION_FACTOR, SWF_MIN_DURATION_FACTOR,
};
