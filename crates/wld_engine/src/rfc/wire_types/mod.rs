// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Spec-conformant wire format types for draft-condrey-rats-pop CDDL schema.
//!
//! This module implements ALL CDDL-defined types from the writerslogic-pop.cddl schema
//! as Rust structs with serde + CBOR serialization. All map keys use integer encoding
//! per IETF CBOR conventions, matching the CDDL definitions exactly.
//!
//! These types are designed for wire-format serialization and are separate from the
//! internal types used by the engine. Conversion traits (`From`) bridge between
//! internal and wire representations.
//!
//! # CBOR Tags
//!
//! - Evidence Packet: `#6.1347571280` (IANA "PPPP")
//! - Attestation Result: `#6.1463894560` (IANA "WAR ")
//!
//! # Module Organization
//!
//! - `enums`: CDDL-defined enumerations (hash algorithms, tiers, verdicts, etc.)
//! - `hash`: Base hash types (HashValue, CompactRef, TimeWindow)
//! - `components`: Evidence component types (DocumentRef, EditDelta, proofs, etc.)
//! - `checkpoint`: Wire-format checkpoint structure
//! - `packet`: Wire-format evidence packet with CBOR encode/decode
//! - `attestation`: Forensic types and attestation result with CBOR encode/decode
//! - `serde_helpers`: Custom serde modules for fixed-size byte arrays

mod serde_helpers;

pub mod attestation;
pub mod checkpoint;
pub mod components;
pub mod enums;
pub mod hash;
pub mod packet;

#[cfg(test)]
mod tests;

use crate::codec::{CBOR_TAG_PPP, CBOR_TAG_WAR};

pub const CBOR_TAG_EVIDENCE_PACKET: u64 = CBOR_TAG_PPP;
pub const CBOR_TAG_ATTESTATION_RESULT: u64 = CBOR_TAG_WAR;

pub use attestation::{
    AbsenceClaim, AttestationResultWire, EntropyReport, ForensicFlag, ForensicSummary,
    ForgeryCostEstimate,
};
pub use checkpoint::CheckpointWire;
pub use components::{
    ActiveProbe, ChannelBinding, DocumentRef, EditDelta, JitterBindingWire, MerkleProof,
    PhysicalLiveness, PhysicalState, PresenceChallenge, ProcessProof, ProfileDeclarationWire,
    ProofParams, SelfReceipt, SWF_MAX_DURATION_FACTOR, SWF_MIN_DURATION_FACTOR,
};
pub use enums::{
    AbsenceType, AttestationTier, BindingType, ContentTier, CostUnit, FeatureId, HashAlgorithm,
    HashSaltMode, ProbeType, ProofAlgorithm, Verdict,
};
pub use hash::{CompactRef, HashValue, TimeWindow};
pub use packet::EvidencePacketWire;
