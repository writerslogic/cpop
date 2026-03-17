// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Evidence packet module: types, builder, verification, and RFC conversion.

mod builder;
mod packet;
mod rfc_conversion;
mod serde_helpers;
#[cfg(test)]
mod tests;
mod types;
pub mod wire_conversion;

pub use self::types::{
    AccessControlInfo, AnchorProof, BehavioralEvidence, BlockchainAnchorInfo, CheckpointProof,
    CheckpointSignature, Claim, ClaimType, ContextPeriod, DictationEvent, DocumentInfo, EditRegion,
    ExternalAnchors, ForensicMetrics, HardwareEvidence, InputDeviceInfo,
    KeyHierarchyEvidencePacket, KeystrokeEvidence, OtsProof, Packet, RecordProvenance,
    Rfc3161Proof, Strength, TrustTier,
};

pub use self::builder::{
    build_ephemeral_packet, compute_events_binding_hash, convert_anchor_proof, Builder,
    EphemeralSnapshot,
};
