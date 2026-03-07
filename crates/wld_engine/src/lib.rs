// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();

pub mod analysis;
pub mod anchors;
pub mod api_types;
pub mod baseline;
pub mod calibration;
pub mod checkpoint;
pub mod checkpoint_mmr;
pub mod codec;
pub mod collaboration;
pub mod compact_ref;
pub mod config;
pub mod continuation;
pub mod crypto;
pub mod declaration;
pub mod engine;
pub mod error;
pub mod evidence;
pub mod fingerprint;
pub mod forensics;
pub mod identity;
pub mod ipc;
pub mod jitter;
pub mod keyhierarchy;
pub mod mmr;
pub mod physics;
pub mod platform;
pub mod presence;
pub mod provenance;
pub mod report;
pub mod research;
pub mod rfc;
pub mod sealed_chain;
pub mod sealed_identity;
pub mod sentinel;
pub mod store;
pub mod timing;
pub mod tpm;
pub mod transcription;
pub mod trust_policy;
pub mod vdf;
pub mod wal;
pub mod war;
#[cfg(feature = "wld_jitter")]
pub mod wld_jitter_bridge;
pub mod writersproof;

/// Safe nanosecond timestamps, falling back to millis-derived nanos on i64 overflow (~2262+).
pub(crate) trait DateTimeNanosExt {
    fn timestamp_nanos_safe(&self) -> i64;
}

impl DateTimeNanosExt for chrono::DateTime<chrono::Utc> {
    fn timestamp_nanos_safe(&self) -> i64 {
        self.timestamp_nanos_opt()
            .unwrap_or_else(|| self.timestamp_millis().saturating_mul(1_000_000))
    }
}

/// Poison-recovering lock access for `RwLock`.
pub(crate) trait RwLockRecover<T> {
    fn read_recover(&self) -> std::sync::RwLockReadGuard<'_, T>;
    fn write_recover(&self) -> std::sync::RwLockWriteGuard<'_, T>;
}

impl<T> RwLockRecover<T> for std::sync::RwLock<T> {
    fn read_recover(&self) -> std::sync::RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(|p| p.into_inner())
    }
    fn write_recover(&self) -> std::sync::RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(|p| p.into_inner())
    }
}

/// Poison-recovering lock access for `Mutex`.
pub(crate) trait MutexRecover<T> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T> MutexRecover<T> for std::sync::Mutex<T> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|p| p.into_inner())
    }
}

pub use crate::config::{FingerprintConfig, PrivacyConfig, ResearchConfig, SentinelConfig};
pub use crate::crypto::{compute_event_hash, compute_event_hmac, derive_hmac_key};
pub use crate::identity::MnemonicHandler;
pub use crate::physics::PhysicalContext;
pub use crate::research::{
    AnonymizedSession, ResearchCollector, ResearchDataExport, ResearchUploader, UploadResult,
};
pub use crate::sentinel::{
    ChangeEvent, ChangeEventType, DaemonHandle, DaemonManager, DaemonState, DaemonStatus,
    DocumentSession, FocusEvent, FocusEventType, Sentinel, SentinelError, SessionEvent,
    SessionEventType, ShadowManager, WindowInfo,
};
pub use crate::store::{SecureEvent, SecureStore};
pub use crate::vdf::{RoughtimeClient, TimeAnchor, TimeKeeper, VdfProof};

pub use crate::collaboration::{
    CollaborationMode, CollaborationPolicy, CollaborationSection, Collaborator, CollaboratorRole,
    ContributionClaim, ContributionSummary, ContributionType, MergeEvent, MergeRecord,
    MergeStrategy, TimeInterval,
};

pub use crate::compact_ref::{
    CompactEvidenceRef, CompactMetadata, CompactRefError, CompactSummary,
};

pub use crate::continuation::{ContinuationSection, ContinuationSummary};

pub use crate::provenance::{
    DerivationClaim, DerivationType, ProvenanceLink, ProvenanceMetadata, ProvenanceSection,
};

pub use crate::trust_policy::{
    AppraisalPolicy, FactorEvidence, FactorType, PolicyMetadata, ThresholdType, TrustComputation,
    TrustFactor, TrustThreshold,
};

pub use crate::vdf::{
    AggregateError, AggregateMetadata, AggregationMethod, MerkleSample, MerkleVdfBuilder,
    MerkleVdfProof, SnarkScheme, SnarkVdfProof, VdfAggregateProof, VerificationMode,
};

pub use crate::fingerprint::{
    ActivityFingerprint, AuthorFingerprint, ConsentManager, ConsentStatus, FingerprintComparison,
    FingerprintManager, FingerprintStatus, ProfileId, VoiceFingerprint,
};

pub use crate::rfc::{
    BiologyInvariantClaim, BiologyScoringParameters, BlockchainAnchor, CalibrationAttestation,
    JitterBinding, RoughtimeSample, TimeBindingTier, TimeEvidence, TsaResponse, ValidationStatus,
    VdfProofRfc,
};

// CDDL-conformant wire format types (RFC 8949)
pub use crate::rfc::wire_types::{
    AttestationResultWire, CheckpointWire, DocumentRef as WireDocumentRef, EvidencePacketWire,
    HashAlgorithm, HashValue as WireHashValue, ProcessProof as WireProcessProof, Verdict,
    CBOR_TAG_ATTESTATION_RESULT, CBOR_TAG_EVIDENCE_PACKET as CBOR_TAG_EVIDENCE_PACKET_WIRE,
};

pub use crate::error::{Error, Result};

#[cfg(feature = "wld_jitter")]
pub use crate::wld_jitter_bridge::{
    EntropyQuality, HybridEvidence, HybridJitterSession, HybridSample, ZoneTrackingEngine,
};

/// Re-export for protocol integration.
pub use wld_protocol;

#[cfg(target_os = "macos")]
#[macro_use]
extern crate objc;
