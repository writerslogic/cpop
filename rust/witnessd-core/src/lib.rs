pub mod analysis;
pub mod anchors;
pub mod api;
pub mod bridge;
pub mod checkpoint;
pub mod collaboration;
pub mod compact_ref;
pub mod config;
pub mod continuation;
pub mod crypto;
pub mod declaration;
pub mod engine;
pub mod evidence;
pub mod fingerprint;
pub mod forensics;
#[cfg(feature = "flutter")]
pub mod frb;
#[cfg(feature = "flutter")]
mod frb_generated; /* AUTO INJECTED BY flutter_rust_bridge. This line may not be accurate, and you can change it according to your needs. */
pub mod identity;
pub mod ipc;
pub mod jitter;
pub mod keyhierarchy;
pub mod mmr;
pub mod physics;
#[cfg(feature = "physjitter")]
pub mod physjitter_bridge;
pub mod platform;
pub mod presence;
pub mod provenance;
pub mod research;
pub mod sentinel;
pub mod store;
pub mod timing;
pub mod tpm;
pub mod trust_policy;
pub mod vdf;
pub mod wal;
pub mod war;

// Re-export common types
pub use crate::config::{FingerprintConfig, PrivacyConfig, ResearchConfig, SentinelConfig};
pub use crate::crypto::{compute_event_hash, compute_event_hmac, derive_hmac_key};
pub use crate::identity::MnemonicHandler;
pub use crate::physics::PhysicalContext;
pub use crate::research::{
    AnonymizedSession, ResearchCollector, ResearchDataExport, ResearchUploader, UploadResult,
};
pub use crate::sentinel::{
    ChangeEvent, ChangeEventType, DaemonManager, DaemonState, DaemonStatus, DocumentSession,
    FocusEvent, FocusEventType, Sentinel, SentinelError, SessionEvent, SessionEventType,
    ShadowManager, WindowInfo,
};
pub use crate::store::{SecureEvent, SecureStore};
pub use crate::vdf::{RoughtimeClient, TimeAnchor, TimeKeeper, VdfProof};

// Re-export collaboration types
pub use crate::collaboration::{
    CollaborationMode, CollaborationPolicy, CollaborationSection, Collaborator, CollaboratorRole,
    ContributionClaim, ContributionSummary, ContributionType, MergeEvent, MergeRecord,
    MergeStrategy, TimeInterval,
};

// Re-export compact reference types
pub use crate::compact_ref::{
    CompactEvidenceRef, CompactMetadata, CompactRefBuilder, CompactRefError, CompactSummary,
};

// Re-export continuation types
pub use crate::continuation::{ContinuationSection, ContinuationSummary};

// Re-export provenance types
pub use crate::provenance::{
    DerivationClaim, DerivationType, ProvenanceLink, ProvenanceMetadata, ProvenanceSection,
};

// Re-export trust policy types
pub use crate::trust_policy::{
    AppraisalPolicy, FactorEvidence, FactorType, PolicyMetadata, ThresholdType, TrustComputation,
    TrustFactor, TrustThreshold,
};

// Re-export VDF aggregation types
pub use crate::vdf::{
    AggregateError, AggregateMetadata, AggregationMethod, MerkleSample, MerkleVdfBuilder,
    MerkleVdfProof, SnarkScheme, SnarkVdfProof, VdfAggregateProof, VerificationMode,
};

// Re-export fingerprint types
pub use crate::fingerprint::{
    ActivityFingerprint, AuthorFingerprint, ConsentManager, ConsentStatus, FingerprintComparison,
    FingerprintManager, FingerprintStatus, ProfileId, VoiceFingerprint,
};

#[cfg(feature = "physjitter")]
pub use crate::physjitter_bridge::{
    EntropyQuality, HybridEvidence, HybridJitterSession, HybridSample, ZoneTrackingEngine,
};

#[cfg(target_os = "macos")]
#[macro_use]
extern crate objc;
