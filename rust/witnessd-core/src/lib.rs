#[cfg(feature = "flutter")]
mod frb_generated; /* AUTO INJECTED BY flutter_rust_bridge. This line may not be accurate, and you can change it according to your needs. */
pub mod crypto;
pub mod store;
pub mod platform;
pub mod jitter;
pub mod physics;
pub mod identity;
pub mod vdf;
pub mod forensics;
pub mod api;
pub mod config;
#[cfg(feature = "flutter")]
pub mod frb;
pub mod engine;
pub mod bridge;
pub mod mmr;
pub mod checkpoint;
pub mod wal;
pub mod declaration;
pub mod presence;
pub mod keyhierarchy;
pub mod tpm;
pub mod anchors;
pub mod analysis;
pub mod evidence;
pub mod sentinel;

// Re-export common types
pub use crate::crypto::{compute_event_hash, compute_event_hmac, derive_hmac_key};
pub use crate::store::{SecureStore, SecureEvent};
pub use crate::physics::PhysicalContext;
pub use crate::vdf::{VdfProof, TimeKeeper, TimeAnchor, RoughtimeClient};
pub use crate::identity::MnemonicHandler;
pub use crate::config::SentinelConfig;
pub use crate::sentinel::{
    Sentinel, SentinelError, DaemonManager, DaemonStatus, DaemonState,
    DocumentSession, SessionEvent, SessionEventType, FocusEvent, FocusEventType,
    ChangeEvent, ChangeEventType, WindowInfo, ShadowManager,
};

#[macro_use]
extern crate objc;
