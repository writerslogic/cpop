// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub mod active_probes;
pub mod behavioral_fingerprint;
pub mod error_topology;
pub mod hurst;
pub mod iki_compression;
pub mod labyrinth;
pub mod lyapunov;
pub mod perplexity;
pub mod pink_noise;
pub mod snr;
pub(crate) mod stats;

pub use active_probes::{
    analyze_galton_invariant, analyze_reflex_gate, ActiveProbeResults, GaltonInvariantResult,
    ProbeSample, ReflexGateResult,
};
pub use behavioral_fingerprint::{BehavioralFingerprint, ForgeryAnalysis, ForgeryFlag};
pub use error_topology::{
    analyze_error_topology, ErrorDistribution, ErrorTopology, EventType, TopologyEvent,
};
pub use hurst::{compute_hurst_dfa, compute_hurst_rs, HurstAnalysis, HurstInterpretation};
pub use iki_compression::{analyze_iki_compression, IkiCompressionAnalysis};
pub use labyrinth::{analyze_labyrinth, LabyrinthAnalysis, LabyrinthParams};
pub use lyapunov::{analyze_lyapunov, LyapunovAnalysis};
pub use pink_noise::{analyze_pink_noise, generate_pink_noise, NoiseType, PinkNoiseAnalysis};
pub use snr::{analyze_snr, SnrAnalysis};
