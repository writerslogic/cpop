// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub mod active_probes;
pub mod behavioral_fingerprint;
pub mod error_topology;
pub mod hurst;
pub mod labyrinth;
pub mod perplexity;
pub mod pink_noise;
pub(crate) mod stats;

pub use active_probes::{
    analyze_galton_invariant, analyze_reflex_gate, ActiveProbeResults, GaltonInvariantResult,
    ProbeSample, ReflexGateResult,
};
pub use behavioral_fingerprint::{BehavioralFingerprint, ForgeryAnalysis, ForgeryFlag};
pub use error_topology::{
    analyze_error_topology, ErrorDistribution, ErrorTopology, EventType, TopologyEvent,
};
pub use hurst::{calculate_hurst_dfa, calculate_hurst_rs, HurstAnalysis, HurstInterpretation};
pub use labyrinth::{analyze_labyrinth, LabyrinthAnalysis, LabyrinthParams};
pub use pink_noise::{analyze_pink_noise, generate_pink_noise, NoiseType, PinkNoiseAnalysis};
