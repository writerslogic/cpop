// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub mod aggregation;
pub mod params;
pub mod proof;
pub mod roughtime_client;
pub mod swf_argon2;
pub mod timekeeper;

pub use aggregation::{
    AggregateError, AggregateMetadata, AggregationMethod, MerkleSample, MerkleVdfBuilder,
    MerkleVdfProof, SnarkScheme, SnarkVdfProof, VdfAggregateProof, VerificationMode,
};
pub use params::{
    calibrate, chain_input, chain_input_entangled, compute, compute_iterations, default_parameters,
    swf_seed_core, swf_seed_enhanced, swf_seed_genesis, verify, verify_with_progress, Parameters,
};
pub use proof::VdfProof;

// CDDL spec calls this "Sequential Work Function (SWF)"; module stays `vdf` for compat
/// Alias for `Parameters` matching the CDDL spec naming.
pub type SwfParameters = Parameters;
/// Alias for `VdfProof` matching the CDDL spec naming.
pub type SwfProof = VdfProof;
pub use roughtime_client::RoughtimeClient;
pub use swf_argon2::{
    enhanced_params, maximum_params, params_for_tier, Argon2SwfParams, Argon2SwfProof,
};
pub use timekeeper::{TimeAnchor, TimeKeeper};
