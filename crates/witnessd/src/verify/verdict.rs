// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Verdict computation from all verification phases.

use crate::forensics::{ForensicMetrics, PerCheckpointResult};
use authorproof_protocol::forensics::ForensicVerdict;

use super::{
    DurationCheck, KeyProvenanceCheck, SealVerification, SWF_DURATION_RATIO_MAX,
    SWF_DURATION_RATIO_MIN,
};

/// Compute overall verdict from all verification phases.
#[allow(clippy::too_many_arguments)]
pub(super) fn compute_verdict(
    structural: bool,
    signature: Option<bool>,
    declaration_valid: bool,
    seals: &SealVerification,
    duration: &DurationCheck,
    key_provenance: &KeyProvenanceCheck,
    forensics: Option<&ForensicMetrics>,
    per_checkpoint: Option<&PerCheckpointResult>,
) -> ForensicVerdict {
    // Broken structural integrity → confirmed forgery
    if !structural {
        return ForensicVerdict::V5ConfirmedForgery;
    }

    // Invalid signature → confirmed forgery
    if signature == Some(false) {
        return ForensicVerdict::V5ConfirmedForgery;
    }

    // Failed seal verification → confirmed forgery
    if seals.jitter_tag_present == Some(false) || seals.entangled_binding_valid == Some(false) {
        return ForensicVerdict::V5ConfirmedForgery;
    }

    // Implausible duration (< 0.5x minimum) → likely synthetic.
    // Only when VDF data exists; ratio=0.0 from missing VDF falls through to V3Suspicious.
    if !duration.plausible
        && duration.computed_min_seconds > 0.0
        && duration.ratio < SWF_DURATION_RATIO_MIN
    {
        return ForensicVerdict::V4LikelySynthetic;
    }

    // Key provenance failure → likely synthetic
    if key_provenance.hierarchy_consistent == Some(false)
        || !key_provenance.ratchet_monotonic
        || !key_provenance.signing_key_consistent
    {
        return ForensicVerdict::V4LikelySynthetic;
    }

    // Duration suspicious (> 3x) → suspicious — check before forensics deferral
    // so an inflated duration cannot be masked by a passing forensic verdict.
    if !duration.plausible && duration.ratio > SWF_DURATION_RATIO_MAX {
        return ForensicVerdict::V3Suspicious;
    }

    // Per-checkpoint flags → suspicious
    if let Some(pcp) = per_checkpoint {
        if pcp.suspicious {
            return ForensicVerdict::V3Suspicious;
        }
    }

    // H-001 (verify): Invalid declaration downgrades the verdict.
    if !declaration_valid {
        // Declaration is missing or has an invalid signature; the best
        // attainable verdict is V2LikelyHuman.
    }

    // H-003 (verify): Cap forensic verdict when seals are structural-only
    // (no HMAC re-derivation) or declaration is invalid, because the
    // verification strength is insufficient for V1VerifiedHuman.
    let seals_structural_only = seals.entangled_binding_valid.is_none();
    let capped = !declaration_valid || seals_structural_only;

    // No VDF proof data present: without time-hardness evidence, the best
    // attainable verdict is V2LikelyHuman regardless of forensic score.
    // This also covers zero-checkpoint packets where computed_min_seconds == 0.0
    // and plausible == true (no checkpoints means no time-hardness proof at all).
    let no_vdf = duration.computed_min_seconds == 0.0;

    // Defer to forensic analysis verdict if available, but respect caps.
    if let Some(fm) = forensics {
        let fv = fm.map_to_protocol_verdict();
        if (no_vdf || capped) && fv == ForensicVerdict::V1VerifiedHuman {
            return ForensicVerdict::V2LikelyHuman;
        }
        return fv;
    }

    // Duration implausible for other reasons (e.g., missing VDF data) → suspicious
    if !duration.plausible {
        return ForensicVerdict::V3Suspicious;
    }

    // Unsigned packet → can only be "likely human" at best
    if signature.is_none() {
        return ForensicVerdict::V2LikelyHuman;
    }

    // Signed packet with valid signature, plausible duration, consistent key
    // provenance, and no suspicious flags → verified human.
    // A packet without VDF proof data (no_vdf) cannot reach V1VerifiedHuman.
    // Capped when seals are structural-only or declaration is invalid.
    if !no_vdf
        && !capped
        && signature == Some(true)
        && key_provenance.signing_key_consistent
        && key_provenance.hierarchy_consistent != Some(false)
    {
        return ForensicVerdict::V1VerifiedHuman;
    }

    ForensicVerdict::V2LikelyHuman
}
