// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;

fn make_test_packet() -> Packet {
    Packet {
        document: crate::evidence::DocumentInfo {
            title: "test".to_string(),
            path: "test.txt".to_string(),
            final_hash: "a".repeat(64),
            final_size: 100,
        },
        chain_hash: "b".repeat(64),
        ..Default::default()
    }
}

#[test]
fn test_duration_check_no_vdf() {
    let packet = make_test_packet();
    let params = vdf::default_parameters();
    let mut warnings = Vec::new();
    let result = seals::verify_duration(&packet, &params, &mut warnings);
    assert!(
        result.plausible,
        "No VDF data should be plausible by default"
    );
}

#[test]
fn test_key_provenance_no_hierarchy() {
    let packet = make_test_packet();
    let mut warnings = Vec::new();
    let result = seals::verify_key_provenance(&packet, &mut warnings);
    assert!(result.hierarchy_consistent.is_none());
    assert!(result.signing_key_consistent);
    assert!(result.ratchet_monotonic);
}

#[test]
fn test_verdict_broken_structural() {
    let v = verdict::compute_verdict(
        false,
        None,
        true,
        &SealVerification {
            jitter_tag_present: None,
            entangled_binding_valid: None,
            checkpoints_checked: 0,
        },
        &DurationCheck {
            computed_min_seconds: 0.0,
            claimed_seconds: 0.0,
            ratio: 1.0,
            plausible: true,
        },
        &KeyProvenanceCheck {
            hierarchy_consistent: None,
            signing_key_consistent: true,
            ratchet_monotonic: true,
        },
        None,
        None,
    );
    assert_eq!(v, ForensicVerdict::V5ConfirmedForgery);
}

#[test]
fn test_verdict_invalid_signature() {
    let v = verdict::compute_verdict(
        true,
        Some(false),
        true,
        &SealVerification {
            jitter_tag_present: None,
            entangled_binding_valid: None,
            checkpoints_checked: 0,
        },
        &DurationCheck {
            computed_min_seconds: 0.0,
            claimed_seconds: 0.0,
            ratio: 1.0,
            plausible: true,
        },
        &KeyProvenanceCheck {
            hierarchy_consistent: None,
            signing_key_consistent: true,
            ratchet_monotonic: true,
        },
        None,
        None,
    );
    assert_eq!(v, ForensicVerdict::V5ConfirmedForgery);
}

#[test]
fn test_verdict_unsigned_packet() {
    let v = verdict::compute_verdict(
        true,
        None,
        true,
        &SealVerification {
            jitter_tag_present: None,
            entangled_binding_valid: None,
            checkpoints_checked: 0,
        },
        &DurationCheck {
            computed_min_seconds: 0.0,
            claimed_seconds: 0.0,
            ratio: 1.0,
            plausible: true,
        },
        &KeyProvenanceCheck {
            hierarchy_consistent: None,
            signing_key_consistent: true,
            ratchet_monotonic: true,
        },
        None,
        None,
    );
    assert_eq!(v, ForensicVerdict::V2LikelyHuman);
}

#[test]
fn test_verdict_no_vdf_data_is_suspicious_not_synthetic() {
    // Checkpoints exist but carry zero VDF iterations: ratio=0.0, plausible=false.
    // Should be V3Suspicious (missing proof), not V4LikelySynthetic.
    let v = verdict::compute_verdict(
        true,
        Some(true),
        true,
        &SealVerification {
            jitter_tag_present: Some(true),
            entangled_binding_valid: None,
            checkpoints_checked: 2,
        },
        &DurationCheck {
            computed_min_seconds: 0.0,
            claimed_seconds: 60.0,
            ratio: 0.0,
            plausible: false,
        },
        &KeyProvenanceCheck {
            hierarchy_consistent: None,
            signing_key_consistent: true,
            ratchet_monotonic: true,
        },
        None,
        None,
    );
    assert_eq!(v, ForensicVerdict::V3Suspicious);
}
