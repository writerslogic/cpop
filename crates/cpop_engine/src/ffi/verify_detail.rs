// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::detect_attestation_tier_info;
use crate::verify::{full_verify, VerifyOptions};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiOrdinalGap {
    pub expected: u64,
    pub actual: u64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCheckpointFlag {
    pub ordinal: u64,
    pub flagged: bool,
    pub flag_reason: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiVerifyDetail {
    pub success: bool,
    pub overall_valid: bool,
    pub signature_valid: bool,
    pub chain_integrity: bool,
    pub checkpoint_count: u32,
    pub swf_iterations_per_second: u64,
    pub attestation_tier: u8,
    pub attestation_tier_label: String,
    pub unsigned_checkpoints: Vec<u64>,
    pub ordinal_gaps: Vec<FfiOrdinalGap>,
    pub warnings: Vec<String>,
    pub checkpoint_flags: Vec<FfiCheckpointFlag>,
    pub error_message: Option<String>,
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_verify_evidence_detailed(path: String) -> FfiVerifyDetail {
    let (_, tier_num, tier_label) = detect_attestation_tier_info();

    let err = |msg: String| FfiVerifyDetail {
        success: false,
        overall_valid: false,
        signature_valid: false,
        chain_integrity: false,
        checkpoint_count: 0,
        swf_iterations_per_second: 0,
        attestation_tier: tier_num,
        attestation_tier_label: tier_label.clone(),
        unsigned_checkpoints: vec![],
        ordinal_gaps: vec![],
        warnings: vec![],
        checkpoint_flags: vec![],
        error_message: Some(msg),
    };

    let path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p,
        Err(e) => return err(e),
    };

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => return err(format!("Failed to read file: {e}")),
    };

    let packet = match crate::evidence::Packet::decode(&data) {
        Ok(p) => p,
        Err(e) => return err(format!("Failed to decode evidence: {e}")),
    };

    let checkpoint_count = packet.checkpoints.len() as u32;
    let swf_ips = packet.vdf_params.iterations_per_second;

    let opts = VerifyOptions {
        vdf_params: packet.vdf_params,
        expected_nonce: None,
        run_forensics: true,
    };

    let result = full_verify(&packet, &opts);

    let signature_valid = result.signature.unwrap_or(false);
    let chain_integrity = result.structural;
    let overall_valid = chain_integrity
        && signature_valid
        && result.duration.plausible
        && result.key_provenance.signing_key_consistent;

    let unsigned_checkpoints: Vec<u64> = if packet.key_hierarchy.is_none() {
        (0..checkpoint_count as u64).collect()
    } else {
        let signed_ordinals: std::collections::HashSet<u64> = packet
            .key_hierarchy
            .as_ref()
            .map(|kh| kh.checkpoint_signatures.iter().map(|s| s.ordinal).collect())
            .unwrap_or_default();
        (0..checkpoint_count as u64)
            .filter(|o| !signed_ordinals.contains(o))
            .collect()
    };

    let mut ordinal_gaps = Vec::new();
    for (i, cp) in packet.checkpoints.iter().enumerate() {
        let expected = i as u64;
        if cp.ordinal != expected {
            ordinal_gaps.push(FfiOrdinalGap {
                expected,
                actual: cp.ordinal,
            });
        }
    }

    let checkpoint_flags: Vec<FfiCheckpointFlag> = result
        .per_checkpoint
        .as_ref()
        .map(|pcp| {
            pcp.checkpoint_flags
                .iter()
                .map(|cf| {
                    let reason = if cf.flagged {
                        let mut reasons = Vec::new();
                        if cf.timing_cv > 1.5 {
                            reasons.push(format!("high timing CV ({:.2})", cf.timing_cv));
                        }
                        if cf.max_velocity_bps > 50.0 {
                            reasons.push(format!("high velocity ({:.0} B/s)", cf.max_velocity_bps));
                        }
                        if cf.all_append {
                            reasons.push("all-append pattern".to_string());
                        }
                        if reasons.is_empty() {
                            Some("flagged".to_string())
                        } else {
                            Some(reasons.join("; "))
                        }
                    } else {
                        None
                    };
                    FfiCheckpointFlag {
                        ordinal: cf.ordinal,
                        flagged: cf.flagged,
                        flag_reason: reason,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    FfiVerifyDetail {
        success: true,
        overall_valid,
        signature_valid,
        chain_integrity,
        checkpoint_count,
        swf_iterations_per_second: swf_ips,
        attestation_tier: tier_num,
        attestation_tier_label: tier_label,
        unsigned_checkpoints,
        ordinal_gaps,
        warnings: result.warnings,
        checkpoint_flags,
        error_message: None,
    }
}
