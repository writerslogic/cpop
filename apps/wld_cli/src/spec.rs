// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub const PROFILE_URI: &str = "urn:ietf:params:pop:profile:1.0";
pub const MIN_CHECKPOINTS_PER_PACKET: usize = 3;

/// Map CLI tier name to CDDL content-tier: basic/standard=1, enhanced=2, maximum=3.
pub fn content_tier_from_cli(tier: &str) -> u8 {
    match tier.to_lowercase().as_str() {
        "basic" => 1,
        "standard" => 1,
        "enhanced" => 2,
        "maximum" => 3,
        _ => 1,
    }
}

pub fn profile_uri_from_cli(_tier: &str) -> &'static str {
    PROFILE_URI
}

/// Map TPM capabilities to attestation tier: T1 (software), T2 (TPM), T3 (hardware-backed).
pub fn attestation_tier_value(has_tpm: bool, tpm_hardware_backed: bool) -> u8 {
    if tpm_hardware_backed {
        3
    } else if has_tpm {
        2
    } else {
        1
    }
}
