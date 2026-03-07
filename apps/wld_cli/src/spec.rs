// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! RATS PoP spec helper functions for CLI tier/profile mapping.

/// EAT profile URI per draft-condrey-rats-pop-protocol.
pub const PROFILE_URI: &str = "urn:ietf:params:rats:eat:profile:pop:1.0";
/// CDDL: 6 => [3* checkpoint] — minimum checkpoints per evidence packet.
pub const MIN_CHECKPOINTS_PER_PACKET: usize = 3;

/// Map CLI evidence tier to CDDL content-tier integer value.
///
/// Per CDDL:
///   content-tier = &( core: 1, enhanced: 2, maximum: 3 )
///
/// CLI mapping:
///   basic    -> core (1)
///   standard -> core (1) with VDF
///   enhanced -> enhanced (2)
///   maximum  -> maximum (3)
pub fn content_tier_from_cli(tier: &str) -> u8 {
    match tier.to_lowercase().as_str() {
        "basic" => 1,
        "standard" => 1,
        "enhanced" => 2,
        "maximum" => 3,
        _ => 1,
    }
}

/// Returns the EAT profile URI (single value per draft-condrey-rats-pop-protocol).
pub fn profile_uri_from_cli(_tier: &str) -> &'static str {
    PROFILE_URI
}

/// Map CLI attestation tier string to CDDL attestation-tier integer value.
///
/// Per CDDL:
///   attestation-tier = &(
///       software-only: 1,      T1: AAL1
///       attested-software: 2,  T2: AAL2
///       hardware-bound: 3,     T3: AAL3
///       hardware-hardened: 4,  T4: LoA4
///   )
pub fn attestation_tier_value(has_tpm: bool, tpm_hardware_backed: bool) -> u8 {
    if tpm_hardware_backed {
        3
    } else if has_tpm {
        2
    } else {
        1
    }
}
