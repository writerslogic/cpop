// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! RATS PoP spec helper functions for CLI tier/profile mapping.

/// Profile URI for core evidence tier (draft-condrey-rats-pop).
pub const PROFILE_URI_CORE: &str = "urn:ietf:params:rats:pop:profile:core";
/// Profile URI for enhanced evidence tier (draft-condrey-rats-pop).
pub const PROFILE_URI_ENHANCED: &str = "urn:ietf:params:rats:pop:profile:enhanced";
/// Profile URI for maximum evidence tier (draft-condrey-rats-pop).
pub const PROFILE_URI_MAXIMUM: &str = "urn:ietf:params:rats:pop:profile:maximum";
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
        "basic" => 1,    // core
        "standard" => 1, // core (with VDF)
        "enhanced" => 2, // enhanced
        "maximum" => 3,  // maximum
        _ => 1,          // default to core
    }
}

/// Map CLI evidence tier to the corresponding profile URI.
pub fn profile_uri_from_cli(tier: &str) -> &'static str {
    match tier.to_lowercase().as_str() {
        "basic" => PROFILE_URI_CORE,
        "standard" => PROFILE_URI_CORE,
        "enhanced" => PROFILE_URI_ENHANCED,
        "maximum" => PROFILE_URI_MAXIMUM,
        _ => PROFILE_URI_CORE,
    }
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
        // Hardware-backed attestation: T3 or T4 depending on features
        3 // hardware-bound (T3)
    } else if has_tpm {
        2 // attested-software (T2)
    } else {
        1 // software-only (T1)
    }
}
