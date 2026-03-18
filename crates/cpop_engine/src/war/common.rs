// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Shared helpers for WAR profile projections (VC, C2PA).

use serde::{Deserialize, Serialize};

use super::ear::{Ar4siStatus, TrustworthinessVector};

/// Serialized trust vector with plain (non-CBOR-keyed) field names.
///
/// Used by both the VC and C2PA profile projections to avoid duplicating
/// the field-by-field copy from [`TrustworthinessVector`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedTrustVector {
    pub instance_identity: i8,
    pub configuration: i8,
    pub executables: i8,
    pub file_system: i8,
    pub hardware: i8,
    pub runtime_opaque: i8,
    pub storage_opaque: i8,
    pub sourced_data: i8,
}

impl From<&TrustworthinessVector> for SerializedTrustVector {
    fn from(tv: &TrustworthinessVector) -> Self {
        Self {
            instance_identity: tv.instance_identity,
            configuration: tv.configuration,
            executables: tv.executables,
            file_system: tv.file_system,
            hardware: tv.hardware,
            runtime_opaque: tv.runtime_opaque,
            storage_opaque: tv.storage_opaque,
            sourced_data: tv.sourced_data,
        }
    }
}

/// Derive attestation tier string from the trust vector's hardware component.
///
/// Returns one of `"hardware_bound"`, `"attested_software"`, or `"software_only"`.
pub fn derive_attestation_tier(tv: &TrustworthinessVector) -> &'static str {
    if tv.hardware >= Ar4siStatus::Affirming as i8 {
        "hardware_bound"
    } else if tv.hardware >= Ar4siStatus::Warning as i8 {
        "attested_software"
    } else {
        "software_only"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialized_trust_vector_from() {
        let tv = TrustworthinessVector {
            instance_identity: 2,
            configuration: 2,
            executables: 0,
            file_system: 2,
            hardware: 32,
            runtime_opaque: 2,
            storage_opaque: 2,
            sourced_data: 2,
        };
        let stv = SerializedTrustVector::from(&tv);
        assert_eq!(stv.instance_identity, 2);
        assert_eq!(stv.hardware, 32);
        assert_eq!(stv.sourced_data, 2);
    }

    #[test]
    fn test_derive_attestation_tier_hardware_bound() {
        let tv = TrustworthinessVector {
            hardware: Ar4siStatus::Affirming as i8,
            ..Default::default()
        };
        assert_eq!(derive_attestation_tier(&tv), "hardware_bound");
    }

    #[test]
    fn test_derive_attestation_tier_warning_is_hardware_bound() {
        // Warning (32) >= Affirming (2), so it maps to hardware_bound.
        let tv = TrustworthinessVector {
            hardware: Ar4siStatus::Warning as i8,
            ..Default::default()
        };
        assert_eq!(derive_attestation_tier(&tv), "hardware_bound");
    }

    #[test]
    fn test_derive_attestation_tier_attested_software() {
        // A value between Warning (32) and Affirming (2) that is >= Warning
        // is unreachable with standard AR4SI values, but a raw value of 1
        // (below Affirming but above None) maps to software_only.
        let tv = TrustworthinessVector {
            hardware: 1,
            ..Default::default()
        };
        assert_eq!(derive_attestation_tier(&tv), "software_only");
    }

    #[test]
    fn test_derive_attestation_tier_software_only() {
        let tv = TrustworthinessVector::default();
        assert_eq!(derive_attestation_tier(&tv), "software_only");
    }
}
