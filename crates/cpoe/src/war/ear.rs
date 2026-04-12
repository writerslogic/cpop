// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! EAR (Entity Attestation Result) types per draft-ietf-rats-ear.
//!
//! Maps CPoE's proof-of-process appraisal onto standard RATS EAR
//! structures with AR4SI trust vectors. Private-use keys 70001-70009
//! carry CPoE-specific claims.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use authorproof_protocol::rfc::wire_types::attestation::{
    AbsenceClaim, EntropyReport, ForensicSummary, ForgeryCostEstimate,
};

// Re-export identical constants and types from protocol.
pub use authorproof_protocol::war::ear::{
    SealClaims, CWT_KEY_EAT_PROFILE, CWT_KEY_IAT, CWT_KEY_SUBMODS, EAR_KEY_POLICY_ID,
    EAR_KEY_STATUS, EAR_KEY_TRUST_VECTOR, EAR_KEY_VERIFIER_ID, POP_EAR_PROFILE, POP_KEY_ABSENCE,
    POP_KEY_CHAIN_DURATION, POP_KEY_CHAIN_LENGTH, POP_KEY_ENTROPY, POP_KEY_EVIDENCE_REF,
    POP_KEY_FORENSIC, POP_KEY_FORGERY_COST, POP_KEY_SEAL, POP_KEY_WARNINGS,
};

/// AR4SI appraisal status per draft-ietf-rats-ar4si.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i8)]
pub enum Ar4siStatus {
    None = 0,
    Affirming = 2,
    Warning = 32,
    Contraindicated = 96,
}

impl Ar4siStatus {
    pub fn from_i8(v: i8) -> Self {
        match v {
            2 => Self::Affirming,
            32 => Self::Warning,
            96 => Self::Contraindicated,
            other => {
                log::warn!("Unknown AR4SI status value {other}, mapping to None");
                Self::None
            }
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Affirming => "affirming",
            Self::Warning => "warning",
            Self::Contraindicated => "contraindicated",
        }
    }
}

/// AR4SI trustworthiness vector — maps from CPoE evidence components.
///
/// Each component is a tier value from -128 to 127:
/// - 2 = affirming, 32 = warning, 96 = contraindicated, 0 = none
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustworthinessVector {
    #[serde(rename = "0")]
    pub instance_identity: i8,
    #[serde(rename = "1")]
    pub configuration: i8,
    #[serde(rename = "2")]
    pub executables: i8,
    #[serde(rename = "3")]
    pub file_system: i8,
    #[serde(rename = "4")]
    pub hardware: i8,
    #[serde(rename = "5")]
    pub runtime_opaque: i8,
    #[serde(rename = "6")]
    pub storage_opaque: i8,
    #[serde(rename = "7")]
    pub sourced_data: i8,
}

impl TrustworthinessVector {
    pub fn worst_component(&self) -> i8 {
        [
            self.instance_identity,
            self.configuration,
            self.executables,
            self.file_system,
            self.hardware,
            self.runtime_opaque,
            self.storage_opaque,
            self.sourced_data,
        ]
        .into_iter()
        .max()
        .unwrap_or(Ar4siStatus::None as i8)
    }

    pub fn overall_status(&self) -> Ar4siStatus {
        let min = self.worst_component();
        if min >= Ar4siStatus::Contraindicated as i8 {
            Ar4siStatus::Contraindicated
        } else if min >= Ar4siStatus::Warning as i8 {
            Ar4siStatus::Warning
        } else if min >= Ar4siStatus::Affirming as i8 {
            Ar4siStatus::Affirming
        } else {
            Ar4siStatus::None
        }
    }

    pub fn header_string(&self) -> String {
        format!(
            "II={} CO={} EX={} FS={} HW={} RO={} SO={} SD={}",
            self.instance_identity,
            self.configuration,
            self.executables,
            self.file_system,
            self.hardware,
            self.runtime_opaque,
            self.storage_opaque,
            self.sourced_data,
        )
    }

    pub fn parse_header(s: &str) -> Option<Self> {
        const VALID_AR4SI: &[i8] = &[0, 2, 32, 96];
        let mut vals = [0i8; 8];
        let labels = ["II=", "CO=", "EX=", "FS=", "HW=", "RO=", "SO=", "SD="];
        let parts: Vec<&str> = s.split_whitespace().collect();
        for (i, label) in labels.iter().enumerate() {
            let part = parts.iter().find(|p| p.starts_with(label))?;
            let v: i8 = part[label.len()..].parse().ok()?;
            if !VALID_AR4SI.contains(&v) {
                return None;
            }
            vals[i] = v;
        }
        Some(Self {
            instance_identity: vals[0],
            configuration: vals[1],
            executables: vals[2],
            file_system: vals[3],
            hardware: vals[4],
            runtime_opaque: vals[5],
            storage_opaque: vals[6],
            sourced_data: vals[7],
        })
    }
}

/// Verifier identity per EAR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierId {
    pub build: String,
    pub developer: String,
}

impl Default for VerifierId {
    fn default() -> Self {
        Self {
            build: format!("cpoe-engine/{}", env!("CARGO_PKG_VERSION")),
            developer: "writerslogic".to_string(),
        }
    }
}

/// Single submodule appraisal within an EAR token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarAppraisal {
    #[serde(rename = "1000")]
    pub ear_status: Ar4siStatus,

    #[serde(rename = "1001", default, skip_serializing_if = "Option::is_none")]
    pub ear_trustworthiness_vector: Option<TrustworthinessVector>,

    #[serde(rename = "1003", default, skip_serializing_if = "Option::is_none")]
    pub ear_appraisal_policy_id: Option<String>,

    #[serde(rename = "70001", default, skip_serializing_if = "Option::is_none")]
    pub pop_seal: Option<SealClaims>,

    #[serde(rename = "70002", default, skip_serializing_if = "Option::is_none")]
    pub pop_evidence_ref: Option<Vec<u8>>,

    #[serde(rename = "70003", default, skip_serializing_if = "Option::is_none")]
    pub pop_entropy_report: Option<EntropyReport>,

    #[serde(rename = "70004", default, skip_serializing_if = "Option::is_none")]
    pub pop_forgery_cost: Option<ForgeryCostEstimate>,

    #[serde(rename = "70005", default, skip_serializing_if = "Option::is_none")]
    pub pop_forensic_summary: Option<ForensicSummary>,

    #[serde(rename = "70006", default, skip_serializing_if = "Option::is_none")]
    pub pop_chain_length: Option<u64>,

    #[serde(rename = "70007", default, skip_serializing_if = "Option::is_none")]
    pub pop_chain_duration: Option<u64>,

    #[serde(rename = "70008", default, skip_serializing_if = "Option::is_none")]
    pub pop_absence_claims: Option<Vec<AbsenceClaim>>,

    #[serde(rename = "70009", default, skip_serializing_if = "Option::is_none")]
    pub pop_warnings: Option<Vec<String>>,

    #[serde(rename = "70010", default, skip_serializing_if = "Option::is_none")]
    pub pop_process_start: Option<String>,

    #[serde(rename = "70011", default, skip_serializing_if = "Option::is_none")]
    pub pop_process_end: Option<String>,
}

/// EAR token per draft-ietf-rats-ear, carrying one or more appraisals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarToken {
    #[serde(rename = "265")]
    pub eat_profile: String,

    #[serde(rename = "6")]
    pub iat: i64,

    #[serde(rename = "1004")]
    pub ear_verifier_id: VerifierId,

    #[serde(rename = "266")]
    pub submods: BTreeMap<String, EarAppraisal>,
}

impl EarToken {
    pub fn overall_status(&self) -> Ar4siStatus {
        self.submods
            .values()
            .map(|a| a.ear_status as i8)
            .max()
            .map(Ar4siStatus::from_i8)
            .unwrap_or(Ar4siStatus::None)
    }

    pub fn pop_appraisal(&self) -> Option<&EarAppraisal> {
        self.submods.get("pop")
    }
}
