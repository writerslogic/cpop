// SPDX-License-Identifier: Apache-2.0

//! EAR (Entity Attestation Result) types per draft-ietf-rats-ear.
//!
//! Maps CPOP's proof-of-process appraisal onto standard RATS EAR
//! structures with AR4SI trust vectors. Private-use keys 70001-70009
//! carry CPOP-specific claims.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::rfc::wire_types::attestation::{
    AbsenceClaim, EntropyReport, ForensicSummary, ForgeryCostEstimate,
};

/// EAT profile URI per draft-condrey-rats-pop-protocol.
pub const POP_EAR_PROFILE: &str = "urn:ietf:params:rats:eat:profile:pop:1.0";

pub const CWT_KEY_IAT: i64 = 6;
pub const CWT_KEY_EAT_PROFILE: i64 = 265;
pub const CWT_KEY_SUBMODS: i64 = 266;
pub const EAR_KEY_STATUS: i64 = 1000;
pub const EAR_KEY_TRUST_VECTOR: i64 = 1001;
pub const EAR_KEY_POLICY_ID: i64 = 1003;
pub const EAR_KEY_VERIFIER_ID: i64 = 1004;

pub const POP_KEY_SEAL: i64 = 70001;
pub const POP_KEY_EVIDENCE_REF: i64 = 70002;
pub const POP_KEY_ENTROPY: i64 = 70003;
pub const POP_KEY_FORGERY_COST: i64 = 70004;
pub const POP_KEY_FORENSIC: i64 = 70005;
pub const POP_KEY_CHAIN_LENGTH: i64 = 70006;
pub const POP_KEY_CHAIN_DURATION: i64 = 70007;
pub const POP_KEY_ABSENCE: i64 = 70008;
pub const POP_KEY_WARNINGS: i64 = 70009;

/// AR4SI appraisal status per draft-ietf-rats-ar4si.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i8)]
pub enum Ar4siStatus {
    /// No status determined
    None = 0,
    /// Evidence affirms trustworthiness
    Affirming = 2,
    /// Evidence contains warnings
    Warning = 32,
    /// Evidence contradicts trustworthiness
    Contraindicated = 96,
}

impl Ar4siStatus {
    /// Convert a raw i8 value to the corresponding status variant.
    pub fn from_i8(v: i8) -> Self {
        match v {
            2 => Self::Affirming,
            32 => Self::Warning,
            96 => Self::Contraindicated,
            _ => Self::None,
        }
    }

    /// Return the lowercase string name of this status.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Affirming => "affirming",
            Self::Warning => "warning",
            Self::Contraindicated => "contraindicated",
        }
    }
}

/// AR4SI trustworthiness vector — maps from CPOP evidence components.
///
/// Each component is a tier value from -128 to 127:
/// - 2 = affirming, 32 = warning, 96 = contraindicated, 0 = none
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustworthinessVector {
    /// Hardware attestation tier (TPM/Secure Enclave)
    #[serde(rename = "0")]
    pub instance_identity: i8,
    /// Software configuration integrity
    #[serde(rename = "1")]
    pub configuration: i8,
    /// Binary attestation (TPM quote)
    #[serde(rename = "2")]
    pub executables: i8,
    /// Document hash chain integrity (H1/H2/H3)
    #[serde(rename = "3")]
    pub file_system: i8,
    /// TPM/Secure Enclave tier
    #[serde(rename = "4")]
    pub hardware: i8,
    /// VDF proof strength
    #[serde(rename = "5")]
    pub runtime_opaque: i8,
    /// Key hierarchy integrity
    #[serde(rename = "6")]
    pub storage_opaque: i8,
    /// Behavioral entropy + jitter
    #[serde(rename = "7")]
    pub sourced_data: i8,
}

impl TrustworthinessVector {
    /// Returns the minimum component value (weakest link).
    pub fn min_component(&self) -> i8 {
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
        .min()
        .unwrap_or(0)
    }

    /// Derive overall AR4SI status from the weakest component.
    pub fn overall_status(&self) -> Ar4siStatus {
        let min = self.min_component();
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

    /// Format as compact header string: "II=2 CO=2 EX=0 FS=2 HW=2 RO=2 SO=2 SD=2"
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

    /// Parse from header string format.
    pub fn parse_header(s: &str) -> Option<Self> {
        let mut vals = [0i8; 8];
        let labels = ["II=", "CO=", "EX=", "FS=", "HW=", "RO=", "SO=", "SD="];
        for (i, label) in labels.iter().enumerate() {
            let part = s.split_whitespace().find(|p| p.starts_with(label))?;
            vals[i] = part[label.len()..].parse().ok()?;
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
    /// Build identifier string (e.g. "cpop-engine/0.3.6")
    pub build: String,
    /// Developer/organization name
    pub developer: String,
}

impl Default for VerifierId {
    fn default() -> Self {
        Self {
            build: format!("cpop-engine/{}", env!("CARGO_PKG_VERSION")),
            developer: "writerslogic".to_string(),
        }
    }
}

/// Seal claims extracted from a WAR block for embedding in EAR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealClaims {
    /// H1: document/checkpoint/declaration binding hash
    #[serde(with = "hex_bytes_32")]
    pub h1: [u8; 32],
    /// H2: jitter/identity binding hash
    #[serde(with = "hex_bytes_32")]
    pub h2: [u8; 32],
    /// H3: VDF/document binding hash (signed)
    #[serde(with = "hex_bytes_32")]
    pub h3: [u8; 32],
    /// Ed25519 signature over H3
    #[serde(with = "hex_bytes_64")]
    pub signature: [u8; 64],
    /// Author's Ed25519 public key
    #[serde(with = "hex_bytes_32")]
    pub public_key: [u8; 32],
}

/// Single submodule appraisal within an EAR token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarAppraisal {
    /// AR4SI status
    #[serde(rename = "1000")]
    pub ear_status: Ar4siStatus,

    /// Trustworthiness vector
    #[serde(rename = "1001", default, skip_serializing_if = "Option::is_none")]
    pub ear_trustworthiness_vector: Option<TrustworthinessVector>,

    /// Appraisal policy ID
    #[serde(rename = "1003", default, skip_serializing_if = "Option::is_none")]
    pub ear_appraisal_policy_id: Option<String>,

    /// WAR seal claims
    #[serde(rename = "70001", default, skip_serializing_if = "Option::is_none")]
    pub pop_seal: Option<SealClaims>,

    /// SHA-256 of evidence packet
    #[serde(rename = "70002", default, skip_serializing_if = "Option::is_none")]
    pub pop_evidence_ref: Option<Vec<u8>>,

    /// Entropy assessment report
    #[serde(rename = "70003", default, skip_serializing_if = "Option::is_none")]
    pub pop_entropy_report: Option<EntropyReport>,

    /// Forgery cost estimate
    #[serde(rename = "70004", default, skip_serializing_if = "Option::is_none")]
    pub pop_forgery_cost: Option<ForgeryCostEstimate>,

    /// Forensic assessment summary
    #[serde(rename = "70005", default, skip_serializing_if = "Option::is_none")]
    pub pop_forensic_summary: Option<ForensicSummary>,

    /// Checkpoint chain length
    #[serde(rename = "70006", default, skip_serializing_if = "Option::is_none")]
    pub pop_chain_length: Option<u64>,

    /// Chain duration (seconds)
    #[serde(rename = "70007", default, skip_serializing_if = "Option::is_none")]
    pub pop_chain_duration: Option<u64>,

    /// Absence claims
    #[serde(rename = "70008", default, skip_serializing_if = "Option::is_none")]
    pub pop_absence_claims: Option<Vec<AbsenceClaim>>,

    /// Warning messages
    #[serde(rename = "70009", default, skip_serializing_if = "Option::is_none")]
    pub pop_warnings: Option<Vec<String>>,
}

/// EAR token per draft-ietf-rats-ear, carrying one or more appraisals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarToken {
    /// EAT profile URI (CWT key 265)
    #[serde(rename = "265")]
    pub eat_profile: String,

    /// Issued-at timestamp, epoch seconds (CWT key 6)
    #[serde(rename = "6")]
    pub iat: i64,

    /// Verifier identity (key 1004)
    #[serde(rename = "1004")]
    pub ear_verifier_id: VerifierId,

    /// Submodule appraisals keyed by name (key 266)
    #[serde(rename = "266")]
    pub submods: BTreeMap<String, EarAppraisal>,
}

impl EarToken {
    /// Overall status: the worst (lowest) status across all submodule appraisals.
    pub fn overall_status(&self) -> Ar4siStatus {
        self.submods
            .values()
            .map(|a| a.ear_status as i8)
            .min()
            .map(Ar4siStatus::from_i8)
            .unwrap_or(Ar4siStatus::None)
    }

    pub fn pop_appraisal(&self) -> Option<&EarAppraisal> {
        self.submods.get("pop")
    }
}

mod hex_bytes_32 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

mod hex_bytes_64 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}
