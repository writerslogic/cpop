// SPDX-License-Identifier: Apache-2.0

// NOTE: cpop_engine extends Block with evidence: Option<Box<Packet>>
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// WAR block format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Version {
    /// Legacy parallel computation (WAR/1.0)
    V1_0,
    /// Entangled computation with jitter binding (WAR/1.1)
    V1_1,
    /// EAR appraisal with attestation results (WAR/2.0)
    V2_0,
}

impl Version {
    pub fn as_str(&self) -> &'static str {
        match self {
            Version::V1_0 => "WAR/1.0",
            Version::V1_1 => "WAR/1.1",
            Version::V2_0 => "WAR/2.0",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "WAR/1.0" => Some(Version::V1_0),
            "WAR/1.1" => Some(Version::V1_1),
            "WAR/2.0" => Some(Version::V2_0),
            _ => None,
        }
    }
}

/// A WAR evidence block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub version: Version,
    /// From declaration or public key fingerprint.
    pub author: String,
    /// SHA-256 of final content.
    pub document_id: [u8; 32],
    pub timestamp: DateTime<Utc>,
    pub statement: String,
    pub seal: Seal,
    /// H3 signature is valid.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub signed: bool,
    /// Freshness nonce for replay attack prevention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_nonce: Option<[u8; 32]>,
    /// EAR appraisal token (WAR/2.0+)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ear: Option<super::ear::EarToken>,
}

/// The cryptographic seal binding all evidence together.
#[derive(Debug, Clone)]
pub struct Seal {
    /// H1: SHA-256(doc || checkpoint_root || declaration)
    pub h1: [u8; 32],
    /// H2: SHA-256(H1 || jitter || pubkey)
    pub h2: [u8; 32],
    /// H3: SHA-256(H2 || vdf_output || doc)
    pub h3: [u8; 32],
    /// H4: Ed25519 signature of H3
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
}

impl Serialize for Seal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Seal", 5)?;
        state.serialize_field("h1", &hex::encode(self.h1))?;
        state.serialize_field("h2", &hex::encode(self.h2))?;
        state.serialize_field("h3", &hex::encode(self.h3))?;
        state.serialize_field("signature", &hex::encode(self.signature))?;
        state.serialize_field("public_key", &hex::encode(self.public_key))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Seal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SealHelper {
            h1: String,
            h2: String,
            h3: String,
            signature: String,
            public_key: String,
        }

        let helper = SealHelper::deserialize(deserializer)?;

        let h1 = hex::decode(&helper.h1).map_err(serde::de::Error::custom)?;
        let h2 = hex::decode(&helper.h2).map_err(serde::de::Error::custom)?;
        let h3 = hex::decode(&helper.h3).map_err(serde::de::Error::custom)?;
        let signature = hex::decode(&helper.signature).map_err(serde::de::Error::custom)?;
        let public_key = hex::decode(&helper.public_key).map_err(serde::de::Error::custom)?;

        if h1.len() != 32 || h2.len() != 32 || h3.len() != 32 {
            return Err(serde::de::Error::custom("hash must be 32 bytes"));
        }
        if signature.len() != 64 {
            return Err(serde::de::Error::custom("signature must be 64 bytes"));
        }
        if public_key.len() != 32 {
            return Err(serde::de::Error::custom("public key must be 32 bytes"));
        }

        let mut seal = Seal {
            h1: [0u8; 32],
            h2: [0u8; 32],
            h3: [0u8; 32],
            signature: [0u8; 64],
            public_key: [0u8; 32],
        };
        seal.h1.copy_from_slice(&h1);
        seal.h2.copy_from_slice(&h2);
        seal.h3.copy_from_slice(&h3);
        seal.signature.copy_from_slice(&signature);
        seal.public_key.copy_from_slice(&public_key);
        Ok(seal)
    }
}

/// Result of WAR block verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub valid: bool,
    pub checks: Vec<CheckResult>,
    pub summary: String,
    pub details: ForensicDetails,
}

/// Individual verification check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// e.g. "seal_signature", "hash_chain"
    pub name: String,
    pub passed: bool,
    pub message: String,
}

/// Detailed forensic information from verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicDetails {
    pub version: String,
    pub author: String,
    pub document_id: String,
    pub timestamp: DateTime<Utc>,
    pub components: Vec<String>,
    /// Total elapsed time from VDF proofs.
    pub elapsed_time_secs: Option<f64>,
    pub checkpoint_count: Option<usize>,
    pub keystroke_count: Option<u64>,
    pub has_jitter_seal: bool,
    pub has_hardware_attestation: bool,
    pub has_verifier_nonce: bool,
    /// Hex-encoded, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_nonce: Option<String>,
}
