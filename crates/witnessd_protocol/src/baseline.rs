// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};

/// Progressive confidence tier for baseline maturity.
///
/// Baselines strengthen as the system observes more writing sessions:
/// - PopulationReference (1-4 sessions): Human vs machine only
/// - Emerging (5-9 sessions): Meaningful author consistency
/// - Established (10-19 sessions): Author identity distinguishable
/// - Mature (20+ sessions): Full authorship attribution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum ConfidenceTier {
    PopulationReference = 1,
    Emerging = 2,
    Established = 3,
    Mature = 4,
}

impl ConfidenceTier {
    /// Determine confidence tier from session count.
    pub fn from_session_count(count: u64) -> Self {
        match count {
            0..=4 => Self::PopulationReference,
            5..=9 => Self::Emerging,
            10..=19 => Self::Established,
            _ => Self::Mature,
        }
    }
}

/// Statistics for streaming metrics using Welford's algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingStats {
    #[serde(rename = "1")]
    pub count: u64,
    #[serde(rename = "2")]
    pub mean: f64,
    #[serde(rename = "3")]
    pub m2: f64,
    #[serde(rename = "4")]
    pub min: f64,
    #[serde(rename = "5")]
    pub max: f64,
}

/// Summary of behavioral metrics for a single session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBehavioralSummary {
    /// 9-bin IKI histogram (edges: 0, 50, 100, 150, 200, 300, 500, 1000, 2000ms)
    #[serde(rename = "1")]
    pub iki_histogram: [f64; 9],
    /// Coefficient of Variation for IKI
    #[serde(rename = "2")]
    pub iki_cv: f64,
    /// Hurst exponent for long-range dependency
    #[serde(rename = "3")]
    pub hurst: f64,
    /// Frequency of cognitive pauses
    #[serde(rename = "4")]
    pub pause_frequency: f64,
    #[serde(rename = "5")]
    pub duration_secs: u64,
    #[serde(rename = "6")]
    pub keystroke_count: u64,
}

/// Portable summary of an author's behavioral baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDigest {
    #[serde(rename = "1")]
    pub version: u32,
    #[serde(rename = "2")]
    pub session_count: u64,
    #[serde(rename = "3")]
    pub total_keystrokes: u64,
    #[serde(rename = "4")]
    pub iki_stats: StreamingStats,
    #[serde(rename = "5")]
    pub cv_stats: StreamingStats,
    #[serde(rename = "6")]
    pub hurst_stats: StreamingStats,
    #[serde(rename = "7")]
    pub aggregate_iki_histogram: [f64; 9],
    #[serde(rename = "8")]
    pub pause_stats: StreamingStats,
    /// MMR root over previous session evidence hashes
    #[serde(rename = "9", with = "serde_bytes")]
    pub session_merkle_root: Vec<u8>,
    #[serde(rename = "10")]
    pub confidence_tier: ConfidenceTier,
    #[serde(rename = "11")]
    pub computed_at: u64,
    /// SHA-256(Ed25519 public key)
    #[serde(rename = "12", with = "serde_bytes")]
    pub identity_fingerprint: Vec<u8>,
}

/// Baseline verification data included in an evidence packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineVerification {
    /// The current baseline digest (None during enrollment).
    #[serde(rename = "1", default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<BaselineDigest>,
    /// Behavioral summary of the current session.
    #[serde(rename = "2")]
    pub session_summary: SessionBehavioralSummary,
    /// COSE_Sign1 signature over the CBOR-encoded digest.
    #[serde(
        rename = "3",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub digest_signature: Option<Vec<u8>>,
}

impl Default for SessionBehavioralSummary {
    fn default() -> Self {
        Self {
            iki_histogram: [0.0; 9],
            iki_cv: 0.0,
            hurst: 0.5,
            pause_frequency: 0.0,
            duration_secs: 0,
            keystroke_count: 0,
        }
    }
}

mod serde_bytes_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(val: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match val {
            Some(v) => serde_bytes::serialize(v, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<serde_bytes::ByteBuf>::deserialize(deserializer)
            .map(|opt| opt.map(|buf| buf.into_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_tier_from_session_count() {
        assert_eq!(
            ConfidenceTier::from_session_count(0),
            ConfidenceTier::PopulationReference
        );
        assert_eq!(
            ConfidenceTier::from_session_count(4),
            ConfidenceTier::PopulationReference
        );
        assert_eq!(
            ConfidenceTier::from_session_count(5),
            ConfidenceTier::Emerging
        );
        assert_eq!(
            ConfidenceTier::from_session_count(10),
            ConfidenceTier::Established
        );
        assert_eq!(
            ConfidenceTier::from_session_count(20),
            ConfidenceTier::Mature
        );
        assert_eq!(
            ConfidenceTier::from_session_count(100),
            ConfidenceTier::Mature
        );
    }

    #[test]
    fn test_baseline_verification_cbor_roundtrip_enrollment() {
        let summary = SessionBehavioralSummary {
            iki_histogram: [0.1, 0.2, 0.15, 0.1, 0.1, 0.15, 0.1, 0.05, 0.05],
            iki_cv: 0.45,
            hurst: 0.72,
            pause_frequency: 3.5,
            duration_secs: 1800,
            keystroke_count: 5000,
        };

        let bv = BaselineVerification {
            digest: None,
            session_summary: summary,
            digest_signature: None,
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&bv, &mut buf).expect("CBOR encode");
        let decoded: BaselineVerification = ciborium::from_reader(&buf[..]).expect("CBOR decode");

        assert!(decoded.digest.is_none());
        assert!((decoded.session_summary.iki_cv - 0.45).abs() < 1e-10);
        assert_eq!(decoded.session_summary.keystroke_count, 5000);
        // Enrollment packet should be compact
        assert!(
            buf.len() < 200,
            "Enrollment wire overhead: {} bytes",
            buf.len()
        );
    }

    #[test]
    fn test_baseline_verification_cbor_roundtrip_with_digest() {
        let digest = BaselineDigest {
            version: 1,
            session_count: 10,
            total_keystrokes: 50000,
            iki_stats: StreamingStats {
                count: 10,
                mean: 150.0,
                m2: 500.0,
                min: 80.0,
                max: 300.0,
            },
            cv_stats: StreamingStats {
                count: 10,
                mean: 0.45,
                m2: 0.02,
                min: 0.3,
                max: 0.6,
            },
            hurst_stats: StreamingStats {
                count: 10,
                mean: 0.72,
                m2: 0.01,
                min: 0.65,
                max: 0.8,
            },
            aggregate_iki_histogram: [0.1, 0.2, 0.15, 0.1, 0.1, 0.15, 0.1, 0.05, 0.05],
            pause_stats: StreamingStats {
                count: 10,
                mean: 3.5,
                m2: 2.0,
                min: 1.0,
                max: 7.0,
            },
            session_merkle_root: vec![0xAA; 32],
            confidence_tier: ConfidenceTier::Established,
            computed_at: 1708790400,
            identity_fingerprint: vec![0xBB; 32],
        };

        let bv = BaselineVerification {
            digest: Some(digest),
            session_summary: SessionBehavioralSummary::default(),
            digest_signature: Some(vec![0xCC; 64]),
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&bv, &mut buf).expect("CBOR encode");
        let decoded: BaselineVerification = ciborium::from_reader(&buf[..]).expect("CBOR decode");

        let d = decoded.digest.as_ref().unwrap();
        assert_eq!(d.session_count, 10);
        assert_eq!(d.confidence_tier, ConfidenceTier::Established);
        assert_eq!(d.identity_fingerprint, vec![0xBB; 32]);
        assert_eq!(decoded.digest_signature.as_ref().unwrap().len(), 64);
        // Full packet with digest should be under 600 bytes
        assert!(buf.len() < 600, "Full wire overhead: {} bytes", buf.len());
    }
}
