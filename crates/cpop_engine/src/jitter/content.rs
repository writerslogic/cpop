// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Content-based verification and zone analysis for jitter chains.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::Error;

use super::engine::{JitterSample, TypingProfile};
use super::timestamp_nanos_u64;
use super::zones::{
    decode_zone_transition, encode_zone_transition, is_valid_zone_transition,
    text_to_zone_sequence, ZoneTransition,
};

/// Aggregate result of content-based jitter chain verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentVerificationResult {
    /// Overall validity (chain integrity AND zone compatibility).
    pub valid: bool,
    /// Whether the hash chain is internally consistent.
    pub chain_valid: bool,
    /// Whether recorded zone transitions match document content.
    pub zones_compatible: bool,
    /// Whether the typing profile appears human-plausible.
    pub profile_plausible: bool,
    /// KL divergence between expected and recorded zone distributions.
    pub zone_divergence: f64,
    /// JS divergence between expected and recorded transition histograms.
    pub transition_divergence: f64,
    /// Cosine similarity score between expected and recorded profiles.
    pub profile_score: f64,
    /// Typing profile extracted from recorded jitter samples.
    pub recorded_profile: TypingProfile,
    /// Typing profile derived from document content analysis.
    pub expected_profile: TypingProfile,
    /// Zone transition histogram extracted from recorded samples.
    pub recorded_transitions: ZoneTransitionHistogram,
    /// Zone transition histogram derived from document content.
    pub expected_transitions: ZoneTransitionHistogram,
    /// Fatal errors encountered during verification.
    pub errors: Vec<String>,
    /// Non-fatal warnings about suspicious patterns.
    pub warnings: Vec<String>,
}

/// Verify a jitter sample chain against the actual document content.
pub fn verify_with_content(samples: &[JitterSample], content: &[u8]) -> ContentVerificationResult {
    let mut result = ContentVerificationResult {
        valid: true,
        chain_valid: true,
        zones_compatible: false,
        profile_plausible: true,
        zone_divergence: 0.0,
        transition_divergence: 0.0,
        profile_score: 0.0,
        recorded_profile: TypingProfile::default(),
        expected_profile: TypingProfile::default(),
        recorded_transitions: ZoneTransitionHistogram::default(),
        expected_transitions: ZoneTransitionHistogram::default(),
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    if samples.is_empty() {
        result.valid = false;
        result.errors.push("no samples to verify".to_string());
        return result;
    }

    if let Err(err) = verify_jitter_chain(samples) {
        result.chain_valid = false;
        result.valid = false;
        result.errors.push(format!("chain integrity: {err}"));
    }

    let expected = analyze_document_zones(content);
    let recorded = extract_recorded_zones(samples);

    result.expected_profile = expected;
    result.recorded_profile = recorded;
    result.zone_divergence = zone_kl_divergence(expected, recorded);

    result.expected_transitions = expected_transition_histogram(content);
    result.recorded_transitions = extract_transition_histogram(samples);
    result.transition_divergence =
        transition_histogram_divergence(result.expected_transitions, result.recorded_transitions);

    if result.transition_divergence > 0.3 {
        result.zones_compatible = false;
        result.warnings.push(format!(
            "zone transition divergence {:.4} exceeds threshold 0.3",
            result.transition_divergence
        ));
    } else {
        result.zones_compatible = true;
    }

    result.profile_plausible = super::is_human_plausible(recorded);
    if !result.profile_plausible {
        result
            .warnings
            .push("typing profile does not appear human-plausible".to_string());
    }

    result.profile_score = super::compare_profiles(expected, recorded);
    result.valid = result.chain_valid && result.zones_compatible;
    result
}

/// Verify jitter values against a shared secret, confirming deterministic derivation.
pub fn verify_with_secret(
    samples: &[JitterSample],
    mut secret: [u8; 32],
) -> crate::error::Result<()> {
    if samples.is_empty() {
        secret.zeroize();
        return Err(Error::validation("empty sample chain"));
    }

    let mut engine = VerificationEngine {
        secret,
        ordinal: 0,
        prev_jitter: 0,
    };
    // Engine owns a copy; zeroize our stack copy
    secret.zeroize();

    for (i, sample) in samples.iter().enumerate() {
        // Producer computes jitter with pre-increment ordinal, then increments.
        // Validate ordinal matches expected post-increment value.
        let expected_ordinal = engine.ordinal + 1;
        if sample.ordinal != expected_ordinal {
            return Err(Error::validation(format!(
                "sample {i}: ordinal mismatch (expected {expected_ordinal}, got {})",
                sample.ordinal
            )));
        }

        let expected = engine.compute_expected_jitter(
            sample.doc_hash,
            sample.zone_transition,
            sample.interval_bucket,
            sample.timestamp,
        );

        if expected
            .to_be_bytes()
            .ct_eq(&sample.jitter_micros.to_be_bytes())
            .unwrap_u8()
            == 0
        {
            return Err(Error::validation(format!(
                "sample {i}: jitter value mismatch"
            )));
        }

        let expected_hash = compute_jitter_sample_hash(sample);
        if sample.sample_hash.ct_eq(&expected_hash).unwrap_u8() == 0 {
            return Err(Error::validation(format!("sample {i}: hash mismatch")));
        }

        engine.prev_jitter = sample.jitter_micros;
        engine.ordinal += 1;
    }

    Ok(())
}

pub(super) fn compute_jitter_sample_hash(sample: &JitterSample) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-jitter-sample-v2");
    hasher.update(sample.ordinal.to_be_bytes());
    hasher.update(timestamp_nanos_u64(sample.timestamp).to_be_bytes());
    hasher.update(sample.doc_hash);
    hasher.update([sample.zone_transition, sample.interval_bucket]);
    hasher.update(sample.jitter_micros.to_be_bytes());
    hasher.update(sample.clock_skew.to_be_bytes());
    hasher.finalize().into()
}

struct VerificationEngine {
    secret: [u8; 32],
    ordinal: u64,
    prev_jitter: u32,
}

impl Drop for VerificationEngine {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl VerificationEngine {
    fn compute_expected_jitter(
        &self,
        doc_hash: [u8; 32],
        zone_transition: u8,
        interval_bucket: u8,
        timestamp: DateTime<Utc>,
    ) -> u32 {
        super::compute_zone_jitter(
            &self.secret,
            self.ordinal,
            &doc_hash,
            zone_transition,
            interval_bucket,
            timestamp,
            self.prev_jitter,
        )
    }
}

/// Derive an expected typing profile from document content via zone analysis.
pub fn analyze_document_zones(content: &[u8]) -> TypingProfile {
    let transitions = text_to_zone_sequence(&String::from_utf8_lossy(content));
    let mut profile = TypingProfile::default();

    for trans in transitions {
        let bucket = 5u8;
        if trans.is_same_finger() {
            profile.same_finger_hist[bucket as usize] =
                profile.same_finger_hist[bucket as usize].saturating_add(1);
        } else if trans.is_same_hand() {
            profile.same_hand_hist[bucket as usize] =
                profile.same_hand_hist[bucket as usize].saturating_add(1);
        } else {
            profile.alternating_hist[bucket as usize] =
                profile.alternating_hist[bucket as usize].saturating_add(1);
            profile.alternating_count = profile.alternating_count.saturating_add(1);
        }
        profile.total_transitions = profile.total_transitions.saturating_add(1);
    }

    if profile.total_transitions > 0 {
        profile.hand_alternation =
            profile.alternating_count as f32 / profile.total_transitions as f32;
    }

    profile
}

/// Build a typing profile from recorded jitter samples' zone transitions.
pub fn extract_recorded_zones(samples: &[JitterSample]) -> TypingProfile {
    let mut profile = TypingProfile::default();

    for sample in samples {
        if sample.zone_transition == 0xFF {
            continue;
        }
        let (from, to) = decode_zone_transition(sample.zone_transition);
        let trans = ZoneTransition { from, to };
        let mut bucket = sample.interval_bucket;
        if bucket >= 10 {
            bucket = 9;
        }

        if trans.is_same_finger() {
            profile.same_finger_hist[bucket as usize] =
                profile.same_finger_hist[bucket as usize].saturating_add(1);
        } else if trans.is_same_hand() {
            profile.same_hand_hist[bucket as usize] =
                profile.same_hand_hist[bucket as usize].saturating_add(1);
        } else {
            profile.alternating_hist[bucket as usize] =
                profile.alternating_hist[bucket as usize].saturating_add(1);
            profile.alternating_count = profile.alternating_count.saturating_add(1);
        }
        profile.total_transitions = profile.total_transitions.saturating_add(1);
    }

    if profile.total_transitions > 0 {
        profile.hand_alternation =
            profile.alternating_count as f32 / profile.total_transitions as f32;
    }

    profile
}

/// Compute KL divergence between expected and recorded zone category distributions.
pub fn zone_kl_divergence(expected: TypingProfile, recorded: TypingProfile) -> f64 {
    let mut exp_same_finger = 0u64;
    let mut exp_same_hand = 0u64;
    let mut exp_alternating = 0u64;
    let mut rec_same_finger = 0u64;
    let mut rec_same_hand = 0u64;
    let mut rec_alternating = 0u64;

    for i in 0..10 {
        exp_same_finger += expected.same_finger_hist[i] as u64;
        exp_same_hand += expected.same_hand_hist[i] as u64;
        exp_alternating += expected.alternating_hist[i] as u64;
        rec_same_finger += recorded.same_finger_hist[i] as u64;
        rec_same_hand += recorded.same_hand_hist[i] as u64;
        rec_alternating += recorded.alternating_hist[i] as u64;
    }

    let exp_total = (exp_same_finger + exp_same_hand + exp_alternating) as f64;
    let rec_total = (rec_same_finger + rec_same_hand + rec_alternating) as f64;

    if exp_total == 0.0 || rec_total == 0.0 {
        if exp_total == 0.0 && rec_total == 0.0 {
            return 0.0;
        }
        return 10.0;
    }

    let epsilon = 0.001;
    let exp = [
        (exp_same_finger as f64 + epsilon) / (exp_total + 3.0 * epsilon),
        (exp_same_hand as f64 + epsilon) / (exp_total + 3.0 * epsilon),
        (exp_alternating as f64 + epsilon) / (exp_total + 3.0 * epsilon),
    ];
    let rec = [
        (rec_same_finger as f64 + epsilon) / (rec_total + 3.0 * epsilon),
        (rec_same_hand as f64 + epsilon) / (rec_total + 3.0 * epsilon),
        (rec_alternating as f64 + epsilon) / (rec_total + 3.0 * epsilon),
    ];

    let mut kl = 0.0;
    for i in 0..3 {
        if rec[i] > 0.0 {
            kl += rec[i] * safe_log(rec[i] / exp[i]);
        }
    }

    kl
}

/// 64-bin histogram of encoded zone transition frequencies.
#[derive(Debug, Clone, Copy)]
pub struct ZoneTransitionHistogram(pub [u32; 64]);

impl Default for ZoneTransitionHistogram {
    fn default() -> Self {
        ZoneTransitionHistogram([0u32; 64])
    }
}

impl Serialize for ZoneTransitionHistogram {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ZoneTransitionHistogram {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = Vec::<u32>::deserialize(deserializer)?;
        if values.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 histogram entries, got {}",
                values.len()
            )));
        }
        let mut array = [0u32; 64];
        array.copy_from_slice(&values);
        Ok(ZoneTransitionHistogram(array))
    }
}

/// Build a zone transition histogram from recorded jitter samples.
pub fn extract_transition_histogram(samples: &[JitterSample]) -> ZoneTransitionHistogram {
    let mut hist = [0u32; 64];
    for sample in samples {
        if is_valid_zone_transition(sample.zone_transition)
            && (sample.zone_transition as usize) < hist.len()
        {
            hist[sample.zone_transition as usize] =
                hist[sample.zone_transition as usize].saturating_add(1);
        }
    }
    ZoneTransitionHistogram(hist)
}

/// Derive an expected zone transition histogram from document content.
pub fn expected_transition_histogram(content: &[u8]) -> ZoneTransitionHistogram {
    let mut hist = [0u32; 64];
    for trans in text_to_zone_sequence(&String::from_utf8_lossy(content)) {
        let encoded = encode_zone_transition(trans.from, trans.to);
        if encoded != 0xFF {
            hist[encoded as usize] = hist[encoded as usize].saturating_add(1);
        }
    }
    ZoneTransitionHistogram(hist)
}

/// Compute Jensen-Shannon divergence between two zone transition histograms.
pub fn transition_histogram_divergence(
    expected: ZoneTransitionHistogram,
    recorded: ZoneTransitionHistogram,
) -> f64 {
    let mut exp_total = 0.0;
    let mut rec_total = 0.0;
    for i in 0..64 {
        exp_total += expected.0[i] as f64;
        rec_total += recorded.0[i] as f64;
    }

    if exp_total == 0.0 && rec_total == 0.0 {
        return 0.0;
    }
    if exp_total == 0.0 || rec_total == 0.0 {
        return 10.0;
    }

    let epsilon = 0.001 / 64.0;
    let mut js = 0.0;
    for i in 0..64 {
        let p_exp = (expected.0[i] as f64 + epsilon) / (exp_total + epsilon * 64.0);
        let p_rec = (recorded.0[i] as f64 + epsilon) / (rec_total + epsilon * 64.0);
        let p_mid = (p_exp + p_rec) / 2.0;
        if p_exp > 0.0 {
            js += 0.5 * p_exp * safe_log(p_exp / p_mid);
        }
        if p_rec > 0.0 {
            js += 0.5 * p_rec * safe_log(p_rec / p_mid);
        }
    }

    js
}

fn safe_log(x: f64) -> f64 {
    if x <= 0.0 {
        0.0
    } else {
        x.ln()
    }
}

/// Verify hash integrity, monotonic timestamps, and ordinal ordering of a jitter chain.
pub fn verify_jitter_chain(samples: &[JitterSample]) -> crate::error::Result<()> {
    if samples.is_empty() {
        return Err(Error::validation("empty sample chain"));
    }

    for i in 0..samples.len() {
        let sample = &samples[i];
        let expected = compute_jitter_sample_hash(sample);
        if sample.sample_hash.ct_eq(&expected).unwrap_u8() == 0 {
            return Err(Error::validation(format!(
                "sample {i}: sample hash mismatch"
            )));
        }
        if i > 0 {
            if sample.timestamp <= samples[i - 1].timestamp {
                return Err(Error::validation(format!(
                    "sample {i}: timestamp not monotonically increasing"
                )));
            }
            if sample.ordinal <= samples[i - 1].ordinal {
                return Err(Error::validation(format!(
                    "sample {i}: ordinal not increasing"
                )));
            }
        }
    }

    Ok(())
}
