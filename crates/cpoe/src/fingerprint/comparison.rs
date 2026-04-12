// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Fingerprint comparison, authorship probability, and profile clustering.

use super::{AuthorFingerprint, ProfileId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Similarity above this threshold yields a SameAuthor verdict.
const SAME_AUTHOR_THRESHOLD: f64 = 0.80;
/// Similarity above this threshold yields a LikelySameAuthor verdict.
const LIKELY_SAME_THRESHOLD: f64 = 0.60;
/// Similarity above this threshold yields an Inconclusive verdict.
const INCONCLUSIVE_THRESHOLD: f64 = 0.40;
/// Similarity above this threshold yields a LikelyDifferentAuthors verdict.
const LIKELY_DIFFERENT_THRESHOLD: f64 = 0.20;

/// Confidence scales linearly with sample count, saturating at this value.
pub(crate) const CONFIDENCE_SATURATION_SAMPLES: f64 = 200.0;

/// Pairwise fingerprint comparison result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintComparison {
    pub profile_a: ProfileId,
    pub profile_b: ProfileId,
    /// 0.0 - 1.0
    pub similarity: f64,
    pub activity_similarity: f64,
    pub voice_similarity: Option<f64>,
    pub confidence: f64,
    pub verdict: ComparisonVerdict,
    pub components: ComparisonComponents,
}

/// Similarity-based authorship verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonVerdict {
    SameAuthor,
    LikelySameAuthor,
    Inconclusive,
    LikelyDifferentAuthors,
    DifferentAuthors,
}

impl ComparisonVerdict {
    /// Classify a similarity score into a verdict category.
    pub fn from_similarity(similarity: f64) -> Self {
        if similarity > SAME_AUTHOR_THRESHOLD {
            Self::SameAuthor
        } else if similarity > LIKELY_SAME_THRESHOLD {
            Self::LikelySameAuthor
        } else if similarity > INCONCLUSIVE_THRESHOLD {
            Self::Inconclusive
        } else if similarity > LIKELY_DIFFERENT_THRESHOLD {
            Self::LikelyDifferentAuthors
        } else {
            Self::DifferentAuthors
        }
    }

    /// Return a human-readable description of this verdict.
    pub fn description(&self) -> &'static str {
        match self {
            Self::SameAuthor => "Very likely the same author",
            Self::LikelySameAuthor => "Probably the same author",
            Self::Inconclusive => "Results inconclusive",
            Self::LikelyDifferentAuthors => "Probably different authors",
            Self::DifferentAuthors => "Very likely different authors",
        }
    }
}

/// Per-dimension similarity breakdown.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComparisonComponents {
    pub iki_similarity: f64,
    pub zone_similarity: f64,
    pub pause_similarity: f64,
    pub word_length_similarity: Option<f64>,
    pub punctuation_similarity: Option<f64>,
    pub ngram_similarity: Option<f64>,
}

/// Full pairwise comparison of two author fingerprints.
pub fn compare_fingerprints(a: &AuthorFingerprint, b: &AuthorFingerprint) -> FingerprintComparison {
    let activity_similarity = a.activity.similarity(&b.activity);

    let iki_sim = a
        .activity
        .iki_distribution
        .similarity(&b.activity.iki_distribution);
    let zone_sim = a.activity.zone_profile.similarity(&b.activity.zone_profile);
    let pause_sim = a
        .activity
        .pause_signature
        .similarity(&b.activity.pause_signature);

    let (voice_similarity, word_len_sim, punct_sim, ngram_sim) =
        if let (Some(va), Some(vb)) = (&a.voice, &b.voice) {
            let sim = va.similarity(vb);
            let word_len = super::voice::histogram_similarity(
                &va.word_length_distribution,
                &vb.word_length_distribution,
            );
            let punct = va
                .punctuation_signature
                .similarity(&vb.punctuation_signature);
            let ngram = va.ngram_signature.similarity(&vb.ngram_signature);
            (Some(sim), Some(word_len), Some(punct), Some(ngram))
        } else {
            (None, None, None, None)
        };

    let similarity = if let Some(voice_sim) = voice_similarity {
        activity_similarity * 0.6 + voice_sim * 0.4
    } else {
        activity_similarity
    };

    let min_samples = a.sample_count.min(b.sample_count);
    let confidence = confidence_from_samples(min_samples);

    FingerprintComparison {
        profile_a: a.id.clone(),
        profile_b: b.id.clone(),
        similarity,
        activity_similarity,
        voice_similarity,
        confidence,
        verdict: ComparisonVerdict::from_similarity(similarity),
        components: ComparisonComponents {
            iki_similarity: iki_sim,
            zone_similarity: zone_sim,
            pause_similarity: pause_sim,
            word_length_similarity: word_len_sim,
            punctuation_similarity: punct_sim,
            ngram_similarity: ngram_sim,
        },
    }
}

/// Linear confidence saturating at `CONFIDENCE_SATURATION_SAMPLES`.
fn confidence_from_samples(samples: u64) -> f64 {
    (samples as f64 / CONFIDENCE_SATURATION_SAMPLES).min(1.0)
}

#[derive(Debug)]
/// Threshold-based matcher for finding similar profiles.
pub struct ProfileMatcher {
    threshold: f64,
    max_results: usize,
}

impl ProfileMatcher {
    /// Default threshold: 0.5, max results: 10.
    pub fn new() -> Self {
        Self {
            threshold: 0.5,
            max_results: 10,
        }
    }

    /// Set the minimum similarity threshold (clamped to 0.0-1.0).
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = crate::utils::Probability::clamp(threshold).get();
        self
    }

    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = max;
        self
    }

    /// Return candidates above threshold, sorted by descending similarity.
    pub fn find_matches(
        &self,
        target: &AuthorFingerprint,
        candidates: &[AuthorFingerprint],
    ) -> Vec<MatchResult> {
        let mut results: Vec<_> = candidates
            .iter()
            .filter(|c| c.id != target.id)
            .map(|candidate| {
                let comparison = compare_fingerprints(target, candidate);
                MatchResult {
                    profile_id: candidate.id.clone(),
                    similarity: comparison.similarity,
                    confidence: comparison.confidence,
                    verdict: comparison.verdict,
                }
            })
            .filter(|r| r.similarity >= self.threshold)
            .collect();

        results.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results.truncate(self.max_results);

        results
    }

    /// Return the single highest-similarity match, if any.
    pub fn find_best_match(
        &self,
        target: &AuthorFingerprint,
        candidates: &[AuthorFingerprint],
    ) -> Option<MatchResult> {
        self.find_matches(target, candidates).into_iter().next()
    }

    /// 1:1 verification against a specific profile.
    pub fn verify_match(
        &self,
        target: &AuthorFingerprint,
        candidate: &AuthorFingerprint,
    ) -> VerificationResult {
        let comparison = compare_fingerprints(target, candidate);

        VerificationResult {
            matches: comparison.similarity >= self.threshold,
            similarity: comparison.similarity,
            confidence: comparison.confidence,
            verdict: comparison.verdict,
        }
    }
}

impl Default for ProfileMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Single match from a profile search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub profile_id: ProfileId,
    pub similarity: f64,
    pub confidence: f64,
    pub verdict: ComparisonVerdict,
}

/// 1:1 verification outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub matches: bool,
    pub similarity: f64,
    pub confidence: f64,
    pub verdict: ComparisonVerdict,
}

#[derive(Debug)]
/// Single-linkage clustering of fingerprints by similarity.
pub struct BatchComparator {
    cluster_threshold: f64,
}

impl BatchComparator {
    /// Default clustering threshold: 0.7.
    pub fn new() -> Self {
        Self {
            cluster_threshold: 0.7,
        }
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.cluster_threshold = threshold;
        self
    }

    /// Greedy leader-based clustering. O(n^2) pairwise comparisons.
    ///
    /// Truncates to 500 fingerprints with a warning if the input exceeds
    /// that limit. Callers with large datasets should sample first.
    pub fn find_clusters(&self, fingerprints: &[AuthorFingerprint]) -> Vec<Cluster> {
        let n = fingerprints.len();
        if n == 0 {
            return Vec::new();
        }
        if n > 500 {
            log::warn!(
                "find_clusters: {} fingerprints exceeds 500 limit, truncating",
                n
            );
            return self.find_clusters(&fingerprints[..500]);
        }

        // O(1) lookup by ProfileId, avoiding repeated linear scans.
        let fp_by_id: HashMap<&ProfileId, &AuthorFingerprint> =
            fingerprints.iter().map(|f| (&f.id, f)).collect();

        let mut assigned = vec![false; n];
        let mut clusters = Vec::new();

        for i in 0..n {
            if assigned[i] {
                continue;
            }

            let mut cluster = Cluster {
                representative: fingerprints[i].id.clone(),
                members: vec![fingerprints[i].id.clone()],
                avg_internal_similarity: 1.0,
            };
            assigned[i] = true;

            for j in (i + 1)..n {
                if assigned[j] {
                    continue;
                }

                let comparison = compare_fingerprints(&fingerprints[i], &fingerprints[j]);
                if comparison.similarity >= self.cluster_threshold {
                    cluster.members.push(fingerprints[j].id.clone());
                    assigned[j] = true;
                }
            }

            if cluster.members.len() > 1 {
                let mut total_sim = 0.0;
                let mut count = 0;
                for (idx, m1) in cluster.members.iter().enumerate() {
                    for m2 in cluster.members.iter().skip(idx + 1) {
                        if let (Some(&f1), Some(&f2)) = (fp_by_id.get(m1), fp_by_id.get(m2)) {
                            total_sim += compare_fingerprints(f1, f2).similarity;
                            count += 1;
                        }
                    }
                }
                if count > 0 {
                    cluster.avg_internal_similarity = total_sim / count as f64;
                }
            }

            clusters.push(cluster);
        }

        clusters
    }
}

impl Default for BatchComparator {
    fn default() -> Self {
        Self::new()
    }
}

/// Group of fingerprints above the clustering threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cluster {
    pub representative: ProfileId,
    pub members: Vec<ProfileId>,
    pub avg_internal_similarity: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::activity::ActivityFingerprint;

    fn make_fingerprint(id: &str, sample_count: u64) -> AuthorFingerprint {
        let mut fp = AuthorFingerprint::with_id(id.to_string(), ActivityFingerprint::default());
        fp.sample_count = sample_count;
        fp.update_confidence();
        fp
    }

    #[test]
    fn test_verdict_from_similarity() {
        assert_eq!(
            ComparisonVerdict::from_similarity(0.9),
            ComparisonVerdict::SameAuthor
        );
        assert_eq!(
            ComparisonVerdict::from_similarity(0.70),
            ComparisonVerdict::LikelySameAuthor
        );
        assert_eq!(
            ComparisonVerdict::from_similarity(0.5),
            ComparisonVerdict::Inconclusive
        );
        assert_eq!(
            ComparisonVerdict::from_similarity(0.3),
            ComparisonVerdict::LikelyDifferentAuthors
        );
        assert_eq!(
            ComparisonVerdict::from_similarity(0.1),
            ComparisonVerdict::DifferentAuthors
        );
    }

    #[test]
    fn test_compare_fingerprints() {
        let fp1 = make_fingerprint("a", 100);
        let fp2 = make_fingerprint("b", 100);

        let comparison = compare_fingerprints(&fp1, &fp2);

        assert_eq!(comparison.profile_a, "a");
        assert_eq!(comparison.profile_b, "b");
        assert!(comparison.similarity >= 0.0 && comparison.similarity <= 1.0);
    }

    #[test]
    fn test_profile_matcher() {
        let target = make_fingerprint("target", 100);
        let candidates = vec![
            make_fingerprint("a", 100),
            make_fingerprint("b", 100),
            make_fingerprint("c", 100),
        ];

        let matcher = ProfileMatcher::new().with_threshold(0.0);
        let matches = matcher.find_matches(&target, &candidates);

        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn test_confidence_from_samples() {
        assert_eq!(confidence_from_samples(0), 0.0);
        assert!((confidence_from_samples(100) - 0.5).abs() < f64::EPSILON);
        assert_eq!(confidence_from_samples(200), 1.0);
        assert_eq!(confidence_from_samples(1000), 1.0);
    }
}
