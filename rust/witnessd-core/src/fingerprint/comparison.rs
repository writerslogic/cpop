//! Fingerprint Comparison and Profile Matching
//!
//! This module provides algorithms for comparing fingerprints
//! and determining authorship probability.

use super::{AuthorFingerprint, ProfileId};
use serde::{Deserialize, Serialize};

// =============================================================================
// Comparison Result
// =============================================================================

/// Result of comparing two fingerprints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintComparison {
    /// First profile ID
    pub profile_a: ProfileId,
    /// Second profile ID
    pub profile_b: ProfileId,
    /// Overall similarity score (0.0 - 1.0)
    pub similarity: f64,
    /// Activity similarity score
    pub activity_similarity: f64,
    /// Voice similarity score (if both have voice data)
    pub voice_similarity: Option<f64>,
    /// Confidence in the comparison
    pub confidence: f64,
    /// Verdict based on similarity
    pub verdict: ComparisonVerdict,
    /// Detailed component scores
    pub components: ComparisonComponents,
}

/// Verdict from fingerprint comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonVerdict {
    /// Very likely same author (similarity > 0.85)
    SameAuthor,
    /// Probably same author (similarity 0.7-0.85)
    LikelySameAuthor,
    /// Inconclusive (similarity 0.4-0.7)
    Inconclusive,
    /// Probably different authors (similarity 0.2-0.4)
    LikelyDifferentAuthors,
    /// Very likely different authors (similarity < 0.2)
    DifferentAuthors,
}

impl ComparisonVerdict {
    /// Determine verdict from similarity score.
    pub fn from_similarity(similarity: f64) -> Self {
        if similarity > 0.85 {
            Self::SameAuthor
        } else if similarity > 0.70 {
            Self::LikelySameAuthor
        } else if similarity > 0.40 {
            Self::Inconclusive
        } else if similarity > 0.20 {
            Self::LikelyDifferentAuthors
        } else {
            Self::DifferentAuthors
        }
    }

    /// Get human-readable description.
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

/// Detailed component scores from comparison.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComparisonComponents {
    /// IKI distribution similarity
    pub iki_similarity: f64,
    /// Zone profile similarity
    pub zone_similarity: f64,
    /// Pause signature similarity
    pub pause_similarity: f64,
    /// Word length similarity (voice)
    pub word_length_similarity: Option<f64>,
    /// Punctuation similarity (voice)
    pub punctuation_similarity: Option<f64>,
    /// N-gram similarity (voice)
    pub ngram_similarity: Option<f64>,
}

// =============================================================================
// Comparison Functions
// =============================================================================

/// Compare two author fingerprints.
pub fn compare_fingerprints(a: &AuthorFingerprint, b: &AuthorFingerprint) -> FingerprintComparison {
    // Activity similarity
    let activity_similarity = a.activity.similarity(&b.activity);

    // Component scores
    let iki_sim = a
        .activity
        .iki_distribution
        .similarity(&b.activity.iki_distribution);
    let zone_sim = a.activity.zone_profile.similarity(&b.activity.zone_profile);
    let pause_sim = a
        .activity
        .pause_signature
        .similarity(&b.activity.pause_signature);

    // Voice similarity (if both have voice data)
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

    // Overall similarity
    let similarity = if let Some(voice_sim) = voice_similarity {
        // Weight activity more heavily (60/40)
        activity_similarity * 0.6 + voice_sim * 0.4
    } else {
        activity_similarity
    };

    // Confidence based on sample counts
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

/// Calculate confidence based on sample count.
fn confidence_from_samples(samples: u64) -> f64 {
    // Confidence increases with samples, asymptotic to 1.0
    // 100 samples ≈ 0.5, 1000 samples ≈ 0.9
    1.0 - 1.0 / (1.0 + samples as f64 / 100.0)
}

// =============================================================================
// Profile Matcher
// =============================================================================

/// Matcher for finding similar profiles in a collection.
pub struct ProfileMatcher {
    /// Minimum similarity threshold
    threshold: f64,
    /// Maximum results to return
    max_results: usize,
}

impl ProfileMatcher {
    /// Create a new profile matcher.
    pub fn new() -> Self {
        Self {
            threshold: 0.5,
            max_results: 10,
        }
    }

    /// Set the similarity threshold.
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Set the maximum number of results.
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = max;
        self
    }

    /// Find matching profiles for a given fingerprint.
    pub fn find_matches(
        &self,
        target: &AuthorFingerprint,
        candidates: &[AuthorFingerprint],
    ) -> Vec<MatchResult> {
        let mut results: Vec<_> = candidates
            .iter()
            .filter(|c| c.id != target.id) // Don't match self
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

        // Sort by similarity (descending)
        results.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Limit results
        results.truncate(self.max_results);

        results
    }

    /// Find the best match for a fingerprint.
    pub fn find_best_match(
        &self,
        target: &AuthorFingerprint,
        candidates: &[AuthorFingerprint],
    ) -> Option<MatchResult> {
        self.find_matches(target, candidates).into_iter().next()
    }

    /// Verify if a fingerprint matches a specific profile.
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

/// Result of finding a matching profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    /// Matched profile ID
    pub profile_id: ProfileId,
    /// Similarity score
    pub similarity: f64,
    /// Confidence level
    pub confidence: f64,
    /// Verdict
    pub verdict: ComparisonVerdict,
}

/// Result of verifying a match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the fingerprints match (above threshold)
    pub matches: bool,
    /// Similarity score
    pub similarity: f64,
    /// Confidence level
    pub confidence: f64,
    /// Verdict
    pub verdict: ComparisonVerdict,
}

// =============================================================================
// Batch Comparison
// =============================================================================

/// Compare multiple fingerprints and find clusters.
pub struct BatchComparator {
    /// Similarity threshold for clustering
    cluster_threshold: f64,
}

impl BatchComparator {
    /// Create a new batch comparator.
    pub fn new() -> Self {
        Self {
            cluster_threshold: 0.7,
        }
    }

    /// Set the clustering threshold.
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.cluster_threshold = threshold;
        self
    }

    /// Find clusters of similar fingerprints.
    pub fn find_clusters(&self, fingerprints: &[AuthorFingerprint]) -> Vec<Cluster> {
        let n = fingerprints.len();
        if n == 0 {
            return Vec::new();
        }

        // Simple greedy clustering
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

            // Find similar fingerprints
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

            // Calculate average internal similarity
            if cluster.members.len() > 1 {
                let mut total_sim = 0.0;
                let mut count = 0;
                for (idx, m1) in cluster.members.iter().enumerate() {
                    for m2 in cluster.members.iter().skip(idx + 1) {
                        if let (Some(f1), Some(f2)) = (
                            fingerprints.iter().find(|f| &f.id == m1),
                            fingerprints.iter().find(|f| &f.id == m2),
                        ) {
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

/// A cluster of similar fingerprints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cluster {
    /// Representative profile ID
    pub representative: ProfileId,
    /// All member profile IDs
    pub members: Vec<ProfileId>,
    /// Average internal similarity
    pub avg_internal_similarity: f64,
}

// =============================================================================
// Tests
// =============================================================================

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
            ComparisonVerdict::from_similarity(0.75),
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

        // Should find all candidates (threshold 0)
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn test_confidence_from_samples() {
        assert!(confidence_from_samples(0) < 0.1);
        assert!(confidence_from_samples(100) > 0.4 && confidence_from_samples(100) < 0.6);
        assert!(confidence_from_samples(1000) > 0.8);
    }
}
