// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Collaborative authorship with per-contributor independent attestations.
//!
//! Each collaborator signs their own attestation (public key + role + checkpoint ranges),
//! so verifiers can confirm participation without shared signing keys.
//!
//! # Privacy Considerations
//!
//! - Public keys may be linkable across documents
//! - Active periods reveal contributor work schedules
//! - Contribution percentages may be contentious

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Collaboration mode between authors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollaborationMode {
    /// One active author at a time
    Sequential,
    /// Concurrent editing, merged
    Parallel,
    /// Primary author + contributors
    Delegated,
    /// Author + reviewers/editors
    PeerReview,
}

/// Collaborator's role in the work
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollaboratorRole {
    /// Main/lead author
    PrimaryAuthor,
    /// Equal contributor
    CoAuthor,
    /// Section/chapter contributor
    ContributingAuthor,
    /// Editorial contributions
    Editor,
    /// Review comments incorporated
    Reviewer,
    /// Data, code, figures
    TechnicalContributor,
    /// Translation work
    Translator,
}

/// Kind of contribution made
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionType {
    /// New text/content
    OriginalContent,
    /// Revisions to existing content
    Editing,
    /// Research contribution
    Research,
    /// Data/analysis contribution
    DataAnalysis,
    /// Visual elements
    FiguresTables,
    /// Code contributions
    Code,
    /// Review that influenced content
    ReviewFeedback,
    /// Organization/structure
    Structural,
}

/// Merge strategy for combining contributions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeStrategy {
    /// Sections appended in order
    SequentialAppend,
    /// Content merged throughout
    Interleaved,
    /// Conflicts manually resolved
    ConflictResolved,
    /// Automated merge tool
    Automated,
}

/// Time interval of collaborator activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeInterval {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Aggregate statistics for a collaborator's contributions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionSummary {
    pub checkpoints_authored: u32,
    pub chars_added: u64,
    pub chars_deleted: u64,
    pub active_time_seconds: f64,

    /// 0.0--1.0
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_contribution_pct: Option<f32>,
}

/// Individual collaborator record with attestation signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collaborator {
    /// Hex-encoded or PEM public key
    pub public_key: String,
    pub role: CollaboratorRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// External identifier (email, ORCID, etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    pub active_periods: Vec<TimeInterval>,
    /// Inclusive (start, end) checkpoint ranges authored
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_ranges: Option<Vec<(u32, u32)>>,
    /// Signature over this collaborator's attestation.
    ///
    /// **Note:** Verification of this signature is deferred until a multi-party
    /// attestation verification flow is implemented. Currently stored but not
    /// cryptographically validated on deserialization.
    pub attestation_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contribution_summary: Option<ContributionSummary>,
}

/// Detailed contribution claim linking a contributor to specific work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionClaim {
    pub contribution_type: ContributionType,
    /// Public key referencing a `Collaborator`
    pub contributor_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_indices: Option<Vec<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// 0.0--1.0
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extent: Option<f32>,
}

/// Record of a single merge operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeEvent {
    pub merge_time: DateTime<Utc>,
    pub resulting_checkpoint: u32,
    pub merged_contributor_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<MergeStrategy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_note: Option<String>,
}

/// Ordered log of merge operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeRecord {
    pub merges: Vec<MergeEvent>,
}

/// Governance policy for collaboration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_approvers_for_merge: Option<u32>,
    #[serde(default)]
    pub requires_all_signatures: bool,
    /// URI to external policy document
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
}

/// Collaboration section embedded in an Evidence packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationSection {
    pub mode: CollaborationMode,
    pub participants: Vec<Collaborator>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributions: Vec<ContributionClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_record: Option<MergeRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<CollaborationPolicy>,
}

impl CollaborationSection {
    /// Create an empty collaboration section with the given mode.
    pub fn new(mode: CollaborationMode) -> Self {
        Self {
            mode,
            participants: Vec::new(),
            contributions: Vec::new(),
            merge_record: None,
            policy: None,
        }
    }

    /// Append a collaborator to the participant list.
    pub fn add_participant(mut self, collaborator: Collaborator) -> Self {
        self.participants.push(collaborator);
        self
    }

    /// Append a contribution claim.
    pub fn add_contribution(mut self, claim: ContributionClaim) -> Self {
        self.contributions.push(claim);
        self
    }

    /// Attach a merge record.
    pub fn with_merge_record(mut self, record: MergeRecord) -> Self {
        self.merge_record = Some(record);
        self
    }

    /// Attach a governance policy.
    pub fn with_policy(mut self, policy: CollaborationPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Verify all checkpoint indices `[0, total_checkpoints)` are claimed by at least one participant.
    ///
    /// Returns an error if any range has start > end or if any checkpoints are uncovered.
    /// Ranges extending beyond `total_checkpoints` are clamped with a warning log.
    pub fn validate_coverage(&self, total_checkpoints: u32) -> Result<(), String> {
        const MAX_CHECKPOINTS: u32 = 1_000_000;
        if total_checkpoints > MAX_CHECKPOINTS {
            return Err(format!(
                "total_checkpoints {} exceeds maximum allowed {}",
                total_checkpoints, MAX_CHECKPOINTS
            ));
        }
        let mut covered = vec![false; total_checkpoints as usize];

        for participant in &self.participants {
            if let Some(ref ranges) = participant.checkpoint_ranges {
                for (start, end) in ranges {
                    // AUD-187: Reject inverted ranges instead of silently ignoring them
                    if start > end {
                        return Err(format!(
                            "invalid checkpoint range ({}, {}): start exceeds end",
                            start, end
                        ));
                    }
                    // AUD-188: Reject out-of-bounds ranges
                    if *end >= total_checkpoints {
                        return Err(format!(
                            "checkpoint range ({}, {}) exceeds total {}",
                            start, end, total_checkpoints
                        ));
                    }
                    let clamped_end = *end;
                    for i in *start..=clamped_end {
                        if (i as usize) < covered.len() {
                            covered[i as usize] = true;
                        }
                    }
                }
            }
        }

        let uncovered: Vec<usize> = covered
            .iter()
            .enumerate()
            .filter(|(_, &c)| !c)
            .map(|(i, _)| i)
            .collect();

        if uncovered.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Checkpoints not covered by any participant: {:?}",
                uncovered
            ))
        }
    }

    /// Return the number of participants.
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Filter participants by role.
    pub fn participants_by_role(&self, role: CollaboratorRole) -> Vec<&Collaborator> {
        self.participants
            .iter()
            .filter(|p| p.role == role)
            .collect()
    }
}

impl Collaborator {
    /// Create a collaborator with the required fields.
    pub fn new(public_key: String, role: CollaboratorRole, signature: String) -> Self {
        Self {
            public_key,
            role,
            display_name: None,
            identifier: None,
            active_periods: Vec::new(),
            checkpoint_ranges: None,
            attestation_signature: signature,
            contribution_summary: None,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Set the external identifier (email, ORCID, etc.).
    pub fn with_identifier(mut self, id: impl Into<String>) -> Self {
        self.identifier = Some(id.into());
        self
    }

    /// Append an active time interval.
    pub fn add_active_period(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.active_periods.push(TimeInterval { start, end });
        self
    }

    /// Set the inclusive checkpoint ranges authored by this collaborator.
    pub fn with_checkpoint_ranges(mut self, ranges: Vec<(u32, u32)>) -> Self {
        self.checkpoint_ranges = Some(ranges);
        self
    }

    /// Attach aggregate contribution statistics.
    pub fn with_summary(mut self, summary: ContributionSummary) -> Self {
        self.contribution_summary = Some(summary);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collaboration_section_builder() {
        let section = CollaborationSection::new(CollaborationMode::Parallel)
            .add_participant(
                Collaborator::new(
                    "pubkey1".to_string(),
                    CollaboratorRole::PrimaryAuthor,
                    "sig1".to_string(),
                )
                .with_name("Alice")
                .with_checkpoint_ranges(vec![(0, 10)]),
            )
            .add_participant(
                Collaborator::new(
                    "pubkey2".to_string(),
                    CollaboratorRole::CoAuthor,
                    "sig2".to_string(),
                )
                .with_name("Bob")
                .with_checkpoint_ranges(vec![(11, 20)]),
            );

        assert_eq!(section.participant_count(), 2);
        assert_eq!(section.mode, CollaborationMode::Parallel);
    }

    #[test]
    fn test_coverage_validation() {
        let section = CollaborationSection::new(CollaborationMode::Sequential)
            .add_participant(
                Collaborator::new(
                    "pk1".to_string(),
                    CollaboratorRole::CoAuthor,
                    "s1".to_string(),
                )
                .with_checkpoint_ranges(vec![(0, 4)]),
            )
            .add_participant(
                Collaborator::new(
                    "pk2".to_string(),
                    CollaboratorRole::CoAuthor,
                    "s2".to_string(),
                )
                .with_checkpoint_ranges(vec![(5, 9)]),
            );

        // 10 checkpoints (0-9) should be covered
        assert!(section.validate_coverage(10).is_ok());

        // 11 checkpoints would have uncovered index 10
        assert!(section.validate_coverage(11).is_err());
    }

    #[test]
    fn test_participants_by_role() {
        let section = CollaborationSection::new(CollaborationMode::Delegated)
            .add_participant(Collaborator::new(
                "pk1".to_string(),
                CollaboratorRole::PrimaryAuthor,
                "s1".to_string(),
            ))
            .add_participant(Collaborator::new(
                "pk2".to_string(),
                CollaboratorRole::Editor,
                "s2".to_string(),
            ))
            .add_participant(Collaborator::new(
                "pk3".to_string(),
                CollaboratorRole::Editor,
                "s3".to_string(),
            ));

        let editors = section.participants_by_role(CollaboratorRole::Editor);
        assert_eq!(editors.len(), 2);
    }

    #[test]
    fn test_serialization() {
        let section = CollaborationSection::new(CollaborationMode::PeerReview).add_participant(
            Collaborator::new(
                "test_key".to_string(),
                CollaboratorRole::Reviewer,
                "test_sig".to_string(),
            ),
        );

        let json = serde_json::to_string(&section).unwrap();
        let parsed: CollaborationSection = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.mode, CollaborationMode::PeerReview);
        assert_eq!(parsed.participants.len(), 1);
    }
}
