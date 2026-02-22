//! Collaborative Authorship Model
//!
//! This module implements the collaborative authorship mechanism defined in the
//! witnessd RFC. It enables multiple contributors to independently attest to
//! their contributions within a shared Evidence structure.
//!
//! # Security Model
//!
//! Each collaborator provides an independent attestation containing:
//! - Their public key (for verification)
//! - Role and contribution claims
//! - Checkpoint ranges they authored
//! - Signature over their attestation
//!
//! Verifiers can confirm that each participant acknowledged their role
//! without requiring all collaborators to share signing keys.
//!
//! # Privacy Considerations
//!
//! - Collaborator public keys may be linkable across documents
//! - Active periods reveal when each contributor was working
//! - Contribution percentages may be contentious

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Mode of collaboration
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

/// Role of a collaborator in the work
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

/// Type of contribution made
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

/// Strategy used for merging contributions
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

/// Time interval during which a collaborator was active
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeInterval {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Summary of a collaborator's contributions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionSummary {
    /// Number of checkpoints authored
    pub checkpoints_authored: u32,

    /// Characters added
    pub chars_added: u64,

    /// Characters deleted
    pub chars_deleted: u64,

    /// Active time in seconds
    pub active_time_seconds: f64,

    /// Estimated contribution percentage (0.0-1.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_contribution_pct: Option<f32>,
}

/// Individual collaborator record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collaborator {
    /// Public key of the collaborator (hex-encoded or PEM)
    pub public_key: String,

    /// Role in the collaboration
    pub role: CollaboratorRole,

    /// Display name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// External identifier (email, ORCID, etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,

    /// Periods when contributor was active
    pub active_periods: Vec<TimeInterval>,

    /// Checkpoint indices (ranges) authored by this collaborator
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_ranges: Option<Vec<(u32, u32)>>,

    /// Signature over this collaborator's attestation
    pub attestation_signature: String,

    /// Summary of contributions
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contribution_summary: Option<ContributionSummary>,
}

/// Detailed contribution claim
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionClaim {
    /// Type of contribution
    pub contribution_type: ContributionType,

    /// Public key of contributor (reference to Collaborator)
    pub contributor_key: String,

    /// Checkpoint indices this claim applies to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_indices: Option<Vec<u32>>,

    /// Description of contribution
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Extent (0.0-1.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extent: Option<f32>,
}

/// Record of a merge operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeEvent {
    /// When the merge occurred
    pub merge_time: DateTime<Utc>,

    /// Checkpoint index resulting from merge
    pub resulting_checkpoint: u32,

    /// Public keys of merged contributors
    pub merged_contributor_keys: Vec<String>,

    /// Strategy used
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<MergeStrategy>,

    /// Notes about the merge
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_note: Option<String>,
}

/// Record of merge operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeRecord {
    pub merges: Vec<MergeEvent>,
}

/// Governance policy for collaboration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationPolicy {
    /// Minimum approvers required for merge
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_approvers_for_merge: Option<u32>,

    /// Whether all signatures are required
    #[serde(default)]
    pub requires_all_signatures: bool,

    /// URI to external policy document
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
}

/// Complete collaboration section for an Evidence packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationSection {
    /// Mode of collaboration
    pub mode: CollaborationMode,

    /// Participating collaborators
    pub participants: Vec<Collaborator>,

    /// Detailed contribution claims
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributions: Vec<ContributionClaim>,

    /// Record of merge operations
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_record: Option<MergeRecord>,

    /// Governance policy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<CollaborationPolicy>,
}

impl CollaborationSection {
    /// Create a new collaboration section
    pub fn new(mode: CollaborationMode) -> Self {
        Self {
            mode,
            participants: Vec::new(),
            contributions: Vec::new(),
            merge_record: None,
            policy: None,
        }
    }

    /// Add a collaborator
    pub fn add_participant(mut self, collaborator: Collaborator) -> Self {
        self.participants.push(collaborator);
        self
    }

    /// Add a contribution claim
    pub fn add_contribution(mut self, claim: ContributionClaim) -> Self {
        self.contributions.push(claim);
        self
    }

    /// Set merge record
    pub fn with_merge_record(mut self, record: MergeRecord) -> Self {
        self.merge_record = Some(record);
        self
    }

    /// Set collaboration policy
    pub fn with_policy(mut self, policy: CollaborationPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Check if all checkpoint indices are covered by participants
    pub fn validate_coverage(&self, total_checkpoints: u32) -> Result<(), String> {
        let mut covered = vec![false; total_checkpoints as usize];

        for participant in &self.participants {
            if let Some(ref ranges) = participant.checkpoint_ranges {
                for (start, end) in ranges {
                    for i in *start..=*end {
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

    /// Count total participants
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Get participants by role
    pub fn participants_by_role(&self, role: CollaboratorRole) -> Vec<&Collaborator> {
        self.participants
            .iter()
            .filter(|p| p.role == role)
            .collect()
    }
}

impl Collaborator {
    /// Create a new collaborator
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

    /// Set display name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Set identifier (e.g., ORCID)
    pub fn with_identifier(mut self, id: impl Into<String>) -> Self {
        self.identifier = Some(id.into());
        self
    }

    /// Add an active period
    pub fn add_active_period(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.active_periods.push(TimeInterval { start, end });
        self
    }

    /// Set checkpoint ranges
    pub fn with_checkpoint_ranges(mut self, ranges: Vec<(u32, u32)>) -> Self {
        self.checkpoint_ranges = Some(ranges);
        self
    }

    /// Set contribution summary
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
