//! Incremental Evidence with Continuation Tokens
//!
//! This module implements continuation tokens for multi-packet Evidence series
//! as defined in the witnessd RFC. Continuation tokens allow a single logical
//! authorship effort to be documented across multiple Evidence packets without
//! losing cryptographic continuity.
//!
//! # Use Cases
//!
//! - Long-form works (novels, dissertations) spanning months or years
//! - Periodic Evidence snapshots for backup and sharing
//! - Projects requiring incremental verification
//!
//! # Security Model
//!
//! Continuation tokens maintain cryptographic continuity by:
//! 1. Including the previous packet's final chain hash in VDF input
//! 2. Binding series-id into the VDF chain to prevent reassignment
//! 3. Requiring consistent signing keys across the series (verified via
//!    series-binding-signature)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Cumulative statistics across an Evidence series
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuationSummary {
    /// Total checkpoints across all packets in series
    pub total_checkpoints: u64,

    /// Total characters processed so far
    pub total_chars: u64,

    /// Total VDF time in seconds across all packets
    pub total_vdf_time_seconds: f64,

    /// Total entropy bits accumulated
    pub total_entropy_bits: f32,

    /// Number of packets in this series (including current)
    pub packets_in_series: u32,

    /// When the series started
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series_started_at: Option<DateTime<Utc>>,

    /// Total elapsed time since series start
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_elapsed_seconds: Option<f64>,
}

/// Continuation token for multi-packet Evidence series
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuationSection {
    /// UUID that remains constant across all packets in the series
    pub series_id: Uuid,

    /// Zero-indexed sequence number (first packet = 0)
    pub packet_sequence: u32,

    /// Hash of final checkpoint in previous packet
    /// MUST be present for packet_sequence > 0
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_packet_chain_hash: Option<String>,

    /// UUID of previous packet in series
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_packet_id: Option<Uuid>,

    /// Running totals across the series
    pub cumulative_summary: ContinuationSummary,

    /// Signature binding this packet to the series
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series_binding_signature: Option<String>,
}

impl ContinuationSection {
    /// Create the first packet in a new series
    pub fn new_series() -> Self {
        Self {
            series_id: Uuid::new_v4(),
            packet_sequence: 0,
            prev_packet_chain_hash: None,
            prev_packet_id: None,
            cumulative_summary: ContinuationSummary {
                total_checkpoints: 0,
                total_chars: 0,
                total_vdf_time_seconds: 0.0,
                total_entropy_bits: 0.0,
                packets_in_series: 1,
                series_started_at: Some(Utc::now()),
                total_elapsed_seconds: None,
            },
            series_binding_signature: None,
        }
    }

    /// Create a continuation packet from a previous packet
    pub fn continue_from(
        prev_series_id: Uuid,
        prev_sequence: u32,
        prev_chain_hash: String,
        prev_packet_id: Uuid,
        prev_summary: &ContinuationSummary,
    ) -> Self {
        Self {
            series_id: prev_series_id,
            packet_sequence: prev_sequence + 1,
            prev_packet_chain_hash: Some(prev_chain_hash),
            prev_packet_id: Some(prev_packet_id),
            cumulative_summary: ContinuationSummary {
                total_checkpoints: prev_summary.total_checkpoints,
                total_chars: prev_summary.total_chars,
                total_vdf_time_seconds: prev_summary.total_vdf_time_seconds,
                total_entropy_bits: prev_summary.total_entropy_bits,
                packets_in_series: prev_summary.packets_in_series + 1,
                series_started_at: prev_summary.series_started_at,
                total_elapsed_seconds: None,
            },
            series_binding_signature: None,
        }
    }

    /// Update cumulative summary with this packet's statistics
    pub fn add_packet_stats(
        &mut self,
        checkpoints: u64,
        chars: u64,
        vdf_time: f64,
        entropy_bits: f32,
    ) {
        self.cumulative_summary.total_checkpoints += checkpoints;
        self.cumulative_summary.total_chars += chars;
        self.cumulative_summary.total_vdf_time_seconds += vdf_time;
        self.cumulative_summary.total_entropy_bits += entropy_bits;
    }

    /// Set the series binding signature
    pub fn with_signature(mut self, signature: String) -> Self {
        self.series_binding_signature = Some(signature);
        self
    }

    /// Check if this is the first packet in a series
    pub fn is_first(&self) -> bool {
        self.packet_sequence == 0
    }

    /// Validate continuation chain integrity
    /// Returns Ok if valid, Err with description if invalid
    pub fn validate(&self) -> Result<(), String> {
        if self.packet_sequence > 0 {
            if self.prev_packet_chain_hash.is_none() {
                return Err("Non-first packet must have prev_packet_chain_hash".to_string());
            }
        } else if self.prev_packet_chain_hash.is_some() {
            return Err(
                "First packet (sequence 0) must not have prev_packet_chain_hash".to_string(),
            );
        }

        if self.cumulative_summary.packets_in_series != self.packet_sequence + 1 {
            return Err(format!(
                "packets_in_series ({}) does not match sequence + 1 ({})",
                self.cumulative_summary.packets_in_series,
                self.packet_sequence + 1
            ));
        }

        Ok(())
    }

    /// Generate VDF input incorporating continuation context
    /// This is used to bind the new packet's VDF chain to the previous packet
    pub fn generate_vdf_context(&self, content_hash: &[u8]) -> Vec<u8> {
        let mut context = Vec::new();

        // Include previous packet's chain hash if present
        if let Some(ref prev_hash) = self.prev_packet_chain_hash {
            context.extend_from_slice(prev_hash.as_bytes());
        }

        // Include content hash
        context.extend_from_slice(content_hash);

        // Include series ID
        context.extend_from_slice(self.series_id.as_bytes());

        // Include sequence number (little-endian)
        context.extend_from_slice(&self.packet_sequence.to_le_bytes());

        context
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_series() {
        let section = ContinuationSection::new_series();
        assert_eq!(section.packet_sequence, 0);
        assert!(section.prev_packet_chain_hash.is_none());
        assert!(section.is_first());
        assert!(section.validate().is_ok());
    }

    #[test]
    fn test_continuation() {
        let first = ContinuationSection::new_series();

        let second = ContinuationSection::continue_from(
            first.series_id,
            first.packet_sequence,
            "chain_hash_abc".to_string(),
            Uuid::new_v4(),
            &first.cumulative_summary,
        );

        assert_eq!(second.packet_sequence, 1);
        assert!(!second.is_first());
        assert_eq!(second.series_id, first.series_id);
        assert_eq!(second.cumulative_summary.packets_in_series, 2);
        assert!(second.validate().is_ok());
    }

    #[test]
    fn test_invalid_first_packet() {
        let mut section = ContinuationSection::new_series();
        section.prev_packet_chain_hash = Some("should_not_exist".to_string());
        assert!(section.validate().is_err());
    }

    #[test]
    fn test_invalid_continuation() {
        let section = ContinuationSection {
            series_id: Uuid::new_v4(),
            packet_sequence: 1,
            prev_packet_chain_hash: None, // Missing!
            prev_packet_id: None,
            cumulative_summary: ContinuationSummary {
                total_checkpoints: 0,
                total_chars: 0,
                total_vdf_time_seconds: 0.0,
                total_entropy_bits: 0.0,
                packets_in_series: 2,
                series_started_at: None,
                total_elapsed_seconds: None,
            },
            series_binding_signature: None,
        };
        assert!(section.validate().is_err());
    }

    #[test]
    fn test_vdf_context() {
        let section = ContinuationSection::new_series();
        let context = section.generate_vdf_context(b"test_content_hash");

        // Should include content hash, series ID, and sequence
        assert!(context.len() > 16); // At least series ID size
    }

    #[test]
    fn test_serialization() {
        let section = ContinuationSection::new_series();
        let json = serde_json::to_string(&section).unwrap();
        let parsed: ContinuationSection = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.series_id, section.series_id);
    }
}
