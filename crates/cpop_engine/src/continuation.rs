// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Continuation tokens for multi-packet Evidence series.
//!
//! Allows a single authorship effort (e.g., a novel spanning months) to be
//! documented across multiple Evidence packets with cryptographic continuity:
//! previous chain hash feeds into VDF input, series-id is bound into the chain,
//! and signing keys must be consistent (verified via series-binding-signature).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Running totals across an Evidence series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuationSummary {
    pub total_checkpoints: u64,
    pub total_chars: u64,
    pub total_vdf_time_seconds: f64,
    pub total_entropy_bits: f32,
    /// Including current packet
    pub packets_in_series: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series_started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_elapsed_seconds: Option<f64>,
}

/// Continuation token linking an Evidence packet into a multi-packet series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuationSection {
    /// Stable across all packets in the series
    pub series_id: Uuid,
    /// Zero-indexed (first packet = 0)
    pub packet_sequence: u32,
    /// Required for `packet_sequence > 0`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_packet_chain_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_packet_id: Option<Uuid>,
    pub cumulative_summary: ContinuationSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series_binding_signature: Option<String>,
}

impl ContinuationSection {
    /// Start a new series (sequence 0, no predecessor).
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

    /// Build a continuation packet linked to the previous one.
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

    /// Accumulate this packet's statistics into the running totals.
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

    /// Attach a series-binding signature.
    pub fn with_signature(mut self, signature: String) -> Self {
        self.series_binding_signature = Some(signature);
        self
    }

    /// Return true if this is the first packet in the series.
    pub fn is_first(&self) -> bool {
        self.packet_sequence == 0
    }

    /// Validate chain integrity: checks `prev_packet_chain_hash` presence
    /// and `packets_in_series` consistency.
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

    /// Generate VDF input binding this packet to previous chain hash + series identity.
    pub fn generate_vdf_context(&self, content_hash: &[u8]) -> Vec<u8> {
        let mut context = Vec::new();

        if let Some(ref prev_hash) = self.prev_packet_chain_hash {
            context.extend_from_slice(prev_hash.as_bytes());
        }

        context.extend_from_slice(content_hash);
        context.extend_from_slice(self.series_id.as_bytes());
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
            prev_packet_chain_hash: None,
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

        assert!(context.len() > 16);
    }

    #[test]
    fn test_serialization() {
        let section = ContinuationSection::new_series();
        let json = serde_json::to_string(&section).unwrap();
        let parsed: ContinuationSection = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.series_id, section.series_id);
    }
}
