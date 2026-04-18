// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

/// Metadata for a single snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotMeta {
    pub id: i64,
    pub document_path: String,
    pub content_hash: [u8; 32],
    pub timestamp_ns: i64,
    pub word_count: i32,
    pub draft_label: Option<String>,
    pub is_restore: bool,
}

/// A snapshot entry enriched with session grouping and word count delta.
#[derive(Debug, Clone)]
pub struct SnapshotEntry {
    pub id: i64,
    pub document_path: String,
    pub content_hash: [u8; 32],
    pub timestamp_ns: i64,
    pub word_count: i32,
    pub word_count_delta: i32,
    pub draft_label: Option<String>,
    pub is_restore: bool,
    pub session_group: u32,
}

/// A single diff operation (word-level).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffOp {
    pub tag: DiffTag,
    pub text: String,
}

/// The kind of change in a diff op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffTag {
    Equal,
    Insert,
    Delete,
}

impl DiffTag {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiffTag::Equal => "equal",
            DiffTag::Insert => "insert",
            DiffTag::Delete => "delete",
        }
    }
}

/// Result of a size check against the 500 MB warning threshold.
#[derive(Debug)]
pub struct StoreSizeInfo {
    pub total_bytes: u64,
    pub over_threshold: bool,
}

/// 500 MB warning threshold in bytes.
pub const SIZE_WARNING_THRESHOLD: u64 = 500_000_000;
