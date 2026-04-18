// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use similar::{ChangeTag, TextDiff};

use super::types::{DiffOp, DiffTag};

/// Compute a word-level diff between `old` and `new` text.
/// Returns a flat list of diff ops suitable for rendering inline track-changes.
pub fn word_diff(old: &str, new: &str) -> Vec<DiffOp> {
    let diff = TextDiff::configure()
        .timeout(std::time::Duration::from_secs(5))
        .diff_words(old, new);

    diff.iter_all_changes()
        .map(|change| {
            let tag = match change.tag() {
                ChangeTag::Equal => DiffTag::Equal,
                ChangeTag::Insert => DiffTag::Insert,
                ChangeTag::Delete => DiffTag::Delete,
            };
            DiffOp {
                tag,
                text: change.value().to_string(),
            }
        })
        .collect()
}
