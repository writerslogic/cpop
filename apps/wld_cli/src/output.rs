// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

/// Controls how command output is formatted.
#[derive(Clone, Copy)]
pub struct OutputMode {
    pub json: bool,
    pub quiet: bool,
}

impl OutputMode {
    pub fn new(json: bool, quiet: bool) -> Self {
        Self { json, quiet }
    }

    /// Returns true if informational output should be shown (not json, not quiet).
    pub fn verbose(&self) -> bool {
        !self.json && !self.quiet
    }
}
