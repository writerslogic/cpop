// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#[derive(Clone, Copy)]
pub struct OutputMode {
    pub json: bool,
    pub quiet: bool,
}

impl OutputMode {
    pub fn new(json: bool, quiet: bool) -> Self {
        Self { json, quiet }
    }

    #[allow(dead_code)]
    pub fn verbose(&self) -> bool {
        !self.json && !self.quiet
    }
}
