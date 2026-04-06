// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};

/// Focused application and document metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FocusInfo {
    pub app_name: String,
    pub bundle_id: String,
    pub pid: i32,
    pub doc_path: Option<String>,
    pub doc_title: Option<String>,
    pub window_title: Option<String>,
}

/// Platform security permission status (accessibility, input monitoring, etc.).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionStatus {
    pub accessibility: bool,
    pub input_monitoring: bool,
    pub input_devices: bool,
    pub all_granted: bool,
}

impl PermissionStatus {
    pub fn all_permitted() -> Self {
        Self {
            accessibility: true,
            input_monitoring: true,
            input_devices: true,
            all_granted: true,
        }
    }
}
