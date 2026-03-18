// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::path::PathBuf;

pub(super) fn default_data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .expect("cannot determine home directory")
            .join("Library/Application Support/CPOP")
    }
    #[cfg(target_os = "windows")]
    {
        dirs::data_local_dir()
            .unwrap_or_else(|| dirs::home_dir().expect("cannot determine home directory"))
            .join("CPOP")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        dirs::home_dir()
            .expect("cannot determine home directory")
            .join(".writersproof")
    }
}

pub(super) fn default_watch_dirs() -> Vec<PathBuf> {
    dirs::home_dir()
        .map(|h| {
            let mut dirs = vec![h.join("Documents"), h.join("Desktop")];
            dirs.retain(|d| d.exists());
            dirs
        })
        .unwrap_or_default()
}
