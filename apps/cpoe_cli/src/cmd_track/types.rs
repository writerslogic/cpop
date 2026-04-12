// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::path::{Path, PathBuf};

/// Target classification for tracking.
pub(super) enum TrackTarget {
    SingleFile(PathBuf),
    Directory(PathBuf),
    ScrivenerPackage(PathBuf),
    TextBundle(PathBuf),
}

impl TrackTarget {
    pub(super) fn root(&self) -> &Path {
        match self {
            Self::SingleFile(p)
            | Self::Directory(p)
            | Self::ScrivenerPackage(p)
            | Self::TextBundle(p) => p,
        }
    }

    pub(super) fn display_name(&self) -> String {
        let root = self.root();
        let name = root.file_name().unwrap_or_default().to_string_lossy();
        match self {
            Self::SingleFile(_) => name.into_owned(),
            Self::Directory(_) => format!("{}/", name),
            Self::ScrivenerPackage(_) => format!("{} (Scrivener)", name),
            Self::TextBundle(_) => format!("{} (TextBundle)", name),
        }
    }

    pub(super) fn is_single_file(&self) -> bool {
        matches!(self, Self::SingleFile(_))
    }

    pub(super) fn mode_str(&self) -> &'static str {
        match self {
            Self::SingleFile(_) => "file",
            Self::Directory(_) => "directory",
            Self::ScrivenerPackage(_) => "scrivener",
            Self::TextBundle(_) => "textbundle",
        }
    }
}
