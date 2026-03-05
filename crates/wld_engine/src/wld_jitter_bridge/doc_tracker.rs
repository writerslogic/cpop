// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::fs;
use std::path::Path;
use std::time::SystemTime;

#[derive(Debug)]
pub(crate) struct DocumentTracker {
    pub(crate) path: String,
    pub(crate) last_mtime: Option<SystemTime>,
    pub(crate) last_size: Option<u64>,
    pub(crate) last_hash: Option<[u8; 32]>,
}

impl DocumentTracker {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, String> {
        let abs_path =
            fs::canonicalize(path.as_ref()).map_err(|e| format!("invalid document path: {e}"))?;

        Ok(Self {
            path: abs_path.to_string_lossy().to_string(),
            last_mtime: None,
            last_size: None,
            last_hash: None,
        })
    }

    pub fn hash(&mut self) -> Result<[u8; 32], String> {
        let metadata = fs::metadata(&self.path).map_err(|e| e.to_string())?;
        let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let size = metadata.len();

        if let (Some(last_mtime), Some(last_size), Some(last_hash)) =
            (self.last_mtime, self.last_size, self.last_hash)
        {
            if mtime == last_mtime && size == last_size {
                return Ok(last_hash);
            }
        }

        let hash = crate::crypto::hash_file(Path::new(&self.path)).map_err(|e| e.to_string())?;

        self.last_mtime = Some(mtime);
        self.last_size = Some(size);
        self.last_hash = Some(hash);

        Ok(hash)
    }
}
