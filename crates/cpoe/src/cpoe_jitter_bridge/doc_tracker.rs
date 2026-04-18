// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

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

        let path_str = abs_path
            .to_str()
            .ok_or("document path contains non-UTF-8 bytes")?;

        Ok(Self {
            path: path_str.to_string(),
            last_mtime: None,
            last_size: None,
            last_hash: None,
        })
    }

    pub fn hash(&mut self) -> Result<[u8; 32], String> {
        let pre_meta = fs::metadata(&self.path).map_err(|e| e.to_string())?;
        let pre_mtime = pre_meta
            .modified()
            .map_err(|e| format!("filesystem does not support mtime: {e}"))?;
        let pre_size = pre_meta.len();

        if let (Some(last_mtime), Some(last_size), Some(last_hash)) =
            (self.last_mtime, self.last_size, self.last_hash)
        {
            if pre_mtime == last_mtime && pre_size == last_size {
                return Ok(last_hash);
            }
        }

        let hash = crate::crypto::hash_file(Path::new(&self.path)).map_err(|e| e.to_string())?;

        // Re-stat to detect concurrent modification during hashing
        let post_meta = fs::metadata(&self.path).map_err(|e| e.to_string())?;
        let post_mtime = post_meta
            .modified()
            .map_err(|e| format!("filesystem does not support mtime: {e}"))?;
        let post_size = post_meta.len();

        if pre_mtime != post_mtime || pre_size != post_size {
            self.last_mtime = None;
            self.last_size = None;
            self.last_hash = None;
            return Err("document modified during hashing, retry".to_string());
        }

        self.last_mtime = Some(post_mtime);
        self.last_size = Some(post_size);
        self.last_hash = Some(hash);

        Ok(hash)
    }
}
