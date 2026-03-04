// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Disk-backed offline attestation queue.
//!
//! When the WritersProof service is unreachable, attestation requests are
//! serialized to `~/.writerslogic/queue/` as individual JSON files. The queue
//! can be drained when connectivity is restored.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};

use super::client::WritersProofClient;
use super::types::{AttestResponse, QueuedAttestation};
use crate::error::{Error, Result};

/// Disk-backed attestation queue.
pub struct OfflineQueue {
    queue_dir: PathBuf,
}

impl OfflineQueue {
    /// Create a queue backed by `queue_dir`, creating it if needed.
    pub fn new(queue_dir: &Path) -> Result<Self> {
        fs::create_dir_all(queue_dir)?;
        Ok(Self {
            queue_dir: queue_dir.to_path_buf(),
        })
    }

    /// Return `~/.writerslogic/queue/`, falling back to a relative path.
    pub fn default_dir() -> PathBuf {
        dirs::home_dir()
            .map(|h| h.join(".writerslogic").join("queue"))
            .unwrap_or_else(|| PathBuf::from(".writerslogic/queue"))
    }

    /// Enqueue an attestation for later submission.
    pub fn enqueue(
        &self,
        evidence_cbor: &[u8],
        nonce: Option<&[u8; 32]>,
        hardware_key_id: &str,
        signing_key: &SigningKey,
    ) -> Result<String> {
        let signature = signing_key.sign(evidence_cbor);
        let id = format!(
            "{}-{}",
            Utc::now().format("%Y%m%d%H%M%S"),
            &hex::encode(&signature.to_bytes()[..4])
        );

        let entry = QueuedAttestation {
            id: id.clone(),
            evidence_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                evidence_cbor,
            ),
            nonce: nonce.map(hex::encode),
            hardware_key_id: hardware_key_id.to_string(),
            signature: hex::encode(signature.to_bytes()),
            retry_count: 0,
            last_error: None,
            created_at: Utc::now().to_rfc3339(),
        };

        let path = self.queue_dir.join(format!("{id}.json"));
        let data = serde_json::to_vec_pretty(&entry)
            .map_err(|e| Error::checkpoint(format!("queue serialize failed: {e}")))?;
        fs::write(&path, data)?;

        Ok(id)
    }

    /// List all queued entries, sorted by creation time.
    pub fn list(&self) -> Result<Vec<QueuedAttestation>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.queue_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                match fs::read(&path) {
                    Ok(data) => match serde_json::from_slice::<QueuedAttestation>(&data) {
                        Ok(queued) => entries.push(queued),
                        Err(e) => log::warn!("Malformed queue entry {}: {e}", path.display()),
                    },
                    Err(e) => {
                        log::warn!("Failed to read queue entry {}: {e}", path.display());
                        continue;
                    }
                }
            }
        }
        entries.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(entries)
    }

    pub fn len(&self) -> Result<usize> {
        Ok(self.list()?.len())
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Submit all queued entries via `client`, fetching fresh nonces for each.
    ///
    /// Successful entries are removed; failed entries stay with incremented
    /// `retry_count` and the error recorded.
    pub async fn drain(
        &self,
        client: &WritersProofClient,
        signing_key: &SigningKey,
    ) -> Result<Vec<AttestResponse>> {
        let entries = self.list()?;
        let mut results = Vec::new();

        for mut entry in entries {
            let evidence = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &entry.evidence_b64,
            )
            .map_err(|e| Error::crypto(format!("base64 decode failed: {e}")))?;

            let nonce = match client.request_nonce().await {
                Ok(resp) => {
                    let n = hex::decode(&resp.nonce)
                        .map_err(|e| Error::crypto(format!("nonce decode: {e}")))?;
                    if n.len() != 32 {
                        self.update_entry_error(&mut entry, "invalid nonce length")?;
                        continue;
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&n);
                    arr
                }
                Err(e) => {
                    self.update_entry_error(&mut entry, &e.to_string())?;
                    continue;
                }
            };

            match client
                .attest(&evidence, &nonce, &entry.hardware_key_id, signing_key)
                .await
            {
                Ok(resp) => {
                    self.remove_entry(&entry.id)?;
                    results.push(resp);
                }
                Err(e) => {
                    self.update_entry_error(&mut entry, &e.to_string())?;
                }
            }
        }

        Ok(results)
    }

    /// Reject IDs with non-alphanumeric chars to prevent path traversal.
    fn validate_id(id: &str) -> Result<()> {
        if id.is_empty()
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Error::validation(format!("invalid queue entry ID: {id:?}")));
        }
        Ok(())
    }

    pub fn remove_entry(&self, id: &str) -> Result<()> {
        Self::validate_id(id)?;
        let path = self.queue_dir.join(format!("{id}.json"));
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    fn update_entry_error(&self, entry: &mut QueuedAttestation, error: &str) -> Result<()> {
        Self::validate_id(&entry.id)?;
        entry.retry_count += 1;
        entry.last_error = Some(error.to_string());

        let path = self.queue_dir.join(format!("{}.json", entry.id));
        let data = serde_json::to_vec_pretty(entry)
            .map_err(|e| Error::checkpoint(format!("queue update serialize failed: {e}")))?;
        fs::write(&path, data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_queue_enqueue_and_list() {
        let dir = TempDir::new().unwrap();
        let queue = OfflineQueue::new(dir.path()).unwrap();

        let key = SigningKey::from_bytes(&[0x42; 32]);
        let evidence = b"test-evidence-cbor";
        let nonce = [0xAA; 32];

        let id = queue
            .enqueue(evidence, Some(&nonce), "hw-key-1", &key)
            .unwrap();
        assert!(!id.is_empty());

        let entries = queue.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hardware_key_id, "hw-key-1");
        assert_eq!(entries[0].retry_count, 0);
    }

    #[test]
    fn test_queue_multiple_entries() {
        let dir = TempDir::new().unwrap();
        let queue = OfflineQueue::new(dir.path()).unwrap();
        let key = SigningKey::from_bytes(&[0x42; 32]);

        for i in 0..3 {
            queue
                .enqueue(&[i], None, &format!("hw-key-{i}"), &key)
                .unwrap();
        }

        assert_eq!(queue.len().unwrap(), 3);
        assert!(!queue.is_empty().unwrap());
    }

    #[test]
    fn test_queue_remove_entry() {
        let dir = TempDir::new().unwrap();
        let queue = OfflineQueue::new(dir.path()).unwrap();
        let key = SigningKey::from_bytes(&[0x42; 32]);

        let id = queue.enqueue(b"data", None, "hw-1", &key).unwrap();
        assert_eq!(queue.len().unwrap(), 1);

        queue.remove_entry(&id).unwrap();
        assert_eq!(queue.len().unwrap(), 0);
    }

    #[test]
    fn test_queue_persistence() {
        let dir = TempDir::new().unwrap();
        let key = SigningKey::from_bytes(&[0x42; 32]);

        // Enqueue in one instance
        {
            let queue = OfflineQueue::new(dir.path()).unwrap();
            queue.enqueue(b"data1", None, "hw-1", &key).unwrap();
        }

        // Read from a new instance
        {
            let queue = OfflineQueue::new(dir.path()).unwrap();
            assert_eq!(queue.len().unwrap(), 1);
        }
    }

    #[test]
    fn test_queue_without_nonce() {
        let dir = TempDir::new().unwrap();
        let queue = OfflineQueue::new(dir.path()).unwrap();
        let key = SigningKey::from_bytes(&[0x42; 32]);

        let id = queue.enqueue(b"data", None, "hw-1", &key).unwrap();
        let entries = queue.list().unwrap();
        assert!(entries[0].nonce.is_none());
        let _ = id;
    }
}
