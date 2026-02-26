// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Disk-backed offline attestation queue.
//!
//! When the WritersProof service is unreachable, attestation requests are
//! serialized to `~/.witnessd/queue/` as individual JSON files. The queue
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
    /// Create a new queue backed by the given directory.
    pub fn new(queue_dir: &Path) -> Result<Self> {
        fs::create_dir_all(queue_dir)?;
        Ok(Self {
            queue_dir: queue_dir.to_path_buf(),
        })
    }

    /// Default queue directory.
    pub fn default_dir() -> PathBuf {
        dirs::home_dir()
            .map(|h| h.join(".witnessd").join("queue"))
            .unwrap_or_else(|| PathBuf::from(".witnessd/queue"))
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

    /// List all queued entries.
    pub fn list(&self) -> Result<Vec<QueuedAttestation>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.queue_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                match fs::read(&path) {
                    Ok(data) => {
                        if let Ok(queued) = serde_json::from_slice::<QueuedAttestation>(&data) {
                            entries.push(queued);
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
        entries.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(entries)
    }

    /// Number of queued entries.
    pub fn len(&self) -> Result<usize> {
        Ok(self.list()?.len())
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Drain the queue, submitting all entries to the WritersProof client.
    ///
    /// Each queued entry is re-signed with the provided signing key (since the
    /// attest endpoint requires a fresh nonce+signature pair). Returns successful
    /// attestation responses. Failed entries remain in the queue with incremented
    /// retry_count and the error recorded.
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

            // Request a fresh nonce for each submission
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

            // Submit with fresh nonce and re-signing
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

    /// Remove a queue entry by ID.
    pub fn remove_entry(&self, id: &str) -> Result<()> {
        let path = self.queue_dir.join(format!("{id}.json"));
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Update an entry with an error and increment retry count.
    fn update_entry_error(&self, entry: &mut QueuedAttestation, error: &str) -> Result<()> {
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
