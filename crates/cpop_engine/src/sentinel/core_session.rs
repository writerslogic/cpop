// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Session management for the Sentinel: start/stop witnessing, baseline updates.

use super::helpers::*;
use super::types::*;
use crate::crypto::ObfuscatedString;
use crate::ipc::IpcErrorCode;
use crate::wal::{EntryType, Wal};
use crate::{MutexRecover, RwLockRecover};
use ed25519_dalek::{Signer, SigningKey};
use sha2::Digest;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use super::core::Sentinel;

impl Sentinel {
    /// Open the event store using the sentinel's signing key.
    fn open_event_store(&self) -> anyhow::Result<crate::store::SecureStore> {
        let signing_key_local = {
            let guard = self.signing_key.read_recover();
            guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("signing key not initialized"))?
                .clone()
        };
        let db_path = self.config.writersproof_dir.join("events.db");
        let hmac_key = crate::crypto::derive_hmac_key(&signing_key_local.to_bytes());
        let store = crate::store::SecureStore::open(&db_path, hmac_key.to_vec())?;
        Ok(store)
    }

    /// Begin witnessing a file, creating a session and WAL entry.
    pub fn start_witnessing(
        &self,
        file_path: &Path,
    ) -> std::result::Result<(), (IpcErrorCode, String)> {
        if !file_path.exists() {
            return Err((
                IpcErrorCode::FileNotFound,
                format!("File not found: {}", file_path.display()),
            ));
        }

        let path_str = file_path.to_string_lossy().to_string();

        // AUD-041: Acquire signing_key before sessions to maintain lock ordering.
        let key = self.signing_key.read_recover().clone();

        // Single write lock for check+insert to avoid TOCTOU race
        let mut sessions = self.sessions.write_recover();
        if sessions.contains_key(&path_str) {
            return Err((
                IpcErrorCode::AlreadyTracking,
                format!("Already tracking: {}", file_path.display()),
            ));
        }
        let mut session = DocumentSession::new(
            path_str.clone(),
            "cli".to_string(),          // app_bundle_id for CLI-initiated tracking
            "writerslogic".to_string(), // app_name
            ObfuscatedString::new(&path_str),
        );

        if let Ok(hash) = compute_file_hash(&path_str) {
            session.initial_hash = Some(hash.clone());
            session.current_hash = Some(hash);
        }

        // Load cumulative stats from previous sessions.
        match self.open_event_store() {
            Ok(store) => match store.load_document_stats(&path_str) {
                Ok(Some(stats)) => {
                    session.cumulative_keystrokes_base = stats.total_keystrokes as u64;
                    session.cumulative_focus_ms_base = stats.total_focus_ms;
                    session.session_number = stats.session_count as u32;
                    session.first_tracked_at =
                        Some(UNIX_EPOCH + Duration::from_secs(stats.first_tracked_at as u64));
                }
                Ok(None) => {
                    session.first_tracked_at = Some(SystemTime::now());
                }
                Err(e) => {
                    log::warn!("Failed to load document stats for {path_str}: {e}");
                    session.first_tracked_at = Some(SystemTime::now());
                }
            },
            Err(e) => {
                log::warn!("Failed to open store for document stats: {e}");
                session.first_tracked_at = Some(SystemTime::now());
            }
        }

        let wal_path = self
            .config
            .wal_dir
            .join(format!("{}.wal", session.session_id));
        // Session IDs are 32 random bytes hex-encoded (64 hex chars -> 32 bytes).
        // Wal::open requires a [u8; 32] session key derived from this ID.
        let mut session_id_bytes = [0u8; 32];
        let hex_str = &session.session_id[..64.min(session.session_id.len())];
        if hex::decode_to_slice(hex_str, &mut session_id_bytes).is_ok() {
            if let Some(ref signing_key) = key {
                // Copy key bytes for Wal::open (which takes SigningKey by value)
                // and zeroize the intermediate copy. SigningKey::from_bytes produces
                // a value whose Drop impl zeroizes internal state.
                let mut key_bytes = signing_key.to_bytes();
                let wal_key = SigningKey::from_bytes(&key_bytes);
                key_bytes.zeroize();
                match Wal::open(&wal_path, session_id_bytes, wal_key) {
                    Ok(wal) => {
                        let payload = create_session_start_payload(&session);
                        if let Err(e) = wal.append(EntryType::SessionStart, payload) {
                            log::warn!(
                                "WAL append failed for session {}: {}",
                                session.session_id,
                                e
                            );
                        }
                    }
                    Err(e) => {
                        log::error!(
                            "WAL::open() failed for session {}: {}; session continues without persistent proof",
                            session.session_id,
                            e
                        );
                    }
                }
            } else {
                log::warn!(
                    "Signing key not initialized, skipping WAL for session {}",
                    session.session_id
                );
            }
        } else {
            log::warn!(
                "Invalid session ID hex '{}', skipping WAL",
                session.session_id
            );
        }

        if self
            .session_events_tx
            .send(SessionEvent {
                event_type: SessionEventType::Started,
                session_id: session.session_id.clone(),
                document_path: path_str.clone(),
                timestamp: SystemTime::now(),
            })
            .is_err()
        {
            log::debug!("no session event listeners for Started");
        }

        sessions.insert(path_str, session);
        Ok(())
    }

    /// Commit a checkpoint for the given file path if the session has new keystrokes.
    /// Returns true if a checkpoint was committed, false otherwise.
    pub fn commit_checkpoint_for_path(&self, path: &str) -> bool {
        let needs_checkpoint = {
            let sessions = self.sessions.read_recover();
            sessions
                .get(path)
                .is_some_and(|s| s.keystroke_count > s.last_checkpoint_keystrokes)
        };
        if !needs_checkpoint {
            return false;
        }

        // Skip shadow:// paths; they have no real file to hash.
        if path.starts_with("shadow://") {
            return false;
        }

        let file_path = std::path::Path::new(path);
        if !file_path.exists() {
            log::warn!("Cannot auto-checkpoint; file not found: {path}");
            return false;
        }

        let content_hash = match crate::crypto::hash_file(file_path) {
            Ok(h) => h,
            Err(e) => {
                log::warn!("Auto-checkpoint hash failed for {path}: {e}");
                return false;
            }
        };

        let file_size = std::fs::metadata(file_path)
            .map(|m| m.len() as i64)
            .unwrap_or(0);

        let mut store = match self.open_event_store() {
            Ok(s) => s,
            Err(e) => {
                log::warn!("Auto-checkpoint store open failed: {e}");
                return false;
            }
        };

        let mut event = crate::store::SecureEvent {
            id: None,
            device_id: [0u8; 16],
            machine_id: String::new(),
            timestamp_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
                .unwrap_or(0),
            file_path: path.to_string(),
            content_hash,
            file_size,
            size_delta: 0,
            previous_hash: [0u8; 32],
            event_hash: [0u8; 32],
            context_type: None,
            context_note: Some("Auto-checkpoint".to_string()),
            vdf_input: None,
            vdf_output: None,
            vdf_iterations: 0,
            forensic_score: 0.0,
            is_paste: false,
            hardware_counter: None,
            input_method: None,
        };

        match store.add_secure_event(&mut event) {
            Ok(_) => {
                log::info!("Auto-checkpoint committed for {path}");
                // Update last_checkpoint_keystrokes so the timer doesn't re-commit
                let mut sessions = self.sessions.write_recover();
                if let Some(session) = sessions.get_mut(path) {
                    session.last_checkpoint_keystrokes = session.keystroke_count;
                }
                true
            }
            Err(e) => {
                log::warn!("Auto-checkpoint store write failed for {path}: {e}");
                false
            }
        }
    }

    /// Stop witnessing a file, ending its session and updating the baseline.
    pub fn stop_witnessing(
        &self,
        file_path: &Path,
    ) -> std::result::Result<(), (IpcErrorCode, String)> {
        let path_str = file_path.to_string_lossy().to_string();

        // Commit a final checkpoint before removing the session so keystrokes
        // are never lost on abrupt session end.
        self.commit_checkpoint_for_path(&path_str);

        let session = self.sessions.write_recover().remove(&path_str);

        if let Some(session) = session {
            // Persist cumulative document stats before tearing down the session.
            let now_ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let elapsed_secs = session.start_time.elapsed().unwrap_or_default().as_secs();
            let first_tracked = session
                .first_tracked_at
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(now_ts);
            match self.open_event_store() {
                Ok(store) => {
                    let prev_dur = store
                        .load_document_stats(&path_str)
                        .ok()
                        .flatten()
                        .map(|s| s.total_duration_secs)
                        .unwrap_or(0);
                    let stats = crate::store::DocumentStats {
                        file_path: path_str.clone(),
                        total_keystrokes: session.total_keystrokes() as i64,
                        total_focus_ms: session.total_focus_ms_cumulative(),
                        session_count: (session.session_number + 1) as i64,
                        total_duration_secs: prev_dur + elapsed_secs as i64,
                        first_tracked_at: first_tracked,
                        last_tracked_at: now_ts,
                    };
                    if let Err(e) = store.save_document_stats(&stats) {
                        log::warn!("Failed to save document stats for {path_str}: {e}");
                    }
                }
                Err(e) => {
                    log::warn!("Failed to open store to save document stats: {e}");
                }
            }

            if self
                .session_events_tx
                .send(SessionEvent {
                    event_type: SessionEventType::Ended,
                    session_id: session.session_id,
                    document_path: path_str,
                    timestamp: SystemTime::now(),
                })
                .is_err()
            {
                log::debug!("no session event listeners for Ended");
            }

            if let Some(shadow_id) = session.shadow_id {
                if let Err(e) = self.shadow.delete(&shadow_id) {
                    log::warn!("shadow buffer delete failed for {shadow_id}: {e}");
                }
            }

            if let Err(e) = self.update_baseline() {
                log::error!("Failed to update baseline: {}", e);
            }

            Ok(())
        } else {
            Err((
                IpcErrorCode::NotTracking,
                format!("Not tracking: {}", file_path.display()),
            ))
        }
    }

    /// Return the paths of all currently tracked files.
    pub fn tracked_files(&self) -> Vec<String> {
        self.sessions.read_recover().keys().cloned().collect()
    }

    /// Return the sentinel start time, or None if not yet started.
    pub fn start_time(&self) -> Option<SystemTime> {
        *self.start_time.lock_recover()
    }

    /// Compute and persist an updated authorship baseline digest from accumulated activity.
    pub fn update_baseline(&self) -> anyhow::Result<()> {
        let summary = self
            .activity_accumulator
            .read_recover()
            .to_session_summary();
        if summary.keystroke_count < 10 {
            return Ok(());
        }

        // Clone signing key into a local and drop the read lock immediately
        // to avoid holding it across database I/O below.
        let signing_key_local = {
            let guard = self.signing_key.read_recover();
            guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("signing key not initialized"))?
                .clone()
        };
        let public_key = signing_key_local.verifying_key().to_bytes();
        let mut hasher = sha2::Sha256::new();
        hasher.update(public_key);
        let identity_fingerprint = hasher.finalize().to_vec();

        let db_path = self.config.writersproof_dir.join("events.db");
        let hmac_key = crate::crypto::derive_hmac_key(&signing_key_local.to_bytes());
        let store = crate::store::SecureStore::open(&db_path, hmac_key.to_vec())?;

        let current_digest =
            if let Some((cbor, _)) = store.get_baseline_digest(&identity_fingerprint)? {
                serde_json::from_slice::<cpop_protocol::baseline::BaselineDigest>(&cbor)?
            } else {
                crate::baseline::compute_initial_digest(identity_fingerprint.clone())
            };

        let updated_digest = crate::baseline::update_digest(current_digest, &summary);

        let digest_cbor = serde_json::to_vec(&updated_digest)?;
        let signature = signing_key_local.sign(&digest_cbor);
        // SigningKey zeroizes its secret material on Drop.
        drop(signing_key_local);

        store.save_baseline_digest(&identity_fingerprint, &digest_cbor, &signature.to_bytes())?;

        log::info!(
            "Authorship baseline updated. Tier: {:?}",
            updated_digest.confidence_tier
        );
        Ok(())
    }
}
