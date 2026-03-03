// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::Utc;
use std::fs;
use std::time::Duration;

use crate::config::ResearchConfig;
use crate::jitter::Evidence;

use super::types::{
    AnonymizedSession, ResearchDataExport, UploadResponse, UploadResult, MIN_SESSIONS_FOR_UPLOAD,
    RESEARCH_UPLOAD_URL, WLD_VERSION,
};

/// Collects anonymized sessions and manages disk persistence / upload.
pub struct ResearchCollector {
    config: ResearchConfig,
    sessions: Vec<AnonymizedSession>,
}

impl ResearchCollector {
    pub fn new(config: ResearchConfig) -> Self {
        Self {
            config,
            sessions: Vec::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.contribute_to_research
    }

    /// Anonymize and enqueue a session (no-op if disabled or below min samples).
    pub fn add_session(&mut self, evidence: &Evidence) {
        if !self.is_enabled() {
            return;
        }

        if evidence.samples.len() < self.config.min_samples_per_session {
            return;
        }

        let anonymized = AnonymizedSession::from_evidence(evidence);
        self.sessions.push(anonymized);

        while self.sessions.len() > self.config.max_sessions {
            self.sessions.remove(0);
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn export(&self) -> ResearchDataExport {
        ResearchDataExport {
            version: 1,
            exported_at: Utc::now(),
            consent_confirmed: self.config.contribute_to_research,
            sessions: self.sessions.clone(),
        }
    }

    pub fn export_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.export()).map_err(|e| e.to_string())
    }

    pub fn save(&self) -> Result<(), String> {
        if self.sessions.is_empty() {
            return Ok(());
        }

        fs::create_dir_all(&self.config.research_data_dir).map_err(|e| e.to_string())?;

        let export = self.export();
        let filename = format!("research_{}.json", Utc::now().format("%Y%m%d_%H%M%S"));
        let path = self.config.research_data_dir.join(filename);

        let json = serde_json::to_string_pretty(&export).map_err(|e| e.to_string())?;
        fs::write(&path, json).map_err(|e| e.to_string())?;

        Ok(())
    }

    pub fn load(&mut self) -> Result<(), String> {
        if !self.config.research_data_dir.exists() {
            return Ok(());
        }

        let entries = fs::read_dir(&self.config.research_data_dir).map_err(|e| e.to_string())?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(export) = serde_json::from_str::<ResearchDataExport>(&content) {
                        for session in export.sessions {
                            self.sessions.push(session);
                        }
                    }
                }
            }
        }

        while self.sessions.len() > self.config.max_sessions {
            self.sessions.remove(0);
        }

        Ok(())
    }

    pub fn clear(&mut self) -> Result<(), String> {
        self.sessions.clear();

        if self.config.research_data_dir.exists() {
            fs::remove_dir_all(&self.config.research_data_dir).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    pub async fn upload(&mut self) -> Result<UploadResult, String> {
        if !self.is_enabled() {
            return Err("Research contribution not enabled".to_string());
        }

        if self.sessions.is_empty() {
            return Ok(UploadResult {
                sessions_uploaded: 0,
                samples_uploaded: 0,
                message: "No sessions to upload".to_string(),
            });
        }

        if self.sessions.len() < MIN_SESSIONS_FOR_UPLOAD {
            return Ok(UploadResult {
                sessions_uploaded: 0,
                samples_uploaded: 0,
                message: format!(
                    "Waiting for more sessions ({}/{})",
                    self.sessions.len(),
                    MIN_SESSIONS_FOR_UPLOAD
                ),
            });
        }

        let export = self.export();
        let client = reqwest::Client::new();

        let response = client
            .post(RESEARCH_UPLOAD_URL)
            .header("Content-Type", "application/json")
            .header("X-WLD-Version", WLD_VERSION)
            .json(&export)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| format!("Upload failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Upload failed with status {}: {}", status, body));
        }

        let result: UploadResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        if result.uploaded > 0 {
            self.sessions.clear();
            if self.config.research_data_dir.exists() {
                let _ = fs::remove_dir_all(&self.config.research_data_dir);
            }
        }

        Ok(UploadResult {
            sessions_uploaded: result.uploaded,
            samples_uploaded: result.samples,
            message: result.message,
        })
    }

    pub fn should_upload(&self) -> bool {
        self.is_enabled() && self.sessions.len() >= MIN_SESSIONS_FOR_UPLOAD
    }
}
