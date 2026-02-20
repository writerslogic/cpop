//! Voice Fingerprinting Consent Management
//!
//! This module handles explicit consent for voice fingerprinting,
//! which captures writing style patterns.
//!
//! # Consent Flow
//!
//! 1. User runs `witnessd fingerprint enable-voice`
//! 2. System displays clear explanation of what is collected
//! 3. User explicitly confirms consent
//! 4. Consent record with timestamp is stored
//!
//! # Revocation
//!
//! Running `witnessd fingerprint disable-voice`:
//! 1. Revokes consent
//! 2. Deletes ALL stored voice fingerprint data
//! 3. Records revocation timestamp

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

// =============================================================================
// Consent Types
// =============================================================================

/// Status of voice fingerprinting consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentStatus {
    /// Never asked
    NotRequested,
    /// User granted consent
    Granted,
    /// User denied consent
    Denied,
    /// User revoked previously granted consent
    Revoked,
}

impl ConsentStatus {
    /// Check if consent is currently active.
    pub fn is_granted(&self) -> bool {
        matches!(self, ConsentStatus::Granted)
    }
}

/// Record of consent decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// Current consent status
    pub status: ConsentStatus,
    /// When consent was first requested
    pub first_requested: Option<DateTime<Utc>>,
    /// When consent was granted (if ever)
    pub granted_at: Option<DateTime<Utc>>,
    /// When consent was revoked (if ever)
    pub revoked_at: Option<DateTime<Utc>>,
    /// Version of the consent text shown
    pub consent_version: String,
    /// Hash of what was explained (for audit)
    pub explanation_hash: String,
}

impl Default for ConsentRecord {
    fn default() -> Self {
        Self {
            status: ConsentStatus::NotRequested,
            first_requested: None,
            granted_at: None,
            revoked_at: None,
            consent_version: CONSENT_VERSION.to_string(),
            explanation_hash: String::new(),
        }
    }
}

// =============================================================================
// Consent Text
// =============================================================================

/// Version of the consent text (bump when explanation changes).
pub const CONSENT_VERSION: &str = "1.0.0";

/// Consent explanation shown to user.
pub const CONSENT_EXPLANATION: &str = r#"
VOICE FINGERPRINTING CONSENT

Witnessd can optionally analyze your WRITING STYLE to create a unique
fingerprint that helps verify you are the author of your documents.

WHAT IS COLLECTED:
- Word length patterns (how long your words typically are)
- Punctuation habits (comma, period usage frequency)
- Writing rhythm (hashed patterns, NOT actual text)
- Correction behavior (backspace usage patterns)

WHAT IS NOT COLLECTED:
- The actual text you type
- Specific words or phrases
- Document contents
- Passwords or sensitive information

This data is:
- Stored LOCALLY on your device only
- ENCRYPTED at rest
- NEVER transmitted to any server
- Completely DELETABLE by revoking consent

Voice fingerprinting is OPTIONAL. Activity fingerprinting (typing rhythm)
works without this and does not capture any content information.

Do you consent to voice fingerprinting? [y/N]
"#;

// =============================================================================
// Consent Manager
// =============================================================================

/// Manager for voice fingerprinting consent.
pub struct ConsentManager {
    /// Path to consent record file
    consent_file: PathBuf,
    /// Current consent record
    record: ConsentRecord,
}

impl ConsentManager {
    /// Create a new consent manager.
    pub fn new(base_path: &Path) -> Result<Self> {
        let consent_file = base_path.join("voice_consent.json");

        let record = if consent_file.exists() {
            let contents = fs::read_to_string(&consent_file)?;
            serde_json::from_str(&contents)?
        } else {
            ConsentRecord::default()
        };

        Ok(Self {
            consent_file,
            record,
        })
    }

    /// Get current consent status.
    pub fn status(&self) -> ConsentStatus {
        self.record.status
    }

    /// Check if voice fingerprinting consent is currently granted.
    pub fn has_voice_consent(&self) -> Result<bool> {
        Ok(self.record.status.is_granted())
    }

    /// Get the consent record.
    pub fn record(&self) -> &ConsentRecord {
        &self.record
    }

    /// Request consent from user.
    ///
    /// This is typically called interactively from the CLI.
    /// Returns true if consent was granted.
    pub fn request_consent(&mut self) -> Result<bool> {
        // In a real implementation, this would interact with the user
        // For now, we just update the record to show consent was requested
        if self.record.first_requested.is_none() {
            self.record.first_requested = Some(Utc::now());
        }

        // Note: Actual consent decision should be made by the caller
        // after displaying CONSENT_EXPLANATION to the user
        Ok(false)
    }

    /// Grant consent (called after user confirms).
    pub fn grant_consent(&mut self) -> Result<()> {
        self.record.status = ConsentStatus::Granted;
        self.record.granted_at = Some(Utc::now());
        self.record.consent_version = CONSENT_VERSION.to_string();
        self.record.explanation_hash = hash_explanation();
        self.save()?;
        Ok(())
    }

    /// Deny consent.
    pub fn deny_consent(&mut self) -> Result<()> {
        self.record.status = ConsentStatus::Denied;
        self.save()?;
        Ok(())
    }

    /// Revoke previously granted consent.
    ///
    /// This should also trigger deletion of all voice fingerprint data.
    pub fn revoke_consent(&mut self) -> Result<()> {
        if self.record.status != ConsentStatus::Granted {
            return Err(anyhow!("Cannot revoke consent that was not granted"));
        }

        self.record.status = ConsentStatus::Revoked;
        self.record.revoked_at = Some(Utc::now());
        self.save()?;
        Ok(())
    }

    /// Get the consent explanation text.
    pub fn get_explanation(&self) -> &'static str {
        CONSENT_EXPLANATION
    }

    /// Get the consent version.
    pub fn get_version(&self) -> &str {
        CONSENT_VERSION
    }

    /// Save the consent record.
    fn save(&self) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = self.consent_file.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(&self.record)?;
        fs::write(&self.consent_file, json)?;
        Ok(())
    }

    /// Delete the consent record file.
    pub fn delete_record(&self) -> Result<()> {
        if self.consent_file.exists() {
            fs::remove_file(&self.consent_file)?;
        }
        Ok(())
    }
}

/// Hash the consent explanation for audit purposes.
fn hash_explanation() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(CONSENT_EXPLANATION.as_bytes());
    hex::encode(hasher.finalize())
}

// =============================================================================
// CLI Helpers
// =============================================================================

/// Format consent status for CLI display.
pub fn format_consent_status(status: ConsentStatus) -> &'static str {
    match status {
        ConsentStatus::NotRequested => "Not requested",
        ConsentStatus::Granted => "Granted",
        ConsentStatus::Denied => "Denied",
        ConsentStatus::Revoked => "Revoked",
    }
}

/// Format consent record for CLI display.
pub fn format_consent_record(record: &ConsentRecord) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Status: {}", format_consent_status(record.status)));

    if let Some(first) = record.first_requested {
        lines.push(format!(
            "First requested: {}",
            first.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }

    if let Some(granted) = record.granted_at {
        lines.push(format!(
            "Granted at: {}",
            granted.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }

    if let Some(revoked) = record.revoked_at {
        lines.push(format!(
            "Revoked at: {}",
            revoked.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }

    lines.push(format!("Consent version: {}", record.consent_version));

    lines.join("\n")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_consent_status_default() {
        let record = ConsentRecord::default();
        assert_eq!(record.status, ConsentStatus::NotRequested);
        assert!(!record.status.is_granted());
    }

    #[test]
    fn test_consent_manager_creation() {
        let dir = tempdir().unwrap();
        let manager = ConsentManager::new(dir.path()).unwrap();
        assert_eq!(manager.status(), ConsentStatus::NotRequested);
    }

    #[test]
    fn test_grant_and_revoke_consent() {
        let dir = tempdir().unwrap();
        let mut manager = ConsentManager::new(dir.path()).unwrap();

        // Grant consent
        manager.grant_consent().unwrap();
        assert_eq!(manager.status(), ConsentStatus::Granted);
        assert!(manager.has_voice_consent().unwrap());

        // Revoke consent
        manager.revoke_consent().unwrap();
        assert_eq!(manager.status(), ConsentStatus::Revoked);
        assert!(!manager.has_voice_consent().unwrap());
    }

    #[test]
    fn test_consent_persistence() {
        let dir = tempdir().unwrap();

        // Grant consent
        {
            let mut manager = ConsentManager::new(dir.path()).unwrap();
            manager.grant_consent().unwrap();
        }

        // Reload and verify
        {
            let manager = ConsentManager::new(dir.path()).unwrap();
            assert_eq!(manager.status(), ConsentStatus::Granted);
        }
    }

    #[test]
    fn test_hash_explanation() {
        let hash = hash_explanation();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA256 hex
    }
}
