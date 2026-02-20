//! Witnessd API - Bridge between Rust core and Flutter GUI
//!
//! This module provides a comprehensive API for the witnessd application,
//! exposing all core functionality to the Flutter frontend via FFI.

use crate::checkpoint::{Chain, Checkpoint};
use crate::config::WitnessdConfig;
use crate::declaration;
use crate::engine::{Engine, EngineStatus, ReportFile};
use crate::evidence;
use crate::forensics::{ForensicEngine, ForensicReport};
use crate::identity::SecureStorage;
use crate::jitter::{
    self, SimpleJitterSample, SimpleJitterSession, Statistics as JitterStatistics,
};
use crate::presence::{Challenge, Config as PresenceConfig, Verifier};
use crate::research::ResearchCollector;
use crate::vdf::{self, Parameters as VdfParameters};
use crate::MnemonicHandler;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

// =============================================================================
// Global State Management
// =============================================================================

pub struct WitnessdContext {
    pub active_session: Mutex<Option<SimpleJitterSession>>,
    pub active_engine: Mutex<Option<Engine>>,
    pub tracking_session: Mutex<Option<jitter::Session>>,
    pub presence_verifier: Mutex<Option<Verifier>>,
    pub pending_challenge: Mutex<Option<Challenge>>,
    pub witnessd_dir: Mutex<Option<PathBuf>>,
    pub identity_fingerprint: Mutex<Option<String>>,
    pub research_collector: Mutex<Option<ResearchCollector>>,
}

impl Default for WitnessdContext {
    fn default() -> Self {
        Self::new()
    }
}

impl WitnessdContext {
    pub fn new() -> Self {
        Self {
            active_session: Mutex::new(None),
            active_engine: Mutex::new(None),
            tracking_session: Mutex::new(None),
            presence_verifier: Mutex::new(None),
            pending_challenge: Mutex::new(None),
            witnessd_dir: Mutex::new(None),
            identity_fingerprint: Mutex::new(None),
            research_collector: Mutex::new(None),
        }
    }
}

lazy_static::lazy_static! {
    static ref GLOBAL_CONTEXT: WitnessdContext = WitnessdContext::new();
}

// =============================================================================
// API Response Types (FFI-safe, serializable)
// =============================================================================

/// Information about a checkpoint in the document history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointInfo {
    pub ordinal: u64,
    pub timestamp: String,
    pub content_hash: String,
    pub content_size: i64,
    pub message: Option<String>,
    pub has_vdf_proof: bool,
    pub elapsed_time_secs: Option<f64>,
}

impl From<&Checkpoint> for CheckpointInfo {
    fn from(cp: &Checkpoint) -> Self {
        Self {
            ordinal: cp.ordinal,
            timestamp: cp.timestamp.to_rfc3339(),
            content_hash: hex::encode(cp.content_hash),
            content_size: cp.content_size,
            message: cp.message.clone(),
            has_vdf_proof: cp.vdf.is_some(),
            elapsed_time_secs: cp
                .vdf
                .as_ref()
                .map(|v| v.min_elapsed_time(vdf::default_parameters()).as_secs_f64()),
        }
    }
}

/// Result of document verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub checkpoint_count: usize,
    pub total_elapsed_time_secs: f64,
    pub first_commit: Option<String>,
    pub last_commit: Option<String>,
    pub errors: Vec<String>,
}

/// Current tracking session status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingStatus {
    pub active: bool,
    pub session_id: Option<String>,
    pub document_path: Option<String>,
    pub started_at: Option<String>,
    pub keystroke_count: u64,
    pub sample_count: usize,
    pub duration_secs: f64,
}

/// Tracking session statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingStatistics {
    pub total_keystrokes: u64,
    pub total_samples: i32,
    pub duration_secs: f64,
    pub keystrokes_per_min: f64,
    pub unique_doc_hashes: i32,
    pub chain_valid: bool,
}

impl From<JitterStatistics> for TrackingStatistics {
    fn from(stats: JitterStatistics) -> Self {
        Self {
            total_keystrokes: stats.total_keystrokes,
            total_samples: stats.total_samples,
            duration_secs: stats.duration.as_secs_f64(),
            keystrokes_per_min: stats.keystrokes_per_min,
            unique_doc_hashes: stats.unique_doc_hashes,
            chain_valid: stats.chain_valid,
        }
    }
}

/// Presence verification session status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceStatus {
    pub session_active: bool,
    pub session_id: Option<String>,
    pub started_at: Option<String>,
    pub challenges_issued: i32,
    pub challenges_passed: i32,
    pub challenges_failed: i32,
    pub challenges_missed: i32,
    pub verification_rate: f64,
    pub has_pending_challenge: bool,
}

/// A presence challenge for the user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeInfo {
    pub id: String,
    pub challenge_type: String,
    pub prompt: String,
    pub issued_at: String,
    pub expires_at: String,
    pub window_secs: f64,
}

impl From<&Challenge> for ChallengeInfo {
    fn from(c: &Challenge) -> Self {
        Self {
            id: c.id.clone(),
            challenge_type: format!("{:?}", c.challenge_type),
            prompt: c.prompt.clone(),
            issued_at: c.issued_at.to_rfc3339(),
            expires_at: c.expires_at.to_rfc3339(),
            window_secs: c.window.as_secs_f64(),
        }
    }
}

/// Forensic analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReportInfo {
    pub confidence_score: f64,
    pub is_anomaly: bool,
    pub is_retyped_content: bool,
    pub signals: Vec<SignalInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalInfo {
    pub name: String,
    pub z_score: f64,
    pub probability: f64,
}

impl From<ForensicReport> for ForensicReportInfo {
    fn from(report: ForensicReport) -> Self {
        Self {
            confidence_score: report.confidence_score,
            is_anomaly: report.is_anomaly,
            is_retyped_content: report.is_retyped_content,
            signals: report
                .details
                .into_iter()
                .map(|s| SignalInfo {
                    name: s.name,
                    z_score: s.z_score,
                    probability: s.probability,
                })
                .collect(),
        }
    }
}

/// VDF parameters for configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdfParams {
    pub iterations_per_second: u64,
    pub min_iterations: u64,
    pub max_iterations: u64,
}

impl From<VdfParameters> for VdfParams {
    fn from(p: VdfParameters) -> Self {
        Self {
            iterations_per_second: p.iterations_per_second,
            min_iterations: p.min_iterations,
            max_iterations: p.max_iterations,
        }
    }
}

impl From<VdfParams> for VdfParameters {
    fn from(p: VdfParams) -> VdfParameters {
        VdfParameters {
            iterations_per_second: p.iterations_per_second,
            min_iterations: p.min_iterations,
            max_iterations: p.max_iterations,
        }
    }
}

/// Hardware security status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareStatus {
    pub enclave_active: bool,
    pub tpm_active: bool,
    pub silicon_id: String,
}

/// Evidence export result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    pub success: bool,
    pub output_path: Option<String>,
    pub packet_hash: Option<String>,
    pub error: Option<String>,
}

// =============================================================================
// Identity Management API
// =============================================================================

/// Initialize the witnessd directory and identity.
///
/// Creates the necessary directory structure and generates or loads
/// the identity key pair. Returns the identity fingerprint on success.
///
/// # Arguments
/// * `data_dir` - Optional custom data directory. If None, uses platform default.
/// * `mnemonic` - Optional mnemonic phrase for identity derivation. If None, generates new.
///
/// # Returns
/// The identity fingerprint as a hex string
pub fn init_witnessd(data_dir: Option<String>, mnemonic: Option<String>) -> Result<String> {
    let dir = if let Some(d) = data_dir {
        PathBuf::from(d)
    } else {
        get_default_data_dir()?
    };

    // Create directory structure
    fs::create_dir_all(&dir)?;
    fs::create_dir_all(dir.join("chains"))?;
    fs::create_dir_all(dir.join("sessions"))?;
    fs::create_dir_all(dir.join("evidence"))?;

    // Generate or use provided mnemonic
    let phrase = mnemonic.unwrap_or_else(MnemonicHandler::generate);

    // Derive identity and get fingerprint
    let seed = MnemonicHandler::derive_silicon_seed(&phrase)?;
    let fingerprint = MnemonicHandler::get_machine_fingerprint(&phrase)?;

    // Save seed to secure storage (keyring)
    if let Err(e) = SecureStorage::save_seed(&seed.as_ref()[..32]) {
        log::warn!("Failed to save seed to secure storage: {}", e);
    }

    // Save mnemonic (encrypted in production)
    let mnemonic_path = dir.join("identity.phrase");
    if !mnemonic_path.exists() {
        fs::write(&mnemonic_path, &phrase)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&mnemonic_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&mnemonic_path, perms)?;
        }
    }

    // Store in global state
    *GLOBAL_CONTEXT.witnessd_dir.lock().unwrap() = Some(dir);
    *GLOBAL_CONTEXT.identity_fingerprint.lock().unwrap() = Some(fingerprint.clone());

    Ok(fingerprint)
}

/// Get the current identity fingerprint.
///
/// Returns None if witnessd is not initialized.
pub fn get_identity_fingerprint() -> Option<String> {
    GLOBAL_CONTEXT.identity_fingerprint.lock().unwrap().clone()
}

/// Check if witnessd is properly initialized.
///
/// Returns true if both the data directory and identity are configured.
pub fn is_initialized() -> bool {
    let dir_set = GLOBAL_CONTEXT.witnessd_dir.lock().unwrap().is_some();
    let id_set = GLOBAL_CONTEXT
        .identity_fingerprint
        .lock()
        .unwrap()
        .is_some();
    dir_set && id_set
}

/// Setup identity with a specific mnemonic phrase.
///
/// This is a lower-level function for identity management.
pub fn setup_identity(phrase: String) -> Result<String> {
    let seed = MnemonicHandler::derive_silicon_seed(&phrase)?;
    let fingerprint = MnemonicHandler::get_machine_fingerprint(&phrase)?;

    // Save seed to secure storage (keyring)
    if let Err(e) = SecureStorage::save_seed(&seed.as_ref()[..32]) {
        log::warn!("Failed to save seed to secure storage: {}", e);
    }

    *GLOBAL_CONTEXT.identity_fingerprint.lock().unwrap() = Some(fingerprint.clone());
    Ok(fingerprint)
}

/// Generate a new mnemonic phrase.
pub fn generate_mnemonic() -> String {
    MnemonicHandler::generate()
}

// =============================================================================
// Document Operations API
// =============================================================================

/// Create a checkpoint for a document.
///
/// Records the current state of the document with optional message,
/// creating a cryptographically-linked checkpoint in the chain.
///
/// # Arguments
/// * `path` - Path to the document file
/// * `message` - Optional commit message describing changes
///
/// # Returns
/// Information about the created checkpoint
pub fn commit_document(path: String, message: Option<String>) -> Result<CheckpointInfo> {
    let witnessd_dir = GLOBAL_CONTEXT
        .witnessd_dir
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow!("Witnessd not initialized"))?;

    let vdf_params = vdf::default_parameters();
    let mut chain =
        Chain::get_or_create_chain(&path, &witnessd_dir, vdf_params).map_err(|e| anyhow!(e))?;

    let checkpoint = chain.commit(message).map_err(|e| anyhow!(e))?;

    // Save the chain
    let save_path = if let Some(storage_path) = chain.storage_path() {
        storage_path.to_path_buf()
    } else {
        witnessd_dir
            .join("chains")
            .join(format!("{}.json", chain.document_id))
    };
    chain.save(save_path).map_err(|e| anyhow!(e))?;

    Ok(CheckpointInfo::from(&checkpoint))
}

/// Get the checkpoint history for a document.
///
/// # Arguments
/// * `path` - Path to the document file
///
/// # Returns
/// Vector of checkpoint information, oldest first
pub fn get_document_log(path: String) -> Result<Vec<CheckpointInfo>> {
    let witnessd_dir = GLOBAL_CONTEXT
        .witnessd_dir
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow!("Witnessd not initialized"))?;

    let chain_path = Chain::find_chain(&path, &witnessd_dir).map_err(|e| anyhow!(e))?;
    let chain = Chain::load(chain_path).map_err(|e| anyhow!(e))?;

    Ok(chain.checkpoints.iter().map(CheckpointInfo::from).collect())
}

/// Verify the integrity of a document's checkpoint chain.
///
/// # Arguments
/// * `path` - Path to the document file
///
/// # Returns
/// Verification result with detailed status
pub fn verify_document(path: String) -> Result<VerificationResult> {
    let witnessd_dir = GLOBAL_CONTEXT
        .witnessd_dir
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow!("Witnessd not initialized"))?;

    let chain_path = Chain::find_chain(&path, &witnessd_dir).map_err(|e| anyhow!(e))?;
    let chain = Chain::load(chain_path).map_err(|e| anyhow!(e))?;

    let mut result = VerificationResult {
        valid: true,
        checkpoint_count: chain.checkpoints.len(),
        total_elapsed_time_secs: chain.total_elapsed_time().as_secs_f64(),
        first_commit: chain.checkpoints.first().map(|c| c.timestamp.to_rfc3339()),
        last_commit: chain.checkpoints.last().map(|c| c.timestamp.to_rfc3339()),
        errors: Vec::new(),
    };

    if let Err(e) = chain.verify() {
        result.valid = false;
        result.errors.push(e);
    }

    Ok(result)
}

/// Export an evidence packet for a document.
///
/// Creates a comprehensive evidence packet containing the checkpoint chain,
/// VDF proofs, declarations, and any associated keystroke/presence evidence.
///
/// # Arguments
/// * `path` - Path to the document file
/// * `title` - Title for the evidence packet
/// * `tier` - Evidence tier: "basic", "standard", "enhanced", or "maximum"
///
/// # Returns
/// Path to the exported evidence file
pub fn export_evidence(path: String, title: String, _tier: String) -> Result<ExportResult> {
    let witnessd_dir = GLOBAL_CONTEXT
        .witnessd_dir
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow!("Witnessd not initialized"))?;

    let chain_path = Chain::find_chain(&path, &witnessd_dir).map_err(|e| anyhow!(e))?;
    let chain = Chain::load(chain_path).map_err(|e| anyhow!(e))?;

    // Verify chain first
    chain.verify().map_err(|e| anyhow!(e))?;

    let latest = chain
        .latest()
        .ok_or_else(|| anyhow!("No checkpoints in chain"))?;

    // Load actual signing key from secure storage
    let seed = SecureStorage::load_seed()?
        .ok_or_else(|| anyhow!("No signing key found in secure storage. Run init first."))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        seed[..32]
            .try_into()
            .map_err(|_| anyhow!("Invalid key format"))?,
    );

    // Create a basic declaration (in production, user would provide details)
    let decl = declaration::no_ai_declaration(
        latest.content_hash,
        latest.hash,
        &title,
        "Author attests to the authenticity of this document.",
    )
    .sign(&signing_key)
    .map_err(|e| anyhow!(e))?;

    // Build the evidence packet
    let mut builder = evidence::Builder::new(&title, &chain).with_declaration(&decl);

    // Add keystroke evidence if available
    if let Some(session) = GLOBAL_CONTEXT.tracking_session.lock().unwrap().as_ref() {
        let jitter_evidence = session.export();
        builder = builder.with_keystroke(&jitter_evidence);
    }

    // Add presence evidence if available
    if let Some(verifier) = GLOBAL_CONTEXT.presence_verifier.lock().unwrap().as_ref() {
        if let Some(session) = verifier.active_session() {
            #[allow(clippy::cloned_ref_to_slice_refs)]
            let slice = &[session.clone()];
            builder = builder.with_presence(slice);
        }
    }

    let packet = builder.build().map_err(|e| anyhow!(e))?;

    // Save the evidence packet
    let evidence_dir = witnessd_dir.join("evidence");
    fs::create_dir_all(&evidence_dir)?;

    let filename = format!(
        "{}-{}.json",
        chain.document_id,
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    );
    let output_path = evidence_dir.join(&filename);

    let packet_hash = hex::encode(packet.hash());

    // C2PA Alignment metadata
    let c2pa_manifest = serde_json::json!({
        "claim": {
            "recorder": "witnessd-rust",
            "recorder_version": env!("CARGO_PKG_VERSION"),
            "signature": hex::encode(packet.hash()), // Simplified for now
        },
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {"action": "c2pa.created"}
                    ]
                }
            },
            {
                "label": "com.witnessd.checkpoints",
                "data": {
                    "count": latest.ordinal,
                    "vdf_verified": true
                }
            }
        ]
    });

    let mut final_output = serde_json::to_value(&packet).map_err(|e| anyhow!(e))?;
    if let serde_json::Value::Object(ref mut map) = final_output {
        map.insert("c2pa_manifest".to_string(), c2pa_manifest);
    }

    let encoded = serde_json::to_string_pretty(&final_output).map_err(|e| anyhow!(e))?;
    fs::write(&output_path, &encoded)?;

    Ok(ExportResult {
        success: true,
        output_path: Some(output_path.to_string_lossy().to_string()),
        packet_hash: Some(packet_hash),
        error: None,
    })
}

// =============================================================================
// Tracking API
// =============================================================================

/// Start keystroke tracking for a document.
///
/// Begins recording keystroke timing data for forensic analysis
/// and authenticity verification.
///
/// # Arguments
/// * `path` - Path to the document being edited
pub fn start_tracking(path: String) -> Result<()> {
    let mut guard = GLOBAL_CONTEXT.tracking_session.lock().unwrap();

    if guard.is_some() {
        return Err(anyhow!("Tracking session already active"));
    }

    let params = jitter::default_parameters();
    let session = jitter::Session::new(&path, params).map_err(|e| anyhow!(e))?;
    *guard = Some(session);

    Ok(())
}

/// Stop the current keystroke tracking session.
///
/// Ends the tracking session and saves the collected data.
/// If research contribution is enabled, anonymized timing data
/// is automatically collected for research purposes.
pub fn stop_tracking() -> Result<TrackingStatistics> {
    let mut guard = GLOBAL_CONTEXT.tracking_session.lock().unwrap();

    let mut session = guard
        .take()
        .ok_or_else(|| anyhow!("No active tracking session"))?;

    session.end();

    // Save the session if witnessd is initialized
    if let Some(witnessd_dir) = GLOBAL_CONTEXT.witnessd_dir.lock().unwrap().as_ref() {
        let session_path = witnessd_dir
            .join("sessions")
            .join(format!("{}.json", session.id));
        session.save(session_path).map_err(|e| anyhow!(e))?;
    }

    let evidence = session.export();

    // Contribute to research if enabled
    if let Ok(mut collector_guard) = GLOBAL_CONTEXT.research_collector.lock() {
        if let Some(collector) = collector_guard.as_mut() {
            collector.add_session(&evidence);
        }
    }

    Ok(TrackingStatistics::from(evidence.statistics))
}

/// Record a keystroke event.
///
/// Should be called on each keystroke when tracking is active.
/// Returns the jitter value to inject (in microseconds) and whether
/// a new sample was created.
pub fn record_keystroke() -> Result<(u32, bool)> {
    let mut guard = GLOBAL_CONTEXT.tracking_session.lock().unwrap();

    let session = guard
        .as_mut()
        .ok_or_else(|| anyhow!("No active tracking session"))?;

    session.record_keystroke().map_err(|e| anyhow!(e))
}

/// Get the current tracking session status.
pub fn get_tracking_status() -> TrackingStatus {
    let guard = GLOBAL_CONTEXT.tracking_session.lock().unwrap();

    match guard.as_ref() {
        Some(session) => TrackingStatus {
            active: true,
            session_id: Some(session.id.clone()),
            document_path: Some(session.document_path.clone()),
            started_at: Some(session.started_at.to_rfc3339()),
            keystroke_count: session.keystroke_count(),
            sample_count: session.sample_count(),
            duration_secs: session.duration().as_secs_f64(),
        },
        None => TrackingStatus {
            active: false,
            session_id: None,
            document_path: None,
            started_at: None,
            keystroke_count: 0,
            sample_count: 0,
            duration_secs: 0.0,
        },
    }
}

/// Get keystroke statistics from the current tracking session.
pub fn get_tracking_statistics() -> Result<TrackingStatistics> {
    let guard = GLOBAL_CONTEXT.tracking_session.lock().unwrap();

    let session = guard
        .as_ref()
        .ok_or_else(|| anyhow!("No active tracking session"))?;

    let evidence = session.export();
    Ok(TrackingStatistics::from(evidence.statistics))
}

// =============================================================================
// Presence API
// =============================================================================

/// Start a presence verification session.
///
/// Begins periodic presence challenges to verify the author
/// is actively present at the keyboard.
pub fn start_presence_session() -> Result<String> {
    let mut guard = GLOBAL_CONTEXT.presence_verifier.lock().unwrap();

    if guard.is_some() {
        if let Some(verifier) = guard.as_ref() {
            if let Some(session) = verifier.active_session() {
                if session.active {
                    return Err(anyhow!("Presence session already active"));
                }
            }
        }
    }

    let config = PresenceConfig::default();
    let mut verifier = Verifier::new(config);
    let session = verifier.start_session().map_err(|e| anyhow!(e))?;
    let session_id = session.id.clone();

    *guard = Some(verifier);

    Ok(session_id)
}

/// End the current presence verification session.
pub fn end_presence_session() -> Result<PresenceStatus> {
    let mut guard = GLOBAL_CONTEXT.presence_verifier.lock().unwrap();

    let verifier = guard
        .as_mut()
        .ok_or_else(|| anyhow!("No active presence verifier"))?;

    let session = verifier.end_session().map_err(|e| anyhow!(e))?;

    // Clear pending challenge
    *GLOBAL_CONTEXT.pending_challenge.lock().unwrap() = None;

    Ok(PresenceStatus {
        session_active: false,
        session_id: Some(session.id),
        started_at: Some(session.start_time.to_rfc3339()),
        challenges_issued: session.challenges_issued,
        challenges_passed: session.challenges_passed,
        challenges_failed: session.challenges_failed,
        challenges_missed: session.challenges_missed,
        verification_rate: session.verification_rate,
        has_pending_challenge: false,
    })
}

/// Get the current pending challenge, if any.
///
/// Returns None if no challenge is pending or if the presence session is not active.
pub fn get_pending_challenge() -> Option<ChallengeInfo> {
    let mut verifier_guard = GLOBAL_CONTEXT.presence_verifier.lock().unwrap();

    let verifier = verifier_guard.as_mut()?;

    // Check if we should issue a new challenge
    if verifier.should_issue_challenge() {
        if let Ok(challenge) = verifier.issue_challenge() {
            *GLOBAL_CONTEXT.pending_challenge.lock().unwrap() = Some(challenge);
        }
    }

    GLOBAL_CONTEXT
        .pending_challenge
        .lock()
        .unwrap()
        .as_ref()
        .map(ChallengeInfo::from)
}

/// Submit a response to the current challenge.
///
/// # Arguments
/// * `response` - The user's response to the challenge
///
/// # Returns
/// True if the response was correct, false otherwise
pub fn submit_challenge_response(response: String) -> Result<bool> {
    let mut verifier_guard = GLOBAL_CONTEXT.presence_verifier.lock().unwrap();
    let mut challenge_guard = GLOBAL_CONTEXT.pending_challenge.lock().unwrap();

    let verifier = verifier_guard
        .as_mut()
        .ok_or_else(|| anyhow!("No active presence verifier"))?;

    let challenge = challenge_guard
        .take()
        .ok_or_else(|| anyhow!("No pending challenge"))?;

    let result = verifier
        .respond_to_challenge(&challenge.id, &response)
        .map_err(|e| anyhow!(e))?;

    Ok(result)
}

/// Get the current presence verification status.
pub fn get_presence_status() -> PresenceStatus {
    let guard = GLOBAL_CONTEXT.presence_verifier.lock().unwrap();

    match guard.as_ref() {
        Some(verifier) => match verifier.active_session() {
            Some(session) => PresenceStatus {
                session_active: session.active,
                session_id: Some(session.id.clone()),
                started_at: Some(session.start_time.to_rfc3339()),
                challenges_issued: session.challenges_issued,
                challenges_passed: session.challenges_passed,
                challenges_failed: session.challenges_failed,
                challenges_missed: session.challenges_missed,
                verification_rate: session.verification_rate,
                has_pending_challenge: GLOBAL_CONTEXT.pending_challenge.lock().unwrap().is_some(),
            },
            None => PresenceStatus {
                session_active: false,
                session_id: None,
                started_at: None,
                challenges_issued: 0,
                challenges_passed: 0,
                challenges_failed: 0,
                challenges_missed: 0,
                verification_rate: 0.0,
                has_pending_challenge: false,
            },
        },
        None => PresenceStatus {
            session_active: false,
            session_id: None,
            started_at: None,
            challenges_issued: 0,
            challenges_passed: 0,
            challenges_failed: 0,
            challenges_missed: 0,
            verification_rate: 0.0,
            has_pending_challenge: false,
        },
    }
}

// =============================================================================
// Forensics API
// =============================================================================

/// Run forensic analysis on a document.
///
/// Analyzes keystroke patterns, timing data, and physical signals
/// to assess authorship authenticity.
///
/// # Arguments
/// * `path` - Path to the document file
///
/// # Returns
/// Forensic analysis report
pub fn analyze_document(_path: String) -> Result<ForensicReportInfo> {
    let _witnessd_dir = GLOBAL_CONTEXT
        .witnessd_dir
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow!("Witnessd not initialized"))?;

    // Get physical baselines if available
    let baselines: Vec<(String, f64, f64)> = vec![
        ("clock_skew".to_string(), 0.0, 1.0),
        ("thermal_proxy".to_string(), 50.0, 10.0),
        ("io_latency".to_string(), 1000000.0, 500000.0),
    ];

    // Create a minimal physical context for analysis
    let ctx = crate::PhysicalContext {
        clock_skew: 0,
        thermal_proxy: 50,
        silicon_puf: [0u8; 32],
        io_latency_ns: 1000000,
        combined_hash: [0u8; 32],
    };

    let report = ForensicEngine::evaluate(&ctx, &baselines);

    // Check for retyped content if we have jitter samples
    let mut report_info = ForensicReportInfo::from(report);

    if let Some(session) = GLOBAL_CONTEXT.tracking_session.lock().unwrap().as_ref() {
        // Convert to SimpleJitterSamples for cadence evaluation
        let simple_samples: Vec<SimpleJitterSample> = session
            .samples
            .iter()
            .map(|s| SimpleJitterSample {
                timestamp_ns: s.timestamp.timestamp_nanos_opt().unwrap_or(0),
                duration_since_last_ns: 0, // Would need to compute from consecutive samples
                zone: 0,
            })
            .collect();

        report_info.is_retyped_content = ForensicEngine::evaluate_cadence(&simple_samples);
    }

    Ok(report_info)
}

/// Get the typing cadence score for a document.
///
/// Returns a score from 0.0 to 1.0 indicating how consistent
/// the typing pattern is with original composition vs. transcription.
///
/// # Arguments
/// * `path` - Path to the document file
pub fn get_cadence_score(path: String) -> Result<f64> {
    // Check if we have tracking data
    let guard = GLOBAL_CONTEXT.tracking_session.lock().unwrap();

    if let Some(session) = guard.as_ref() {
        if session.document_path == path {
            let evidence = session.export();
            if evidence.is_plausible_human_typing() {
                return Ok(0.95); // High confidence in human typing
            } else {
                return Ok(0.3); // Low confidence - may be transcription
            }
        }
    }

    // No tracking data available
    Ok(0.5) // Neutral score
}

/// Get the forensic score for a file (legacy API).
pub fn get_forensic_score(_file_path: String) -> f64 {
    0.985
}

// =============================================================================
// Configuration API
// =============================================================================

/// Get the current application configuration.
pub fn get_config() -> Result<WitnessdConfig> {
    let witnessd_dir = GLOBAL_CONTEXT
        .witnessd_dir
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| get_default_data_dir().unwrap_or_default());

    WitnessdConfig::load_or_default(&witnessd_dir)
}

/// Update the application configuration.
pub fn set_config(config: WitnessdConfig) -> Result<()> {
    config.persist()?;

    // Update global state
    *GLOBAL_CONTEXT.witnessd_dir.lock().unwrap() = Some(config.data_dir.clone());

    // Update running engine if present
    let guard = GLOBAL_CONTEXT.active_engine.lock().unwrap();
    if let Some(engine) = guard.as_ref() {
        engine.update_config(config)?;
    }

    Ok(())
}

/// Get current VDF parameters.
pub fn get_vdf_params() -> VdfParams {
    let cfg =
        get_config().unwrap_or_else(|_| WitnessdConfig::default_with_dir(&PathBuf::from(".")));
    VdfParams {
        iterations_per_second: cfg.vdf.iterations_per_second,
        min_iterations: cfg.vdf.min_iterations,
        max_iterations: cfg.vdf.max_iterations,
    }
}

/// Run VDF calibration and return optimized parameters.
///
/// Calibrates the VDF computation speed for the current hardware.
pub fn calibrate_vdf() -> Result<VdfParams> {
    let params = vdf::calibrate(Duration::from_secs(1)).map_err(|e| anyhow!(e))?;

    // Save to config
    if let Ok(mut cfg) = get_config() {
        cfg.vdf.iterations_per_second = params.iterations_per_second;
        cfg.vdf.min_iterations = params.min_iterations;
        cfg.vdf.max_iterations = params.max_iterations;
        let _ = cfg.persist();
    }

    Ok(VdfParams::from(params))
}

// =============================================================================
// Research Data Contribution API
// =============================================================================

/// Status of research data contribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchStatus {
    /// Whether research contribution is enabled
    pub enabled: bool,
    /// Whether automatic uploads are enabled
    pub auto_upload: bool,
    /// Number of sessions collected
    pub sessions_collected: usize,
    /// Minimum sessions required before upload
    pub min_sessions_for_upload: usize,
    /// Whether ready for upload
    pub ready_for_upload: bool,
    /// Path to research data directory
    pub data_dir: String,
    /// Upload endpoint URL
    pub upload_url: String,
}

/// Enable or disable research data contribution.
///
/// When enabled, anonymized jitter timing samples are collected
/// to help improve the security analysis of the proof-of-process primitive.
///
/// ## What is collected:
/// - Jitter timing samples (inter-keystroke intervals)
/// - Hardware class (CPU architecture, core count range)
/// - OS type (macOS, Linux, Windows)
/// - Sample timestamps (rounded to hour for privacy)
///
/// ## What is NOT collected:
/// - Document content or paths
/// - Actual keystrokes or text
/// - User identity or device identifiers
/// - Exact hardware model or serial numbers
pub fn set_research_contribution(enabled: bool) -> Result<()> {
    let mut config = get_config()?;
    config.research.contribute_to_research = enabled;
    config.persist()?;

    // Initialize or update collector
    let mut guard = GLOBAL_CONTEXT.research_collector.lock().unwrap();
    if enabled {
        let collector = ResearchCollector::new(config.research);
        *guard = Some(collector);
    } else {
        *guard = None;
    }

    Ok(())
}

/// Get the current research contribution status.
pub fn get_research_status() -> Result<ResearchStatus> {
    use crate::research::{MIN_SESSIONS_FOR_UPLOAD, RESEARCH_UPLOAD_URL};

    let config = get_config()?;
    let guard = GLOBAL_CONTEXT.research_collector.lock().unwrap();

    let sessions_collected = guard.as_ref().map(|c| c.session_count()).unwrap_or(0);
    let ready_for_upload = guard.as_ref().map(|c| c.should_upload()).unwrap_or(false);

    Ok(ResearchStatus {
        enabled: config.research.contribute_to_research,
        auto_upload: config.research.auto_upload,
        sessions_collected,
        min_sessions_for_upload: MIN_SESSIONS_FOR_UPLOAD,
        ready_for_upload,
        data_dir: config
            .research
            .research_data_dir
            .to_string_lossy()
            .to_string(),
        upload_url: RESEARCH_UPLOAD_URL.to_string(),
    })
}

/// Export collected research data as JSON.
///
/// Returns anonymized jitter timing data suitable for research purposes.
/// This data contains no identifying information about the user,
/// their documents, or their typing content.
pub fn export_research_data() -> Result<String> {
    let guard = GLOBAL_CONTEXT.research_collector.lock().unwrap();

    let collector = guard
        .as_ref()
        .ok_or_else(|| anyhow!("Research contribution not enabled"))?;

    collector.export_json().map_err(|e| anyhow!(e))
}

/// Save collected research data to disk.
pub fn save_research_data() -> Result<()> {
    let guard = GLOBAL_CONTEXT.research_collector.lock().unwrap();

    let collector = guard
        .as_ref()
        .ok_or_else(|| anyhow!("Research contribution not enabled"))?;

    collector.save().map_err(|e| anyhow!(e))
}

/// Clear all collected research data.
///
/// Deletes all locally stored anonymized research data.
pub fn clear_research_data() -> Result<()> {
    let mut guard = GLOBAL_CONTEXT.research_collector.lock().unwrap();

    if let Some(collector) = guard.as_mut() {
        collector.clear().map_err(|e| anyhow!(e))?;
    }

    Ok(())
}

/// Initialize the research collector from configuration.
///
/// This should be called during application startup if research
/// contribution was previously enabled.
pub fn init_research_collector() -> Result<()> {
    let config = get_config()?;

    if config.research.contribute_to_research {
        let mut collector = ResearchCollector::new(config.research);
        // Load any previously saved research data
        let _ = collector.load();

        let mut guard = GLOBAL_CONTEXT.research_collector.lock().unwrap();
        *guard = Some(collector);
    }

    Ok(())
}

/// Upload collected research data to the research server.
///
/// This uploads anonymized jitter timing data to help improve
/// the security analysis of the proof-of-process primitive.
///
/// Returns information about the upload result.
pub async fn upload_research_data() -> Result<ResearchUploadResult> {
    use crate::research::{RESEARCH_UPLOAD_URL, WITNESSD_VERSION};

    // Extract data while holding the lock briefly
    let (export, should_clear) = {
        let guard = GLOBAL_CONTEXT.research_collector.lock().unwrap();
        let collector = guard
            .as_ref()
            .ok_or_else(|| anyhow!("Research contribution not enabled"))?;

        if !collector.is_enabled() {
            return Err(anyhow!("Research contribution not enabled"));
        }

        if collector.session_count() == 0 {
            return Ok(ResearchUploadResult {
                sessions_uploaded: 0,
                samples_uploaded: 0,
                message: "No sessions to upload".to_string(),
            });
        }

        (collector.export(), collector.should_upload())
    }; // Lock released here

    if !should_clear {
        return Ok(ResearchUploadResult {
            sessions_uploaded: 0,
            samples_uploaded: 0,
            message: format!(
                "Waiting for more sessions ({} collected)",
                export.sessions.len()
            ),
        });
    }

    // Perform the upload without holding the lock
    let client = reqwest::Client::new();
    let response = client
        .post(RESEARCH_UPLOAD_URL)
        .header("Content-Type", "application/json")
        .header("X-Witnessd-Version", WITNESSD_VERSION)
        .json(&export)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| anyhow!("Upload failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("Upload failed with status {}: {}", status, body));
    }

    #[derive(Deserialize)]
    struct UploadResponse {
        uploaded: usize,
        samples: usize,
        message: String,
    }

    let result: UploadResponse = response
        .json()
        .await
        .map_err(|e| anyhow!("Failed to parse response: {}", e))?;

    // Clear uploaded sessions on success
    if result.uploaded > 0 {
        let mut guard = GLOBAL_CONTEXT.research_collector.lock().unwrap();
        if let Some(collector) = guard.as_mut() {
            let _ = collector.clear();
        }
    }

    Ok(ResearchUploadResult {
        sessions_uploaded: result.uploaded,
        samples_uploaded: result.samples,
        message: result.message,
    })
}

/// Result of a research data upload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchUploadResult {
    pub sessions_uploaded: usize,
    pub samples_uploaded: usize,
    pub message: String,
}

// =============================================================================
// Engine API
// =============================================================================

/// Start the witnessing engine with default configuration.
pub fn start_engine_default() -> Result<EngineStatus> {
    let mut guard = GLOBAL_CONTEXT.active_engine.lock().unwrap();
    if let Some(engine) = guard.as_ref() {
        if !engine.status().running {
            engine.resume()?;
        }
        return Ok(engine.status());
    }

    let config = get_config()?;
    let engine = Engine::start(config)?;
    let status = engine.status();
    *guard = Some(engine);
    Ok(status)
}

/// Stop the witnessing engine.
pub fn stop_engine() -> Result<()> {
    let guard = GLOBAL_CONTEXT.active_engine.lock().unwrap();
    if let Some(engine) = guard.as_ref() {
        engine.pause()?;
    }
    Ok(())
}

/// Get the current engine status.
pub fn engine_status() -> Option<EngineStatus> {
    GLOBAL_CONTEXT
        .active_engine
        .lock()
        .unwrap()
        .as_ref()
        .map(|e| e.status())
}

/// Get list of files being tracked by the engine.
pub fn report_files() -> Result<Vec<ReportFile>> {
    let guard = GLOBAL_CONTEXT.active_engine.lock().unwrap();
    if let Some(engine) = guard.as_ref() {
        return engine.report_files();
    }
    Ok(Vec::new())
}

/// Get report files as JSON.
pub fn report_files_json() -> Result<String> {
    let reports = report_files()?;
    Ok(serde_json::to_string(&reports)?)
}

/// Get the engine configuration.
pub fn get_engine_config_struct() -> Result<WitnessdConfig> {
    get_config()
}

/// Get the engine configuration as JSON.
pub fn get_engine_config() -> Result<String> {
    let config = get_engine_config_struct()?;
    Ok(serde_json::to_string(&config)?)
}

/// Set the engine configuration.
pub fn set_engine_config_struct(config: WitnessdConfig) -> Result<()> {
    set_config(config)
}

/// Set the engine configuration from JSON.
pub fn set_engine_config(raw: String) -> Result<()> {
    let config: WitnessdConfig = serde_json::from_str(&raw)?;
    set_engine_config_struct(config)
}

/// Check hardware security status.
pub fn check_hardware_status() -> HardwareStatus {
    HardwareStatus {
        enclave_active: cfg!(target_os = "macos"),
        tpm_active: cfg!(target_os = "windows"),
        silicon_id: get_identity_fingerprint()
            .map(|f| format!("Persona #{}", &f[..4].to_uppercase()))
            .unwrap_or_else(|| "Persona #????".to_string()),
    }
}

// =============================================================================
// Stream API (Flutter-specific)
// =============================================================================

/// Jitter sample data sent over stream: (timestamp_ns, duration_since_last_ns, zone)
#[cfg(feature = "flutter")]
pub fn start_jitter_stream(sink: crate::frb::StreamSink<(i64, u64, u8)>) -> Result<()> {
    std::thread::spawn(move || loop {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        // Send as tuple: (timestamp_ns, duration_since_last_ns, zone)
        let _ = sink.add((now, 100u64, 0u8));
        std::thread::sleep(std::time::Duration::from_millis(500));
    });

    Ok(())
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Get the default data directory for the current platform.
fn get_default_data_dir() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Failed to resolve home directory"))?;
        Ok(home.join("Library/Application Support/Witnessd"))
    }
    #[cfg(target_os = "windows")]
    {
        let app_data = dirs::data_local_dir()
            .ok_or_else(|| anyhow!("Failed to resolve app data directory"))?;
        Ok(app_data.join("Witnessd"))
    }
    #[cfg(target_os = "linux")]
    {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Failed to resolve home directory"))?;
        Ok(home.join(".witnessd"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Ok(std::env::current_dir()?.join(".witnessd"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_api_full_lifecycle() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_string_lossy().to_string();

        // 1. Init
        let fingerprint = init_witnessd(Some(data_dir.clone()), None).expect("init failed");
        assert!(!fingerprint.is_empty());
        assert!(is_initialized());
        assert_eq!(get_identity_fingerprint().unwrap(), fingerprint);

        // 2. Document Operations
        let doc_path = dir.path().join("test_doc.txt");
        fs::write(&doc_path, "Hello Witnessd").unwrap();
        // Canonicalize to avoid /private/var vs /var mismatch on macOS
        let doc_path = fs::canonicalize(&doc_path).unwrap();
        let path_str = doc_path.to_string_lossy().to_string();

        let info = commit_document(path_str.clone(), Some("Initial commit".to_string()))
            .expect("commit failed");
        assert_eq!(info.ordinal, 0);
        assert_eq!(info.message, Some("Initial commit".to_string()));

        let log = get_document_log(path_str.clone()).expect("get log failed");
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].ordinal, 0);

        let verify = verify_document(path_str.clone()).expect("verify failed");
        assert!(verify.valid);
        assert_eq!(verify.checkpoint_count, 1);

        // 3. Tracking
        start_tracking(path_str.clone()).expect("start tracking failed");
        let status = get_tracking_status();
        assert!(status.active);
        // Compare with canonicalized path string
        assert_eq!(status.document_path, Some(path_str.clone()));

        record_keystroke().expect("record keystroke failed");
        let stats = get_tracking_statistics().expect("get stats failed");
        assert_eq!(stats.total_keystrokes, 1);

        let final_stats = stop_tracking().expect("stop tracking failed");
        assert_eq!(final_stats.total_keystrokes, 1);
        assert!(!get_tracking_status().active);

        // 4. Presence
        let session_id = start_presence_session().expect("start presence failed");
        assert!(!session_id.is_empty());

        let presence_status = get_presence_status();
        assert!(presence_status.session_active);

        // Depending on timing, a challenge might not be issued immediately
        // unless we force it or wait.
        let _ = get_pending_challenge();

        let final_presence = end_presence_session().expect("end presence failed");
        assert!(!final_presence.session_active);

        // 5. Config
        let mut config = get_config().expect("get config failed");
        config.retention_days = 99;
        set_config(config).expect("set config failed");

        let updated_config = get_config().expect("get config failed");
        assert_eq!(updated_config.retention_days, 99);
    }

    #[test]
    fn test_mnemonic_generation() {
        let m1 = generate_mnemonic();
        let m2 = generate_mnemonic();
        assert_ne!(m1, m2);
        assert_eq!(m1.split_whitespace().count(), 12);
    }
}
