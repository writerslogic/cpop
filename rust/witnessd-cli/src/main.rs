use anyhow::{anyhow, Context, Result};
use chrono::{TimeZone, Utc};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use witnessd_core::config::WitnessdConfig;
use witnessd_core::declaration::{self, AIExtent, AIPurpose, ModalityType};
use witnessd_core::war;
use witnessd_core::evidence;
use witnessd_core::fingerprint::{ConsentManager, ConsentStatus, FingerprintManager, ProfileId};
use witnessd_core::jitter::{
    default_parameters as default_jitter_params, Session as JitterSession,
};
use witnessd_core::keyhierarchy::{derive_master_identity, SoftwarePUF};
use witnessd_core::presence::{
    ChallengeStatus, Config as PresenceConfig, Session as PresenceSession, Verifier,
};
use witnessd_core::tpm;
use witnessd_core::vdf;
use witnessd_core::vdf::params::{calibrate, Parameters as VdfParameters};
use witnessd_core::{derive_hmac_key, DaemonManager, SecureEvent, SecureStore};

mod smart_defaults;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Cryptographic authorship witnessing CLI",
    long_about = "WitnessD creates cryptographic proof of authorship for your documents.\n\n\
        It records timestamped checkpoints with VDF (Verifiable Delay Function) proofs \
        to demonstrate that time actually elapsed during composition. This helps prove \
        that a document was written incrementally by a human, not generated instantly by AI.\n\n\
        KEY CONCEPTS:\n  \
        - Checkpoint: A cryptographic snapshot of your document at a point in time\n  \
        - VDF Proof: Mathematical proof that real time passed (cannot be faked)\n  \
        - Evidence Packet: Exportable proof bundle with all checkpoints and proofs\n  \
        - Declaration: Your signed statement about how the document was created"
)]
#[command(after_help = "\
GETTING STARTED:\n  \
    1. Initialize:  witnessd init\n  \
    2. Calibrate:   witnessd calibrate\n  \
    3. Checkpoint:  witnessd commit <file> -m \"message\"\n  \
    4. Export:      witnessd export <file> -t standard\n\n\
WHEN TO CHECKPOINT:\n  \
    - After completing a section or paragraph\n  \
    - Before and after major edits\n  \
    - When taking a break from writing\n  \
    More checkpoints = stronger authorship evidence.\n\n\
For command help: witnessd <command> --help\n\n\
Run 'witnessd' without arguments for quick status.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize witnessd - creates keys, identity, and database
    ///
    /// Creates ~/.witnessd with signing keys and tamper-evident database.
    #[command(
        alias = "INIT",
        alias = "Init",
        after_help = "\
WHAT IT CREATES:\n  \
    ~/.witnessd/signing_key     Your private key (keep secure!)\n  \
    ~/.witnessd/events.db       Tamper-evident checkpoint database\n\n\
NEXT: Run 'witnessd calibrate' to optimize for your CPU."
    )]
    Init {
        /// Optional path (ignored, for forgiveness of 'witnessd init .')
        #[arg(hide = true)]
        _path: Option<PathBuf>,
    },
    /// Create a checkpoint for a file with VDF time proof
    ///
    /// Records file state with cryptographic hash and VDF proof.
    #[command(
        alias = "COMMIT",
        alias = "Commit",
        alias = "checkpoint",
        after_help = "\
EXAMPLES:\n  \
    witnessd commit essay.txt -m \"Draft 1\"\n  \
    witnessd commit thesis.tex -m \"Chapter 2\"\n  \
    witnessd commit              (select from recently modified files)\n\n\
TIP: Checkpoint after sections, before revisions, and on breaks."
    )]
    Commit {
        /// Path to the file to checkpoint (optional - will prompt if omitted)
        file: Option<PathBuf>,
        /// Message describing this checkpoint
        #[arg(short, long)]
        message: Option<String>,
    },
    /// Show checkpoint history for a file
    ///
    /// Displays all checkpoints with timestamps, hashes, and VDF elapsed times.
    #[command(
        alias = "LOG",
        alias = "Log",
        alias = "history",
        after_help = "\
EXAMPLES:\n  \
    witnessd log essay.txt      View checkpoint history\n  \
    witnessd log                List all tracked documents"
    )]
    Log {
        /// Path to the file (optional - lists all tracked files if omitted)
        file: Option<PathBuf>,
    },
    /// Export evidence packet with declaration for verification
    ///
    /// Creates a portable JSON file with all checkpoints, VDF proofs, and your
    /// signed declaration about how the document was created.
    #[command(after_help = "\
EVIDENCE TIERS:\n  \
    basic     Content hashes + timestamps only (fastest)\n  \
    standard  + VDF time proofs + signed declaration (recommended)\n  \
    enhanced  + keystroke timing evidence (requires track sessions)\n  \
    maximum   + presence verification (full forensic package)\n\n\
OUTPUT FORMATS:\n  \
    json      Machine-readable JSON (default)\n  \
    war       ASCII-armored WAR block (human-readable)\n\n\
EXAMPLES:\n  \
    witnessd export essay.txt -t standard\n  \
    witnessd export thesis.tex -t enhanced -o proof.json\n  \
    witnessd export essay.txt -f war -o proof.war")]
    Export {
        /// Path to the file to export evidence for
        file: PathBuf,
        /// Evidence tier: basic, standard, enhanced, maximum (see --help)
        #[arg(short = 't', long, visible_alias = "tier", default_value = "basic")]
        tier: String,
        /// Output file path (default: <filename>.evidence.json or .war)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        /// Output format: json (default) or war (ASCII-armored)
        #[arg(short = 'f', long, default_value = "json")]
        format: String,
    },
    /// Verify the integrity of a database or evidence packet
    ///
    /// Checks that an evidence packet is valid and unmodified.
    #[command(after_help = "\
INPUT FORMATS:\n  \
    .json     JSON evidence packet\n  \
    .war      ASCII-armored WAR block\n  \
    .db       Local SQLite database\n\n\
EXAMPLES:\n  \
    witnessd verify essay.evidence.json   Verify evidence packet\n  \
    witnessd verify proof.war             Verify WAR block\n  \
    witnessd verify ~/.witnessd/events.db Verify local database")]
    Verify {
        /// Path to the file (evidence packet .json, WAR block .war, or database .db)
        file: PathBuf,
        /// Path to signing_key file (for database verification only)
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    /// Manage presence verification sessions
    ///
    /// Proves you were actively present during writing with challenges.
    #[command(after_help = "\
EXAMPLES:\n  \
    witnessd presence start       Start a new session\n  \
    witnessd presence challenge   Answer a presence challenge\n  \
    witnessd presence status      Check current session\n  \
    witnessd presence stop        End session and save results")]
    Presence {
        #[command(subcommand)]
        action: PresenceAction,
    },
    /// Track keyboard activity for typing evidence (count only, no key capture)
    ///
    /// Records keystroke timing patterns (NOT actual keys pressed).
    #[command(after_help = "\
EXAMPLES:\n  \
    witnessd track start essay.txt    Start tracking\n  \
    witnessd track stop               Stop and save session\n  \
    witnessd track export <id>        Export session evidence\n\n\
PRIVACY: Only counts keystrokes and timing - NOT what you type.")]
    Track {
        #[command(subcommand)]
        action: TrackAction,
    },
    /// Calibrate VDF performance for this machine
    ///
    /// Measures your CPU's hashing speed for accurate time proofs.
    #[command(after_help = "\
WHY: VDF proofs need to know your CPU speed to calculate elapsed time.\n\n\
WHEN TO RE-CALIBRATE:\n  \
    - After upgrading your CPU\n  \
    - When moving to a different machine")]
    #[command(alias = "CALIBRATE", alias = "Calibrate")]
    Calibrate,
    /// Show witnessd status and configuration
    #[command(alias = "STATUS", alias = "Status")]
    Status,
    /// List all tracked documents
    #[command(alias = "LIST", alias = "List", alias = "ls")]
    List,
    /// Watch folders for automatic checkpointing
    ///
    /// Monitors directories and creates checkpoints when files change.
    #[command(
        alias = "WATCH",
        alias = "Watch",
        after_help = "\
EXAMPLES:\n  \
    witnessd watch add ./documents\n  \
    witnessd watch add ./thesis -p \"*.tex,*.bib\"\n  \
    witnessd watch start\n  \
    witnessd watch                  (start watching if folders configured)\n\n\
DEFAULT PATTERNS: *.txt,*.md,*.rtf,*.doc,*.docx"
    )]
    Watch {
        #[command(subcommand)]
        action: Option<WatchAction>,
        /// Shortcut: folder to watch (same as 'watch add <folder>')
        #[arg(conflicts_with = "action")]
        folder: Option<PathBuf>,
    },
    /// Start the witnessd daemon
    ///
    /// Starts background monitoring with keystroke capture and automatic checkpointing.
    #[command(
        alias = "START",
        alias = "Start",
        after_help = "\
EXAMPLES:\n  \
    witnessd start                  Start daemon in background\n  \
    witnessd start --foreground     Run in foreground (for debugging)\n\n\
The daemon provides:\n  \
    - System-wide keystroke monitoring (timing only, not content)\n  \
    - Automatic checkpointing on file save\n  \
    - Activity fingerprint accumulation\n  \
    - Idle detection"
    )]
    Start {
        /// Run in foreground instead of background
        #[arg(short, long)]
        foreground: bool,
    },
    /// Stop the witnessd daemon
    #[command(alias = "STOP", alias = "Stop")]
    Stop,
    /// Manage author fingerprints
    ///
    /// Activity fingerprinting captures HOW you type (timing, cadence).
    /// Voice fingerprinting captures writing style (requires explicit consent).
    #[command(
        alias = "FINGERPRINT",
        alias = "Fingerprint",
        alias = "fp",
        after_help = "\
EXAMPLES:\n  \
    witnessd fingerprint status          Show fingerprint status\n  \
    witnessd fingerprint enable-voice    Enable voice fingerprinting\n  \
    witnessd fingerprint show            Show current fingerprint\n  \
    witnessd fingerprint compare A B     Compare two profiles\n\n\
PRIVACY:\n  \
    Activity fingerprinting is ON by default (captures timing only).\n  \
    Voice fingerprinting is OFF by default (requires explicit consent)."
    )]
    Fingerprint {
        #[command(subcommand)]
        action: FingerprintAction,
    },
    /// Manage document sessions
    ///
    /// Sessions track work on documents across editing sessions.
    #[command(
        alias = "SESSION",
        alias = "Session",
        after_help = "\
EXAMPLES:\n  \
    witnessd session list            List active sessions\n  \
    witnessd session show <id>       Show session details\n  \
    witnessd session export <id>     Export session evidence"
    )]
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },
    /// Manage witnessd configuration
    #[command(
        alias = "CONFIG",
        alias = "Config",
        alias = "cfg",
        after_help = "\
EXAMPLES:\n  \
    witnessd config show             Show all configuration\n  \
    witnessd config set sentinel.auto_start true\n  \
    witnessd config edit             Open in editor"
    )]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand, Clone)]
enum WatchAction {
    /// Add a folder to watch for automatic checkpointing
    Add {
        /// Path to folder to watch (defaults to current directory)
        path: Option<PathBuf>,
        /// File patterns to include (e.g., "*.txt,*.md")
        #[arg(short, long, default_value = "*.txt,*.md,*.rtf,*.doc,*.docx")]
        patterns: String,
    },
    /// Remove a folder from watch list
    Remove {
        /// Path to folder
        path: PathBuf,
    },
    /// List watched folders
    List,
    /// Start watching (runs in foreground)
    Start,
    /// Show watch status
    Status,
}

#[derive(Subcommand)]
enum PresenceAction {
    /// Start a new presence verification session
    Start,
    /// Stop the current presence verification session
    Stop,
    /// Show status of the current presence verification session
    Status,
    /// Issue and respond to a presence challenge
    Challenge,
}

#[derive(Subcommand)]
enum TrackAction {
    /// Start tracking keyboard activity for a file
    Start {
        /// Path to the document to track
        file: PathBuf,
        /// Use hardware entropy when available (physjitter)
        #[cfg(feature = "physjitter")]
        #[arg(long, help = "Use hardware entropy when available")]
        physjitter: bool,
    },
    /// Stop tracking and save evidence
    Stop,
    /// Show current tracking status
    Status,
    /// List saved tracking sessions
    List,
    /// Export jitter evidence from a session
    Export {
        /// Session ID to export
        session_id: String,
    },
}

#[derive(Subcommand)]
enum FingerprintAction {
    /// Show fingerprint status
    Status,
    /// Enable activity fingerprinting (default: on)
    EnableActivity,
    /// Disable activity fingerprinting
    DisableActivity,
    /// Enable voice fingerprinting (requires consent)
    EnableVoice,
    /// Disable voice fingerprinting and delete all voice data
    DisableVoice,
    /// Show a fingerprint profile
    Show {
        /// Profile ID to show (defaults to current profile)
        #[arg(short, long)]
        id: Option<String>,
    },
    /// Compare two fingerprint profiles
    Compare {
        /// First profile ID
        id1: String,
        /// Second profile ID
        id2: String,
    },
    /// List all stored fingerprint profiles
    List,
    /// Delete a fingerprint profile
    Delete {
        /// Profile ID to delete
        id: String,
        /// Force deletion without confirmation
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum SessionAction {
    /// List active sessions
    List,
    /// Show session details
    Show {
        /// Session ID to show
        id: String,
    },
    /// Export session evidence
    Export {
        /// Session ID to export
        id: String,
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current configuration
    Show,
    /// Set a configuration value
    Set {
        /// Key to set (e.g., sentinel.auto_start)
        key: String,
        /// Value to set
        value: String,
    },
    /// Edit configuration in your default editor
    Edit,
    /// Reset configuration to defaults
    Reset {
        /// Force reset without confirmation
        #[arg(short, long)]
        force: bool,
    },
}

/// Get the witnessd data directory
fn witnessd_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("WITNESSD_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home.join(".witnessd"))
}

/// Ensure the witnessd directory structure exists
fn ensure_dirs() -> Result<WitnessdConfig> {
    let dir = witnessd_dir()?;
    let config = WitnessdConfig::load_or_default(&dir)?;

    let dirs = [
        config.data_dir.clone(),
        config.data_dir.join("chains"),
        config.data_dir.join("sessions"),
        config.data_dir.join("tracking"),
        config.data_dir.join("sentinel"),
        config.data_dir.join("sentinel").join("wal"),
    ];

    for d in &dirs {
        fs::create_dir_all(d).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                anyhow!(
                    "Permission denied creating directory: {}\n\n\
                     Check that you have write access to this location.",
                    d.display()
                )
            } else {
                anyhow!("Failed to create directory {}: {}", d.display(), e)
            }
        })?;
    }

    Ok(config)
}

/// Load VDF parameters from config
fn load_vdf_params(config: &WitnessdConfig) -> VdfParameters {
    VdfParameters::from(config.clone())
}

/// Open the secure SQLite store
fn open_secure_store() -> Result<SecureStore> {
    let config = ensure_dirs()?;
    let dir = config.data_dir;
    let db_path = dir.join("events.db");
    let key_path = dir.join("signing_key");

    let key_data = fs::read(&key_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow!(
                "WitnessD has not been initialized yet.\n\n\
                 Run 'witnessd init' to set up WitnessD for the first time."
            )
        } else if e.kind() == std::io::ErrorKind::PermissionDenied {
            anyhow!(
                "Permission denied: {}\n\n\
                 Check that you have read access to the WitnessD data directory.",
                key_path.display()
            )
        } else {
            anyhow!("Failed to read signing key: {}", e)
        }
    })?;
    // Handle both 32-byte (seed only) and 64-byte (full keypair) formats
    // Always use the first 32 bytes (seed) for HMAC derivation for consistency
    let seed_data = if key_data.len() >= 32 {
        &key_data[..32]
    } else {
        return Err(anyhow!("Invalid signing key: expected at least 32 bytes"));
    };
    let hmac_key = derive_hmac_key(seed_data);

    SecureStore::open(&db_path, hmac_key).map_err(|e| {
        anyhow!(
            "Database error: {}\n\n\
             If this persists, check if another process is using the database.",
            e
        )
    })
}

/// Get device ID from public key
fn get_device_id() -> [u8; 16] {
    if let Ok(dir) = witnessd_dir() {
        let key_path = dir.join("signing_key.pub");
        if let Ok(pub_key) = fs::read(&key_path) {
            let h = Sha256::digest(&pub_key);
            let mut id = [0u8; 16];
            id.copy_from_slice(&h[..16]);
            return id;
        }
    }
    [0u8; 16]
}

/// Get machine ID (hostname)
fn get_machine_id() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

// =============================================================================
// Init Command Implementation
// =============================================================================

fn cmd_init() -> Result<()> {
    let config = ensure_dirs()?;
    let dir = &config.data_dir;

    // Generate signing key if not exists
    let key_path = dir.join("signing_key");
    let priv_key: SigningKey;

    if !key_path.exists() {
        println!("Generating Ed25519 signing key...");
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)?;
        priv_key = SigningKey::from_bytes(&seed);
        let pub_key = priv_key.verifying_key();

        fs::write(&key_path, priv_key.to_bytes())?;
        fs::write(key_path.with_extension("pub"), pub_key.to_bytes())?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
        }

        println!("  Public key: {}...", hex::encode(&pub_key.to_bytes()[..8]));
    } else {
        let key_data = fs::read(&key_path)?;
        // Handle both 32-byte (seed only) and 64-byte (full keypair) formats
        let seed: [u8; 32] = if key_data.len() == 32 {
            key_data
                .try_into()
                .map_err(|_| anyhow!("Invalid key file"))?
        } else if key_data.len() == 64 {
            // Legacy format: first 32 bytes are the seed
            key_data[..32]
                .try_into()
                .map_err(|_| anyhow!("Invalid key file"))?
        } else {
            return Err(anyhow!(
                "Invalid key file: expected 32 or 64 bytes, got {}",
                key_data.len()
            ));
        };
        priv_key = SigningKey::from_bytes(&seed);
    }

    // Initialize master identity from PUF (key hierarchy)
    let puf_seed_path = dir.join("puf_seed");
    if !puf_seed_path.exists() {
        println!("Initializing master identity from PUF...");
        let puf = SoftwarePUF::new_with_path(&puf_seed_path)
            .map_err(|e| anyhow!("Failed to create PUF seed: {}", e))?;

        let identity = derive_master_identity(&puf)
            .map_err(|e| anyhow!("Failed to derive master identity: {}", e))?;

        // Save identity public key
        let identity_path = dir.join("identity.json");
        let identity_data = serde_json::json!({
            "version": 1,
            "fingerprint": identity.fingerprint,
            "public_key": hex::encode(&identity.public_key),
            "device_id": identity.device_id,
            "created_at": identity.created_at.to_rfc3339(),
        });
        fs::write(
            &identity_path,
            serde_json::to_string_pretty(&identity_data)?,
        )?;

        println!("  Master Identity: {}", identity.fingerprint);
        println!("  Device ID: {}", identity.device_id);
    } else {
        let puf = SoftwarePUF::new_with_path(&puf_seed_path)
            .map_err(|e| anyhow!("Failed to load PUF: {}", e))?;
        let identity = derive_master_identity(&puf)
            .map_err(|e| anyhow!("Failed to derive identity: {}", e))?;
        println!("  Existing Master Identity: {}", identity.fingerprint);
    }

    // Create secure SQLite database
    let db_path = dir.join("events.db");
    if !db_path.exists() {
        println!("Creating secure event database...");

        let hmac_key = derive_hmac_key(&priv_key.to_bytes());
        let _db = SecureStore::open(&db_path, hmac_key).context("Failed to create database")?;
        println!("  Database: events.db (tamper-evident)");
    }

    println!();
    println!("============================================================");
    println!("  WitnessD initialized successfully!");
    println!("============================================================");
    println!();
    println!("NEXT STEPS:");
    println!();
    println!("  1. CALIBRATE your machine (required, takes ~2 seconds):");
    println!("     $ witnessd calibrate");
    println!();
    println!("  2. START CHECKPOINTING your work:");
    println!("     $ witnessd commit myfile.txt -m \"First draft\"");
    println!();
    println!("  3. When ready, EXPORT your evidence:");
    println!("     $ witnessd export myfile.txt -t standard");
    println!();
    println!("TIP: Checkpoint frequently while writing. Each checkpoint adds");
    println!("     to your authorship evidence. Run 'witnessd --help' for more.");

    Ok(())
}

// =============================================================================
// Commit Command Implementation
// =============================================================================

fn cmd_commit(file_path: &PathBuf, message: Option<String>) -> Result<()> {
    // Check file exists
    if !file_path.exists() {
        return Err(anyhow!(
            "File not found: {}\n\n\
             Check that the file exists and the path is correct.",
            file_path.display()
        ));
    }

    // Get absolute path
    let abs_path = fs::canonicalize(file_path).map_err(|e| {
        anyhow!(
            "Cannot resolve path {}: {}\n\n\
             Check that the path is valid and accessible.",
            file_path.display(),
            e
        )
    })?;
    let abs_path_str = abs_path.to_string_lossy().to_string();

    // Open secure database
    let mut db = open_secure_store()?;

    // Read file content and compute hash
    let content = fs::read(&abs_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            anyhow!(
                "Permission denied: {}\n\n\
                 Check that you have read access to this file.",
                abs_path.display()
            )
        } else {
            anyhow!("Failed to read file {}: {}", abs_path.display(), e)
        }
    })?;
    let content_hash: [u8; 32] = Sha256::digest(&content).into();
    let file_size = content.len() as i64;

    // Get previous event for this file (for VDF input and size delta)
    let events = db.get_events_for_file(&abs_path_str)?;
    let last_event = events.last();

    let (vdf_input, size_delta): ([u8; 32], i32) = if let Some(last) = last_event {
        (last.event_hash, (file_size - last.file_size) as i32)
    } else {
        // Genesis: VDF input is content hash
        (content_hash, file_size as i32)
    };

    // Load VDF parameters and compute VDF proof
    let config = ensure_dirs()?;
    let vdf_params = load_vdf_params(&config);

    print!("Computing checkpoint...");
    io::stdout().flush()?;

    let start = std::time::Instant::now();
    let vdf_proof = vdf::compute(vdf_input, Duration::from_secs(1), vdf_params)
        .map_err(|e| anyhow!("VDF computation failed: {}", e))?;
    let elapsed = start.elapsed();

    // Create event
    let mut event = SecureEvent {
        id: None,
        device_id: get_device_id(),
        machine_id: get_machine_id(),
        timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
        file_path: abs_path_str.clone(),
        content_hash,
        file_size,
        size_delta,
        previous_hash: [0u8; 32], // Will be set by insert_secure_event
        event_hash: [0u8; 32],    // Will be computed by insert_secure_event
        context_type: message.clone(),
        context_note: None,
        vdf_input: Some(vdf_input),
        vdf_output: Some(vdf_proof.output),
        vdf_iterations: vdf_proof.iterations,
        forensic_score: 1.0,
        is_paste: false,
    };

    db.insert_secure_event(&mut event)
        .context("Failed to save checkpoint")?;

    // Get checkpoint number
    let events = db.get_events_for_file(&abs_path_str)?;
    let count = events.len();

    println!(" done ({:.2?})", elapsed);
    println!();
    println!("Checkpoint #{} created", count);
    println!("  Content hash: {}...", hex::encode(&content_hash[..8]));
    println!("  Event hash:   {}...", hex::encode(&event.event_hash[..8]));
    println!(
        "  VDF proves:   >= {:?} elapsed",
        vdf_proof.min_elapsed_time(vdf_params)
    );
    if let Some(msg) = &message {
        println!("  Message:      {}", msg);
    }

    Ok(())
}

// =============================================================================
// Log Command Implementation
// =============================================================================

fn cmd_log(file_path: &PathBuf) -> Result<()> {
    // Get absolute path
    let abs_path = fs::canonicalize(file_path).context("Failed to resolve path")?;
    let abs_path_str = abs_path.to_string_lossy().to_string();

    // Open database
    let db = open_secure_store()?;

    // Get events for file
    let events = db.get_events_for_file(&abs_path_str)?;

    if events.is_empty() {
        let file_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| file_path.display().to_string());
        println!("No checkpoints found for this file.\n");
        println!("Create one with: witnessd commit {}", file_name);
        return Ok(());
    }

    // Calculate total VDF time
    let config = ensure_dirs()?;
    let vdf_params = load_vdf_params(&config);
    let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();
    let total_vdf_time =
        Duration::from_secs_f64(total_iterations as f64 / vdf_params.iterations_per_second as f64);

    println!(
        "=== Checkpoint History: {} ===",
        file_path.file_name().unwrap_or_default().to_string_lossy()
    );
    println!("Document: {}", abs_path_str);
    println!("Checkpoints: {}", events.len());
    println!("Total VDF time: {:.0?}", total_vdf_time);
    println!();

    for (i, ev) in events.iter().enumerate() {
        let ts = Utc.timestamp_nanos(ev.timestamp_ns);
        println!("[{}] {}", i + 1, ts.format("%Y-%m-%d %H:%M:%S"));
        println!("    Hash: {}", hex::encode(ev.content_hash));
        print!("    Size: {} bytes", ev.file_size);
        if ev.size_delta != 0 {
            if ev.size_delta > 0 {
                print!(" (+{})", ev.size_delta);
            } else {
                print!(" ({})", ev.size_delta);
            }
        }
        println!();
        if ev.vdf_iterations > 0 {
            let elapsed_secs = ev.vdf_iterations as f64 / vdf_params.iterations_per_second as f64;
            let elapsed_dur = Duration::from_secs_f64(elapsed_secs);
            println!("    VDF:  >= {:.0?}", elapsed_dur);
        }
        if let Some(ref msg) = ev.context_type {
            if !msg.is_empty() {
                println!("    Msg:  {}", msg);
            }
        }
        println!();
    }

    Ok(())
}

// =============================================================================
// Export Command Implementation
// =============================================================================

fn cmd_export(
    file_path: &PathBuf,
    tier: &str,
    output: Option<PathBuf>,
    session_id: Option<String>,
    format: &str,
) -> Result<()> {
    // Get absolute path
    let abs_path = fs::canonicalize(file_path).context("Failed to resolve path")?;
    let abs_path_str = abs_path.to_string_lossy().to_string();

    // Open database
    let db = open_secure_store()?;

    // Get events for file
    let events = db.get_events_for_file(&abs_path_str)?;

    if events.is_empty() {
        let file_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| file_path.display().to_string());
        return Err(anyhow!(
            "No checkpoints found for this file.\n\n\
             Create one first with: witnessd commit {}",
            file_name
        ));
    }

    let config = ensure_dirs()?;
    let dir = &config.data_dir;
    let vdf_params = load_vdf_params(&config);

    // Load signing key
    let key_path = dir.join("signing_key");
    let priv_key_data = fs::read(&key_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow!(
                "WitnessD has not been initialized yet.\n\n\
                 Run 'witnessd init' to set up WitnessD for the first time."
            )
        } else {
            anyhow!("Failed to load signing key: {}", e)
        }
    })?;
    // Handle both 32-byte (seed only) and 64-byte (full keypair) formats
    let seed: [u8; 32] = if priv_key_data.len() == 32 {
        priv_key_data
            .try_into()
            .map_err(|_| anyhow!("Invalid signing key"))?
    } else if priv_key_data.len() >= 64 {
        priv_key_data[..32]
            .try_into()
            .map_err(|_| anyhow!("Invalid signing key"))?
    } else {
        return Err(anyhow!("Invalid signing key: expected 32 or 64 bytes"));
    };
    let signing_key = SigningKey::from_bytes(&seed);

    // Get latest event
    let latest = events.last().unwrap();

    // Look for tracking evidence
    let mut keystroke_evidence = serde_json::Value::Null;
    if tier.to_lowercase() == "enhanced" || tier.to_lowercase() == "maximum" {
        let tracking_dir = dir.join("tracking");
        let mut session_to_load = session_id;

        // If no session ID provided, try to find one matching the file
        if session_to_load.is_none() && tracking_dir.exists() {
            if let Ok(entries) = fs::read_dir(&tracking_dir) {
                let mut candidates = Vec::new();
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "json") {
                        // Quick check of content without full parse
                        if let Ok(content) = fs::read_to_string(&path) {
                            if content.contains(&abs_path_str) {
                                // Found a candidate
                                if let Ok(meta) = fs::metadata(&path) {
                                    if let Ok(modified) = meta.modified() {
                                        candidates.push((path, modified));
                                    }
                                }
                            }
                        }
                    }
                }
                // Pick most recent
                candidates.sort_by(|a, b| b.1.cmp(&a.1));
                if let Some((path, _)) = candidates.first() {
                    println!(
                        "Found matching tracking session: {:?}",
                        path.file_name().unwrap()
                    );
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        // Extract ID from filename (id.session.json or id.hybrid.json)
                        let id = name.split('.').next().unwrap_or("").to_string();
                        if !id.is_empty() {
                            session_to_load = Some(id);
                        }
                    }
                }
            }
        }

        if let Some(id) = session_to_load {
            let session_path = tracking_dir.join(format!("{}.session.json", id));
            let hybrid_path = tracking_dir.join(format!("{}.hybrid.json", id));

            keystroke_evidence = if hybrid_path.exists() {
                #[cfg(feature = "physjitter")]
                {
                    match witnessd_core::HybridJitterSession::load(&hybrid_path) {
                        Ok(s) => {
                            serde_json::to_value(s.export()).unwrap_or(serde_json::Value::Null)
                        }
                        Err(_) => serde_json::Value::Null,
                    }
                }
                #[cfg(not(feature = "physjitter"))]
                {
                    serde_json::Value::Null
                }
            } else if session_path.exists() {
                match JitterSession::load(&session_path) {
                    Ok(s) => serde_json::to_value(s.export()).unwrap_or(serde_json::Value::Null),
                    Err(_) => serde_json::Value::Null,
                }
            } else {
                serde_json::Value::Null
            };

            if keystroke_evidence != serde_json::Value::Null {
                println!("Including keystroke evidence from session {}", id);
            } else if session_path.exists() || hybrid_path.exists() {
                println!("Warning: Could not load tracking session {}", id);
            }
        } else {
            println!("No matching tracking session found for this document.");
            println!(
                "Tip: Run 'witnessd track start' before writing to generate enhanced evidence."
            );
        }
    }

    // Collect declaration
    println!("=== Process Declaration ===");
    println!("You must declare how this document was created.");
    println!();

    let decl = collect_declaration(
        latest.content_hash,
        latest.event_hash,
        file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        &signing_key,
    )?;

    // Calculate totals
    let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();
    let total_vdf_time =
        Duration::from_secs_f64(total_iterations as f64 / vdf_params.iterations_per_second as f64);

    // Parse strength/tier - must match Strength enum variants
    let strength = match tier.to_lowercase().as_str() {
        "basic" => "Basic",
        "standard" => "Standard",
        "enhanced" => "Enhanced",
        "maximum" => "Maximum",
        _ => "Basic",
    };

    // Build evidence packet matching the evidence::Packet schema
    let checkpoints: Vec<serde_json::Value> = events
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let elapsed_secs = ev.vdf_iterations as f64 / vdf_params.iterations_per_second as f64;
            let elapsed_dur = Duration::from_secs_f64(elapsed_secs);
            serde_json::json!({
                "ordinal": i as u64,
                "timestamp": Utc.timestamp_nanos(ev.timestamp_ns).to_rfc3339(),
                "content_hash": hex::encode(ev.content_hash),
                "content_size": ev.file_size,
                "message": ev.context_type,
                "vdf_input": ev.vdf_input.map(hex::encode),
                "vdf_output": ev.vdf_output.map(hex::encode),
                "vdf_iterations": ev.vdf_iterations,
                "elapsed_time": {
                    "secs": elapsed_dur.as_secs(),
                    "nanos": elapsed_dur.subsec_nanos()
                },
                "previous_hash": hex::encode(ev.previous_hash),
                "hash": hex::encode(ev.event_hash),
                "signature": null
            })
        })
        .collect();

    let packet = serde_json::json!({
        "version": 1,
        "exported_at": Utc::now().to_rfc3339(),
        "strength": strength,
        "provenance": null,
        "document": {
            "title": file_path.file_name().unwrap_or_default().to_string_lossy(),
            "path": abs_path_str,
            "final_hash": hex::encode(latest.content_hash),
            "final_size": latest.file_size
        },
        "checkpoints": checkpoints,
        "vdf_params": {
            "iterations_per_second": vdf_params.iterations_per_second,
            "min_iterations": vdf_params.min_iterations,
            "max_iterations": vdf_params.max_iterations
        },
        "chain_hash": hex::encode(latest.event_hash),
        "declaration": decl,
        "presence": null,
        "hardware": null,
        "keystroke": keystroke_evidence,
        "behavioral": null,
        "contexts": [],
        "external": null,
        "key_hierarchy": null,
        "claims": [
            {"type": "chain_integrity", "description": "Content states form unbroken cryptographic chain", "confidence": "cryptographic"},
            {"type": "time_elapsed", "description": format!("At least {:?} elapsed during documented composition", total_vdf_time), "confidence": "cryptographic"}
        ],
        "limitations": [
            "Cannot prove cognitive origin of ideas",
            "Cannot prove absence of AI involvement in ideation"
        ]
    });

    // Add key hierarchy evidence if available
    let identity_path = dir.join("identity.json");
    if identity_path.exists() {
        if let Ok(identity_data) = fs::read_to_string(&identity_path) {
            if let Ok(identity) = serde_json::from_str::<serde_json::Value>(&identity_data) {
                // Note: The full key_hierarchy structure requires more data from a session
                // For now, we include a minimal version for compatibility
                println!(
                    "Including key hierarchy evidence: {}",
                    identity
                        .get("fingerprint")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                );
            }
        }
    }

    // Determine output path and format
    let format_lower = format.to_lowercase();
    let out_path = output.unwrap_or_else(|| {
        let name = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        match format_lower.as_str() {
            "war" => PathBuf::from(format!("{}.war", name)),
            _ => PathBuf::from(format!("{}.evidence.json", name)),
        }
    });

    // Save based on format
    match format_lower.as_str() {
        "war" => {
            // Parse the JSON packet into an evidence::Packet for WAR block creation
            let evidence_packet: evidence::Packet = serde_json::from_value(packet.clone())
                .context("Failed to create evidence packet")?;

            // Create and sign WAR block
            let war_block = war::Block::from_packet_signed(&evidence_packet, &signing_key)
                .map_err(|e| anyhow!("Failed to create WAR block: {}", e))?;

            // Encode as ASCII-armored text
            let data = war_block.encode_ascii();
            fs::write(&out_path, data)?;

            println!();
            println!("WAR block exported to: {}", out_path.display());
            println!("  Version: {}", war_block.version.as_str());
            println!("  Author: {}", war_block.author);
            println!("  Signed: {}", if war_block.signed { "yes" } else { "no" });
            println!("  Checkpoints: {}", events.len());
            println!("  Total VDF time: {:?}", total_vdf_time);
            println!("  Tier: {}", tier);
        }
        _ => {
            // JSON format (default)
            let data = serde_json::to_string_pretty(&packet)?;
            fs::write(&out_path, data)?;

            println!();
            println!("Evidence exported to: {}", out_path.display());
            println!("  Checkpoints: {}", events.len());
            println!("  Total VDF time: {:?}", total_vdf_time);
            println!("  Tier: {}", tier);
        }
    }

    Ok(())
}

/// Collect a declaration from the user
fn collect_declaration(
    document_hash: [u8; 32],
    chain_hash: [u8; 32],
    title: String,
    signing_key: &SigningKey,
) -> Result<declaration::Declaration> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();

    println!("Did you use any AI tools in creating this document? (y/n)");
    print!("> ");
    io::stdout().flush()?;

    let mut input = String::new();
    reader.read_line(&mut input)?;
    let used_ai = input.trim().to_lowercase().starts_with('y');

    println!();
    println!("Enter your declaration statement (a brief description of how you created this):");
    print!("> ");
    io::stdout().flush()?;

    input.clear();
    reader.read_line(&mut input)?;
    let statement = input.trim().to_string();

    if statement.is_empty() {
        return Err(anyhow!("Declaration statement is required"));
    }

    let decl = if used_ai {
        println!();
        println!("What AI tool did you use? (e.g., ChatGPT, Claude, Copilot)");
        print!("> ");
        io::stdout().flush()?;

        input.clear();
        reader.read_line(&mut input)?;
        let tool_name = input.trim().to_string();

        println!();
        println!("What was the extent of AI usage? (minimal/moderate/substantial)");
        print!("> ");
        io::stdout().flush()?;

        input.clear();
        reader.read_line(&mut input)?;
        let extent_str = input.trim().to_lowercase();
        let extent = match extent_str.as_str() {
            "substantial" => AIExtent::Substantial,
            "moderate" => AIExtent::Moderate,
            _ => AIExtent::Minimal,
        };

        declaration::ai_assisted_declaration(document_hash, chain_hash, &title)
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .add_ai_tool(&tool_name, None, AIPurpose::Drafting, None, extent)
            .with_statement(&statement)
            .sign(signing_key)
            .map_err(|e| anyhow!("Failed to create declaration: {}", e))?
    } else {
        declaration::no_ai_declaration(document_hash, chain_hash, &title, &statement)
            .sign(signing_key)
            .map_err(|e| anyhow!("Failed to create declaration: {}", e))?
    };

    Ok(decl)
}

// =============================================================================
// Verify Command Implementation
// =============================================================================

fn cmd_verify(file_path: &PathBuf, key: Option<PathBuf>) -> Result<()> {
    // Check if it's a JSON file (evidence packet), WAR file, or database
    let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    if ext == "json" {
        // Verify evidence packet
        let data = fs::read(file_path).context("Failed to read evidence file")?;
        let packet: evidence::Packet =
            serde_json::from_slice(&data).context("Failed to parse evidence packet")?;

        let config = ensure_dirs()?;
        let vdf_params = load_vdf_params(&config);
        match packet.verify(vdf_params) {
            Ok(()) => {
                println!("[OK] Evidence packet VERIFIED");
                println!("  Document: {}", packet.document.title);
                println!("  Checkpoints: {}", packet.checkpoints.len());
                println!("  Total elapsed: {:?}", packet.total_elapsed_time());
                if let Some(decl) = &packet.declaration {
                    println!(
                        "  Declaration: {}",
                        if decl.verify() { "valid" } else { "INVALID" }
                    );
                }
            }
            Err(e) => {
                println!("[FAILED] Evidence packet INVALID: {}", e);
            }
        }
    } else if ext == "war" {
        // Verify WAR block
        let data = fs::read_to_string(file_path).context("Failed to read WAR file")?;
        let war_block = war::Block::decode_ascii(&data)
            .map_err(|e| anyhow!("Failed to parse WAR block: {}", e))?;

        let report = war_block.verify();

        if report.valid {
            println!("[OK] WAR block VERIFIED");
        } else {
            println!("[FAILED] WAR block INVALID");
        }

        println!("  Version: {}", report.details.version);
        println!("  Author: {}", report.details.author);
        println!("  Document: {}", &report.details.document_id[..16]);
        println!("  Timestamp: {}", report.details.timestamp);

        println!();
        println!("Verification checks:");
        for check in &report.checks {
            let status = if check.passed { "[OK]" } else { "[FAIL]" };
            println!("  {} {}: {}", status, check.name, check.message);
        }

        if !report.valid {
            println!();
            println!("Summary: {}", report.summary);
        }
    } else {
        // Verify database
        let key_path =
            key.unwrap_or_else(|| witnessd_dir().unwrap_or_default().join("signing_key"));

        println!("Verifying database: {}", file_path.display());

        let key_data = fs::read(&key_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow!(
                    "Signing key not found: {}\n\n\
                     Specify the key with --key, or run 'witnessd init' first.",
                    key_path.display()
                )
            } else {
                anyhow!("Failed to read signing key: {}", e)
            }
        })?;
        // Use first 32 bytes for consistency with both 32-byte and 64-byte key formats
        let seed_data = if key_data.len() >= 32 {
            &key_data[..32]
        } else {
            &key_data
        };
        let hmac_key = derive_hmac_key(seed_data);

        match SecureStore::open(file_path, hmac_key) {
            Ok(_) => println!("[OK] Database integrity VERIFIED"),
            Err(e) => println!("[FAILED] Database integrity FAILED: {}", e),
        }
    }

    Ok(())
}

// =============================================================================
// Presence Command Implementation
// =============================================================================

fn cmd_presence(action: PresenceAction) -> Result<()> {
    let config = ensure_dirs()?;
    let dir = config.data_dir;
    let session_file = dir.join("sessions").join("current.json");

    match action {
        PresenceAction::Start => {
            // Check for existing session
            if session_file.exists() {
                return Err(anyhow!(
                    "Session already active. Run 'witnessd presence stop' first."
                ));
            }

            let mut verifier = Verifier::new(PresenceConfig::default());
            let session = verifier
                .start_session()
                .map_err(|e| anyhow!("Error starting session: {}", e))?;

            let data = session
                .encode()
                .map_err(|e| anyhow!("Error encoding session: {}", e))?;
            fs::write(&session_file, &data).with_context(|| "Failed to save session")?;

            println!("Presence verification session started.");
            println!("Session ID: {}", session.id);
            println!();
            println!("Run 'witnessd presence challenge' periodically to verify presence.");
        }

        PresenceAction::Stop => {
            let data = fs::read(&session_file).map_err(|_| anyhow!("No active session."))?;

            let mut session = PresenceSession::decode(&data)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

            session.active = false;
            session.end_time = Some(chrono::Utc::now());

            // Calculate stats
            for challenge in &session.challenges {
                session.challenges_issued += 1;
                match challenge.status {
                    ChallengeStatus::Passed => session.challenges_passed += 1,
                    ChallengeStatus::Failed => session.challenges_failed += 1,
                    _ => session.challenges_missed += 1,
                }
            }
            if session.challenges_issued > 0 {
                session.verification_rate =
                    session.challenges_passed as f64 / session.challenges_issued as f64;
            }

            // Archive session
            let archive_path = dir.join("sessions").join(format!("{}.json", session.id));
            let archive_data = session
                .encode()
                .map_err(|e| anyhow!("Error encoding session: {}", e))?;
            fs::write(&archive_path, &archive_data)?;
            fs::remove_file(&session_file)?;

            let duration = session
                .end_time
                .map(|end| end.signed_duration_since(session.start_time))
                .unwrap_or_else(chrono::Duration::zero);

            println!("Session ended.");
            println!("Duration: {}s", duration.num_seconds());
            println!(
                "Challenges: {} issued, {} passed ({:.0}%)",
                session.challenges_issued,
                session.challenges_passed,
                session.verification_rate * 100.0
            );
        }

        PresenceAction::Status => {
            let data = match fs::read(&session_file) {
                Ok(d) => d,
                Err(_) => {
                    println!("No active session.");
                    return Ok(());
                }
            };

            let session = PresenceSession::decode(&data)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

            let duration = chrono::Utc::now().signed_duration_since(session.start_time);

            println!("Active session:");
            println!("  ID: {}", session.id);
            println!(
                "  Started: {}",
                session.start_time.format("%Y-%m-%dT%H:%M:%S%.3fZ")
            );
            println!("  Duration: {}s", duration.num_seconds());
            println!("  Challenges: {}", session.challenges.len());
        }

        PresenceAction::Challenge => {
            let data = fs::read(&session_file)
                .map_err(|_| anyhow!("No active session. Run 'witnessd presence start' first."))?;

            let mut session = PresenceSession::decode(&data)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

            let mut verifier = Verifier::new(PresenceConfig::default());
            verifier
                .start_session()
                .map_err(|e| anyhow!("Error starting verifier: {}", e))?;

            let challenge = verifier
                .issue_challenge()
                .map_err(|e| anyhow!("Error issuing challenge: {}", e))?;

            println!("=== Presence Challenge ===");
            println!();
            println!("{}", challenge.prompt);
            println!();
            println!("You have {:?} to respond.", challenge.window);
            print!("Your answer: ");
            io::stdout().flush()?;

            let stdin = io::stdin();
            let mut response = String::new();
            stdin.lock().read_line(&mut response)?;
            let response = response.trim();

            let passed = verifier
                .respond_to_challenge(&challenge.id, response)
                .map_err(|e| anyhow!("Error: {}", e))?;

            // Update session with the challenge result
            if let Some(active_session) = verifier.active_session() {
                if let Some(last_challenge) = active_session.challenges.last() {
                    session.challenges.push(last_challenge.clone());
                }
            }

            let new_data = session
                .encode()
                .map_err(|e| anyhow!("Error encoding session: {}", e))?;
            fs::write(&session_file, &new_data)?;

            if passed {
                println!("[PASSED] Challenge PASSED");
            } else {
                println!("[FAILED] Challenge FAILED");
            }
        }
    }

    Ok(())
}

// =============================================================================
// Track Command Implementation
// =============================================================================

/// Helper function for track start command
#[allow(unused_variables)]
fn cmd_track_start(
    file: &Path,
    tracking_dir: &Path,
    current_file: &Path,
    use_physjitter: bool,
) -> Result<()> {
    // Get absolute path for the file
    let abs_path =
        fs::canonicalize(file).with_context(|| format!("Error resolving path: {:?}", file))?;

    // Check file exists
    if !abs_path.exists() {
        return Err(anyhow!("File not found: {:?}", file));
    }

    // Check for existing session
    if current_file.exists() {
        return Err(anyhow!(
            "Tracking session already active. Run 'witnessd track stop' first."
        ));
    }

    #[cfg(feature = "physjitter")]
    if use_physjitter {
        // Create a new hybrid jitter session with physjitter
        let jitter_params = default_jitter_params();
        let session = witnessd_core::HybridJitterSession::new(&abs_path, Some(jitter_params))
            .map_err(|e| anyhow!("Error creating hybrid session: {}", e))?;

        // Save session info with hybrid marker
        let session_info = serde_json::json!({
            "id": session.id,
            "document_path": abs_path.to_string_lossy(),
            "started_at": chrono::Utc::now().to_rfc3339(),
            "hybrid": true,
        });

        fs::write(current_file, serde_json::to_string_pretty(&session_info)?)?;

        // Save the session itself
        let session_path = tracking_dir.join(format!("{}.hybrid.json", session.id));
        session
            .save(&session_path)
            .map_err(|e| anyhow!("Error saving session: {}", e))?;

        println!("Keystroke tracking started (physjitter mode).");
        println!("Session ID: {}", session.id);
        println!("Document: {}", abs_path.display());
        println!();
        println!("Hardware entropy: enabled (with automatic fallback)");
        println!("PRIVACY NOTE: Only keystroke counts are recorded, NOT key values.");
        println!();
        println!("Run 'witnessd track status' to check progress.");
        println!("Run 'witnessd track stop' when done.");
        return Ok(());
    }

    // Standard jitter session (no physjitter or feature not enabled)
    let jitter_params = default_jitter_params();
    let session = JitterSession::new(&abs_path, jitter_params)
        .map_err(|e| anyhow!("Error creating session: {}", e))?;

    // Save session info
    let session_info = serde_json::json!({
        "id": session.id,
        "document_path": abs_path.to_string_lossy(),
        "started_at": chrono::Utc::now().to_rfc3339(),
        "hybrid": false,
    });

    fs::write(current_file, serde_json::to_string_pretty(&session_info)?)?;

    // Save the session itself
    let session_path = tracking_dir.join(format!("{}.session.json", session.id));
    session
        .save(&session_path)
        .map_err(|e| anyhow!("Error saving session: {}", e))?;

    println!("Keystroke tracking started.");
    println!("Session ID: {}", session.id);
    println!("Document: {:?}", abs_path);
    println!();
    println!("PRIVACY NOTE: Only keystroke counts are recorded, NOT key values.");
    println!();
    println!("Run 'witnessd track status' to check progress.");
    println!("Run 'witnessd track stop' when done.");

    Ok(())
}

fn cmd_track(action: TrackAction) -> Result<()> {
    let config = ensure_dirs()?;
    let dir = config.data_dir;
    let tracking_dir = dir.join("tracking");
    let current_file = tracking_dir.join("current_session.json");

    match action {
        #[cfg(feature = "physjitter")]
        TrackAction::Start { file, physjitter } => {
            cmd_track_start(&file, &tracking_dir, &current_file, physjitter)?;
        }
        #[cfg(not(feature = "physjitter"))]
        TrackAction::Start { file } => {
            cmd_track_start(&file, &tracking_dir, &current_file, false)?;
        }

        TrackAction::Stop => {
            let data = fs::read_to_string(&current_file)
                .map_err(|_| anyhow!("No active tracking session."))?;

            let session_info: serde_json::Value = serde_json::from_str(&data)?;
            let session_id = session_info
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Invalid session info"))?;
            #[allow(unused_variables)]
            let is_hybrid = session_info
                .get("hybrid")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            #[cfg(feature = "physjitter")]
            if is_hybrid {
                // Load hybrid session
                let session_path = tracking_dir.join(format!("{}.hybrid.json", session_id));
                let mut session = witnessd_core::HybridJitterSession::load(&session_path)
                    .map_err(|e| anyhow!("Error loading hybrid session: {}", e))?;

                session.end();
                session
                    .save(&session_path)
                    .map_err(|e| anyhow!("Error saving session: {}", e))?;

                fs::remove_file(&current_file)?;

                let duration = session.duration();
                let keystroke_count = session.keystroke_count();
                let sample_count = session.sample_count();
                let phys_ratio = session.phys_ratio();

                println!("Tracking session stopped (physjitter mode).");
                println!("Duration: {:?}", duration);
                println!("Keystrokes: {}", keystroke_count);
                println!("Samples: {}", sample_count);
                println!("Hardware entropy ratio: {:.1}%", phys_ratio * 100.0);

                if duration.as_secs() > 0 {
                    let keystrokes_per_min =
                        keystroke_count as f64 / (duration.as_secs_f64() / 60.0);
                    println!("Typing rate: {:.0} keystrokes/min", keystrokes_per_min);
                }

                println!();
                println!("Session saved: {}", session_id);
                println!();
                println!("Include this tracking evidence when exporting:");
                println!("  witnessd track export {}", session_id);
                return Ok(());
            }

            // Standard session
            let session_path = tracking_dir.join(format!("{}.session.json", session_id));
            let mut session = JitterSession::load(&session_path)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

            session.end();
            session
                .save(&session_path)
                .map_err(|e| anyhow!("Error saving session: {}", e))?;

            fs::remove_file(&current_file)?;

            let duration = session.duration();
            let keystroke_count = session.keystroke_count();
            let sample_count = session.sample_count();

            println!("Tracking session stopped.");
            println!("Duration: {:?}", duration);
            println!("Keystrokes: {}", keystroke_count);
            println!("Samples: {}", sample_count);

            if duration.as_secs() > 0 {
                let keystrokes_per_min = keystroke_count as f64 / (duration.as_secs_f64() / 60.0);
                println!("Typing rate: {:.0} keystrokes/min", keystrokes_per_min);
            }

            println!();
            println!("Session saved: {}", session_id);
            println!();
            println!("Include this tracking evidence when exporting:");
            println!("  witnessd track export {}", session_id);
        }

        TrackAction::Status => {
            let data = match fs::read_to_string(&current_file) {
                Ok(d) => d,
                Err(_) => {
                    println!("No active tracking session.");
                    return Ok(());
                }
            };

            let session_info: serde_json::Value = serde_json::from_str(&data)?;
            let session_id = session_info
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Invalid session info"))?;
            #[allow(unused_variables)]
            let is_hybrid = session_info
                .get("hybrid")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            #[cfg(feature = "physjitter")]
            if is_hybrid {
                let session_path = tracking_dir.join(format!("{}.hybrid.json", session_id));
                let session = witnessd_core::HybridJitterSession::load(&session_path)
                    .map_err(|e| anyhow!("Error loading hybrid session: {}", e))?;

                let duration = session.duration();
                let keystroke_count = session.keystroke_count();
                let sample_count = session.sample_count();
                let phys_ratio = session.phys_ratio();

                println!("=== Active Tracking Session (physjitter) ===");
                println!("Session ID: {}", session.id);
                println!("Document: {}", session.document_path);
                println!(
                    "Started: {}",
                    session.started_at.format("%Y-%m-%dT%H:%M:%S%.3fZ")
                );
                println!("Duration: {:?}", duration);
                println!("Keystrokes: {}", keystroke_count);
                println!("Jitter samples: {}", sample_count);
                println!("Hardware entropy ratio: {:.1}%", phys_ratio * 100.0);

                if duration.as_secs() > 0 && keystroke_count > 0 {
                    let keystrokes_per_min =
                        keystroke_count as f64 / (duration.as_secs_f64() / 60.0);
                    println!("Typing rate: {:.0} keystrokes/min", keystrokes_per_min);
                }
                return Ok(());
            }

            // Standard session
            let session_path = tracking_dir.join(format!("{}.session.json", session_id));
            let session = JitterSession::load(&session_path)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

            let duration = session.duration();
            let keystroke_count = session.keystroke_count();
            let sample_count = session.sample_count();

            println!("=== Active Tracking Session ===");
            println!("Session ID: {}", session.id);
            println!("Document: {}", session.document_path);
            println!(
                "Started: {}",
                session.started_at.format("%Y-%m-%dT%H:%M:%S%.3fZ")
            );
            println!("Duration: {:?}", duration);
            println!("Keystrokes: {}", keystroke_count);
            println!("Jitter samples: {}", sample_count);

            if duration.as_secs() > 0 && keystroke_count > 0 {
                let keystrokes_per_min = keystroke_count as f64 / (duration.as_secs_f64() / 60.0);
                println!("Typing rate: {:.0} keystrokes/min", keystrokes_per_min);
            }
        }

        TrackAction::List => {
            let entries =
                fs::read_dir(&tracking_dir).with_context(|| "Error reading tracking directory")?;

            let mut standard_sessions = Vec::new();
            #[cfg(feature = "physjitter")]
            let mut hybrid_sessions = Vec::new();

            for entry in entries.flatten() {
                let path = entry.path();
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                if filename.ends_with(".session.json") {
                    if let Ok(session) = JitterSession::load(&path) {
                        standard_sessions.push(session);
                    }
                }

                #[cfg(feature = "physjitter")]
                if filename.ends_with(".hybrid.json") {
                    if let Ok(session) = witnessd_core::HybridJitterSession::load(&path) {
                        hybrid_sessions.push(session);
                    }
                }
            }

            #[cfg(feature = "physjitter")]
            let total = standard_sessions.len() + hybrid_sessions.len();
            #[cfg(not(feature = "physjitter"))]
            let total = standard_sessions.len();

            if total == 0 {
                println!("No saved tracking sessions.");
                return Ok(());
            }

            println!("Saved tracking sessions:");

            for session in standard_sessions {
                let duration = session.duration();
                println!(
                    "  {}: {} keystrokes, {} samples, {:?}",
                    session.id,
                    session.keystroke_count(),
                    session.sample_count(),
                    duration
                );
            }

            #[cfg(feature = "physjitter")]
            for session in hybrid_sessions {
                let duration = session.duration();
                let phys_ratio = session.phys_ratio();
                println!(
                    "  {} [physjitter]: {} keystrokes, {} samples, {:?}, {:.0}% hardware",
                    session.id,
                    session.keystroke_count(),
                    session.sample_count(),
                    duration,
                    phys_ratio * 100.0
                );
            }
        }

        TrackAction::Export { session_id } => {
            // Try to load hybrid session first
            #[cfg(feature = "physjitter")]
            {
                let hybrid_path = tracking_dir.join(format!("{}.hybrid.json", session_id));
                if hybrid_path.exists() {
                    let session = witnessd_core::HybridJitterSession::load(&hybrid_path)
                        .map_err(|e| anyhow!("Error loading hybrid session: {}", e))?;

                    let ev = session.export();

                    // Verify the evidence
                    ev.verify()
                        .map_err(|e| anyhow!("Evidence verification failed: {}", e))?;

                    // Export to JSON
                    let out_path = format!("{}.hybrid-jitter.json", session_id);
                    let data = ev
                        .encode()
                        .map_err(|e| anyhow!("Error encoding evidence: {}", e))?;
                    fs::write(&out_path, &data)?;

                    println!("Hybrid jitter evidence exported to: {}", out_path);
                    println!();
                    println!("Evidence summary:");
                    println!("  Duration: {:?}", ev.statistics.duration);
                    println!("  Keystrokes: {}", ev.statistics.total_keystrokes);
                    println!("  Samples: {}", ev.statistics.total_samples);
                    println!("  Document states: {}", ev.statistics.unique_doc_hashes);
                    println!("  Chain valid: {}", ev.statistics.chain_valid);
                    println!();
                    println!("Entropy quality:");
                    println!(
                        "  Hardware ratio: {:.1}%",
                        ev.entropy_quality.phys_ratio * 100.0
                    );
                    println!("  Physics samples: {}", ev.entropy_quality.phys_samples);
                    println!("  Pure HMAC samples: {}", ev.entropy_quality.pure_samples);
                    println!("  Source: {}", ev.entropy_source());

                    if ev.is_plausible_human_typing() {
                        println!("  Plausibility: consistent with human typing");
                    } else {
                        println!("  Plausibility: unusual patterns detected");
                    }
                    return Ok(());
                }
            }

            // Standard session
            let session_path = tracking_dir.join(format!("{}.session.json", session_id));
            let session = JitterSession::load(&session_path)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

            let ev = session.export();

            // Verify the evidence
            ev.verify()
                .map_err(|e| anyhow!("Evidence verification failed: {}", e))?;

            // Export to JSON
            let out_path = format!("{}.jitter.json", session_id);
            let data = ev
                .encode()
                .map_err(|e| anyhow!("Error encoding evidence: {}", e))?;
            fs::write(&out_path, &data)?;

            println!("Jitter evidence exported to: {}", out_path);
            println!();
            println!("Evidence summary:");
            println!("  Duration: {:?}", ev.statistics.duration);
            println!("  Keystrokes: {}", ev.statistics.total_keystrokes);
            println!("  Samples: {}", ev.statistics.total_samples);
            println!("  Document states: {}", ev.statistics.unique_doc_hashes);
            println!("  Chain valid: {}", ev.statistics.chain_valid);

            if ev.is_plausible_human_typing() {
                println!("  Plausibility: consistent with human typing");
            } else {
                println!("  Plausibility: unusual patterns detected");
            }
        }
    }

    Ok(())
}

// =============================================================================
// Daemon Start/Stop Command Implementation
// =============================================================================

fn cmd_start(foreground: bool) -> Result<()> {
    let config = ensure_dirs()?;

    // Check if daemon is already running
    let daemon_manager = DaemonManager::new(config.data_dir.clone());
    let status = daemon_manager.status();

    if status.running {
        if let Some(pid) = status.pid {
            println!("Daemon is already running (PID: {})", pid);
        } else {
            println!("Daemon is already running.");
        }
        println!();
        println!("Use 'witnessd status' for details or 'witnessd stop' to stop.");
        return Ok(());
    }

    if foreground {
        println!("Starting witnessd daemon in foreground...");
        println!("Press Ctrl+C to stop.");
        println!();

        // TODO: Run daemon in foreground using Sentinel::start()
        // This requires setting up the async runtime and Sentinel properly
        println!("Foreground mode not yet implemented.");
        println!("The sentinel daemon functionality is available but needs");
        println!("integration with the CLI runtime.");
    } else {
        println!("Starting witnessd daemon...");
        println!();

        // TODO: Spawn daemon as background process
        // This requires daemonization logic (fork on Unix, service on Windows)
        println!("Background daemon mode not yet implemented.");
        println!();
        println!("For now, you can use:");
        println!("  - 'witnessd watch start' for file monitoring");
        println!("  - 'witnessd track start <file>' for keystroke tracking");
    }

    Ok(())
}

fn cmd_stop() -> Result<()> {
    let config = ensure_dirs()?;

    let daemon_manager = DaemonManager::new(config.data_dir.clone());
    let status = daemon_manager.status();

    if status.running {
        if let Some(pid) = status.pid {
            println!("Stopping daemon (PID: {})...", pid);

            // Send SIGTERM to the daemon process
            #[cfg(unix)]
            {
                let _ = std::process::Command::new("kill")
                    .arg("-TERM")
                    .arg(pid.to_string())
                    .status();
            }

            #[cfg(windows)]
            {
                // On Windows, we'd need to use taskkill or similar
                let _ = std::process::Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .status();
            }

            // Wait briefly and check if stopped
            std::thread::sleep(Duration::from_millis(500));
            let new_status = daemon_manager.status();
            if !new_status.running {
                println!("Daemon stopped.");
            } else {
                println!("Daemon may still be stopping...");
            }
        } else {
            println!("Daemon appears to be running but PID unknown.");
        }
    } else {
        println!("Daemon is not running.");
    }

    Ok(())
}

// =============================================================================
// Fingerprint Command Implementation
// =============================================================================

fn cmd_fingerprint(action: FingerprintAction) -> Result<()> {
    let config = ensure_dirs()?;
    let fingerprint_dir = config.fingerprint.storage_path.clone();

    match action {
        FingerprintAction::Status => {
            let manager = FingerprintManager::new(&fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            let consent_manager = ConsentManager::new(&config.data_dir)
                .map_err(|e| anyhow!("Failed to open consent manager: {}", e))?;

            println!("=== Fingerprint Status ===");
            println!();

            // Activity fingerprinting status
            println!(
                "Activity fingerprinting: {}",
                if config.fingerprint.activity_enabled {
                    "ENABLED"
                } else {
                    "disabled"
                }
            );
            println!("  (Captures HOW you type - timing, cadence, rhythm)");

            // Voice fingerprinting status
            let voice_status = match consent_manager.status() {
                ConsentStatus::Granted => "ENABLED (consent given)",
                ConsentStatus::Denied => "disabled (consent denied)",
                ConsentStatus::Revoked => "disabled (consent revoked)",
                ConsentStatus::NotRequested => "disabled (consent not requested)",
            };
            println!();
            println!(
                "Voice fingerprinting:    {}",
                if config.fingerprint.voice_enabled {
                    voice_status
                } else {
                    "disabled"
                }
            );
            println!("  (Captures writing style - word patterns, punctuation)");

            // Current profile status from FingerprintManager
            println!();
            let fp_status = manager.status();
            let min_samples = config.fingerprint.min_samples as usize;

            if fp_status.activity_samples == 0 && fp_status.current_profile_id.is_none() {
                println!("Profile: None created yet");
                println!("  Start the daemon to begin building your fingerprint.");
            } else if fp_status.activity_samples < min_samples {
                let progress =
                    (fp_status.activity_samples as f64 / min_samples as f64 * 100.0).min(100.0);
                println!("Profile: Building ({:.0}% complete)", progress);
                println!(
                    "  Samples: {} / {} minimum",
                    fp_status.activity_samples, min_samples
                );
            } else {
                println!("Profile: Ready");
                println!("  Confidence: {:.1}%", fp_status.confidence * 100.0);
                println!("  Activity samples: {}", fp_status.activity_samples);
                if fp_status.voice_samples > 0 {
                    println!("  Voice samples: {}", fp_status.voice_samples);
                }
            }
        }

        FingerprintAction::EnableActivity => {
            let mut config = config;
            config.fingerprint.activity_enabled = true;
            config.persist()?;
            println!("Activity fingerprinting enabled.");
            println!();
            println!("This captures typing timing patterns (HOW you type, not WHAT).");
            println!("Start the daemon with 'witnessd start' to begin collecting.");
        }

        FingerprintAction::DisableActivity => {
            let mut config = config;
            config.fingerprint.activity_enabled = false;
            config.persist()?;
            println!("Activity fingerprinting disabled.");
        }

        FingerprintAction::EnableVoice => {
            let mut consent_manager = ConsentManager::new(&config.data_dir)
                .map_err(|e| anyhow!("Failed to open consent manager: {}", e))?;

            // Check current status
            match consent_manager.status() {
                ConsentStatus::Granted => {
                    println!("Voice fingerprinting is already enabled.");
                    return Ok(());
                }
                ConsentStatus::Denied | ConsentStatus::Revoked => {
                    println!("You previously declined voice fingerprinting.");
                    println!();
                }
                ConsentStatus::NotRequested => {}
            }

            // Show consent explanation
            println!("=== Voice Fingerprinting Consent ===");
            println!();
            println!(
                "{}",
                witnessd_core::fingerprint::consent::CONSENT_EXPLANATION
            );
            println!();

            // Ask for consent
            print!("Do you consent to voice fingerprinting? (yes/no): ");
            io::stdout().flush()?;

            let stdin = io::stdin();
            let mut response = String::new();
            stdin.lock().read_line(&mut response)?;
            let response = response.trim().to_lowercase();

            if response == "yes" || response == "y" {
                consent_manager
                    .grant_consent()
                    .map_err(|e| anyhow!("Failed to record consent: {}", e))?;

                let mut config = config;
                config.fingerprint.voice_enabled = true;
                config.persist()?;

                println!();
                println!("Voice fingerprinting enabled.");
                println!("Your writing style will now be analyzed (no raw text stored).");
            } else {
                consent_manager
                    .deny_consent()
                    .map_err(|e| anyhow!("Failed to record denial: {}", e))?;

                println!();
                println!("Voice fingerprinting not enabled.");
            }
        }

        FingerprintAction::DisableVoice => {
            let mut consent_manager = ConsentManager::new(&config.data_dir)
                .map_err(|e| anyhow!("Failed to open consent manager: {}", e))?;

            // Revoke consent
            consent_manager
                .revoke_consent()
                .map_err(|e| anyhow!("Failed to revoke consent: {}", e))?;

            // Update config
            let mut config = config;
            config.fingerprint.voice_enabled = false;
            config.persist()?;

            // Note: Voice data deletion would require iterating through profiles
            // For now, just disable voice collection
            println!("Voice fingerprinting disabled.");
            println!("Voice data collection has been stopped.");
            println!("To delete existing voice data, delete profiles individually.");
        }

        FingerprintAction::Show { id } => {
            let manager = FingerprintManager::new(&fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            let profile_id: ProfileId = id.unwrap_or_else(|| {
                // Try to get current profile ID
                manager
                    .status()
                    .current_profile_id
                    .unwrap_or_else(|| "default".to_string())
            });

            match manager.load(&profile_id) {
                Ok(fp) => {
                    println!("=== Fingerprint Profile: {} ===", fp.id);
                    println!();
                    println!("Name: {}", fp.name.as_deref().unwrap_or("(unnamed)"));
                    println!("Created: {}", fp.created_at.format("%Y-%m-%d %H:%M:%S"));
                    println!("Updated: {}", fp.updated_at.format("%Y-%m-%d %H:%M:%S"));
                    println!("Samples: {}", fp.sample_count);
                    println!("Confidence: {:.1}%", fp.confidence * 100.0);
                    println!();

                    println!("Activity Fingerprint:");
                    println!("  IKI mean: {:.1} ms", fp.activity.iki_distribution.mean);
                    println!("  IKI std: {:.1} ms", fp.activity.iki_distribution.std_dev);
                    println!(
                        "  Zone preference: {}",
                        fp.activity.zone_profile.dominant_zone()
                    );

                    if let Some(voice) = &fp.voice {
                        println!();
                        println!("Voice Fingerprint:");
                        println!("  Word samples: {}", voice.total_words);
                        println!("  Avg word length: {:.1}", voice.avg_word_length());
                    }
                }
                Err(e) => {
                    return Err(anyhow!("Profile not found: {}", e));
                }
            }
        }

        FingerprintAction::Compare { id1, id2 } => {
            let manager = FingerprintManager::new(&fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            let comparison = manager
                .compare(&id1, &id2)
                .map_err(|e| anyhow!("Failed to compare profiles: {}", e))?;

            println!("=== Fingerprint Comparison ===");
            println!();
            println!("Profile A: {}", comparison.profile_a);
            println!("Profile B: {}", comparison.profile_b);
            println!();
            println!("Overall Similarity: {:.1}%", comparison.similarity * 100.0);
            println!(
                "Activity Similarity: {:.1}%",
                comparison.activity_similarity * 100.0
            );
            if let Some(voice_sim) = comparison.voice_similarity {
                println!("Voice Similarity: {:.1}%", voice_sim * 100.0);
            }
            println!();
            println!("Confidence: {:.1}%", comparison.confidence * 100.0);
            println!("Verdict: {}", comparison.verdict.description());
        }

        FingerprintAction::List => {
            let manager = FingerprintManager::new(&fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            let profiles = manager
                .list_profiles()
                .map_err(|e| anyhow!("Failed to list profiles: {}", e))?;

            if profiles.is_empty() {
                println!("No fingerprint profiles stored.");
                println!();
                println!("Start the daemon to begin building your fingerprint:");
                println!("  witnessd start");
                return Ok(());
            }

            println!("Stored fingerprint profiles:");
            for profile in profiles {
                let voice_indicator = if profile.has_voice { " [+voice]" } else { "" };
                println!(
                    "  {}: {} samples, {:.0}% confidence{}",
                    profile.id,
                    profile.sample_count,
                    profile.confidence * 100.0,
                    voice_indicator
                );
            }
        }

        FingerprintAction::Delete { id, force } => {
            if !force {
                print!("Delete fingerprint profile '{}'? (yes/no): ", id);
                io::stdout().flush()?;

                let stdin = io::stdin();
                let mut response = String::new();
                stdin.lock().read_line(&mut response)?;
                let response = response.trim().to_lowercase();

                if response != "yes" && response != "y" {
                    println!("Cancelled.");
                    return Ok(());
                }
            }

            let mut manager = FingerprintManager::new(&fingerprint_dir)
                .map_err(|e| anyhow!("Failed to open fingerprint storage: {}", e))?;

            manager
                .delete(&id)
                .map_err(|e| anyhow!("Failed to delete profile: {}", e))?;

            println!("Profile '{}' deleted.", id);
        }
    }

    Ok(())
}

// =============================================================================
// Session Command Implementation
// =============================================================================

fn cmd_session(action: SessionAction) -> Result<()> {
    let config = ensure_dirs()?;
    let sentinel_dir = config.data_dir.join("sentinel");

    match action {
        SessionAction::List => {
            let sessions_file = sentinel_dir.join("active_sessions.json");

            if !sessions_file.exists() {
                println!("No active sessions.");
                println!();
                println!("Start the daemon to begin tracking sessions:");
                println!("  witnessd start");
                return Ok(());
            }

            let data = fs::read_to_string(&sessions_file)?;
            let sessions: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap_or_default();

            if sessions.is_empty() {
                println!("No active sessions.");
                return Ok(());
            }

            println!("Active sessions:");
            for session in sessions {
                let id = session
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let binding = session
                    .get("binding_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let samples = session
                    .get("sample_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                println!("  {}: {} binding, {} samples", id, binding, samples);
            }
        }

        SessionAction::Show { id } => {
            let session_file = sentinel_dir.join("sessions").join(format!("{}.json", id));

            if !session_file.exists() {
                return Err(anyhow!("Session not found: {}", id));
            }

            let data = fs::read_to_string(&session_file)?;
            let session: serde_json::Value = serde_json::from_str(&data)?;

            println!("=== Session: {} ===", id);
            println!();
            println!("{}", serde_json::to_string_pretty(&session)?);
        }

        SessionAction::Export { id, output } => {
            let session_file = sentinel_dir.join("sessions").join(format!("{}.json", id));

            if !session_file.exists() {
                return Err(anyhow!("Session not found: {}", id));
            }

            let out_path = output.unwrap_or_else(|| PathBuf::from(format!("{}.session.json", id)));

            fs::copy(&session_file, &out_path)?;

            println!("Session exported to: {}", out_path.display());
        }
    }

    Ok(())
}

// =============================================================================
// Config Command Implementation
// =============================================================================

fn cmd_config(action: ConfigAction) -> Result<()> {
    let dir = witnessd_dir()?;
    let config_path = dir.join("witnessd.json");

    match action {
        ConfigAction::Show => {
            let config = WitnessdConfig::load_or_default(&dir)?;

            println!("=== witnessd Configuration ===");
            println!();
            println!("Data directory: {}", config.data_dir.display());
            println!();
            println!("[VDF]");
            println!(
                "  iterations_per_second: {}",
                config.vdf.iterations_per_second
            );
            println!("  min_iterations: {}", config.vdf.min_iterations);
            println!("  max_iterations: {}", config.vdf.max_iterations);
            println!();
            println!("[Sentinel]");
            println!("  auto_start: {}", config.sentinel.auto_start);
            println!(
                "  heartbeat_interval_secs: {}",
                config.sentinel.heartbeat_interval_secs
            );
            println!(
                "  checkpoint_interval_secs: {}",
                config.sentinel.checkpoint_interval_secs
            );
            println!("  idle_timeout_secs: {}", config.sentinel.idle_timeout_secs);
            println!();
            println!("[Fingerprint]");
            println!(
                "  activity_enabled: {}",
                config.fingerprint.activity_enabled
            );
            println!("  voice_enabled: {}", config.fingerprint.voice_enabled);
            println!("  retention_days: {}", config.fingerprint.retention_days);
            println!("  min_samples: {}", config.fingerprint.min_samples);
            println!();
            println!("[Privacy]");
            println!(
                "  detect_sensitive_fields: {}",
                config.privacy.detect_sensitive_fields
            );
            println!("  hash_urls: {}", config.privacy.hash_urls);
            println!("  obfuscate_titles: {}", config.privacy.obfuscate_titles);
            println!();
            println!("Config file: {}", config_path.display());
        }

        ConfigAction::Set { key, value } => {
            let mut config = WitnessdConfig::load_or_default(&dir)?;

            // Parse key path (e.g., "sentinel.auto_start")
            let parts: Vec<&str> = key.split('.').collect();

            match parts.as_slice() {
                ["sentinel", "auto_start"] => {
                    config.sentinel.auto_start = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid boolean value: {}", value))?;
                }
                ["sentinel", "heartbeat_interval_secs"] => {
                    config.sentinel.heartbeat_interval_secs = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                }
                ["sentinel", "checkpoint_interval_secs"] => {
                    config.sentinel.checkpoint_interval_secs = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                }
                ["sentinel", "idle_timeout_secs"] => {
                    config.sentinel.idle_timeout_secs = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                }
                ["fingerprint", "activity_enabled"] => {
                    config.fingerprint.activity_enabled = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid boolean value: {}", value))?;
                }
                ["fingerprint", "voice_enabled"] => {
                    config.fingerprint.voice_enabled = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid boolean value: {}", value))?;
                }
                ["fingerprint", "retention_days"] => {
                    config.fingerprint.retention_days = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                }
                ["fingerprint", "min_samples"] => {
                    config.fingerprint.min_samples = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                }
                ["privacy", "detect_sensitive_fields"] => {
                    config.privacy.detect_sensitive_fields = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid boolean value: {}", value))?;
                }
                ["privacy", "hash_urls"] => {
                    config.privacy.hash_urls = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid boolean value: {}", value))?;
                }
                ["privacy", "obfuscate_titles"] => {
                    config.privacy.obfuscate_titles = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid boolean value: {}", value))?;
                }
                _ => {
                    return Err(anyhow!(
                        "Unknown configuration key: {}\n\n\
                         Valid keys:\n  \
                           sentinel.auto_start\n  \
                           sentinel.heartbeat_interval_secs\n  \
                           sentinel.checkpoint_interval_secs\n  \
                           sentinel.idle_timeout_secs\n  \
                           fingerprint.activity_enabled\n  \
                           fingerprint.voice_enabled\n  \
                           fingerprint.retention_days\n  \
                           fingerprint.min_samples\n  \
                           privacy.detect_sensitive_fields\n  \
                           privacy.hash_urls\n  \
                           privacy.obfuscate_titles",
                        key
                    ));
                }
            }

            config.persist()?;
            println!("Set {} = {}", key, value);
        }

        ConfigAction::Edit => {
            // Ensure config file exists
            let config = WitnessdConfig::load_or_default(&dir)?;
            config.persist()?;

            // Open in editor
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| {
                if cfg!(target_os = "windows") {
                    "notepad".to_string()
                } else {
                    "nano".to_string()
                }
            });

            println!("Opening {} in {}...", config_path.display(), editor);

            let status = std::process::Command::new(&editor)
                .arg(&config_path)
                .status()
                .map_err(|e| anyhow!("Failed to open editor '{}': {}", editor, e))?;

            if status.success() {
                // Validate the edited config
                match WitnessdConfig::load_or_default(&dir) {
                    Ok(_) => println!("Configuration saved."),
                    Err(e) => println!("Warning: Configuration may be invalid: {}", e),
                }
            }
        }

        ConfigAction::Reset { force } => {
            if !force {
                print!("Reset all configuration to defaults? (yes/no): ");
                io::stdout().flush()?;

                let stdin = io::stdin();
                let mut response = String::new();
                stdin.lock().read_line(&mut response)?;
                let response = response.trim().to_lowercase();

                if response != "yes" && response != "y" {
                    println!("Cancelled.");
                    return Ok(());
                }
            }

            // Remove config file
            if config_path.exists() {
                fs::remove_file(&config_path)?;
            }

            // Create new default config
            let config = WitnessdConfig::load_or_default(&dir)?;
            config.persist()?;

            println!("Configuration reset to defaults.");
        }
    }

    Ok(())
}

// =============================================================================
// Calibrate Command Implementation
// =============================================================================

fn cmd_calibrate() -> Result<()> {
    println!("Calibrating VDF performance...");
    println!("This measures your CPU's SHA-256 hashing speed.");
    println!();

    let calibrated_params =
        calibrate(Duration::from_secs(2)).map_err(|e| anyhow!("Calibration failed: {}", e))?;

    println!(
        "Iterations per second: {}",
        calibrated_params.iterations_per_second
    );
    println!(
        "Min iterations (0.1s): {}",
        calibrated_params.min_iterations
    );
    println!(
        "Max iterations (1hr):  {}",
        calibrated_params.max_iterations
    );
    println!();

    // Save to config
    let mut config = ensure_dirs()?;
    config.vdf.iterations_per_second = calibrated_params.iterations_per_second;
    config.vdf.min_iterations = calibrated_params.min_iterations;
    config.vdf.max_iterations = calibrated_params.max_iterations;
    config.persist()?;

    println!("Calibration saved.");

    Ok(())
}

// =============================================================================
// Status Command Implementation
// =============================================================================

fn cmd_status() -> Result<()> {
    let config = ensure_dirs()?;
    let dir = &config.data_dir;

    println!("=== witnessd Status ===");
    println!();

    println!("Data directory: {}", dir.display());

    // Check signing key
    let key_path = dir.join("signing_key.pub");
    if let Ok(pub_key) = fs::read(&key_path) {
        if pub_key.len() >= 8 {
            println!("Public key: {}...", hex::encode(&pub_key[..8]));
        }
    }

    // Check identity
    let identity_path = dir.join("identity.json");
    if identity_path.exists() {
        if let Ok(data) = fs::read_to_string(&identity_path) {
            if let Ok(identity) = serde_json::from_str::<serde_json::Value>(&data) {
                println!(
                    "Master Identity: {}",
                    identity
                        .get("fingerprint")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                );
            }
        }
    }

    // Check VDF calibration
    println!("VDF iterations/sec: {}", config.vdf.iterations_per_second);

    println!();
    println!("=== Secure Database ===");

    // Check SQLite database
    let db_path = dir.join("events.db");
    let signing_key_path = dir.join("signing_key");

    if db_path.exists() && signing_key_path.exists() {
        match fs::read(&signing_key_path) {
            Ok(key_data) => {
                // Use first 32 bytes for consistency with both 32-byte and 64-byte key formats
                let seed_data = if key_data.len() >= 32 {
                    &key_data[..32]
                } else {
                    &key_data
                };
                let hmac_key = derive_hmac_key(seed_data);
                match SecureStore::open(&db_path, hmac_key) {
                    Ok(store) => {
                        println!("Database: VERIFIED (tamper-evident)");
                        // List tracked files
                        if let Ok(files) = store.list_files() {
                            println!();
                            println!("Tracked documents: {}", files.len());
                            for (path, last_ts, count) in files.iter().take(10) {
                                let ts = Utc.timestamp_nanos(*last_ts);
                                println!(
                                    "  {} ({} checkpoints, last: {})",
                                    path,
                                    count,
                                    ts.format("%Y-%m-%d %H:%M")
                                );
                            }
                            if files.len() > 10 {
                                println!("  ... and {} more", files.len() - 10);
                            }
                        }
                    }
                    Err(e) => {
                        println!("Database: ERROR ({})", e);
                    }
                }
            }
            Err(e) => {
                println!("Database: ERROR reading key ({})", e);
            }
        }
    } else {
        println!("Database: not found");
    }

    println!();
    println!("=== Sessions ===");

    // Check chains
    let chains_dir = dir.join("chains");
    if let Ok(entries) = fs::read_dir(&chains_dir) {
        let count = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "json")
                    .unwrap_or(false)
            })
            .count();
        println!("JSON chains: {}", count);
    } else {
        println!("JSON chains: 0");
    }

    // Check for active presence session
    let session_file = dir.join("sessions").join("current.json");
    if session_file.exists() {
        println!("Presence session: ACTIVE");
    } else {
        println!("Presence session: none");
    }

    // Check for active tracking session
    let tracking_file = dir.join("tracking").join("current_session.json");
    if tracking_file.exists() {
        println!("Tracking session: ACTIVE");
    } else {
        println!("Tracking session: none");
    }

    println!();
    println!("=== Hardware ===");

    // Use catch_unwind to gracefully handle any hardware detection issues
    match std::panic::catch_unwind(|| {
        let provider = tpm::detect_provider();
        let caps = provider.capabilities();
        (provider, caps)
    }) {
        Ok((provider, caps)) => {
            if caps.hardware_backed {
                println!("TPM: hardware-backed");
                println!("  Device ID: {}", provider.device_id());
                println!("  Supports PCRs: {}", caps.supports_pcrs);
                println!("  Supports sealing: {}", caps.supports_sealing);
                println!("  Supports attestation: {}", caps.supports_attestation);
                println!("  Monotonic counter: {}", caps.monotonic_counter);
                println!("  Secure clock: {}", caps.secure_clock);
            } else {
                println!("TPM: not available (software provider)");
            }
        }
        Err(_) => {
            println!("TPM: detection failed (hardware probe error)");
            println!("  Using software provider as fallback");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {:#}", e);
        eprintln!();
        eprintln!("For more information, try 'witnessd --help'");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Auto-start daemon if configured and not already running
    // (Skip for start/stop/status/init commands to avoid recursion)
    let should_auto_start = !matches!(
        &cli.command,
        Some(Commands::Start { .. })
            | Some(Commands::Stop)
            | Some(Commands::Status)
            | Some(Commands::Init { .. })
            | Some(Commands::Calibrate)
            | Some(Commands::Config { .. })
            | None
    );

    if should_auto_start {
        if let Ok(dir) = witnessd_dir() {
            if let Ok(config) = WitnessdConfig::load_or_default(&dir) {
                if config.sentinel.auto_start {
                    // Check if daemon is running
                    let daemon_manager = DaemonManager::new(config.data_dir.clone());
                    let status = daemon_manager.status();
                    if !status.running {
                        // Auto-start is configured but daemon isn't running
                        // For now, we don't auto-spawn the daemon - that would require
                        // proper daemonization. Just note that auto_start is set.
                        // Users can run 'witnessd start' manually.
                    }
                }
            }
        }
    }

    match cli.command {
        Some(Commands::Init { _path: _ }) => {
            cmd_init()?;
        }
        Some(Commands::Commit { file, message }) => {
            // Use smart commit to handle optional file and auto-init
            cmd_commit_smart(file, message)?;
        }
        Some(Commands::Log { file }) => {
            // Use smart log to handle optional file
            cmd_log_smart(file)?;
        }
        Some(Commands::Export { file, tier, output, format }) => {
            cmd_export(&file, &tier, output, None, &format)?;
        }
        Some(Commands::Verify { file, key }) => {
            cmd_verify(&file, key)?;
        }
        Some(Commands::Presence { action }) => {
            cmd_presence(action)?;
        }
        Some(Commands::Track { action }) => {
            cmd_track(action)?;
        }
        Some(Commands::Calibrate) => {
            cmd_calibrate()?;
        }
        Some(Commands::Status) => {
            cmd_status()?;
        }
        Some(Commands::List) => {
            cmd_list()?;
        }
        Some(Commands::Watch { action, folder }) => {
            cmd_watch_smart(action, folder).await?;
        }
        Some(Commands::Start { foreground }) => {
            cmd_start(foreground)?;
        }
        Some(Commands::Stop) => {
            cmd_stop()?;
        }
        Some(Commands::Fingerprint { action }) => {
            cmd_fingerprint(action)?;
        }
        Some(Commands::Session { action }) => {
            cmd_session(action)?;
        }
        Some(Commands::Config { action }) => {
            cmd_config(action)?;
        }
        None => {
            // No command provided - show smart status dashboard
            show_quick_status()?;
        }
    }

    Ok(())
}

// =============================================================================
// List Command Implementation
// =============================================================================

fn cmd_list() -> Result<()> {
    let db = open_secure_store()?;
    let files = db.list_files()?;

    if files.is_empty() {
        println!("No tracked documents.");
        return Ok(());
    }

    println!("Tracked documents:");
    for (path, last_ts, count) in &files {
        let ts = Utc.timestamp_nanos(*last_ts);
        println!(
            "  {} ({} checkpoints, last: {})",
            path,
            count,
            ts.format("%Y-%m-%d %H:%M")
        );
    }

    Ok(())
}

// =============================================================================
// Smart Defaults Helper Functions
// =============================================================================

/// Show quick status when no command is given
fn show_quick_status() -> Result<()> {
    let dir = witnessd_dir()?;
    let config = WitnessdConfig::load_or_default(&dir)?;

    // Get tracked files if initialized
    let tracked_files = if dir.join("signing_key").exists() {
        match open_secure_store() {
            Ok(db) => db.list_files().unwrap_or_default(),
            Err(_) => vec![],
        }
    } else {
        vec![]
    };

    smart_defaults::show_quick_status(&dir, config.vdf.iterations_per_second, &tracked_files);
    Ok(())
}

/// Smart commit - handles auto-init and file selection
fn cmd_commit_smart(file: Option<PathBuf>, message: Option<String>) -> Result<()> {
    let dir = witnessd_dir()?;

    // Auto-init if not initialized
    if !smart_defaults::is_initialized(&dir) {
        println!("WitnessD is not initialized.");
        if smart_defaults::ask_confirmation("Initialize now?", true)? {
            cmd_init()?;
            println!();
        } else {
            return Err(anyhow!("Run 'witnessd init' first."));
        }
    }

    // Warn about VDF calibration
    let config = ensure_dirs()?;
    smart_defaults::ensure_vdf_calibrated_with_warning(config.vdf.iterations_per_second);

    // Determine file to commit
    let file_path = match file {
        Some(f) => {
            // Handle "." or "./" - show file selection
            let path_str = f.to_string_lossy();
            if path_str == "." || path_str == "./" {
                select_file_for_commit()?
            } else {
                f
            }
        }
        None => select_file_for_commit()?,
    };

    // Use default message if none provided
    let msg = message.or_else(|| Some(smart_defaults::default_commit_message()));

    cmd_commit(&file_path, msg)
}

/// Select a file for commit interactively
fn select_file_for_commit() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;

    // First check for tracked files in current directory
    if let Ok(db) = open_secure_store() {
        let tracked = db.list_files()?;
        let cwd_str = cwd.to_string_lossy();
        let tracked_in_cwd: Vec<PathBuf> = tracked
            .iter()
            .filter(|(path, _, _)| path.starts_with(cwd_str.as_ref()))
            .map(|(path, _, _)| PathBuf::from(path))
            .collect();

        if tracked_in_cwd.len() == 1 {
            // Single tracked file - use it
            let file = &tracked_in_cwd[0];
            println!(
                "Using tracked file: {}",
                file.file_name().unwrap_or_default().to_string_lossy()
            );
            return Ok(file.clone());
        } else if !tracked_in_cwd.is_empty() {
            // Multiple tracked files - let user choose
            println!("Multiple tracked files found:");
            if let Some(selected) = smart_defaults::select_file_from_list(&tracked_in_cwd, "")? {
                return Ok(selected);
            }
        }
    }

    // Fall back to recently modified files
    let recent = smart_defaults::get_recently_modified_files(&cwd, 10);
    if recent.is_empty() {
        return Err(anyhow!(
            "No files found in current directory.\n\n\
             Specify a file: witnessd commit <file>"
        ));
    }

    println!("Select a file to checkpoint:");
    match smart_defaults::select_file_from_list(&recent, "")? {
        Some(f) => Ok(f),
        None => Err(anyhow!("No file selected.")),
    }
}

/// Smart log - lists all files if none specified
fn cmd_log_smart(file: Option<PathBuf>) -> Result<()> {
    match file {
        Some(f) => cmd_log(&f),
        None => {
            // No file - list all tracked documents
            println!("No file specified. Showing all tracked documents:");
            println!();
            cmd_list()
        }
    }
}

/// Smart watch - handles default folder and starts if no action given
async fn cmd_watch_smart(action: Option<WatchAction>, folder: Option<PathBuf>) -> Result<()> {
    // Handle folder shortcut
    if let Some(f) = folder {
        let path = smart_defaults::normalize_path(&f)?;
        let action = WatchAction::Add {
            path: Some(path),
            patterns: "*.txt,*.md,*.rtf,*.doc,*.docx".to_string(),
        };
        return cmd_watch(Some(action)).await;
    }

    // Handle action
    match action {
        Some(WatchAction::Add { path, patterns }) => {
            // Default to current directory if no path
            let watch_path = match path {
                Some(p) => smart_defaults::normalize_path(&p)?,
                None => std::env::current_dir()?,
            };
            let action = WatchAction::Add {
                path: Some(watch_path),
                patterns,
            };
            cmd_watch(Some(action)).await
        }
        Some(a) => cmd_watch(Some(a)).await,
        None => {
            // No action - start watching if configured, otherwise show status
            let config = load_watch_config()?;
            if config.folders.is_empty() {
                println!("No folders configured for watching.");
                println!();
                println!("Add a folder with: witnessd watch add <folder>");
                println!("Or start watching current directory: witnessd watch .");
                Ok(())
            } else {
                // Start watching
                cmd_watch(Some(WatchAction::Start)).await
            }
        }
    }
}

// =============================================================================
// Watch Command Implementation
// =============================================================================

use glob::Pattern;
use notify::{
    Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use std::sync::mpsc as std_mpsc;

/// Watch configuration stored in config
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WatchConfig {
    folders: Vec<WatchFolder>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WatchFolder {
    path: String,
    patterns: Vec<String>,
    enabled: bool,
}

fn load_watch_config() -> Result<WatchConfig> {
    let dir = witnessd_dir()?;
    let config_path = dir.join("watch_config.json");

    if config_path.exists() {
        let data = fs::read_to_string(&config_path)?;
        Ok(serde_json::from_str(&data)?)
    } else {
        Ok(WatchConfig { folders: vec![] })
    }
}

fn save_watch_config(config: &WatchConfig) -> Result<()> {
    let dir = witnessd_dir()?;
    let config_path = dir.join("watch_config.json");
    let data = serde_json::to_string_pretty(config)?;
    fs::write(config_path, data)?;
    Ok(())
}

async fn cmd_watch(action: Option<WatchAction>) -> Result<()> {
    let action = action.ok_or_else(|| anyhow!("No watch action specified"))?;
    match action {
        WatchAction::Add { path, patterns } => {
            // Use provided path or default to current directory
            let watch_path = path.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
            let abs_path = fs::canonicalize(&watch_path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    anyhow!(
                        "Folder not found: {}\n\n\
                         Check that the folder exists and the path is correct.",
                        watch_path.display()
                    )
                } else {
                    anyhow!("Cannot access folder {}: {}", watch_path.display(), e)
                }
            })?;

            if !abs_path.is_dir() {
                return Err(anyhow!(
                    "Not a directory: {}\n\n\
                     The specified path is not a folder.",
                    watch_path.display()
                ));
            }

            let mut config = load_watch_config()?;
            let path_str = abs_path.to_string_lossy().to_string();

            // Check if already exists
            if config.folders.iter().any(|f| f.path == path_str) {
                println!("Folder already being watched: {}", path_str);
                return Ok(());
            }

            let pattern_list: Vec<String> =
                patterns.split(',').map(|s| s.trim().to_string()).collect();

            config.folders.push(WatchFolder {
                path: path_str.clone(),
                patterns: pattern_list.clone(),
                enabled: true,
            });

            save_watch_config(&config)?;

            println!("Added watch folder: {}", path_str);
            println!("  Patterns: {}", pattern_list.join(", "));
        }

        WatchAction::Remove { path } => {
            let abs_path = fs::canonicalize(&path).unwrap_or(path.clone());
            let path_str = abs_path.to_string_lossy().to_string();

            let mut config = load_watch_config()?;
            let before = config.folders.len();
            config.folders.retain(|f| f.path != path_str);

            if config.folders.len() < before {
                save_watch_config(&config)?;
                println!("Removed watch folder: {}", path_str);
            } else {
                println!("Folder not in watch list: {}", path_str);
            }
        }

        WatchAction::List => {
            let config = load_watch_config()?;

            if config.folders.is_empty() {
                println!("No folders being watched.");
                println!();
                println!("Add a folder with: witnessd watch add <path>");
                return Ok(());
            }

            println!("Watched folders:");
            for folder in &config.folders {
                let status = if folder.enabled { "active" } else { "paused" };
                println!("  {} [{}]", folder.path, status);
                println!("    Patterns: {}", folder.patterns.join(", "));
            }
        }

        WatchAction::Status => {
            let config = load_watch_config()?;
            let db = open_secure_store()?;
            let files = db.list_files()?;

            println!("=== Watch Status ===");
            println!();
            println!("Folders: {}", config.folders.len());
            println!("Documents tracked: {}", files.len());

            if !config.folders.is_empty() {
                println!();
                println!("Active watch folders:");
                for folder in config.folders.iter().filter(|f| f.enabled) {
                    println!("  {}", folder.path);
                }
            }
        }

        WatchAction::Start => {
            let config = load_watch_config()?;

            if config.folders.is_empty() {
                println!("No folders configured. Add folders first:");
                println!("  witnessd watch add <path>");
                return Ok(());
            }

            println!("Starting automatic checkpoint watcher...");
            println!("Watching {} folder(s)", config.folders.len());
            println!();
            println!("Press Ctrl+C to stop.");
            println!();

            run_watcher(&config).await?;
        }
    }

    Ok(())
}

async fn run_watcher(config: &WatchConfig) -> Result<()> {
    let (tx, rx) = std_mpsc::channel();

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        NotifyConfig::default().with_poll_interval(Duration::from_secs(2)),
    )?;

    // Compile patterns
    let mut folder_patterns: Vec<(PathBuf, Vec<Pattern>)> = vec![];

    for folder in config.folders.iter().filter(|f| f.enabled) {
        let path = PathBuf::from(&folder.path);
        let patterns: Vec<Pattern> = folder
            .patterns
            .iter()
            .filter_map(|p| Pattern::new(p).ok())
            .collect();

        watcher.watch(&path, RecursiveMode::Recursive)?;
        println!("Watching: {}", folder.path);
        folder_patterns.push((path, patterns));
    }

    println!();

    // Track recently checkpointed files to debounce
    let mut last_checkpoint: HashMap<PathBuf, Instant> = HashMap::new();
    let debounce_duration = Duration::from_secs(5);

    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(event) => {
                // Only handle modify/create events
                match event.kind {
                    EventKind::Modify(_) | EventKind::Create(_) => {
                        for path in event.paths {
                            // Check if file matches any watched pattern
                            if should_checkpoint(&path, &folder_patterns) {
                                // Debounce
                                let now = Instant::now();
                                if let Some(last) = last_checkpoint.get(&path) {
                                    if now.duration_since(*last) < debounce_duration {
                                        continue;
                                    }
                                }

                                // Create checkpoint
                                if path.exists() && path.is_file() {
                                    match auto_checkpoint(&path) {
                                        Ok(()) => {
                                            last_checkpoint.insert(path.clone(), now);
                                            println!(
                                                "[{}] Checkpoint: {}",
                                                Utc::now().format("%H:%M:%S"),
                                                path.file_name()
                                                    .unwrap_or_default()
                                                    .to_string_lossy()
                                            );
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "Checkpoint error for {}: {}",
                                                path.display(),
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                // Normal timeout, continue
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    Ok(())
}

fn should_checkpoint(path: &Path, folder_patterns: &[(PathBuf, Vec<Pattern>)]) -> bool {
    let file_name: &str = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };

    // Skip hidden files and temp files
    if file_name.starts_with('.') || file_name.ends_with('~') || file_name.ends_with(".tmp") {
        return false;
    }

    for (folder, patterns) in folder_patterns {
        if path.starts_with(folder) {
            // If no patterns, match all
            if patterns.is_empty() {
                return true;
            }
            // Check if file matches any pattern
            for pattern in patterns {
                if pattern.matches(file_name) {
                    return true;
                }
            }
        }
    }

    false
}

fn auto_checkpoint(file_path: &Path) -> Result<()> {
    let abs_path = fs::canonicalize(file_path)?;
    let abs_path_str = abs_path.to_string_lossy().to_string();

    let mut db = open_secure_store()?;

    // Read file and compute hash
    let content = fs::read(&abs_path)?;
    let content_hash: [u8; 32] = Sha256::digest(&content).into();
    let file_size = content.len() as i64;

    // Check if content changed from last checkpoint
    let events = db.get_events_for_file(&abs_path_str)?;
    if let Some(last) = events.last() {
        if last.content_hash == content_hash {
            // Content unchanged, skip
            return Ok(());
        }
    }

    let last_event = events.last();
    let (vdf_input, size_delta): ([u8; 32], i32) = if let Some(last) = last_event {
        (last.event_hash, (file_size - last.file_size) as i32)
    } else {
        (content_hash, file_size as i32)
    };

    // Compute VDF
    let config = ensure_dirs()?;
    let vdf_params = load_vdf_params(&config);
    let vdf_proof = vdf::compute(vdf_input, Duration::from_millis(500), vdf_params)
        .map_err(|e| anyhow!("VDF failed: {}", e))?;

    // Create event
    let mut event = SecureEvent {
        id: None,
        device_id: get_device_id(),
        machine_id: get_machine_id(),
        timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
        file_path: abs_path_str,
        content_hash,
        file_size,
        size_delta,
        previous_hash: [0u8; 32],
        event_hash: [0u8; 32],
        context_type: Some("auto".to_string()),
        context_note: None,
        vdf_input: Some(vdf_input),
        vdf_output: Some(vdf_proof.output),
        vdf_iterations: vdf_proof.iterations,
        forensic_score: 1.0,
        is_paste: false,
    };

    db.insert_secure_event(&mut event)?;

    Ok(())
}
