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
use witnessd_core::evidence;
use witnessd_core::jitter::{default_parameters as default_jitter_params, Session as JitterSession};
use witnessd_core::keyhierarchy::{derive_master_identity, SoftwarePUF};
use witnessd_core::presence::{ChallengeStatus, Config as PresenceConfig, Session as PresenceSession, Verifier};
use witnessd_core::tpm;
use witnessd_core::vdf;
use witnessd_core::vdf::params::{calibrate, Parameters as VdfParameters};
use witnessd_core::{derive_hmac_key, SecureEvent, SecureStore};

#[derive(Parser)]
#[command(author, version, about = "Cryptographic authorship witnessing CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize witnessd in current directory
    Init,
    /// Create a checkpoint for a file
    Commit {
        /// Path to the file to checkpoint
        file: PathBuf,
        /// Commit message
        #[arg(short, long)]
        message: Option<String>,
    },
    /// Show checkpoint history for a file
    Log {
        /// Path to the file
        file: PathBuf,
    },
    /// Export evidence packet with declaration
    Export {
        /// Path to the file
        file: PathBuf,
        /// Evidence tier: basic, standard, enhanced, maximum
        #[arg(short = 't', long, visible_alias = "tier", default_value = "basic")]
        tier: String,
        /// Output file (default: <file>.evidence.json)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
    /// Verify the integrity of a secure database or evidence packet
    Verify {
        /// Path to the file (database or evidence packet)
        file: PathBuf,
        /// Path to the signing_key file (for database verification)
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    /// Manage presence verification sessions
    Presence {
        #[command(subcommand)]
        action: PresenceAction,
    },
    /// Track keyboard activity (count only, no key capture)
    Track {
        #[command(subcommand)]
        action: TrackAction,
    },
    /// Calibrate VDF performance for this machine
    Calibrate,
    /// Show witnessd status and configuration
    Status,
    /// List all tracked documents
    List,
    /// Watch folders for automatic checkpointing
    Watch {
        #[command(subcommand)]
        action: WatchAction,
    },
}

#[derive(Subcommand)]
enum WatchAction {
    /// Add a folder to watch for automatic checkpointing
    Add {
        /// Path to folder to watch
        path: PathBuf,
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
        fs::create_dir_all(d).with_context(|| format!("Failed to create directory: {:?}", d))?;
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

    let key_data = fs::read(&key_path).context("Failed to read signing key. Run 'witnessd init' first.")?;
    // Handle both 32-byte (seed only) and 64-byte (full keypair) formats
    // Always use the first 32 bytes (seed) for HMAC derivation for consistency
    let seed_data = if key_data.len() >= 32 {
        &key_data[..32]
    } else {
        return Err(anyhow!("Invalid signing key: expected at least 32 bytes"));
    };
    let hmac_key = derive_hmac_key(seed_data);

    SecureStore::open(db_path, hmac_key).context("Failed to open database")
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
            key_data.try_into().map_err(|_| anyhow!("Invalid key file"))? 
        } else if key_data.len() == 64 {
            // Legacy format: first 32 bytes are the seed
            key_data[..32].try_into().map_err(|_| anyhow!("Invalid key file"))? 
        } else {
            return Err(anyhow!("Invalid key file: expected 32 or 64 bytes, got {}", key_data.len()));
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
        fs::write(&identity_path, serde_json::to_string_pretty(&identity_data)?)?;

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
    println!("witnessd initialized!");
    println!();
    println!("Next steps:");
    println!("  1. Run 'witnessd calibrate' to calibrate VDF for your machine");
    println!("  2. Create checkpoints with 'witnessd commit <file> -m \"message\"'");
    println!("  3. Export evidence with 'witnessd export <file>'");
    println!();
    println!("Optional: Run 'witnessd sentinel start' for automatic document tracking");

    Ok(())
}

// =============================================================================
// Commit Command Implementation
// =============================================================================

fn cmd_commit(file_path: &PathBuf, message: Option<String>) -> Result<()> {
    // Check file exists
    if !file_path.exists() {
        return Err(anyhow!("File not found: {:?}", file_path));
    }

    // Get absolute path
    let abs_path = fs::canonicalize(file_path).context("Failed to resolve path")?;
    let abs_path_str = abs_path.to_string_lossy().to_string();

    // Open secure database
    let mut db = open_secure_store()?;

    // Read file content and compute hash
    let content = fs::read(&abs_path).context("Failed to read file")?;
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
        println!("No checkpoint history found for: {:?}", file_path);
        return Ok(())
    }

    // Calculate total VDF time
    let config = ensure_dirs()?;
    let vdf_params = load_vdf_params(&config);
    let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();
    let total_vdf_time = Duration::from_secs_f64(
        total_iterations as f64 / vdf_params.iterations_per_second as f64,
    );

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

fn cmd_export(file_path: &PathBuf, tier: &str, output: Option<PathBuf>) -> Result<()> {
    // Get absolute path
    let abs_path = fs::canonicalize(file_path).context("Failed to resolve path")?;
    let abs_path_str = abs_path.to_string_lossy().to_string();

    // Open database
    let db = open_secure_store()?;

    // Get events for file
    let events = db.get_events_for_file(&abs_path_str)?;

    if events.is_empty() {
        return Err(anyhow!("No checkpoint history found for: {:?}", file_path));
    }

    let config = ensure_dirs()?;
    let dir = &config.data_dir;
    let vdf_params = load_vdf_params(&config);

    // Load signing key
    let key_path = dir.join("signing_key");
    let priv_key_data = fs::read(&key_path).context("Failed to load signing key")?;
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
    let total_vdf_time = Duration::from_secs_f64(
        total_iterations as f64 / vdf_params.iterations_per_second as f64,
    );

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
                "vdf_input": ev.vdf_input.map(|h| hex::encode(h)),
                "vdf_output": ev.vdf_output.map(|h| hex::encode(h)),
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
        "keystroke": null,
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

    // Determine output path
    let out_path = output.unwrap_or_else(|| {
        let name = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        PathBuf::from(format!("{}.evidence.json", name))
    });

    // Save
    let data = serde_json::to_string_pretty(&packet)?;
    fs::write(&out_path, data)?;

    println!();
    println!("Evidence exported to: {:?}", out_path);
    println!("  Checkpoints: {}", events.len());
    println!("  Total VDF time: {:?}", total_vdf_time);
    println!("  Tier: {}", tier);

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
    // Check if it's a JSON file (evidence packet) or database
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

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
    } else {
        // Verify database
        let key_path = key.unwrap_or_else(|| witnessd_dir().unwrap_or_default().join("signing_key"));

        println!("Verifying database: {:?}", file_path);

        let key_data = fs::read(&key_path).context("Failed to read signing key")?;
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
                return Err(anyhow!("Session already active. Run 'witnessd presence stop' first."));
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
                    return Ok(())
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
            let data = fs::read(&session_file).map_err(|_| {
                anyhow!("No active session. Run 'witnessd presence start' first.")
            })?;

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

fn cmd_track(action: TrackAction) -> Result<()> {
    let config = ensure_dirs()?;
    let dir = config.data_dir;
    let tracking_dir = dir.join("tracking");
    let current_file = tracking_dir.join("current_session.json");

    match action {
        TrackAction::Start { file } => {
            // Get absolute path for the file
            let abs_path = fs::canonicalize(&file)
                .with_context(|| format!("Error resolving path: {:?}", file))?;

            // Check file exists
            if !abs_path.exists() {
                return Err(anyhow!("File not found: {:?}", file));
            }

            // Check for existing session
            if current_file.exists() {
                return Err(anyhow!("Tracking session already active. Run 'witnessd track stop' first."));
            }

            // Create a new jitter session
            let jitter_params = default_jitter_params();
            let session = JitterSession::new(&abs_path, jitter_params)
                .map_err(|e| anyhow!("Error creating session: {}", e))?;

            // Save session info
            let session_info = serde_json::json!({
                "id": session.id,
                "document_path": abs_path.to_string_lossy(),
                "started_at": chrono::Utc::now().to_rfc3339(),
            });

            fs::write(&current_file, serde_json::to_string_pretty(&session_info)?)?;

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
        }

        TrackAction::Stop => {
            let data = fs::read_to_string(&current_file)
                .map_err(|_| anyhow!("No active tracking session."))?;

            let session_info: serde_json::Value = serde_json::from_str(&data)?;
            let session_id = session_info
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Invalid session info"))?;

            // Load session
            let session_path = tracking_dir.join(format!("{}.session.json", session_id));
            let mut session = JitterSession::load(&session_path)
                .map_err(|e| anyhow!("Error loading session: {}", e))?;

            // End and save
            session.end();
            session
                .save(&session_path)
                .map_err(|e| anyhow!("Error saving session: {}", e))?;

            // Remove current session marker
            fs::remove_file(&current_file)?;

            let duration = session.duration();
            let keystroke_count = session.keystroke_count();
            let sample_count = session.sample_count();

            println!("Tracking session stopped.");
            println!("Duration: {:?}", duration);
            println!("Keystrokes: {}", keystroke_count);
            println!("Samples: {}", sample_count);

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
        }

        TrackAction::Status => {
            let data = match fs::read_to_string(&current_file) {
                Ok(d) => d,
                Err(_) => {
                    println!("No active tracking session.");
                    return Ok(())
                }
            };

            let session_info: serde_json::Value = serde_json::from_str(&data)?;
            let session_id = session_info
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Invalid session info"))?;

            // Load session
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
                let keystrokes_per_min =
                    keystroke_count as f64 / (duration.as_secs_f64() / 60.0);
                println!("Typing rate: {:.0} keystrokes/min", keystrokes_per_min);
            }
        }

        TrackAction::List => {
            let entries =
                fs::read_dir(&tracking_dir).with_context(|| "Error reading tracking directory")?;

            let mut sessions = Vec::new();
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.ends_with(".session.json"))
                    .unwrap_or(false)
                {
                    if let Ok(session) = JitterSession::load(&path) {
                        sessions.push(session);
                    }
                }
            }

            if sessions.is_empty() {
                println!("No saved tracking sessions.");
                return Ok(())
            }

            println!("Saved tracking sessions:");
            for session in sessions {
                let duration = session.duration();
                println!(
                    "  {}: {} keystrokes, {} samples, {:?}",
                    session.id,
                    session.keystroke_count(),
                    session.sample_count(),
                    duration
                );
            }
        }

        TrackAction::Export { session_id } => {
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
            println!(
                "  Document states: {}",
                ev.statistics.unique_doc_hashes
            );
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

    println!("Data directory: {:?}", dir);

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
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            cmd_init()?;
        }
        Commands::Commit { file, message } => {
            cmd_commit(&file, message)?;
        }
        Commands::Log { file } => {
            cmd_log(&file)?;
        }
        Commands::Export { file, tier, output } => {
            cmd_export(&file, &tier, output)?;
        }
        Commands::Verify { file, key } => {
            cmd_verify(&file, key)?;
        }
        Commands::Presence { action } => {
            cmd_presence(action)?;
        }
        Commands::Track { action } => {
            cmd_track(action)?;
        }
        Commands::Calibrate => {
            cmd_calibrate()?;
        }
        Commands::Status => {
            cmd_status()?;
        }
        Commands::List => {
            cmd_list()?;
        }
        Commands::Watch { action } => {
            cmd_watch(action).await?;
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
        return Ok(())
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
// Watch Command Implementation
// =============================================================================

use glob::Pattern;
use notify::{Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
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

async fn cmd_watch(action: WatchAction) -> Result<()> {
    match action {
        WatchAction::Add { path, patterns } => {
            let abs_path = fs::canonicalize(&path)
                .with_context(|| format!("Folder not found: {:?}", path))?;

            if !abs_path.is_dir() {
                return Err(anyhow!("Not a directory: {:?}", path));
            }

            let mut config = load_watch_config()?;
            let path_str = abs_path.to_string_lossy().to_string();

            // Check if already exists
            if config.folders.iter().any(|f| f.path == path_str) {
                println!("Folder already being watched: {}", path_str);
                return Ok(())
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
                return Ok(())
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
                return Ok(())
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
                                            eprintln!("Checkpoint error for {:?}: {}", path, e);
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
            return Ok(())
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