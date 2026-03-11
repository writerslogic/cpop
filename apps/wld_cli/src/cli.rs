// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Cryptographic authorship witnessing CLI",
    long_about = "WritersLogic creates cryptographic proof of authorship for your documents.\n\n\
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
    1. Initialize:  wld init\n  \
    2. Calibrate:   wld calibrate\n  \
    3. Checkpoint:  wld commit <file> -m \"message\"\n  \
    4. Export:      wld export <file> -t standard\n\n\
SHORTCUTS:\n  \
    wld <file>       Track keystrokes on a file\n  \
    wld <folder>     Watch a folder for changes\n  \
    wld commit       Checkpoint (select from recent files)\n\n\
WHEN TO CHECKPOINT:\n  \
    - After completing a section or paragraph\n  \
    - Before and after major edits\n  \
    - When taking a break from writing\n  \
    More checkpoints = stronger authorship evidence.\n\n\
For command help: wld <command> --help\n\n\
Run 'wld' without arguments for quick status.")]
#[command(args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// File to track or folder to watch (shorthand for `wld track <file>` / `wld watch <folder>`)
    pub path: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize WritersLogic (keys, database, identity)
    #[command(after_help = "\
WHAT IT CREATES:\n  \
    ~/.writerslogic/signing_key     Your private key (keep secure!)\n  \
    ~/.writerslogic/events.db       Tamper-evident checkpoint database\n\n\
NEXT: Run 'wld calibrate' to optimize for your CPU.")]
    Init {},
    /// Create a cryptographic checkpoint of a document
    #[command(
        alias = "checkpoint",
        after_help = "\
EXAMPLES:\n  \
    wld commit essay.txt -m \"Draft 1\"\n  \
    wld commit thesis.tex -m \"Chapter 2\"\n  \
    wld commit              (select from recently modified files)\n\n\
TIP: Checkpoint after sections, before revisions, and on breaks."
    )]
    Commit {
        file: Option<PathBuf>,
        #[arg(short, long)]
        message: Option<String>,
        /// Anchor evidence in WritersProof transparency log (Pro tier).
        #[arg(long)]
        anchor: bool,
    },
    /// View checkpoint history for a document
    #[command(
        alias = "history",
        after_help = "\
EXAMPLES:\n  \
    wld log essay.txt      View checkpoint history\n  \
    wld log                List all tracked documents"
    )]
    Log { file: Option<PathBuf> },
    /// Export evidence packet for a document
    #[command(after_help = "\
EVIDENCE TIERS:\n  \
    basic     Content hashes + timestamps only (fastest)\n  \
    standard  + VDF time proofs + signed declaration (recommended)\n  \
    enhanced  + keystroke timing evidence (requires track sessions)\n  \
    maximum   + presence verification (full forensic package)\n\n\
OUTPUT FORMATS:\n  \
    json      Machine-readable JSON (default)\n  \
    cpop      CDDL-conformant CBOR evidence packet (.cpop)\n  \
    cwar      ASCII-armored CWAR block (human-readable)\n  \
    html      Visual evidence report\n\n\
EXAMPLES:\n  \
    wld export essay.txt -t standard\n  \
    wld export thesis.tex -t enhanced -o proof.json\n  \
    wld export essay.txt -f cpop -o proof.cpop\n  \
    wld export essay.txt -f cwar -o proof.cwar")]
    Export {
        file: PathBuf,
        #[arg(short = 't', long, visible_alias = "tier", default_value = "basic")]
        tier: String,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        #[arg(short = 'f', long, default_value = "json")]
        format: String,
        /// Embed steganographic zero-width character watermark (Pro tier).
        #[arg(long)]
        stego: bool,
    },
    /// Verify an evidence packet, WAR block, or database
    #[command(after_help = "\
INPUT FORMATS:\n  \
    .json     JSON evidence packet\n  \
    .cwar     ASCII-armored CWAR block\n  \
    .db       Local SQLite database\n\n\
EXAMPLES:\n  \
    wld verify essay.evidence.json   Verify evidence packet\n  \
    wld verify proof.cwar            Verify CWAR block\n  \
    wld verify ~/.writerslogic/events.db Verify local database")]
    Verify {
        file: PathBuf,
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    /// Interactive presence verification challenges
    #[command(after_help = "\
EXAMPLES:\n  \
    wld presence start       Start a new session\n  \
    wld presence challenge   Answer a presence challenge\n  \
    wld presence status      Check current session\n  \
    wld presence stop        End session and save results")]
    Presence {
        #[command(subcommand)]
        action: PresenceAction,
    },
    /// Track keystrokes on a document (timing + behavioral evidence)
    #[command(after_help = "\
EXAMPLES:\n  \
    wld track essay.txt          Start tracking a file\n  \
    wld track stop               Stop and save session\n  \
    wld track status             Check active session\n  \
    wld track export <id>        Export session evidence\n\n\
PRIVACY: Only counts keystrokes and timing - NOT what you type.")]
    Track {
        #[command(subcommand)]
        action: Option<TrackAction>,
        /// File to track (shorthand for `wld track start <file>`)
        #[arg(conflicts_with = "action")]
        file: Option<PathBuf>,
    },
    /// Calibrate VDF speed for your CPU
    #[command(after_help = "\
WHY: VDF proofs need to know your CPU speed to calculate elapsed time.\n\n\
WHEN TO RE-CALIBRATE:\n  \
    - After upgrading your CPU\n  \
    - When moving to a different machine")]
    Calibrate,
    /// Show WritersLogic status
    Status,
    /// List all tracked documents
    #[command(alias = "ls")]
    List,
    /// Watch a folder and auto-checkpoint on file changes
    #[command(after_help = "\
EXAMPLES:\n  \
    wld watch add ./documents\n  \
    wld watch add ./thesis -p \"*.tex,*.bib\"\n  \
    wld watch start\n  \
    wld watch                  (start watching if folders configured)\n\n\
DEFAULT PATTERNS: *.txt,*.md,*.rtf,*.doc,*.docx")]
    Watch {
        #[command(subcommand)]
        action: Option<WatchAction>,
        #[arg(conflicts_with = "action")]
        folder: Option<PathBuf>,
    },
    /// Start the WritersLogic daemon
    #[command(after_help = "\
EXAMPLES:\n  \
    wld start                  Start daemon in background\n  \
    wld start --foreground     Run in foreground (for debugging)\n\n\
The daemon provides:\n  \
    - System-wide keystroke monitoring (timing only, not content)\n  \
    - Automatic checkpointing on file save\n  \
    - Activity fingerprint accumulation\n  \
    - Idle detection")]
    Start {
        #[arg(short, long)]
        foreground: bool,
    },
    /// Stop the WritersLogic daemon
    Stop,
    /// Manage activity and voice fingerprints
    #[command(
        alias = "fp",
        after_help = "\
EXAMPLES:\n  \
    wld fingerprint status          Show fingerprint status\n  \
    wld fingerprint enable-voice    Enable voice fingerprinting\n  \
    wld fingerprint show            Show current fingerprint\n  \
    wld fingerprint compare A B     Compare two profiles\n\n\
PRIVACY:\n  \
    Activity fingerprinting is ON by default (captures timing only).\n  \
    Voice fingerprinting is OFF by default (requires explicit consent)."
    )]
    Fingerprint {
        #[command(subcommand)]
        action: FingerprintAction,
    },
    /// Manage tracking sessions
    #[command(after_help = "\
EXAMPLES:\n  \
    wld session list            List active sessions\n  \
    wld session show <id>       Show session details\n  \
    wld session export <id>     Export session evidence")]
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },
    /// Show or recover your cryptographic identity
    #[command(
        alias = "id",
        after_help = "\
EXAMPLES:\n  \
    wld identity --fingerprint      Show identity fingerprint\n  \
    wld identity --did              Show Decentralized Identifier (DID)\n  \
    wld identity --mnemonic         Show recovery phrase (Keep secret!)\n  \
    wld identity --recover          Recover from mnemonic (reads from stdin)\n\n\
SECURITY:\n  \
    Use 'wld identity --recover' without arguments to enter the phrase securely\n  \
    via standard input. Avoid passing the phrase as an argument."
    )]
    Identity {
        #[arg(long)]
        fingerprint: bool,
        #[arg(long)]
        did: bool,
        #[arg(long)]
        mnemonic: bool,
        #[arg(long)]
        recover: bool,
        #[arg(long)]
        json: bool,
    },
    /// View and modify WritersLogic configuration
    #[command(
        alias = "cfg",
        after_help = "\
EXAMPLES:\n  \
    wld config show             Show all configuration\n  \
    wld config set sentinel.auto_start true\n  \
    wld config edit             Open in editor"
    )]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand, Clone)]
pub enum WatchAction {
    Add {
        path: Option<PathBuf>,
        #[arg(short, long, default_value = "*.txt,*.md,*.rtf,*.doc,*.docx")]
        patterns: String,
    },
    Remove {
        path: PathBuf,
    },
    List,
    Start,
    Status,
}

#[derive(Subcommand)]
pub enum PresenceAction {
    Start,
    Stop,
    Status,
    Challenge,
}

#[derive(Subcommand)]
pub enum TrackAction {
    Start {
        file: PathBuf,
        #[cfg(feature = "wld_jitter")]
        #[arg(long, help = "Use hardware entropy when available")]
        wld_jitter: bool,
    },
    Stop,
    Status,
    List,
    Export {
        session_id: String,
    },
}

#[derive(Subcommand)]
pub enum FingerprintAction {
    Status,
    EnableActivity,
    DisableActivity,
    EnableVoice,
    DisableVoice,
    Show {
        #[arg(short, long)]
        id: Option<String>,
    },
    Compare {
        id1: String,
        id2: String,
    },
    List,
    Delete {
        id: String,
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum SessionAction {
    List,
    Show {
        id: String,
    },
    Export {
        id: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    Show,
    Set {
        key: String,
        value: String,
    },
    Edit,
    Reset {
        #[arg(short, long)]
        force: bool,
    },
}
