// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
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
        #[arg(hide = true)]
        _path: Option<PathBuf>,
    },
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
        file: Option<PathBuf>,
        #[arg(short, long)]
        message: Option<String>,
    },
    #[command(
        alias = "LOG",
        alias = "Log",
        alias = "history",
        after_help = "\
EXAMPLES:\n  \
    witnessd log essay.txt      View checkpoint history\n  \
    witnessd log                List all tracked documents"
    )]
    Log { file: Option<PathBuf> },
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
        file: PathBuf,
        #[arg(short = 't', long, visible_alias = "tier", default_value = "basic")]
        tier: String,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        #[arg(short = 'f', long, default_value = "json")]
        format: String,
    },
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
        file: PathBuf,
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
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
    #[command(after_help = "\
WHY: VDF proofs need to know your CPU speed to calculate elapsed time.\n\n\
WHEN TO RE-CALIBRATE:\n  \
    - After upgrading your CPU\n  \
    - When moving to a different machine")]
    #[command(alias = "CALIBRATE", alias = "Calibrate")]
    Calibrate,
    #[command(alias = "STATUS", alias = "Status")]
    Status,
    #[command(alias = "LIST", alias = "List", alias = "ls")]
    List,
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
        #[arg(conflicts_with = "action")]
        folder: Option<PathBuf>,
    },
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
        #[arg(short, long)]
        foreground: bool,
    },
    #[command(alias = "STOP", alias = "Stop")]
    Stop,
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
    #[command(
        alias = "IDENTITY",
        alias = "Identity",
        alias = "id",
        after_help = "\
EXAMPLES:\n  \
    witnessd identity --fingerprint      Show identity fingerprint\n  \
    witnessd identity --did              Show Decentralized Identifier (DID)\n  \
    witnessd identity --mnemonic         Show recovery phrase (Keep secret!)\n  \
    witnessd identity --recover          Recover from mnemonic (reads from stdin)\n\n\
SECURITY:\n  \
    Use 'witnessd identity --recover' without arguments to enter the phrase securely\n  \
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
        #[cfg(feature = "witnessd_jitter")]
        #[arg(long, help = "Use hardware entropy when available")]
        witnessd_jitter: bool,
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
