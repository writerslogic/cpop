// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "WritersLogic — cryptographic proof that a human wrote your document",
    long_about = "\
WritersLogic captures behavioral evidence during document creation and packages \
it into cryptographically signed evidence packets that prove a human authored \
content over time, not generated it instantly with AI.\n\n\
KEY CONCEPTS:\n  \
  Checkpoint   Cryptographic snapshot of your document at a point in time\n  \
  VDF Proof    Mathematical proof that real wall-clock time elapsed (unforgeable)\n  \
  Evidence     Exportable proof bundle (.cpop) with checkpoints, timing, and proofs\n  \
  Declaration  Your signed statement about how the document was created\n\n\
WORKFLOW:\n  \
  1. wld <file>           Start tracking keystrokes on a document\n  \
  2. wld commit <file>    Checkpoint after writing sessions\n  \
  3. wld export <file>    Package evidence for submission\n  \
  4. wld verify <file>    Anyone can verify the evidence offline"
)]
#[command(after_help = "\
QUICK START:\n  \
    $ wld essay.txt                     Track keystrokes on a file\n  \
    $ wld commit essay.txt -m \"Draft 1\"  Checkpoint your progress\n  \
    $ wld export essay.txt -t standard   Export a proof bundle\n  \
    $ wld verify essay.evidence.json     Verify an evidence packet\n\n\
SHORTHAND:\n  \
    wld <file>         Equivalent to 'wld track start <file>'\n  \
    wld <folder>       Track all files in a directory\n  \
    wld                Show status + interactive menu (in a terminal)\n\n\
COMMON WORKFLOWS:\n  \
    Track + Commit     wld essay.txt && wld commit essay.txt -m \"Done\"\n  \
    Prove authorship   wld export essay.txt -t enhanced -f cpop -o proof.cpop\n  \
    Verify offline     wld verify proof.cpop\n\n\
WHEN TO CHECKPOINT:\n  \
    - After completing a section or paragraph\n  \
    - Before and after major edits\n  \
    - When taking a break from writing\n  \
    More checkpoints = stronger authorship evidence.\n\n\
EVIDENCE TIERS (weakest → strongest):\n  \
    basic      Content hashes + timestamps only\n  \
    standard   + VDF time proofs + signed declaration\n  \
    enhanced   + keystroke timing evidence (requires track sessions)\n  \
    maximum    + presence verification (full forensic package)\n\n\
ENVIRONMENT:\n  \
    WLD_DATA_DIR    Override default data directory (~/.writerslogic)\n  \
    EDITOR          Editor for 'wld config edit'\n\n\
For command help: wld <command> --help")]
#[command(args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// File, folder, or project to track (shorthand for `wld track start <path>`)
    pub path: Option<PathBuf>,

    /// Output results as JSON (for scripting and CI pipelines)
    #[arg(long, global = true)]
    pub json: bool,

    /// Suppress non-error output
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize WritersLogic (keys, database, VDF calibration)
    #[command(
        hide = true,
        after_help = "\
WHAT IT CREATES:\n  \
    ~/.writerslogic/signing_key     Ed25519 private key (keep secure!)\n  \
    ~/.writerslogic/events.db       Tamper-evident checkpoint database\n\n\
Also calibrates VDF speed for your CPU (takes a few seconds).\n\
This runs automatically on first use — you rarely need to call it manually.\n\n\
EXAMPLES:\n  \
    wld init           Initialize with default settings\n\n\
If already initialized, this is a safe no-op."
    )]
    Init {},
    /// Create a cryptographic checkpoint of a document
    #[command(
        alias = "checkpoint",
        after_help = "\
A checkpoint captures the current state of your document with a cryptographic \
hash and VDF time proof. Each checkpoint is chained to the previous one, forming \
an unforgeable timeline of your writing process.\n\n\
EXAMPLES:\n  \
    wld commit essay.txt -m \"Draft 1\"        Checkpoint with a message\n  \
    wld commit thesis.tex -m \"Chapter 2\"     Checkpoint a LaTeX file\n  \
    wld commit                               Select from recently modified files\n  \
    wld commit essay.txt --anchor            Also anchor in transparency log\n\n\
TIP: Checkpoint after sections, before revisions, and on breaks.\n  \
     More frequent checkpoints strengthen your authorship evidence."
    )]
    Commit {
        /// Document to checkpoint (omit to select interactively)
        file: Option<PathBuf>,
        /// Human-readable checkpoint description (e.g. "Finished introduction")
        #[arg(short, long)]
        message: Option<String>,
        /// Anchor evidence in WritersProof transparency log (Pro tier)
        #[arg(long)]
        anchor: bool,
    },
    /// View checkpoint history for a document
    #[command(
        alias = "history",
        alias = "ls",
        after_help = "\
EXAMPLES:\n  \
    wld log essay.txt      View checkpoint history for a specific file\n  \
    wld log                List all tracked documents with checkpoint counts\n  \
    wld history            Alias for 'wld log'\n  \
    wld ls                 Alias for 'wld log'"
    )]
    Log {
        /// Document to show history for (omit to list all tracked documents)
        file: Option<PathBuf>,
    },
    /// Export evidence packet for a document
    #[command(
        alias = "prove",
        after_help = "\
Packages all checkpoints, timing proofs, and behavioral evidence for a document \
into a single verifiable evidence packet. The recipient can verify it offline \
with 'wld verify'.\n\n\
EVIDENCE TIERS (weakest → strongest):\n  \
    basic     Content hashes + timestamps only (fastest, smallest)\n  \
    standard  + VDF time proofs + signed declaration (recommended)\n  \
    enhanced  + keystroke timing evidence (requires track sessions)\n  \
    maximum   + presence verification (full forensic package)\n\n\
OUTPUT FORMATS:\n  \
    json      Machine-readable JSON (default)\n  \
    cpop      CBOR evidence packet per draft-condrey-rats-pop (.cpop)\n  \
    cwar      ASCII-armored attestation result block (.cwar)\n  \
    html      Visual evidence report for human review\n\n\
EXAMPLES:\n  \
    wld export essay.txt                        Basic tier, JSON output\n  \
    wld export essay.txt -t standard            Recommended for submissions\n  \
    wld export thesis.tex -t enhanced -o proof.json\n  \
    wld export essay.txt -f cpop -o proof.cpop  CBOR wire format\n  \
    wld export essay.txt -f cwar -o proof.cwar  ASCII-armored block\n  \
    wld export essay.txt --stego                Embed ZWC watermark (Pro)\n  \
    wld prove essay.txt -t standard             'prove' is an alias for 'export'"
    )]
    Export {
        /// Document to export evidence for
        file: PathBuf,
        /// Evidence tier: basic, standard, enhanced, or maximum
        #[arg(short = 't', long, visible_alias = "tier", default_value = "basic")]
        tier: String,
        /// Output file path (defaults to stdout for JSON, required for cpop/cwar)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        /// Output format: json, cpop, cwar, or html
        #[arg(short = 'f', long, default_value = "json")]
        format: String,
        /// Embed steganographic zero-width character watermark (Pro tier)
        #[arg(long)]
        stego: bool,
    },
    /// Verify an evidence packet, attestation block, or database
    #[command(
        alias = "check",
        after_help = "\
Validates cryptographic integrity of evidence offline. Checks hash chains, VDF \
proofs, signatures, and timestamp consistency. No network access required.\n\n\
SUPPORTED INPUT FORMATS:\n  \
    .json     JSON evidence packet\n  \
    .cpop     CBOR evidence packet (draft-condrey-rats-pop wire format)\n  \
    .cwar     ASCII-armored attestation result block\n  \
    .db       Local SQLite database (full integrity check)\n\n\
EXAMPLES:\n  \
    wld verify essay.evidence.json           Verify a JSON evidence packet\n  \
    wld verify proof.cpop                    Verify a CPOP wire-format packet\n  \
    wld verify proof.cwar                    Verify an attestation result\n  \
    wld verify proof.cpop --key author.pub   Verify against a specific public key\n  \
    wld verify ~/.writerslogic/events.db     Full database integrity check\n  \
    wld check proof.cpop                     'check' is an alias for 'verify'"
    )]
    Verify {
        /// Evidence file to verify (.json, .cpop, .cwar, or .db)
        file: PathBuf,
        /// Public key file to verify signatures against (optional)
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    /// Interactive presence verification challenges
    #[command(after_help = "\
Presence verification adds an extra layer of proof that a human was actively \
present during writing. The daemon issues periodic challenges that require \
human-speed responses, making automated forgery significantly harder.\n\n\
EXAMPLES:\n  \
    wld presence start       Start a presence verification session\n  \
    wld presence challenge   Answer the current pending challenge\n  \
    wld presence status      Check session state and challenge history\n  \
    wld presence stop        End session and record results\n\n\
Presence evidence is included in 'maximum' tier exports.")]
    Presence {
        #[command(subcommand)]
        action: PresenceAction,
    },
    /// Track keystrokes on a file, folder, or project
    #[command(after_help = "\
Monitors keystroke timing (NOT content) while you write, building behavioral \
evidence that strengthens your authorship proof. Tracking sessions are saved \
and can be exported as part of 'enhanced' or 'maximum' tier evidence.\n\n\
EXAMPLES:\n  \
    wld track start essay.txt        Track a single file\n  \
    wld track start ./thesis/        Track all files in a folder\n  \
    wld track start novel.scriv      Track a Scrivener project\n  \
    wld track stop                   Stop and save current session\n  \
    wld track status                 Check active session\n  \
    wld track list                   List saved sessions\n  \
    wld track show <id>              Inspect a saved session\n  \
    wld track export <id>            Export session evidence\n\n\
SUPPORTED PROJECT TYPES:\n  \
    Scrivener (.scriv), TextBundle (.textbundle), and plain directories.\n  \
    Binary files, archives, media, and databases are automatically skipped.\n\n\
SHORTHAND:\n  \
    wld <file>   is equivalent to 'wld track start <file>'\n\n\
PRIVACY: Only keystroke counts and inter-key timing are recorded, \
never the actual characters typed.")]
    #[command(args_conflicts_with_subcommands = true)]
    Track {
        #[command(subcommand)]
        action: Option<TrackAction>,
        /// File, folder, or project to track (shorthand for `wld track start <path>`)
        file: Option<PathBuf>,
    },
    /// Re-calibrate VDF speed for your CPU
    #[command(
        hide = true,
        after_help = "\
VDF (Verifiable Delay Function) proofs require knowing your CPU's iteration \
speed to calculate elapsed time accurately.\n\n\
WHEN TO RE-CALIBRATE:\n  \
    - After upgrading your CPU or moving to a different machine\n  \
    - If checkpoint timing seems inaccurate\n\n\
EXAMPLES:\n  \
    wld calibrate          Run VDF speed calibration\n\n\
NOTE: Calibration runs automatically during 'wld init' and on first track."
    )]
    Calibrate,
    /// Show WritersLogic status (daemon, identity, recent activity)
    Status,
    /// Generate shell completions for bash, zsh, fish, elvish, or powershell
    #[command(
        hide = true,
        after_help = "\
Outputs completion scripts to stdout. Redirect to the appropriate file for \
your shell.\n\n\
EXAMPLES:\n  \
    wld completions bash  > ~/.bash_completion.d/wld\n  \
    wld completions zsh   > ~/.zsh/completions/_wld\n  \
    wld completions fish  > ~/.config/fish/completions/wld.fish\n\n\
After installing, restart your shell or source the file."
    )]
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
    /// Start the WritersLogic daemon
    #[command(
        hide = true,
        after_help = "\
The daemon runs in the background and provides system-wide services:\n  \
    - Keystroke timing capture (timing only, not content)\n  \
    - Automatic checkpointing on file save\n  \
    - Activity fingerprint accumulation\n  \
    - Idle detection and session management\n\n\
EXAMPLES:\n  \
    wld start                  Start daemon in background\n  \
    wld start --foreground     Run in foreground (for debugging)\n\n\
The daemon auto-starts when needed if sentinel.auto_start is true in config."
    )]
    Start {
        /// Run in foreground instead of daemonizing (useful for debugging)
        #[arg(short, long)]
        foreground: bool,
    },
    /// Stop the WritersLogic daemon
    #[command(
        hide = true,
        after_help = "\
Gracefully stops the background daemon. Active tracking sessions are saved \
before shutdown.\n\n\
EXAMPLES:\n  \
    wld stop"
    )]
    Stop,
    /// Manage activity and voice fingerprints
    #[command(
        alias = "fp",
        after_help = "\
Fingerprints capture your unique typing rhythm and behavioral patterns. They \
strengthen authorship evidence by linking documents to your personal style.\n\n\
EXAMPLES:\n  \
    wld fingerprint status          Show fingerprint collection status\n  \
    wld fingerprint show            Display your current fingerprint\n  \
    wld fingerprint show --id abc   Show a specific fingerprint by ID\n  \
    wld fingerprint compare A B     Compare two fingerprint profiles\n  \
    wld fingerprint list            List all stored fingerprints\n  \
    wld fingerprint delete <id>     Delete a fingerprint\n  \
    wld fp status                   'fp' is an alias for 'fingerprint'\n\n\
PRIVACY:\n  \
    Activity fingerprinting is ON by default (captures timing patterns only).\n  \
    Voice fingerprinting is OFF by default (requires explicit consent).\n  \
    Enable voice: wld config set fingerprint.voice_enabled true"
    )]
    Fingerprint {
        #[command(subcommand)]
        action: FingerprintAction,
    },
    /// One-shot text attestation via ephemeral session
    #[command(
        hide = true,
        after_help = "\
Creates a single attestation for text content without a persistent tracking \
session. Useful for quick proofs or integration with other tools.\n\n\
EXAMPLES:\n  \
    wld attest -i document.txt -o proof.cwar     Attest a file\n  \
    wld attest -f json -o proof.json              Output as JSON\n  \
    wld attest --non-interactive < input.txt      Pipe-friendly mode\n\n\
OUTPUT FORMATS:\n  \
    war     ASCII-armored attestation result (default)\n  \
    json    Machine-readable JSON"
    )]
    Attest {
        /// Output format: war or json
        #[arg(short, long, default_value = "war")]
        format: String,
        /// Input file (reads stdin if omitted)
        #[arg(short, long)]
        input: Option<PathBuf>,
        /// Output file (writes stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Skip interactive prompts (for piped input)
        #[arg(long)]
        non_interactive: bool,
    },
    /// Show or recover your cryptographic identity
    #[command(
        alias = "id",
        after_help = "\
Your WritersLogic identity is an Ed25519 keypair derived from a BIP-39 mnemonic \
seed phrase. It signs all checkpoints and evidence packets.\n\n\
DISPLAY OPTIONS:\n  \
    wld identity                    Show identity summary\n  \
    wld identity --fingerprint      Show public key fingerprint (safe to share)\n  \
    wld identity --did              Show Decentralized Identifier (DID)\n  \
    wld identity --mnemonic         Show 24-word recovery phrase (KEEP SECRET!)\n  \
    wld id                          'id' is an alias for 'identity'\n\n\
RECOVERY:\n  \
    wld identity --recover          Recover identity from mnemonic phrase\n\n\
    The recovery phrase is read from stdin to avoid shell history exposure.\n  \
    Example: echo \"word1 word2 ...\" | wld identity --recover\n\n\
SECURITY:\n  \
    - The mnemonic is the master secret — never share it or pass it as an argument\n  \
    - The fingerprint and DID are safe to share publicly\n  \
    - Keys are stored in ~/.writerslogic/signing_key"
    )]
    Identity {
        /// Show public key fingerprint (safe to share)
        #[arg(long)]
        fingerprint: bool,
        /// Show Decentralized Identifier (DID)
        #[arg(long)]
        did: bool,
        /// Show 24-word BIP-39 recovery phrase (KEEP SECRET)
        #[arg(long)]
        mnemonic: bool,
        /// Recover identity from mnemonic phrase (reads from stdin)
        #[arg(long)]
        recover: bool,
    },
    /// View and modify WritersLogic configuration
    #[command(
        alias = "cfg",
        after_help = "\
EXAMPLES:\n  \
    wld config show                              Show all settings\n  \
    wld config set sentinel.auto_start true       Auto-start daemon\n  \
    wld config set fingerprint.voice_enabled true  Enable voice fingerprinting\n  \
    wld config edit                               Open config in $EDITOR\n  \
    wld config reset --force                      Reset to defaults\n  \
    wld cfg show                                  'cfg' is an alias for 'config'\n\n\
CONFIG FILE:\n  \
    Located at ~/.writerslogic/config.toml"
    )]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Display the WritersLogic manual
    #[command(
        alias = "manual",
        after_help = "\
Prints a comprehensive reference covering all commands, concepts, file formats, \
and configuration options.\n\n\
EXAMPLES:\n  \
    wld man              Display the full manual\n  \
    wld man | less       Page through the manual\n  \
    wld manual           Alias for 'wld man'"
    )]
    Man,
}

#[derive(Subcommand)]
pub enum PresenceAction {
    /// Start a presence verification session
    Start,
    /// End the current presence session and save results
    Stop,
    /// Show current session state and challenge history
    Status,
    /// Answer the current pending presence challenge
    Challenge,
}

#[derive(Subcommand)]
pub enum TrackAction {
    /// Start tracking keystrokes on a file, folder, or project
    Start {
        /// File, folder, or writing app project (.scriv, .textbundle)
        path: PathBuf,
        /// Glob patterns to filter files (e.g. "*.txt,*.md") — directory mode only
        #[arg(short, long, default_value = "")]
        patterns: String,
        #[cfg(feature = "wld_jitter")]
        #[arg(long, help = "Use hardware entropy when available")]
        wld_jitter: bool,
    },
    /// Stop the active tracking session and save results
    Stop,
    /// Show active tracking session status
    Status,
    /// List all saved tracking sessions
    List,
    /// Show details of a saved tracking session
    Show {
        /// Session ID to display
        id: String,
    },
    /// Export evidence from a saved tracking session
    Export {
        /// Session ID to export
        session_id: String,
    },
}

#[derive(Subcommand)]
pub enum FingerprintAction {
    /// Show fingerprint collection status and statistics
    Status,
    /// Display a fingerprint profile
    Show {
        /// Fingerprint ID to display (omit for current profile)
        #[arg(short, long)]
        id: Option<String>,
    },
    /// Compare two fingerprint profiles for similarity
    Compare {
        /// First fingerprint ID
        id1: String,
        /// Second fingerprint ID
        id2: String,
    },
    /// List all stored fingerprint profiles
    List,
    /// Delete a stored fingerprint profile
    Delete {
        /// Fingerprint ID to delete
        id: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show all configuration settings
    Show,
    /// Set a configuration key to a new value
    Set {
        /// Dotted key path (e.g. "sentinel.auto_start")
        key: String,
        /// New value
        value: String,
    },
    /// Open configuration file in $EDITOR
    Edit,
    /// Reset configuration to defaults
    Reset {
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },
}
