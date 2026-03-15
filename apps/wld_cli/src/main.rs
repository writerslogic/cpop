// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! WritersLogic CLI — cryptographic authorship witnessing.

use std::io::IsTerminal;

use anyhow::Result;
use clap::{CommandFactory, Parser};

mod cli;
mod cmd_attest;
mod cmd_commit;
mod cmd_config;
mod cmd_daemon;
mod cmd_export;
mod cmd_fingerprint;
mod cmd_identity;
mod cmd_init;
mod cmd_log;
mod cmd_presence;
mod cmd_status;
mod cmd_track;
mod cmd_verify;
mod output;
mod smart_defaults;
mod spec;
mod util;

use cli::{Cli, Commands};
use output::OutputMode;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {:#}", e);
        eprintln!();
        eprintln!("For more information, try 'wld --help'");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let out = OutputMode::new(cli.json, cli.quiet);
    let has_path_arg = cli.path.is_some();
    let should_auto_start = has_path_arg
        || !matches!(
            &cli.command,
            Some(Commands::Start { .. })
                | Some(Commands::Stop)
                | Some(Commands::Status)
                | Some(Commands::Init { .. })
                | Some(Commands::Calibrate)
                | Some(Commands::Config { .. })
                | Some(Commands::Completions { .. })
                | None
        );

    if should_auto_start {
        if let Ok(dir) = util::writerslogic_dir() {
            if let Ok(config) = wld_engine::config::WLDConfig::load_or_default(&dir) {
                if config.sentinel.auto_start {
                    let daemon_manager = wld_engine::DaemonManager::new(&config.data_dir);
                    if !daemon_manager.is_running() {
                        if !out.quiet {
                            eprintln!("Starting WritersLogic daemon...");
                        }
                        if let Err(e) = cmd_daemon::cmd_start(false).await {
                            eprintln!("Warning: auto-start daemon failed: {}", e);
                        }
                    }
                }
            }
        }
    }

    // Auto-initialize if needed (for commands that require it)
    let needs_init = matches!(
        &cli.command,
        Some(Commands::Commit { .. })
            | Some(Commands::Log { .. })
            | Some(Commands::Export { .. })
            | Some(Commands::Verify { .. })
            | Some(Commands::Track { .. })
            | Some(Commands::Calibrate)
            | Some(Commands::Fingerprint { .. })
            | Some(Commands::Attest { .. })
            | Some(Commands::Presence { .. })
    ) || cli.path.is_some();

    if needs_init {
        if let Ok(dir) = util::writerslogic_dir() {
            if !dir.join("signing_key").exists() {
                if !out.quiet {
                    eprintln!("First run — initializing WritersLogic...");
                    eprintln!();
                }
                cmd_init::cmd_init()?;
                if !out.quiet {
                    eprintln!();
                }
            }
        }
    }

    match cli.command {
        Some(Commands::Init {}) => {
            cmd_init::cmd_init()?;
        }
        Some(Commands::Identity {
            fingerprint,
            did,
            mnemonic,
            recover,
        }) => {
            cmd_identity::cmd_identity(fingerprint, did, mnemonic, recover, out.json)?;
        }
        Some(Commands::Commit {
            file,
            message,
            anchor,
        }) => {
            cmd_commit::cmd_commit_smart(file, message, anchor, &out).await?;
        }
        Some(Commands::Log { file }) => {
            cmd_log::cmd_log_smart(file, &out)?;
        }
        Some(Commands::Export {
            file,
            tier,
            output,
            format,
            stego,
        }) => {
            cmd_export::cmd_export(&file, &tier, output, &format, stego).await?;
        }
        Some(Commands::Verify { file, key }) => {
            cmd_verify::cmd_verify(&file, key, &out)?;
        }
        Some(Commands::Presence { action }) => {
            cmd_presence::cmd_presence(action, &out)?;
        }
        Some(Commands::Track { action, file }) => {
            cmd_track::cmd_track_smart(action, file, &out).await?;
        }
        Some(Commands::Calibrate) => {
            cmd_status::cmd_calibrate()?;
        }
        Some(Commands::Status) => {
            cmd_status::cmd_status(&out)?;
        }
        Some(Commands::Start { foreground }) => {
            cmd_daemon::cmd_start(foreground).await?;
        }
        Some(Commands::Stop) => {
            cmd_daemon::cmd_stop()?;
        }
        Some(Commands::Fingerprint { action }) => {
            cmd_fingerprint::cmd_fingerprint(action, &out)?;
        }
        Some(Commands::Attest {
            format,
            input,
            output,
            non_interactive,
        }) => {
            cmd_attest::cmd_attest(&format, input, output, non_interactive)?;
        }
        Some(Commands::Config { action }) => {
            cmd_config::cmd_config(action)?;
        }
        Some(Commands::Completions { shell }) => {
            clap_complete::generate(shell, &mut Cli::command(), "wld", &mut std::io::stdout());
        }
        Some(Commands::Man) => {
            print_manual();
        }
        None => {
            if let Some(path) = cli.path {
                let resolved = util::normalize_path(&path)?;
                cmd_track::cmd_track_smart(None, Some(resolved), &out).await?;
            } else {
                cmd_status::show_quick_status(&out)?;

                if !out.json && !out.quiet && std::io::stdout().is_terminal() {
                    interactive_menu(&out).await?;
                }
            }
        }
    }

    Ok(())
}

/// Print the full WritersLogic manual to stdout.
fn print_manual() {
    print!(
        "\
WRITERSLOGIC(1)                  User Manual                  WRITERSLOGIC(1)

NAME
    wld — cryptographic proof-of-process authorship witnessing

SYNOPSIS
    wld [OPTIONS] [<path>]
    wld <command> [ARGS...]

DESCRIPTION
    WritersLogic captures behavioral evidence during document creation and
    packages it into cryptographically signed evidence packets that prove a
    human authored content over time. Evidence includes keystroke timing,
    VDF (Verifiable Delay Function) time proofs, checkpoint hash chains,
    and optional presence verification.

    The evidence format follows draft-condrey-rats-pop, an IETF protocol
    specification for proof-of-process attestation.

WORKFLOW
    The typical authorship proving workflow is:

    1. Track     Start monitoring keystrokes while you write.
                 $ wld essay.txt

    2. Commit    Checkpoint your document periodically.
                 $ wld commit essay.txt -m \"Finished intro\"

    3. Export    Package evidence for submission or archival.
                 $ wld export essay.txt -t standard -o proof.cpop

    4. Verify    Anyone can verify evidence offline.
                 $ wld verify proof.cpop

COMMANDS
    Core Commands:
      commit      Create a cryptographic checkpoint of a document
      log         View checkpoint history (aliases: history, ls)
      export      Export evidence packet (alias: prove)
      verify      Verify an evidence packet (alias: check)
      track       Track keystrokes on a file, folder, or project
      status      Show WritersLogic status

    Identity & Security:
      identity    Show or recover your cryptographic identity (alias: id)
      fingerprint Manage activity and voice fingerprints (alias: fp)
      presence    Interactive presence verification challenges
      config      View and modify configuration (alias: cfg)

    Advanced (hidden from default help):
      init        Initialize WritersLogic manually
      start       Start the daemon
      stop        Stop the daemon
      calibrate   Re-calibrate VDF speed
      attest      One-shot text attestation
      completions Generate shell completions
      man         Display this manual

EVIDENCE TIERS
    basic       Content hashes + timestamps only (smallest, fastest)
    standard    + VDF time proofs + signed declaration (recommended)
    enhanced    + keystroke timing evidence (requires track sessions)
    maximum     + presence verification (full forensic package)

    Stronger tiers require more data collection but produce more
    convincing authorship evidence.

OUTPUT FORMATS
    json        Machine-readable JSON evidence packet (default)
    cpop        CBOR wire format per draft-condrey-rats-pop (.cpop)
    cwar        ASCII-armored attestation result block (.cwar)
    html        Visual evidence report for human review

KEY CONCEPTS
    Checkpoint
        A cryptographic snapshot (SHA-256 hash + VDF proof + signature)
        of your document at a point in time. Checkpoints are chained:
        each includes the hash of the previous, forming an unforgeable
        timeline.

    VDF Proof
        A Verifiable Delay Function proof that demonstrates real wall-
        clock time elapsed between checkpoints. Cannot be parallelized
        or precomputed.

    Evidence Packet
        A self-contained bundle of checkpoints, proofs, timing data,
        and a signed declaration. Verifiable offline by anyone.

    Declaration
        Your signed statement about document authorship, embedded in
        the evidence packet.

    Fingerprint
        A behavioral profile of your typing rhythm (inter-key timing
        distributions). Stored locally, included in enhanced/maximum
        evidence tiers.

IDENTITY
    WritersLogic uses an Ed25519 keypair derived from a BIP-39 mnemonic
    seed phrase. The private key signs all checkpoints and evidence.

    $ wld identity                Show identity summary
    $ wld identity --fingerprint  Public key fingerprint (safe to share)
    $ wld identity --did          Decentralized Identifier
    $ wld identity --mnemonic     Recovery phrase (KEEP SECRET)
    $ wld identity --recover      Recover from mnemonic (reads stdin)

FILES
    ~/.writerslogic/
        signing_key     Ed25519 private key
        events.db       Tamper-evident checkpoint database
        config.toml     Configuration file
        vdf_calibration VDF speed calibration data

ENVIRONMENT
    WLD_DATA_DIR    Override default data directory (~/.writerslogic)
    EDITOR          Editor for 'wld config edit'

PRIVACY
    Keystroke tracking captures only timing (inter-key intervals) and
    counts. The actual characters typed are NEVER recorded or stored.
    Voice fingerprinting is OFF by default and requires explicit consent.

SEE ALSO
    https://writerslogic.com              Product homepage
    https://writersproof.com              Verification API
    draft-condrey-rats-pop                IETF protocol specification
"
    );
}

/// Interactive menu shown when `wld` is invoked with no arguments on a TTY.
async fn interactive_menu(out: &OutputMode) -> Result<()> {
    use dialoguer::{Input, Select};
    use std::path::PathBuf;

    let items = &[
        "Track a file or folder",
        "Create checkpoint",
        "View history",
        "Export evidence",
        "Verify evidence",
        "Show identity",
        "Configuration",
        "Quit",
    ];

    eprintln!();
    let selection = Select::new()
        .with_prompt("What would you like to do?")
        .items(items)
        .default(0)
        .interact_opt()?;

    match selection {
        Some(0) => {
            let path: String = Input::new()
                .with_prompt("Path to file or folder")
                .interact_text()?;
            let resolved = util::normalize_path(&PathBuf::from(path))?;
            cmd_track::cmd_track_smart(None, Some(resolved), out).await?;
        }
        Some(1) => {
            cmd_commit::cmd_commit_smart(None, None, false, out).await?;
        }
        Some(2) => {
            cmd_log::cmd_log_smart(None, out)?;
        }
        Some(3) => {
            let path: String = Input::new().with_prompt("Path to file").interact_text()?;
            cmd_export::cmd_export(&PathBuf::from(path), "standard", None, "json", false).await?;
        }
        Some(4) => {
            let path: String = Input::new()
                .with_prompt("Path to evidence file")
                .interact_text()?;
            cmd_verify::cmd_verify(&PathBuf::from(path), None, out)?;
        }
        Some(5) => {
            cmd_identity::cmd_identity(false, false, false, false, out.json)?;
        }
        Some(6) => {
            cmd_config::cmd_config(cli::ConfigAction::Show)?;
        }
        _ => {} // Quit or Esc
    }

    Ok(())
}
