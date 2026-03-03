// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! WritersLogic CLI — cryptographic authorship witnessing.

use anyhow::Result;
use clap::Parser;

mod cli;
mod cmd_commit;
mod cmd_config;
mod cmd_daemon;
mod cmd_export;
mod cmd_fingerprint;
mod cmd_identity;
mod cmd_init;
mod cmd_log;
mod cmd_presence;
mod cmd_session;
mod cmd_status;
mod cmd_track;
mod cmd_verify;
mod cmd_watch;
mod smart_defaults;
mod spec;
mod util;

use cli::{Cli, Commands};

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
        if let Ok(dir) = util::writerslogic_dir() {
            if let Ok(config) = wld_engine::config::WLDConfig::load_or_default(&dir) {
                if config.sentinel.auto_start {
                    let daemon_manager =
                        wld_engine::DaemonManager::new(config.data_dir.clone());
                    let _status = daemon_manager.status();
                }
            }
        }
    }

    match cli.command {
        Some(Commands::Init { _path: _ }) => {
            cmd_init::cmd_init()?;
        }
        Some(Commands::Identity {
            fingerprint,
            did,
            mnemonic,
            recover,
            json,
        }) => {
            cmd_identity::cmd_identity(fingerprint, did, mnemonic, recover, json)?;
        }
        Some(Commands::Commit { file, message }) => {
            cmd_commit::cmd_commit_smart(file, message)?;
        }
        Some(Commands::Log { file }) => {
            cmd_log::cmd_log_smart(file)?;
        }
        Some(Commands::Export {
            file,
            tier,
            output,
            format,
        }) => {
            cmd_export::cmd_export(&file, &tier, output, None, &format)?;
        }
        Some(Commands::Verify { file, key }) => {
            cmd_verify::cmd_verify(&file, key)?;
        }
        Some(Commands::Presence { action }) => {
            cmd_presence::cmd_presence(action)?;
        }
        Some(Commands::Track { action }) => {
            cmd_track::cmd_track(action)?;
        }
        Some(Commands::Calibrate) => {
            cmd_status::cmd_calibrate()?;
        }
        Some(Commands::Status) => {
            cmd_status::cmd_status()?;
        }
        Some(Commands::List) => {
            cmd_status::cmd_list()?;
        }
        Some(Commands::Watch { action, folder }) => {
            cmd_watch::cmd_watch_smart(action, folder).await?;
        }
        Some(Commands::Start { foreground }) => {
            cmd_daemon::cmd_start(foreground).await?;
        }
        Some(Commands::Stop) => {
            cmd_daemon::cmd_stop()?;
        }
        Some(Commands::Fingerprint { action }) => {
            cmd_fingerprint::cmd_fingerprint(action)?;
        }
        Some(Commands::Session { action }) => {
            cmd_session::cmd_session(action)?;
        }
        Some(Commands::Config { action }) => {
            cmd_config::cmd_config(action)?;
        }
        None => {
            cmd_status::show_quick_status()?;
        }
    }

    Ok(())
}
