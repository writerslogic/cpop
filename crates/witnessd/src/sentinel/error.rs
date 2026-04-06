// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::wal::WalError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SentinelError {
    #[error("not available on this platform - {0}")]
    NotAvailable(String),

    #[error("already running")]
    AlreadyRunning,

    #[error("not running")]
    NotRunning,

    #[error("session not found for {0}")]
    SessionNotFound(String),

    #[error("invalid configuration - {0}")]
    InvalidConfig(String),

    #[error("daemon not running")]
    DaemonNotRunning,

    #[error("daemon already running (PID {0})")]
    DaemonAlreadyRunning(i32),

    #[error("shadow buffer not found - {0}")]
    ShadowNotFound(String),

    #[error("io error - {0}")]
    Io(#[from] std::io::Error),

    #[error("wal error - {0}")]
    Wal(#[from] WalError),

    #[error("serialization error - {0}")]
    Serialization(String),

    #[error("channel error - {0}")]
    Channel(String),

    #[error("ipc error - {0}")]
    Ipc(String),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, SentinelError>;
