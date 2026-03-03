// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::wal::WalError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SentinelError {
    #[error("sentinel: not available on this platform - {0}")]
    NotAvailable(String),

    #[error("sentinel: already running")]
    AlreadyRunning,

    #[error("sentinel: not running")]
    NotRunning,

    #[error("sentinel: session not found for {0}")]
    SessionNotFound(String),

    #[error("sentinel: invalid configuration - {0}")]
    InvalidConfig(String),

    #[error("sentinel: daemon not running")]
    DaemonNotRunning,

    #[error("sentinel: daemon already running (PID {0})")]
    DaemonAlreadyRunning(i32),

    #[error("sentinel: shadow buffer not found - {0}")]
    ShadowNotFound(String),

    #[error("sentinel: io error - {0}")]
    Io(#[from] std::io::Error),

    #[error("sentinel: wal error - {0}")]
    Wal(#[from] WalError),

    #[error("sentinel: serialization error - {0}")]
    Serialization(String),

    #[error("sentinel: channel error - {0}")]
    Channel(String),

    #[error("sentinel: ipc error - {0}")]
    Ipc(String),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, SentinelError>;
