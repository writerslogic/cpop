// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Request {
    StartSession {
        document_url: String,
        document_title: String,
        #[serde(default)]
        protocol_version: Option<String>,
    },
    Checkpoint {
        content_hash: String,
        char_count: u64,
        delta: i64,
        /// Browser-side commitment hash (optional for backward compat).
        #[serde(default)]
        commitment: Option<String>,
        /// Checkpoint ordinal from the browser (optional for backward compat).
        #[serde(default)]
        ordinal: Option<u64>,
    },
    StopSession,
    GetStatus,
    InjectJitter {
        intervals: Vec<u64>,
    },
    Ping {
        #[serde(default)]
        protocol_version: Option<String>,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Response {
    SessionStarted {
        session_id: String,
        message: String,
        /// Session nonce the browser must include in commitments.
        session_nonce: String,
    },
    CheckpointCreated {
        hash: String,
        checkpoint_count: u64,
        message: String,
        /// Server-side commitment hash for the browser to chain.
        commitment: String,
    },
    SessionStopped {
        message: String,
    },
    Status {
        initialized: bool,
        active_session: bool,
        document_url: Option<String>,
        document_title: Option<String>,
        checkpoint_count: u64,
        tracked_files: u32,
        total_checkpoints: u64,
    },
    JitterReceived {
        count: usize,
    },
    Pong {
        version: String,
    },
    Error {
        message: String,
        code: String,
    },
}

pub(crate) struct Session {
    pub(crate) id: String,
    pub(crate) document_url: String,
    pub(crate) document_title: String,
    pub(crate) checkpoint_count: u64,
    pub(crate) evidence_path: std::path::PathBuf,
    pub(crate) jitter_intervals: Vec<u64>,
    pub(crate) prev_commitment: [u8; 32],
    pub(crate) expected_ordinal: u64,
    pub(crate) session_nonce: [u8; 16],
    pub(crate) last_char_count: u64,
    pub(crate) last_checkpoint_ts: u64,
    /// Token bucket in milli-batches (1 batch = 1000 units; refill at 10 batches/sec = 10 units/ms).
    pub(crate) bucket_millitokens: u64,
    pub(crate) last_refill: std::time::Instant,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.session_nonce.zeroize();
        self.prev_commitment.zeroize();
    }
}

static SESSION: OnceLock<Mutex<Option<Session>>> = OnceLock::new();

pub(crate) fn session() -> &'static Mutex<Option<Session>> {
    SESSION.get_or_init(|| Mutex::new(None))
}
