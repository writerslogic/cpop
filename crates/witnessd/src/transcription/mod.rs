// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Transcription detection: audio dictation metadata and cross-window text comparison.

pub mod audio;
pub mod cross_window;

pub use audio::{TranscriptionCollector, TranscriptionMetadata, TranscriptionTimingStats};
pub use cross_window::{CrossWindowMatch, TranscriptionDetector};
