// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Forensics error types.

/// Forensic analysis error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ForensicsError {
    #[error("Insufficient data for analysis")]
    InsufficientData,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Computation error: {0}")]
    ComputationError(String),
}
