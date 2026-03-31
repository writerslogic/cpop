// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared HTTP helpers for anchor providers.

use super::AnchorError;

/// Default per-request timeout for anchor HTTP clients.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Build an HTTP client with the given timeout (in seconds).
///
/// Falls back to [`DEFAULT_TIMEOUT_SECS`] when `timeout_secs` is `None`.
pub(crate) fn build_http_client(timeout_secs: Option<u64>) -> Result<reqwest::Client, AnchorError> {
    let secs = timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(secs))
        .build()
        .map_err(|e| AnchorError::Network(format!("HTTP client init failed: {e}")))
}

/// Check a JSON-RPC response body for an `error` field and convert it to an [`AnchorError`].
pub(crate) fn check_json_rpc_error(body: &serde_json::Value) -> Result<(), AnchorError> {
    if let Some(error) = body.get("error") {
        if !error.is_null() {
            let msg = error
                .get("message")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| error.to_string());
            return Err(AnchorError::Submission(msg));
        }
    }
    Ok(())
}
