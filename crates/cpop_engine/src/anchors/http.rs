// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared HTTP helpers for anchor providers.
//!
//! Extracts the duplicated JSON-RPC request/response pattern used by
//! Ethereum and Bitcoin providers, and the common HTTP client construction
//! used across all anchor backends.

use std::sync::atomic::{AtomicU64, Ordering};

use super::AnchorError;

/// Default per-request timeout for anchor HTTP clients.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Monotonically increasing counter for JSON-RPC request IDs.
static RPC_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

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

/// Send a JSON-RPC 2.0 request and return the `result` field.
///
/// This encapsulates the pattern shared by Ethereum and Bitcoin providers:
/// build the envelope, POST it, check for a JSON-RPC `error` object, and
/// extract the `result` value.
pub(crate) async fn json_rpc_call(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, AnchorError> {
    let id = RPC_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params
    });

    let response = client
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|e| AnchorError::Network(e.to_string()))?;

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AnchorError::Network(e.to_string()))?;

    check_json_rpc_error(&body)?;

    Ok(body["result"].clone())
}

/// Send an authenticated JSON-RPC 2.0 request (HTTP Basic Auth) and return the `result` field.
///
/// Used by Bitcoin provider which requires RPC authentication.
pub(crate) async fn json_rpc_call_with_auth(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
    username: &str,
    password: &str,
) -> Result<serde_json::Value, AnchorError> {
    let id = RPC_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params
    });

    let response = client
        .post(url)
        .basic_auth(username, Some(password))
        .json(&request)
        .send()
        .await
        .map_err(|e| AnchorError::Network(e.to_string()))?;

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AnchorError::Network(e.to_string()))?;

    check_json_rpc_error(&body)?;

    Ok(body["result"].clone())
}

/// Check a JSON-RPC response body for an `error` field and convert it to an [`AnchorError`].
///
/// Also used by the notary provider for its JSON API error checking.
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
