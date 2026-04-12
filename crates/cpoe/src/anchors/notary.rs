// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::{AnchorError, AnchorProvider, Proof, ProofStatus, ProviderType};
use async_trait::async_trait;
use base64::Engine;

/// Anchor provider backed by a remote notary service API.
pub struct NotaryProvider {
    endpoint: String,
    api_key: Option<String>,
    client: reqwest::Client,
}

impl NotaryProvider {
    /// Create a provider with the given endpoint and optional API key.
    pub fn new(endpoint: String, api_key: Option<String>) -> Result<Self, AnchorError> {
        let parsed = url::Url::parse(&endpoint)
            .map_err(|e| AnchorError::Unavailable(format!("invalid endpoint URL: {e}")))?;
        if parsed.scheme() != "https" {
            return Err(AnchorError::Unavailable(
                "notary endpoint must use HTTPS".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| AnchorError::Network(format!("client init: {e}")))?;
        Ok(Self {
            endpoint,
            api_key,
            client,
        })
    }

    /// Create from `NOTARY_ENDPOINT` and optional `NOTARY_API_KEY` env vars.
    pub fn from_env() -> Result<Self, AnchorError> {
        let endpoint = std::env::var("NOTARY_ENDPOINT")
            .map_err(|_| AnchorError::Unavailable("NOTARY_ENDPOINT not set".into()))?;
        let api_key = std::env::var("NOTARY_API_KEY").ok();
        Self::new(endpoint, api_key)
    }

    async fn post_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, AnchorError> {
        let base = url::Url::parse(&self.endpoint)
            .map_err(|e| AnchorError::Unavailable(format!("invalid endpoint URL: {e}")))?;
        let base = if base.path().ends_with('/') {
            base
        } else {
            let mut s = base.to_string();
            s.push('/');
            url::Url::parse(&s)
                .map_err(|e| AnchorError::Unavailable(format!("invalid endpoint URL: {e}")))?
        };
        let url = base
            .join(path.trim_start_matches('/'))
            .map_err(|e| AnchorError::Unavailable(format!("invalid path: {e}")))?;
        let mut req = self.client.post(url).json(&body);
        if let Some(ref key) = self.api_key {
            req = req.bearer_auth(key);
        }
        const MAX_BODY: usize = 10_000_000;
        let response = req
            .send()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;

        if let Some(cl) = response.content_length() {
            if cl as usize > MAX_BODY {
                return Err(AnchorError::Network(
                    "response Content-Length exceeds 10 MB limit".into(),
                ));
            }
        }

        let status = response.status();
        if !status.is_success() {
            return Err(AnchorError::Network(format!(
                "notary request failed: HTTP {status}"
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;
        if bytes.len() > MAX_BODY {
            return Err(AnchorError::Network(
                "response body exceeds 10 MB limit".into(),
            ));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| AnchorError::Network(e.to_string()))?;

        super::http::check_json_rpc_error(&value)?;

        Ok(value)
    }
}

#[async_trait]
impl AnchorProvider for NotaryProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Notary
    }

    fn name(&self) -> &str {
        "Notary Service"
    }

    async fn is_available(&self) -> bool {
        self.post_json("health", serde_json::json!({}))
            .await
            .is_ok()
    }

    async fn submit(&self, hash: &[u8; 32]) -> Result<Proof, AnchorError> {
        let response = self
            .post_json("submit", serde_json::json!({"hash": hex::encode(hash)}))
            .await?;

        let id = response
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                log::warn!("notary response missing 'id' field");
                ""
            });
        let proof_data = match response.get("proof").and_then(|v| v.as_str()) {
            Some(s) => base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|e| AnchorError::InvalidFormat(format!("bad base64: {e}")))?,
            None => vec![],
        };

        Ok(Proof {
            id: if id.is_empty() {
                format!("notary-{}", crate::utils::short_hex_id(hash))
            } else {
                id.to_string()
            },
            provider: ProviderType::Notary,
            status: ProofStatus::Pending,
            anchored_hash: *hash,
            submitted_at: chrono::Utc::now(),
            confirmed_at: None,
            proof_data,
            location: None,
            attestation_path: None,
            extra: Default::default(),
        })
    }

    async fn check_status(&self, proof: &Proof) -> Result<Proof, AnchorError> {
        let response = self
            .post_json("status", serde_json::json!({"id": proof.id}))
            .await?;

        let mut updated = proof.clone();
        if let Some(status) = response.get("status").and_then(|v| v.as_str()) {
            if status == "confirmed" {
                updated.status = ProofStatus::Confirmed;
                // Prefer the server-provided timestamp ("confirmed_at" or "timestamp") so
                // the recorded time reflects when the notary actually confirmed the entry,
                // not when this client polled. Fall back to Utc::now() if absent.
                let server_ts = response
                    .get("confirmed_at")
                    .or_else(|| response.get("timestamp"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&chrono::Utc));
                updated.confirmed_at = Some(server_ts.unwrap_or_else(chrono::Utc::now));
            } else if status == "failed" {
                updated.status = ProofStatus::Failed;
            }
        }

        Ok(updated)
    }

    async fn verify(&self, proof: &Proof) -> Result<bool, AnchorError> {
        let response = self
            .post_json("verify", serde_json::json!({"id": proof.id}))
            .await?;
        Ok(response
            .get("valid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }
}
