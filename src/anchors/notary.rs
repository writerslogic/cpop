use super::{AnchorError, AnchorProvider, Proof, ProofStatus, ProviderType};
use async_trait::async_trait;
use base64::Engine;

pub struct NotaryProvider {
    endpoint: String,
    api_key: Option<String>,
    client: reqwest::Client,
}

impl NotaryProvider {
    pub fn new(endpoint: String, api_key: Option<String>) -> Self {
        Self {
            endpoint,
            api_key,
            client: reqwest::Client::new(),
        }
    }

    pub fn from_env() -> Result<Self, AnchorError> {
        let endpoint = std::env::var("NOTARY_ENDPOINT")
            .map_err(|_| AnchorError::Unavailable("NOTARY_ENDPOINT not set".into()))?;
        let api_key = std::env::var("NOTARY_API_KEY").ok();
        Ok(Self::new(endpoint, api_key))
    }

    async fn post_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, AnchorError> {
        let url = format!(
            "{}/{}",
            self.endpoint.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let mut req = self.client.post(url).json(&body);
        if let Some(ref key) = self.api_key {
            req = req.bearer_auth(key);
        }
        let response = req
            .send()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;

        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;

        if let Some(error) = value.get("error") {
            if !error.is_null() {
                return Err(AnchorError::Submission(error.to_string()));
            }
        }

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

        let id = response.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let proof_data = response
            .get("proof")
            .and_then(|v| v.as_str())
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .unwrap_or_default();

        Ok(Proof {
            id: if id.is_empty() {
                format!("notary-{}", hex::encode(&hash[..8]))
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
                updated.confirmed_at = Some(chrono::Utc::now());
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
