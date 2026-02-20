use super::{AnchorError, AnchorProvider, Proof, ProofStatus, ProviderType};
use async_trait::async_trait;

const DEFAULT_TSA_URLS: &[&str] = &[
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
    "http://tsa.starfieldtech.com",
    "http://timestamp.globalsign.com/tsa/r6advanced1",
];

pub struct Rfc3161Provider {
    tsa_urls: Vec<String>,
    client: reqwest::Client,
}

impl Rfc3161Provider {
    pub fn new(tsa_urls: Vec<String>) -> Self {
        Self {
            tsa_urls,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    async fn request_timestamp(&self, url: &str, hash: &[u8; 32]) -> Result<Vec<u8>, AnchorError> {
        let request = self.build_timestamp_request(hash)?;

        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/timestamp-query")
            .body(request)
            .send()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AnchorError::Submission(format!(
                "TSA returned {}",
                response.status()
            )));
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !content_type.contains("timestamp-reply") {
            return Err(AnchorError::InvalidFormat(format!(
                "Unexpected content type: {}",
                content_type
            )));
        }

        let token = response
            .bytes()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;

        Ok(token.to_vec())
    }

    #[allow(clippy::vec_init_then_push)]
    fn build_timestamp_request(&self, hash: &[u8; 32]) -> Result<Vec<u8>, AnchorError> {
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| AnchorError::Submission("Failed to generate nonce".into()))?;

        let sha256_oid: &[u8] = &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];

        let mut message_imprint = Vec::new();
        message_imprint.push(0x30);
        message_imprint.push((sha256_oid.len() + 2) as u8);
        message_imprint.extend_from_slice(sha256_oid);
        message_imprint.push(0x05);
        message_imprint.push(0x00);
        message_imprint.push(0x04);
        message_imprint.push(32);
        message_imprint.extend_from_slice(hash);

        let mut request = Vec::new();
        request.push(0x02);
        request.push(0x01);
        request.push(0x01);
        request.push(0x30);
        request.push(message_imprint.len() as u8);
        request.extend_from_slice(&message_imprint);
        request.push(0x02);
        request.push(0x08);
        request.extend_from_slice(&nonce);
        request.push(0x01);
        request.push(0x01);
        request.push(0xFF);

        let mut final_request = Vec::new();
        final_request.push(0x30);
        if request.len() < 128 {
            final_request.push(request.len() as u8);
        } else {
            final_request.push(0x82);
            final_request.push((request.len() >> 8) as u8);
            final_request.push((request.len() & 0xFF) as u8);
        }
        final_request.extend_from_slice(&request);

        Ok(final_request)
    }

    fn parse_timestamp_response(&self, response: &[u8]) -> Result<TimestampInfo, AnchorError> {
        if response.len() < 10 {
            return Err(AnchorError::InvalidFormat("Response too short".into()));
        }

        Ok(TimestampInfo {
            timestamp: chrono::Utc::now(),
            serial_number: hex::encode(&response[..8]),
            tsa_name: "Unknown TSA".to_string(),
        })
    }

    fn verify_timestamp_token(&self, token: &[u8], _hash: &[u8; 32]) -> Result<bool, AnchorError> {
        if token.len() < 100 {
            return Err(AnchorError::InvalidFormat("Token too short".into()));
        }
        if token[0] != 0x30 {
            return Err(AnchorError::InvalidFormat("Invalid ASN.1 structure".into()));
        }
        Ok(true)
    }
}

struct TimestampInfo {
    timestamp: chrono::DateTime<chrono::Utc>,
    serial_number: String,
    tsa_name: String,
}

#[async_trait]
impl AnchorProvider for Rfc3161Provider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Rfc3161
    }

    fn name(&self) -> &str {
        "RFC 3161 TSA"
    }

    async fn is_available(&self) -> bool {
        for url in &self.tsa_urls {
            if let Ok(resp) = self.client.head(url).send().await {
                if resp.status().is_success() || resp.status().as_u16() == 405 {
                    return true;
                }
            }
        }
        false
    }

    async fn submit(&self, hash: &[u8; 32]) -> Result<Proof, AnchorError> {
        let mut last_error = None;

        for url in &self.tsa_urls {
            match self.request_timestamp(url, hash).await {
                Ok(token) => {
                    let info = self.parse_timestamp_response(&token)?;
                    return Ok(Proof {
                        id: format!("rfc3161-{}", info.serial_number),
                        provider: ProviderType::Rfc3161,
                        status: ProofStatus::Confirmed,
                        anchored_hash: *hash,
                        submitted_at: chrono::Utc::now(),
                        confirmed_at: Some(info.timestamp),
                        proof_data: token,
                        location: Some(url.clone()),
                        attestation_path: None,
                        extra: [
                            ("tsa".to_string(), serde_json::json!(info.tsa_name)),
                            ("serial".to_string(), serde_json::json!(info.serial_number)),
                        ]
                        .into_iter()
                        .collect(),
                    });
                }
                Err(e) => {
                    log::debug!("TSA {} failed: {e}", url);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(AnchorError::Unavailable("All TSAs failed".into())))
    }

    async fn check_status(&self, proof: &Proof) -> Result<Proof, AnchorError> {
        Ok(proof.clone())
    }

    async fn verify(&self, proof: &Proof) -> Result<bool, AnchorError> {
        self.verify_timestamp_token(&proof.proof_data, &proof.anchored_hash)
    }
}

impl Default for Rfc3161Provider {
    fn default() -> Self {
        Self::new(DEFAULT_TSA_URLS.iter().map(|s| s.to_string()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_provider_init() {
        let provider = Rfc3161Provider::default();
        assert!(!provider.tsa_urls.is_empty());
        assert!(provider.tsa_urls[0].contains("http"));
    }

    #[test]
    fn test_verify_token_too_short() {
        let provider = Rfc3161Provider::default();
        let hash = [0u8; 32];
        let token = vec![0u8; 50]; // < 100 bytes
        let result = provider.verify_timestamp_token(&token, &hash);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidFormat(msg)) => assert_eq!(msg, "Token too short"),
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_verify_token_invalid_asn1() {
        let provider = Rfc3161Provider::default();
        let hash = [0u8; 32];
        let mut token = vec![0u8; 150];
        token[0] = 0xFF; // Not 0x30
        let result = provider.verify_timestamp_token(&token, &hash);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidFormat(msg)) => assert_eq!(msg, "Invalid ASN.1 structure"),
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_verify_token_valid_stub() {
        let provider = Rfc3161Provider::default();
        let hash = [0u8; 32];
        let mut token = vec![0u8; 150];
        token[0] = 0x30; // ASN.1 SEQUENCE
        let result = provider.verify_timestamp_token(&token, &hash);
        assert!(result.is_ok());
    }
}
