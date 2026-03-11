// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! HTTP client for the WritersProof attestation API.

use ed25519_dalek::{Signer, SigningKey};
use reqwest::Client;

use super::types::{
    AnchorRequest, AnchorResponse, AttestResponse, EnrollRequest, EnrollResponse, NonceResponse,
    StegoSignRequest, StegoSignResponse, StegoVerifyResponse, VerifyResponse,
};
use crate::error::{Error, Result};

/// WritersProof API client.
pub struct WritersProofClient {
    base_url: String,
    jwt: Option<String>,
    client: Client,
}

impl WritersProofClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            jwt: None,
            client: Client::new(),
        }
    }

    /// Set the JWT token for authenticated requests.
    pub fn with_jwt(mut self, token: String) -> Self {
        self.jwt = Some(token);
        self
    }

    /// Request a fresh nonce from the verifier.
    ///
    /// `POST /v1/nonce`
    pub async fn request_nonce(&self) -> Result<NonceResponse> {
        let url = format!("{}/v1/nonce", self.base_url);
        let mut req = self.client.post(&url);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("nonce request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "nonce request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.json::<NonceResponse>()
            .await
            .map_err(|e| Error::crypto(format!("nonce response parse failed: {e}")))
    }

    /// Enroll a device with WritersProof.
    ///
    /// `POST /v1/enroll`
    pub async fn enroll(&self, req: EnrollRequest) -> Result<EnrollResponse> {
        let url = format!("{}/v1/enroll", self.base_url);
        let mut http_req = self.client.post(&url).json(&req);
        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt);
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("enroll request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "enroll request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.json::<EnrollResponse>()
            .await
            .map_err(|e| Error::crypto(format!("enroll response parse failed: {e}")))
    }

    /// Submit evidence for attestation.
    ///
    /// `POST /v1/attest`
    ///
    /// The evidence CBOR is sent as the request body. Nonce, hardware key ID,
    /// and signature are sent as custom headers.
    pub async fn attest(
        &self,
        evidence_cbor: &[u8],
        nonce: &[u8; 32],
        hardware_key_id: &str,
        signing_key: &SigningKey,
    ) -> Result<AttestResponse> {
        let signature = signing_key.sign(evidence_cbor);
        let url = format!("{}/v1/attest", self.base_url);

        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/cbor")
            .header("X-WLD-Nonce", hex::encode(nonce))
            .header("X-WLD-Hardware-Key-Id", hardware_key_id)
            .header("X-WLD-Signature", hex::encode(signature.to_bytes()))
            .body(evidence_cbor.to_vec());

        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("attest request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "attest request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.json::<AttestResponse>()
            .await
            .map_err(|e| Error::crypto(format!("attest response parse failed: {e}")))
    }

    /// Get an attestation certificate by ID.
    ///
    /// `GET /v1/certificates/:id`
    pub async fn get_certificate(&self, id: &str) -> Result<Vec<u8>> {
        let url = format!("{}/v1/certificates/{}", self.base_url, id);
        let mut req = self.client.get(&url);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("certificate request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "certificate request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| Error::crypto(format!("certificate response read failed: {e}")))
    }

    /// Get the certificate revocation list.
    ///
    /// `GET /v1/crl`
    pub async fn get_crl(&self) -> Result<Vec<u8>> {
        let url = format!("{}/v1/crl", self.base_url);
        let mut req = self.client.get(&url);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("CRL request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "CRL request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| Error::crypto(format!("CRL response read failed: {e}")))
    }

    /// Anchor an evidence packet hash in the transparency log.
    ///
    /// `POST /v1/anchor`
    pub async fn anchor(&self, req: AnchorRequest) -> Result<AnchorResponse> {
        let url = format!("{}/v1/anchor", self.base_url);
        let mut http_req = self.client.post(&url).json(&req);
        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt);
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("anchor request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "anchor request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.json::<AnchorResponse>()
            .await
            .map_err(|e| Error::crypto(format!("anchor response parse failed: {e}")))
    }

    /// Verify an evidence packet.
    ///
    /// `POST /v1/verify`
    pub async fn verify(&self, evidence_cbor: &[u8]) -> Result<VerifyResponse> {
        let url = format!("{}/v1/verify", self.base_url);
        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/vnd.writerslogic-pop+cbor")
            .body(evidence_cbor.to_vec());

        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("verify request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "verify request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.json::<VerifyResponse>()
            .await
            .map_err(|e| Error::crypto(format!("verify response parse failed: {e}")))
    }

    /// Request a steganographic watermark signing from WritersProof.
    ///
    /// `POST /v1/stego/sign`
    pub async fn stego_sign(&self, req: StegoSignRequest) -> Result<StegoSignResponse> {
        let url = format!("{}/v1/stego/sign", self.base_url);
        let mut http_req = self.client.post(&url).json(&req);
        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt);
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("stego sign request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "stego sign request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.json::<StegoSignResponse>()
            .await
            .map_err(|e| Error::crypto(format!("stego sign response parse failed: {e}")))
    }

    /// Verify a steganographic watermark via WritersProof.
    ///
    /// `POST /v1/stego/verify`
    pub async fn stego_verify(
        &self,
        document_text: &str,
        mmr_root: &str,
    ) -> Result<StegoVerifyResponse> {
        let url = format!("{}/v1/stego/verify", self.base_url);
        let body = serde_json::json!({
            "document_text": document_text,
            "mmr_root": mmr_root,
        });

        let mut req = self.client.post(&url).json(&body);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("stego verify request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "stego verify request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.json::<StegoVerifyResponse>()
            .await
            .map_err(|e| Error::crypto(format!("stego verify response parse failed: {e}")))
    }

    /// Check if the WritersProof service is reachable.
    ///
    /// `GET /health`
    pub async fn is_online(&self) -> bool {
        let url = format!("{}/health", self.base_url);
        match self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) => r.status().is_success(),
            Err(e) => {
                log::debug!("Health check failed: {e}");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_construction() {
        let client = WritersProofClient::new("https://api.writersproof.com");
        assert_eq!(client.base_url, "https://api.writersproof.com");
        assert!(client.jwt.is_none());
    }

    #[test]
    fn test_client_with_jwt() {
        let client = WritersProofClient::new("https://api.writersproof.com")
            .with_jwt("test-token".to_string());
        assert_eq!(client.jwt.as_deref(), Some("test-token"));
    }

    #[test]
    fn test_trailing_slash_stripped() {
        let client = WritersProofClient::new("https://api.writersproof.com/");
        assert_eq!(client.base_url, "https://api.writersproof.com");
    }
}
