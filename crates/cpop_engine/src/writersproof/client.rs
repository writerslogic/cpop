// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! HTTP client for the WritersProof attestation API.

use ed25519_dalek::{Signer, SigningKey};
use reqwest::Client;
use sha2::{Digest, Sha256};

use super::types::{
    AnchorRequest, AnchorResponse, AttestResponse, BeaconRequest, BeaconResponse, EnrollRequest,
    EnrollResponse, NonceResponse, StegoSignRequest, StegoSignResponse, StegoVerifyResponse,
    VerifyResponse,
};
use crate::error::{Error, Result};
use crate::steganography::{ZwcExtractor, ZwcParams};

/// WritersProof API client.
pub struct WritersProofClient {
    base_url: String,
    jwt: Option<String>,
    client: Client,
}

impl WritersProofClient {
    /// Create a client targeting the given API base URL.
    ///
    /// In production, `base_url` must use HTTPS to protect JWT tokens and
    /// evidence data in transit. HTTP is only allowed in debug builds for
    /// local development.
    pub fn new(base_url: &str) -> Result<Self> {
        let url = base_url.trim_end_matches('/').to_string();
        #[cfg(not(debug_assertions))]
        if !url.starts_with("https://") {
            return Err(Error::crypto(format!(
                "WritersProof base_url must use HTTPS in release builds: {}",
                &url[..url.len().min(40)]
            )));
        }
        Ok(Self {
            base_url: url,
            jwt: None,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| Error::crypto(format!("HTTP client build failed: {e}")))?,
        })
    }

    /// Set the JWT token for authenticated requests.
    pub fn with_jwt(mut self, token: String) -> Self {
        self.jwt = Some(token);
        self
    }

    /// Request a fresh nonce from the verifier.
    ///
    /// `POST /v1/nonce`
    pub async fn request_nonce(&self, hardware_key_id: &str) -> Result<NonceResponse> {
        let url = format!("{}/v1/nonce", self.base_url);
        let body = serde_json::json!({ "hardwareKeyId": hardware_key_id });
        let mut req = self.client.post(&url).json(&body);
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
        let hkid_bytes = hardware_key_id.as_bytes();
        let mut sign_payload = zeroize::Zeroizing::new(Vec::with_capacity(
            4 + nonce.len() + 4 + hkid_bytes.len() + 4 + evidence_cbor.len(),
        ));
        sign_payload.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
        sign_payload.extend_from_slice(nonce);
        sign_payload.extend_from_slice(&(hkid_bytes.len() as u32).to_be_bytes());
        sign_payload.extend_from_slice(hkid_bytes);
        sign_payload.extend_from_slice(&(evidence_cbor.len() as u32).to_be_bytes());
        sign_payload.extend_from_slice(evidence_cbor);
        let signature = signing_key.sign(&sign_payload);
        let url = format!("{}/v1/attest", self.base_url);

        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/cbor")
            .header("X-CPOP-Nonce", hex::encode(nonce))
            .header("X-CPOP-Hardware-Key-Id", hardware_key_id)
            .header("X-CPOP-Signature", hex::encode(signature.to_bytes()))
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
        // Validate certificate ID to prevent path traversal (e.g., "../../admin/keys")
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Error::crypto(format!(
                "invalid certificate ID: must be alphanumeric/dash/underscore, got: {}",
                &id[..id.len().min(32)]
            )));
        }
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

        const MAX_CERT_SIZE: u64 = 10_000_000; // 10 MB
        if let Some(cl) = resp.content_length() {
            if cl > MAX_CERT_SIZE {
                return Err(Error::crypto(format!(
                    "certificate Content-Length too large: {cl} bytes (max {MAX_CERT_SIZE})"
                )));
            }
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::crypto(format!("certificate response read failed: {e}")))?;
        if body.len() as u64 > MAX_CERT_SIZE {
            return Err(Error::crypto(format!(
                "certificate response too large: {} bytes (max {MAX_CERT_SIZE})",
                body.len()
            )));
        }
        Ok(body.to_vec())
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

        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::crypto(format!("CRL response read failed: {e}")))?;
        if body.len() > 50_000_000 {
            return Err(Error::crypto(format!(
                "CRL response too large: {} bytes (max 50MB)",
                body.len()
            )));
        }
        Ok(body.to_vec())
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

    /// Fetch temporal beacon attestation from WritersProof.
    ///
    /// WritersProof fetches the latest drand round and NIST pulse server-side,
    /// then counter-signs the bundle. The returned `wp_signature` is included
    /// in the H2 seal computation, cryptographically binding the beacon values
    /// to the evidence packet.
    ///
    /// `POST /v1/beacon`
    pub async fn fetch_beacon(
        &self,
        checkpoint_hash: &str,
        timeout_secs: u64,
    ) -> Result<BeaconResponse> {
        let url = format!("{}/v1/beacon", self.base_url);
        let req = BeaconRequest {
            checkpoint_hash: checkpoint_hash.to_string(),
        };

        let effective_timeout = timeout_secs.max(1); // Enforce minimum 1s timeout
        let mut http_req = self
            .client
            .post(&url)
            .json(&req)
            .timeout(std::time::Duration::from_secs(effective_timeout));

        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt);
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("beacon request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "beacon request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.json::<BeaconResponse>()
            .await
            .map_err(|e| Error::crypto(format!("beacon response parse failed: {e}")))
    }

    /// Verify an evidence packet.
    ///
    /// `POST /v1/verify`
    pub async fn verify(&self, evidence_cbor: &[u8]) -> Result<VerifyResponse> {
        let url = format!("{}/v1/verify", self.base_url);
        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/vnd.writersproof.cpop+cbor")
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

        let mut response = resp
            .json::<VerifyResponse>()
            .await
            .map_err(|e| Error::crypto(format!("verify response parse failed: {e}")))?;
        response.sanitize();
        Ok(response)
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
    /// The document text is never sent to the server. Instead, this method:
    /// 1. Hashes the clean (ZWC-stripped) document text with SHA-256 locally.
    /// 2. Extracts the ZWC watermark tag from the document locally.
    /// 3. Sends only `{doc_hash, extracted_tag, mmr_root}` to the server.
    ///
    /// `POST /v1/stego/verify`
    pub async fn stego_verify(
        &self,
        document_text: &str,
        mmr_root: &str,
    ) -> Result<StegoVerifyResponse> {
        // Extract ZWC tag and hash the clean text locally — never send plaintext.
        let extractor = ZwcExtractor::new(ZwcParams::default());
        let extracted_tag = extractor.extract_tag(document_text);
        let clean_text = ZwcExtractor::strip_zwc(document_text);
        let doc_hash = hex::encode(Sha256::digest(clean_text.as_bytes()));
        let extracted_tag_hex = hex::encode(&extracted_tag);

        let url = format!("{}/v1/stego/verify", self.base_url);
        let body = serde_json::json!({
            "docHash": doc_hash,
            "extractedTag": extracted_tag_hex,
            "mmrRoot": mmr_root,
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
        let client = WritersProofClient::new("https://api.writersproof.com").unwrap();
        assert_eq!(client.base_url, "https://api.writersproof.com");
        assert!(client.jwt.is_none());
    }

    #[test]
    fn test_client_with_jwt() {
        let client = WritersProofClient::new("https://api.writersproof.com")
            .unwrap()
            .with_jwt("test-token".to_string());
        assert_eq!(client.jwt.as_deref(), Some("test-token"));
    }

    #[test]
    fn test_trailing_slash_stripped() {
        let client = WritersProofClient::new("https://api.writersproof.com/").unwrap();
        assert_eq!(client.base_url, "https://api.writersproof.com");
    }
}
