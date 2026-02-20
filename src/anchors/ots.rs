use super::{
    AnchorError, AnchorProvider, AttestationOp, AttestationStep, Proof, ProofStatus, ProviderType,
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};

const OTS_CALENDAR_URLS: &[&str] = &[
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
];

const OTS_MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

pub struct OpenTimestampsProvider {
    calendar_urls: Vec<String>,
    client: reqwest::Client,
}

impl OpenTimestampsProvider {
    pub fn new() -> Self {
        Self {
            calendar_urls: OTS_CALENDAR_URLS.iter().map(|s| s.to_string()).collect(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    #[allow(dead_code)]
    pub fn with_calendars(urls: Vec<String>) -> Self {
        Self {
            calendar_urls: urls,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    async fn submit_to_calendar(&self, url: &str, hash: &[u8; 32]) -> Result<Vec<u8>, AnchorError> {
        let endpoint = format!("{}/digest", url);

        let response = self
            .client
            .post(&endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(hash.to_vec())
            .send()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AnchorError::Submission(format!(
                "Calendar returned {}",
                response.status()
            )));
        }

        let proof_bytes = response
            .bytes()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;

        Ok(proof_bytes.to_vec())
    }

    async fn upgrade_proof(&self, proof_data: &[u8]) -> Result<Option<Vec<u8>>, AnchorError> {
        let pending_urls = self.find_pending_calendars(proof_data)?;

        for url in pending_urls {
            let endpoint = format!("{}/timestamp", url);
            let commitment = self.extract_commitment(proof_data, &url)?;

            let response = self
                .client
                .get(&endpoint)
                .query(&[("commitment", hex::encode(&commitment))])
                .send()
                .await;

            if let Ok(resp) = response {
                if resp.status().is_success() {
                    let upgraded = resp
                        .bytes()
                        .await
                        .map_err(|e| AnchorError::Network(e.to_string()))?;
                    return Ok(Some(self.merge_proofs(proof_data, &upgraded)?));
                }
            }
        }

        Ok(None)
    }

    fn find_pending_calendars(&self, _proof_data: &[u8]) -> Result<Vec<String>, AnchorError> {
        Ok(self.calendar_urls.clone())
    }

    fn extract_commitment(&self, proof_data: &[u8], _url: &str) -> Result<Vec<u8>, AnchorError> {
        Ok(Sha256::digest(proof_data).to_vec())
    }

    fn merge_proofs(&self, original: &[u8], upgrade: &[u8]) -> Result<Vec<u8>, AnchorError> {
        let mut merged = original.to_vec();
        merged.extend_from_slice(upgrade);
        Ok(merged)
    }

    fn parse_attestation_path(
        &self,
        proof_data: &[u8],
    ) -> Result<Vec<AttestationStep>, AnchorError> {
        let mut steps = Vec::new();
        if proof_data.len() < OTS_MAGIC.len() {
            return Err(AnchorError::InvalidFormat("Proof too short".into()));
        }

        if &proof_data[..OTS_MAGIC.len()] != OTS_MAGIC {
            return Err(AnchorError::InvalidFormat("Invalid OTS magic".into()));
        }

        let mut pos: usize = OTS_MAGIC.len();

        while pos < proof_data.len() {
            let op_byte = proof_data[pos];
            pos += 1;

            let step = match op_byte {
                0x08 => AttestationStep {
                    operation: AttestationOp::Sha256,
                    data: Vec::new(),
                },
                0x02 => AttestationStep {
                    operation: AttestationOp::Ripemd160,
                    data: Vec::new(),
                },
                0xf0 => {
                    let len = proof_data.get(pos).copied().unwrap_or(0) as usize;
                    pos += 1;
                    let data = proof_data.get(pos..pos + len).unwrap_or(&[]).to_vec();
                    pos += len;
                    AttestationStep {
                        operation: AttestationOp::Append,
                        data,
                    }
                }
                0xf1 => {
                    let len = proof_data.get(pos).copied().unwrap_or(0) as usize;
                    pos += 1;
                    let data = proof_data.get(pos..pos + len).unwrap_or(&[]).to_vec();
                    pos += len;
                    AttestationStep {
                        operation: AttestationOp::Prepend,
                        data,
                    }
                }
                0x00 => AttestationStep {
                    operation: AttestationOp::Verify,
                    data: Vec::new(),
                },
                _ => continue,
            };

            steps.push(step);
        }

        Ok(steps)
    }

    fn verify_attestation_path(
        &self,
        hash: &[u8; 32],
        steps: &[AttestationStep],
    ) -> Result<Vec<u8>, AnchorError> {
        let mut current = hash.to_vec();

        for step in steps {
            current = match step.operation {
                AttestationOp::Sha256 => Sha256::digest(&current).to_vec(),
                AttestationOp::Ripemd160 => {
                    use ripemd::Ripemd160;
                    Ripemd160::digest(&current).to_vec()
                }
                AttestationOp::Append => {
                    let mut new = current.clone();
                    new.extend_from_slice(&step.data);
                    new
                }
                AttestationOp::Prepend => {
                    let mut new = step.data.clone();
                    new.extend_from_slice(&current);
                    new
                }
                AttestationOp::Verify => current.clone(),
            };
        }

        Ok(current)
    }
}

#[async_trait]
impl AnchorProvider for OpenTimestampsProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::OpenTimestamps
    }

    fn name(&self) -> &str {
        "OpenTimestamps"
    }

    async fn is_available(&self) -> bool {
        for url in &self.calendar_urls {
            if let Ok(resp) = self.client.get(url).send().await {
                if resp.status().is_success() {
                    return true;
                }
            }
        }
        false
    }

    async fn submit(&self, hash: &[u8; 32]) -> Result<Proof, AnchorError> {
        let mut last_error = None;

        for url in &self.calendar_urls {
            match self.submit_to_calendar(url, hash).await {
                Ok(proof_data) => {
                    return Ok(Proof {
                        id: format!("ots-{}", hex::encode(&hash[..8])),
                        provider: ProviderType::OpenTimestamps,
                        status: ProofStatus::Pending,
                        anchored_hash: *hash,
                        submitted_at: chrono::Utc::now(),
                        confirmed_at: None,
                        proof_data,
                        location: Some(url.clone()),
                        attestation_path: None,
                        extra: Default::default(),
                    });
                }
                Err(e) => {
                    log::debug!("Calendar {} failed: {e}", url);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(AnchorError::Unavailable("All calendars failed".into())))
    }

    async fn check_status(&self, proof: &Proof) -> Result<Proof, AnchorError> {
        if let Some(upgraded_data) = self.upgrade_proof(&proof.proof_data).await? {
            let path = self.parse_attestation_path(&upgraded_data)?;
            let has_bitcoin = path.iter().any(|s| s.operation == AttestationOp::Verify);

            let mut updated = proof.clone();
            updated.proof_data = upgraded_data;
            updated.attestation_path = Some(path);

            if has_bitcoin {
                updated.status = ProofStatus::Confirmed;
                updated.confirmed_at = Some(chrono::Utc::now());
            }

            return Ok(updated);
        }

        Ok(proof.clone())
    }

    async fn verify(&self, proof: &Proof) -> Result<bool, AnchorError> {
        let path = if let Some(ref path) = proof.attestation_path {
            path.clone()
        } else {
            self.parse_attestation_path(&proof.proof_data)?
        };

        let result = self.verify_attestation_path(&proof.anchored_hash, &path)?;
        Ok(!result.is_empty())
    }

    async fn upgrade(&self, proof: &Proof) -> Result<Option<Proof>, AnchorError> {
        if proof.status == ProofStatus::Confirmed {
            return Ok(None);
        }

        if let Some(upgraded_data) = self.upgrade_proof(&proof.proof_data).await? {
            let mut updated = proof.clone();
            updated.proof_data = upgraded_data;
            updated.attestation_path = Some(self.parse_attestation_path(&updated.proof_data)?);

            if let Some(ref path) = updated.attestation_path {
                if path.iter().any(|s| s.operation == AttestationOp::Verify) {
                    updated.status = ProofStatus::Confirmed;
                    updated.confirmed_at = Some(chrono::Utc::now());
                }
            }

            return Ok(Some(updated));
        }

        Ok(None)
    }
}

impl Default for OpenTimestampsProvider {
    fn default() -> Self {
        Self::new()
    }
}
