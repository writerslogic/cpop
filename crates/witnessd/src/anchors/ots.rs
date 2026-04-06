// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

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

/// Anchor provider using OpenTimestamps calendar servers for Bitcoin attestation.
pub struct OpenTimestampsProvider {
    calendar_urls: Vec<String>,
    client: reqwest::Client,
}

impl OpenTimestampsProvider {
    /// Create a provider using the default public calendar servers.
    pub fn new() -> Result<Self, AnchorError> {
        Ok(Self {
            calendar_urls: OTS_CALENDAR_URLS.iter().map(|s| s.to_string()).collect(),
            client: super::http::build_http_client(None)?,
        })
    }

    /// Create a provider using custom calendar server URLs.
    #[allow(dead_code)]
    pub fn with_calendars(urls: Vec<String>) -> Result<Self, AnchorError> {
        Ok(Self {
            calendar_urls: urls,
            client: super::http::build_http_client(None)?,
        })
    }

    async fn submit_to_calendar(&self, url: &str, hash: &[u8; 32]) -> Result<Vec<u8>, AnchorError> {
        let endpoint = format!("{}/digest", url);

        let response = self
            .client
            .post(&endpoint)
            .header("Content-Type", "application/octet-stream")
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

    async fn upgrade_proof(&self, proof_data: &[u8], anchored_hash: &[u8; 32]) -> Result<Option<Vec<u8>>, AnchorError> {
        let pending_urls = self.find_pending_calendars(proof_data)?;

        for url in pending_urls {
            let endpoint = format!("{}/timestamp", url);
            let commitment = self.extract_commitment(proof_data, &url, anchored_hash)?;

            let response = self
                .client
                .get(&endpoint)
                .query(&[("commitment", hex::encode(&commitment))])
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let upgraded = resp
                            .bytes()
                            .await
                            .map_err(|e| AnchorError::Network(e.to_string()))?;
                        return Ok(Some(self.merge_proofs(proof_data, &upgraded, &url)?));
                    }
                    log::debug!("Calendar {} returned {} during upgrade", url, resp.status());
                }
                Err(e) => {
                    log::debug!("Calendar {} upgrade request failed: {e}", url);
                }
            }
        }

        Ok(None)
    }

    /// Parse OTS proof data to find calendar URLs whose attestations are still pending.
    fn find_pending_calendars(&self, proof_data: &[u8]) -> Result<Vec<String>, AnchorError> {
        let mut urls = Vec::new();
        if proof_data.len() < OTS_MAGIC.len() {
            return Ok(urls);
        }

        if &proof_data[..OTS_MAGIC.len()] != OTS_MAGIC {
            return Err(AnchorError::InvalidFormat("Invalid OTS magic".into()));
        }

        let mut pos = OTS_MAGIC.len();
        while pos < proof_data.len() {
            let op = proof_data[pos];
            pos += 1;

            match op {
                0x08 | 0x02 => {} // sha256, ripemd160
                0xf0 | 0xf1 => {
                    let _ = Self::read_data(proof_data, &mut pos)?;
                }
                0x00 => {
                    // Pending attestation
                    let url = Self::read_string(proof_data, &mut pos)?;
                    urls.push(url);
                }
                _ => break, // Unknown or terminal
            }
        }
        Ok(urls)
    }

    /// Extract the calendar-specific commitment hash from an OTS proof
    /// by replaying operations starting from the anchored hash.
    fn extract_commitment(&self, proof_data: &[u8], url: &str, anchored_hash: &[u8; 32]) -> Result<Vec<u8>, AnchorError> {
        if proof_data.len() < OTS_MAGIC.len() {
            return Err(AnchorError::InvalidFormat("Proof too short".into()));
        }

        let mut current_hash = anchored_hash.to_vec();
        let mut pos = OTS_MAGIC.len();

        while pos < proof_data.len() {
            let op = proof_data[pos];
            pos += 1;

            match op {
                0x08 => { // sha256
                    current_hash = Sha256::digest(&current_hash).to_vec();
                }
                0x02 => { // ripemd160
                    use ripemd::Ripemd160;
                    current_hash = Ripemd160::digest(&current_hash).to_vec();
                }
                0xf0 => { // append
                    let data = Self::read_data(proof_data, &mut pos)?;
                    current_hash.extend_from_slice(&data);
                }
                0xf1 => { // prepend
                    let data = Self::read_data(proof_data, &mut pos)?;
                    let mut new = data;
                    new.extend_from_slice(&current_hash);
                    current_hash = new;
                }
                0x00 => {
                    let found_url = Self::read_string(proof_data, &mut pos)?;
                    if found_url == url {
                        return Ok(current_hash);
                    }
                }
                _ => break,
            }
        }

        Err(AnchorError::Unavailable(format!("URL {url} not found in proof")))
    }

    /// Merge an upgraded calendar response into the original OTS proof.
    fn merge_proofs(&self, original: &[u8], upgrade: &[u8], url: &str) -> Result<Vec<u8>, AnchorError> {
        if original.len() < OTS_MAGIC.len() {
            return Err(AnchorError::InvalidFormat("Original proof too short".into()));
        }

        let mut result = original[..OTS_MAGIC.len()].to_vec();
        let mut pos = OTS_MAGIC.len();

        while pos < original.len() {
            let op_pos = pos;
            let op = original[pos];
            pos += 1;

            match op {
                0x08 | 0x02 => {
                    result.push(op);
                }
                0xf0 | 0xf1 => {
                    result.push(op);
                    let data_start = pos;
                    let _ = Self::read_data(original, &mut pos)?;
                    result.extend_from_slice(&original[data_start..pos]);
                }
                0x00 => {
                    let url_start = pos;
                    let found_url = Self::read_string(original, &mut pos)?;
                    if found_url == url {
                        // Strip magic from upgrade if present
                        if upgrade.starts_with(OTS_MAGIC) {
                            result.extend_from_slice(&upgrade[OTS_MAGIC.len()..]);
                        } else {
                            result.extend_from_slice(upgrade);
                        }
                    } else {
                        result.push(0x00);
                        result.extend_from_slice(&original[url_start..pos]);
                    }
                }
                _ => {
                    result.extend_from_slice(&original[op_pos..]);
                    break;
                }
            }
        }
        Ok(result)
    }

    /// Read a Bitcoin-style varint (compact size) from `data` at `pos`,
    /// advancing `pos` past the encoded integer.
    fn read_varint(data: &[u8], pos: &mut usize) -> Result<usize, AnchorError> {
        if *pos >= data.len() {
            return Err(AnchorError::InvalidFormat(
                "Truncated proof: expected varint".into(),
            ));
        }
        let first = data[*pos];
        *pos += 1;
        match first {
            0x00..=0xfc => Ok(first as usize),
            0xfd => {
                if *pos + 2 > data.len() {
                    return Err(AnchorError::InvalidFormat(
                        "Truncated proof: expected 2-byte varint".into(),
                    ));
                }
                let v = u16::from_le_bytes([data[*pos], data[*pos + 1]]) as usize;
                *pos += 2;
                Ok(v)
            }
            0xfe => {
                if *pos + 4 > data.len() {
                    return Err(AnchorError::InvalidFormat(
                        "Truncated proof: expected 4-byte varint".into(),
                    ));
                }
                let v = u32::from_le_bytes([
                    data[*pos],
                    data[*pos + 1],
                    data[*pos + 2],
                    data[*pos + 3],
                ]) as usize;
                *pos += 4;
                Ok(v)
            }
            0xff => {
                if *pos + 8 > data.len() {
                    return Err(AnchorError::InvalidFormat(
                        "Truncated proof: expected 8-byte varint".into(),
                    ));
                }
                let v = u64::from_le_bytes([
                    data[*pos],
                    data[*pos + 1],
                    data[*pos + 2],
                    data[*pos + 3],
                    data[*pos + 4],
                    data[*pos + 5],
                    data[*pos + 6],
                    data[*pos + 7],
                ]) as usize;
                *pos += 8;
                Ok(v)
            }
        }
    }

    /// Read a varint-prefixed byte slice from `data` at `pos`,
    /// advancing `pos` past both the length and the payload.
    fn read_data(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, AnchorError> {
        let len = Self::read_varint(data, pos)?;
        if *pos + len > data.len() {
            return Err(AnchorError::InvalidFormat(format!(
                "Truncated proof: need {} bytes at offset {}, have {}",
                len,
                *pos,
                data.len() - *pos
            )));
        }
        let result = data[*pos..*pos + len].to_vec();
        *pos += len;
        Ok(result)
    }

    /// Read a varint-prefixed UTF-8 string from `data` at `pos`.
    fn read_string(data: &[u8], pos: &mut usize) -> Result<String, AnchorError> {
        let bytes = Self::read_data(data, pos)?;
        String::from_utf8(bytes).map_err(|e| AnchorError::InvalidFormat(format!("Invalid UTF-8: {e}")))
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
                    let data = Self::read_data(proof_data, &mut pos)?;
                    AttestationStep {
                        operation: AttestationOp::Append,
                        data,
                    }
                }
                0xf1 => {
                    let data = Self::read_data(proof_data, &mut pos)?;
                    AttestationStep {
                        operation: AttestationOp::Prepend,
                        data,
                    }
                }
                0x00 => AttestationStep {
                    operation: AttestationOp::Verify,
                    data: Vec::new(),
                },
                unknown => {
                    return Err(AnchorError::InvalidFormat(format!(
                        "Unknown OTS opcode: 0x{:02x}",
                        unknown
                    )));
                }
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
                // Verify is a terminal attestation marker; it does not transform
                // the hash. Actual block header validation is deferred to the
                // `verify()` trait method.
                AttestationOp::Verify => current.clone(),
            };
        }

        Ok(current)
    }
}

/// # Security
///
/// Bitcoin block header cross-checking is **not yet implemented**. The
/// `verify` method only confirms that the attestation path contains a
/// `Verify` step and yields a 32-byte candidate hash; it does not fetch
/// or validate the actual block header from a trusted source. Results
/// should be treated as structural-only until full cross-check is added.
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

        Err(last_error.unwrap_or_else(|| {
            log::warn!("OTS submit failed: no calendar URLs configured");
            AnchorError::Unavailable("All calendars failed".into())
        }))
    }

    async fn check_status(&self, proof: &Proof) -> Result<Proof, AnchorError> {
        if let Some(upgraded_data) = self.upgrade_proof(&proof.proof_data, &proof.anchored_hash).await? {
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
        // NOTE: Full OTS verification requires fetching the Bitcoin block header
        // from a trusted source and checking that the final hash in the
        // attestation path matches it. That network check is not yet implemented.
        // We parse the path and confirm structural sanity (Verify step present,
        // 32-byte result) but return an error so callers know actual verification
        // cannot be performed yet.
        log::warn!(
            "ots verify: Bitcoin block header cross-check not implemented; \
             performing structural check only"
        );
        let path = if let Some(ref path) = proof.attestation_path {
            path.clone()
        } else {
            self.parse_attestation_path(&proof.proof_data)?
        };

        let has_bitcoin = path.iter().any(|s| s.operation == AttestationOp::Verify);
        if !has_bitcoin {
            return Ok(false);
        }

        let result = self.verify_attestation_path(&proof.anchored_hash, &path)?;
        if result.len() != 32 {
            return Ok(false);
        }

        Err(AnchorError::Unavailable(
            "Bitcoin block header cross-check not yet implemented; structural check passed".into(),
        ))
    }

    async fn upgrade(&self, proof: &Proof) -> Result<Option<Proof>, AnchorError> {
        if proof.status == ProofStatus::Confirmed {
            return Ok(None);
        }

        if let Some(upgraded_data) = self.upgrade_proof(&proof.proof_data, &proof.anchored_hash).await? {
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
