// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::{AnchorError, AnchorProvider, Proof, ProofStatus, ProviderType};
use async_trait::async_trait;
use subtle::ConstantTimeEq;

const DEFAULT_TSA_URLS: &[&str] = &[
    "https://timestamp.digicert.com",
    "https://timestamp.sectigo.com",
    "https://freetsa.org/tsr",
    "https://timestamp.globalsign.com/tsa/r6advanced1",
];

/// Anchor provider using RFC 3161 Time-Stamp Authorities.
pub struct Rfc3161Provider {
    tsa_urls: Vec<String>,
    client: reqwest::Client,
}

impl Rfc3161Provider {
    /// Create a provider with explicit TSA endpoint URLs.
    pub fn new(tsa_urls: Vec<String>) -> Result<Self, AnchorError> {
        let client = super::http::build_http_client(None)?;
        Ok(Self { tsa_urls, client })
    }

    async fn request_timestamp(&self, url: &str, hash: &[u8; 32]) -> Result<Vec<u8>, AnchorError> {
        let (request, nonce_sent) = self.build_timestamp_request(hash)?;

        let mut response = self
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

        const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1 MB

        // Pre-flight check on Content-Length header when present.
        if let Some(content_length) = response.content_length() {
            if content_length > MAX_RESPONSE_SIZE as u64 {
                return Err(AnchorError::InvalidFormat(format!(
                    "TSA response too large: {} bytes (max {})",
                    content_length, MAX_RESPONSE_SIZE
                )));
            }
        }

        // Stream the body in chunks to enforce the size cap even when the
        // server uses chunked transfer-encoding (no Content-Length header).
        let mut body = Vec::new();
        loop {
            // reqwest's Response exposes chunk() which returns Option<Bytes>
            let chunk = response
                .chunk()
                .await
                .map_err(|e| AnchorError::Network(e.to_string()))?;
            match chunk {
                Some(bytes) => {
                    body.extend_from_slice(&bytes);
                    if body.len() > MAX_RESPONSE_SIZE {
                        return Err(AnchorError::InvalidFormat(format!(
                            "TSA response too large: >{} bytes (max {})",
                            body.len(),
                            MAX_RESPONSE_SIZE
                        )));
                    }
                }
                None => break,
            }
        }
        // H-051: Verify the nonce in the response matches the request nonce
        let tst_info = extract_tst_info(&body)?;
        let response_nonce = extract_nonce(&tst_info)
            .ok_or_else(|| AnchorError::InvalidFormat("TSA response missing nonce".into()))?;
        if response_nonce.ct_eq(nonce_sent.as_slice()).unwrap_u8() != 1 {
            return Err(AnchorError::InvalidFormat(
                "TSA response nonce does not match request nonce".into(),
            ));
        }

        Ok(body)
    }

    #[allow(clippy::vec_init_then_push)]
    fn build_timestamp_request(&self, hash: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), AnchorError> {
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| AnchorError::Submission("Failed to generate nonce".into()))?;
        let nonce_vec = nonce.to_vec();

        let sha256_oid: &[u8] = &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];

        // MessageImprint SEQUENCE wraps AlgorithmIdentifier (OID + NULL) + OCTET STRING (hash)
        let mi_content_len = sha256_oid.len() + 2 + 2 + 32; // OID + NULL tag/len + OCTET STRING tag/len + hash
        debug_assert!(
            mi_content_len <= 127,
            "DER short form requires length <= 127"
        );
        let mut message_imprint = Vec::new();
        message_imprint.push(0x30);
        message_imprint.push(
            u8::try_from(mi_content_len)
                .map_err(|_| AnchorError::Submission("DER length overflow".into()))?,
        );
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
        request.push(
            u8::try_from(message_imprint.len())
                .map_err(|_| AnchorError::Submission("DER length overflow".into()))?,
        );
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

        Ok((final_request, nonce_vec))
    }

    /// Extract timestamp, serial, and TSA name from a TimeStampResp (RFC 3161 s2.4.2).
    fn parse_timestamp_response(&self, response: &[u8]) -> Result<TimestampInfo, AnchorError> {
        if response.len() < 10 {
            return Err(AnchorError::InvalidFormat("Response too short".into()));
        }

        let tst_info = extract_tst_info(response)?;
        let gen_time = extract_generalized_time(&tst_info).ok_or_else(|| {
            AnchorError::InvalidFormat("Cannot extract genTime from TSTInfo".into())
        })?;
        let serial = extract_serial_number(&tst_info).ok_or_else(|| {
            AnchorError::InvalidFormat("Cannot extract serialNumber from TSTInfo".into())
        })?;

        Ok(TimestampInfo {
            timestamp: gen_time,
            serial_number: serial,
            tsa_name: "RFC 3161 TSA".to_string(),
        })
    }

    /// Verify that the embedded MessageImprint hash matches `hash`.
    ///
    /// # Security
    ///
    /// **CMS signature verification is NOT implemented** (AUD-124). The TSA's digital
    /// signature over the TSTInfo is not checked. This function only verifies that the
    /// embedded hash matches the expected value. A forged timestamp token with the correct
    /// hash will pass this check. Full CMS/PKCS#7 signature verification requires a
    /// DER/X.509 parsing library and TSA certificate chain validation.
    fn verify_timestamp_token(&self, token: &[u8], hash: &[u8; 32]) -> Result<bool, AnchorError> {
        log::warn!(
            "verify_timestamp_token: CMS signature verification is not implemented; \
             only the embedded MessageImprint hash is checked"
        );

        if token.len() < 100 {
            return Err(AnchorError::InvalidFormat("Token too short".into()));
        }
        if token[0] != 0x30 {
            return Err(AnchorError::InvalidFormat("Invalid ASN.1 structure".into()));
        }

        let tst_info = extract_tst_info(token)?;
        let imprint_hash = extract_message_imprint_hash(&tst_info).ok_or_else(|| {
            AnchorError::InvalidFormat("Cannot extract MessageImprint hash from TSTInfo".into())
        })?;
        if imprint_hash.ct_eq(hash).unwrap_u8() != 1 {
            return Err(AnchorError::HashMismatch);
        }

        Ok(true)
    }
}

// DER/CMS parsing uses byte-range offsets to sidestep lifetime issues
// with closure-based iteration.

/// DER TLV as byte-range offsets into the source buffer.
#[derive(Clone, Copy)]
struct Tlv {
    tag: u8,
    content_start: usize,
    content_end: usize,
}

impl Tlv {
    fn content<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.content_start..self.content_end]
    }
}

/// Read a single DER TLV at `offset`.
fn read_tlv(data: &[u8], offset: usize) -> Option<Tlv> {
    if offset >= data.len() {
        return None;
    }
    let tag = data[offset];
    let length_offset = offset.checked_add(1)?;
    let (length, header_len) = read_der_length(data, length_offset)?;
    let content_start = length_offset.checked_add(header_len)?;
    let content_end = content_start.checked_add(length)?;
    if content_end > data.len() {
        return None;
    }
    Some(Tlv {
        tag,
        content_start,
        content_end,
    })
}

/// Parse DER definite-length at `offset`. Returns `(value, header_bytes)`.
fn read_der_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    if offset >= data.len() {
        return None;
    }
    let first = data[offset];
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x80 {
        None // indefinite-length not supported
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || offset + 1 + num_bytes > data.len() {
            return None;
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = length
                .checked_shl(8)
                .and_then(|l| l.checked_add(data[offset + 1 + i] as usize))?;
        }
        Some((length, 1 + num_bytes))
    }
}

/// Iterate child TLVs within a constructed content region.
fn children(data: &[u8], start: usize, end: usize) -> Vec<Tlv> {
    let mut result = Vec::new();
    let mut pos = start;
    while pos < end {
        if let Some(tlv) = read_tlv(data, pos) {
            result.push(tlv);
            pos = tlv.content_end;
        } else {
            break;
        }
    }
    result
}

/// Children of a TLV (offsets relative to `data`).
fn children_of(data: &[u8], tlv: &Tlv) -> Vec<Tlv> {
    children(data, tlv.content_start, tlv.content_end)
}

/// First child matching `tag`, if any.
fn find_child_by_tag(data: &[u8], parent: &Tlv, tag: u8) -> Option<Tlv> {
    children_of(data, parent).into_iter().find(|c| c.tag == tag)
}

/// Extract TSTInfo from a TimeStampResp or bare ContentInfo.
///
/// Path: TimeStampResp -> ContentInfo -> SignedData -> EncapContentInfo -> eContent.
fn extract_tst_info(data: &[u8]) -> Result<Vec<u8>, AnchorError> {
    let outer = read_tlv(data, 0)
        .ok_or_else(|| AnchorError::InvalidFormat("Cannot parse outer SEQUENCE".into()))?;
    if outer.tag != 0x30 {
        return Err(AnchorError::InvalidFormat("Expected SEQUENCE".into()));
    }

    let outer_kids = children_of(data, &outer);
    if outer_kids.is_empty() {
        return Err(AnchorError::InvalidFormat("Empty outer SEQUENCE".into()));
    }

    // First child SEQUENCE => TimeStampResp wrapper; otherwise bare ContentInfo
    let content_info_tlv = if outer_kids[0].tag == 0x30 && outer_kids.len() > 1 {
        &outer_kids[1]
    } else {
        &outer
    };

    // ContentInfo: SEQUENCE { OID, [0] EXPLICIT content }
    let explicit0 = find_child_by_tag(data, content_info_tlv, 0xA0).ok_or_else(|| {
        AnchorError::InvalidFormat("Cannot find [0] content in ContentInfo".into())
    })?;

    // SignedData SEQUENCE inside [0]
    let signed_data = children_of(data, &explicit0)
        .into_iter()
        .find(|c| c.tag == 0x30)
        .ok_or_else(|| AnchorError::InvalidFormat("Cannot find SignedData SEQUENCE".into()))?;

    // Walk SignedData children to find encapContentInfo -> [0] -> OCTET STRING
    for child in children_of(data, &signed_data) {
        if child.tag == 0x30 {
            if let Some(econtent_explicit) = find_child_by_tag(data, &child, 0xA0) {
                if let Some(octet) = find_child_by_tag(data, &econtent_explicit, 0x04) {
                    return Ok(octet.content(data).to_vec());
                }
                // Fallback: raw content bytes
                return Ok(econtent_explicit.content(data).to_vec());
            }
        }
    }

    Err(AnchorError::InvalidFormat(
        "Cannot find TSTInfo in CMS envelope".into(),
    ))
}

/// Extract `genTime` (tag 0x18) from TSTInfo.
fn extract_generalized_time(tst_info: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    let outer = read_tlv(tst_info, 0)?;
    let inner_start = if outer.tag == 0x30 {
        outer.content_start
    } else {
        0
    };
    let inner_end = if outer.tag == 0x30 {
        outer.content_end
    } else {
        tst_info.len()
    };

    for child in children(tst_info, inner_start, inner_end) {
        if child.tag == 0x18 {
            if let Ok(s) = std::str::from_utf8(child.content(tst_info)) {
                return parse_generalized_time(s);
            }
        }
    }
    None
}

/// Parse ASN.1 GeneralizedTime (`YYYYMMDDHHMMSS[.frac]Z`) to `DateTime<Utc>`.
fn parse_generalized_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDateTime, TimeZone};
    let s = s.trim_end_matches('Z');

    if let Some((base, _frac)) = s.split_once('.') {
        if base.len() == 14 {
            let naive = NaiveDateTime::parse_from_str(base, "%Y%m%d%H%M%S").ok()?;
            return Some(chrono::Utc.from_utc_datetime(&naive));
        }
    }

    if s.len() >= 14 {
        let naive = NaiveDateTime::parse_from_str(&s[..14], "%Y%m%d%H%M%S").ok()?;
        return Some(chrono::Utc.from_utc_datetime(&naive));
    }

    None
}

/// Extract `serialNumber` (4th field, INTEGER) from TSTInfo.
fn extract_serial_number(tst_info: &[u8]) -> Option<String> {
    let outer = read_tlv(tst_info, 0)?;
    let inner_start = if outer.tag == 0x30 {
        outer.content_start
    } else {
        0
    };
    let inner_end = if outer.tag == 0x30 {
        outer.content_end
    } else {
        tst_info.len()
    };

    let kids = children(tst_info, inner_start, inner_end);
    if kids.len() > 3 && kids[3].tag == 0x02 {
        return Some(hex::encode(kids[3].content(tst_info)));
    }
    None
}

/// Extract `nonce` (INTEGER) from TSTInfo.
///
/// TSTInfo fields: version, policy, messageImprint, serialNumber, genTime, [accuracy],
/// [ordering], [nonce]. The nonce is the first INTEGER (tag 0x02) after genTime (tag 0x18).
///
/// RFC 3161 permits nonces of 1-64 bytes. The returned `Vec<u8>` contains the canonical
/// value (leading zero padding from DER encoding is stripped).
fn extract_nonce(tst_info: &[u8]) -> Option<Vec<u8>> {
    let outer = read_tlv(tst_info, 0)?;
    let inner_start = if outer.tag == 0x30 {
        outer.content_start
    } else {
        0
    };
    let inner_end = if outer.tag == 0x30 {
        outer.content_end
    } else {
        tst_info.len()
    };

    let kids = children(tst_info, inner_start, inner_end);
    // Walk past genTime (0x18) and find the next INTEGER (0x02) which is the nonce
    let mut past_gentime = false;
    for child in &kids {
        if child.tag == 0x18 {
            past_gentime = true;
            continue;
        }
        if past_gentime && child.tag == 0x02 {
            let content = child.content(tst_info);
            // RFC 3161 nonces may be 1-64 bytes; reject obviously invalid lengths.
            if content.is_empty() || content.len() > 65 {
                return None;
            }
            // DER INTEGER may have a leading 0x00 sign byte; strip it.
            let canonical = if content.len() > 1 && content[0] == 0x00 {
                &content[1..]
            } else {
                content
            };
            if canonical.is_empty() || canonical.len() > 64 {
                return None;
            }
            return Some(canonical.to_vec());
        }
    }
    None
}

/// Extract `hashedMessage` from the MessageImprint (3rd child) of TSTInfo.
fn extract_message_imprint_hash(tst_info: &[u8]) -> Option<[u8; 32]> {
    let outer = read_tlv(tst_info, 0)?;
    let inner_start = if outer.tag == 0x30 {
        outer.content_start
    } else {
        0
    };
    let inner_end = if outer.tag == 0x30 {
        outer.content_end
    } else {
        tst_info.len()
    };

    let kids = children(tst_info, inner_start, inner_end);
    if kids.len() <= 2 || kids[2].tag != 0x30 {
        return None;
    }

    let imprint_kids = children_of(tst_info, &kids[2]);
    if imprint_kids.len() > 1 && imprint_kids[1].tag == 0x04 {
        let content = imprint_kids[1].content(tst_info);
        if content.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(content);
            return Some(hash);
        }
    }
    None
}

struct TimestampInfo {
    timestamp: chrono::DateTime<chrono::Utc>,
    serial_number: String,
    tsa_name: String,
}

/// # Security
///
/// CMS signature verification is **not yet implemented** (AUD-124). The
/// `verify_timestamp_token` method only checks that the embedded
/// `MessageImprint` hash matches the expected value; it does not verify
/// the TSA's digital signature. Results should be treated as
/// structural-only until full CMS/PKCS#7 verification is added.
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

impl Rfc3161Provider {
    /// Create a provider using well-known public TSA endpoints.
    pub fn with_defaults() -> Result<Self, AnchorError> {
        Self::new(DEFAULT_TSA_URLS.iter().map(|s| s.to_string()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_default_provider_init() {
        let provider = Rfc3161Provider::with_defaults().unwrap();
        assert!(!provider.tsa_urls.is_empty());
        assert!(provider.tsa_urls[0].contains("http"));
    }

    #[test]
    fn test_verify_token_too_short() {
        let provider = Rfc3161Provider::with_defaults().unwrap();
        let hash = [0u8; 32];
        let token = vec![0u8; 50];
        let result = provider.verify_timestamp_token(&token, &hash);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidFormat(msg)) => assert_eq!(msg, "Token too short"),
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_verify_token_invalid_asn1() {
        let provider = Rfc3161Provider::with_defaults().unwrap();
        let hash = [0u8; 32];
        let mut token = vec![0u8; 150];
        token[0] = 0xFF;
        let result = provider.verify_timestamp_token(&token, &hash);
        assert!(result.is_err());
        match result {
            Err(AnchorError::InvalidFormat(msg)) => assert_eq!(msg, "Invalid ASN.1 structure"),
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_verify_token_unparseable_tst_info_returns_err() {
        let provider = Rfc3161Provider::with_defaults().unwrap();
        let hash = [0u8; 32];
        let mut token = vec![0u8; 150];
        token[0] = 0x30;
        let result = provider.verify_timestamp_token(&token, &hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_der_length_parsing() {
        assert_eq!(read_der_length(&[0x05], 0), Some((5, 1)));
        assert_eq!(read_der_length(&[0x82, 0x01, 0x00], 0), Some((256, 3)));
        assert_eq!(read_der_length(&[0x81, 0x80], 0), Some((128, 2)));
    }

    #[test]
    fn test_der_length_overflow() {
        // 4-byte length 0xFF_FF_FF_FF overflows on 32-bit targets
        let data = [0x84, 0xFF, 0xFF, 0xFF, 0xFF];
        let result = read_der_length(&data, 0);
        if usize::BITS == 32 {
            assert_eq!(result, None, "should reject overflow on 32-bit");
        } else {
            // 64-bit: length parses but read_tlv rejects (exceeds buffer)
            assert!(result.is_some());
            let tlv = read_tlv(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF], 0);
            assert!(tlv.is_none(), "content_end exceeds data length");
        }
    }

    #[test]
    fn test_parse_generalized_time() {
        let dt = parse_generalized_time("20250101120000Z");
        assert!(dt.is_some());
        let dt = dt.unwrap();
        assert_eq!(dt.year(), 2025);

        let dt2 = parse_generalized_time("20250615153045.123Z");
        assert!(dt2.is_some());
    }
}
