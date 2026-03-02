// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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
    pub fn new(tsa_urls: Vec<String>) -> Result<Self, AnchorError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| AnchorError::Network(format!("HTTP client init failed: {e}")))?;
        Ok(Self { tsa_urls, client })
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

    /// Parse a TimeStampResp (RFC 3161 section 2.4.2) to extract the
    /// embedded timestamp, serial number, and TSA name from the TSTInfo.
    fn parse_timestamp_response(&self, response: &[u8]) -> Result<TimestampInfo, AnchorError> {
        if response.len() < 10 {
            return Err(AnchorError::InvalidFormat("Response too short".into()));
        }

        // Extract TSTInfo from the CMS envelope
        let tst_info = extract_tst_info(response)?;

        // Parse genTime from TSTInfo
        let gen_time = extract_generalized_time(&tst_info).unwrap_or_else(chrono::Utc::now);

        // Parse serialNumber from TSTInfo
        let serial = extract_serial_number(&tst_info)
            .unwrap_or_else(|| hex::encode(&response[..std::cmp::min(8, response.len())]));

        Ok(TimestampInfo {
            timestamp: gen_time,
            serial_number: serial,
            tsa_name: "RFC 3161 TSA".to_string(),
        })
    }

    /// Verify an RFC 3161 timestamp token by checking that the embedded
    /// MessageImprint hash matches the expected hash.
    fn verify_timestamp_token(&self, token: &[u8], hash: &[u8; 32]) -> Result<bool, AnchorError> {
        if token.len() < 100 {
            return Err(AnchorError::InvalidFormat("Token too short".into()));
        }
        if token[0] != 0x30 {
            return Err(AnchorError::InvalidFormat("Invalid ASN.1 structure".into()));
        }

        // Extract TSTInfo and verify the MessageImprint hash
        let tst_info = extract_tst_info(token)?;

        // Extract the hashedMessage from the MessageImprint in TSTInfo
        let imprint_hash = extract_message_imprint_hash(&tst_info).ok_or_else(|| {
            AnchorError::InvalidFormat("Cannot extract MessageImprint hash from TSTInfo".into())
        })?;
        if imprint_hash != *hash {
            return Err(AnchorError::HashMismatch);
        }

        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Minimal DER parsing helpers for RFC 3161 / CMS structures.
//
// Uses offset-based iteration to avoid lifetime issues with closures.
// ---------------------------------------------------------------------------

/// A parsed DER TLV element as byte-range offsets into the source buffer.
#[derive(Clone, Copy)]
struct Tlv {
    tag: u8,
    /// Start of the content (after tag+length header).
    content_start: usize,
    /// End of the content (exclusive).
    content_end: usize,
}

impl Tlv {
    fn content<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.content_start..self.content_end]
    }
}

/// Read a DER tag-length-value at `offset`.
fn read_tlv(data: &[u8], offset: usize) -> Option<Tlv> {
    if offset >= data.len() {
        return None;
    }
    let tag = data[offset];
    let (length, header_len) = read_der_length(data, offset + 1)?;
    let content_start = offset + 1 + header_len;
    let content_end = content_start + length;
    if content_end > data.len() {
        return None;
    }
    Some(Tlv {
        tag,
        content_start,
        content_end,
    })
}

/// Read a DER definite-length encoding starting at `offset`.
/// Returns (length_value, number_of_length_bytes).
fn read_der_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    if offset >= data.len() {
        return None;
    }
    let first = data[offset];
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x80 {
        None // indefinite length not supported
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || offset + 1 + num_bytes > data.len() {
            return None;
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | data[offset + 1 + i] as usize;
        }
        Some((length, 1 + num_bytes))
    }
}

/// Collect all child TLVs within a SEQUENCE/SET content region.
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

/// Shorthand: children of a content slice (offsets relative to `data`).
fn children_of(data: &[u8], tlv: &Tlv) -> Vec<Tlv> {
    children(data, tlv.content_start, tlv.content_end)
}

/// Find the first child with a given tag.
fn find_child_by_tag(data: &[u8], parent: &Tlv, tag: u8) -> Option<Tlv> {
    children_of(data, parent).into_iter().find(|c| c.tag == tag)
}

/// Extract TSTInfo bytes from a TimeStampResp or ContentInfo (CMS SignedData).
///
/// Navigates: TimeStampResp → TimeStampToken (ContentInfo) → SignedData →
/// EncapsulatedContentInfo → eContent (OCTET STRING) which contains TSTInfo.
fn extract_tst_info(data: &[u8]) -> Result<Vec<u8>, AnchorError> {
    // Outer SEQUENCE
    let outer = read_tlv(data, 0)
        .ok_or_else(|| AnchorError::InvalidFormat("Cannot parse outer SEQUENCE".into()))?;
    if outer.tag != 0x30 {
        return Err(AnchorError::InvalidFormat("Expected SEQUENCE".into()));
    }

    let outer_kids = children_of(data, &outer);
    if outer_kids.is_empty() {
        return Err(AnchorError::InvalidFormat("Empty outer SEQUENCE".into()));
    }

    // Determine if this is a TimeStampResp (first child is SEQUENCE = PKIStatusInfo)
    // or directly a ContentInfo (first child is OID).
    let content_info_tlv = if outer_kids[0].tag == 0x30 && outer_kids.len() > 1 {
        // TimeStampResp: [PKIStatusInfo, ContentInfo(SEQUENCE)]
        &outer_kids[1]
    } else {
        // ContentInfo directly
        &outer
    };

    // ContentInfo = SEQUENCE { OID, [0] EXPLICIT content }
    // Find [0] EXPLICIT (tag 0xA0)
    let explicit0 = find_child_by_tag(data, content_info_tlv, 0xA0).ok_or_else(|| {
        AnchorError::InvalidFormat("Cannot find [0] content in ContentInfo".into())
    })?;

    // Inside [0]: SignedData SEQUENCE
    let signed_data = children_of(data, &explicit0)
        .into_iter()
        .find(|c| c.tag == 0x30)
        .ok_or_else(|| AnchorError::InvalidFormat("Cannot find SignedData SEQUENCE".into()))?;

    // SignedData children: version, digestAlgorithms, encapContentInfo, [certs], [crls], signerInfos
    // encapContentInfo is a SEQUENCE; look for one containing [0] EXPLICIT with OCTET STRING
    for child in children_of(data, &signed_data) {
        if child.tag == 0x30 {
            // Check if this SEQUENCE contains a [0] EXPLICIT tag
            if let Some(econtent_explicit) = find_child_by_tag(data, &child, 0xA0) {
                // Inside [0]: OCTET STRING containing TSTInfo
                if let Some(octet) = find_child_by_tag(data, &econtent_explicit, 0x04) {
                    return Ok(octet.content(data).to_vec());
                }
                // Might be the raw bytes
                return Ok(econtent_explicit.content(data).to_vec());
            }
        }
    }

    Err(AnchorError::InvalidFormat(
        "Cannot find TSTInfo in CMS envelope".into(),
    ))
}

/// Extract the GeneralizedTime from TSTInfo.
///
/// TSTInfo fields: version, policy, messageImprint, serialNumber, genTime, ...
/// genTime is tagged 0x18 (GeneralizedTime).
fn extract_generalized_time(tst_info: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    // Parse TSTInfo as SEQUENCE
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

/// Parse ASN.1 GeneralizedTime string to chrono DateTime.
fn parse_generalized_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDateTime, TimeZone};
    let s = s.trim_end_matches('Z');

    // Try with fractional seconds
    if let Some((base, _frac)) = s.split_once('.') {
        if base.len() == 14 {
            let naive = NaiveDateTime::parse_from_str(base, "%Y%m%d%H%M%S").ok()?;
            return Some(chrono::Utc.from_utc_datetime(&naive));
        }
    }

    // Without fractional seconds: YYYYMMDDHHMMSS
    if s.len() >= 14 {
        let naive = NaiveDateTime::parse_from_str(&s[..14], "%Y%m%d%H%M%S").ok()?;
        return Some(chrono::Utc.from_utc_datetime(&naive));
    }

    None
}

/// Extract serialNumber (INTEGER) from TSTInfo.
///
/// serialNumber is the 4th field (index 3) in TSTInfo.
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
    // 4th child (index 3) should be serialNumber INTEGER
    if kids.len() > 3 && kids[3].tag == 0x02 {
        return Some(hex::encode(kids[3].content(tst_info)));
    }
    None
}

/// Extract the hashedMessage from MessageImprint inside TSTInfo.
///
/// messageImprint is the 3rd child (index 2) of TSTInfo.
/// MessageImprint = SEQUENCE { hashAlgorithm, hashedMessage OCTET STRING }
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
    // 3rd child (index 2) is messageImprint SEQUENCE
    if kids.len() <= 2 || kids[2].tag != 0x30 {
        return None;
    }

    let imprint_kids = children_of(tst_info, &kids[2]);
    // 2nd child (index 1) is hashedMessage OCTET STRING
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
        let provider = Rfc3161Provider::with_defaults().unwrap();
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
    fn test_verify_token_unparseable_tst_info_returns_err() {
        let provider = Rfc3161Provider::with_defaults().unwrap();
        let hash = [0u8; 32];
        let mut token = vec![0u8; 150];
        token[0] = 0x30; // ASN.1 SEQUENCE but invalid TSTInfo
        let result = provider.verify_timestamp_token(&token, &hash);
        // Must return Err when TSTInfo cannot be extracted, not Ok(true)
        assert!(result.is_err());
    }

    #[test]
    fn test_der_length_parsing() {
        // Short form
        assert_eq!(read_der_length(&[0x05], 0), Some((5, 1)));
        // Long form: 2 bytes
        assert_eq!(read_der_length(&[0x82, 0x01, 0x00], 0), Some((256, 3)));
        // Single byte long form
        assert_eq!(read_der_length(&[0x81, 0x80], 0), Some((128, 2)));
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
