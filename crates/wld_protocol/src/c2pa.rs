// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! C2PA (Coalition for Content Provenance and Authenticity) manifest generation.
//!
//! Produces sidecar `.c2pa` manifests containing PoP evidence assertions
//! per C2PA 2.2 specification (2025-05-01). The manifest uses JUMBF
//! (ISO 19566-5) box format with COSE_Sign1 signatures.

use crate::crypto::PoPSigner;
use crate::error::{Error, Result};
use crate::rfc::EvidencePacket;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Custom PoP assertion embedded in C2PA manifests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoPAssertion {
    pub label: String,
    pub version: u32,
    pub evidence_id: String,
    /// SHA-256 digest of the original evidence packet bytes.
    pub evidence_hash: String,
    pub jitter_seals: Vec<JitterSeal>,
}

/// Per-checkpoint jitter seal entry within a PoP assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterSeal {
    pub sequence: u64,
    pub timestamp: u64,
    pub seal_hash: String,
}

impl PoPAssertion {
    /// Build a PoP assertion from an evidence packet and its raw CBOR bytes.
    pub fn from_evidence(packet: &EvidencePacket, original_bytes: &[u8]) -> Self {
        let hash = Sha256::digest(original_bytes);

        let jitter_seals = packet
            .checkpoints
            .iter()
            .map(|cp| JitterSeal {
                sequence: cp.sequence,
                timestamp: cp.timestamp,
                seal_hash: hex::encode(&cp.checkpoint_hash.digest),
            })
            .collect();

        Self {
            label: ASSERTION_LABEL_POP.to_string(),
            version: packet.version,
            evidence_id: hex::encode(&packet.packet_id),
            evidence_hash: hex::encode(hash),
            jitter_seals,
        }
    }
}

/// Standard C2PA actions assertion (§12.1, CBOR map).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionsAssertion {
    pub actions: Vec<Action>,
}

/// Single C2PA action entry (e.g., "c2pa.created").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(rename = "softwareAgent", skip_serializing_if = "Option::is_none")]
    pub software_agent: Option<SoftwareAgent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<ActionParameters>,
}

/// Software agent can be a string or a structured claim-generator-info map (§12.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SoftwareAgent {
    Simple(String),
    Info(ClaimGeneratorInfo),
}

/// Optional parameters for a C2PA action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// C2PA hash-data assertion binding manifest to the asset (§9.1, CBOR map).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashDataAssertion {
    pub name: String,
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    /// Algorithm identifier per §15.4.
    #[serde(rename = "alg")]
    pub algorithm: String,
    #[serde(default)]
    pub exclusions: Vec<ExclusionRange>,
}

/// Byte range exclusion for embedded manifests (§9.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionRange {
    pub start: u64,
    pub length: u64,
}

/// C2PA claim v2 per §10 and §15.6. All field names match the CDDL schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2paClaim {
    /// §10.5
    pub claim_generator: String,

    /// §10.5, required in v2.
    pub claim_generator_info: Vec<ClaimGeneratorInfo>,

    /// §10.3, required.
    #[serde(rename = "instanceID")]
    pub instance_id: String,

    /// §10.7, required.
    pub signature: String,

    /// §10.6
    pub created_assertions: Vec<HashedUri>,

    #[serde(rename = "dc:title", skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(rename = "dc:format", skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// §10.5
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimGeneratorInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Hashed URI reference per §8.4.2 and §15.10.3.
/// The hash is binary (CBOR bstr), computed over the JUMBF superbox
/// contents (description + content boxes, excluding the 8-byte superbox header)
/// per §8.4.2.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedUri {
    pub url: String,
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

/// Assertion JUMBF bytes are pre-built so the hashes in
/// `claim.created_assertions` match the actual bytes written
/// into JUMBF output (no double-serialization risk).
#[derive(Debug, Clone)]
pub struct C2paManifest {
    pub claim: C2paClaim,
    /// Must match assertion URL paths.
    pub manifest_label: String,
    pub assertion_boxes: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
}

/// C2PA manifest store superbox UUID (C2PA 2.2 §8.1).
const C2PA_MANIFEST_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x70, 0x61, // "c2pa"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

const C2PA_MANIFEST_UUID: [u8; 16] = [
    0x63, 0x32, 0x6D, 0x61, // "c2ma"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

const C2PA_CLAIM_UUID: [u8; 16] = [
    0x63, 0x32, 0x63, 0x6C, // "c2cl"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

const C2PA_ASSERTION_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x61, 0x73, // "c2as"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

const C2PA_SIGNATURE_UUID: [u8; 16] = [
    0x63, 0x32, 0x63, 0x73, // "c2cs"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// ISO 19566-5
const JUMBF_CBOR_UUID: [u8; 16] = [
    0x63, 0x62, 0x6F, 0x72, // "cbor"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// ISO 19566-5
const JUMBF_JSON_UUID: [u8; 16] = [
    0x6A, 0x73, 0x6F, 0x6E, // "json"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// JUMBF label for the PoP evidence assertion.
pub const ASSERTION_LABEL_POP: &str = "org.pop.evidence";
/// JUMBF label for the C2PA actions assertion.
pub const ASSERTION_LABEL_ACTIONS: &str = "c2pa.actions";
/// JUMBF label for the C2PA hard-binding hash assertion.
pub const ASSERTION_LABEL_HASH_DATA: &str = "c2pa.hash.data";

const CLAIM_GENERATOR: &str = concat!(
    "WritersLogic/",
    env!("CARGO_PKG_VERSION"),
    " wld_protocol/",
    env!("CARGO_PKG_VERSION")
);

/// IANA-registered COSE_Key label for unprotected headers.
const COSE_HEADER_LABEL_COSE_KEY: i64 = -1;

/// Minimal JUMBF box writer (ISO 19566-5).
struct JumbfWriter {
    buf: Vec<u8>,
}

impl JumbfWriter {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(4096),
        }
    }

    fn write_description(&mut self, uuid: &[u8; 16], label: Option<&str>, toggles: u8) {
        let label_bytes = label.map(|l| l.as_bytes());
        let label_len = label_bytes.map_or(0, |b| b.len() + 1); // NUL terminator
        let box_len = 8 + 16 + 1 + label_len;
        self.write_box_header(box_len as u32, b"jumd");
        self.buf.extend_from_slice(uuid);
        self.buf.push(toggles);
        if let Some(bytes) = label_bytes {
            self.buf.extend_from_slice(bytes);
            self.buf.push(0);
        }
    }

    fn write_content_cbor(&mut self, data: &[u8]) {
        let box_len = (8 + data.len()) as u32;
        self.write_box_header(box_len, b"cbor");
        self.buf.extend_from_slice(data);
    }

    fn write_content_json(&mut self, data: &[u8]) {
        let box_len = (8 + data.len()) as u32;
        self.write_box_header(box_len, b"json");
        self.buf.extend_from_slice(data);
    }

    fn write_raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Returns offset for back-patching length.
    fn begin_superbox(&mut self) -> usize {
        let offset = self.buf.len();
        self.write_box_header(0, b"jumb");
        offset
    }

    fn end_superbox(&mut self, offset: usize) {
        let total_len = (self.buf.len() - offset) as u32;
        self.buf[offset..offset + 4].copy_from_slice(&total_len.to_be_bytes());
    }

    fn write_box_header(&mut self, size: u32, box_type: &[u8; 4]) {
        self.buf.extend_from_slice(&size.to_be_bytes());
        self.buf.extend_from_slice(box_type);
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Builds a C2PA 2.2 sidecar manifest from PoP evidence.
pub struct C2paManifestBuilder {
    document_hash: [u8; 32],
    document_filename: Option<String>,
    evidence_bytes: Vec<u8>,
    evidence_packet: EvidencePacket,
    title: Option<String>,
    manifest_label: String,
}

impl C2paManifestBuilder {
    /// Create a builder from a decoded evidence packet, its raw bytes, and the document hash.
    pub fn new(
        evidence_packet: EvidencePacket,
        evidence_bytes: Vec<u8>,
        document_hash: [u8; 32],
    ) -> Self {
        let manifest_label = format!(
            "urn:writerslogic:{}",
            hex::encode(&evidence_packet.packet_id)
        );
        Self {
            document_hash,
            document_filename: None,
            evidence_bytes,
            evidence_packet,
            title: None,
            manifest_label,
        }
    }

    /// Set the document filename for the hard-binding assertion.
    pub fn document_filename(mut self, name: impl Into<String>) -> Self {
        self.document_filename = Some(name.into());
        self
    }

    /// Set the dc:title metadata field in the claim.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Build and encode the manifest as a complete JUMBF binary sidecar.
    pub fn build_jumbf(self, signer: &dyn PoPSigner) -> Result<Vec<u8>> {
        let manifest = self.build_manifest(signer)?;
        encode_jumbf(&manifest)
    }

    /// Build the manifest structure with assertions, claim, and COSE signature.
    pub fn build_manifest(self, signer: &dyn PoPSigner) -> Result<C2paManifest> {
        let pop_assertion =
            PoPAssertion::from_evidence(&self.evidence_packet, &self.evidence_bytes);

        let now = chrono::Utc::now().to_rfc3339();

        let actions_assertion = ActionsAssertion {
            actions: vec![Action {
                action: "c2pa.created".to_string(),
                when: Some(now),
                software_agent: Some(SoftwareAgent::Info(ClaimGeneratorInfo {
                    name: "WritersLogic".to_string(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                })),
                parameters: Some(ActionParameters {
                    description: Some(
                        "Document authored with WritersLogic Proof-of-Process witnessing"
                            .to_string(),
                    ),
                }),
            }],
        };

        let hash_data_assertion = HashDataAssertion {
            name: self
                .document_filename
                .clone()
                .unwrap_or_else(|| "document".to_string()),
            hash: self.document_hash.to_vec(),
            algorithm: "sha256".to_string(),
            exclusions: vec![],
        };

        // Built once; same bytes are hashed for the claim and embedded in JUMBF.
        let hash_data_box =
            build_assertion_jumbf_cbor(ASSERTION_LABEL_HASH_DATA, &hash_data_assertion)?;
        let actions_box = build_assertion_jumbf_cbor(ASSERTION_LABEL_ACTIONS, &actions_assertion)?;
        let pop_box = build_assertion_jumbf_json(ASSERTION_LABEL_POP, &pop_assertion)?;

        // §8.4.2.3: hash superbox contents, skipping 8-byte jumb header
        let hash_data_hash = Sha256::digest(&hash_data_box[8..]);
        let actions_hash = Sha256::digest(&actions_box[8..]);
        let pop_hash = Sha256::digest(&pop_box[8..]);

        let manifest_label = &self.manifest_label;

        let sig_url = format!("self#jumbf=/c2pa/{manifest_label}/c2pa.signature");

        let created_assertions = vec![
            HashedUri {
                url: format!(
                    "self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{ASSERTION_LABEL_HASH_DATA}"
                ),
                hash: hash_data_hash.to_vec(),
                alg: Some("sha256".to_string()),
            },
            HashedUri {
                url: format!(
                    "self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{ASSERTION_LABEL_ACTIONS}"
                ),
                hash: actions_hash.to_vec(),
                alg: Some("sha256".to_string()),
            },
            HashedUri {
                url: format!(
                    "self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{ASSERTION_LABEL_POP}"
                ),
                hash: pop_hash.to_vec(),
                alg: Some("sha256".to_string()),
            },
        ];

        let claim = C2paClaim {
            claim_generator: CLAIM_GENERATOR.to_string(),
            claim_generator_info: vec![
                ClaimGeneratorInfo {
                    name: "WritersLogic".to_string(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                },
                ClaimGeneratorInfo {
                    name: "wld_protocol".to_string(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                },
            ],
            instance_id: format!("xmp:iid:{}", hex::encode(&self.evidence_packet.packet_id)),
            signature: sig_url,
            created_assertions,
            title: self.title,
            format: None,
        };

        // §13.2: COSE_Sign1 with public key in unprotected header
        let claim_cbor = ciborium_to_vec(&claim)?;
        let signature = sign_c2pa_claim(&claim_cbor, signer)?;

        Ok(C2paManifest {
            claim,
            manifest_label: self.manifest_label.clone(),
            assertion_boxes: vec![hash_data_box, actions_box, pop_box],
            signature,
        })
    }
}

/// §13.2: COSE_Sign1 with public key in unprotected header.
fn sign_c2pa_claim(claim_cbor: &[u8], signer: &dyn PoPSigner) -> Result<Vec<u8>> {
    let protected = HeaderBuilder::new().algorithm(signer.algorithm()).build();

    let mut unprotected = coset::Header::default();
    unprotected.rest.push((
        coset::Label::Int(COSE_HEADER_LABEL_COSE_KEY),
        ciborium::Value::Bytes(signer.public_key()),
    ));

    let mut sign_error: Option<Error> = None;
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(claim_cbor.to_vec())
        .create_signature(&[], |sig_data| match signer.sign(sig_data) {
            Ok(sig) => sig,
            Err(e) => {
                sign_error = Some(e);
                Vec::new()
            }
        })
        .build();

    if let Some(e) = sign_error {
        return Err(e);
    }

    if sign1.signature.is_empty() {
        return Err(Error::Crypto(
            "COSE signing produced empty signature".to_string(),
        ));
    }

    sign1
        .to_vec()
        .map_err(|e| Error::Crypto(format!("COSE encoding error: {e}")))
}

fn build_assertion_jumbf_json<T: Serialize>(label: &str, value: &T) -> Result<Vec<u8>> {
    let content = serde_json::to_vec(value).map_err(|e| Error::Serialization(e.to_string()))?;
    build_assertion_jumbf(label, &JUMBF_JSON_UUID, &content, false)
}

fn build_assertion_jumbf_cbor<T: Serialize>(label: &str, value: &T) -> Result<Vec<u8>> {
    let content = ciborium_to_vec(value)?;
    build_assertion_jumbf(label, &JUMBF_CBOR_UUID, &content, true)
}

fn build_assertion_jumbf(
    label: &str,
    uuid: &[u8; 16],
    content: &[u8],
    is_cbor: bool,
) -> Result<Vec<u8>> {
    let mut w = JumbfWriter::new();
    let off = w.begin_superbox();
    w.write_description(uuid, Some(label), 0x03);
    if is_cbor {
        w.write_content_cbor(content);
    } else {
        w.write_content_json(content);
    }
    w.end_superbox(off);
    Ok(w.finish())
}

fn ciborium_to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| Error::Serialization(format!("CBOR encode: {e}")))?;
    Ok(buf)
}

/// Encode a C2PA manifest as JUMBF binary (`.c2pa` sidecar).
pub fn encode_jumbf(manifest: &C2paManifest) -> Result<Vec<u8>> {
    let mut w = JumbfWriter::new();

    let store_off = w.begin_superbox();
    w.write_description(&C2PA_MANIFEST_STORE_UUID, Some("c2pa"), 0x03);

    let manifest_off = w.begin_superbox();
    w.write_description(&C2PA_MANIFEST_UUID, Some(&manifest.manifest_label), 0x03);

    // §15.6
    let claim_off = w.begin_superbox();
    w.write_description(&C2PA_CLAIM_UUID, Some("c2pa.claim.v2"), 0x03);
    let claim_cbor = ciborium_to_vec(&manifest.claim)?;
    w.write_content_cbor(&claim_cbor);
    w.end_superbox(claim_off);

    let astore_off = w.begin_superbox();
    w.write_description(&C2PA_ASSERTION_STORE_UUID, Some("c2pa.assertions"), 0x03);
    for assertion_box in &manifest.assertion_boxes {
        w.write_raw(assertion_box);
    }
    w.end_superbox(astore_off);

    let sig_off = w.begin_superbox();
    w.write_description(&C2PA_SIGNATURE_UUID, Some("c2pa.signature"), 0x03);
    w.write_content_cbor(&manifest.signature);
    w.end_superbox(sig_off);

    w.end_superbox(manifest_off);
    w.end_superbox(store_off);

    Ok(w.finish())
}

/// Structural validation result for a C2PA manifest.
#[derive(Debug)]
pub struct ValidationResult {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// Return true if no validation errors were found.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// §15.10.1.2 standard manifest validation.
pub fn validate_manifest(manifest: &C2paManifest) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let hard_binding_count = manifest
        .claim
        .created_assertions
        .iter()
        .filter(|a| a.url.contains(ASSERTION_LABEL_HASH_DATA))
        .count();
    if hard_binding_count != 1 {
        errors.push(format!(
            "Standard manifest requires exactly 1 hard binding, found {hard_binding_count}"
        ));
    }

    let actions_count = manifest
        .claim
        .created_assertions
        .iter()
        .filter(|a| a.url.contains(ASSERTION_LABEL_ACTIONS))
        .count();
    if actions_count != 1 {
        errors.push(format!(
            "Standard manifest requires exactly 1 actions assertion, found {actions_count}"
        ));
    }

    for (i, assertion) in manifest.claim.created_assertions.iter().enumerate() {
        if !assertion.url.contains(&manifest.manifest_label) {
            errors.push(format!(
                "created_assertions[{i}].url does not contain manifest label '{}'",
                manifest.manifest_label
            ));
        }
    }

    if !manifest.claim.signature.contains(&manifest.manifest_label) {
        errors.push(format!(
            "signature URI does not contain manifest label '{}'",
            manifest.manifest_label
        ));
    }

    if manifest.claim.claim_generator_info.is_empty() {
        errors.push("claim_generator_info must have at least one entry".to_string());
    } else if manifest.claim.claim_generator_info[0].name.is_empty() {
        errors.push("claim_generator_info[0].name must not be empty".to_string());
    }

    if manifest.claim.instance_id.is_empty() {
        errors.push("instanceID must not be empty".to_string());
    }

    if manifest.claim.signature.is_empty() {
        errors.push("signature URI must not be empty".to_string());
    }

    for (i, assertion) in manifest.claim.created_assertions.iter().enumerate() {
        if assertion.hash.len() != 32 {
            errors.push(format!(
                "created_assertions[{i}] hash length {} != 32",
                assertion.hash.len()
            ));
        }
        if assertion.url.is_empty() {
            errors.push(format!("created_assertions[{i}] has empty URL"));
        }
    }

    if manifest.assertion_boxes.len() != manifest.claim.created_assertions.len() {
        errors.push(format!(
            "assertion_boxes count ({}) != created_assertions count ({})",
            manifest.assertion_boxes.len(),
            manifest.claim.created_assertions.len()
        ));
    }

    for (i, (assertion_ref, box_bytes)) in manifest
        .claim
        .created_assertions
        .iter()
        .zip(manifest.assertion_boxes.iter())
        .enumerate()
    {
        if box_bytes.len() < 8 {
            errors.push(format!("assertion_boxes[{i}] too short"));
            continue;
        }
        let computed_hash = Sha256::digest(&box_bytes[8..]);
        if assertion_ref.hash != computed_hash.as_slice() {
            errors.push(format!(
                "created_assertions[{i}] hash mismatch: claim has {}, box hashes to {}",
                hex::encode(&assertion_ref.hash),
                hex::encode(computed_hash)
            ));
        }
    }

    if manifest.signature.is_empty() {
        errors.push("COSE_Sign1 signature is empty".to_string());
    }

    if manifest.manifest_label.is_empty() {
        warnings.push("manifest_label is empty".to_string());
    }

    ValidationResult { errors, warnings }
}

/// Verify structural integrity of a C2PA JUMBF sidecar.
pub fn verify_jumbf_structure(data: &[u8]) -> Result<JumbfInfo> {
    if data.len() < 8 {
        return Err(Error::Validation("JUMBF data too short".to_string()));
    }

    let box_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if box_len > data.len() {
        return Err(Error::Validation(
            "JUMBF box length exceeds data".to_string(),
        ));
    }

    let box_type = &data[4..8];
    if box_type != b"jumb" {
        return Err(Error::Validation(format!(
            "Expected JUMBF superbox, got {:?}",
            String::from_utf8_lossy(box_type)
        )));
    }

    let mut offset = 8;
    let mut found_jumd = false;
    let mut child_count = 0u32;

    while offset + 8 <= box_len {
        let child_len = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        if child_len < 8 || offset + child_len > box_len {
            return Err(Error::Validation(format!(
                "Invalid child box length {child_len} at offset {offset}"
            )));
        }
        let child_type = &data[offset + 4..offset + 8];
        if child_type == b"jumd" {
            found_jumd = true;
        }
        child_count += 1;
        offset += child_len;
    }

    if !found_jumd {
        return Err(Error::Validation(
            "Manifest store missing description box".to_string(),
        ));
    }

    Ok(JumbfInfo {
        total_size: box_len,
        child_boxes: child_count,
    })
}

/// Info from JUMBF structural validation.
#[derive(Debug)]
pub struct JumbfInfo {
    pub total_size: usize,
    pub child_boxes: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc::{Checkpoint, DocumentRef, HashAlgorithm, HashValue};
    use ed25519_dalek::SigningKey;

    fn test_evidence_packet() -> EvidencePacket {
        EvidencePacket {
            version: 1,
            profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
            packet_id: vec![0xAA; 16],
            created: 1710000000000,
            document: DocumentRef {
                content_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: vec![0xAB; 32],
                },
                filename: Some("test.txt".to_string()),
                byte_length: 1024,
                char_count: 512,
            },
            checkpoints: vec![
                make_checkpoint(0, 1710000001000),
                make_checkpoint(1, 1710000002000),
                make_checkpoint(2, 1710000003000),
            ],
            attestation_tier: None,
            baseline_verification: None,
        }
    }

    fn make_checkpoint(seq: u64, ts: u64) -> Checkpoint {
        Checkpoint {
            sequence: seq,
            checkpoint_id: vec![0u8; 16],
            timestamp: ts,
            content_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: vec![seq as u8; 32],
            },
            char_count: 100 + seq * 50,
            prev_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: vec![0u8; 32],
            },
            checkpoint_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: vec![seq as u8 + 0x10; 32],
            },
            jitter_hash: None,
        }
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    fn build_test_manifest() -> C2paManifest {
        let packet = test_evidence_packet();
        let evidence_bytes = b"fake evidence cbor".to_vec();
        let doc_hash = [0xABu8; 32];
        let key = test_signing_key();

        C2paManifestBuilder::new(packet, evidence_bytes, doc_hash)
            .document_filename("test.txt")
            .title("Test Document")
            .build_manifest(&key)
            .unwrap()
    }

    #[test]
    fn pop_assertion_from_evidence() {
        let packet = test_evidence_packet();
        let evidence_bytes = b"fake evidence cbor";
        let assertion = PoPAssertion::from_evidence(&packet, evidence_bytes);

        assert_eq!(assertion.label, ASSERTION_LABEL_POP);
        assert_eq!(assertion.version, 1);
        assert_eq!(assertion.jitter_seals.len(), 3);
        assert!(!assertion.evidence_hash.is_empty());
    }

    #[test]
    fn claim_v2_required_fields() {
        let manifest = build_test_manifest();

        assert!(
            !manifest.claim.instance_id.is_empty(),
            "instanceID required"
        );
        assert!(
            manifest.claim.instance_id.starts_with("xmp:iid:"),
            "instanceID should use XMP format"
        );
        assert!(
            !manifest.claim.signature.is_empty(),
            "signature URI required"
        );
        assert!(
            manifest.claim.signature.contains("c2pa.signature"),
            "signature should reference signature box"
        );
        assert!(
            !manifest.claim.claim_generator_info.is_empty(),
            "claim_generator_info required"
        );
        assert!(
            !manifest.claim.claim_generator_info[0].name.is_empty(),
            "first entry must have name"
        );
        assert_eq!(manifest.claim.created_assertions.len(), 3);
    }

    #[test]
    fn manifest_label_consistent_in_urls() {
        let manifest = build_test_manifest();

        for assertion in &manifest.claim.created_assertions {
            assert!(
                assertion.url.contains(&manifest.manifest_label),
                "Assertion URL '{}' must contain manifest label '{}'",
                assertion.url,
                manifest.manifest_label
            );
        }

        assert!(
            manifest.claim.signature.contains(&manifest.manifest_label),
            "Signature URL must contain manifest label"
        );
    }

    #[test]
    fn assertion_hashes_match_stored_boxes() {
        let manifest = build_test_manifest();

        assert_eq!(
            manifest.assertion_boxes.len(),
            manifest.claim.created_assertions.len()
        );

        for (assertion_ref, box_bytes) in manifest
            .claim
            .created_assertions
            .iter()
            .zip(manifest.assertion_boxes.iter())
        {
            let computed = Sha256::digest(&box_bytes[8..]);
            assert_eq!(
                assertion_ref.hash,
                computed.to_vec(),
                "Stored box hash must match claim reference"
            );
        }
    }

    #[test]
    fn hashed_uri_uses_binary_hash() {
        let manifest = build_test_manifest();
        for assertion_ref in &manifest.claim.created_assertions {
            assert_eq!(assertion_ref.hash.len(), 32, "SHA-256 = 32 raw bytes");
        }
    }

    #[test]
    fn signature_contains_public_key() {
        let manifest = build_test_manifest();

        let sign1 = coset::CoseSign1::from_slice(&manifest.signature).expect("valid COSE_Sign1");
        let pk_entry = sign1
            .unprotected
            .rest
            .iter()
            .find(|(label, _)| *label == coset::Label::Int(COSE_HEADER_LABEL_COSE_KEY));
        assert!(
            pk_entry.is_some(),
            "Public key must be in unprotected header"
        );

        if let Some((_, ciborium::Value::Bytes(pk_bytes))) = pk_entry {
            let key = test_signing_key();
            assert_eq!(
                pk_bytes,
                &key.verifying_key().to_bytes().to_vec(),
                "Embedded key must match signer"
            );
        } else {
            panic!("Public key header value must be bytes");
        }
    }

    #[test]
    fn standard_manifest_validation_passes() {
        let manifest = build_test_manifest();
        let result = validate_manifest(&manifest);
        assert!(
            result.is_valid(),
            "Valid manifest should pass: {:?}",
            result.errors
        );
    }

    #[test]
    fn validation_catches_label_mismatch() {
        let mut manifest = build_test_manifest();
        manifest.manifest_label = "urn:wrong:label".to_string();
        let result = validate_manifest(&manifest);
        assert!(!result.is_valid());
        assert!(
            result.errors.iter().any(|e| e.contains("manifest label")),
            "Should catch label mismatch: {:?}",
            result.errors
        );
    }

    #[test]
    fn validation_catches_hash_mismatch() {
        let mut manifest = build_test_manifest();
        if let Some(first_box) = manifest.assertion_boxes.first_mut() {
            if first_box.len() > 10 {
                first_box[10] ^= 0xFF;
            }
        }
        let result = validate_manifest(&manifest);
        assert!(!result.is_valid());
        assert!(
            result.errors.iter().any(|e| e.contains("hash mismatch")),
            "Should catch hash mismatch: {:?}",
            result.errors
        );
    }

    #[test]
    fn validation_catches_missing_hard_binding() {
        let mut manifest = build_test_manifest();
        manifest
            .claim
            .created_assertions
            .retain(|a| !a.url.contains(ASSERTION_LABEL_HASH_DATA));
        manifest.assertion_boxes.remove(0); // hash.data is first
        let result = validate_manifest(&manifest);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.contains("hard binding")));
    }

    #[test]
    fn validation_catches_missing_actions() {
        let mut manifest = build_test_manifest();
        manifest
            .claim
            .created_assertions
            .retain(|a| !a.url.contains(ASSERTION_LABEL_ACTIONS));
        manifest.assertion_boxes.remove(1); // actions is second
        let result = validate_manifest(&manifest);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.contains("actions")));
    }

    #[test]
    fn encode_jumbf_roundtrip() {
        let manifest = build_test_manifest();
        let jumbf = encode_jumbf(&manifest).unwrap();

        assert!(jumbf.len() > 100);
        let info = verify_jumbf_structure(&jumbf).unwrap();
        assert!(info.child_boxes >= 2);
        assert_eq!(&jumbf[4..8], b"jumb");

        let box_len = u32::from_be_bytes([jumbf[0], jumbf[1], jumbf[2], jumbf[3]]) as usize;
        assert_eq!(box_len, jumbf.len());
    }

    #[test]
    fn jumbf_contains_manifest_label() {
        let manifest = build_test_manifest();
        let jumbf = encode_jumbf(&manifest).unwrap();
        let jumbf_str = String::from_utf8_lossy(&jumbf);

        assert!(
            jumbf_str.contains(&manifest.manifest_label),
            "JUMBF must contain the manifest label as the box label"
        );
        assert!(
            jumbf_str.contains("c2pa.claim.v2"),
            "JUMBF must contain c2pa.claim.v2 label"
        );
    }

    #[test]
    fn jumbf_contains_cbor_content() {
        let manifest = build_test_manifest();
        let jumbf = encode_jumbf(&manifest).unwrap();
        let has_cbor_box = jumbf.windows(4).any(|w| w == b"cbor");
        assert!(has_cbor_box, "JUMBF should contain cbor content boxes");
    }

    #[test]
    fn jumbf_structure_validation_errors() {
        assert!(verify_jumbf_structure(&[]).is_err());
        assert!(verify_jumbf_structure(&[0; 4]).is_err());

        let mut bad = vec![0, 0, 0, 16];
        bad.extend_from_slice(b"xxxx");
        bad.extend_from_slice(&[0; 8]);
        assert!(verify_jumbf_structure(&bad).is_err());
    }

    #[test]
    fn unique_packet_id_produces_unique_manifest() {
        let mut p1 = test_evidence_packet();
        let mut p2 = test_evidence_packet();
        p1.packet_id = vec![0x01; 16];
        p2.packet_id = vec![0x02; 16];
        let key = test_signing_key();

        let m1 = C2paManifestBuilder::new(p1, b"ev1".to_vec(), [0xAA; 32])
            .build_manifest(&key)
            .unwrap();
        let m2 = C2paManifestBuilder::new(p2, b"ev2".to_vec(), [0xBB; 32])
            .build_manifest(&key)
            .unwrap();

        assert_ne!(m1.manifest_label, m2.manifest_label);
        assert_ne!(m1.claim.instance_id, m2.claim.instance_id);
    }

    #[test]
    fn full_pipeline_build_validate_encode() {
        let packet = test_evidence_packet();
        let evidence_bytes = b"fake evidence cbor".to_vec();
        let doc_hash = [0xABu8; 32];
        let key = test_signing_key();

        let builder = C2paManifestBuilder::new(packet, evidence_bytes, doc_hash)
            .document_filename("test.txt")
            .title("Test Document");

        let manifest = builder.build_manifest(&key).unwrap();

        let validation = validate_manifest(&manifest);
        assert!(validation.is_valid(), "Errors: {:?}", validation.errors);

        let jumbf = encode_jumbf(&manifest).unwrap();
        assert!(jumbf.len() > 200);

        let info = verify_jumbf_structure(&jumbf).unwrap();
        assert_eq!(info.total_size, jumbf.len());
    }
}
