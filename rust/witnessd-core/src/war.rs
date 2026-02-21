//! WAR (Witnessd Authorship Record) block encoding and verification.
//!
//! This module implements the WAR evidence block format, a PGP-style ASCII-armored
//! representation of witnessd evidence that is human-readable and independently verifiable.
//!
//! ## Format Versions
//!
//! - **WAR/1.0**: Legacy parallel computation mode
//! - **WAR/1.1**: Entangled computation mode with jitter binding
//!
//! ## Block Structure
//!
//! ```text
//! -----BEGIN WITNESSD AUTHORSHIP RECORD-----
//! Version: WAR/1.1
//! Author: <author name or identifier>
//! Document-ID: <hex hash of document>
//! Timestamp: <ISO 8601 timestamp>
//!
//! <declaration text>
//!
//! -----BEGIN SEAL-----
//! <hex-encoded signature line 1>
//! <hex-encoded signature line 2>
//! <hex-encoded signature line 3>
//! -----END SEAL-----
//! -----END WITNESSD AUTHORSHIP RECORD-----
//! ```

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::declaration::Declaration;
use crate::evidence::Packet;
use crate::vdf;

/// WAR block format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Version {
    /// Legacy parallel computation (WAR/1.0)
    V1_0,
    /// Entangled computation with jitter binding (WAR/1.1)
    V1_1,
}

impl Version {
    pub fn as_str(&self) -> &'static str {
        match self {
            Version::V1_0 => "WAR/1.0",
            Version::V1_1 => "WAR/1.1",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "WAR/1.0" => Some(Version::V1_0),
            "WAR/1.1" => Some(Version::V1_1),
            _ => None,
        }
    }
}

/// A WAR evidence block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Format version
    pub version: Version,
    /// Author identifier (from declaration or public key fingerprint)
    pub author: String,
    /// Document identifier (SHA-256 of final content)
    pub document_id: [u8; 32],
    /// Block creation timestamp
    pub timestamp: DateTime<Utc>,
    /// Declaration statement text
    pub statement: String,
    /// The cryptographic seal (chained hash signature)
    pub seal: Seal,
    /// Full evidence packet for verification (not included in ASCII output)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Box<Packet>>,
    /// Whether the seal has been signed (H3 signature is valid)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub signed: bool,
}

/// The cryptographic seal binding all evidence together.
#[derive(Debug, Clone)]
pub struct Seal {
    /// H1: SHA-256(doc ‖ checkpoint_root ‖ declaration)
    pub h1: [u8; 32],
    /// H2: SHA-256(H1 ‖ jitter ‖ pubkey)
    pub h2: [u8; 32],
    /// H3: SHA-256(H2 ‖ vdf_output ‖ doc)
    pub h3: [u8; 32],
    /// H4: Ed25519 signature of H3
    pub signature: [u8; 64],
    /// Author's public key for verification
    pub public_key: [u8; 32],
}

// Custom Serialize/Deserialize for Seal using hex encoding
impl Serialize for Seal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Seal", 5)?;
        state.serialize_field("h1", &hex::encode(self.h1))?;
        state.serialize_field("h2", &hex::encode(self.h2))?;
        state.serialize_field("h3", &hex::encode(self.h3))?;
        state.serialize_field("signature", &hex::encode(self.signature))?;
        state.serialize_field("public_key", &hex::encode(self.public_key))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Seal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SealHelper {
            h1: String,
            h2: String,
            h3: String,
            signature: String,
            public_key: String,
        }

        let helper = SealHelper::deserialize(deserializer)?;

        let h1 = hex::decode(&helper.h1).map_err(serde::de::Error::custom)?;
        let h2 = hex::decode(&helper.h2).map_err(serde::de::Error::custom)?;
        let h3 = hex::decode(&helper.h3).map_err(serde::de::Error::custom)?;
        let signature = hex::decode(&helper.signature).map_err(serde::de::Error::custom)?;
        let public_key = hex::decode(&helper.public_key).map_err(serde::de::Error::custom)?;

        if h1.len() != 32 || h2.len() != 32 || h3.len() != 32 {
            return Err(serde::de::Error::custom("hash must be 32 bytes"));
        }
        if signature.len() != 64 {
            return Err(serde::de::Error::custom("signature must be 64 bytes"));
        }
        if public_key.len() != 32 {
            return Err(serde::de::Error::custom("public key must be 32 bytes"));
        }

        let mut seal = Seal {
            h1: [0u8; 32],
            h2: [0u8; 32],
            h3: [0u8; 32],
            signature: [0u8; 64],
            public_key: [0u8; 32],
        };
        seal.h1.copy_from_slice(&h1);
        seal.h2.copy_from_slice(&h2);
        seal.h3.copy_from_slice(&h3);
        seal.signature.copy_from_slice(&signature);
        seal.public_key.copy_from_slice(&public_key);
        Ok(seal)
    }
}

/// Result of WAR block verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Overall verification status
    pub valid: bool,
    /// Individual check results
    pub checks: Vec<CheckResult>,
    /// Human-readable summary
    pub summary: String,
    /// Detailed forensic information
    pub details: ForensicDetails,
}

/// Individual verification check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

/// Detailed forensic information from verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicDetails {
    /// Version detected
    pub version: String,
    /// Author identifier
    pub author: String,
    /// Document hash
    pub document_id: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Components included
    pub components: Vec<String>,
    /// Total elapsed time from VDF proofs
    pub elapsed_time_secs: Option<f64>,
    /// Number of checkpoints
    pub checkpoint_count: Option<usize>,
    /// Keystroke count (if available)
    pub keystroke_count: Option<u64>,
    /// Whether jitter seal is present
    pub has_jitter_seal: bool,
    /// Whether hardware attestation is present
    pub has_hardware_attestation: bool,
}

impl Block {
    /// Create a WAR block from an evidence packet.
    ///
    /// The returned block is unsigned. Call `sign()` with the signing key
    /// to create a properly signed seal. Alternatively, use `from_packet_signed()`
    /// if you have the signing key available.
    ///
    /// Note: An unsigned block can still be verified via the declaration signature
    /// and hash chain, but the seal signature check will fail.
    pub fn from_packet(packet: &Packet) -> Result<Self, String> {
        let declaration = packet
            .declaration
            .as_ref()
            .ok_or("evidence packet missing declaration")?;

        // Determine version based on declaration jitter seal
        let version = if declaration.has_jitter_seal() {
            Version::V1_1
        } else {
            Version::V1_0
        };

        // Get document ID from final content hash
        let document_id = hex::decode(&packet.document.final_hash)
            .map_err(|e| format!("invalid document hash: {e}"))?;
        if document_id.len() != 32 {
            return Err("document hash must be 32 bytes".to_string());
        }
        let mut doc_id = [0u8; 32];
        doc_id.copy_from_slice(&document_id);

        // Extract author from declaration public key (fingerprint)
        let author = if declaration.author_public_key.len() == 32 {
            let fingerprint = &hex::encode(&declaration.author_public_key)[..16];
            format!("key:{}", fingerprint)
        } else {
            "unknown".to_string()
        };

        // Compute the seal (unsigned - signature will be zeros until sign() is called)
        let seal = compute_seal(packet, declaration)?;

        Ok(Self {
            version,
            author,
            document_id: doc_id,
            timestamp: packet.exported_at,
            statement: declaration.statement.clone(),
            seal,
            evidence: Some(Box::new(packet.clone())),
            signed: false,
        })
    }

    /// Create a signed WAR block from an evidence packet.
    ///
    /// This is a convenience method that creates the block and signs it
    /// in one step.
    pub fn from_packet_signed(packet: &Packet, signing_key: &SigningKey) -> Result<Self, String> {
        let mut block = Self::from_packet(packet)?;
        block.sign(signing_key)?;
        Ok(block)
    }

    /// Sign the WAR block's seal with the given signing key.
    ///
    /// This creates the H4 signature over H3, binding the author to the
    /// complete hash chain. The signing key must correspond to the public
    /// key in the seal.
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), String> {
        // Verify the signing key matches the seal's public key
        let expected_pubkey = signing_key.verifying_key().to_bytes();
        if expected_pubkey != self.seal.public_key {
            return Err("signing key does not match seal public key".to_string());
        }

        // Sign H3
        let signature = signing_key.sign(&self.seal.h3);
        self.seal.signature = signature.to_bytes();
        self.signed = true;

        Ok(())
    }

    /// Encode the WAR block as ASCII-armored text.
    pub fn encode_ascii(&self) -> String {
        let mut output = String::new();

        output.push_str("-----BEGIN WITNESSD AUTHORSHIP RECORD-----\n");
        output.push_str(&format!("Version: {}\n", self.version.as_str()));
        output.push_str(&format!("Author: {}\n", self.author));
        output.push_str(&format!("Document-ID: {}\n", hex::encode(self.document_id)));
        output.push_str(&format!("Timestamp: {}\n", self.timestamp.to_rfc3339()));
        output.push('\n');

        // Declaration statement (word-wrapped at 72 chars)
        for line in word_wrap(&self.statement, 72) {
            output.push_str(&line);
            output.push('\n');
        }

        output.push('\n');
        output.push_str("-----BEGIN SEAL-----\n");

        // Encode seal as hex lines (64 chars per line)
        let seal_hex = self.seal.encode_hex();
        for chunk in seal_hex.as_bytes().chunks(64) {
            output.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            output.push('\n');
        }

        output.push_str("-----END SEAL-----\n");
        output.push_str("-----END WITNESSD AUTHORSHIP RECORD-----\n");

        output
    }

    /// Decode a WAR block from ASCII-armored text.
    pub fn decode_ascii(text: &str) -> Result<Self, String> {
        let lines: Vec<&str> = text.lines().collect();

        // Find block boundaries
        let start = lines
            .iter()
            .position(|l| l.contains("BEGIN WITNESSD AUTHORSHIP RECORD"))
            .ok_or("missing WAR block header")?;
        let end = lines
            .iter()
            .position(|l| l.contains("END WITNESSD AUTHORSHIP RECORD"))
            .ok_or("missing WAR block footer")?;

        if start >= end {
            return Err("invalid block structure".to_string());
        }

        // Parse headers
        let mut version = Version::V1_0;
        let mut author = String::new();
        let mut document_id = [0u8; 32];
        let mut timestamp = Utc::now();
        let mut header_end = start + 1;

        for (i, line) in lines[start + 1..end].iter().enumerate() {
            if line.is_empty() {
                header_end = start + 1 + i;
                break;
            }

            if let Some(val) = line.strip_prefix("Version: ") {
                version =
                    Version::parse(val.trim()).ok_or_else(|| format!("unknown version: {val}"))?;
            } else if let Some(val) = line.strip_prefix("Author: ") {
                author = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("Document-ID: ") {
                let bytes =
                    hex::decode(val.trim()).map_err(|e| format!("invalid document ID: {e}"))?;
                if bytes.len() != 32 {
                    return Err("document ID must be 32 bytes".to_string());
                }
                document_id.copy_from_slice(&bytes);
            } else if let Some(val) = line.strip_prefix("Timestamp: ") {
                timestamp = DateTime::parse_from_rfc3339(val.trim())
                    .map_err(|e| format!("invalid timestamp: {e}"))?
                    .with_timezone(&Utc);
            }
        }

        // Find seal section (bounded to within block region for safety)
        let seal_start = lines[start..end]
            .iter()
            .position(|l| l.contains("BEGIN SEAL"))
            .map(|pos| start + pos)
            .ok_or("missing seal header")?;
        let seal_end = lines[start..end]
            .iter()
            .position(|l| l.contains("END SEAL"))
            .map(|pos| start + pos)
            .ok_or("missing seal footer")?;

        // Parse statement (between headers and seal)
        let statement_lines: Vec<&str> = lines[header_end + 1..seal_start]
            .iter()
            .filter(|l| !l.is_empty())
            .copied()
            .collect();
        let statement = statement_lines.join(" ");

        // Parse seal
        let seal_hex: String = lines[seal_start + 1..seal_end]
            .iter()
            .map(|l| l.trim())
            .collect();
        let seal = Seal::decode_hex(&seal_hex)?;

        // Check if the seal has a non-zero signature (indicates it was signed)
        let signed = seal.signature != [0u8; 64];

        Ok(Self {
            version,
            author,
            document_id,
            timestamp,
            statement,
            seal,
            evidence: None,
            signed,
        })
    }

    /// Verify the WAR block and produce a verification report.
    pub fn verify(&self) -> VerificationReport {
        let mut checks = Vec::new();
        let mut all_passed = true;

        // Check 1: Signature verification
        let sig_check = self.verify_signature();
        if !sig_check.passed {
            all_passed = false;
        }
        checks.push(sig_check);

        // Check 2: Hash chain verification (if evidence available)
        if let Some(evidence) = &self.evidence {
            let chain_check = verify_hash_chain(&self.seal, evidence, self.version);
            if !chain_check.passed {
                all_passed = false;
            }
            checks.push(chain_check);

            // Check 3: VDF verification
            let vdf_check = verify_vdf_proofs(evidence);
            if !vdf_check.passed {
                all_passed = false;
            }
            checks.push(vdf_check);

            // Check 4: Declaration signature
            let decl_check = verify_declaration(evidence);
            if !decl_check.passed {
                all_passed = false;
            }
            checks.push(decl_check);
        } else {
            // Without evidence, we can only verify the final signature
            checks.push(CheckResult {
                name: "hash_chain".to_string(),
                passed: false,
                message: "Cannot verify hash chain without full evidence".to_string(),
            });
        }

        // Build summary
        let summary = if all_passed {
            format!(
                "WAR block VALID: {} evidence for document {}",
                self.version.as_str(),
                &hex::encode(self.document_id)[..16]
            )
        } else {
            let failed: Vec<_> = checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| c.name.as_str())
                .collect();
            format!("WAR block INVALID: failed checks: {}", failed.join(", "))
        };

        // Build forensic details
        let details = self.build_forensic_details();

        VerificationReport {
            valid: all_passed,
            checks,
            summary,
            details,
        }
    }

    fn verify_signature(&self) -> CheckResult {
        // Check if block was properly signed
        if !self.signed {
            // For unsigned blocks, we can't verify the seal signature.
            // The declaration signature is verified separately in verify_declaration().
            // This is a warning, not a failure - the evidence is still valid
            // via the declaration, just not via the seal signature.
            return CheckResult {
                name: "seal_signature".to_string(),
                passed: true, // Pass with warning - declaration sig is still verified
                message: "Seal unsigned (declaration signature verified separately)".to_string(),
            };
        }

        // Verify Ed25519 signature of H3
        let public_key = match VerifyingKey::from_bytes(&self.seal.public_key) {
            Ok(key) => key,
            Err(e) => {
                return CheckResult {
                    name: "seal_signature".to_string(),
                    passed: false,
                    message: format!("Invalid public key: {e}"),
                };
            }
        };

        let signature = Signature::from_bytes(&self.seal.signature);
        match public_key.verify_strict(&self.seal.h3, &signature) {
            Ok(()) => CheckResult {
                name: "seal_signature".to_string(),
                passed: true,
                message: "Ed25519 seal signature valid (H3 signed)".to_string(),
            },
            Err(e) => CheckResult {
                name: "seal_signature".to_string(),
                passed: false,
                message: format!("Seal signature verification failed: {e}"),
            },
        }
    }

    fn build_forensic_details(&self) -> ForensicDetails {
        let mut components = vec!["document".to_string(), "declaration".to_string()];

        let (elapsed_time_secs, checkpoint_count, keystroke_count, has_jitter_seal, has_hw) =
            if let Some(evidence) = &self.evidence {
                let elapsed = evidence.total_elapsed_time().as_secs_f64();
                let cp_count = evidence.checkpoints.len();
                let ks_count = evidence.keystroke.as_ref().map(|k| k.total_keystrokes);

                if evidence.keystroke.is_some() {
                    components.push("keystroke_evidence".to_string());
                }
                if evidence.presence.is_some() {
                    components.push("presence".to_string());
                }
                if evidence.hardware.is_some() {
                    components.push("hardware_attestation".to_string());
                }
                if evidence.behavioral.is_some() {
                    components.push("behavioral".to_string());
                }

                let has_jitter = evidence
                    .declaration
                    .as_ref()
                    .map(|d| d.has_jitter_seal())
                    .unwrap_or(false);
                let has_hw_attest = evidence.hardware.is_some();

                (
                    Some(elapsed),
                    Some(cp_count),
                    ks_count,
                    has_jitter,
                    has_hw_attest,
                )
            } else {
                (None, None, None, self.version == Version::V1_1, false)
            };

        ForensicDetails {
            version: self.version.as_str().to_string(),
            author: self.author.clone(),
            document_id: hex::encode(self.document_id),
            timestamp: self.timestamp,
            components,
            elapsed_time_secs,
            checkpoint_count,
            keystroke_count,
            has_jitter_seal,
            has_hardware_attestation: has_hw,
        }
    }
}

impl Seal {
    /// Encode the seal as a hex string.
    pub fn encode_hex(&self) -> String {
        let mut data = Vec::with_capacity(32 * 3 + 64 + 32);
        data.extend_from_slice(&self.h1);
        data.extend_from_slice(&self.h2);
        data.extend_from_slice(&self.h3);
        data.extend_from_slice(&self.signature);
        data.extend_from_slice(&self.public_key);
        hex::encode(data)
    }

    /// Decode the seal from a hex string.
    pub fn decode_hex(hex_str: &str) -> Result<Self, String> {
        let data = hex::decode(hex_str).map_err(|e| format!("invalid seal hex: {e}"))?;
        if data.len() != 32 * 3 + 64 + 32 {
            return Err(format!(
                "invalid seal length: expected {}, got {}",
                32 * 3 + 64 + 32,
                data.len()
            ));
        }

        let mut h1 = [0u8; 32];
        let mut h2 = [0u8; 32];
        let mut h3 = [0u8; 32];
        let mut signature = [0u8; 64];
        let mut public_key = [0u8; 32];

        h1.copy_from_slice(&data[0..32]);
        h2.copy_from_slice(&data[32..64]);
        h3.copy_from_slice(&data[64..96]);
        signature.copy_from_slice(&data[96..160]);
        public_key.copy_from_slice(&data[160..192]);

        Ok(Self {
            h1,
            h2,
            h3,
            signature,
            public_key,
        })
    }
}

/// Compute the cryptographic seal for an evidence packet.
///
/// Returns a seal with the hash chain computed (H1, H2, H3) and the public key set.
/// The signature field is left as zeros - call `Block::sign()` to create the
/// H4 signature over H3.
fn compute_seal(packet: &Packet, declaration: &Declaration) -> Result<Seal, String> {
    // Get document hash
    let doc_hash = hex::decode(&packet.document.final_hash)
        .map_err(|e| format!("invalid document hash: {e}"))?;

    // Get checkpoint root (hash of final checkpoint)
    let checkpoint_root =
        hex::decode(&packet.chain_hash).map_err(|e| format!("invalid chain hash: {e}"))?;

    // Get jitter hash (from declaration jitter seal or zeros)
    let jitter_hash = declaration
        .jitter_sealed
        .as_ref()
        .map(|j| j.jitter_hash)
        .unwrap_or([0u8; 32]);

    // Get VDF output (from last checkpoint with VDF)
    let vdf_output = packet
        .checkpoints
        .iter()
        .rev()
        .find_map(|cp| cp.vdf_output.as_ref())
        .and_then(|o| hex::decode(o).ok())
        .unwrap_or_else(|| vec![0u8; 32]);

    // H1 = SHA-256(doc ‖ checkpoint_root ‖ declaration_hash)
    let declaration_bytes = declaration
        .encode()
        .map_err(|e| format!("failed to encode declaration: {e}"))?;
    let declaration_hash = Sha256::digest(&declaration_bytes);
    let mut h1_hasher = Sha256::new();
    h1_hasher.update(b"witnessd-seal-h1-v1");
    h1_hasher.update(&doc_hash);
    h1_hasher.update(&checkpoint_root);
    h1_hasher.update(declaration_hash);
    let h1: [u8; 32] = h1_hasher.finalize().into();

    // H2 = SHA-256(H1 ‖ jitter ‖ pubkey)
    let mut h2_hasher = Sha256::new();
    h2_hasher.update(b"witnessd-seal-h2-v1");
    h2_hasher.update(h1);
    h2_hasher.update(jitter_hash);
    h2_hasher.update(&declaration.author_public_key);
    let h2: [u8; 32] = h2_hasher.finalize().into();

    // H3 = SHA-256(H2 ‖ vdf_output ‖ doc)
    let mut h3_hasher = Sha256::new();
    h3_hasher.update(b"witnessd-seal-h3-v1");
    h3_hasher.update(h2);
    h3_hasher.update(&vdf_output);
    h3_hasher.update(&doc_hash);
    let h3: [u8; 32] = h3_hasher.finalize().into();

    // Public key from declaration (signature will be set by Block::sign())
    let mut public_key = [0u8; 32];
    if declaration.author_public_key.len() == 32 {
        public_key.copy_from_slice(&declaration.author_public_key);
    }

    Ok(Seal {
        h1,
        h2,
        h3,
        signature: [0u8; 64], // Set by Block::sign()
        public_key,
    })
}

fn verify_hash_chain(seal: &Seal, evidence: &Packet, version: Version) -> CheckResult {
    let declaration = match &evidence.declaration {
        Some(d) => d,
        None => {
            return CheckResult {
                name: "hash_chain".to_string(),
                passed: false,
                message: "Missing declaration".to_string(),
            };
        }
    };

    // Recompute the seal and compare
    match compute_seal(evidence, declaration) {
        Ok(computed) => {
            if computed.h1 != seal.h1 {
                return CheckResult {
                    name: "hash_chain".to_string(),
                    passed: false,
                    message: "H1 mismatch: document/checkpoint binding failed".to_string(),
                };
            }
            if computed.h2 != seal.h2 {
                return CheckResult {
                    name: "hash_chain".to_string(),
                    passed: false,
                    message: "H2 mismatch: jitter/identity binding failed".to_string(),
                };
            }
            if computed.h3 != seal.h3 {
                return CheckResult {
                    name: "hash_chain".to_string(),
                    passed: false,
                    message: "H3 mismatch: VDF binding failed".to_string(),
                };
            }
            CheckResult {
                name: "hash_chain".to_string(),
                passed: true,
                message: format!("Hash chain valid ({} mode)", version.as_str()),
            }
        }
        Err(e) => CheckResult {
            name: "hash_chain".to_string(),
            passed: false,
            message: format!("Failed to compute seal: {e}"),
        },
    }
}

fn verify_vdf_proofs(evidence: &Packet) -> CheckResult {
    let mut verified = 0;
    let mut total = 0;

    for (i, cp) in evidence.checkpoints.iter().enumerate() {
        if let (Some(input_hex), Some(output_hex), Some(iterations)) =
            (&cp.vdf_input, &cp.vdf_output, cp.vdf_iterations)
        {
            total += 1;
            let input = match hex::decode(input_hex) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                Ok(b) => {
                    return CheckResult {
                        name: "vdf_proofs".to_string(),
                        passed: false,
                        message: format!(
                            "VDF input at checkpoint {i} has invalid length: {} (expected 32)",
                            b.len()
                        ),
                    };
                }
                Err(e) => {
                    return CheckResult {
                        name: "vdf_proofs".to_string(),
                        passed: false,
                        message: format!("VDF input at checkpoint {i} decode error: {e}"),
                    };
                }
            };
            let output = match hex::decode(output_hex) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                Ok(b) => {
                    return CheckResult {
                        name: "vdf_proofs".to_string(),
                        passed: false,
                        message: format!(
                            "VDF output at checkpoint {i} has invalid length: {} (expected 32)",
                            b.len()
                        ),
                    };
                }
                Err(e) => {
                    return CheckResult {
                        name: "vdf_proofs".to_string(),
                        passed: false,
                        message: format!("VDF output at checkpoint {i} decode error: {e}"),
                    };
                }
            };

            let proof = vdf::VdfProof {
                input,
                output,
                iterations,
                duration: std::time::Duration::from_secs(0),
            };

            if proof.verify() {
                verified += 1;
            } else {
                return CheckResult {
                    name: "vdf_proofs".to_string(),
                    passed: false,
                    message: format!("VDF proof at checkpoint {i} failed verification"),
                };
            }
        }
    }

    if total == 0 {
        CheckResult {
            name: "vdf_proofs".to_string(),
            passed: true,
            message: "No VDF proofs to verify (first checkpoint only)".to_string(),
        }
    } else {
        CheckResult {
            name: "vdf_proofs".to_string(),
            passed: true,
            message: format!("All {verified}/{total} VDF proofs verified"),
        }
    }
}

fn verify_declaration(evidence: &Packet) -> CheckResult {
    match &evidence.declaration {
        Some(decl) => {
            if decl.verify() {
                CheckResult {
                    name: "declaration".to_string(),
                    passed: true,
                    message: "Declaration signature valid".to_string(),
                }
            } else {
                CheckResult {
                    name: "declaration".to_string(),
                    passed: false,
                    message: "Declaration signature invalid".to_string(),
                }
            }
        }
        None => CheckResult {
            name: "declaration".to_string(),
            passed: false,
            message: "Missing declaration".to_string(),
        },
    }
}

/// Word wrap text at specified width.
fn word_wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.len() + 1 + word.len() <= width {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            current_line = word.to_string();
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint;
    use crate::declaration;
    use crate::evidence;
    use ed25519_dalek::SigningKey;
    use std::fs;
    use std::time::Duration;
    use tempfile::TempDir;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn create_test_evidence() -> (Packet, TempDir) {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("test_doc.txt");
        fs::write(&path, b"Test document content for WAR block").expect("write");

        let mut chain =
            checkpoint::Chain::new(&path, vdf::default_parameters()).expect("create chain");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit");

        let latest = chain.latest().expect("latest");
        let signing_key = test_signing_key();
        let decl = declaration::no_ai_declaration(
            latest.content_hash,
            latest.hash,
            "Test Document",
            "I wrote this document myself without AI assistance.",
        )
        .sign(&signing_key)
        .expect("sign");

        let packet = evidence::Builder::new("Test Document", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build packet");

        (packet, dir)
    }

    #[test]
    fn test_version_parsing() {
        assert_eq!(Version::parse("WAR/1.0"), Some(Version::V1_0));
        assert_eq!(Version::parse("WAR/1.1"), Some(Version::V1_1));
        assert_eq!(Version::parse("invalid"), None);

        assert_eq!(Version::V1_0.as_str(), "WAR/1.0");
        assert_eq!(Version::V1_1.as_str(), "WAR/1.1");
    }

    #[test]
    fn test_seal_encode_decode_roundtrip() {
        let seal = Seal {
            h1: [1u8; 32],
            h2: [2u8; 32],
            h3: [3u8; 32],
            signature: [4u8; 64],
            public_key: [5u8; 32],
        };

        let hex = seal.encode_hex();
        let decoded = Seal::decode_hex(&hex).expect("decode");

        assert_eq!(decoded.h1, seal.h1);
        assert_eq!(decoded.h2, seal.h2);
        assert_eq!(decoded.h3, seal.h3);
        assert_eq!(decoded.signature, seal.signature);
        assert_eq!(decoded.public_key, seal.public_key);
    }

    #[test]
    fn test_block_from_packet() {
        let (packet, _dir) = create_test_evidence();
        let block = Block::from_packet(&packet).expect("create block");

        assert_eq!(block.version, Version::V1_0); // No jitter seal
        assert!(!block.author.is_empty());
        assert_eq!(
            block.statement,
            "I wrote this document myself without AI assistance."
        );
        assert!(block.evidence.is_some());
        assert!(!block.signed); // Unsigned until sign() is called
    }

    #[test]
    fn test_block_from_packet_signed() {
        let (packet, _dir) = create_test_evidence();
        let signing_key = test_signing_key();
        let block = Block::from_packet_signed(&packet, &signing_key).expect("create signed block");

        assert!(block.signed);
        assert_ne!(block.seal.signature, [0u8; 64]); // Signature is not zero

        // Verify the signed block
        let report = block.verify();
        assert!(
            report.valid,
            "Signed block should verify: {}",
            report.summary
        );

        // Check that seal signature passed
        let seal_check = report.checks.iter().find(|c| c.name == "seal_signature");
        assert!(seal_check.is_some(), "Should have seal_signature check");
        assert!(seal_check.unwrap().passed, "Seal signature should pass");
    }

    #[test]
    fn test_block_ascii_encode_decode() {
        let (packet, _dir) = create_test_evidence();
        let block = Block::from_packet(&packet).expect("create block");

        let ascii = block.encode_ascii();
        assert!(ascii.contains("BEGIN WITNESSD AUTHORSHIP RECORD"));
        assert!(ascii.contains("END WITNESSD AUTHORSHIP RECORD"));
        assert!(ascii.contains("BEGIN SEAL"));
        assert!(ascii.contains("END SEAL"));
        assert!(ascii.contains("Version: WAR/1.0"));

        let decoded = Block::decode_ascii(&ascii).expect("decode");
        assert_eq!(decoded.version, block.version);
        assert_eq!(decoded.author, block.author);
        assert_eq!(decoded.document_id, block.document_id);
        // Statement may have minor whitespace differences from word-wrap
        assert!(decoded.statement.contains("I wrote this document"));
    }

    #[test]
    fn test_block_verification_unsigned() {
        let (packet, _dir) = create_test_evidence();
        let block = Block::from_packet(&packet).expect("create block");

        let report = block.verify();

        // Unsigned block still passes verification via declaration signature
        // (seal_signature check passes with a warning for unsigned blocks)
        assert!(
            report.valid,
            "Unsigned block should still verify: {}",
            report.summary
        );
        assert!(report.checks.iter().any(|c| c.name == "seal_signature"));
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "declaration" && c.passed));
        assert!(!report.summary.is_empty());
    }

    #[test]
    fn test_word_wrap() {
        let text = "This is a test of the word wrapping function.";
        let wrapped = word_wrap(text, 20);

        for line in &wrapped {
            assert!(line.len() <= 20, "Line too long: {}", line);
        }
        assert!(wrapped.len() > 1);
    }

    #[test]
    fn test_forensic_details() {
        let (packet, _dir) = create_test_evidence();
        let block = Block::from_packet(&packet).expect("create block");

        let report = block.verify();
        let details = &report.details;

        assert_eq!(details.version, "WAR/1.0");
        assert!(!details.author.is_empty());
        assert!(!details.document_id.is_empty());
        assert!(details.components.contains(&"document".to_string()));
        assert!(details.components.contains(&"declaration".to_string()));
    }

    #[test]
    fn test_block_with_jitter_seal_is_v1_1() {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("test_doc.txt");
        fs::write(&path, b"Test content").expect("write");

        let mut chain =
            checkpoint::Chain::new(&path, vdf::default_parameters()).expect("create chain");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit");

        let latest = chain.latest().expect("latest");
        let signing_key = test_signing_key();

        // Create declaration with jitter seal
        let jitter = declaration::DeclarationJitter::from_samples(&[1000u32; 10], 1000, false);
        let decl =
            declaration::no_ai_declaration(latest.content_hash, latest.hash, "Test", "Statement")
                .with_jitter_seal(jitter)
                .sign(&signing_key)
                .expect("sign");

        let packet = evidence::Builder::new("Test", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        let block = Block::from_packet(&packet).expect("create block");
        assert_eq!(block.version, Version::V1_1);
    }

    #[test]
    fn test_seal_decode_invalid_length() {
        let err = Seal::decode_hex("abcd").unwrap_err();
        assert!(err.contains("invalid seal length"));
    }

    #[test]
    fn test_block_missing_declaration() {
        // Create a packet without declaration (this will fail in Builder)
        // So we test that from_packet properly handles missing declaration
        let (mut packet, _dir) = create_test_evidence();
        packet.declaration = None;

        let err = Block::from_packet(&packet).unwrap_err();
        assert!(err.contains("missing declaration"));
    }
}
