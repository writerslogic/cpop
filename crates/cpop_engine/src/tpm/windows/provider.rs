// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::DateTimeNanosExt;
use crate::MutexRecover;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::sync::Mutex;

use super::super::{Attestation, Binding, Capabilities, PcrValue, Provider, Quote, TpmError};
use super::commands::build_pcr_read_command;
use super::context::TbsContext;
use super::helpers::{
    build_auth_area_with_password, build_empty_auth_area, build_sealing_public,
    build_srk_public_ecc, create_srk_public_key,
};
use super::types::*;

/// Windows TPM 2.0 provider via TBS (TPM Base Services).
pub struct WindowsTpmProvider {
    context: Mutex<TbsContext>,
    public_key: Vec<u8>,
    state: Mutex<WindowsTpmState>,
}

struct WindowsTpmState {
    counter: u64,
}

/// Initialize the Windows TPM provider, returning `None` if no TPM 2.0 is present.
pub fn try_init() -> Option<WindowsTpmProvider> {
    match TbsContext::new() {
        Ok(context) => match context.get_device_info() {
            Ok(info) if info.is_tpm20() => {
                log::info!(
                    "Windows TPM 2.0 detected (version: {}, revision: {})",
                    info.tpm_version,
                    info.tpm_impl_revision
                );

                let public_key = match create_srk_public_key(&context) {
                    Ok(key) => key,
                    Err(e) => {
                        log::error!(
                            "Failed to derive SRK public key: {}. TPM provider unavailable.",
                            e
                        );
                        return None;
                    }
                };

                Some(WindowsTpmProvider {
                    context: Mutex::new(context),
                    public_key,
                    state: Mutex::new(WindowsTpmState { counter: 0 }),
                })
            }
            Ok(info) => {
                log::warn!(
                    "TPM found but not version 2.0 (version: {}), using software fallback",
                    info.tpm_version
                );
                None
            }
            Err(e) => {
                log::warn!(
                    "Failed to get TPM device info: {}, using software fallback",
                    e
                );
                None
            }
        },
        Err(e) => {
            log::debug!("Windows TPM not available: {}", e);
            None
        }
    }
}

impl WindowsTpmProvider {
    fn read_pcrs(&self, ctx: &TbsContext, pcrs: &[u32]) -> Result<Vec<PcrValue>, TpmError> {
        if pcrs.is_empty() {
            return Ok(Vec::new());
        }

        let cmd = build_pcr_read_command(pcrs);
        let response = ctx
            .submit_command(&cmd)
            .map_err(|e| TpmError::Quote(e.to_string()))?;

        self.parse_pcr_read_response(&response, pcrs)
    }

    /// Parse TPM2_PCR_Read response layout:
    /// header(10) + pcrUpdateCounter(4) + TPML_PCR_SELECTION + TPML_DIGEST
    fn parse_pcr_read_response(
        &self,
        response: &[u8],
        pcrs: &[u32],
    ) -> Result<Vec<PcrValue>, TpmError> {
        if response.len() < 14 {
            return Err(TpmError::Quote("PCR read response too short".to_string()));
        }

        let mut offset = TPM2_RESPONSE_HEADER_SIZE + 4; // skip pcrUpdateCounter

        let selection_count = super::helpers::read_u32_be(&response, offset)
            .map_err(|_| TpmError::Quote("PCR read response missing selection count".into()))?;
        offset += 4;

        for _ in 0..selection_count {
            if offset + 3 > response.len() {
                return Err(TpmError::Quote(
                    "PCR read response truncated in selection".to_string(),
                ));
            }
            offset += 2;
            let size_of_select = response[offset] as usize;
            offset += 1;
            if offset
                .checked_add(size_of_select)
                .is_none_or(|end| end > response.len())
            {
                return Err(TpmError::Quote(
                    "PCR read response: sizeOfSelect exceeds buffer".to_string(),
                ));
            }
            offset += size_of_select;
        }

        let digest_count = super::helpers::read_u32_be(&response, offset)
            .map_err(|_| TpmError::Quote("PCR read response missing digest count".into()))?;
        offset += 4;

        let mut values = Vec::new();
        for (_i, &pcr) in pcrs.iter().take(digest_count as usize).enumerate() {
            if offset + 2 > response.len() {
                return Err(TpmError::Quote(
                    "PCR read response truncated in digest header".to_string(),
                ));
            }
            let digest_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
            offset += 2;

            if offset
                .checked_add(digest_size)
                .is_none_or(|end| end > response.len())
            {
                return Err(TpmError::Quote(
                    "PCR read response truncated in digest value".to_string(),
                ));
            }
            let value = response[offset..offset + digest_size].to_vec();
            offset += digest_size;

            values.push(PcrValue { index: pcr, value });
        }

        Ok(values)
    }

    /// Real TPM2_Sign using an ECC P-256 key created under the SRK.
    ///
    /// Creates a transient signing key via TPM2_Create + TPM2_Load, signs with
    /// TPM2_Sign (ECDSA-P256-SHA256), then flushes the key handle.
    fn sign_payload(&self, ctx: &TbsContext, data: &[u8]) -> Result<Vec<u8>, TpmError> {
        // 1. Create the SRK (parent for our signing key)
        let srk_response = self
            .create_primary_srk(ctx)
            .map_err(|e| TpmError::Signing(format!("SRK creation: {e}")))?;
        if srk_response.len() < 14 {
            return Err(TpmError::Signing("SRK response too short".into()));
        }
        let srk_handle = super::helpers::read_u32_be(&srk_response, 10)
            .map_err(|e| TpmError::Signing(format!("SRK handle parse: {e}")))?;

        // 2. Create a signing key under the SRK
        let signing_key_blob = self
            .create_signing_key(ctx, srk_handle)
            .map_err(|e| TpmError::Signing(format!("signing key create: {e}")))?;

        // 3. Load the signing key
        let key_handle = self
            .load_key(ctx, srk_handle, &signing_key_blob)
            .map_err(|e| TpmError::Signing(format!("signing key load: {e}")))?;

        // 4. Hash the data (TPM2_Sign expects a digest)
        let digest: [u8; 32] = Sha256::digest(data).into();

        // 5. TPM2_Sign
        let sign_result = self.tpm2_sign(ctx, key_handle, &digest);

        // 6. Cleanup: flush both handles regardless of sign result
        let _ = self.flush_context(ctx, key_handle);
        let _ = self.flush_context(ctx, srk_handle);

        sign_result
    }

    /// Create an ECC P-256 signing key under the given parent handle.
    fn create_signing_key(
        &self,
        ctx: &TbsContext,
        parent_handle: u32,
    ) -> Result<Vec<u8>, TpmError> {
        let mut body = Vec::new();
        body.extend_from_slice(&parent_handle.to_be_bytes());

        let auth_area = build_empty_auth_area(parent_handle);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        // inSensitive: empty userAuth + empty data
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());

        let public_area = super::helpers::build_signing_key_public_ecc();
        body.extend_from_slice(&(public_area.len() as u16).to_be_bytes());
        body.extend_from_slice(&public_area);

        body.extend_from_slice(&0u16.to_be_bytes()); // outsideInfo
        body.extend_from_slice(&0u32.to_be_bytes()); // creationPCR

        let mut cmd = Vec::with_capacity(10 + body.len());
        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_CREATE.to_be_bytes());
        cmd.extend_from_slice(&body);

        let response = ctx
            .submit_command(&cmd)
            .map_err(|e| TpmError::Signing(format!("TPM2_Create: {e}")))?;

        // Parse into blob: [pub_len][pub][priv_len][priv]
        self.parse_create_response(&response)
            .map_err(|e| TpmError::Signing(format!("parse signing key: {e}")))
    }

    /// Load a key blob under the given parent, returning the loaded handle.
    fn load_key(&self, ctx: &TbsContext, parent_handle: u32, blob: &[u8]) -> Result<u32, TpmError> {
        // blob format: [pub_len:4][pub][priv_len:4][priv]
        let pub_len = super::helpers::read_u32_be(blob, 0)
            .map_err(|e| TpmError::Signing(format!("load key blob parse: {e}")))?
            as usize;
        if 4 + pub_len > blob.len() {
            return Err(TpmError::Signing(
                "load key blob: pub_len exceeds blob size".into(),
            ));
        }
        let pub_bytes = &blob[4..4 + pub_len];
        let priv_offset = 4 + pub_len;
        let priv_len = super::helpers::read_u32_be(blob, priv_offset)
            .map_err(|e| TpmError::Signing(format!("load key blob parse: {e}")))?
            as usize;
        if priv_offset + 4 + priv_len > blob.len() {
            return Err(TpmError::Signing(
                "load key blob: priv_len exceeds blob size".into(),
            ));
        }
        let priv_bytes = &blob[priv_offset + 4..priv_offset + 4 + priv_len];

        let mut body = Vec::new();
        body.extend_from_slice(&parent_handle.to_be_bytes());

        let auth_area = build_empty_auth_area(parent_handle);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        // inPrivate: TPM2B_PRIVATE
        body.extend_from_slice(&(priv_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(priv_bytes);

        // inPublic: TPM2B_PUBLIC
        body.extend_from_slice(&(pub_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(pub_bytes);

        let mut cmd = Vec::with_capacity(10 + body.len());
        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_LOAD.to_be_bytes());
        cmd.extend_from_slice(&body);

        let response = ctx
            .submit_command(&cmd)
            .map_err(|e| TpmError::Signing(format!("TPM2_Load: {e}")))?;

        if response.len() < 14 {
            return Err(TpmError::Signing("TPM2_Load response too short".into()));
        }
        let rc = super::helpers::read_u32_be(&response, 6)
            .map_err(|e| TpmError::Signing(format!("Load rc parse: {e}")))?;
        if rc != TPM_RC_SUCCESS {
            return Err(TpmError::Signing(format!("TPM2_Load rc=0x{rc:08X}")));
        }

        super::helpers::read_u32_be(&response, 10)
            .map_err(|e| TpmError::Signing(format!("Load handle parse: {e}")))
    }

    /// TPM2_Sign: ECDSA-P256-SHA256 signature over a 32-byte digest.
    ///
    /// Returns the raw ECDSA signature as r || s (64 bytes for P-256).
    fn tpm2_sign(
        &self,
        ctx: &TbsContext,
        key_handle: u32,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, TpmError> {
        let mut body = Vec::new();
        body.extend_from_slice(&key_handle.to_be_bytes());

        let auth_area = build_empty_auth_area(key_handle);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        // TPM2B_DIGEST: size-prefixed digest
        body.extend_from_slice(&(digest.len() as u16).to_be_bytes());
        body.extend_from_slice(digest);

        // TPMT_SIG_SCHEME: ECDSA with SHA-256
        body.extend_from_slice(&TPM2_ALG_ECDSA.to_be_bytes());
        body.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes());

        // TPMT_TK_HASHCHECK: NULL ticket (we hashed externally)
        body.extend_from_slice(&TPM2_ST_HASHCHECK.to_be_bytes());
        body.extend_from_slice(&TPM2_RH_NULL.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // empty digest

        let mut cmd = Vec::with_capacity(10 + body.len());
        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_SIGN.to_be_bytes());
        cmd.extend_from_slice(&body);

        let response = ctx
            .submit_command(&cmd)
            .map_err(|e| TpmError::Signing(format!("TPM2_Sign: {e}")))?;

        self.parse_ecdsa_signature(&response)
    }

    /// Parse TPM2_Sign ECDSA response into r || s (64 bytes).
    fn parse_ecdsa_signature(&self, response: &[u8]) -> Result<Vec<u8>, TpmError> {
        if response.len() < 14 {
            return Err(TpmError::Signing("TPM2_Sign response too short".into()));
        }
        let rc = super::helpers::read_u32_be(response, 6)
            .map_err(|e| TpmError::Signing(format!("Sign rc parse: {e}")))?;
        if rc != TPM_RC_SUCCESS {
            return Err(TpmError::Signing(format!("TPM2_Sign rc=0x{rc:08X}")));
        }

        // Response: header(10) + parameterSize(4) + TPMT_SIGNATURE
        // TPMT_SIGNATURE for ECDSA: sigAlg(2) + hashAlg(2) + r(2+N) + s(2+N)
        let mut offset = 14;
        if offset + 4 > response.len() {
            return Err(TpmError::Signing("missing signature header".into()));
        }
        offset += 2; // sigAlg (ECDSA)
        offset += 2; // hashAlg (SHA256)

        // TPM2B_ECC_PARAMETER: signatureR
        if offset + 2 > response.len() {
            return Err(TpmError::Signing("missing r size".into()));
        }
        let r_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
        offset += 2;
        if offset + r_size > response.len() || r_size > 32 {
            return Err(TpmError::Signing("r truncated or oversized".into()));
        }
        // Left-pad to 32 bytes if shorter
        let mut r = [0u8; 32];
        r[32 - r_size..].copy_from_slice(&response[offset..offset + r_size]);
        offset += r_size;

        // TPM2B_ECC_PARAMETER: signatureS
        if offset + 2 > response.len() {
            return Err(TpmError::Signing("missing s size".into()));
        }
        let s_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
        offset += 2;
        if offset + s_size > response.len() || s_size > 32 {
            return Err(TpmError::Signing("s truncated or oversized".into()));
        }
        let mut s = [0u8; 32];
        s[32 - s_size..].copy_from_slice(&response[offset..offset + s_size]);

        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&r);
        signature.extend_from_slice(&s);
        Ok(signature)
    }

    /// TPM2_CreatePrimary: ECC P-256 SRK under Owner hierarchy.
    fn create_primary_srk(&self, ctx: &TbsContext) -> Result<Vec<u8>, TbsError> {
        let mut cmd = Vec::with_capacity(128);
        let mut body = Vec::new();

        body.extend_from_slice(&TPM2_RH_OWNER.to_be_bytes());

        let auth_area = build_empty_auth_area(TPM2_RH_OWNER);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        body.extend_from_slice(&4u16.to_be_bytes()); // inSensitive size
        body.extend_from_slice(&0u16.to_be_bytes()); // empty userAuth
        body.extend_from_slice(&0u16.to_be_bytes()); // empty data

        let public_area = build_srk_public_ecc();
        body.extend_from_slice(&(public_area.len() as u16).to_be_bytes());
        body.extend_from_slice(&public_area);

        body.extend_from_slice(&0u16.to_be_bytes()); // outsideInfo
        body.extend_from_slice(&0u32.to_be_bytes()); // creationPCR

        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_CREATE_PRIMARY.to_be_bytes());
        cmd.extend_from_slice(&body);

        ctx.submit_command(&cmd)
    }

    fn create_sealed_object(
        &self,
        ctx: &TbsContext,
        parent_handle: u32,
        data: &[u8],
    ) -> Result<Vec<u8>, TbsError> {
        let mut body = Vec::new();

        body.extend_from_slice(&parent_handle.to_be_bytes());

        let auth_area = build_empty_auth_area(parent_handle);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        let auth_value = self.derive_seal_auth_value(ctx);
        let sensitive_size = 2 + auth_value.len() + 2 + data.len();
        body.extend_from_slice(&(sensitive_size as u16).to_be_bytes());
        body.extend_from_slice(&(auth_value.len() as u16).to_be_bytes());
        body.extend_from_slice(&auth_value);
        body.extend_from_slice(&(data.len() as u16).to_be_bytes());
        body.extend_from_slice(data);

        let public_area = build_sealing_public();
        body.extend_from_slice(&(public_area.len() as u16).to_be_bytes());
        body.extend_from_slice(&public_area);

        body.extend_from_slice(&0u16.to_be_bytes()); // outsideInfo
        body.extend_from_slice(&0u32.to_be_bytes()); // creationPCR

        let mut cmd = Vec::with_capacity(10 + body.len());
        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_CREATE.to_be_bytes());
        cmd.extend_from_slice(&body);

        ctx.submit_command(&cmd)
    }

    /// Parse TPM2_Create response into `[pub_len: u32][pub][priv_len: u32][priv]`.
    fn parse_create_response(&self, response: &[u8]) -> Result<Vec<u8>, String> {
        if response.len() < 16 {
            return Err("response too short".into());
        }

        let mut offset = 14; // header(10) + parameterSize(4)

        if offset + 2 > response.len() {
            return Err("missing outPrivate size".into());
        }
        let priv_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
        offset += 2;
        if offset + priv_size > response.len() {
            return Err("outPrivate truncated".into());
        }
        let priv_bytes = &response[offset..offset + priv_size];
        offset += priv_size;

        if offset + 2 > response.len() {
            return Err("missing outPublic size".into());
        }
        let pub_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
        offset += 2;
        if offset + pub_size > response.len() {
            return Err("outPublic truncated".into());
        }
        let pub_bytes = &response[offset..offset + pub_size];

        let mut blob = Vec::with_capacity(8 + pub_bytes.len() + priv_bytes.len());
        blob.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
        blob.extend_from_slice(pub_bytes);
        blob.extend_from_slice(&(priv_bytes.len() as u32).to_be_bytes());
        blob.extend_from_slice(priv_bytes);

        Ok(blob)
    }

    fn load_object(
        &self,
        ctx: &TbsContext,
        parent_handle: u32,
        pub_bytes: &[u8],
        priv_bytes: &[u8],
    ) -> Result<Vec<u8>, TbsError> {
        let mut body = Vec::new();

        body.extend_from_slice(&parent_handle.to_be_bytes());

        let auth_area = build_empty_auth_area(parent_handle);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        body.extend_from_slice(&(priv_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(priv_bytes);

        body.extend_from_slice(&(pub_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(pub_bytes);

        let mut cmd = Vec::with_capacity(10 + body.len());
        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_LOAD.to_be_bytes());
        cmd.extend_from_slice(&body);

        ctx.submit_command(&cmd)
    }

    fn unseal_object(&self, ctx: &TbsContext, obj_handle: u32) -> Result<Vec<u8>, TbsError> {
        let mut body = Vec::new();

        body.extend_from_slice(&obj_handle.to_be_bytes());

        let auth_value = self.derive_seal_auth_value(ctx);
        let auth_area = build_auth_area_with_password(obj_handle, &auth_value);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        let mut cmd = Vec::with_capacity(10 + body.len());
        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_UNSEAL.to_be_bytes());
        cmd.extend_from_slice(&body);

        ctx.submit_command(&cmd)
    }

    fn flush_context(&self, ctx: &TbsContext, handle: u32) -> Result<(), TbsError> {
        let mut cmd = Vec::with_capacity(14);
        let command_size: u32 = 14;
        cmd.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_FLUSH_CONTEXT.to_be_bytes());
        cmd.extend_from_slice(&handle.to_be_bytes());
        ctx.submit_command(&cmd)?;
        Ok(())
    }

    /// Hardware-bound: derived from TPM device ID and SRK public key so sealed
    /// blobs can't be moved to another machine.
    fn derive_seal_auth_value(&self, ctx: &TbsContext) -> zeroize::Zeroizing<Vec<u8>> {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-seal-auth-v2");
        hasher.update(ctx.device_id().as_bytes());
        hasher.update(&self.public_key);
        let hash = hasher.finalize();
        zeroize::Zeroizing::new(hash[..32].to_vec())
    }

    fn build_quote_attestation_data(
        &self,
        nonce: &[u8],
        pcr_values: &[PcrValue],
        timestamp: &chrono::DateTime<Utc>,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(&0xFF544347u32.to_be_bytes()); // TCG magic
        data.extend_from_slice(&0x8018u16.to_be_bytes()); // ATTEST_QUOTE
        data.extend_from_slice(&0u16.to_be_bytes()); // qualifiedSigner

        let nonce_len = nonce.len().min(64) as u16;
        data.extend_from_slice(&nonce_len.to_be_bytes());
        data.extend_from_slice(&nonce[..nonce_len as usize]);

        let clock = timestamp.timestamp() as u64;
        data.extend_from_slice(&clock.to_be_bytes()); // TPMS_CLOCK_INFO
        data.extend_from_slice(&0u32.to_be_bytes()); // resetCount
        data.extend_from_slice(&0u32.to_be_bytes()); // restartCount
        data.push(1); // safe

        data.extend_from_slice(&0u64.to_be_bytes()); // firmwareVersion
        let mut pcr_digest = Sha256::new();
        for pcr in pcr_values {
            pcr_digest.update(&pcr.value);
        }
        let digest = pcr_digest.finalize();
        data.extend_from_slice(&(digest.len() as u16).to_be_bytes());
        data.extend_from_slice(&digest);

        data
    }
}

impl Provider for WindowsTpmProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hardware_backed: true,
            supports_pcrs: true,
            supports_sealing: true,
            supports_attestation: false, // sign_payload is not real TPM2_Sign
            monotonic_counter: true,
            secure_clock: true,
        }
    }

    fn device_id(&self) -> String {
        let ctx = self.context.lock_recover();
        ctx.device_id().to_string()
    }

    fn algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::ES256
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn quote(&self, nonce: &[u8], pcrs: &[u32]) -> Result<Quote, TpmError> {
        let ctx = self.context.lock_recover();
        let timestamp = Utc::now();

        let pcr_values = if !pcrs.is_empty() {
            self.read_pcrs(&ctx, pcrs)?
        } else {
            Vec::new()
        };

        let attested_data = self.build_quote_attestation_data(nonce, &pcr_values, &timestamp);
        let signature = self.sign_payload(&ctx, &attested_data)?;

        Ok(Quote {
            provider_type: "tpm2-windows".to_string(),
            device_id: ctx.device_id().to_string(),
            timestamp,
            nonce: nonce.to_vec(),
            attested_data,
            signature,
            public_key: self.public_key.clone(),
            pcr_values,
            extra: std::collections::HashMap::new(),
        })
    }

    fn bind(&self, data: &[u8]) -> Result<Binding, TpmError> {
        let ctx = self.context.lock_recover();
        let counter = {
            let mut state = self.state.lock_recover();
            state.counter += 1;
            state.counter
        };

        let timestamp = Utc::now();
        let device_id = ctx.device_id().to_string();
        let attested_hash = Sha256::digest(data).to_vec();

        let mut payload = Vec::new();
        payload.extend_from_slice(&attested_hash);
        payload.extend_from_slice(&timestamp.timestamp_nanos_safe().to_le_bytes());
        payload.extend_from_slice(device_id.as_bytes());

        let signature = self.sign_payload(&ctx, &payload)?;

        Ok(Binding {
            version: 1,
            provider_type: "tpm2-windows".to_string(),
            device_id,
            timestamp,
            attested_hash,
            signature,
            public_key: self.public_key.clone(),
            monotonic_counter: Some(counter),
            safe_clock: Some(true),
            attestation: Some(Attestation {
                payload,
                quote: None,
            }),
        })
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TpmError> {
        let ctx = self.context.lock_recover();
        self.sign_payload(&ctx, data)
    }

    fn verify(&self, binding: &Binding) -> Result<(), TpmError> {
        super::super::verification::verify_binding(binding)
    }

    fn seal(&self, data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TpmError> {
        let ctx = self.context.lock_recover();
        let srk_response = self
            .create_primary_srk(&ctx)
            .map_err(|e| TpmError::Sealing(format!("SRK creation failed: {}", e)))?;

        let srk_handle = super::helpers::read_u32_be(&srk_response, 10)
            .map_err(|e| TpmError::Sealing(format!("SRK handle parse: {e}")))?;

        let create_response = self
            .create_sealed_object(&ctx, srk_handle, data)
            .map_err(|e| TpmError::Sealing(format!("seal create failed: {}", e)))?;

        let sealed_blob = self
            .parse_create_response(&create_response)
            .map_err(|e| TpmError::Sealing(format!("parse create response: {}", e)))?;

        if let Err(e) = self.flush_context(&ctx, srk_handle) {
            log::warn!("Failed to flush SRK context after seal: {e}");
        }

        Ok(sealed_blob)
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, TpmError> {
        let ctx = self.context.lock_recover();
        let (pub_bytes, priv_bytes) = super::super::parse_sealed_blob(sealed)?;

        let srk_response = self
            .create_primary_srk(&ctx)
            .map_err(|e| TpmError::Unsealing(format!("SRK creation failed: {}", e)))?;
        let srk_handle = super::helpers::read_u32_be(&srk_response, 10)
            .map_err(|e| TpmError::Unsealing(format!("SRK handle parse: {e}")))?;

        let load_response = self
            .load_object(&ctx, srk_handle, pub_bytes, priv_bytes)
            .map_err(|e| TpmError::Unsealing(format!("load failed: {}", e)))?;
        let obj_handle = super::helpers::read_u32_be(&load_response, 10)
            .map_err(|e| TpmError::Unsealing(format!("object handle parse: {e}")))?;

        let unseal_result = self.unseal_object(&ctx, obj_handle);

        if let Err(e) = self.flush_context(&ctx, obj_handle) {
            log::warn!("Failed to flush object context after unseal: {e}");
        }
        if let Err(e) = self.flush_context(&ctx, srk_handle) {
            log::warn!("Failed to flush SRK context after unseal: {e}");
        }

        let unseal_response =
            unseal_result.map_err(|e| TpmError::Unsealing(format!("unseal failed: {}", e)))?;

        if unseal_response.len() < 12 {
            return Err(TpmError::Unsealing("unseal response too short".into()));
        }
        let data_size = u16::from_be_bytes([unseal_response[10], unseal_response[11]]) as usize;
        if unseal_response.len() < 12 + data_size {
            return Err(TpmError::Unsealing("unseal data truncated".into()));
        }

        Ok(unseal_response[12..12 + data_size].to_vec())
    }

    fn clock_info(&self) -> Result<super::super::ClockInfo, TpmError> {
        let ctx = self.context.lock_recover();
        let command_size: u32 = 10;
        let mut cmd = Vec::with_capacity(command_size as usize);
        cmd.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&0x00000181u32.to_be_bytes()); // CC_ReadClock

        let response = ctx
            .submit_command(&cmd)
            .map_err(|e| TpmError::Quote(format!("ReadClock failed: {}", e)))?;

        if response.len() < 10 + 8 + 8 + 4 + 4 + 1 {
            return Err(TpmError::Quote("ReadClock response too short".into()));
        }

        let offset = 18;
        let clock = u64::from_be_bytes([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
            response[offset + 4],
            response[offset + 5],
            response[offset + 6],
            response[offset + 7],
        ]);
        let reset_count = super::helpers::read_u32_be(&response, offset + 8)
            .map_err(|e| TpmError::CommunicationError(e))?;
        let restart_count = super::helpers::read_u32_be(&response, offset + 12)
            .map_err(|e| TpmError::CommunicationError(e))?;
        let safe = response[offset + 16] != 0;

        Ok(super::super::ClockInfo {
            clock,
            reset_count,
            restart_count,
            safe,
        })
    }
}
