// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! TPM2 signing operations: sign_payload, create_signing_key, tpm2_sign.

use sha2::{Digest, Sha256};

use super::context::TbsContext;
use super::helpers::{build_empty_auth_area, build_srk_public_ecc};
use super::provider::WindowsTpmProvider;
use super::types::*;
use crate::tpm::TpmError;

impl WindowsTpmProvider {
    /// Real TPM2_Sign using an ECC P-256 key created under the SRK.
    ///
    /// Creates a transient signing key via TPM2_Create + TPM2_Load, signs with
    /// TPM2_Sign (ECDSA-P256-SHA256), then flushes the key handle.
    pub(super) fn sign_payload(&self, ctx: &TbsContext, data: &[u8]) -> Result<Vec<u8>, TpmError> {
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
    pub(super) fn load_key(
        &self,
        ctx: &TbsContext,
        parent_handle: u32,
        blob: &[u8],
    ) -> Result<u32, TpmError> {
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

        if response.len() < 10 {
            return Err(TpmError::Signing("TPM2_Sign response too short".into()));
        }
        let rc = super::helpers::read_u32_be(&response, 6)
            .map_err(|e| TpmError::Signing(format!("Sign rc parse: {e}")))?;
        if rc != TPM_RC_SUCCESS {
            return Err(TpmError::Signing(format!("TPM2_Sign rc=0x{rc:08X}")));
        }

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
    pub(super) fn create_primary_srk(&self, ctx: &TbsContext) -> Result<Vec<u8>, TbsError> {
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

    /// Parse TPM2_Create response into `[pub_len: u32][pub][priv_len: u32][priv]`.
    pub(super) fn parse_create_response(&self, response: &[u8]) -> Result<Vec<u8>, String> {
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

    pub(super) fn flush_context(&self, ctx: &TbsContext, handle: u32) -> Result<(), TbsError> {
        let mut cmd = Vec::with_capacity(14);
        let command_size: u32 = 14;
        cmd.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_FLUSH_CONTEXT.to_be_bytes());
        cmd.extend_from_slice(&handle.to_be_bytes());
        ctx.submit_command(&cmd)?;
        Ok(())
    }

    pub(super) fn build_quote_attestation_data(
        &self,
        nonce: &[u8],
        pcr_values: &[super::super::PcrValue],
        timestamp: &chrono::DateTime<chrono::Utc>,
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
