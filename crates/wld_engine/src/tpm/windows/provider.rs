// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::DateTimeNanosExt;
use crate::MutexRecover;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::sync::Mutex;

use super::super::{Attestation, Binding, Capabilities, PcrValue, Provider, Quote, TPMError};
use super::commands::build_pcr_read_command;
use super::context::TbsContext;
use super::helpers::{
    build_auth_area_with_password, build_empty_auth_area, build_sealing_public,
    build_srk_public_ecc, create_srk_public_key,
};
use super::types::*;

pub struct WindowsTpmProvider {
    context: TbsContext,
    public_key: Vec<u8>,
    state: Mutex<WindowsTpmState>,
}

struct WindowsTpmState {
    counter: u64,
}

/// Probe for an available TPM 2.0 via TBS.
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
                        log::warn!(
                            "Failed to derive SRK public key: {}. Falling back to TPM random.",
                            e
                        );
                        context.get_random(32).unwrap_or_else(|_| vec![0u8; 32])
                    }
                };

                Some(WindowsTpmProvider {
                    context,
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
    fn read_pcrs(&self, pcrs: &[u32]) -> Result<Vec<PcrValue>, TPMError> {
        if pcrs.is_empty() {
            return Ok(Vec::new());
        }

        let cmd = build_pcr_read_command(pcrs);
        let response = self
            .context
            .submit_command(&cmd)
            .map_err(|e| TPMError::Quote(e.to_string()))?;

        self.parse_pcr_read_response(&response, pcrs)
    }

    /// Parse TPM2_PCR_Read response:
    /// header(10) + pcrUpdateCounter(4) + TPML_PCR_SELECTION + TPML_DIGEST
    fn parse_pcr_read_response(
        &self,
        response: &[u8],
        pcrs: &[u32],
    ) -> Result<Vec<PcrValue>, TPMError> {
        if response.len() < 14 {
            return Err(TPMError::Quote("PCR read response too short".to_string()));
        }

        let mut offset = TPM2_RESPONSE_HEADER_SIZE;

        offset += 4;

        let selection_count = super::helpers::read_u32_be(&response, offset)
            .map_err(|_| TPMError::Quote("PCR read response missing selection count".into()))?;
        offset += 4;

        for _ in 0..selection_count {
            if offset + 3 > response.len() {
                return Err(TPMError::Quote(
                    "PCR read response truncated in selection".to_string(),
                ));
            }
            offset += 2; // hash algorithm
            let size_of_select = response[offset] as usize;
            offset += 1;
            if offset
                .checked_add(size_of_select)
                .is_none_or(|end| end > response.len())
            {
                return Err(TPMError::Quote(
                    "PCR read response: sizeOfSelect exceeds buffer".to_string(),
                ));
            }
            offset += size_of_select;
        }

        let digest_count = super::helpers::read_u32_be(&response, offset)
            .map_err(|_| TPMError::Quote("PCR read response missing digest count".into()))?;
        offset += 4;

        let mut values = Vec::new();
        for (_i, &pcr) in pcrs.iter().take(digest_count as usize).enumerate() {
            if offset + 2 > response.len() {
                return Err(TPMError::Quote(
                    "PCR read response truncated in digest header".to_string(),
                ));
            }
            let digest_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
            offset += 2;

            if offset
                .checked_add(digest_size)
                .is_none_or(|end| end > response.len())
            {
                return Err(TPMError::Quote(
                    "PCR read response truncated in digest value".to_string(),
                ));
            }
            let value = response[offset..offset + digest_size].to_vec();
            offset += digest_size;

            values.push(PcrValue { index: pcr, value });
        }

        Ok(values)
    }

    /// TPM-assisted signature: TPM random || SHA256(random || data).
    /// TODO: use TPM2_Sign with a loaded key for real signatures.
    fn sign_payload(&self, data: &[u8]) -> Result<Vec<u8>, TPMError> {
        let random = self
            .context
            .get_random(32)
            .map_err(|e| TPMError::Signing(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(&random);
        hasher.update(data);
        let hash = hasher.finalize();

        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&random);
        signature.extend_from_slice(&hash);

        Ok(signature)
    }

    /// Create ECC P-256 SRK under the Owner hierarchy via TPM2_CreatePrimary.
    fn create_primary_srk(&self) -> Result<Vec<u8>, TbsError> {
        let mut cmd = Vec::with_capacity(128);
        let mut body = Vec::new();

        body.extend_from_slice(&TPM2_RH_OWNER.to_be_bytes());

        let auth_area = build_empty_auth_area(TPM2_RH_OWNER);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        // inSensitive: empty userAuth + empty data
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());

        let public_area = build_srk_public_ecc();
        body.extend_from_slice(&(public_area.len() as u16).to_be_bytes());
        body.extend_from_slice(&public_area);

        // outsideInfo (empty) + creationPCR (none)
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());

        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_CREATE_PRIMARY.to_be_bytes());
        cmd.extend_from_slice(&body);

        self.context.submit_command(&cmd)
    }

    fn create_sealed_object(&self, parent_handle: u32, data: &[u8]) -> Result<Vec<u8>, TbsError> {
        let mut body = Vec::new();

        body.extend_from_slice(&parent_handle.to_be_bytes());

        let auth_area = build_empty_auth_area(parent_handle);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        // inSensitive: machine-specific authValue + data to seal
        let auth_value = self.derive_seal_auth_value();
        let sensitive_size = 2 + auth_value.len() + 2 + data.len();
        body.extend_from_slice(&(sensitive_size as u16).to_be_bytes());
        body.extend_from_slice(&(auth_value.len() as u16).to_be_bytes());
        body.extend_from_slice(&auth_value);
        body.extend_from_slice(&(data.len() as u16).to_be_bytes());
        body.extend_from_slice(data);

        let public_area = build_sealing_public();
        body.extend_from_slice(&(public_area.len() as u16).to_be_bytes());
        body.extend_from_slice(&public_area);

        // outsideInfo (empty) + creationPCR (none)
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());

        let mut cmd = Vec::with_capacity(10 + body.len());
        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_CREATE.to_be_bytes());
        cmd.extend_from_slice(&body);

        self.context.submit_command(&cmd)
    }

    /// Extract outPrivate/outPublic from TPM2_Create response into sealed blob:
    /// `[pub_len: u32][pub_bytes][priv_len: u32][priv_bytes]`
    fn parse_create_response(&self, response: &[u8]) -> Result<Vec<u8>, String> {
        if response.len() < 16 {
            return Err("response too short".into());
        }

        // Skip header (10) + parameterSize (4)
        let mut offset = 14;

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

        self.context.submit_command(&cmd)
    }

    fn unseal_object(&self, obj_handle: u32) -> Result<Vec<u8>, TbsError> {
        let mut body = Vec::new();

        body.extend_from_slice(&obj_handle.to_be_bytes());

        let auth_value = self.derive_seal_auth_value();
        let auth_area = build_auth_area_with_password(obj_handle, &auth_value);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        let mut cmd = Vec::with_capacity(10 + body.len());
        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_UNSEAL.to_be_bytes());
        cmd.extend_from_slice(&body);

        self.context.submit_command(&cmd)
    }

    fn flush_context(&self, handle: u32) -> Result<(), TbsError> {
        let mut cmd = Vec::with_capacity(14);
        let command_size: u32 = 14;
        cmd.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&0x00000165u32.to_be_bytes()); // TPM2_CC_FlushContext
        cmd.extend_from_slice(&handle.to_be_bytes());
        self.context.submit_command(&cmd)?;
        Ok(())
    }

    /// Derive a machine-specific auth value for sealed objects.
    /// Prevents moving the sealed blob to another machine -- the authValue
    /// is derived from the TPM's device ID, making it hardware-bound.
    fn derive_seal_auth_value(&self) -> Vec<u8> {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-seal-auth-v1");
        hasher.update(self.context.device_id().as_bytes());
        // Must be deterministic (not random), otherwise unseal would fail
        let hash = hasher.finalize();
        hash[..32].to_vec()
    }

    /// Build a TPMS_ATTEST-like structure for a quote.
    fn build_quote_attestation_data(
        &self,
        nonce: &[u8],
        pcr_values: &[PcrValue],
        timestamp: &chrono::DateTime<Utc>,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(&0xFF544347u32.to_be_bytes()); // TCG magic
        data.extend_from_slice(&0x8018u16.to_be_bytes()); // ATTEST_QUOTE
        data.extend_from_slice(&0u16.to_be_bytes()); // qualifiedSigner (empty)

        let nonce_len = nonce.len().min(64) as u16;
        data.extend_from_slice(&nonce_len.to_be_bytes()); // extraData (nonce)
        data.extend_from_slice(&nonce[..nonce_len as usize]);

        // TPMS_CLOCK_INFO
        let clock = timestamp.timestamp() as u64;
        data.extend_from_slice(&clock.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes()); // resetCount
        data.extend_from_slice(&0u32.to_be_bytes()); // restartCount
        data.push(1); // safe

        data.extend_from_slice(&0u64.to_be_bytes()); // firmwareVersion

        // PCR digest
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
            // sign_payload uses SHA256(random||data), not real TPM2_Sign
            supports_attestation: false,
            monotonic_counter: true,
            secure_clock: true,
        }
    }

    fn device_id(&self) -> String {
        self.context.device_id().to_string()
    }

    fn algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::ES256
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn quote(&self, nonce: &[u8], pcrs: &[u32]) -> Result<Quote, TPMError> {
        let timestamp = Utc::now();

        let pcr_values = if !pcrs.is_empty() {
            self.read_pcrs(pcrs)?
        } else {
            Vec::new()
        };

        let attested_data = self.build_quote_attestation_data(nonce, &pcr_values, &timestamp);
        let signature = self.sign_payload(&attested_data)?;

        Ok(Quote {
            provider_type: "tpm2-windows".to_string(),
            device_id: self.device_id(),
            timestamp,
            nonce: nonce.to_vec(),
            attested_data,
            signature,
            public_key: self.public_key.clone(),
            pcr_values,
            extra: std::collections::HashMap::new(),
        })
    }

    fn bind(&self, data: &[u8]) -> Result<Binding, TPMError> {
        let counter = {
            let mut state = self.state.lock_recover();
            state.counter += 1;
            state.counter
        };

        let timestamp = Utc::now();
        let device_id = self.device_id();
        let attested_hash = Sha256::digest(data).to_vec();

        let mut payload = Vec::new();
        payload.extend_from_slice(&attested_hash);
        payload.extend_from_slice(&timestamp.timestamp_nanos_safe().to_le_bytes());
        payload.extend_from_slice(device_id.as_bytes());

        let signature = self.sign_payload(&payload)?;

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

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TPMError> {
        self.sign_payload(data)
    }

    fn verify(&self, binding: &Binding) -> Result<(), TPMError> {
        super::super::verification::verify_binding(binding)
    }

    fn seal(&self, data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TPMError> {
        let srk_response = self
            .create_primary_srk()
            .map_err(|e| TPMError::Sealing(format!("SRK creation failed: {}", e)))?;

        let srk_handle = super::helpers::read_u32_be(&srk_response, 10)
            .map_err(|e| TPMError::Sealing(format!("SRK handle parse: {e}")))?;

        let create_response = self
            .create_sealed_object(srk_handle, data)
            .map_err(|e| TPMError::Sealing(format!("seal create failed: {}", e)))?;

        let sealed_blob = self
            .parse_create_response(&create_response)
            .map_err(|e| TPMError::Sealing(format!("parse create response: {}", e)))?;

        if let Err(e) = self.flush_context(srk_handle) {
            log::warn!("Failed to flush SRK context after seal: {e}");
        }

        Ok(sealed_blob)
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, TPMError> {
        let (pub_bytes, priv_bytes) = super::super::parse_sealed_blob(sealed)?;

        let srk_response = self
            .create_primary_srk()
            .map_err(|e| TPMError::Unsealing(format!("SRK creation failed: {}", e)))?;
        let srk_handle = super::helpers::read_u32_be(&srk_response, 10)
            .map_err(|e| TPMError::Unsealing(format!("SRK handle parse: {e}")))?;

        let load_response = self
            .load_object(srk_handle, pub_bytes, priv_bytes)
            .map_err(|e| TPMError::Unsealing(format!("load failed: {}", e)))?;
        let obj_handle = super::helpers::read_u32_be(&load_response, 10)
            .map_err(|e| TPMError::Unsealing(format!("object handle parse: {e}")))?;

        let unseal_result = self.unseal_object(obj_handle);

        if let Err(e) = self.flush_context(obj_handle) {
            log::warn!("Failed to flush object context after unseal: {e}");
        }
        if let Err(e) = self.flush_context(srk_handle) {
            log::warn!("Failed to flush SRK context after unseal: {e}");
        }

        let unseal_response =
            unseal_result.map_err(|e| TPMError::Unsealing(format!("unseal failed: {}", e)))?;

        if unseal_response.len() < 12 {
            return Err(TPMError::Unsealing("unseal response too short".into()));
        }
        let data_size = u16::from_be_bytes([unseal_response[10], unseal_response[11]]) as usize;
        if unseal_response.len() < 12 + data_size {
            return Err(TPMError::Unsealing("unseal data truncated".into()));
        }

        Ok(unseal_response[12..12 + data_size].to_vec())
    }

    fn clock_info(&self) -> Result<super::super::ClockInfo, TPMError> {
        let command_size: u32 = 10;
        let mut cmd = Vec::with_capacity(command_size as usize);
        cmd.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&0x00000181u32.to_be_bytes());

        let response = self
            .context
            .submit_command(&cmd)
            .map_err(|e| TPMError::Quote(format!("ReadClock failed: {}", e)))?;

        if response.len() < 10 + 8 + 8 + 4 + 4 + 1 {
            return Err(TPMError::Quote("ReadClock response too short".into()));
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
            .map_err(|e| TPMError::CommunicationError(e))?;
        let restart_count = super::helpers::read_u32_be(&response, offset + 12)
            .map_err(|e| TPMError::CommunicationError(e))?;
        let safe = response[offset + 16] != 0;

        Ok(super::super::ClockInfo {
            clock,
            reset_count,
            restart_count,
            safe,
        })
    }
}
