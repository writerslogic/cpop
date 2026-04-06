// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Windows TPM 2.0 provider struct, initialization, and Provider trait impl.

use crate::DateTimeNanosExt;
use crate::MutexRecover;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::sync::Mutex;

use super::super::{Attestation, Binding, Capabilities, PcrValue, Provider, Quote, TpmError};
use super::commands::build_pcr_read_command;
use super::context::TbsContext;
use super::helpers::create_srk_public_key;
use super::types::*;

/// Windows TPM 2.0 provider via TBS (TPM Base Services).
pub struct WindowsTpmProvider {
    pub(super) context: Mutex<TbsContext>,
    pub(super) public_key: Vec<u8>,
    pub(super) state: Mutex<WindowsTpmState>,
}

pub(super) struct WindowsTpmState {
    pub(super) counter: u64,
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
    pub(super) fn read_pcrs(
        &self,
        ctx: &TbsContext,
        pcrs: &[u32],
    ) -> Result<Vec<PcrValue>, TpmError> {
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
        // Hold the state lock across counter increment and payload construction
        // so the counter value is atomically associated with this specific binding.
        let (counter, timestamp, device_id, attested_hash) = {
            let mut state = self.state.lock_recover();
            state.counter += 1;
            let counter = state.counter;
            let timestamp = Utc::now();
            let device_id = ctx.device_id().to_string();
            let attested_hash = Sha256::digest(data).to_vec();
            (counter, timestamp, device_id, attested_hash)
        };

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
        cmd.extend_from_slice(&TPM2_CC_READ_CLOCK.to_be_bytes());

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
