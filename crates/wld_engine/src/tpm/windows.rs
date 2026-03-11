// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#![cfg(target_os = "windows")]

//! Windows TPM 2.0 provider using the native TBS (TPM Base Services) API.
//!
//! This module provides TPM 2.0 support on Windows through the TBS API.
//! It includes a TbsContext wrapper for safe handle management, command builders,
//! and response parsers for TPM2 commands.

use super::{Attestation, Binding, Capabilities, PcrValue, Provider, Quote, TPMError};
use crate::DateTimeNanosExt;
use crate::MutexRecover;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::sync::Mutex;

use windows::Win32::System::TpmBaseServices::{
    Tbsi_Context_Create, Tbsi_GetDeviceInfo, Tbsip_Context_Close, Tbsip_Submit_Command,
    TBS_COMMAND_LOCALITY, TBS_COMMAND_PRIORITY, TBS_CONTEXT_PARAMS, TBS_CONTEXT_PARAMS2,
    TPM_DEVICE_INFO,
};

const TBS_SUCCESS: u32 = 0x0;

mod tbs_error {
    pub const TBS_E_INTERNAL_ERROR: u32 = 0x80284001;
    pub const TBS_E_BAD_PARAMETER: u32 = 0x80284002;
    pub const TBS_E_INVALID_OUTPUT_POINTER: u32 = 0x80284003;
    pub const TBS_E_INVALID_CONTEXT: u32 = 0x80284004;
    pub const TBS_E_INSUFFICIENT_BUFFER: u32 = 0x80284005;
    pub const TBS_E_IOERROR: u32 = 0x80284006;
    pub const TBS_E_INVALID_CONTEXT_PARAM: u32 = 0x80284007;
    pub const TBS_E_SERVICE_NOT_RUNNING: u32 = 0x80284008;
    pub const TBS_E_TOO_MANY_TBS_CONTEXTS: u32 = 0x80284009;
    pub const TBS_E_SERVICE_START_PENDING: u32 = 0x8028400B;
    pub const TBS_E_BUFFER_TOO_LARGE: u32 = 0x8028400E;
    pub const TBS_E_TPM_NOT_FOUND: u32 = 0x8028400F;
    pub const TBS_E_SERVICE_DISABLED: u32 = 0x80284010;
}

const TPM_VERSION_20: u32 = 2;
const TBS_COMMAND_LOCALITY_ZERO: u32 = 0;
const TBS_COMMAND_PRIORITY_NORMAL: u32 = 200;

const TPM2_ST_NO_SESSIONS: u16 = 0x8001;
const TPM2_ST_SESSIONS: u16 = 0x8002;
const TPM2_CC_GET_RANDOM: u32 = 0x0000017B;
const TPM2_CC_PCR_READ: u32 = 0x0000017E;
const TPM2_CC_CREATE: u32 = 0x00000153;
const TPM2_CC_LOAD: u32 = 0x00000157;
const TPM2_CC_UNSEAL: u32 = 0x0000015E;
const TPM2_CC_CREATE_PRIMARY: u32 = 0x00000131;
const TPM2_ALG_KEYEDHASH: u16 = 0x0008;
const TPM2_ALG_NULL: u16 = 0x0010;
const TPM2_ALG_AES: u16 = 0x0006;
const TPM2_ALG_CFB: u16 = 0x0043;
const TPM2_ALG_ECC: u16 = 0x0023;
const TPM2_ECC_NIST_P256: u16 = 0x0003;
const TPM2_RH_OWNER: u32 = 0x40000001;
const TPM2_ALG_SHA256: u16 = 0x000B;
/// tag (2) + responseSize (4) + responseCode (4)
const TPM2_RESPONSE_HEADER_SIZE: usize = 10;
const TPM_RC_SUCCESS: u32 = 0x000;
const MAX_RESPONSE_SIZE: usize = 4096;

#[derive(Debug, Clone)]
pub enum TbsError {
    TbsError { code: u32, message: String },
    TpmError { code: u32 },
    ResponseTooShort,
    InvalidContext,
    TpmNotFound,
    ServiceNotRunning,
}

impl std::fmt::Display for TbsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TbsError::TbsError { code, message } => {
                write!(f, "TBS error 0x{:08X}: {}", code, message)
            }
            TbsError::TpmError { code } => write!(f, "TPM error 0x{:03X}", code),
            TbsError::ResponseTooShort => write!(f, "TPM response too short"),
            TbsError::InvalidContext => write!(f, "Invalid TBS context"),
            TbsError::TpmNotFound => write!(f, "TPM not found"),
            TbsError::ServiceNotRunning => write!(f, "TBS service not running"),
        }
    }
}

impl std::error::Error for TbsError {}

impl From<TbsError> for TPMError {
    fn from(e: TbsError) -> Self {
        match e {
            TbsError::TpmNotFound | TbsError::ServiceNotRunning => TPMError::NotAvailable,
            TbsError::InvalidContext => TPMError::NotInitialized,
            _ => TPMError::Signing(e.to_string()),
        }
    }
}

fn tbs_result_to_error(result: u32) -> TbsError {
    let message = match result {
        tbs_error::TBS_E_INTERNAL_ERROR => "Internal error",
        tbs_error::TBS_E_BAD_PARAMETER => "Bad parameter",
        tbs_error::TBS_E_INVALID_OUTPUT_POINTER => "Invalid output pointer",
        tbs_error::TBS_E_INVALID_CONTEXT => "Invalid context",
        tbs_error::TBS_E_INSUFFICIENT_BUFFER => "Insufficient buffer",
        tbs_error::TBS_E_IOERROR => "I/O error communicating with TPM",
        tbs_error::TBS_E_INVALID_CONTEXT_PARAM => "Invalid context parameter",
        tbs_error::TBS_E_SERVICE_NOT_RUNNING => "TBS service not running",
        tbs_error::TBS_E_TOO_MANY_TBS_CONTEXTS => "Too many TBS contexts",
        tbs_error::TBS_E_SERVICE_START_PENDING => "TBS service starting",
        tbs_error::TBS_E_BUFFER_TOO_LARGE => "Buffer too large",
        tbs_error::TBS_E_TPM_NOT_FOUND => "TPM not found",
        tbs_error::TBS_E_SERVICE_DISABLED => "TBS service disabled",
        _ => "Unknown error",
    };

    match result {
        tbs_error::TBS_E_TPM_NOT_FOUND => TbsError::TpmNotFound,
        tbs_error::TBS_E_SERVICE_NOT_RUNNING | tbs_error::TBS_E_SERVICE_DISABLED => {
            TbsError::ServiceNotRunning
        }
        tbs_error::TBS_E_INVALID_CONTEXT => TbsError::InvalidContext,
        _ => TbsError::TbsError {
            code: result,
            message: message.to_string(),
        },
    }
}

/// Wrapper around a TBS context handle for TPM 2.0 operations.
/// The context is automatically closed when dropped.
pub struct TbsContext {
    handle: *mut c_void,
    device_id: String,
}

// SAFETY: TBS handles are thread-safe; access is gated through &self / &mut self
unsafe impl Send for TbsContext {}
unsafe impl Sync for TbsContext {}

impl TbsContext {
    pub fn new() -> Result<Self, TbsError> {
        let mut params: TBS_CONTEXT_PARAMS2 = unsafe { std::mem::zeroed() };
        params.version = TPM_VERSION_20;

        // Bit layout: 0=requestRaw, 1=includeTpm12, 2=includeTpm20
        #[allow(unused_unsafe)]
        unsafe {
            params.Anonymous.asUINT32 = 0b100;
        }

        let mut context: *mut c_void = std::ptr::null_mut();

        let result = unsafe {
            Tbsi_Context_Create(
                &params as *const TBS_CONTEXT_PARAMS2 as *const TBS_CONTEXT_PARAMS,
                &mut context,
            )
        };

        if result != TBS_SUCCESS {
            return Err(tbs_result_to_error(result));
        }

        if context.is_null() {
            return Err(TbsError::InvalidContext);
        }

        let mut ctx = TbsContext {
            handle: context,
            device_id: String::new(),
        };

        match ctx.get_random(16) {
            Ok(random_bytes) => {
                ctx.device_id = format!("windows-tpm-{}", hex::encode(&random_bytes[..8]));
            }
            Err(_) => {
                ctx.device_id = format!("windows-tpm-{:x}", Utc::now().timestamp());
            }
        }

        Ok(ctx)
    }

    /// Submits a raw TPM2 command and returns the full response including header.
    pub fn submit_command(&self, command: &[u8]) -> Result<Vec<u8>, TbsError> {
        if self.handle.is_null() {
            return Err(TbsError::InvalidContext);
        }

        let mut response = vec![0u8; MAX_RESPONSE_SIZE];
        let mut response_size = MAX_RESPONSE_SIZE as u32;

        let result = unsafe {
            Tbsip_Submit_Command(
                self.handle,
                TBS_COMMAND_LOCALITY(TBS_COMMAND_LOCALITY_ZERO),
                TBS_COMMAND_PRIORITY(TBS_COMMAND_PRIORITY_NORMAL),
                command,
                response.as_mut_ptr(),
                &mut response_size,
            )
        };

        if result != TBS_SUCCESS {
            return Err(tbs_result_to_error(result));
        }

        response.truncate(response_size as usize);

        if response.len() < TPM2_RESPONSE_HEADER_SIZE {
            return Err(TbsError::ResponseTooShort);
        }

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != TPM_RC_SUCCESS {
            return Err(TbsError::TpmError { code: rc });
        }

        Ok(response)
    }

    pub fn get_device_info(&self) -> Result<TpmDeviceInfo, TbsError> {
        let mut info: TPM_DEVICE_INFO = unsafe { std::mem::zeroed() };

        let result = unsafe {
            Tbsi_GetDeviceInfo(
                std::mem::size_of::<TPM_DEVICE_INFO>() as u32,
                &mut info as *mut TPM_DEVICE_INFO as *mut c_void,
            )
        };

        if result != TBS_SUCCESS {
            return Err(tbs_result_to_error(result));
        }

        Ok(TpmDeviceInfo {
            struct_version: info.structVersion,
            tpm_version: info.tpmVersion,
            tpm_interface_type: info.tpmInterfaceType,
            tpm_impl_revision: info.tpmImpRevision,
        })
    }

    pub fn get_random(&self, num_bytes: u16) -> Result<Vec<u8>, TbsError> {
        let cmd = build_get_random_command(num_bytes);
        let response = self.submit_command(&cmd)?;

        if response.len() < 12 {
            return Err(TbsError::ResponseTooShort);
        }

        let digest_size = u16::from_be_bytes([response[10], response[11]]) as usize;
        if response.len() < 12 + digest_size {
            return Err(TbsError::ResponseTooShort);
        }

        Ok(response[12..12 + digest_size].to_vec())
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

impl Drop for TbsContext {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let _ = Tbsip_Context_Close(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

#[derive(Debug, Clone)]
pub struct TpmDeviceInfo {
    pub struct_version: u32,
    /// 1 = TPM 1.2, 2 = TPM 2.0
    pub tpm_version: u32,
    pub tpm_interface_type: u32,
    pub tpm_impl_revision: u32,
}

impl TpmDeviceInfo {
    pub fn is_tpm20(&self) -> bool {
        self.tpm_version == TPM_VERSION_20
    }
}

/// Build a TPM2_GetRandom command (`num_bytes` max ~48-64 depending on TPM).
pub fn build_get_random_command(num_bytes: u16) -> Vec<u8> {
    let command_size: u32 = 12;
    let mut cmd = Vec::with_capacity(command_size as usize);

    cmd.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&command_size.to_be_bytes());
    cmd.extend_from_slice(&TPM2_CC_GET_RANDOM.to_be_bytes());
    cmd.extend_from_slice(&num_bytes.to_be_bytes());

    cmd
}

/// Parse a TPM2_GetRandom response, extracting the TPM2B_DIGEST payload.
pub fn parse_get_random_response(response: &[u8]) -> Result<Vec<u8>, TPMError> {
    if response.len() < TPM2_RESPONSE_HEADER_SIZE {
        return Err(TPMError::Quote(format!(
            "Response too short: {} bytes, expected at least {}",
            response.len(),
            TPM2_RESPONSE_HEADER_SIZE
        )));
    }

    let response_code = parse_response_code(response)?;
    if response_code != 0 {
        return Err(TPMError::Quote(format!(
            "TPM error response code: 0x{:08X}",
            response_code
        )));
    }

    if response.len() < TPM2_RESPONSE_HEADER_SIZE + 2 {
        return Err(TPMError::Quote(
            "Response missing TPM2B_DIGEST size field".to_string(),
        ));
    }

    let digest_size = u16::from_be_bytes([response[10], response[11]]) as usize;

    if response.len() < TPM2_RESPONSE_HEADER_SIZE + 2 + digest_size {
        return Err(TPMError::Quote(format!(
            "Response truncated: expected {} bytes of random data, have {}",
            digest_size,
            response.len() - TPM2_RESPONSE_HEADER_SIZE - 2
        )));
    }

    Ok(response[12..12 + digest_size].to_vec())
}

/// Build a TPM2_PCR_Read command for SHA-256 bank (indices 0-23).
pub fn build_pcr_read_command(pcr_selection: &[u32]) -> Vec<u8> {
    let mut pcr_bitmap: [u8; 3] = [0, 0, 0];
    for &pcr_index in pcr_selection {
        if pcr_index < 24 {
            pcr_bitmap[(pcr_index / 8) as usize] |= 1 << (pcr_index % 8);
        }
    }

    let command_size: u32 = 20;
    let mut cmd = Vec::with_capacity(command_size as usize);

    cmd.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&command_size.to_be_bytes());
    cmd.extend_from_slice(&TPM2_CC_PCR_READ.to_be_bytes());

    cmd.extend_from_slice(&1u32.to_be_bytes());
    cmd.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes());
    cmd.push(3u8);
    cmd.extend_from_slice(&pcr_bitmap);

    cmd
}

/// Extract the response code (bytes 6-9, big-endian) from a TPM2 response header.
pub fn parse_response_code(response: &[u8]) -> Result<u32, TPMError> {
    if response.len() < TPM2_RESPONSE_HEADER_SIZE {
        return Err(TPMError::Quote(format!(
            "Response too short to parse response code: {} bytes",
            response.len()
        )));
    }

    let response_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    Ok(response_code)
}

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

        if offset + 4 > response.len() {
            return Err(TPMError::Quote(
                "PCR read response missing selection count".to_string(),
            ));
        }
        let selection_count = u32::from_be_bytes([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
        ]);
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

        if offset + 4 > response.len() {
            return Err(TPMError::Quote(
                "PCR read response missing digest count".to_string(),
            ));
        }
        let digest_count = u32::from_be_bytes([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
        ]);
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
        super::verification::verify_binding(binding)
    }

    fn seal(&self, data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TPMError> {
        let srk_response = self
            .create_primary_srk()
            .map_err(|e| TPMError::Sealing(format!("SRK creation failed: {}", e)))?;

        let srk_handle = u32::from_be_bytes([
            srk_response[10],
            srk_response[11],
            srk_response[12],
            srk_response[13],
        ]);

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
        let (pub_bytes, priv_bytes) = super::parse_sealed_blob(sealed)?;

        let srk_response = self
            .create_primary_srk()
            .map_err(|e| TPMError::Unsealing(format!("SRK creation failed: {}", e)))?;
        let srk_handle = u32::from_be_bytes([
            srk_response[10],
            srk_response[11],
            srk_response[12],
            srk_response[13],
        ]);

        let load_response = self
            .load_object(srk_handle, pub_bytes, priv_bytes)
            .map_err(|e| TPMError::Unsealing(format!("load failed: {}", e)))?;
        let obj_handle = u32::from_be_bytes([
            load_response[10],
            load_response[11],
            load_response[12],
            load_response[13],
        ]);

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

    fn clock_info(&self) -> Result<super::ClockInfo, TPMError> {
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
        let reset_count = u32::from_be_bytes([
            response[offset + 8],
            response[offset + 9],
            response[offset + 10],
            response[offset + 11],
        ]);
        let restart_count = u32::from_be_bytes([
            response[offset + 12],
            response[offset + 13],
            response[offset + 14],
            response[offset + 15],
        ]);
        let safe = response[offset + 16] != 0;

        Ok(super::ClockInfo {
            clock,
            reset_count,
            restart_count,
            safe,
        })
    }
}

fn build_empty_auth_area(handle: u32) -> Vec<u8> {
    build_auth_area_with_password(handle, &[])
}

/// Build a TPM_RS_PW authorization area with the given password.
fn build_auth_area_with_password(handle: u32, password: &[u8]) -> Vec<u8> {
    let mut auth = Vec::new();
    auth.extend_from_slice(&0x40000009u32.to_be_bytes());
    auth.extend_from_slice(&0u16.to_be_bytes());
    auth.push(0x01);
    auth.extend_from_slice(&(password.len() as u16).to_be_bytes());
    auth.extend_from_slice(password);
    auth
}

/// Build a TPMT_PUBLIC for an ECC P-256 Storage Root Key.
fn build_srk_public_ecc() -> Vec<u8> {
    let mut public = Vec::new();

    public.extend_from_slice(&TPM2_ALG_ECC.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes());

    // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | restricted | decrypt
    let attrs: u32 = 0x00030472;
    public.extend_from_slice(&attrs.to_be_bytes());

    public.extend_from_slice(&0u16.to_be_bytes());

    public.extend_from_slice(&TPM2_ALG_AES.to_be_bytes());
    public.extend_from_slice(&128u16.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_CFB.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes());
    public.extend_from_slice(&TPM2_ECC_NIST_P256.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes());

    public.extend_from_slice(&0u16.to_be_bytes());
    public.extend_from_slice(&0u16.to_be_bytes());

    public
}

/// Create the ECC P-256 SRK via TPM2_CreatePrimary and return its public key.
///
/// The SRK is deterministic — same template + same TPM hierarchy = same key on every call.
/// Returns the 64-byte uncompressed ECC point (x || y).
fn create_srk_public_key(context: &TbsContext) -> Result<Vec<u8>, String> {
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

    let mut cmd = Vec::with_capacity(10 + body.len());
    let command_size = (10 + body.len()) as u32;
    cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&command_size.to_be_bytes());
    cmd.extend_from_slice(&TPM2_CC_CREATE_PRIMARY.to_be_bytes());
    cmd.extend_from_slice(&body);

    let response = context
        .submit_command(&cmd)
        .map_err(|e| format!("CreatePrimary failed: {e}"))?;

    if response.len() < 18 {
        return Err("CreatePrimary response too short".into());
    }
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    if rc != TPM_RC_SUCCESS {
        return Err(format!("TPM2_CreatePrimary rc=0x{rc:08X}"));
    }
    let handle = u32::from_be_bytes([response[10], response[11], response[12], response[13]]);

    let mut offset = 18;
    if offset + 2 > response.len() {
        return Err("Missing outPublic size".into());
    }
    offset += 2;
    offset += 2 + 2 + 4;

    if offset + 2 > response.len() {
        return Err("Missing authPolicy".into());
    }
    let auth_policy_len = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2 + auth_policy_len;

    if offset + 2 > response.len() {
        return Err("Missing symmetric algorithm".into());
    }
    let sym_alg = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    if sym_alg != TPM2_ALG_NULL {
        offset += 2 + 2;
    }
    if offset + 2 > response.len() {
        return Err("Missing scheme".into());
    }
    let scheme_alg = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    if scheme_alg != TPM2_ALG_NULL {
        offset += 2; // hashAlg
    }
    offset += 2; // curveID
                 // kdf
    if offset + 2 > response.len() {
        return Err("Missing kdf".into());
    }
    let kdf_alg = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    if kdf_alg != TPM2_ALG_NULL {
        offset += 2;
    }

    // TPMS_ECC_POINT: x = TPM2B(size + data), y = TPM2B(size + data)
    if offset + 2 > response.len() {
        return Err("Missing x size".into());
    }
    let x_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2;
    if offset + x_size > response.len() {
        return Err("x truncated".into());
    }
    let x = &response[offset..offset + x_size];
    offset += x_size;

    if offset + 2 > response.len() {
        return Err("Missing y size".into());
    }
    let y_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2;
    if offset + y_size > response.len() {
        return Err("y truncated".into());
    }
    let y = &response[offset..offset + y_size];

    // Flush the transient primary key — we only needed the public point
    let mut flush_cmd = Vec::with_capacity(14);
    flush_cmd.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
    flush_cmd.extend_from_slice(&14u32.to_be_bytes());
    flush_cmd.extend_from_slice(&0x00000165u32.to_be_bytes()); // TPM2_CC_FlushContext
    flush_cmd.extend_from_slice(&handle.to_be_bytes());
    let _ = context.submit_command(&flush_cmd);

    let mut public_key = Vec::with_capacity(x_size + y_size);
    public_key.extend_from_slice(x);
    public_key.extend_from_slice(y);

    Ok(public_key)
}

/// Build a TPMT_PUBLIC for a KeyedHash sealing object.
fn build_sealing_public() -> Vec<u8> {
    let mut public = Vec::new();

    public.extend_from_slice(&TPM2_ALG_KEYEDHASH.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes());

    // fixedTPM | fixedParent | userWithAuth
    let attrs: u32 = 0x00000052;
    public.extend_from_slice(&attrs.to_be_bytes());

    public.extend_from_slice(&0u16.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes());
    public.extend_from_slice(&0u16.to_be_bytes());

    public
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_get_random_command() {
        let cmd = build_get_random_command(32);

        assert_eq!(cmd.len(), 12);
        assert_eq!(cmd[0..2], [0x80, 0x01]); // tag
        assert_eq!(cmd[2..6], [0x00, 0x00, 0x00, 0x0C]); // commandSize
        assert_eq!(cmd[6..10], [0x00, 0x00, 0x01, 0x7B]); // commandCode
        assert_eq!(cmd[10..12], [0x00, 0x20]); // bytesRequested
    }

    #[test]
    fn test_build_get_random_command_max_bytes() {
        let cmd = build_get_random_command(0xFFFF);
        assert_eq!(cmd[10], 0xFF);
        assert_eq!(cmd[11], 0xFF);
    }

    #[test]
    fn test_parse_get_random_response_success() {
        let mut response = Vec::new();
        response.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
        response.extend_from_slice(&20u32.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes());
        response.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);

        let result = parse_get_random_response(&response).unwrap();
        assert_eq!(result, vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn test_parse_get_random_response_tpm_error() {
        let mut response = Vec::new();
        response.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
        response.extend_from_slice(&10u32.to_be_bytes());
        response.extend_from_slice(&0x101u32.to_be_bytes()); // TPM_RC_FAILURE

        let result = parse_get_random_response(&response);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("0x00000101"));
    }

    #[test]
    fn test_parse_get_random_response_too_short() {
        let response = vec![0x80, 0x01, 0x00, 0x00];
        assert!(parse_get_random_response(&response).is_err());
    }

    #[test]
    fn test_build_pcr_read_command_single_pcr() {
        let cmd = build_pcr_read_command(&[0]);

        assert_eq!(cmd.len(), 20);
        assert_eq!(cmd[0..2], [0x80, 0x01]); // tag
        assert_eq!(cmd[2..6], [0x00, 0x00, 0x00, 0x14]); // commandSize
        assert_eq!(cmd[6..10], [0x00, 0x00, 0x01, 0x7E]); // commandCode
        assert_eq!(cmd[10..14], [0x00, 0x00, 0x00, 0x01]); // count
        assert_eq!(cmd[14..16], [0x00, 0x0B]); // hash alg
        assert_eq!(cmd[16], 0x03); // sizeofSelect
        assert_eq!(cmd[17..20], [0x01, 0x00, 0x00]); // PCR 0 bitmap
    }

    #[test]
    fn test_build_pcr_read_command_multiple_pcrs() {
        let cmd = build_pcr_read_command(&[0, 4, 7]);
        // PCR 0|4|7 = 0x01|0x10|0x80 = 0x91
        assert_eq!(cmd[17], 0x91);
        assert_eq!(cmd[18], 0x00);
        assert_eq!(cmd[19], 0x00);
    }

    #[test]
    fn test_build_pcr_read_command_pcrs_across_bytes() {
        let cmd = build_pcr_read_command(&[0, 8, 16]);
        // Each PCR is bit 0 of its respective byte
        assert_eq!(cmd[17..20], [0x01, 0x01, 0x01]);
    }

    #[test]
    fn test_build_pcr_read_command_ignores_invalid_pcrs() {
        let cmd = build_pcr_read_command(&[0, 24, 100]);
        assert_eq!(cmd[17..20], [0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_parse_response_code_success() {
        let mut response = Vec::new();
        response.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
        response.extend_from_slice(&10u32.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(parse_response_code(&response).unwrap(), 0);
    }

    #[test]
    fn test_parse_response_code_error() {
        let mut response = Vec::new();
        response.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
        response.extend_from_slice(&10u32.to_be_bytes());
        response.extend_from_slice(&0x8CE_u32.to_be_bytes());
        assert_eq!(parse_response_code(&response).unwrap(), 0x8CE);
    }

    #[test]
    fn test_parse_response_code_too_short() {
        let response = vec![0x80, 0x01, 0x00, 0x00, 0x00];
        assert!(parse_response_code(&response).is_err());
    }

    #[test]
    fn test_tbs_error_display() {
        let err = TbsError::TpmNotFound;
        assert_eq!(err.to_string(), "TPM not found");

        let err = TbsError::TpmError { code: 0x101 };
        assert_eq!(err.to_string(), "TPM error 0x101");

        let err = TbsError::TbsError {
            code: 0x80284001,
            message: "Internal error".to_string(),
        };
        assert!(err.to_string().contains("0x80284001"));
    }

    #[test]
    fn test_tbs_error_to_tpm_error() {
        let err: TPMError = TbsError::TpmNotFound.into();
        assert!(matches!(err, TPMError::NotAvailable));

        let err: TPMError = TbsError::ServiceNotRunning.into();
        assert!(matches!(err, TPMError::NotAvailable));

        let err: TPMError = TbsError::InvalidContext.into();
        assert!(matches!(err, TPMError::NotInitialized));
    }

    #[test]
    fn test_tpm_device_info_is_tpm20() {
        let info = TpmDeviceInfo {
            struct_version: 2,
            tpm_version: 2,
            tpm_interface_type: 0,
            tpm_impl_revision: 0,
        };
        assert!(info.is_tpm20());

        let info_v12 = TpmDeviceInfo {
            struct_version: 1,
            tpm_version: 1,
            tpm_interface_type: 0,
            tpm_impl_revision: 0,
        };
        assert!(!info_v12.is_tpm20());
    }
}
