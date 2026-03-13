// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::Utc;
use std::ffi::c_void;

use windows::Win32::System::TpmBaseServices::{
    Tbsi_Context_Create, Tbsi_GetDeviceInfo, Tbsip_Context_Close, Tbsip_Submit_Command,
    TBS_COMMAND_LOCALITY, TBS_COMMAND_PRIORITY, TBS_CONTEXT_PARAMS, TBS_CONTEXT_PARAMS2,
    TPM_DEVICE_INFO,
};

use super::commands::build_get_random_command;
use super::types::*;

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

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]); // bounds checked above
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
