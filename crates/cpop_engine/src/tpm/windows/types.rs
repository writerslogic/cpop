// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::super::TpmError;

pub const TBS_SUCCESS: u32 = 0x0;

pub mod tbs_error {
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

pub const TPM_VERSION_20: u32 = 2;
pub const TBS_COMMAND_LOCALITY_ZERO: u32 = 0;
pub const TBS_COMMAND_PRIORITY_NORMAL: u32 = 200;

pub const TPM2_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM2_ST_SESSIONS: u16 = 0x8002;
pub const TPM2_CC_GET_RANDOM: u32 = 0x0000017B;
pub const TPM2_CC_PCR_READ: u32 = 0x0000017E;
pub const TPM2_CC_CREATE: u32 = 0x00000153;
pub const TPM2_CC_LOAD: u32 = 0x00000157;
pub const TPM2_CC_UNSEAL: u32 = 0x0000015E;
pub const TPM2_CC_CREATE_PRIMARY: u32 = 0x00000131;
pub const TPM2_ALG_KEYEDHASH: u16 = 0x0008;
pub const TPM2_ALG_NULL: u16 = 0x0010;
pub const TPM2_ALG_AES: u16 = 0x0006;
pub const TPM2_ALG_CFB: u16 = 0x0043;
pub const TPM2_ALG_ECC: u16 = 0x0023;
pub const TPM2_ECC_NIST_P256: u16 = 0x0003;
pub const TPM2_RH_OWNER: u32 = 0x40000001;
pub const TPM2_ALG_SHA256: u16 = 0x000B;
/// tag (2) + responseSize (4) + responseCode (4)
pub const TPM2_RESPONSE_HEADER_SIZE: usize = 10;
pub const TPM_RC_SUCCESS: u32 = 0x000;
pub const MAX_RESPONSE_SIZE: usize = 4096;

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

impl From<TbsError> for TpmError {
    fn from(e: TbsError) -> Self {
        match e {
            TbsError::TpmNotFound | TbsError::ServiceNotRunning => TpmError::NotAvailable,
            TbsError::InvalidContext => TpmError::NotInitialized,
            _ => TpmError::Signing(e.to_string()),
        }
    }
}

pub fn tbs_result_to_error(result: u32) -> TbsError {
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
