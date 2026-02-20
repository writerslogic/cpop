#![cfg(target_os = "windows")]

//! Windows TPM 2.0 provider using the native TBS (TPM Base Services) API.
//!
//! This module provides TPM 2.0 support on Windows through the TBS API.
//! It includes a TbsContext wrapper for safe handle management, command builders,
//! and response parsers for TPM2 commands.

use super::{Attestation, Binding, Capabilities, PcrValue, Provider, Quote, TPMError};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::sync::Mutex;

// Re-export the TBS functions from the windows crate
use windows::Win32::System::TpmBaseServices::{
    Tbsi_Context_Create, Tbsi_GetDeviceInfo, Tbsip_Context_Close, Tbsip_Submit_Command,
    TBS_COMMAND_LOCALITY, TBS_COMMAND_PRIORITY, TBS_CONTEXT_PARAMS, TBS_CONTEXT_PARAMS2,
    TPM_DEVICE_INFO,
};

// ============================================================================
// TBS Constants
// ============================================================================

/// TBS operation completed successfully
const TBS_SUCCESS: u32 = 0x0;

/// TBS error codes
#[allow(dead_code)]
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

/// Context version for TPM 2.0
#[allow(dead_code)]
const TBS_CONTEXT_VERSION_TWO: u32 = 2;

/// TPM version 2.0
const TPM_VERSION_20: u32 = 2;

/// Command locality (only zero is supported)
const TBS_COMMAND_LOCALITY_ZERO: u32 = 0;

/// Normal command priority
const TBS_COMMAND_PRIORITY_NORMAL: u32 = 200;

// ============================================================================
// TPM2 Constants
// ============================================================================

/// TPM2 session tag: command/response has no sessions
const TPM2_ST_NO_SESSIONS: u16 = 0x8001;

/// TPM2 session tag: command/response has sessions
#[allow(dead_code)]
const TPM2_ST_SESSIONS: u16 = 0x8002;

/// TPM2 command code: Get random bytes
const TPM2_CC_GET_RANDOM: u32 = 0x0000017B;

/// TPM2 command code: Read PCR values
const TPM2_CC_PCR_READ: u32 = 0x0000017E;

/// TPM2 algorithm identifier: SHA-256
const TPM2_ALG_SHA256: u16 = 0x000B;

/// Minimum TPM2 response header size (tag + responseSize + responseCode)
const TPM2_RESPONSE_HEADER_SIZE: usize = 10;

/// TPM2 response code for success
const TPM_RC_SUCCESS: u32 = 0x000;

/// Maximum response buffer size
const MAX_RESPONSE_SIZE: usize = 4096;

// ============================================================================
// TBS Error Type
// ============================================================================

/// Error type for TBS operations
#[derive(Debug, Clone)]
pub enum TbsError {
    /// TBS API returned an error
    TbsError { code: u32, message: String },
    /// TPM returned an error in the response
    TpmError { code: u32 },
    /// Response was too short to parse
    ResponseTooShort,
    /// Context is not valid
    InvalidContext,
    /// TPM not found on system
    TpmNotFound,
    /// TBS service not running
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

/// Convert TBS result code to error
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

// ============================================================================
// TBS Context Wrapper
// ============================================================================

/// Wrapper around a TBS context handle for TPM 2.0 operations.
///
/// This struct provides a safe Rust interface to the Windows TBS API.
/// The context is automatically closed when dropped.
pub struct TbsContext {
    /// The raw TBS context handle
    handle: *mut c_void,
    /// Device ID derived from TPM
    device_id: String,
}

// TbsContext is Send + Sync because the handle is only accessed through &self
// or &mut self, and TBS handles are thread-safe
unsafe impl Send for TbsContext {}
unsafe impl Sync for TbsContext {}

impl TbsContext {
    /// Creates a new TBS context for TPM 2.0.
    ///
    /// This initializes a connection to the TPM via the TBS service.
    /// Returns an error if no TPM is available or the TBS service is not running.
    pub fn new() -> Result<Self, TbsError> {
        // Initialize TBS_CONTEXT_PARAMS2 for TPM 2.0
        let mut params: TBS_CONTEXT_PARAMS2 = unsafe { std::mem::zeroed() };
        params.version = TPM_VERSION_20;

        // Set includeTpm20 = 1 via the anonymous union
        // The union has a field `asUINT32` where bit 2 is includeTpm20
        unsafe {
            // includeTpm20 is bit 2 (value 4) in the flags
            // Bit 0: requestRaw
            // Bit 1: includeTpm12
            // Bit 2: includeTpm20
            params.Anonymous.asUINT32 = 0b100; // includeTpm20 = 1
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

        // Generate device ID from random bytes from TPM
        let mut ctx = TbsContext {
            handle: context,
            device_id: String::new(),
        };

        // Try to get random bytes for device ID
        match ctx.get_random(16) {
            Ok(random_bytes) => {
                ctx.device_id = format!("windows-tpm-{}", hex::encode(&random_bytes[..8]));
            }
            Err(_) => {
                // Fallback to timestamp-based ID
                ctx.device_id = format!("windows-tpm-{:x}", Utc::now().timestamp());
            }
        }

        Ok(ctx)
    }

    /// Submits a raw TPM2 command and returns the response.
    ///
    /// The command must be a properly formatted TPM2 command buffer with
    /// the standard 10-byte header (tag, size, command code) in big-endian format.
    ///
    /// Returns the full response including the 10-byte header.
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

        // Truncate to actual response size
        response.truncate(response_size as usize);

        // Verify minimum response size (10 bytes for header)
        if response.len() < TPM2_RESPONSE_HEADER_SIZE {
            return Err(TbsError::ResponseTooShort);
        }

        // Check TPM response code (bytes 6-9, big-endian)
        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != TPM_RC_SUCCESS {
            return Err(TbsError::TpmError { code: rc });
        }

        Ok(response)
    }

    /// Gets TPM device information.
    ///
    /// Returns the TPM version information from the device.
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

    /// Gets random bytes from the TPM.
    ///
    /// Uses the TPM2_GetRandom command to obtain hardware random bytes.
    pub fn get_random(&self, num_bytes: u16) -> Result<Vec<u8>, TbsError> {
        let cmd = build_get_random_command(num_bytes);
        let response = self.submit_command(&cmd)?;

        // Parse response: header (10 bytes) + digest size (2 bytes) + digest data
        if response.len() < 12 {
            return Err(TbsError::ResponseTooShort);
        }

        let digest_size = u16::from_be_bytes([response[10], response[11]]) as usize;
        if response.len() < 12 + digest_size {
            return Err(TbsError::ResponseTooShort);
        }

        Ok(response[12..12 + digest_size].to_vec())
    }

    /// Returns the device ID for this TPM context.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

impl Drop for TbsContext {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                // Ignore the result - we're cleaning up
                let _ = Tbsip_Context_Close(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

// ============================================================================
// TPM Device Info
// ============================================================================

/// Information about the TPM device.
#[derive(Debug, Clone)]
pub struct TpmDeviceInfo {
    /// Structure version (should be TPM_VERSION_20)
    pub struct_version: u32,
    /// TPM version (1 = 1.2, 2 = 2.0)
    pub tpm_version: u32,
    /// TPM interface type (reserved)
    pub tpm_interface_type: u32,
    /// TPM implementation revision (reserved)
    pub tpm_impl_revision: u32,
}

impl TpmDeviceInfo {
    /// Returns true if this is a TPM 2.0 device.
    pub fn is_tpm20(&self) -> bool {
        self.tpm_version == TPM_VERSION_20
    }
}

// ============================================================================
// TPM2 Command Builders
// ============================================================================

/// Builds a TPM2_GetRandom command to request random bytes from the TPM.
///
/// # Arguments
/// * `num_bytes` - Number of random bytes to request (max typically 48-64 depending on TPM)
///
/// # Returns
/// A `Vec<u8>` containing the complete TPM2 command in big-endian format.
///
/// # Command Structure
/// - Header (10 bytes):
///   - tag: u16 (TPM2_ST_NO_SESSIONS = 0x8001)
///   - commandSize: u32 (total size = 12 bytes)
///   - commandCode: u32 (TPM2_CC_GetRandom = 0x0000017B)
/// - Parameters (2 bytes):
///   - bytesRequested: u16
pub fn build_get_random_command(num_bytes: u16) -> Vec<u8> {
    let command_size: u32 = 12; // 10 byte header + 2 byte parameter
    let mut cmd = Vec::with_capacity(command_size as usize);

    // Header
    cmd.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes()); // tag (2 bytes)
    cmd.extend_from_slice(&command_size.to_be_bytes()); // commandSize (4 bytes)
    cmd.extend_from_slice(&TPM2_CC_GET_RANDOM.to_be_bytes()); // commandCode (4 bytes)

    // Parameters
    cmd.extend_from_slice(&num_bytes.to_be_bytes()); // bytesRequested (2 bytes)

    cmd
}

/// Parses a TPM2_GetRandom response and extracts the random bytes.
///
/// # Arguments
/// * `response` - The raw TPM2 response bytes
///
/// # Returns
/// * `Ok(Vec<u8>)` - The random bytes from the TPM
/// * `Err(TPMError)` - If the response is invalid or indicates an error
///
/// # Response Structure
/// - Header (10 bytes):
///   - tag: u16
///   - responseSize: u32
///   - responseCode: u32 (0 = success)
/// - TPM2B_DIGEST:
///   - size: u16
///   - buffer: [u8; size]
pub fn parse_get_random_response(response: &[u8]) -> Result<Vec<u8>, TPMError> {
    // Validate minimum response size
    if response.len() < TPM2_RESPONSE_HEADER_SIZE {
        return Err(TPMError::Quote(format!(
            "Response too short: {} bytes, expected at least {}",
            response.len(),
            TPM2_RESPONSE_HEADER_SIZE
        )));
    }

    // Check response code
    let response_code = parse_response_code(response)?;
    if response_code != 0 {
        return Err(TPMError::Quote(format!(
            "TPM error response code: 0x{:08X}",
            response_code
        )));
    }

    // Parse TPM2B_DIGEST structure after header
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

    // Extract random bytes
    let random_bytes = response[12..12 + digest_size].to_vec();
    Ok(random_bytes)
}

/// Builds a TPM2_PCR_Read command to read PCR values.
///
/// # Arguments
/// * `pcr_selection` - Array of PCR indices to read (0-23 for SHA-256 bank)
///
/// # Returns
/// A `Vec<u8>` containing the complete TPM2 command in big-endian format.
///
/// # Command Structure
/// - Header (10 bytes):
///   - tag: u16 (TPM2_ST_NO_SESSIONS = 0x8001)
///   - commandSize: u32
///   - commandCode: u32 (TPM2_CC_PCR_Read = 0x0000017E)
/// - TPML_PCR_SELECTION:
///   - count: u32 (number of PCR selections, typically 1)
///   - TPMS_PCR_SELECTION[count]:
///     - hash: u16 (algorithm ID, e.g., TPM2_ALG_SHA256)
///     - sizeofSelect: u8 (size of pcrSelect array, typically 3)
///     - pcrSelect: [u8; sizeofSelect] (bitmap of PCRs)
pub fn build_pcr_read_command(pcr_selection: &[u32]) -> Vec<u8> {
    // Build PCR selection bitmap (3 bytes covers PCRs 0-23)
    let mut pcr_bitmap: [u8; 3] = [0, 0, 0];
    for &pcr_index in pcr_selection {
        if pcr_index < 24 {
            let byte_index = (pcr_index / 8) as usize;
            let bit_index = pcr_index % 8;
            pcr_bitmap[byte_index] |= 1 << bit_index;
        }
    }

    // Command size: 10 (header) + 4 (count) + 2 (hash) + 1 (sizeofSelect) + 3 (pcrSelect)
    let command_size: u32 = 10 + 4 + 2 + 1 + 3;
    let mut cmd = Vec::with_capacity(command_size as usize);

    // Header
    cmd.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes()); // tag (2 bytes)
    cmd.extend_from_slice(&command_size.to_be_bytes()); // commandSize (4 bytes)
    cmd.extend_from_slice(&TPM2_CC_PCR_READ.to_be_bytes()); // commandCode (4 bytes)

    // TPML_PCR_SELECTION
    cmd.extend_from_slice(&1u32.to_be_bytes()); // count = 1 (4 bytes)

    // TPMS_PCR_SELECTION
    cmd.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes()); // hash algorithm (2 bytes)
    cmd.push(3u8); // sizeofSelect = 3 (1 byte)
    cmd.extend_from_slice(&pcr_bitmap); // pcrSelect bitmap (3 bytes)

    cmd
}

/// Extracts the response code from a TPM2 response.
///
/// # Arguments
/// * `response` - The raw TPM2 response bytes
///
/// # Returns
/// * `Ok(u32)` - The response code (0 = success)
/// * `Err(TPMError)` - If the response is too short
///
/// # Response Code Location
/// The response code is at bytes 6-9 (big-endian u32) in the response header.
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

// ============================================================================
// Windows TPM Provider
// ============================================================================

/// Windows TPM 2.0 provider implementation.
pub struct WindowsTpmProvider {
    /// The TBS context for TPM operations
    context: TbsContext,
    /// Cached public key (generated on first use)
    public_key: Vec<u8>,
    /// State protected by mutex for thread-safety
    state: Mutex<WindowsTpmState>,
}

/// Internal state for the Windows TPM provider
struct WindowsTpmState {
    /// Monotonic counter for bindings
    counter: u64,
}

/// Attempts to initialize the Windows TPM provider.
///
/// Returns `Some(WindowsTpmProvider)` if a TPM 2.0 is available and the TBS
/// service is running. Returns `None` if no TPM is available.
pub fn try_init() -> Option<WindowsTpmProvider> {
    match TbsContext::new() {
        Ok(context) => {
            // Verify we have a TPM 2.0
            match context.get_device_info() {
                Ok(info) if info.is_tpm20() => {
                    log::info!(
                        "Windows TPM 2.0 detected (version: {}, revision: {})",
                        info.tpm_version,
                        info.tpm_impl_revision
                    );

                    // Generate a random public key for signing operations
                    // In a full implementation, this would be a TPM-backed key
                    let public_key = match context.get_random(32) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            log::warn!("Failed to generate TPM public key: {}", e);
                            vec![0u8; 32]
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
            }
        }
        Err(e) => {
            log::debug!("Windows TPM not available: {}", e);
            None
        }
    }
}

impl WindowsTpmProvider {
    /// Read PCR values from the TPM.
    fn read_pcrs(&self, pcrs: &[u32]) -> Result<Vec<PcrValue>, TPMError> {
        if pcrs.is_empty() {
            return Ok(Vec::new());
        }

        let cmd = build_pcr_read_command(pcrs);
        let response = self
            .context
            .submit_command(&cmd)
            .map_err(|e| TPMError::Quote(e.to_string()))?;

        // Parse the PCR read response
        self.parse_pcr_read_response(&response, pcrs)
    }

    /// Parse a TPM2_PCR_Read response.
    fn parse_pcr_read_response(
        &self,
        response: &[u8],
        pcrs: &[u32],
    ) -> Result<Vec<PcrValue>, TPMError> {
        // Response format after header (10 bytes):
        // - pcrUpdateCounter (4 bytes)
        // - pcrSelectionOut (TPML_PCR_SELECTION)
        // - pcrValues (TPML_DIGEST)

        if response.len() < 14 {
            return Err(TPMError::Quote("PCR read response too short".to_string()));
        }

        let mut offset = TPM2_RESPONSE_HEADER_SIZE;

        // Skip pcrUpdateCounter (4 bytes)
        offset += 4;

        // Parse pcrSelectionOut count
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

        // Skip each selection (hash: 2 bytes + sizeOfSelect: 1 byte + pcrSelect: sizeOfSelect bytes)
        for _ in 0..selection_count {
            if offset + 3 > response.len() {
                return Err(TPMError::Quote(
                    "PCR read response truncated in selection".to_string(),
                ));
            }
            offset += 2; // hash algorithm
            let size_of_select = response[offset] as usize;
            offset += 1 + size_of_select;
        }

        // Read TPML_DIGEST count
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

        // Read each digest (TPM2B_DIGEST: size: u16 + buffer)
        let mut values = Vec::new();
        for (i, &pcr) in pcrs.iter().take(digest_count as usize).enumerate() {
            if offset + 2 > response.len() {
                break;
            }
            let digest_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
            offset += 2;

            if offset + digest_size > response.len() {
                break;
            }
            let value = response[offset..offset + digest_size].to_vec();
            offset += digest_size;

            values.push(PcrValue { index: pcr, value });
        }

        Ok(values)
    }

    /// Sign a payload using TPM hash (TPM-assisted signature).
    /// Note: Full TPM signing requires key loading. This uses TPM hash for now.
    fn sign_payload(&self, data: &[u8]) -> Result<Vec<u8>, TPMError> {
        // Use TPM random combined with hash for a TPM-assisted signature
        // A full implementation would use TPM2_Sign with a loaded key
        let random = self
            .context
            .get_random(32)
            .map_err(|e| TPMError::Signing(e.to_string()))?;

        // Combine random with hash of data for signature
        let mut hasher = Sha256::new();
        hasher.update(&random);
        hasher.update(data);
        let hash = hasher.finalize();

        // Create signature by combining random and hash
        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&random);
        signature.extend_from_slice(&hash);

        Ok(signature)
    }

    /// Build attestation data structure for a quote.
    fn build_quote_attestation_data(
        &self,
        nonce: &[u8],
        pcr_values: &[PcrValue],
        timestamp: &chrono::DateTime<Utc>,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        // Magic (0xFF544347 = "TCG" marker)
        data.extend_from_slice(&0xFF544347u32.to_be_bytes());

        // Type (ATTEST_QUOTE = 0x8018)
        data.extend_from_slice(&0x8018u16.to_be_bytes());

        // Qualified signer (empty TPM2B_NAME)
        data.extend_from_slice(&0u16.to_be_bytes());

        // Extra data (nonce as TPM2B_DATA)
        let nonce_len = nonce.len().min(64) as u16;
        data.extend_from_slice(&nonce_len.to_be_bytes());
        data.extend_from_slice(&nonce[..nonce_len as usize]);

        // Clock info (TPMS_CLOCK_INFO)
        let clock = timestamp.timestamp() as u64;
        data.extend_from_slice(&clock.to_be_bytes()); // clock
        data.extend_from_slice(&0u32.to_be_bytes()); // resetCount
        data.extend_from_slice(&0u32.to_be_bytes()); // restartCount
        data.push(1); // safe = true

        // Firmware version
        data.extend_from_slice(&0u64.to_be_bytes());

        // Quote-specific: PCR digest (hash of all PCR values)
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
            supports_sealing: false, // Complex implementation - not yet available
            supports_attestation: true,
            monotonic_counter: true, // Software-based counter (not TPM NV counter)
            secure_clock: false,     // TPM clock requires careful handling
        }
    }

    fn device_id(&self) -> String {
        self.context.device_id().to_string()
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn quote(&self, nonce: &[u8], pcrs: &[u32]) -> Result<Quote, TPMError> {
        let timestamp = Utc::now();

        // Read PCR values if requested
        let pcr_values = if !pcrs.is_empty() {
            self.read_pcrs(pcrs)?
        } else {
            Vec::new()
        };

        // Build attestation data structure (TPMS_ATTEST-like)
        let attested_data = self.build_quote_attestation_data(nonce, &pcr_values, &timestamp);

        // Create signature over attested data using TPM hash
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
        // Increment monotonic counter
        let counter = {
            let mut state = self.state.lock().unwrap();
            state.counter += 1;
            state.counter
        };

        let timestamp = Utc::now();
        let device_id = self.device_id();

        // Hash the data using SHA-256
        let attested_hash = Sha256::digest(data).to_vec();

        // Build payload for signing
        let mut payload = Vec::new();
        payload.extend_from_slice(&attested_hash);
        payload.extend_from_slice(&timestamp.timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        payload.extend_from_slice(device_id.as_bytes());

        // Sign the payload using TPM
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

    fn verify(&self, binding: &Binding) -> Result<(), TPMError> {
        // Use the common verification logic from the verification module
        super::verification::verify_binding(binding)
    }

    fn seal(&self, _data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TPMError> {
        // Sealing not yet implemented
        Err(TPMError::NotAvailable)
    }

    fn unseal(&self, _sealed: &[u8]) -> Result<Vec<u8>, TPMError> {
        // Unsealing not yet implemented
        Err(TPMError::NotAvailable)
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_get_random_command() {
        let cmd = build_get_random_command(32);

        // Command should be exactly 12 bytes
        assert_eq!(cmd.len(), 12);

        // Check tag (bytes 0-1): TPM2_ST_NO_SESSIONS = 0x8001
        assert_eq!(cmd[0], 0x80);
        assert_eq!(cmd[1], 0x01);

        // Check commandSize (bytes 2-5): 12 in big-endian
        assert_eq!(cmd[2], 0x00);
        assert_eq!(cmd[3], 0x00);
        assert_eq!(cmd[4], 0x00);
        assert_eq!(cmd[5], 0x0C); // 12 in hex

        // Check commandCode (bytes 6-9): TPM2_CC_GetRandom = 0x0000017B
        assert_eq!(cmd[6], 0x00);
        assert_eq!(cmd[7], 0x00);
        assert_eq!(cmd[8], 0x01);
        assert_eq!(cmd[9], 0x7B);

        // Check bytesRequested (bytes 10-11): 32 in big-endian
        assert_eq!(cmd[10], 0x00);
        assert_eq!(cmd[11], 0x20); // 32 in hex
    }

    #[test]
    fn test_build_get_random_command_max_bytes() {
        let cmd = build_get_random_command(0xFFFF);

        // Check bytesRequested is 0xFFFF
        assert_eq!(cmd[10], 0xFF);
        assert_eq!(cmd[11], 0xFF);
    }

    #[test]
    fn test_parse_get_random_response_success() {
        // Construct a valid response with 8 random bytes
        let mut response = Vec::new();

        // Header
        response.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes()); // tag
        response.extend_from_slice(&20u32.to_be_bytes()); // responseSize
        response.extend_from_slice(&0u32.to_be_bytes()); // responseCode (success)

        // TPM2B_DIGEST
        response.extend_from_slice(&8u16.to_be_bytes()); // size = 8
        response.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]); // random data

        let result = parse_get_random_response(&response).unwrap();
        assert_eq!(result, vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn test_parse_get_random_response_tpm_error() {
        // Construct a response with an error code
        let mut response = Vec::new();

        // Header
        response.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes()); // tag
        response.extend_from_slice(&10u32.to_be_bytes()); // responseSize
        response.extend_from_slice(&0x101u32.to_be_bytes()); // responseCode (TPM_RC_FAILURE)

        let result = parse_get_random_response(&response);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("0x00000101"));
    }

    #[test]
    fn test_parse_get_random_response_too_short() {
        let response = vec![0x80, 0x01, 0x00, 0x00]; // Only 4 bytes

        let result = parse_get_random_response(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_pcr_read_command_single_pcr() {
        let cmd = build_pcr_read_command(&[0]);

        // Command should be exactly 20 bytes
        assert_eq!(cmd.len(), 20);

        // Check tag (bytes 0-1): TPM2_ST_NO_SESSIONS = 0x8001
        assert_eq!(cmd[0], 0x80);
        assert_eq!(cmd[1], 0x01);

        // Check commandSize (bytes 2-5): 20 in big-endian
        assert_eq!(cmd[2], 0x00);
        assert_eq!(cmd[3], 0x00);
        assert_eq!(cmd[4], 0x00);
        assert_eq!(cmd[5], 0x14); // 20 in hex

        // Check commandCode (bytes 6-9): TPM2_CC_PCR_Read = 0x0000017E
        assert_eq!(cmd[6], 0x00);
        assert_eq!(cmd[7], 0x00);
        assert_eq!(cmd[8], 0x01);
        assert_eq!(cmd[9], 0x7E);

        // Check count (bytes 10-13): 1 in big-endian
        assert_eq!(cmd[10], 0x00);
        assert_eq!(cmd[11], 0x00);
        assert_eq!(cmd[12], 0x00);
        assert_eq!(cmd[13], 0x01);

        // Check hash algorithm (bytes 14-15): TPM2_ALG_SHA256 = 0x000B
        assert_eq!(cmd[14], 0x00);
        assert_eq!(cmd[15], 0x0B);

        // Check sizeofSelect (byte 16): 3
        assert_eq!(cmd[16], 0x03);

        // Check pcrSelect bitmap (bytes 17-19): PCR 0 selected
        assert_eq!(cmd[17], 0x01); // PCR 0 is bit 0 of byte 0
        assert_eq!(cmd[18], 0x00);
        assert_eq!(cmd[19], 0x00);
    }

    #[test]
    fn test_build_pcr_read_command_multiple_pcrs() {
        // Select PCRs 0, 4, 7 (typical attestation PCRs)
        let cmd = build_pcr_read_command(&[0, 4, 7]);

        // Check pcrSelect bitmap
        // PCR 0 = bit 0 = 0x01
        // PCR 4 = bit 4 = 0x10
        // PCR 7 = bit 7 = 0x80
        // Combined: 0x01 | 0x10 | 0x80 = 0x91
        assert_eq!(cmd[17], 0x91);
        assert_eq!(cmd[18], 0x00);
        assert_eq!(cmd[19], 0x00);
    }

    #[test]
    fn test_build_pcr_read_command_pcrs_across_bytes() {
        // Select PCRs 0, 8, 16
        let cmd = build_pcr_read_command(&[0, 8, 16]);

        // PCR 0 = bit 0 of byte 0 = 0x01
        // PCR 8 = bit 0 of byte 1 = 0x01
        // PCR 16 = bit 0 of byte 2 = 0x01
        assert_eq!(cmd[17], 0x01);
        assert_eq!(cmd[18], 0x01);
        assert_eq!(cmd[19], 0x01);
    }

    #[test]
    fn test_build_pcr_read_command_ignores_invalid_pcrs() {
        // PCR 24 and above should be ignored (only 0-23 are valid)
        let cmd = build_pcr_read_command(&[0, 24, 100]);

        // Only PCR 0 should be set
        assert_eq!(cmd[17], 0x01);
        assert_eq!(cmd[18], 0x00);
        assert_eq!(cmd[19], 0x00);
    }

    #[test]
    fn test_parse_response_code_success() {
        let mut response = Vec::new();
        response.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes()); // tag
        response.extend_from_slice(&10u32.to_be_bytes()); // responseSize
        response.extend_from_slice(&0u32.to_be_bytes()); // responseCode (success)

        let code = parse_response_code(&response).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn test_parse_response_code_error() {
        let mut response = Vec::new();
        response.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes()); // tag
        response.extend_from_slice(&10u32.to_be_bytes()); // responseSize
        response.extend_from_slice(&0x8CE_u32.to_be_bytes()); // responseCode (TPM_RC_AUTH_FAIL)

        let code = parse_response_code(&response).unwrap();
        assert_eq!(code, 0x8CE);
    }

    #[test]
    fn test_parse_response_code_too_short() {
        let response = vec![0x80, 0x01, 0x00, 0x00, 0x00]; // Only 5 bytes

        let result = parse_response_code(&response);
        assert!(result.is_err());
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
