// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::super::TpmError;
use super::types::*;

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
pub fn parse_get_random_response(response: &[u8]) -> Result<Vec<u8>, TpmError> {
    if response.len() < TPM2_RESPONSE_HEADER_SIZE {
        return Err(TpmError::Quote(format!(
            "Response too short: {} bytes, expected at least {}",
            response.len(),
            TPM2_RESPONSE_HEADER_SIZE
        )));
    }

    let response_code = parse_response_code(response)?;
    if response_code != 0 {
        return Err(TpmError::Quote(format!(
            "TPM error response code: 0x{:08X}",
            response_code
        )));
    }

    if response.len() < TPM2_RESPONSE_HEADER_SIZE + 2 {
        return Err(TpmError::Quote(
            "Response missing TPM2B_DIGEST size field".to_string(),
        ));
    }

    let digest_size = u16::from_be_bytes([response[10], response[11]]) as usize;

    if response.len() < TPM2_RESPONSE_HEADER_SIZE + 2 + digest_size {
        return Err(TpmError::Quote(format!(
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
pub fn parse_response_code(response: &[u8]) -> Result<u32, TpmError> {
    if response.len() < TPM2_RESPONSE_HEADER_SIZE {
        return Err(TpmError::Quote(format!(
            "Response too short to parse response code: {} bytes",
            response.len()
        )));
    }

    let response_code =
        super::helpers::read_u32_be(response, 6).map_err(|e| TpmError::CommunicationError(e))?;
    Ok(response_code)
}
