// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

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
    use types::TPM2_ST_NO_SESSIONS;

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
    use types::TPM2_ST_NO_SESSIONS;

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
    use types::TPM2_ST_NO_SESSIONS;

    let mut response = Vec::new();
    response.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
    response.extend_from_slice(&10u32.to_be_bytes());
    response.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(parse_response_code(&response).unwrap(), 0);
}

#[test]
fn test_parse_response_code_error() {
    use types::TPM2_ST_NO_SESSIONS;

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
    use super::super::TpmError;

    let err: TpmError = TbsError::TpmNotFound.into();
    assert!(matches!(err, TpmError::NotAvailable));

    let err: TpmError = TbsError::ServiceNotRunning.into();
    assert!(matches!(err, TpmError::NotAvailable));

    let err: TpmError = TbsError::InvalidContext.into();
    assert!(matches!(err, TpmError::NotInitialized));
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
