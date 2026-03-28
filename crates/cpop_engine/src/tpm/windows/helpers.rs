// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::context::TbsContext;
use super::types::*;

pub fn read_u32_be(data: &[u8], offset: usize) -> Result<u32, String> {
    data.get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| format!("buffer too short at offset {offset}"))
}

pub fn build_empty_auth_area(handle: u32) -> Vec<u8> {
    build_auth_area_with_password(handle, &[])
}

/// Build a TPM_RS_PW authorization area with the given password.
///
/// # Panics
/// Panics if `password.len() > 65535` (TPM auth value size limit).
pub fn build_auth_area_with_password(handle: u32, password: &[u8]) -> Vec<u8> {
    assert!(
        password.len() <= u16::MAX as usize,
        "TPM auth password exceeds u16 max"
    );
    let mut auth = Vec::new();
    auth.extend_from_slice(&0x40000009u32.to_be_bytes()); // TPM_RS_PW
    auth.extend_from_slice(&0u16.to_be_bytes());
    auth.push(0x01);
    auth.extend_from_slice(&(password.len() as u16).to_be_bytes());
    auth.extend_from_slice(password);
    auth
}

/// Build a TPMT_PUBLIC for an ECC P-256 Storage Root Key.
pub fn build_srk_public_ecc() -> Vec<u8> {
    let mut public = Vec::new();

    public.extend_from_slice(&TPM2_ALG_ECC.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes());

    // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | restricted | decrypt
    let attrs: u32 = 0x00030472;
    public.extend_from_slice(&attrs.to_be_bytes());

    public.extend_from_slice(&0u16.to_be_bytes()); // authPolicy (empty)
    public.extend_from_slice(&TPM2_ALG_AES.to_be_bytes());
    public.extend_from_slice(&128u16.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_CFB.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes()); // scheme
    public.extend_from_slice(&TPM2_ECC_NIST_P256.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes()); // kdf

    public.extend_from_slice(&0u16.to_be_bytes()); // unique.x (empty)
    public.extend_from_slice(&0u16.to_be_bytes()); // unique.y (empty)

    public
}

/// Create the ECC P-256 SRK via TPM2_CreatePrimary and return its public key.
///
/// The SRK is deterministic — same template + same TPM hierarchy = same key on every call.
/// Returns the 64-byte uncompressed ECC point (x || y).
pub fn create_srk_public_key(context: &TbsContext) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    body.extend_from_slice(&TPM2_RH_OWNER.to_be_bytes());
    let auth_area = build_empty_auth_area(TPM2_RH_OWNER);
    body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
    body.extend_from_slice(&auth_area);
    // inSensitive: 4-byte header (empty userAuth + empty data)
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    let public_area = build_srk_public_ecc();
    body.extend_from_slice(&(public_area.len() as u16).to_be_bytes());
    body.extend_from_slice(&public_area);
    body.extend_from_slice(&0u16.to_be_bytes()); // outsideInfo (empty)
    body.extend_from_slice(&0u32.to_be_bytes()); // creationPCR (none)

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
    let rc = read_u32_be(&response, 6)?;
    if rc != TPM_RC_SUCCESS {
        return Err(format!("TPM2_CreatePrimary rc=0x{rc:08X}"));
    }
    let handle = read_u32_be(&response, 10)?;

    // Walk the TPMT_PUBLIC structure to reach the ECC point at the end.
    // Field sizes are per TPM 2.0 Part 2, Section 12.2.4.
    let mut offset = 18;
    if offset + 2 > response.len() {
        return Err("Missing outPublic size".into());
    }
    offset += 2; // outPublic size
    offset += 2 + 2 + 4; // type + nameAlg + objectAttributes

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
        offset += 2 + 2; // keyBits + mode
    }
    if offset + 2 > response.len() {
        return Err("Missing scheme".into());
    }
    let scheme_alg = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    if scheme_alg != TPM2_ALG_NULL {
        offset += 2;
    }
    offset += 2; // curveID
    if offset + 2 > response.len() {
        return Err("Missing kdf".into());
    }
    let kdf_alg = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    if kdf_alg != TPM2_ALG_NULL {
        offset += 2;
    }

    // TPMS_ECC_POINT: TPM2B_ECC_PARAMETER(size + data) for x and y
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

    // Flush transient primary — we only needed the public point
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

/// Build a TPMT_PUBLIC for an ECC P-256 signing-only key (child of SRK).
///
/// Attributes: fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign
/// Scheme: ECDSA with SHA-256.
pub fn build_signing_key_public_ecc() -> Vec<u8> {
    let mut public = Vec::new();

    public.extend_from_slice(&TPM2_ALG_ECC.to_be_bytes()); // type
    public.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes()); // nameAlg

    // fixedTPM(0x02) | fixedParent(0x10) | sensitiveDataOrigin(0x20) | userWithAuth(0x40) | sign(0x40000)
    let attrs: u32 = 0x00040072;
    public.extend_from_slice(&attrs.to_be_bytes());

    public.extend_from_slice(&0u16.to_be_bytes()); // authPolicy (empty)
    public.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes()); // symmetric (none for signing key)
    public.extend_from_slice(&TPM2_ALG_ECDSA.to_be_bytes()); // scheme = ECDSA
    public.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes()); // scheme.hashAlg
    public.extend_from_slice(&TPM2_ECC_NIST_P256.to_be_bytes()); // curveID
    public.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes()); // kdf (none)

    public.extend_from_slice(&0u16.to_be_bytes()); // unique.x (empty — TPM generates)
    public.extend_from_slice(&0u16.to_be_bytes()); // unique.y (empty)

    public
}

/// Build a TPMT_PUBLIC for a KeyedHash sealing object.
pub fn build_sealing_public() -> Vec<u8> {
    let mut public = Vec::new();

    public.extend_from_slice(&TPM2_ALG_KEYEDHASH.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes());

    // fixedTPM | fixedParent | userWithAuth
    let attrs: u32 = 0x00000052;
    public.extend_from_slice(&attrs.to_be_bytes());

    public.extend_from_slice(&0u16.to_be_bytes()); // authPolicy (empty)
    public.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes()); // scheme
    public.extend_from_slice(&0u16.to_be_bytes()); // unique (empty)

    public
}
