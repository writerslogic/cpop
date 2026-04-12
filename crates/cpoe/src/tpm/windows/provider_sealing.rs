// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! TPM2 sealing operations: seal, unseal, create_sealed_object, derive_seal_auth_value.

use sha2::{Digest, Sha256};

use super::context::TbsContext;
use super::helpers::{build_auth_area_with_password, build_empty_auth_area, build_sealing_public};
use super::provider::WindowsTpmProvider;
use super::types::*;

impl WindowsTpmProvider {
    pub(super) fn create_sealed_object(
        &self,
        ctx: &TbsContext,
        parent_handle: u32,
        data: &[u8],
    ) -> Result<Vec<u8>, TbsError> {
        let mut body = Vec::new();

        body.extend_from_slice(&parent_handle.to_be_bytes());

        let auth_area = build_empty_auth_area(parent_handle);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        let auth_value = self.derive_seal_auth_value(ctx);
        let sensitive_size = 2 + auth_value.len() + 2 + data.len();
        body.extend_from_slice(&(sensitive_size as u16).to_be_bytes());
        body.extend_from_slice(&(auth_value.len() as u16).to_be_bytes());
        body.extend_from_slice(&auth_value);
        body.extend_from_slice(&(data.len() as u16).to_be_bytes());
        body.extend_from_slice(data);

        let public_area = build_sealing_public();
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

        ctx.submit_command(&cmd)
    }

    pub(super) fn load_object(
        &self,
        ctx: &TbsContext,
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

        ctx.submit_command(&cmd)
    }

    pub(super) fn unseal_object(
        &self,
        ctx: &TbsContext,
        obj_handle: u32,
    ) -> Result<Vec<u8>, TbsError> {
        let mut body = Vec::new();

        body.extend_from_slice(&obj_handle.to_be_bytes());

        let auth_value = self.derive_seal_auth_value(ctx);
        let auth_area = build_auth_area_with_password(obj_handle, &auth_value);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        let mut cmd = Vec::with_capacity(10 + body.len());
        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_UNSEAL.to_be_bytes());
        cmd.extend_from_slice(&body);

        ctx.submit_command(&cmd)
    }

    /// Hardware-bound: derived from TPM device ID and SRK public key so sealed
    /// blobs can't be moved to another machine.
    pub(super) fn derive_seal_auth_value(&self, ctx: &TbsContext) -> zeroize::Zeroizing<Vec<u8>> {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(b"cpoe-seal-auth-v2");
        hasher.update(ctx.device_id().as_bytes());
        hasher.update(&self.public_key);
        let hash = hasher.finalize();
        zeroize::Zeroizing::new(hash[..32].to_vec())
    }
}
