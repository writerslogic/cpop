// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Windows TPM 2.0 provider using the native TBS (TPM Base Services) API.

mod commands;
mod context;
mod helpers;
mod provider;
#[cfg(test)]
mod tests;
mod types;

pub use commands::{
    build_get_random_command, build_pcr_read_command, parse_get_random_response,
    parse_response_code,
};
pub use context::{TbsContext, TpmDeviceInfo};
pub use helpers::{
    build_auth_area_with_password, build_empty_auth_area, build_sealing_public,
    build_srk_public_ecc, create_srk_public_key,
};
pub use provider::{try_init, WindowsTpmProvider};
pub use types::{tbs_error, tbs_result_to_error, TbsError};
