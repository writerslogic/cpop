// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Evidence FFI bindings: shared helpers and re-exports.
//!
//! The actual FFI functions are split across submodules:
//! - `evidence_export`: `ffi_export_evidence`, `ffi_get_compact_ref`
//! - `evidence_checkpoint`: `ffi_create_checkpoint`
//! - `evidence_derivative`: `ffi_link_derivative`, `ffi_export_c2pa_manifest`

use std::sync::OnceLock;

/// Cached device identity for populating evidence events (EH-013).
static DEVICE_IDENTITY: OnceLock<([u8; 16], String)> = OnceLock::new();

pub(crate) fn device_identity() -> &'static ([u8; 16], String) {
    DEVICE_IDENTITY.get_or_init(|| {
        match crate::identity::secure_storage::SecureStorage::load_device_identity() {
            Ok(Some(identity)) => identity,
            Ok(None) | Err(_) => {
                log::error!(
                    "SecureStorage device identity unavailable; using random ephemeral device ID"
                );
                let mut fallback_id = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rand::rng(), &mut fallback_id);
                let machine_id =
                    sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
                (fallback_id, machine_id)
            }
        }
    })
}
