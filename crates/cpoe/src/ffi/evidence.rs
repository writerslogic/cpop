// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Evidence FFI bindings: shared helpers and re-exports.
//!
//! The actual FFI functions are split across submodules:
//! - `evidence_export`: `ffi_export_evidence`, `ffi_get_compact_ref`
//! - `evidence_checkpoint`: `ffi_create_checkpoint`
//! - `evidence_derivative`: `ffi_link_derivative`, `ffi_export_c2pa_manifest`

pub(crate) use super::helpers::device_identity;
