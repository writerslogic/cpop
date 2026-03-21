// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! CPOP Authorship Report (WAR) generation.
//!
//! Produces self-contained HTML reports from evidence packets and forensic
//! analysis. Reports follow the WAR-v1.4 schema and ENFSI verbal equivalence
//! scale for likelihood ratios.

mod html;
pub mod pdf;
mod types;

pub use html::render_html;
pub use pdf::render_pdf;
// render_pdf now returns Result<Vec<u8>, String>
pub use types::*;
