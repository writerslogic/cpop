// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

mod css;
mod helpers;
mod sections;

use super::types::*;
use std::fmt::Write;

/// Render a self-contained HTML report from a `WarReport`.
pub fn render_html(r: &WarReport) -> String {
    let mut html = String::with_capacity(32_000);
    css::write_head(&mut html, r);
    sections::write_header(&mut html, r);
    sections::write_verdict(&mut html, r);
    sections::write_enfsi_scale(&mut html, r);
    sections::write_chain_of_custody(&mut html, r);
    sections::write_category_scores(&mut html, r);
    sections::write_session_timeline(&mut html, r);
    sections::write_process_evidence(&mut html, r);
    sections::write_dimension_analysis(&mut html, r);
    sections::write_statistical_methodology(&mut html, r);
    sections::write_dimension_lr_table(&mut html, r);
    sections::write_checkpoint_chain(&mut html, r);
    sections::write_forgery_resistance(&mut html, r);
    sections::write_flags(&mut html, r);
    sections::write_scope(&mut html, r);
    sections::write_analyzed_text(&mut html, r);
    sections::write_verification_instructions(&mut html);
    sections::write_footer(&mut html, r);
    let _ = write!(html, "</div></body></html>");
    html
}
