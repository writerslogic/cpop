// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

mod css;
mod helpers;
mod sections;

use super::types::*;
use std::fmt::Write;

/// Render a self-contained HTML report from a `WarReport`.
pub fn render_html(r: &WarReport) -> String {
    let mut html = String::with_capacity(32_000);
    // Writing to a String is infallible (fmt::Write for String never fails),
    // but we propagate fmt::Result for correctness via a helper.
    let _ = render_html_inner(&mut html, r);
    html
}

fn render_html_inner(html: &mut String, r: &WarReport) -> std::fmt::Result {
    css::write_head(html, r)?;
    sections::write_header(html, r)?;
    sections::write_verdict(html, r)?;
    sections::write_enfsi_scale(html, r)?;
    sections::write_chain_of_custody(html, r)?;
    sections::write_category_scores(html, r)?;
    sections::write_session_timeline(html, r)?;
    sections::write_process_evidence(html, r)?;
    sections::write_dimension_analysis(html, r)?;
    sections::write_statistical_methodology(html, r)?;
    sections::write_dimension_lr_table(html, r)?;
    sections::write_checkpoint_chain(html, r)?;
    sections::write_forgery_resistance(html, r)?;
    sections::write_flags(html, r)?;
    sections::write_scope(html, r)?;
    sections::write_analyzed_text(html, r)?;
    sections::write_verification_instructions(html)?;
    sections::write_footer(html, r)?;
    write!(html, "</div></body></html>")
}
