// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

mod css;
mod helpers;
mod sections;

use super::types::*;
use std::fmt::Write;

/// Render a self-contained HTML report from a `WarReport`.
pub fn render_html(r: &WarReport) -> String {
    let mut html = String::new();
    html.reserve(48_000);
    // String::write_fmt is infallible; the expect documents that invariant.
    render_html_inner(&mut html, r).expect("infallible: String::Write");
    html
}

fn render_html_inner(html: &mut String, r: &WarReport) -> std::fmt::Result {
    css::write_head(html, r)?;

    // Document title
    sections::write_header(html, r)?;

    // Formal examination metadata block
    sections::write_examination_metadata(html, r)?;

    // Executive summary (plain-English for non-technical readers)
    sections::write_executive_summary(html, r)?;

    // Declaration of findings (score, verdict, LR, ENFSI)
    sections::write_verdict(html, r)?;
    sections::write_enfsi_scale(html, r)?;
    sections::write_lr_interpretation(html, r)?;
    sections::write_key_findings(html, r)?;

    // Methodology with explicit hypotheses
    sections::write_methodology(html, r)?;

    // Chain of evidence
    sections::write_chain_of_custody(html, r)?;

    // Author declaration
    sections::write_declaration_summary(html, r)?;

    // Key hierarchy
    sections::write_key_hierarchy(html, r)?;

    // Category scores + writing flow
    sections::write_category_scores(html, r)?;

    // Process evidence (exhibits A-F, dynamic notes)
    sections::write_process_evidence(html, r)?;

    // Forensic breakdown
    sections::write_forensic_breakdown(html, r)?;

    // Edit topology
    sections::write_edit_topology(html, r)?;

    // Session timeline
    sections::write_session_timeline(html, r)?;

    // Activity contexts
    sections::write_activity_contexts(html, r)?;

    // Hardware attestation
    sections::write_hardware_attestation(html, r)?;

    // Detailed dimension analysis
    sections::write_dimension_analysis(html, r)?;

    // Per-dimension LR table
    sections::write_dimension_lr_table(html, r)?;

    // Checkpoint chain
    sections::write_checkpoint_chain(html, r)?;

    // Forgery resistance
    sections::write_forgery_resistance(html, r)?;

    // Analysis flags
    sections::write_flags(html, r)?;

    // Anomaly details
    sections::write_anomalies_detail(html, r)?;

    // Scope, limitations, admissibility
    sections::write_scope(html, r)?;

    // Analyzed text
    sections::write_analyzed_text(html, r)?;

    // Verification instructions
    sections::write_verification_instructions(html)?;

    // Glossary
    sections::write_glossary(html)?;

    // Verifiable Credential
    sections::write_verifiable_credential(html, r)?;

    // Embedded evidence (self-verifying artifact)
    sections::write_embedded_evidence(html, r)?;

    // Certification
    sections::write_footer(html, r)?;

    write!(html, "</div></body></html>")
}
