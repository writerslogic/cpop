// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! PDF report generation for Forensic Authorship Examination Reports.
//!
//! Produces self-contained forensic artifact PDFs with anti-forgery security
//! features (guilloche, microtext, void pantograph) derived from the
//! cryptographic seal. The PDF embeds document metadata, a human-readable
//! verification block, and optionally the full CBOR evidence payload.

mod charts;
mod embed;
mod layout;
mod layout_sections;
mod security;

use crate::report::types::WarReport;
use printpdf::*;
use std::io::BufWriter;

/// Render a signed PDF report from a `WarReport`.
///
/// The returned bytes are a complete PDF document ready to write to disk.
/// The PDF includes:
/// - Security features (guilloché, microtext) seeded from `security_seed`
/// - Embedded WAR block in a PDF annotation (for offline verification)
/// - QR code linking to WritersProof verification
///
/// `security_seed` should be `signer.sign(b"cpop-security-v1" || H3)` — a 64-byte
/// value that only the signing key holder can produce.
///
/// # Errors
///
/// Returns an error if font loading or PDF serialization fails (should not happen
/// with built-in fonts under normal conditions).
pub fn render_pdf(report: &WarReport, security_seed: Option<&[u8; 64]>) -> Result<Vec<u8>, String> {
    let version = env!("CARGO_PKG_VERSION");
    let doc_hash_short = report
        .document_hash
        .get(..16)
        .unwrap_or(&report.document_hash);

    let (doc, page1, layer1) = PdfDocument::new(
        format!(
            "Forensic Authorship Examination Report - {}",
            report.report_id
        ),
        Mm(210.0), // A4 width
        Mm(297.0), // A4 height
        "Layer 1",
    );

    // Set PDF document info metadata
    let doc = doc
        .with_author(format!("CPOP Forensic Engine {}", version))
        .with_subject(format!(
            "Authorship examination report for document {}",
            doc_hash_short
        ))
        .with_creator("WritersLogic CPOP Engine")
        .with_producer(format!("cpop-engine/{}", version))
        .with_keywords(vec![
            report.report_id.clone(),
            report.document_hash.clone(),
            report.signing_key_fingerprint.clone(),
            report.verdict.label().to_string(),
            report.enfsi_tier.label().to_string(),
            report.algorithm_version.clone(),
            report.schema_version.clone(),
        ]);

    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| format!("failed to load Helvetica font: {e}"))?;
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| format!("failed to load HelveticaBold font: {e}"))?;
    let font_mono = doc
        .add_builtin_font(BuiltinFont::Courier)
        .map_err(|e| format!("failed to load Courier font: {e}"))?;

    let fonts = PdfFonts {
        regular: font,
        bold: font_bold,
        mono: font_mono,
    };

    let footer = format!(
        "Forensic Authorship Examination Report | {} | {} | {}",
        report.report_id, report.algorithm_version, report.schema_version,
    );

    // Page 1: Header, verdict, declaration, QR
    let current_layer = doc.get_page(page1).get_layer(layer1);
    if let Some(seed) = security_seed {
        security::draw_guilloche_border(&current_layer, seed);
    }
    layout::draw_page1(&current_layer, report, &fonts, security_seed, &footer);

    // Page 2: Evidence analysis, temporal witnesses, flags
    let (page2, layer2) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page2).get_layer(layer2);
    if let Some(seed) = security_seed {
        security::draw_guilloche_border(&current_layer, seed);
    }
    layout_sections::draw_page2(&current_layer, report, &fonts, &footer);

    // Page 3: Scope, verification instructions, verification block
    let (page3, layer3) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page3).get_layer(layer3);
    layout_sections::draw_page3(&current_layer, report, &fonts, &footer);

    // Page 4 (optional): Machine-readable evidence payload
    if report.evidence_cbor_b64.is_some() {
        let (page4, layer4) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
        let current_layer = doc.get_page(page4).get_layer(layer4);
        embed::draw_evidence_page(&current_layer, report, &fonts, &footer);
    }

    // Serialize to bytes
    let mut buf = BufWriter::new(Vec::new());
    doc.save(&mut buf)
        .map_err(|e| format!("PDF serialization failed: {e}"))?;
    buf.into_inner()
        .map_err(|e| format!("PDF buffer flush failed: {e}"))
}

/// Font handles for the PDF document.
pub(crate) struct PdfFonts {
    pub regular: IndirectFontRef,
    pub bold: IndirectFontRef,
    pub mono: IndirectFontRef,
}
