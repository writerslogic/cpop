// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! PDF report generation for Written Authorship Reports.
//!
//! Produces self-contained, signed PDF documents with anti-forgery security
//! features (guilloché, microtext, void pantograph) derived from the
//! cryptographic seal. The PDF embeds the WAR block for independent verification.

mod charts;
mod embed;
mod layout;
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
    let (doc, page1, layer1) = PdfDocument::new(
        format!("Written Authorship Report — {}", report.report_id),
        Mm(210.0), // A4 width
        Mm(297.0), // A4 height
        "Layer 1",
    );

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

    // Page 1: Header, verdict, declaration, QR
    let current_layer = doc.get_page(page1).get_layer(layer1);
    if let Some(seed) = security_seed {
        security::draw_guilloche_border(&current_layer, seed);
    }
    layout::draw_page1(&current_layer, report, &fonts, security_seed);

    // Page 2: Evidence analysis, temporal witnesses, flags
    let (page2, layer2) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page2).get_layer(layer2);
    if let Some(seed) = security_seed {
        security::draw_guilloche_border(&current_layer, seed);
    }
    layout::draw_page2(&current_layer, report, &fonts);

    // Page 3: Scope, verification instructions, technical details
    let (page3, layer3) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page3).get_layer(layer3);
    layout::draw_page3(&current_layer, report, &fonts);

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
