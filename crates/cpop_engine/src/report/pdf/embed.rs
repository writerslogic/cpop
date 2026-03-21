// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Embedding of WAR block and verification data in PDF metadata.
//!
//! The PDF embeds the ASCII-armored WAR block and compact reference
//! as custom metadata fields. This enables offline extraction and
//! verification without the WritersProof API.

/// Build a QR code image for embedding in the PDF.
///
/// The QR encodes a data URI (not a URL) containing the compact reference
/// and public key fingerprint, preventing URL spoofing attacks.
#[allow(dead_code)]
pub fn generate_qr_png(data: &str) -> Option<Vec<u8>> {
    use qrcode::render::svg;
    use qrcode::QrCode;

    let code = QrCode::new(data.as_bytes()).ok()?;
    let svg_str = code.render::<svg::Color>().min_dimensions(100, 100).build();

    // printpdf doesn't natively handle SVG, so we return the SVG string
    // as bytes for now. The layout module handles placement.
    Some(svg_str.into_bytes())
}

/// Format the compact reference for QR embedding.
///
/// Format: `cpop:verify:1:<compact-ref>:<pubkey-fingerprint>`
/// Example: `cpop:verify:1:pop-ref:writerslogic:7f83b165:14:ed25519:9b2f7a3c`
#[allow(dead_code)]
pub fn format_qr_data(compact_ref: &str, pubkey_fingerprint: &str) -> String {
    format!("cpop:verify:1:{}:{}", compact_ref, pubkey_fingerprint)
}
