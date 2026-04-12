// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Individual page section renderers for PDF reports (pages 2 and 3).

use super::layout::{
    draw_card, fill_rect, stroke_rect, text, wrap_text_lines, BLACK, CONTENT_WIDTH, GRAY,
    MARGIN_LEFT, PAGE_TOP,
};
use super::PdfFonts;
use printpdf::*;

mod forensics_detail;
mod page2;
mod page3;

pub use forensics_detail::draw_forensics_page;
pub use page2::draw_page2;
pub use page3::draw_page3;

/// Light border color used for card outlines.
const BORDER_COLOR: (f32, f32, f32) = (0.88, 0.88, 0.88);
/// Border thickness in mm (maps to ~0.85 pt).
const BORDER_THICKNESS: f32 = 0.3;
/// White background for cards.
const WHITE: (f32, f32, f32) = (1.0, 1.0, 1.0);
/// Subtle alternating-row tint for tables.
const ALT_ROW: (f32, f32, f32) = (0.98, 0.98, 0.98);
