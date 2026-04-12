// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::report::types::*;

pub fn draw_page2(layer: &PdfLayerReference, r: &WarReport, fonts: &PdfFonts, footer: &str) {
    let mut y = PAGE_TOP;

    // ── 5. Session Timeline ──
    if !r.sessions.is_empty() {
        text(
            layer,
            "5. Session Timeline",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 7.0;

        for s in &r.sessions {
            if y < 20.0 {
                break;
            }
            // White card with thin border
            fill_rect(layer, MARGIN_LEFT, y - 4.0, CONTENT_WIDTH, 12.0, WHITE);
            stroke_rect(
                layer,
                MARGIN_LEFT,
                y - 4.0,
                CONTENT_WIDTH,
                12.0,
                BORDER_THICKNESS,
                BORDER_COLOR,
            );
            // Green left accent border (2mm wide)
            fill_rect(layer, MARGIN_LEFT, y - 4.0, 2.0, 12.0, (0.18, 0.49, 0.20));

            text(
                layer,
                &format!("Session {} — {:.0} min", s.index, s.duration_min),
                8.0,
                MARGIN_LEFT + 6.0,
                y + 3.0,
                &fonts.bold,
                BLACK,
            );
            text(
                layer,
                &s.summary,
                6.0,
                MARGIN_LEFT + 6.0,
                y - 1.5,
                &fonts.regular,
                GRAY,
            );
            y -= 16.0;
        }
    }
    y -= 7.0;

    // ── 6. Process Evidence ──
    text(
        layer,
        "6. Process Evidence",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 7.0;

    let p = &r.process;
    let evidence_items: Vec<(&str, String)> = vec![
        (
            "Revision Intensity",
            p.revision_intensity
                .map(|v| format!("{:.2} edits/sentence", v))
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Pause Distribution",
            p.pause_median_sec
                .map(|v| {
                    let mut s = format!("Median: {:.1}s", v);
                    if let Some(p95) = p.pause_p95_sec {
                        s.push_str(&format!(" | P95: {:.1}s", p95));
                    }
                    s
                })
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Paste Ratio",
            p.paste_ratio_pct
                .map(|v| format!("{:.1}% of total text", v))
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Keystroke Dynamics",
            p.iki_cv
                .map(|v| {
                    let mut s = format!("IKI CV: {:.2}", v);
                    if let Some(bg) = p.bigram_consistency {
                        s.push_str(&format!(" | Bigram: {:.2}", bg));
                    }
                    s
                })
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Deletion Patterns",
            p.deletion_sequences
                .map(|v| {
                    let mut s = format!("{} sequences", v);
                    if let Some(avg) = p.avg_deletion_length {
                        s.push_str(&format!(" | Avg: {:.1} chars", avg));
                    }
                    s
                })
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Time Proofs",
            p.swf_checkpoints
                .map(|v| {
                    let mut s = format!("{} SWF checkpoints", v);
                    if p.swf_chain_verified {
                        s.push_str(" | Chain: verified");
                    }
                    s
                })
                .unwrap_or_else(|| "—".into()),
        ),
    ];

    let col_w = CONTENT_WIDTH / 2.0;
    for (i, (label, value)) in evidence_items.iter().enumerate() {
        let col = i % 2;
        let row = i / 2;
        let ex = MARGIN_LEFT + col as f32 * (col_w + 2.0);
        let ey = y - row as f32 * 16.0;

        // White card with thin border
        fill_rect(layer, ex, ey - 5.0, col_w - 2.0, 14.0, WHITE);
        stroke_rect(
            layer,
            ex,
            ey - 5.0,
            col_w - 2.0,
            14.0,
            BORDER_THICKNESS,
            BORDER_COLOR,
        );
        text(layer, label, 7.0, ex + 4.0, ey + 4.0, &fonts.bold, BLACK);
        text(layer, value, 6.5, ex + 4.0, ey - 0.5, &fonts.regular, GRAY);
    }
    y -= (evidence_items.len() as f32 / 2.0).ceil() * 16.0 + 7.0;

    // ── 7. Analysis Flags ──
    if !r.flags.is_empty() {
        let pos = r
            .flags
            .iter()
            .filter(|f| f.signal == FlagSignal::Human)
            .count();
        let neg = r
            .flags
            .iter()
            .filter(|f| f.signal == FlagSignal::Synthetic)
            .count();
        text(
            layer,
            &format!("7. Analysis Flags ({} positive, {} negative)", pos, neg),
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 6.0;

        // Table header
        text(
            layer,
            "CATEGORY",
            5.5,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.bold,
            GRAY,
        );
        text(layer, "FLAG", 5.5, MARGIN_LEFT + 30.0, y, &fonts.bold, GRAY);
        text(
            layer,
            "SIGNAL",
            5.5,
            MARGIN_LEFT + 130.0,
            y,
            &fonts.bold,
            GRAY,
        );
        y -= 4.0;

        for (row_idx, f) in r.flags.iter().enumerate() {
            if y < 18.0 {
                break;
            }
            // Alternating row backgrounds
            if row_idx % 2 == 0 {
                fill_rect(layer, MARGIN_LEFT, y - 2.0, CONTENT_WIDTH, 5.0, ALT_ROW);
            }

            let signal_color = match f.signal {
                FlagSignal::Human => (0.18_f32, 0.49, 0.20),
                FlagSignal::Synthetic => (0.78, 0.16, 0.16),
                FlagSignal::Neutral => (0.62, 0.62, 0.62),
            };
            let icon = match f.signal {
                FlagSignal::Human => "✓",
                FlagSignal::Synthetic => "✗",
                FlagSignal::Neutral => "—",
            };

            let category_display = if f.category.chars().count() > 40 {
                let truncated: String = f.category.chars().take(40).collect();
                format!("{truncated}...")
            } else {
                f.category.clone()
            };
            let flag_display = if f.flag.chars().count() > 60 {
                let truncated: String = f.flag.chars().take(60).collect();
                format!("{truncated}...")
            } else {
                f.flag.clone()
            };
            text(
                layer,
                &category_display,
                6.5,
                MARGIN_LEFT + 2.0,
                y,
                &fonts.regular,
                BLACK,
            );
            text(
                layer,
                &flag_display,
                6.5,
                MARGIN_LEFT + 30.0,
                y,
                &fonts.regular,
                BLACK,
            );
            text(
                layer,
                &format!("{} {}", icon, f.signal.label()),
                6.5,
                MARGIN_LEFT + 130.0,
                y,
                &fonts.bold,
                signal_color,
            );
            y -= 5.0;
        }
    }

    // Footer
    text(layer, footer, 5.0, MARGIN_LEFT, 10.0, &fonts.regular, GRAY);
}
