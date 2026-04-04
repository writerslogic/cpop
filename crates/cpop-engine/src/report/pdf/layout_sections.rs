// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Individual page section renderers for PDF reports (pages 2 and 3).

use super::layout::{
    draw_card, fill_rect, stroke_rect, text, wrap_text_lines, BLACK, CONTENT_WIDTH, GRAY,
    MARGIN_LEFT, PAGE_TOP,
};
use super::PdfFonts;
use crate::report::types::*;
use crate::utils::finite_or;
use printpdf::*;

/// Light border color used for card outlines.
const BORDER_COLOR: (f32, f32, f32) = (0.88, 0.88, 0.88);
/// Border thickness in mm (maps to ~0.85 pt).
const BORDER_THICKNESS: f32 = 0.3;
/// White background for cards.
const WHITE: (f32, f32, f32) = (1.0, 1.0, 1.0);
/// Subtle alternating-row tint for tables.
const ALT_ROW: (f32, f32, f32) = (0.98, 0.98, 0.98);

// ── Page 2 ────────────────────────────────────────────────────────────

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

// ── Page 3 ────────────────────────────────────────────────────────────

pub fn draw_page3(layer: &PdfLayerReference, r: &WarReport, fonts: &PdfFonts, footer: &str) {
    let mut y = PAGE_TOP;

    // ── 8. Scope & Limitations ──
    text(
        layer,
        "8. Scope and Limitations",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 7.0;

    let supports = [
        "Evidence of human cognitive constraint patterns",
        "Stylometric consistency with natural authorship",
        "Documented methodology for dispute review",
        "Reproducible analysis (same text + algorithm = same results)",
    ];
    text(
        layer,
        "What This Report Supports:",
        7.0,
        MARGIN_LEFT + 2.0,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 4.0;
    for item in &supports {
        text(
            layer,
            &format!("• {}", item),
            6.0,
            MARGIN_LEFT + 4.0,
            y,
            &fonts.regular,
            BLACK,
        );
        y -= 4.0;
    }
    y -= 2.0;

    let does_not = [
        "Named author identity (requires additional evidence)",
        "AI was not used at any point in the process",
        "Text has not been edited, paraphrased, or translated",
        "Definitive attribution beyond reasonable doubt",
    ];
    text(
        layer,
        "What This Report Does NOT Prove:",
        7.0,
        MARGIN_LEFT + 2.0,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 4.0;
    for item in &does_not {
        text(
            layer,
            &format!("• {}", item),
            6.0,
            MARGIN_LEFT + 4.0,
            y,
            &fonts.regular,
            BLACK,
        );
        y -= 4.0;
    }
    y -= 7.0;

    // ── 9. Verification Instructions ──
    text(
        layer,
        "9. Independent Verification",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 8.0;

    let box_h = 28.0;
    let half_w = CONTENT_WIDTH / 2.0 - 2.0;

    // Offline box: white with border
    fill_rect(layer, MARGIN_LEFT, y - 24.0, half_w, box_h, WHITE);
    stroke_rect(
        layer,
        MARGIN_LEFT,
        y - 24.0,
        half_w,
        box_h,
        BORDER_THICKNESS,
        BORDER_COLOR,
    );
    text(
        layer,
        "OFFLINE VERIFICATION",
        7.0,
        MARGIN_LEFT + 5.0,
        y,
        &fonts.bold,
        BLACK,
    );
    text(
        layer,
        "Extract WAR seal from PDF → verify Ed25519",
        5.5,
        MARGIN_LEFT + 5.0,
        y - 5.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "signature → verify enrollment cert chain",
        5.5,
        MARGIN_LEFT + 5.0,
        y - 9.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "Run: cpop verify <file.pdf>",
        6.0,
        MARGIN_LEFT + 5.0,
        y - 17.0,
        &fonts.mono,
        BLACK,
    );

    // Online box: white with border
    let ox = MARGIN_LEFT + CONTENT_WIDTH / 2.0 + 2.0;
    fill_rect(layer, ox, y - 24.0, half_w, box_h, WHITE);
    stroke_rect(
        layer,
        ox,
        y - 24.0,
        half_w,
        box_h,
        BORDER_THICKNESS,
        BORDER_COLOR,
    );
    text(
        layer,
        "ONLINE VERIFICATION",
        7.0,
        ox + 5.0,
        y,
        &fonts.bold,
        BLACK,
    );
    text(
        layer,
        "All offline checks + transparency log",
        5.5,
        ox + 5.0,
        y - 5.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "anchor + certificate revocation check",
        5.5,
        ox + 5.0,
        y - 9.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "Scan QR or visit writersproof.com/verify",
        6.0,
        ox + 5.0,
        y - 17.0,
        &fonts.mono,
        BLACK,
    );
    y -= 34.0;

    // ── Additional Limitations ──
    if !r.limitations.is_empty() {
        text(
            layer,
            "Additional Limitations:",
            7.0,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 4.0;
        for lim in &r.limitations {
            text(
                layer,
                &format!("• {}", lim),
                6.0,
                MARGIN_LEFT + 4.0,
                y,
                &fonts.regular,
                BLACK,
            );
            y -= 4.0;
        }
    }
    y -= 7.0;

    // ── 10. Analyzed Text (if available) ──
    if let Some(ref analyzed) = r.analyzed_text {
        text(
            layer,
            "10. Analyzed Text",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 3.0;
        text(
            layer,
            "Document hash verified against chain of custody record.",
            5.5,
            MARGIN_LEFT,
            y,
            &fonts.regular,
            GRAY,
        );
        y -= 5.0;

        // White box with thin border
        fill_rect(layer, MARGIN_LEFT, y - 60.0, CONTENT_WIDTH, 62.0, WHITE);
        stroke_rect(
            layer,
            MARGIN_LEFT,
            y - 60.0,
            CONTENT_WIDTH,
            62.0,
            BORDER_THICKNESS,
            BORDER_COLOR,
        );

        // Word-wrap the text into the box
        let mut ty = y - 3.0;
        for line in wrap_text_lines(analyzed, 100) {
            text(
                layer,
                &line,
                6.5,
                MARGIN_LEFT + 5.0,
                ty,
                &fonts.regular,
                BLACK,
            );
            ty -= 4.0;
            if ty < y - 58.0 {
                text(
                    layer,
                    "[continued...]",
                    5.5,
                    MARGIN_LEFT + 5.0,
                    ty,
                    &fonts.regular,
                    GRAY,
                );
                break;
            }
        }
    }

    // ── VERIFICATION BLOCK ──
    // Visually distinct bordered block as the human-readable trust anchor.
    let vb_h = 42.0;
    let vb_y = 22.0;
    // Dark border
    stroke_rect(
        layer,
        MARGIN_LEFT,
        vb_y,
        CONTENT_WIDTH,
        vb_h,
        0.8,
        (0.13, 0.13, 0.13),
    );
    // Light inner background
    fill_rect(
        layer,
        MARGIN_LEFT + 0.4,
        vb_y + 0.4,
        CONTENT_WIDTH - 0.8,
        vb_h - 0.8,
        (0.97, 0.97, 0.99),
    );

    let mut vy = vb_y + vb_h - 4.0;
    text(
        layer,
        "VERIFICATION",
        9.0,
        MARGIN_LEFT + 4.0,
        vy,
        &fonts.bold,
        BLACK,
    );
    vy -= 5.5;

    let lr_str = if r.likelihood_ratio >= 100.0 {
        format!("{:.0}", r.likelihood_ratio)
    } else {
        format!("{:.1}", r.likelihood_ratio)
    };
    let vb_rows: Vec<(&str, String)> = vec![
        ("Report ID:", r.report_id.clone()),
        ("Document Hash (SHA-256):", r.document_hash.clone()),
        (
            "Evidence Hash:",
            r.evidence_hash.clone().unwrap_or_else(|| "N/A".to_string()),
        ),
        ("Signing Key:", r.signing_key_fingerprint.clone()),
        (
            "Assessment:",
            format!("{}/100 | LR {} | {}", r.score, lr_str, r.enfsi_tier.label()),
        ),
        (
            "Generated:",
            r.generated_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        ),
        ("Verify:", "https://writersproof.com/verify".to_string()),
    ];
    for (label, value) in &vb_rows {
        text(layer, label, 5.5, MARGIN_LEFT + 4.0, vy, &fonts.bold, BLACK);
        // Truncate long hashes for display
        let display = if value.len() > 72 {
            format!(
                "{}...{}",
                value.get(..32).unwrap_or(value),
                value.get(value.len().saturating_sub(8)..).unwrap_or(value),
            )
        } else {
            value.clone()
        };
        text(
            layer,
            &display,
            5.0,
            MARGIN_LEFT + 40.0,
            vy,
            &fonts.mono,
            (0.20, 0.20, 0.20),
        );
        vy -= 4.5;
    }

    // ── Disclaimer / Footer ──
    text(
        layer,
        "This report documents process analysis only. It does not constitute legal advice or definitive proof of authorship.",
        5.0,
        MARGIN_LEFT,
        15.0,
        &fonts.regular,
        GRAY,
    );
    text(layer, footer, 5.0, MARGIN_LEFT, 10.0, &fonts.regular, GRAY);
}

// ── Forensics Detail Page ────────────────────────────────────────────

pub(super) fn draw_forensics_page(
    layer: &PdfLayerReference,
    report: &WarReport,
    fonts: &PdfFonts,
    footer: &str,
) {
    let mut y = PAGE_TOP;

    // ── Page Title ──
    text(
        layer,
        "Forensic Analysis Details",
        12.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 10.0;

    // ── Writing Mode Section ──
    if let Some(ref fm) = report.forensic_metrics {
        text(
            layer,
            "Writing Mode",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 7.0;

        // Writing mode badge
        let mode_color = match fm.writing_mode.as_str() {
            "Cognitive" => (0.18, 0.49, 0.20),
            "Transcriptive" => (0.78, 0.16, 0.16),
            _ => (0.96, 0.50, 0.09), // Mixed / unknown
        };
        fill_rect(layer, MARGIN_LEFT, y - 1.5, 30.0, 7.0, mode_color);
        text(
            layer,
            &fm.writing_mode,
            7.0,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.bold,
            WHITE,
        );

        // Risk level badge
        let risk_color = match fm.risk_level.as_str() {
            "Low" => (0.18, 0.49, 0.20),
            "Medium" => (0.96, 0.50, 0.09),
            _ => (0.78, 0.16, 0.16), // High / Critical
        };
        fill_rect(layer, MARGIN_LEFT + 34.0, y - 1.5, 24.0, 7.0, risk_color);
        text(
            layer,
            &format!("Risk: {}", fm.risk_level),
            6.0,
            MARGIN_LEFT + 36.0,
            y,
            &fonts.bold,
            WHITE,
        );
        y -= 10.0;

        // Cognitive score bar
        let cog_f = if fm.cognitive_score.is_finite() {
            fm.cognitive_score
        } else {
            0.0
        };
        let cog_score = (cog_f * 100.0).round().clamp(0.0, 100.0) as u32;
        super::charts::draw_score_bar(
            layer,
            &fonts.regular,
            &fonts.bold,
            "Cognitive",
            cog_score,
            (0.13, 0.59, 0.95),
            MARGIN_LEFT + 2.0,
            y,
            100.0,
        );
        y -= 8.0;

        // Revision cycle count and Hurst exponent
        text(
            layer,
            &format!("Revision Cycles: {}", fm.revision_cycle_count),
            7.0,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.regular,
            BLACK,
        );
        if let Some(hurst) = fm.hurst_exponent.filter(|v| v.is_finite()) {
            text(
                layer,
                &format!("Hurst Exponent: {:.3}", hurst),
                7.0,
                MARGIN_LEFT + 60.0,
                y,
                &fonts.regular,
                BLACK,
            );
        }
        y -= 12.0;

        // ── Cadence Metrics (2x3 grid of cards) ──
        text(
            layer,
            "Cadence Metrics",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 7.0;

        let metrics: [(&str, String); 6] = [
            ("Mean IKI (ms)", format!("{:.1}", finite_or(fm.mean_iki_ms, 0.0))),
            ("CV", format!("{:.3}", finite_or(fm.coefficient_of_variation, 0.0))),
            ("Burst Count", format!("{}", fm.burst_count)),
            ("Pause Count", format!("{}", fm.pause_count)),
            ("Correction Ratio", format!("{:.3}", finite_or(fm.correction_ratio, 0.0))),
            ("Burst Speed CV", format!("{:.3}", finite_or(fm.burst_speed_cv, 0.0))),
        ];

        let card_w = (CONTENT_WIDTH - 4.0) / 3.0;
        let card_h = 14.0;
        for (i, (label, value)) in metrics.iter().enumerate() {
            let col = i % 3;
            let row = i / 3;
            let cx = MARGIN_LEFT + col as f32 * (card_w + 2.0);
            let cy = y - row as f32 * (card_h + 2.0);

            draw_card(layer, cx, cy - card_h, card_w, card_h);
            text(layer, label, 6.0, cx + 3.0, cy - 3.0, &fonts.bold, GRAY);
            text(layer, value, 9.0, cx + 3.0, cy - 9.0, &fonts.bold, BLACK);
        }
        y -= 2.0 * (card_h + 2.0) + 7.0;
    }

    // ── Edit Topology ──
    if !report.edit_topology.is_empty() && y > 40.0 {
        text(
            layer,
            "Edit Distribution Across Document",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 4.0;

        super::charts::draw_topology_bar(
            layer,
            &report.edit_topology,
            MARGIN_LEFT,
            y - 10.0,
            CONTENT_WIDTH,
            10.0,
        );
        y -= 14.0;
        text(
            layer,
            "Green = insertions, Red = deletions, Gray = no edits",
            5.5,
            MARGIN_LEFT,
            y,
            &fonts.regular,
            GRAY,
        );
        y -= 10.0;
    }

    // ── Activity Context Timeline ──
    if !report.activity_contexts.is_empty() && y > 30.0 {
        text(
            layer,
            "Activity Timeline",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 4.0;

        super::charts::draw_context_timeline(
            layer,
            &report.activity_contexts,
            MARGIN_LEFT,
            y - 8.0,
            CONTENT_WIDTH,
            8.0,
        );
        y -= 12.0;
        text(
            layer,
            "Green=focused  Gray=break  Blue=research  Orange=revision",
            5.5,
            MARGIN_LEFT,
            y,
            &fonts.regular,
            GRAY,
        );
        y -= 10.0;
    }

    // ── Anomalies Table ──
    if !report.anomalies.is_empty() && y > 30.0 {
        text(
            layer,
            &format!("Anomalies ({})", report.anomalies.len()),
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
            "SEVERITY",
            5.5,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.bold,
            GRAY,
        );
        text(layer, "TYPE", 5.5, MARGIN_LEFT + 28.0, y, &fonts.bold, GRAY);
        text(
            layer,
            "DESCRIPTION",
            5.5,
            MARGIN_LEFT + 60.0,
            y,
            &fonts.bold,
            GRAY,
        );
        y -= 4.0;

        for (row_idx, anomaly) in report.anomalies.iter().enumerate() {
            if y < 18.0 {
                break;
            }
            if row_idx % 2 == 0 {
                fill_rect(layer, MARGIN_LEFT, y - 2.0, CONTENT_WIDTH, 5.0, ALT_ROW);
            }

            let sev_color = match anomaly.severity.as_str() {
                "Alert" => (0.78_f32, 0.16, 0.16),
                "Warning" => (0.90, 0.45, 0.00),
                _ => (0.13, 0.47, 0.78), // Info / other
            };
            text(
                layer,
                &anomaly.severity,
                6.5,
                MARGIN_LEFT + 2.0,
                y,
                &fonts.bold,
                sev_color,
            );

            let type_display = if anomaly.anomaly_type.len() > 20 {
                let t: String = anomaly.anomaly_type.chars().take(20).collect();
                format!("{t}...")
            } else {
                anomaly.anomaly_type.clone()
            };
            text(
                layer,
                &type_display,
                6.5,
                MARGIN_LEFT + 28.0,
                y,
                &fonts.regular,
                BLACK,
            );

            let desc_display = if anomaly.description.len() > 65 {
                let d: String = anomaly.description.chars().take(65).collect();
                format!("{d}...")
            } else {
                anomaly.description.clone()
            };
            text(
                layer,
                &desc_display,
                6.0,
                MARGIN_LEFT + 60.0,
                y,
                &fonts.regular,
                BLACK,
            );

            y -= 5.0;
        }
    }

    // ── Footer ──
    text(layer, footer, 5.0, MARGIN_LEFT, 10.0, &fonts.regular, GRAY);
}
