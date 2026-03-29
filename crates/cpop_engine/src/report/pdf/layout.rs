// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Page layout and text placement for PDF reports.

use super::charts;
use super::security;
use super::PdfFonts;
use crate::report::types::*;
use printpdf::*;

/// Split text into lines using word boundaries, respecting a max character width.
fn wrap_text_lines(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line.push_str(word);
        } else if current_line.len() + 1 + word.len() > max_chars {
            lines.push(std::mem::take(&mut current_line));
            current_line.push_str(word);
        } else {
            current_line.push(' ');
            current_line.push_str(word);
        }
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }
    lines
}

const MARGIN_LEFT: f32 = 20.0;
// Page right margin (used for future right-aligned elements).
#[allow(dead_code)]
const MARGIN_RIGHT: f32 = 190.0;
const PAGE_TOP: f32 = 280.0;
const CONTENT_WIDTH: f32 = 170.0;

/// Color for each tier badge.
fn tier_color(tier: &str) -> (f32, f32, f32) {
    match tier {
        "T1" => (0.62, 0.62, 0.62), // gray
        "T2" => (0.13, 0.59, 0.95), // blue
        "T3" => (0.18, 0.49, 0.20), // green
        "T4" => (0.83, 0.68, 0.21), // gold
        _ => (0.62, 0.62, 0.62),
    }
}

fn verdict_color(verdict: &Verdict) -> (f32, f32, f32) {
    match verdict {
        Verdict::VerifiedHuman => (0.18, 0.49, 0.20),
        Verdict::LikelyHuman => (0.34, 0.55, 0.18),
        Verdict::Inconclusive => (0.96, 0.50, 0.09),
        Verdict::Suspicious => (0.90, 0.32, 0.00),
        Verdict::LikelySynthetic => (0.72, 0.11, 0.11),
    }
}

/// Dimension bar colors.
fn dimension_color(name: &str) -> (f32, f32, f32) {
    match name.to_lowercase().as_str() {
        "temporal" => (0.13, 0.59, 0.95),
        "behavioral" => (0.30, 0.69, 0.31),
        "linguistic" => (0.61, 0.15, 0.69),
        "structural" => (1.00, 0.60, 0.00),
        _ => (0.47, 0.56, 0.61),
    }
}

/// Draw a colored rectangle.
fn fill_rect(layer: &PdfLayerReference, x: f32, y: f32, w: f32, h: f32, color: (f32, f32, f32)) {
    layer.set_fill_color(Color::Rgb(Rgb::new(color.0, color.1, color.2, None)));
    layer.add_rect(Rect::new(Mm(x), Mm(y), Mm(x + w), Mm(y + h)));
}

/// Draw text at position.
fn text(
    layer: &PdfLayerReference,
    s: &str,
    size: f32,
    x: f32,
    y: f32,
    font: &IndirectFontRef,
    color: (f32, f32, f32),
) {
    layer.set_fill_color(Color::Rgb(Rgb::new(color.0, color.1, color.2, None)));
    layer.use_text(s, size, Mm(x), Mm(y), font);
}

const BLACK: (f32, f32, f32) = (0.13, 0.13, 0.13);
const GRAY: (f32, f32, f32) = (0.38, 0.38, 0.38);
const WHITE: (f32, f32, f32) = (1.0, 1.0, 1.0);

// ── Page 1 ────────────────────────────────────────────────────────────

pub fn draw_page1(
    layer: &PdfLayerReference,
    r: &WarReport,
    fonts: &PdfFonts,
    security_seed: Option<&[u8; 64]>,
) {
    let mut y = PAGE_TOP;

    // Title
    text(
        layer,
        "Written Authorship Report",
        18.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 6.0;

    // Subtitle
    let subtitle = format!(
        "Report {} | Algorithm {} | {}",
        r.report_id,
        r.algorithm_version,
        r.generated_at.format("%B %-d, %Y"),
    );
    text(layer, &subtitle, 7.0, MARGIN_LEFT, y, &fonts.regular, GRAY);
    y -= 4.0;

    if r.is_sample {
        text(
            layer,
            "SAMPLE",
            7.0,
            MARGIN_LEFT + 140.0,
            y + 4.0,
            &fonts.bold,
            GRAY,
        );
    }

    // Microtext rule line
    if let Some(_seed) = security_seed {
        let micro = format!(
            "{} · {}",
            r.report_id,
            r.document_hash.get(..16).unwrap_or("")
        );
        security::draw_microtext(layer, &fonts.mono, y, &micro, 210.0);
    }
    y -= 6.0;

    // ── Tier Badge ──
    // Derive tier from score
    let tier_label = match r.score {
        80..=100 => "T4",
        60..=79 => "T3",
        40..=59 => "T2",
        _ => "T1",
    };
    let tc = tier_color(tier_label);
    fill_rect(layer, MARGIN_LEFT, y - 2.0, 30.0, 12.0, tc);
    text(
        layer,
        tier_label,
        12.0,
        MARGIN_LEFT + 3.0,
        y,
        &fonts.bold,
        WHITE,
    );
    let tier_name = match tier_label {
        "T1" => "BASIC",
        "T2" => "STANDARD",
        "T3" => "ENHANCED",
        "T4" => "MAXIMUM",
        _ => "",
    };
    text(
        layer,
        tier_name,
        8.0,
        MARGIN_LEFT + 14.0,
        y + 1.0,
        &fonts.bold,
        WHITE,
    );
    y -= 16.0;

    // ── Verdict Banner ──
    let vc = verdict_color(&r.verdict);
    fill_rect(layer, MARGIN_LEFT, y - 4.0, CONTENT_WIDTH, 22.0, vc);

    // Score
    text(
        layer,
        &format!("{}", r.score),
        28.0,
        MARGIN_LEFT + 4.0,
        y + 4.0,
        &fonts.bold,
        WHITE,
    );
    text(
        layer,
        "/ 100",
        9.0,
        MARGIN_LEFT + 22.0,
        y + 4.0,
        &fonts.regular,
        WHITE,
    );

    // Verdict label
    text(
        layer,
        r.verdict.label(),
        12.0,
        MARGIN_LEFT + 42.0,
        y + 8.0,
        &fonts.bold,
        WHITE,
    );
    text(
        layer,
        r.verdict.subtitle(),
        7.0,
        MARGIN_LEFT + 42.0,
        y + 2.0,
        &fonts.regular,
        WHITE,
    );

    // Likelihood ratio
    let lr_str = if r.likelihood_ratio >= 100.0 {
        format!("{:.0}", r.likelihood_ratio)
    } else {
        format!("{:.1}", r.likelihood_ratio)
    };
    text(
        layer,
        &lr_str,
        16.0,
        MARGIN_LEFT + 140.0,
        y + 8.0,
        &fonts.bold,
        WHITE,
    );
    text(
        layer,
        "LR",
        6.0,
        MARGIN_LEFT + 140.0,
        y + 2.0,
        &fonts.regular,
        WHITE,
    );
    text(
        layer,
        r.enfsi_tier.label(),
        6.0,
        MARGIN_LEFT + 150.0,
        y + 2.0,
        &fonts.regular,
        WHITE,
    );
    y -= 28.0;

    // ── ENFSI Scale ──
    text(
        layer,
        "ENFSI Verbal Equivalence Scale:",
        6.0,
        MARGIN_LEFT,
        y + 2.0,
        &fonts.regular,
        GRAY,
    );
    y -= 4.0;
    let tiers = [
        ("<1", (0.78_f32, 0.16, 0.16), EnfsiTier::Against),
        ("1-10", (0.90, 0.32, 0.00), EnfsiTier::Weak),
        ("10-100", (0.98, 0.66, 0.15), EnfsiTier::Moderate),
        ("100-1K", (0.40, 0.73, 0.42), EnfsiTier::ModeratelyStrong),
        ("1K-10K", (0.18, 0.49, 0.20), EnfsiTier::Strong),
        ("≥10K", (0.11, 0.37, 0.13), EnfsiTier::VeryStrong),
    ];
    let seg_w = CONTENT_WIDTH / 6.0;
    for (i, (label, color, tier)) in tiers.iter().enumerate() {
        let sx = MARGIN_LEFT + i as f32 * seg_w;
        fill_rect(layer, sx, y - 1.0, seg_w - 0.5, 5.0, *color);
        text(layer, label, 5.0, sx + 1.0, y, &fonts.regular, WHITE);
        if *tier == r.enfsi_tier {
            // Active indicator: outline
            layer.set_outline_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
            layer.set_outline_thickness(0.5);
            let outline = Rect::new(Mm(sx), Mm(y - 1.0), Mm(sx + seg_w - 0.5), Mm(y + 4.0));
            layer.add_rect(outline);
        }
    }
    y -= 10.0;

    // ── Author Declaration ──
    text(
        layer,
        "Author Declaration",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 6.0;

    // Declaration box
    fill_rect(
        layer,
        MARGIN_LEFT,
        y - 22.0,
        CONTENT_WIDTH,
        24.0,
        (0.96, 0.96, 0.96),
    );
    // We don't have the declaration text in WarReport, so use verdict_description
    let decl_text = &r.verdict_description;
    let mut dy = y - 2.0;
    for line in wrap_text_lines(decl_text, 90) {
        text(
            layer,
            &line,
            7.0,
            MARGIN_LEFT + 3.0,
            dy,
            &fonts.regular,
            BLACK,
        );
        dy -= 4.0;
    }
    y -= 28.0;

    // ── Chain of Custody ──
    text(
        layer,
        "Document Identity",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 6.0;

    let rows = [
        ("Document Hash:", &r.document_hash),
        ("Signing Key:", &r.signing_key_fingerprint),
        ("Evidence Bundle:", &r.evidence_bundle_version),
        ("Device Attestation:", &r.device_attestation),
    ];
    for (label, value) in &rows {
        text(layer, label, 7.0, MARGIN_LEFT + 2.0, y, &fonts.bold, BLACK);
        let display = if value.len() > 64 {
            format!(
                "{}...{}",
                value.get(..8).unwrap_or(value),
                value.get(value.len().saturating_sub(8)..).unwrap_or(value),
            )
        } else {
            value.to_string()
        };
        text(
            layer,
            &display,
            6.5,
            MARGIN_LEFT + 42.0,
            y,
            &fonts.mono,
            GRAY,
        );
        y -= 5.0;
    }

    if let Some(words) = r.document_words {
        text(
            layer,
            "Document Length:",
            7.0,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.bold,
            BLACK,
        );
        let mut len_str = format!("{} words", words);
        if let Some(chars) = r.document_chars {
            len_str.push_str(&format!(" | {} chars", chars));
        }
        text(
            layer,
            &len_str,
            6.5,
            MARGIN_LEFT + 42.0,
            y,
            &fonts.mono,
            GRAY,
        );
        y -= 5.0;
    }
    y -= 4.0;

    // ── Category Scores ──
    if !r.dimensions.is_empty() {
        text(
            layer,
            "Category Scores",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 7.0;

        for d in &r.dimensions {
            let dc = dimension_color(&d.name);
            charts::draw_score_bar(
                layer,
                &fonts.regular,
                &fonts.bold,
                &d.name,
                d.score,
                dc,
                MARGIN_LEFT + 2.0,
                y,
                100.0,
            );
            y -= 7.0;
        }
    }
    y -= 4.0;

    // ── Writing Flow ──
    if !r.writing_flow.is_empty() {
        text(
            layer,
            "Writing Flow",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 3.0;
        charts::draw_flow_chart(
            layer,
            &r.writing_flow,
            MARGIN_LEFT,
            y - 25.0,
            CONTENT_WIDTH,
            25.0,
        );
        y -= 30.0;
        text(
            layer,
            "Keystroke intensity over time. Dips = natural thinking pauses.",
            5.5,
            MARGIN_LEFT,
            y,
            &fonts.regular,
            GRAY,
        );
    }

    // ── Footer ──
    text(
        layer,
        &format!(
            "CPOP Authorship Report | {} | {} | {}",
            r.report_id, r.algorithm_version, r.schema_version,
        ),
        5.0,
        MARGIN_LEFT,
        10.0,
        &fonts.regular,
        GRAY,
    );
}

// ── Page 2 ────────────────────────────────────────────────────────────

pub fn draw_page2(layer: &PdfLayerReference, r: &WarReport, fonts: &PdfFonts) {
    let mut y = PAGE_TOP;

    // ── Session Timeline ──
    if !r.sessions.is_empty() {
        text(
            layer,
            "Session Timeline",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 7.0;

        for s in &r.sessions {
            fill_rect(
                layer,
                MARGIN_LEFT,
                y - 3.0,
                CONTENT_WIDTH,
                10.0,
                (0.96, 0.96, 0.96),
            );
            // Green left border
            fill_rect(layer, MARGIN_LEFT, y - 3.0, 1.5, 10.0, (0.18, 0.49, 0.20));

            text(
                layer,
                &format!("Session {} — {:.0} min", s.index, s.duration_min),
                8.0,
                MARGIN_LEFT + 4.0,
                y + 2.0,
                &fonts.bold,
                BLACK,
            );
            text(
                layer,
                &s.summary,
                6.0,
                MARGIN_LEFT + 4.0,
                y - 2.0,
                &fonts.regular,
                GRAY,
            );
            y -= 14.0;
        }
    }
    y -= 4.0;

    // ── Process Evidence ──
    text(
        layer,
        "Writing Process Evidence",
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
        let ey = y - row as f32 * 14.0;

        fill_rect(layer, ex, ey - 4.0, col_w - 2.0, 12.0, (0.96, 0.96, 0.96));
        text(layer, label, 7.0, ex + 2.0, ey + 3.0, &fonts.bold, BLACK);
        text(layer, value, 6.5, ex + 2.0, ey - 1.5, &fonts.regular, GRAY);
    }
    y -= (evidence_items.len() as f32 / 2.0).ceil() * 14.0 + 6.0;

    // ── Analysis Flags ──
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
            &format!("Analysis Flags ({} positive, {} negative)", pos, neg),
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

        for f in &r.flags {
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
                6.0,
                MARGIN_LEFT + 2.0,
                y,
                &fonts.regular,
                BLACK,
            );
            text(
                layer,
                &flag_display,
                6.0,
                MARGIN_LEFT + 30.0,
                y,
                &fonts.regular,
                BLACK,
            );
            text(
                layer,
                &format!("{} {}", icon, f.signal.label()),
                6.0,
                MARGIN_LEFT + 130.0,
                y,
                &fonts.bold,
                signal_color,
            );
            y -= 4.5;
        }
    }

    // Footer
    text(
        layer,
        &format!("CPOP Authorship Report | {} | Page 2", r.report_id),
        5.0,
        MARGIN_LEFT,
        10.0,
        &fonts.regular,
        GRAY,
    );
}

// ── Page 3 ────────────────────────────────────────────────────────────

pub fn draw_page3(layer: &PdfLayerReference, r: &WarReport, fonts: &PdfFonts) {
    let mut y = PAGE_TOP;

    // ── Scope & Limitations ──
    text(
        layer,
        "Scope and Limitations",
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
    y -= 6.0;

    // ── Verification Instructions ──
    text(
        layer,
        "How to Verify This Evidence",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 8.0;

    // Offline box
    fill_rect(
        layer,
        MARGIN_LEFT,
        y - 20.0,
        CONTENT_WIDTH / 2.0 - 2.0,
        24.0,
        (0.96, 0.96, 0.96),
    );
    text(
        layer,
        "OFFLINE VERIFICATION",
        7.0,
        MARGIN_LEFT + 3.0,
        y,
        &fonts.bold,
        BLACK,
    );
    text(
        layer,
        "Extract WAR seal from PDF → verify Ed25519",
        5.5,
        MARGIN_LEFT + 3.0,
        y - 5.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "signature → verify enrollment cert chain",
        5.5,
        MARGIN_LEFT + 3.0,
        y - 9.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "Run: cpop verify <file.pdf>",
        6.0,
        MARGIN_LEFT + 3.0,
        y - 15.0,
        &fonts.mono,
        BLACK,
    );

    // Online box
    let ox = MARGIN_LEFT + CONTENT_WIDTH / 2.0 + 2.0;
    fill_rect(
        layer,
        ox,
        y - 20.0,
        CONTENT_WIDTH / 2.0 - 2.0,
        24.0,
        (0.96, 0.96, 0.96),
    );
    text(
        layer,
        "ONLINE VERIFICATION",
        7.0,
        ox + 3.0,
        y,
        &fonts.bold,
        BLACK,
    );
    text(
        layer,
        "All offline checks + transparency log",
        5.5,
        ox + 3.0,
        y - 5.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "anchor + certificate revocation check",
        5.5,
        ox + 3.0,
        y - 9.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "Scan QR or visit writerslogic.com/verify",
        6.0,
        ox + 3.0,
        y - 15.0,
        &fonts.mono,
        BLACK,
    );
    y -= 30.0;

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
    y -= 6.0;

    // ── Analyzed Text (if available) ──
    if let Some(ref analyzed) = r.analyzed_text {
        text(
            layer,
            "Analyzed Text",
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

        fill_rect(
            layer,
            MARGIN_LEFT,
            y - 60.0,
            CONTENT_WIDTH,
            62.0,
            (0.98, 0.98, 0.98),
        );

        // Word-wrap the text into the box
        let mut ty = y - 2.0;
        for line in wrap_text_lines(analyzed, 100) {
            text(
                layer,
                &line,
                6.0,
                MARGIN_LEFT + 3.0,
                ty,
                &fonts.regular,
                BLACK,
            );
            ty -= 3.5;
            if ty < y - 58.0 {
                text(
                    layer,
                    "[continued...]",
                    5.5,
                    MARGIN_LEFT + 3.0,
                    ty,
                    &fonts.regular,
                    GRAY,
                );
                break;
            }
        }
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
    text(
        layer,
        &format!(
            "CPOP Authorship Report | {} | {} | Page 3 | © {} WritersLogic",
            r.report_id,
            r.schema_version,
            r.generated_at.format("%Y"),
        ),
        5.0,
        MARGIN_LEFT,
        10.0,
        &fonts.regular,
        GRAY,
    );
}
