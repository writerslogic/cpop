// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::helpers::*;
use crate::report::types::*;
use std::fmt::{self, Write};

/// Validate a CSS color value to prevent XSS injection via style attributes.
/// Only hex colors (#RGB, #RGBA, #RRGGBB, #RRGGBBAA) are allowed. Returns
/// "gray" for any value that doesn't match.
fn sanitize_css_color(color: &str) -> &str {
    let bytes = color.as_bytes();
    // #RGB=4, #RGBA=5, #RRGGBB=7, #RRGGBBAA=9 are all valid CSS hex colors
    let valid = bytes.first() == Some(&b'#')
        && matches!(bytes.len(), 4 | 5 | 7 | 9)
        && bytes[1..].iter().all(|b| b.is_ascii_hexdigit());
    if valid {
        color
    } else {
        "gray"
    }
}

pub(super) fn write_header(html: &mut String, r: &WarReport) -> fmt::Result {
    let sample = if r.is_sample {
        r#"<span class="sample-badge">SAMPLE</span>"#
    } else {
        ""
    };
    write!(
        html,
        r#"<h1>CPOP Authorship Report{sample}</h1>
<p class="subtitle">
  Report ID: {id} &nbsp;|&nbsp; Algorithm: {alg} &nbsp;|&nbsp;
  Generated: {ts} &nbsp;|&nbsp; Report Schema: {schema} &nbsp;|&nbsp; ENFSI-compliant
</p>
<hr>
"#,
        id = html_escape(&r.report_id),
        alg = html_escape(&r.algorithm_version),
        ts = r.generated_at.format("%B %-d, %Y at %-I:%M:%S %p UTC"),
        schema = html_escape(&r.schema_version),
    )
}

pub(super) fn write_verdict(html: &mut String, r: &WarReport) -> fmt::Result {
    let color = sanitize_css_color(r.verdict.css_color());
    let lr_display = format_lr(r.likelihood_ratio);
    write!(
        html,
        r#"<div class="verdict" style="background:{color}">
  <div class="verdict-score">{score}<small>/ 100</small></div>
  <div class="verdict-body">
    <h2>{label} &mdash; {subtitle}</h2>
    <p>{desc}</p>
  </div>
  <div class="verdict-lr">
    <div class="lr-value">{lr}</div>
    <div class="lr-label">Likelihood Ratio</div>
    <div class="lr-tier">{tier}</div>
  </div>
</div>
"#,
        score = r.score,
        label = r.verdict.label(),
        subtitle = r.verdict.subtitle(),
        desc = html_escape(&r.verdict_description),
        lr = lr_display,
        tier = r.enfsi_tier.label(),
    )
}

pub(super) fn write_enfsi_scale(html: &mut String, r: &WarReport) -> fmt::Result {
    let tiers = [
        ("enfsi-against", "&lt;1 Against", EnfsiTier::Against),
        ("enfsi-weak", "1-10 Weak", EnfsiTier::Weak),
        ("enfsi-moderate", "10-100 Moderate", EnfsiTier::Moderate),
        (
            "enfsi-modstrong",
            "100-1K Moderately Strong",
            EnfsiTier::ModeratelyStrong,
        ),
        ("enfsi-strong", "1K-10K Strong", EnfsiTier::Strong),
        (
            "enfsi-vstrong",
            "&ge;10K Very Strong",
            EnfsiTier::VeryStrong,
        ),
    ];
    write!(
        html,
        r#"<p style="font-size:12px;color:var(--gray-700)">ENFSI Verbal Equivalence Scale:</p><div class="enfsi-scale">"#
    )?;
    for (class, label, tier) in &tiers {
        let active = if *tier == r.enfsi_tier {
            " enfsi-active"
        } else {
            ""
        };
        write!(html, r#"<span class="{class}{active}">{label}</span>"#)?;
    }
    writeln!(html, "</div>")
}

pub(super) fn write_chain_of_custody(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(
        html,
        r#"<h2>Chain of Custody</h2><div class="info-box"><table>"#
    )?;

    row(html, "Document Hash (SHA-256):", &r.document_hash)?;
    row(html, "Signing Key Fingerprint:", &r.signing_key_fingerprint)?;

    let mut doc_len = String::new();
    if let Some(w) = r.document_words {
        write!(doc_len, "{} words", w)?;
    }
    if let Some(c) = r.document_chars {
        if !doc_len.is_empty() {
            doc_len.push_str(" | ");
        }
        write!(doc_len, "{} characters", format_number(c))?;
    }
    if !doc_len.is_empty() {
        row(html, "Document Length:", &doc_len)?;
    }

    let bundle = format!(
        "{} | {} session{} | {:.0} min total | {} revision events captured",
        r.evidence_bundle_version,
        r.session_count,
        if r.session_count == 1 { "" } else { "s" },
        r.total_duration_min,
        r.revision_events,
    );
    row(html, "Evidence Bundle:", &bundle)?;
    row(html, "Device Attestation:", &r.device_attestation)?;

    if let Some(ref anchor) = r.blockchain_anchor {
        row(html, "Blockchain Anchor:", anchor)?;
    }

    writeln!(html, "</table></div>")
}

pub(super) fn write_category_scores(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.dimensions.is_empty() {
        return Ok(());
    }
    write!(
        html,
        r#"<div class="category-scores"><div class="score-bars"><h2 style="margin-top:0">Category Scores</h2>"#
    )?;
    for d in &r.dimensions {
        write!(
            html,
            r#"<div class="score-bar-row">
<span class="score-bar-label" style="color:{color}">{name}</span>
<div class="score-bar-track"><div class="score-bar-fill" style="width:{score}%;background:{color}"></div></div>
<span class="score-bar-value">{score}</span>
</div>"#,
            name = html_escape(&d.name),
            score = d.score.min(100),
            color = sanitize_css_color(&d.color),
        )?;
    }
    write_category_composite_note(html, r)?;
    write!(html, "</div>")?;

    if !r.writing_flow.is_empty() {
        write_writing_flow(html, r)?;
    }

    writeln!(html, "</div>")
}

fn write_category_composite_note(html: &mut String, r: &WarReport) -> fmt::Result {
    let all_pass = r.dimensions.iter().all(|d| d.score >= 60);
    let contradicts = r.dimensions.iter().any(|d| d.score < 40);
    if contradicts {
        write!(
            html,
            r#"<p class="composite-note">Warning: one or more dimensions below threshold.</p>"#,
        )
    } else if all_pass {
        write!(
            html,
            r#"<p class="composite-note">Composite vector: no dimension contradicts verdict. Minimum threshold: 60. All dimensions pass.</p>"#
        )
    } else {
        Ok(())
    }
}

fn write_writing_flow(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(
        html,
        r#"<div><h2 style="margin-top:0">Writing Flow Visualization</h2><div class="flow-chart">"#
    )?;
    let max_intensity = r
        .writing_flow
        .iter()
        .map(|p| p.intensity)
        .fold(0.0_f64, f64::max)
        .max(0.01);
    for point in &r.writing_flow {
        let pct = (point.intensity / max_intensity * 100.0).min(100.0);
        let color = match point.phase.as_str() {
            "drafting" => "#4caf50",
            "revising" => "#2196f3",
            "polish" => "#9c27b0",
            "pause" => "#e0e0e0",
            _ => "#78909c",
        };
        write!(
            html,
            r#"<div class="flow-bar" style="height:{pct:.0}%;background:{color}"></div>"#
        )?;
    }
    write!(html, "</div>")?;
    if let (Some(first), Some(last)) = (r.writing_flow.first(), r.writing_flow.last()) {
        write!(
            html,
            r#"<div class="flow-labels"><span>{:.0}:00</span><span>Drafting</span><span>Pause</span><span>Revising</span><span>Polish</span><span>{:.0}:{:02.0}</span></div>"#,
            first.offset_min,
            last.offset_min as u64,
            ((last.offset_min % 1.0) * 60.0) as u64,
        )?;
    }
    write!(
        html,
        r#"<p class="flow-caption">Keystroke intensity over time. Dips indicate natural thinking pauses. Irregular burst patterns are characteristic of human cognitive processing.</p>"#
    )?;
    write!(html, "</div>")
}

pub(super) fn write_dimension_analysis(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.dimensions.is_empty() {
        return Ok(());
    }
    writeln!(html, "<h2>Detailed Dimension Analysis</h2>")?;
    for d in &r.dimensions {
        if d.analysis.is_empty() {
            continue;
        }
        write!(
            html,
            r#"<div class="dimension-card">
<h3 style="color:{color}">{name}</h3>
<div class="dimension-badge" style="background:{color}">{score}</div>
"#,
            name = html_escape(&d.name),
            score = d.score,
            color = sanitize_css_color(&d.color),
        )?;
        for detail in &d.analysis {
            write!(
                html,
                r#"<p class="dimension-detail"><strong>{}:</strong> {}</p>"#,
                html_escape(&detail.label),
                html_escape(&detail.text),
            )?;
        }
        writeln!(html, "</div>")?;
    }
    Ok(())
}

pub(super) fn write_statistical_methodology(html: &mut String, r: &WarReport) -> fmt::Result {
    let meth = match r.methodology {
        Some(ref m) => m,
        None => return Ok(()),
    };
    write!(
        html,
        r#"<h2>Statistical Methodology</h2><div class="methodology-grid">"#
    )?;
    write!(
        html,
        r#"<div class="methodology-card"><h4>Likelihood Ratio Computation</h4><p>{}</p></div>"#,
        html_escape(&meth.lr_computation),
    )?;
    write!(
        html,
        r#"<div class="methodology-card"><h4>Confidence Interval</h4><p>{}</p></div>"#,
        html_escape(&meth.confidence_interval),
    )?;
    write!(
        html,
        r#"<div class="methodology-card"><h4>Calibration</h4><p>{}</p></div>"#,
        html_escape(&meth.calibration),
    )?;
    writeln!(html, "</div>")
}

pub(super) fn write_dimension_lr_table(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.dimensions.is_empty() {
        return Ok(());
    }
    writeln!(html, "<h2>Per-Dimension Likelihood Ratios</h2>")?;
    write!(
        html,
        r#"<table class="data"><tr><th>Dimension</th><th>Score</th><th>LR</th><th>Log-LR</th><th>Confidence</th><th>Key Discriminator</th></tr>"#
    )?;
    for d in &r.dimensions {
        let conf_pct = (d.confidence * 100.0).min(100.0);
        write!(
            html,
            r#"<tr><td style="color:{color};font-weight:600">{name}</td><td>{score}</td><td>{lr}</td><td>{log_lr:.2}</td><td><div class="confidence-bar" style="width:{conf_pct:.0}px;background:{color}"></div></td><td>{disc}</td></tr>"#,
            name = html_escape(&d.name),
            score = d.score,
            lr = format_lr(d.lr),
            log_lr = d.log_lr,
            conf_pct = conf_pct,
            color = sanitize_css_color(&d.color),
            disc = html_escape(&d.key_discriminator),
        )?;
    }
    write!(
        html,
        r#"<tr style="font-weight:700"><td>Combined</td><td>{score}</td><td>{lr}</td><td>{log_lr:.2}</td><td><div class="confidence-bar" style="width:{conf_pct:.0}px;background:#2e7d32"></div></td><td>All dimensions concordant</td></tr>"#,
        score = r.score,
        lr = format_lr(r.likelihood_ratio),
        log_lr = if r.likelihood_ratio > 0.0 {
            r.likelihood_ratio.log10()
        } else {
            0.0
        },
        conf_pct = (r.score as f64).min(100.0),
    )?;
    writeln!(html, "</table>")
}

pub(super) fn write_process_evidence(html: &mut String, r: &WarReport) -> fmt::Result {
    let p = &r.process;
    write!(
        html,
        r#"<h2>Process Evidence (Proof Daemon)</h2><div class="evidence-grid">"#
    )?;

    write_evidence_revision_intensity(html, p)?;
    write_evidence_pause_distribution(html, p)?;
    write_evidence_paste_ratio(html, p)?;
    write_evidence_keystroke_dynamics(html, p)?;
    write_evidence_deletion_patterns(html, p)?;
    write_evidence_swf(html, p)?;

    writeln!(html, "</div>")
}

fn write_evidence_revision_intensity(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Revision Intensity</h4>"#
    )?;
    if let Some(ri) = p.revision_intensity {
        write!(
            html,
            r#"<div class="metric">{:.2} edits/sentence</div>"#,
            ri
        )?;
    }
    if let Some(ref bl) = p.revision_baseline {
        write!(html, r#"<div class="note">{}</div>"#, html_escape(bl))?;
    }
    write!(html, "</div>")
}

fn write_evidence_pause_distribution(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Pause Distribution</h4>"#
    )?;
    if let Some(med) = p.pause_median_sec {
        write!(html, r#"<div class="metric">Median: {:.1}s"#, med)?;
        if let Some(p95) = p.pause_p95_sec {
            write!(html, " | P95: {:.1}s", p95)?;
        }
        if let Some(max) = p.pause_max_sec {
            write!(html, " | Max: {:.0}s", max)?;
        }
        write!(html, "</div>")?;
    }
    write!(
        html,
        r#"<div class="note">Kernel density matches natural cognitive processing.</div></div>"#
    )
}

fn write_evidence_paste_ratio(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(html, r#"<div class="evidence-card"><h4>Paste Ratio</h4>"#)?;
    if let Some(pr) = p.paste_ratio_pct {
        write!(html, r#"<div class="metric">{:.1}% of total text"#, pr)?;
        if let Some(ops) = p.paste_operations {
            write!(html, " | {} operations", ops)?;
        }
        if let Some(max) = p.paste_max_chars {
            write!(html, " | All &lt;{} chars", max)?;
        }
        write!(html, "</div>")?;
    }
    write!(
        html,
        r#"<div class="note">Consistent with inline self-editing.</div></div>"#
    )
}

fn write_evidence_keystroke_dynamics(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Keystroke Dynamics</h4>"#
    )?;
    if let Some(cv) = p.iki_cv {
        write!(
            html,
            r#"<div class="metric">Inter-key interval CV: {:.2}"#,
            cv
        )?;
        if let Some(bg) = p.bigram_consistency {
            write!(html, " | Bigram consistency: {:.2}", bg)?;
        }
        write!(html, "</div>")?;
    }
    if let Some(ks) = p.total_keystrokes {
        write!(
            html,
            r#"<div class="metric">{} keystrokes captured</div>"#,
            format_number(ks)
        )?;
    }
    write!(
        html,
        r#"<div class="note">Timing signature stable throughout session. Behavioral fingerprint consistent with single-author composition.</div></div>"#
    )
}

fn write_evidence_deletion_patterns(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Deletion Patterns</h4>"#
    )?;
    if let Some(ds) = p.deletion_sequences {
        write!(html, r#"<div class="metric">{} backspace sequences"#, ds)?;
        if let Some(avg) = p.avg_deletion_length {
            write!(html, " | Avg length: {:.1} chars", avg)?;
        }
        if let Some(sd) = p.select_delete_ops {
            write!(html, " | {} select-delete operations", sd)?;
        }
        write!(html, "</div>")?;
    }
    write!(
        html,
        r#"<div class="note">Character-level corrections indicate real-time composition.</div></div>"#
    )
}

fn write_evidence_swf(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Sequential Work Functions</h4>"#
    )?;
    if let Some(count) = p.swf_checkpoints {
        write!(html, r#"<div class="metric">{} SWF checkpoints"#, count)?;
        if let Some(avg) = p.swf_avg_compute_ms {
            write!(html, " | Avg compute: {}ms", avg)?;
        }
        let verified = if p.swf_chain_verified {
            "verified"
        } else {
            "unverified"
        };
        write!(html, " | Chain integrity: {}", verified)?;
        write!(html, "</div>")?;
    }
    if let Some(hrs) = p.swf_backdating_hours {
        write!(
            html,
            r#"<div class="note">Cryptographic proof that writing occurred over real minutes. Backdating would require ~{:.0} hours of computation.</div>"#,
            hrs
        )?;
    }
    write!(html, "</div>")
}

pub(super) fn write_session_timeline(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.sessions.is_empty() {
        return Ok(());
    }
    writeln!(html, "<h2>Session Timeline</h2>")?;
    for s in &r.sessions {
        write!(
            html,
            r#"<div class="session-box">
<h4>Session {idx} &mdash; {dur:.0} min</h4>
<p>{start} &bull; {summary}</p>
</div>
"#,
            idx = s.index,
            dur = s.duration_min,
            start = s.start.format("%B %-d, %Y %-I:%M %p"),
            summary = html_escape(&s.summary),
        )?;
    }
    Ok(())
}

pub(super) fn write_checkpoint_chain(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.checkpoints.is_empty() {
        return Ok(());
    }
    writeln!(html, "<h2>Checkpoint Chain</h2>")?;
    write!(
        html,
        r#"<table class="data"><tr><th>Seq</th><th>Timestamp</th><th>Content Hash</th><th>Size</th><th>VDF Iterations</th><th>Elapsed</th></tr>"#
    )?;
    for cp in &r.checkpoints {
        let hash_short = if cp.content_hash.len() > 16 {
            format!(
                "{}...{}",
                cp.content_hash.get(..8).unwrap_or(&cp.content_hash),
                cp.content_hash
                    .get(cp.content_hash.len().saturating_sub(8)..)
                    .unwrap_or(&cp.content_hash),
            )
        } else {
            cp.content_hash.clone()
        };
        let vdf = cp
            .vdf_iterations
            .map(format_number)
            .unwrap_or_else(|| "\u{2014}".into());
        let elapsed = cp
            .elapsed_ms
            .map(|ms| format!("{:.1}s", ms as f64 / 1000.0))
            .unwrap_or_else(|| "\u{2014}".into());
        write!(
            html,
            "<tr><td>{ord}</td><td>{ts}</td><td><code>{hash}</code></td><td>{size}</td><td>{vdf}</td><td>{elapsed}</td></tr>",
            ord = cp.ordinal,
            ts = cp.timestamp.format("%H:%M:%S"),
            hash = hash_short,
            size = format_bytes(cp.content_size),
        )?;
    }
    writeln!(html, "</table>")
}

pub(super) fn write_forgery_resistance(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.forgery.components.is_empty() {
        return Ok(());
    }
    writeln!(html, "<h2>Forgery Resistance Analysis</h2>")?;
    write!(html, r#"<div class="info-box"><table>"#)?;
    row(html, "Resistance Tier:", &r.forgery.tier)?;
    let forge_time = format_duration_human(r.forgery.estimated_forge_time_sec);
    row(html, "Estimated Forge Time:", &forge_time)?;
    if let Some(ref weak) = r.forgery.weakest_link {
        row(html, "Weakest Link:", weak)?;
    }
    writeln!(html, "</table></div>")?;

    write!(
        html,
        r#"<table class="data"><tr><th>Component</th><th>Present</th><th>CPU Cost</th><th>Detail</th></tr>"#
    )?;
    for c in &r.forgery.components {
        let present = if c.present { "&#10003;" } else { "&#10007;" };
        let cost = if c.cost_cpu_sec.is_infinite() {
            "Infeasible".to_string()
        } else {
            format_duration_human(c.cost_cpu_sec)
        };
        write!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&c.name),
            present,
            cost,
            html_escape(&c.explanation),
        )?;
    }
    writeln!(html, "</table>")
}

pub(super) fn write_flags(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.flags.is_empty() {
        return Ok(());
    }
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
    writeln!(
        html,
        "<h2>Analysis Flags ({} positive, {} negative)</h2>",
        pos, neg
    )?;
    write!(
        html,
        r#"<table class="data"><tr><th>Category</th><th>Flag</th><th>Detail</th><th>Signal</th></tr>"#
    )?;
    for f in &r.flags {
        let class = match f.signal {
            FlagSignal::Human => "flag-human",
            FlagSignal::Synthetic => "flag-synthetic",
            FlagSignal::Neutral => "flag-neutral",
        };
        let icon = match f.signal {
            FlagSignal::Human => "&#10003;",
            FlagSignal::Synthetic => "&#10007;",
            FlagSignal::Neutral => "&mdash;",
        };
        write!(
            html,
            r#"<tr><td>{cat}</td><td>{flag}</td><td>{detail}</td><td class="{class}">{icon} {label}</td></tr>"#,
            cat = html_escape(&f.category),
            flag = html_escape(&f.flag),
            detail = html_escape(&f.detail),
            label = f.signal.label(),
        )?;
    }
    writeln!(html, "</table>")
}

pub(super) fn write_scope(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(
        html,
        r#"<h2>Scope and Limitations</h2>
<div class="scope-grid">
<div>
<h3>What This Report Supports:</h3>
<ul>
<li>Evidence of human cognitive constraint patterns</li>
<li>Stylometric consistency with natural authorship</li>
<li>Documented methodology for dispute review</li>
<li>Reproducible analysis (same text + algorithm = same results)</li>
</ul>
<h3>What This Report Does NOT Prove:</h3>
<ul>
<li>Named author identity (requires additional evidence)</li>
<li>AI was not used at any point in the process</li>
<li>Text has not been edited, paraphrased, or translated</li>
<li>Definitive attribution beyond reasonable doubt</li>
</ul>
</div>
<div>
<h3>Factors That Could Affect Results:</h3>
<ul>
<li>Heavy editing or translation of original text</li>
<li>Genre shifts (technical vs. creative writing)</li>
<li>Templates, outlines, or structured prompts</li>
<li>Collaborative authorship or editorial input</li>
<li>Text length under 200 words</li>
</ul>
<h3>FRE 902(13) Compliance:</h3>
<ul>
<li>Evidence generated by automated process</li>
<li>Process verified to produce accurate results</li>
<li>Certified by qualified person (algorithm attestation)</li>
<li>Hash chain provides tamper-evident integrity</li>
</ul>
</div>
</div>
"#
    )?;

    if !r.limitations.is_empty() {
        write!(html, r#"<h3>Additional Limitations</h3><ul>"#)?;
        for lim in &r.limitations {
            write!(html, "<li>{}</li>", html_escape(lim))?;
        }
        writeln!(html, "</ul>")?;
    }
    Ok(())
}

pub(super) fn write_analyzed_text(html: &mut String, r: &WarReport) -> fmt::Result {
    if let Some(ref text) = r.analyzed_text {
        write!(
            html,
            r#"<h2>Analyzed Text</h2>
<p style="font-size:12px;color:var(--gray-700)">The following text was submitted for analysis. Document hash verified against chain of custody record above.</p>
<div class="analyzed-text">{}</div>
"#,
            html_escape(text)
        )?;
    }
    Ok(())
}

pub(super) fn write_verification_instructions(html: &mut String) -> fmt::Result {
    write!(
        html,
        r#"<div class="section">
  <h2>How to Verify This Evidence</h2>
  <p>This evidence packet can be independently verified:</p>
  <ul>
    <li><strong>Web:</strong> Upload this file at <a href="https://writerslogic.com/verify" target="_blank" rel="noopener noreferrer">writerslogic.com/verify</a> &mdash; verification runs in your browser, no data is uploaded</li>
    <li><strong>CLI:</strong> Install the open-source tool and run <code>cpop verify &lt;file&gt;</code></li>
  </ul>
  <p>Verification checks the cryptographic signatures, checkpoint chain integrity, VDF timing proofs, and behavioral consistency.</p>
</div>
"#,
    )
}

pub(super) fn write_footer(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(
        html,
        r#"<div class="report-footer">
CPOP Authorship Report &nbsp;|&nbsp; {id} &nbsp;|&nbsp; Algorithm {alg} &nbsp;|&nbsp; Schema {schema}<br>
This report documents process analysis only. It does not constitute legal advice or definitive proof of authorship.
&copy; {year} WritersLogic
</div>
"#,
        id = html_escape(&r.report_id),
        alg = html_escape(&r.algorithm_version),
        schema = html_escape(&r.schema_version),
        year = r.generated_at.format("%Y"),
    )
}
