// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::types::*;
use std::fmt::Write;

/// Render a self-contained HTML report from a `WarReport`.
pub fn render_html(r: &WarReport) -> String {
    let mut html = String::with_capacity(32_000);
    write_head(&mut html, r);
    write_header(&mut html, r);
    write_verdict(&mut html, r);
    write_enfsi_scale(&mut html, r);
    write_chain_of_custody(&mut html, r);
    write_process_evidence(&mut html, r);
    write_session_timeline(&mut html, r);
    write_checkpoint_chain(&mut html, r);
    write_forgery_resistance(&mut html, r);
    write_flags(&mut html, r);
    write_scope(&mut html, r);
    write_analyzed_text(&mut html, r);
    write_footer(&mut html, r);
    let _ = write!(html, "</div></body></html>");
    html
}

fn write_head(html: &mut String, r: &WarReport) {
    let _ = write!(
        html,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WritersLogic Authorship Report — {report_id}</title>
<style>
:root {{
  --green: #2e7d32;
  --green-light: #e8f5e9;
  --orange: #f57f17;
  --red: #c62828;
  --gray-50: #fafafa;
  --gray-100: #f5f5f5;
  --gray-200: #eeeeee;
  --gray-300: #e0e0e0;
  --gray-500: #9e9e9e;
  --gray-700: #616161;
  --gray-900: #212121;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  color: var(--gray-900);
  background: #fff;
  line-height: 1.5;
  font-size: 14px;
}}
.container {{ max-width: 800px; margin: 0 auto; padding: 40px 32px; }}
h1 {{ font-size: 28px; font-weight: 700; margin-bottom: 4px; }}
h2 {{ font-size: 20px; font-weight: 700; margin: 32px 0 16px; border-bottom: 2px solid var(--gray-300); padding-bottom: 8px; }}
h3 {{ font-size: 16px; font-weight: 600; margin: 20px 0 8px; }}
.sample-badge {{
  display: inline-block;
  background: var(--gray-500);
  color: #fff;
  font-size: 11px;
  font-weight: 700;
  padding: 2px 10px;
  border-radius: 4px;
  vertical-align: middle;
  margin-left: 12px;
  letter-spacing: 0.5px;
}}
.subtitle {{ color: var(--gray-700); font-size: 13px; margin-bottom: 24px; }}
hr {{ border: none; border-top: 1px solid var(--gray-300); margin: 24px 0; }}

/* Verdict banner */
.verdict {{
  border-radius: 8px;
  padding: 24px 28px;
  margin: 24px 0;
  display: flex;
  align-items: center;
  gap: 24px;
}}
.verdict-score {{
  font-size: 56px;
  font-weight: 700;
  color: #fff;
  line-height: 1;
  text-align: center;
  min-width: 90px;
}}
.verdict-score small {{ font-size: 18px; font-weight: 400; display: block; }}
.verdict-body {{ flex: 1; color: #fff; }}
.verdict-body h2 {{ color: #fff; border: none; margin: 0 0 6px; padding: 0; font-size: 22px; }}
.verdict-body p {{ margin: 0; font-size: 14px; opacity: 0.92; }}
.verdict-lr {{
  text-align: center;
  min-width: 120px;
  color: #fff;
}}
.verdict-lr .lr-value {{ font-size: 36px; font-weight: 700; }}
.verdict-lr .lr-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
.verdict-lr .lr-tier {{ font-size: 13px; font-weight: 600; }}

/* ENFSI scale */
.enfsi-scale {{ display: flex; gap: 0; margin: 8px 0 24px; font-size: 11px; font-weight: 600; }}
.enfsi-scale span {{
  flex: 1;
  text-align: center;
  padding: 6px 4px;
  color: #fff;
}}
.enfsi-against {{ background: #c62828; border-radius: 4px 0 0 4px; }}
.enfsi-weak {{ background: #e65100; }}
.enfsi-moderate {{ background: #f9a825; color: #333 !important; }}
.enfsi-modstrong {{ background: #66bb6a; }}
.enfsi-strong {{ background: #2e7d32; }}
.enfsi-vstrong {{ background: #1b5e20; border-radius: 0 4px 4px 0; }}
.enfsi-active {{ outline: 3px solid #333; outline-offset: -3px; font-weight: 800; }}

/* Info box */
.info-box {{
  background: var(--gray-100);
  border: 1px solid var(--gray-300);
  border-radius: 6px;
  padding: 16px 20px;
  margin: 12px 0;
}}
.info-box table {{ width: 100%; }}
.info-box td {{ padding: 3px 0; vertical-align: top; }}
.info-box td:first-child {{ font-weight: 600; white-space: nowrap; padding-right: 16px; min-width: 200px; }}
.info-box td:last-child {{ color: var(--gray-700); font-family: "SF Mono", "Fira Code", monospace; font-size: 13px; }}

/* Process evidence grid */
.evidence-grid {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin: 12px 0;
}}
.evidence-card {{
  background: var(--gray-100);
  border: 1px solid var(--gray-300);
  border-radius: 6px;
  padding: 14px 16px;
}}
.evidence-card h4 {{ font-size: 14px; font-weight: 700; margin-bottom: 6px; }}
.evidence-card .metric {{ font-size: 15px; margin-bottom: 4px; }}
.evidence-card .note {{ font-size: 12px; color: var(--gray-700); font-style: italic; }}

/* Tables */
table.data {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }}
table.data th {{
  text-align: left;
  padding: 8px 12px;
  background: var(--gray-200);
  font-weight: 700;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--gray-700);
}}
table.data td {{ padding: 8px 12px; border-bottom: 1px solid var(--gray-200); }}
table.data tr:last-child td {{ border-bottom: none; }}
table.data tr:nth-child(even) {{ background: var(--gray-50); }}

/* Checkpoint chain */
.checkpoint {{ display: flex; align-items: center; gap: 8px; padding: 6px 0; font-size: 13px; font-family: monospace; }}
.checkpoint .ord {{ font-weight: 700; min-width: 24px; }}
.checkpoint .hash {{ color: var(--gray-700); }}
.checkpoint .time {{ color: var(--gray-500); font-size: 12px; }}
.checkpoint-arrow {{ color: var(--gray-300); font-size: 16px; text-align: center; }}

/* Flags */
.flag-human {{ color: var(--green); font-weight: 600; }}
.flag-synthetic {{ color: var(--red); font-weight: 600; }}
.flag-neutral {{ color: var(--gray-500); font-weight: 600; }}

/* Session */
.session-box {{
  background: var(--gray-100);
  border-left: 4px solid var(--green);
  padding: 12px 16px;
  margin: 8px 0;
  border-radius: 0 6px 6px 0;
}}
.session-box h4 {{ margin-bottom: 4px; }}
.session-box p {{ font-size: 13px; color: var(--gray-700); margin: 0; }}

/* Forgery */
.forgery-bar {{
  height: 8px;
  border-radius: 4px;
  background: var(--gray-200);
  margin: 4px 0 2px;
}}
.forgery-fill {{ height: 100%; border-radius: 4px; }}

/* Scope */
.scope-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 12px 0; }}
.scope-grid ul {{ margin: 0; padding-left: 20px; font-size: 13px; }}
.scope-grid li {{ margin-bottom: 4px; }}

/* Analyzed text */
.analyzed-text {{
  background: var(--gray-50);
  border: 1px solid var(--gray-300);
  padding: 20px 24px;
  border-radius: 6px;
  font-size: 14px;
  line-height: 1.7;
  column-count: 2;
  column-gap: 32px;
  margin: 12px 0;
}}

/* Footer */
.report-footer {{
  border-top: 1px solid var(--gray-300);
  padding-top: 12px;
  margin-top: 32px;
  font-size: 11px;
  color: var(--gray-500);
  text-align: center;
}}

@media print {{
  body {{ font-size: 12px; }}
  .container {{ padding: 20px; }}
  .verdict {{ break-inside: avoid; }}
  .evidence-grid {{ break-inside: avoid; }}
  h2 {{ break-after: avoid; }}
  .session-box {{ break-inside: avoid; }}
}}
@media (max-width: 600px) {{
  .evidence-grid {{ grid-template-columns: 1fr; }}
  .scope-grid {{ grid-template-columns: 1fr; }}
  .analyzed-text {{ column-count: 1; }}
  .verdict {{ flex-direction: column; text-align: center; }}
}}
</style>
</head>
<body>
<div class="container">
"#,
        report_id = r.report_id
    );
}

fn write_header(html: &mut String, r: &WarReport) {
    let sample = if r.is_sample {
        r#"<span class="sample-badge">SAMPLE</span>"#
    } else {
        ""
    };
    let _ = write!(
        html,
        r#"<h1>WritersLogic Authorship Report{sample}</h1>
<p class="subtitle">
  Report ID: {id} &nbsp;|&nbsp; Algorithm: {alg} &nbsp;|&nbsp;
  Generated: {ts} &nbsp;|&nbsp; Report Schema: {schema} &nbsp;|&nbsp; ENFSI-compliant
</p>
<hr>
"#,
        id = r.report_id,
        alg = r.algorithm_version,
        ts = r.generated_at.format("%B %-d, %Y at %-I:%M:%S %p UTC"),
        schema = r.schema_version,
    );
}

fn write_verdict(html: &mut String, r: &WarReport) {
    let color = r.verdict.css_color();
    let lr_display = format_lr(r.likelihood_ratio);
    let _ = write!(
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
    );
}

fn write_enfsi_scale(html: &mut String, r: &WarReport) {
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
    let _ = write!(
        html,
        r#"<p style="font-size:12px;color:var(--gray-700)">ENFSI Verbal Equivalence Scale:</p><div class="enfsi-scale">"#
    );
    for (class, label, tier) in &tiers {
        let active = if *tier == r.enfsi_tier {
            " enfsi-active"
        } else {
            ""
        };
        let _ = write!(html, r#"<span class="{class}{active}">{label}</span>"#);
    }
    html.push_str("</div>\n");
}

fn write_chain_of_custody(html: &mut String, r: &WarReport) {
    let _ = write!(
        html,
        r#"<h2>Chain of Custody</h2><div class="info-box"><table>"#
    );

    row(html, "Document Hash (SHA-256):", &r.document_hash);
    row(html, "Signing Key Fingerprint:", &r.signing_key_fingerprint);

    let mut doc_len = String::new();
    if let Some(w) = r.document_words {
        let _ = write!(doc_len, "{} words", w);
    }
    if let Some(c) = r.document_chars {
        if !doc_len.is_empty() {
            doc_len.push_str(" | ");
        }
        let _ = write!(doc_len, "{} characters", format_number(c));
    }
    if !doc_len.is_empty() {
        row(html, "Document Length:", &doc_len);
    }

    let bundle = format!(
        "{} | {} session{} | {:.0} min total | {} revision events captured",
        r.evidence_bundle_version,
        r.session_count,
        if r.session_count == 1 { "" } else { "s" },
        r.total_duration_min,
        r.revision_events,
    );
    row(html, "Evidence Bundle:", &bundle);
    row(html, "Device Attestation:", &r.device_attestation);

    if let Some(ref anchor) = r.blockchain_anchor {
        row(html, "Blockchain Anchor:", anchor);
    }

    html.push_str("</table></div>\n");
}

fn write_process_evidence(html: &mut String, r: &WarReport) {
    let p = &r.process;
    let _ = write!(
        html,
        r#"<h2>Process Evidence (Proof Daemon)</h2><div class="evidence-grid">"#
    );

    // Revision intensity
    let _ = write!(
        html,
        r#"<div class="evidence-card"><h4>Revision Intensity</h4>"#
    );
    if let Some(ri) = p.revision_intensity {
        let _ = write!(
            html,
            r#"<div class="metric">{:.2} edits/sentence</div>"#,
            ri
        );
    }
    if let Some(ref bl) = p.revision_baseline {
        let _ = write!(html, r#"<div class="note">{}</div>"#, html_escape(bl));
    }
    let _ = write!(html, "</div>");

    // Pause distribution
    let _ = write!(
        html,
        r#"<div class="evidence-card"><h4>Pause Distribution</h4>"#
    );
    if let Some(med) = p.pause_median_sec {
        let _ = write!(html, r#"<div class="metric">Median: {:.1}s"#, med);
        if let Some(p95) = p.pause_p95_sec {
            let _ = write!(html, " | P95: {:.1}s", p95);
        }
        if let Some(max) = p.pause_max_sec {
            let _ = write!(html, " | Max: {:.0}s", max);
        }
        let _ = write!(html, "</div>");
    }
    let _ = write!(
        html,
        r#"<div class="note">Kernel density matches natural cognitive processing.</div></div>"#
    );

    // Paste ratio
    let _ = write!(html, r#"<div class="evidence-card"><h4>Paste Ratio</h4>"#);
    if let Some(pr) = p.paste_ratio_pct {
        let _ = write!(html, r#"<div class="metric">{:.1}% of total text"#, pr);
        if let Some(ops) = p.paste_operations {
            let _ = write!(html, " | {} operations", ops);
        }
        if let Some(max) = p.paste_max_chars {
            let _ = write!(html, " | All &lt;{} chars", max);
        }
        let _ = write!(html, "</div>");
    }
    let _ = write!(
        html,
        r#"<div class="note">Consistent with inline self-editing.</div></div>"#
    );

    // Keystroke dynamics
    let _ = write!(
        html,
        r#"<div class="evidence-card"><h4>Keystroke Dynamics</h4>"#
    );
    if let Some(cv) = p.iki_cv {
        let _ = write!(
            html,
            r#"<div class="metric">Inter-key interval CV: {:.2}"#,
            cv
        );
        if let Some(bg) = p.bigram_consistency {
            let _ = write!(html, " | Bigram consistency: {:.2}", bg);
        }
        let _ = write!(html, "</div>");
    }
    if let Some(ks) = p.total_keystrokes {
        let _ = write!(
            html,
            r#"<div class="metric">{} keystrokes captured</div>"#,
            format_number(ks)
        );
    }
    let _ = write!(
        html,
        r#"<div class="note">Timing signature stable throughout session. Behavioral fingerprint consistent with single-author composition.</div></div>"#
    );

    // Deletion patterns
    let _ = write!(
        html,
        r#"<div class="evidence-card"><h4>Deletion Patterns</h4>"#
    );
    if let Some(ds) = p.deletion_sequences {
        let _ = write!(html, r#"<div class="metric">{} backspace sequences"#, ds);
        if let Some(avg) = p.avg_deletion_length {
            let _ = write!(html, " | Avg length: {:.1} chars", avg);
        }
        if let Some(sd) = p.select_delete_ops {
            let _ = write!(html, " | {} select-delete operations", sd);
        }
        let _ = write!(html, "</div>");
    }
    let _ = write!(
        html,
        r#"<div class="note">Character-level corrections indicate real-time composition.</div></div>"#
    );

    // SWF checkpoints
    let _ = write!(
        html,
        r#"<div class="evidence-card"><h4>Sequential Work Functions</h4>"#
    );
    if let Some(count) = p.swf_checkpoints {
        let _ = write!(html, r#"<div class="metric">{} SWF checkpoints"#, count);
        if let Some(avg) = p.swf_avg_compute_ms {
            let _ = write!(html, " | Avg compute: {}ms", avg);
        }
        let verified = if p.swf_chain_verified {
            "verified"
        } else {
            "unverified"
        };
        let _ = write!(html, " | Chain integrity: {}", verified);
        let _ = write!(html, "</div>");
    }
    if let Some(hrs) = p.swf_backdating_hours {
        let _ = write!(
            html,
            r#"<div class="note">Cryptographic proof that writing occurred over real minutes. Backdating would require ~{:.0} hours of computation.</div>"#,
            hrs
        );
    }
    let _ = write!(html, "</div>");

    html.push_str("</div>\n");
}

fn write_session_timeline(html: &mut String, r: &WarReport) {
    if r.sessions.is_empty() {
        return;
    }
    html.push_str("<h2>Session Timeline</h2>\n");
    for s in &r.sessions {
        let _ = write!(
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
        );
    }
}

fn write_checkpoint_chain(html: &mut String, r: &WarReport) {
    if r.checkpoints.is_empty() {
        return;
    }
    html.push_str("<h2>Checkpoint Chain</h2>\n");
    let _ = write!(
        html,
        r#"<table class="data"><tr><th>Seq</th><th>Timestamp</th><th>Content Hash</th><th>Size</th><th>VDF Iterations</th><th>Elapsed</th></tr>"#
    );
    for cp in &r.checkpoints {
        let hash_short = if cp.content_hash.len() > 16 {
            format!(
                "{}...{}",
                &cp.content_hash[..8],
                &cp.content_hash[cp.content_hash.len() - 8..]
            )
        } else {
            cp.content_hash.clone()
        };
        let vdf = cp
            .vdf_iterations
            .map(format_number)
            .unwrap_or_else(|| "—".into());
        let elapsed = cp
            .elapsed_ms
            .map(|ms| format!("{:.1}s", ms as f64 / 1000.0))
            .unwrap_or_else(|| "—".into());
        let _ = write!(
            html,
            "<tr><td>{ord}</td><td>{ts}</td><td><code>{hash}</code></td><td>{size}</td><td>{vdf}</td><td>{elapsed}</td></tr>",
            ord = cp.ordinal,
            ts = cp.timestamp.format("%H:%M:%S"),
            hash = hash_short,
            size = format_bytes(cp.content_size),
        );
    }
    html.push_str("</table>\n");
}

fn write_forgery_resistance(html: &mut String, r: &WarReport) {
    if r.forgery.components.is_empty() {
        return;
    }
    html.push_str("<h2>Forgery Resistance Analysis</h2>\n");
    let _ = write!(html, r#"<div class="info-box"><table>"#);
    row(html, "Resistance Tier:", &r.forgery.tier);
    let forge_time = format_duration_human(r.forgery.estimated_forge_time_sec);
    row(html, "Estimated Forge Time:", &forge_time);
    if let Some(ref weak) = r.forgery.weakest_link {
        row(html, "Weakest Link:", weak);
    }
    html.push_str("</table></div>\n");

    let _ = write!(
        html,
        r#"<table class="data"><tr><th>Component</th><th>Present</th><th>CPU Cost</th><th>Detail</th></tr>"#
    );
    for c in &r.forgery.components {
        let present = if c.present { "&#10003;" } else { "&#10007;" };
        let cost = if c.cost_cpu_sec.is_infinite() {
            "Infeasible".to_string()
        } else {
            format_duration_human(c.cost_cpu_sec)
        };
        let _ = write!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&c.name),
            present,
            cost,
            html_escape(&c.explanation),
        );
    }
    html.push_str("</table>\n");
}

fn write_flags(html: &mut String, r: &WarReport) {
    if r.flags.is_empty() {
        return;
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
    let _ = writeln!(
        html,
        "<h2>Analysis Flags ({} positive, {} negative)</h2>",
        pos, neg
    );
    let _ = write!(
        html,
        r#"<table class="data"><tr><th>Category</th><th>Flag</th><th>Detail</th><th>Signal</th></tr>"#
    );
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
        let _ = write!(
            html,
            r#"<tr><td>{cat}</td><td>{flag}</td><td>{detail}</td><td class="{class}">{icon} {label}</td></tr>"#,
            cat = html_escape(&f.category),
            flag = html_escape(&f.flag),
            detail = html_escape(&f.detail),
            label = f.signal.label(),
        );
    }
    html.push_str("</table>\n");
}

fn write_scope(html: &mut String, r: &WarReport) {
    let _ = write!(
        html,
        r#"<h2>Scope and Limitations</h2>
<div class="scope-grid">
<div>
<h3>What This Report Supports:</h3>
<ul>
<li>Evidence of human cognitive constraint patterns</li>
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
    );

    if !r.limitations.is_empty() {
        let _ = write!(html, r#"<h3>Additional Limitations</h3><ul>"#);
        for lim in &r.limitations {
            let _ = write!(html, "<li>{}</li>", html_escape(lim));
        }
        html.push_str("</ul>\n");
    }
}

fn write_analyzed_text(html: &mut String, r: &WarReport) {
    if let Some(ref text) = r.analyzed_text {
        let _ = write!(
            html,
            r#"<h2>Analyzed Text</h2>
<p style="font-size:12px;color:var(--gray-700)">The following text was submitted for analysis. Document hash verified against chain of custody record above.</p>
<div class="analyzed-text">{}</div>
"#,
            html_escape(text)
        );
    }
}

fn write_footer(html: &mut String, r: &WarReport) {
    let _ = write!(
        html,
        r#"<div class="report-footer">
WritersLogic Authorship Report &nbsp;|&nbsp; {id} &nbsp;|&nbsp; Algorithm {alg} &nbsp;|&nbsp; Schema {schema}<br>
This report documents process analysis only. It does not constitute legal advice or definitive proof of authorship.
&copy; {year} WritersLogic, Inc.
</div>
"#,
        id = r.report_id,
        alg = r.algorithm_version,
        schema = r.schema_version,
        year = r.generated_at.format("%Y"),
    );
}

// -- Helpers --

fn row(html: &mut String, label: &str, value: &str) {
    let _ = write!(
        html,
        "<tr><td>{}</td><td>{}</td></tr>",
        label,
        html_escape(value)
    );
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn format_lr(lr: f64) -> String {
    if lr >= 10_000.0 {
        format!("{:.0}", lr)
    } else if lr >= 1_000.0 {
        format_number(lr as u64)
    } else if lr >= 100.0 {
        format!("{:.0}", lr)
    } else if lr >= 10.0 {
        format!("{:.1}", lr)
    } else {
        format!("{:.2}", lr)
    }
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn format_duration_human(seconds: f64) -> String {
    if seconds.is_infinite() {
        return "Infeasible".to_string();
    }
    if seconds < 60.0 {
        format!("{:.0} seconds", seconds)
    } else if seconds < 3600.0 {
        format!("{:.0} minutes", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1} hours", seconds / 3600.0)
    } else if seconds < 86400.0 * 365.0 {
        format!("{:.1} days", seconds / 86400.0)
    } else {
        format!("{:.1} years", seconds / (86400.0 * 365.0))
    }
}
