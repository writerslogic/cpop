// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::helpers::html_escape;
use crate::report::types::*;
use std::fmt::{self, Write};

pub(super) fn write_head(html: &mut String, r: &WarReport) -> fmt::Result {
    let report_id_escaped = html_escape(&r.report_id);
    write!(
        html,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CPOP Authorship Report — {report_id}</title>
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

/* Category scores */
.category-scores {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
  margin: 12px 0;
}}
.score-bars {{ }}
.score-bar-row {{
  display: flex;
  align-items: center;
  margin-bottom: 8px;
}}
.score-bar-label {{ font-weight: 600; font-size: 14px; min-width: 100px; }}
.score-bar-track {{
  flex: 1;
  height: 18px;
  background: var(--gray-200);
  border-radius: 4px;
  overflow: hidden;
  margin: 0 8px;
}}
.score-bar-fill {{
  height: 100%;
  border-radius: 4px;
  transition: width 0.3s;
}}
.score-bar-value {{ font-weight: 700; min-width: 28px; text-align: right; font-size: 14px; }}
.composite-note {{ font-size: 12px; color: var(--gray-700); margin-top: 8px; }}

/* Writing flow */
.flow-chart {{
  position: relative;
  height: 120px;
  background: var(--gray-50);
  border: 1px solid var(--gray-300);
  border-radius: 6px;
  display: flex;
  align-items: flex-end;
  padding: 8px 4px;
  gap: 1px;
  overflow: hidden;
}}
.flow-bar {{
  flex: 1;
  min-width: 2px;
  border-radius: 2px 2px 0 0;
}}
.flow-labels {{
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: var(--gray-500);
  margin-top: 4px;
}}
.flow-caption {{
  font-size: 12px;
  color: var(--gray-700);
  margin-top: 8px;
}}

/* Dimension analysis */
.dimension-card {{
  background: var(--gray-50);
  border: 1px solid var(--gray-300);
  border-radius: 6px;
  padding: 16px 20px;
  margin: 12px 0;
  position: relative;
}}
.dimension-card h3 {{
  font-size: 16px;
  margin: 0 0 10px;
}}
.dimension-badge {{
  position: absolute;
  top: 16px;
  right: 20px;
  width: 36px;
  height: 36px;
  border-radius: 6px;
  color: #fff;
  font-weight: 700;
  font-size: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
}}
.dimension-detail {{ font-size: 13px; margin-bottom: 4px; }}
.dimension-detail strong {{ font-weight: 600; }}

/* Methodology */
.methodology-grid {{
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 12px;
  margin: 12px 0;
}}
.methodology-card {{
  background: var(--gray-100);
  border: 1px solid var(--gray-300);
  border-radius: 6px;
  padding: 14px 16px;
}}
.methodology-card h4 {{ font-size: 14px; margin-bottom: 6px; }}
.methodology-card p {{ font-size: 12px; color: var(--gray-700); margin: 0; }}

/* LR table confidence bar */
.confidence-bar {{
  display: inline-block;
  height: 10px;
  border-radius: 3px;
  min-width: 40px;
  max-width: 100px;
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
        report_id = report_id_escaped
    )
}
