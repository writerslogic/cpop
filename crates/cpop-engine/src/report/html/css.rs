// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::helpers::html_escape;
use crate::report::types::*;
use std::fmt::{self, Write};

const CSS_BASE: &str = include_str!("templates/base.css");
const CSS_COMPONENTS: &str = include_str!("templates/components.css");
const CSS_LAYOUT: &str = include_str!("templates/layout.css");

/// Write the `<!DOCTYPE>` through opening `<div class="report">`, including
/// `<style>`, cryptographic `<meta>` anchors, PROV-O/CPOP JSON-LD, and CSS.
pub(super) fn write_head(html: &mut String, r: &WarReport) -> fmt::Result {
    let report_id = html_escape(&r.report_id);
    let doc_hash = html_escape(&r.document_hash);
    let schema = html_escape(&r.schema_version);
    let alg = html_escape(&r.algorithm_version);
    let key_fp = html_escape(&r.signing_key_fingerprint);
    let ts_iso = r.generated_at.to_rfc3339();
    let score = r.score;
    let lr = r.likelihood_ratio;
    let lr_log10 = if lr > 0.0 { lr.log10() } else { 0.0 };
    let enfsi = r.enfsi_tier.label();
    let cp_count = r.checkpoints.len();
    let session_count = r.session_count;
    let lr_display = if lr.is_finite() {
        format!("{lr:.6}")
    } else {
        "null".to_string()
    };

    write!(
        html,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Forensic Authorship Examination Report — {report_id}</title>

<!-- Cryptographic anchor tags (machine-readable, for automated verification) -->
<meta name="pop-report-id" content="{report_id}">
<meta name="pop-schema" content="{schema}">
<meta name="pop-root-hash" content="{doc_hash}">
<meta name="pop-algorithm" content="{alg}">
<meta name="pop-generated" content="{ts_iso}">
<meta name="pop-key-fingerprint" content="{key_fp}">
<meta name="pop-score" content="{score}">
<meta name="pop-log-lr" content="{lr_log10:.4}">
<meta name="pop-enfsi-tier" content="{enfsi}">
<meta name="pop-checkpoints" content="{cp_count}">
<meta name="report-version" content="1.0">
<meta name="protocol-version" content="pop-v1">

<!-- W3C PROV-O + CPOP domain ontology (canonical machine-readable provenance) -->
<script type="application/ld+json">
{{
  "@context": {{
    "prov": "http://www.w3.org/ns/prov#",
    "cpop": "https://writerslogic.com/ns/cpop#",
    "xsd": "http://www.w3.org/2001/XMLSchema#"
  }},
  "@graph": [
    {{
      "@id": "urn:cpop:report:{report_id}",
      "@type": ["cpop:AuthorshipReport", "prov:Entity"],
      "cpop:reportId": "{report_id}",
      "cpop:schemaVersion": "{schema}",
      "cpop:algorithmVersion": "{alg}",
      "cpop:assessmentScore": {score},
      "cpop:likelihoodRatio": {lr_display},
      "cpop:logLikelihoodRatio": {lr_log10:.6},
      "cpop:enfsiTier": "{enfsi}",
      "cpop:checkpointCount": {cp_count},
      "cpop:sessionCount": {session_count},
      "prov:generatedAtTime": {{
        "@type": "xsd:dateTime",
        "@value": "{ts_iso}"
      }},
      "prov:wasGeneratedBy": {{
        "@id": "urn:cpop:examination:{report_id}"
      }},
      "prov:wasDerivedFrom": {{
        "@id": "urn:cpop:evidence:{doc_hash}"
      }}
    }},
    {{
      "@id": "urn:cpop:examination:{report_id}",
      "@type": ["cpop:ForensicExamination", "prov:Activity"],
      "prov:wasAssociatedWith": {{
        "@id": "urn:cpop:engine:{alg}"
      }},
      "prov:used": {{
        "@id": "urn:cpop:evidence:{doc_hash}"
      }},
      "prov:generated": {{
        "@id": "urn:cpop:report:{report_id}"
      }}
    }},
    {{
      "@id": "urn:cpop:engine:{alg}",
      "@type": ["cpop:ForensicEngine", "prov:SoftwareAgent"],
      "cpop:engineName": "CPOP Forensic Engine",
      "cpop:engineVersion": "{alg}",
      "cpop:protocolSpec": "draft-condrey-rats-pop"
    }},
    {{
      "@id": "urn:cpop:evidence:{doc_hash}",
      "@type": ["cpop:EvidencePacket", "prov:Entity"],
      "cpop:documentHash": "{doc_hash}",
      "cpop:signingKeyFingerprint": "{key_fp}",
      "cpop:checkpointCount": {cp_count},
      "cpop:sessionCount": {session_count}
    }},
    {{
      "@id": "urn:cpop:document:{doc_hash}",
      "@type": ["cpop:DocumentArtifact", "prov:Entity"],
      "cpop:sha256": "{doc_hash}",
      "prov:wasAttributedTo": {{
        "@type": "prov:Agent"
      }}
    }}
  ]
}}
</script>

<style>
{css_base}
{css_components}
{css_layout}
</style>
</head>
<body class="pop-report">
<div class="report">
"#,
        css_base = CSS_BASE,
        css_components = CSS_COMPONENTS,
        css_layout = CSS_LAYOUT,
    )
}
