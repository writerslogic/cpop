// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::helpers::html_escape;
use crate::report::types::*;
use std::fmt::{self, Write};

const CSS_BASE: &str = include_str!("templates/base.css");
const CSS_COMPONENTS: &str = include_str!("templates/components.css");
const CSS_LAYOUT: &str = include_str!("templates/layout.css");

fn build_jsonld(r: &WarReport) -> String {
    let report_id = &r.report_id;
    let doc_hash = &r.document_hash;
    let schema = &r.schema_version;
    let alg = &r.algorithm_version;
    let key_fp = &r.signing_key_fingerprint;
    let ts_iso = r.generated_at.to_rfc3339();
    let cp_count = r.checkpoints.len();
    let session_count = r.session_count;

    let lr_value: serde_json::Value = if r.likelihood_ratio.is_finite() {
        serde_json::json!(r.likelihood_ratio)
    } else {
        serde_json::Value::Null
    };
    let log_lr_value: serde_json::Value = if r.likelihood_ratio > 0.0 {
        serde_json::json!(r.likelihood_ratio.log10())
    } else {
        serde_json::json!(0.0)
    };

    let graph = serde_json::json!({
        "@context": {
            "prov": "http://www.w3.org/ns/prov#",
            "cpop": "https://writerslogic.com/ns/cpop#",
            "xsd": "http://www.w3.org/2001/XMLSchema#"
        },
        "@graph": [
            {
                "@id": format!("urn:cpop:report:{report_id}"),
                "@type": ["cpop:AuthorshipReport", "prov:Entity"],
                "cpop:reportId": report_id,
                "cpop:schemaVersion": schema,
                "cpop:engineVersion": alg,
                "cpop:protocolVersion": "cpop-v1",
                "cpop:assessmentScore": r.score,
                "cpop:likelihoodRatio": lr_value,
                "cpop:logLikelihoodRatio": log_lr_value,
                "cpop:enfsiTier": r.enfsi_tier.label(),
                "cpop:checkpointCount": cp_count,
                "cpop:sessionCount": session_count,
                "cpop:evidenceType": "behavioral-process-evidence",
                "cpop:assertionMethod": "automated",
                "prov:generatedAtTime": {
                    "@type": "xsd:dateTime",
                    "@value": ts_iso
                },
                "prov:wasGeneratedBy": {
                    "@id": format!("urn:cpop:examination:{report_id}")
                },
                "prov:qualifiedDerivation": {
                    "@type": "prov:Derivation",
                    "prov:entity": { "@id": format!("urn:cpop:evidence:sha256:{doc_hash}") },
                    "prov:hadActivity": { "@id": format!("urn:cpop:examination:{report_id}") }
                },
                "prov:wasDerivedFrom": {
                    "@id": format!("urn:cpop:evidence:sha256:{doc_hash}")
                }
            },
            {
                "@id": format!("urn:cpop:examination:{report_id}"),
                "@type": ["cpop:ForensicExamination", "prov:Activity"],
                "prov:wasAssociatedWith": {
                    "@id": format!("urn:cpop:engine:{alg}")
                },
                "prov:used": {
                    "@id": format!("urn:cpop:evidence:sha256:{doc_hash}")
                },
                "prov:generated": {
                    "@id": format!("urn:cpop:report:{report_id}")
                }
            },
            {
                "@id": format!("urn:cpop:engine:{alg}"),
                "@type": ["cpop:ForensicEngine", "prov:SoftwareAgent"],
                "cpop:engineName": "CPOP Forensic Engine",
                "cpop:engineVersion": alg,
                "cpop:protocolSpec": "draft-condrey-rats-pop"
            },
            {
                "@id": format!("urn:cpop:evidence:sha256:{doc_hash}"),
                "@type": ["cpop:EvidencePacket", "prov:Entity"],
                "cpop:documentHash": doc_hash,
                "cpop:documentHashAlgorithm": "SHA-256",
                "cpop:signingKeyFingerprint": key_fp,
                "cpop:checkpointCount": cp_count,
                "cpop:sessionCount": session_count
            },
            {
                "@id": format!("urn:cpop:document:sha256:{doc_hash}"),
                "@type": ["cpop:DocumentArtifact", "prov:Entity"],
                "cpop:sha256": doc_hash,
                "cpop:documentHashAlgorithm": "SHA-256"
            }
        ]
    });

    serde_json::to_string_pretty(&graph).unwrap_or_else(|_| "{}".to_string())
}

/// Write the `<!DOCTYPE>` through opening `<div class="report">`, including
/// `<style>`, cryptographic `<meta>` anchors, PROV-O/CPOP JSON-LD, and CSS.
pub(super) fn write_head(html: &mut String, r: &WarReport) -> fmt::Result {
    let report_id = html_escape(&r.report_id);
    let doc_hash = html_escape(&r.document_hash);
    let evidence_hash = r
        .evidence_hash
        .as_deref()
        .map(html_escape)
        .unwrap_or_default();
    let schema = html_escape(&r.schema_version);
    let alg = html_escape(&r.algorithm_version);
    let key_fp = html_escape(&r.signing_key_fingerprint);
    let ts_iso = r.generated_at.to_rfc3339();
    let score = r.score;
    let lr_log10 = if r.likelihood_ratio > 0.0 {
        r.likelihood_ratio.log10()
    } else {
        0.0
    };
    let enfsi = r.enfsi_tier.label();
    let cp_count = r.checkpoints.len();

    let jsonld = build_jsonld(r);

    write!(
        html,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Forensic Authorship Examination Report — {report_id}</title>

<!-- Cryptographic anchor tags (machine-readable, for automated verification) -->
<meta name="cpop-report-id" content="{report_id}">
<meta name="cpop-schema" content="{schema}">
<meta name="cpop-document-hash" content="{doc_hash}">
<meta name="cpop-document-hash-algorithm" content="SHA-256">
<meta name="cpop-evidence-hash" content="{evidence_hash}">
<meta name="cpop-evidence-hash-algorithm" content="SHA-256">
<meta name="cpop-engine-version" content="{alg}">
<meta name="cpop-generated" content="{ts_iso}">
<meta name="cpop-key-fingerprint" content="{key_fp}">
<meta name="cpop-score" content="{score}">
<meta name="cpop-log-lr" content="{lr_log10:.4}">
<meta name="cpop-enfsi-tier" content="{enfsi}">
<meta name="cpop-checkpoints" content="{cp_count}">
<meta name="cpop-report-version" content="1.0">
<meta name="cpop-protocol-version" content="cpop-v1">
<meta name="cpop-media-type" content="application/vnd.writerslogic.cpop+cbor">

<!-- W3C PROV-O + CPOP domain ontology (canonical machine-readable provenance) -->
<script type="application/ld+json">
{jsonld}
</script>

<style>
{css_base}
{css_components}
{css_layout}
</style>

<!-- Integrity: rendered fields digest (verifier compares visible values against signed payload) -->
<meta name="cpop-signature-algorithm" content="Ed25519">
<meta name="cpop-signing-key-fingerprint" content="{key_fp}">
</head>
<body class="cpop-report">
<div class="report">
"#,
        css_base = CSS_BASE,
        css_components = CSS_COMPONENTS,
        css_layout = CSS_LAYOUT,
    )
}
