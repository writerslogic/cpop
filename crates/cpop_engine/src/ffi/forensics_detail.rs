// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::open_store;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiForensicBreakdown {
    pub success: bool,
    pub monotonic_append_ratio: f64,
    pub edit_entropy: f64,
    pub median_interval: f64,
    pub mean_iki_ms: f64,
    pub std_dev_iki_ms: f64,
    pub coefficient_of_variation: f64,
    pub burst_count: u32,
    pub pause_count: u32,
    pub mean_bps: f64,
    pub max_bps: f64,
    pub hurst_exponent: Option<f64>,
    pub assessment_score: f64,
    pub perplexity_score: f64,
    pub risk_level: String,
    pub protocol_verdict: String,
    pub anomaly_count: u32,
    pub anomalies: Vec<FfiAnomaly>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiAnomaly {
    pub timestamp_epoch_ms: Option<i64>,
    pub anomaly_type: String,
    pub description: String,
    pub severity: String,
}

impl FfiForensicBreakdown {
    fn error(msg: String) -> Self {
        Self {
            success: false,
            monotonic_append_ratio: 0.0,
            edit_entropy: 0.0,
            median_interval: 0.0,
            mean_iki_ms: 0.0,
            std_dev_iki_ms: 0.0,
            coefficient_of_variation: 0.0,
            burst_count: 0,
            pause_count: 0,
            mean_bps: 0.0,
            max_bps: 0.0,
            hurst_exponent: None,
            assessment_score: 0.0,
            perplexity_score: 0.0,
            risk_level: "unknown".to_string(),
            protocol_verdict: "unknown".to_string(),
            anomaly_count: 0,
            anomalies: Vec::new(),
            error_message: Some(msg),
        }
    }
}

/// Return a detailed forensic breakdown for a tracked file.
///
/// Runs both the authorship profile (anomaly detection) and the full forensic
/// metrics pipeline (cadence, velocity, behavioral fingerprint, etc.), returning
/// rich structured data suitable for native UI display.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_forensic_breakdown(path: String) -> FfiForensicBreakdown {
    let path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => return FfiForensicBreakdown::error(e),
    };

    let store = match open_store() {
        Ok(s) => s,
        Err(e) => return FfiForensicBreakdown::error(e),
    };

    let events = match store.get_events_for_file(&path) {
        Ok(e) => e,
        Err(e) => return FfiForensicBreakdown::error(format!("Failed to load events: {}", e)),
    };

    if events.is_empty() {
        return FfiForensicBreakdown::error("No events found for this file".to_string());
    }

    let profile = crate::forensics::ForensicEngine::evaluate_authorship(&path, &events);

    let event_data: Vec<crate::forensics::EventData> = events
        .iter()
        .map(|e| crate::forensics::EventData {
            id: e.id.unwrap_or(0),
            timestamp_ns: e.timestamp_ns,
            file_size: e.file_size,
            size_delta: e.size_delta,
            file_path: e.file_path.clone(),
        })
        .collect();

    let mut regions = std::collections::HashMap::new();
    for e in &events {
        if let Some(id) = e.id {
            let delta = e.size_delta;
            let sign = if delta > 0 {
                1
            } else if delta < 0 {
                -1
            } else {
                0
            };
            regions.insert(
                id,
                vec![crate::forensics::RegionData {
                    start_pct: 1.0,
                    end_pct: 1.0,
                    delta_sign: sign,
                    byte_count: delta.abs(),
                }],
            );
        }
    }

    let metrics = crate::forensics::analyze_forensics(&event_data, &regions, None, None, None);

    let protocol_verdict = metrics.map_to_protocol_verdict();

    let anomalies: Vec<FfiAnomaly> = profile
        .anomalies
        .iter()
        .map(|a| FfiAnomaly {
            timestamp_epoch_ms: a.timestamp.map(|t| t.timestamp_millis()),
            anomaly_type: a.anomaly_type.to_string(),
            description: a.description.clone(),
            severity: a.severity.to_string(),
        })
        .collect();

    let mean_iki_ms = {
        let v = metrics.cadence.mean_iki_ns / 1_000_000.0;
        if v.is_finite() {
            v
        } else {
            0.0
        }
    };
    let std_dev_iki_ms = {
        let v = metrics.cadence.std_dev_iki_ns / 1_000_000.0;
        if v.is_finite() {
            v
        } else {
            0.0
        }
    };
    let cv = if metrics.cadence.coefficient_of_variation.is_finite() {
        metrics.cadence.coefficient_of_variation
    } else {
        0.0
    };

    FfiForensicBreakdown {
        success: true,
        monotonic_append_ratio: profile.metrics.monotonic_append_ratio,
        edit_entropy: profile.metrics.edit_entropy,
        median_interval: profile.metrics.median_interval,
        mean_iki_ms,
        std_dev_iki_ms,
        coefficient_of_variation: cv,
        burst_count: metrics.cadence.burst_count as u32,
        pause_count: metrics.cadence.pause_count as u32,
        mean_bps: if metrics.velocity.mean_bps.is_finite() {
            metrics.velocity.mean_bps
        } else {
            0.0
        },
        max_bps: if metrics.velocity.max_bps.is_finite() {
            metrics.velocity.max_bps
        } else {
            0.0
        },
        hurst_exponent: metrics.hurst_exponent.filter(|h| h.is_finite()),
        assessment_score: if metrics.assessment_score.is_finite() {
            metrics.assessment_score
        } else {
            0.0
        },
        perplexity_score: if metrics.perplexity_score.is_finite() {
            metrics.perplexity_score
        } else {
            0.0
        },
        risk_level: metrics.risk_level.to_string().to_lowercase(),
        protocol_verdict: format!("{:?}", protocol_verdict),
        anomaly_count: profile.anomalies.len() as u32,
        anomalies,
        error_message: None,
    }
}
