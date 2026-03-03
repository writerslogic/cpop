// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::helpers;
use super::*;
use crate::jitter::{default_parameters, Session};
use chrono::Timelike;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_hardware_class_detection() {
    let hw = helpers::detect_hardware_class();
    assert!(!hw.arch.is_empty());
    assert!(!hw.core_bucket.is_empty());
}

#[test]
fn test_os_type_detection() {
    let os = helpers::detect_os_type();
    #[cfg(target_os = "macos")]
    assert_eq!(os, OsType::MacOS);
    #[cfg(target_os = "linux")]
    assert_eq!(os, OsType::Linux);
    #[cfg(target_os = "windows")]
    assert_eq!(os, OsType::Windows);
}

#[test]
fn test_timestamp_rounding() {
    use chrono::Utc;
    let ts = Utc::now();
    let rounded = helpers::round_timestamp_to_hour(ts);
    assert_eq!(rounded.minute(), 0);
    assert_eq!(rounded.second(), 0);
    assert_eq!(rounded.nanosecond(), 0);
}

#[test]
fn test_anonymized_session_creation() {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "test content").unwrap();
    temp_file.flush().unwrap();

    let params = default_parameters();
    let mut session = Session::new(temp_file.path(), params).unwrap();

    for _ in 0..100 {
        let _ = session.record_keystroke();
    }

    let evidence = session.export();
    let anonymized = AnonymizedSession::from_evidence(&evidence);

    assert!(!anonymized.research_id.is_empty());
    assert_eq!(anonymized.collected_at.minute(), 0);
    assert!(!anonymized.hardware_class.arch.is_empty());
}

#[test]
fn test_research_collector_disabled() {
    use crate::config::ResearchConfig;
    use crate::jitter::{Evidence, Statistics};
    use chrono::Utc;

    let config = ResearchConfig {
        contribute_to_research: false,
        ..Default::default()
    };

    let mut collector = ResearchCollector::new(config);
    assert!(!collector.is_enabled());

    let evidence = Evidence {
        session_id: "test".to_string(),
        started_at: Utc::now(),
        ended_at: Utc::now(),
        document_path: "/test".to_string(),
        params: default_parameters(),
        samples: vec![],
        statistics: Statistics::default(),
    };

    collector.add_session(&evidence);
    assert_eq!(collector.session_count(), 0);
}

#[test]
fn test_memory_bucket() {
    assert_eq!(helpers::memory_gb_to_bucket(2), "<=4GB");
    assert_eq!(helpers::memory_gb_to_bucket(6), "4-8GB");
    assert_eq!(helpers::memory_gb_to_bucket(12), "8-16GB");
    assert_eq!(helpers::memory_gb_to_bucket(24), "16-32GB");
    assert_eq!(helpers::memory_gb_to_bucket(64), "32GB+");
}
