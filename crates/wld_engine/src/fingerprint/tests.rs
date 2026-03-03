// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;

#[test]
fn test_author_fingerprint_creation() {
    let activity = ActivityFingerprint::default();
    let fp = AuthorFingerprint::new(activity);
    assert!(!fp.id.is_empty());
    assert_eq!(fp.sample_count, 0);
    assert_eq!(fp.confidence, 0.0);
}

#[test]
fn test_confidence_calculation() {
    let mut fp = AuthorFingerprint::new(ActivityFingerprint::default());
    fp.sample_count = 100;
    fp.update_confidence();
    assert!(fp.confidence > 0.4 && fp.confidence < 0.6);

    fp.sample_count = 1000;
    fp.update_confidence();
    assert!(fp.confidence > 0.85);
}

#[test]
fn test_default_config() {
    let config = FingerprintConfig::default();
    assert!(config.activity_enabled);
    assert!(!config.voice_enabled);
    assert_eq!(config.retention_days, 365);
}
