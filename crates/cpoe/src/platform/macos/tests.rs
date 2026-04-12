// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;

#[test]
fn test_permission_check() {
    // This will return false in CI environments without permissions
    // Just verify it doesn't panic
    let _ = get_permission_status();
}

#[test]
fn test_strict_mode_toggle() {
    let original = get_strict_mode();
    set_strict_mode(!original);
    assert_eq!(get_strict_mode(), !original);
    set_strict_mode(original);
    assert_eq!(get_strict_mode(), original);
}

#[test]
fn test_dual_layer_no_hid() {
    // When HID count is 0, no synthetic detection possible.
    let validation = validate_dual_layer(100, 0);
    assert!(!validation.synthetic_detected);
    assert_eq!(validation.discrepancy, 0);
}

#[test]
fn test_dual_layer_matching_counts() {
    let validation = validate_dual_layer(100, 100);
    assert!(!validation.synthetic_detected);
    assert_eq!(validation.discrepancy, 0);
}

#[test]
fn test_dual_layer_synthetic_detected() {
    // CG has 150 events but HID only saw 100: >10% excess.
    let validation = validate_dual_layer(150, 100);
    assert!(validation.synthetic_detected);
    assert_eq!(validation.discrepancy, 50);
}

#[test]
fn test_dual_layer_small_discrepancy_ok() {
    // 5 extra events out of 100 is 5%, below threshold.
    let validation = validate_dual_layer(105, 100);
    assert!(!validation.synthetic_detected);
}

#[test]
fn test_synthetic_stats_reset() {
    reset_synthetic_stats();
    let stats = get_synthetic_stats();
    assert_eq!(stats.total_events, 0);
    assert_eq!(stats.verified_hardware, 0);
}
