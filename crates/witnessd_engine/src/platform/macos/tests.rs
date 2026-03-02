// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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
fn test_dual_layer_validation() {
    reset_hid_keystroke_count();
    let validation = validate_dual_layer(0);
    assert!(!validation.synthetic_detected);
    assert_eq!(validation.discrepancy, 0);
}

#[test]
fn test_synthetic_stats_reset() {
    reset_synthetic_stats();
    let stats = get_synthetic_stats();
    assert_eq!(stats.total_events, 0);
    assert_eq!(stats.verified_hardware, 0);
}
