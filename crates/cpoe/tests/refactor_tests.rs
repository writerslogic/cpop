// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use cpoe_engine::utils::stats::{coefficient_of_variation, mean, median, std_dev};
use cpoe_engine::utils::time::now_ns;

#[test]
fn test_now_ns_monotonic() {
    let t1 = now_ns();
    std::thread::sleep(std::time::Duration::from_millis(1));
    let t2 = now_ns();
    assert!(t2 >= t1);
    assert!(t1 > 0);
}

#[test]
fn test_stats_helpers() {
    let data = vec![100.0, 200.0, 300.0];
    assert_eq!(mean(&data), 200.0);

    let expected_std = (20000.0f64 / 3.0).sqrt();
    assert!((std_dev(&data) - expected_std).abs() < 1e-10);

    assert!((coefficient_of_variation(&data) - (expected_std / 200.0)).abs() < 1e-10);

    assert_eq!(median(&data), 200.0);

    let data2 = vec![1.0, 2.0, 3.0, 4.0];
    assert_eq!(median(&data2), 2.5);
}
