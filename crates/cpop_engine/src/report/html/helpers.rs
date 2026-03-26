// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use std::fmt::{self, Write};

pub(super) fn row(html: &mut String, label: &str, value: &str) -> fmt::Result {
    write!(
        html,
        "<tr><td>{}</td><td>{}</td></tr>",
        label,
        html_escape(value)
    )
}

pub(super) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

pub(super) fn format_lr(lr: f64) -> String {
    if !lr.is_finite() || lr < 0.0 {
        return "N/A".to_string();
    }
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

pub(super) fn format_number(n: u64) -> String {
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

pub(super) fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub(super) fn format_duration_human(seconds: f64) -> String {
    if seconds.is_nan() || seconds < 0.0 {
        return "N/A".to_string();
    }
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
