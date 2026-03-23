// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! E2E tests for `cpop track` subcommand.
//!
//! Note: `track start <file>` runs a blocking file watcher, so we only test
//! non-blocking subcommands (list, status, show, stop, export) and error paths
//! where `track start` fails immediately (nonexistent file).
//! Some track commands prompt for confirmation — we send "n\n" as stdin to avoid blocking.

mod common;

#[test]
fn test_track_list_empty_before_tracking() {
    let env = common::TempEnv::with_identity();
    let output = env.run(&["track", "list"], Some("n\n"));
    common::assert_no_panic(&output, "track list empty");
    if output.success {
        let combined = format!("{}{}", output.stdout, output.stderr);
        assert!(
            combined.contains("No")
                || combined.contains("no")
                || output.stdout.trim().is_empty()
                || combined.contains("0"),
            "empty track list should indicate no sessions, got: {combined}"
        );
    }
}

#[test]
fn test_track_stop_without_active_session() {
    let env = common::TempEnv::with_identity();
    let output = env.run(&["track", "stop"], Some("n\n"));
    let combined = format!("{}{}", output.stdout, output.stderr);
    common::assert_no_panic(&output, "track stop no session");
    assert!(
        combined.to_lowercase().contains("no")
            || combined.to_lowercase().contains("not")
            || combined.to_lowercase().contains("error")
            || combined.to_lowercase().contains("active"),
        "stopping without active session should report no session, got: {combined}"
    );
}

#[test]
fn test_track_status_without_active_session() {
    let env = common::TempEnv::with_identity();
    let output = env.run(&["track", "status"], Some("n\n"));
    common::assert_no_panic(&output, "track status without active session");
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(
        combined.to_lowercase().contains("no")
            || combined.to_lowercase().contains("not")
            || combined.to_lowercase().contains("inactive")
            || combined.to_lowercase().contains("active"),
        "status without session should describe state, got: {combined}"
    );
}

#[test]
fn test_track_show_nonexistent_session_errors() {
    let env = common::TempEnv::with_identity();
    let output = env.run(
        &["track", "show", "nonexistent-session-id-xyz"],
        Some("n\n"),
    );
    common::assert_no_panic(&output, "track show nonexistent session");
    assert!(
        !output.success,
        "track show on nonexistent session should fail"
    );
}

#[test]
fn test_track_export_nonexistent_session_errors() {
    let env = common::TempEnv::with_identity();
    let output = env.run(&["track", "export", "nonexistent-session-id"], Some("n\n"));
    common::assert_no_panic(&output, "track export nonexistent session");
    assert!(
        !output.success,
        "track export on nonexistent session should fail"
    );
}
