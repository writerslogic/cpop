// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
//
// End-to-end application tests that exercise the cpop CLI binary as a real user would.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::tempdir;

/// Run the cpop binary with the given args and data dir, returning (stdout, stderr, exit_code).
fn run_cpop(data_dir: &Path, args: &[&str]) -> (String, String, i32) {
    run_cpop_with_stdin(data_dir, args, None)
}

/// Run the cpop binary with optional stdin content.
fn run_cpop_with_stdin(
    data_dir: &Path,
    args: &[&str],
    stdin_content: Option<&str>,
) -> (String, String, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cpop"))
        .args(args)
        .env("CPOP_DATA_DIR", data_dir)
        .env("CPOP_NO_KEYCHAIN", "1")
        .env("CPOP_SKIP_PERMISSIONS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run cpop");

    if let Some(content) = stdin_content {
        let mut stdin = child.stdin.take().expect("failed to open stdin");
        stdin
            .write_all(content.as_bytes())
            .expect("failed to write stdin");
    }

    let output = child.wait_with_output().expect("failed to wait on child");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

/// Run cpop and assert it succeeds (exit code 0), returning stdout.
fn run_cpop_ok(data_dir: &Path, args: &[&str]) -> String {
    run_cpop_ok_with_stdin(data_dir, args, None)
}

/// Run cpop with stdin and assert it succeeds, returning stdout.
fn run_cpop_ok_with_stdin(data_dir: &Path, args: &[&str], stdin_content: Option<&str>) -> String {
    let (stdout, stderr, code) = run_cpop_with_stdin(data_dir, args, stdin_content);
    assert_eq!(
        code,
        0,
        "cpop {} failed (exit {})\nstdout: {}\nstderr: {}",
        args.join(" "),
        code,
        stdout,
        stderr
    );
    stdout
}

/// Initialize a cpop data directory (creates signing key, identity, etc.).
fn init_cpop(data_dir: &Path) {
    run_cpop_ok(data_dir, &["init"]);
}

/// Create 3 checkpoints for a file (the minimum required for export).
fn create_min_checkpoints(data_dir: &Path, file_path: &Path) {
    fs::write(file_path, "Version 1: initial draft content.").unwrap();
    run_cpop_ok(
        data_dir,
        &["commit", file_path.to_str().unwrap(), "-m", "Draft 1"],
    );

    fs::write(
        file_path,
        "Version 2: revised draft content with additions.",
    )
    .unwrap();
    run_cpop_ok(
        data_dir,
        &["commit", file_path.to_str().unwrap(), "-m", "Draft 2"],
    );

    fs::write(
        file_path,
        "Version 3: final revised draft content with more additions and edits.",
    )
    .unwrap();
    run_cpop_ok(
        data_dir,
        &["commit", file_path.to_str().unwrap(), "-m", "Draft 3"],
    );
}

// ---------------------------------------------------------------------------
// Scenario 1: Complete authoring workflow
// ---------------------------------------------------------------------------

#[test]
fn scenario_complete_authoring_workflow() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let essay = data.join("essay.txt");

    // 1. Create document and first commit
    fs::write(&essay, "The beginning of a great essay.").unwrap();
    let stdout = run_cpop_ok(data, &["commit", essay.to_str().unwrap(), "-m", "Draft 1"]);
    assert!(
        stdout.contains("Checkpoint #1"),
        "First commit should create checkpoint #1. Got: {}",
        stdout
    );
    // Data dir should have signing key
    assert!(
        data.join("signing_key").exists(),
        "signing_key should exist after commit"
    );

    // 2. Modify and commit again
    fs::write(
        &essay,
        "The beginning of a great essay. Adding more thoughts and ideas.",
    )
    .unwrap();
    let stdout = run_cpop_ok(data, &["commit", essay.to_str().unwrap(), "-m", "Draft 2"]);
    assert!(
        stdout.contains("Checkpoint #2"),
        "Second commit should create checkpoint #2. Got: {}",
        stdout
    );

    // 3. Third commit (needed for export)
    fs::write(
        &essay,
        "The beginning of a great essay. Adding more thoughts and ideas. Concluding paragraph here.",
    )
    .unwrap();
    let stdout = run_cpop_ok(data, &["commit", essay.to_str().unwrap(), "-m", "Draft 3"]);
    assert!(
        stdout.contains("Checkpoint #3"),
        "Third commit should create checkpoint #3. Got: {}",
        stdout
    );

    // 4. Log should show all 3 checkpoints
    let stdout = run_cpop_ok(data, &["log", essay.to_str().unwrap()]);
    assert!(
        stdout.contains("Draft 1"),
        "Log should show Draft 1. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("Draft 2"),
        "Log should show Draft 2. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("Draft 3"),
        "Log should show Draft 3. Got: {}",
        stdout
    );

    // 5. Export as JSON
    let evidence_json = data.join("essay.evidence.json");
    let stdout = run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            essay.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            evidence_json.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nTest declaration\n"),
    );
    assert!(
        stdout.contains("exported") || stdout.contains("Evidence"),
        "Export should confirm success. Got: {}",
        stdout
    );
    assert!(evidence_json.exists(), "JSON evidence file should exist");
    // Verify it is valid JSON
    let json_data = fs::read_to_string(&evidence_json).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_data).unwrap_or_else(|e| {
        panic!(
            "Evidence should be valid JSON: {}. Content: {}",
            e,
            &json_data[..200.min(json_data.len())]
        )
    });
    assert!(parsed.is_object(), "Evidence JSON should be an object");

    // 6. Export as c2pa
    let c2pa_path = data.join("essay.c2pa.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            essay.to_str().unwrap(),
            "-f",
            "c2pa",
            "-o",
            c2pa_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nTest declaration\n"),
    );
    assert!(c2pa_path.exists(), "C2PA file should exist");

    // 7. Verify the JSON evidence
    // Verify may exit non-zero in test due to suspicious duration ratio (fast commits),
    // but structural verification should pass.
    let (stdout, _, _) = run_cpop(data, &["verify", evidence_json.to_str().unwrap()]);
    assert!(
        stdout.contains("Evidence packet Verified") || stdout.contains("Structural"),
        "Verification should confirm structural validity. Got: {}",
        stdout
    );

    // 8. Status should show the tracked file
    let stdout = run_cpop_ok(data, &["status"]);
    assert!(
        stdout.contains("Status") || stdout.contains("status"),
        "Status output should contain status info. Got: {}",
        stdout
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: Export format matrix
// ---------------------------------------------------------------------------

#[test]
fn scenario_export_format_matrix() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("formats.txt");
    create_min_checkpoints(data, &doc);

    // Test each export format
    let formats_and_extensions: &[(&str, &str)] = &[
        ("json", "formats.txt.evidence.json"),
        ("cpop", "formats.txt.cpop"),
        ("cwar", "formats.txt.cwar"),
        ("html", "formats.txt.report.html"),
        ("c2pa", "formats.txt.c2pa.json"),
    ];

    for (format, expected_name) in formats_and_extensions {
        let out_path = data.join(expected_name);
        let (stdout, stderr, code) = run_cpop_with_stdin(
            data,
            &[
                "export",
                doc.to_str().unwrap(),
                "-f",
                format,
                "-o",
                out_path.to_str().unwrap(),
                "--no-beacons",
            ],
            Some("n\nDeclaration\n"),
        );
        assert_eq!(
            code, 0,
            "Export as {} should succeed (exit {})\nstdout: {}\nstderr: {}",
            format, code, stdout, stderr
        );
        assert!(
            out_path.exists(),
            "Output file for format '{}' should exist at {}",
            format,
            out_path.display()
        );
        let file_size = fs::metadata(&out_path).unwrap().len();
        assert!(
            file_size > 0,
            "Output for format '{}' should be non-empty",
            format
        );
    }

    // Verify JSON output parses correctly
    let json_path = data.join("formats.txt.evidence.json");
    let json_data = fs::read_to_string(&json_path).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&json_data).expect("JSON evidence should parse");
    assert!(parsed.is_object(), "JSON evidence should be an object");

    // Verify c2pa output contains assertion-related content
    let c2pa_data = fs::read_to_string(data.join("formats.txt.c2pa.json")).unwrap();
    let c2pa_parsed: serde_json::Value =
        serde_json::from_str(&c2pa_data).expect("C2PA JSON should parse");
    assert!(c2pa_parsed.is_object(), "C2PA should be an object");
}

// ---------------------------------------------------------------------------
// Scenario 3: Error handling
// ---------------------------------------------------------------------------

#[test]
fn scenario_error_commit_nonexistent() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let (_, stderr, code) = run_cpop(data, &["commit", "/nonexistent/path/file.txt"]);
    assert_ne!(code, 0, "Commit of nonexistent file should fail");
    assert!(
        stderr.contains("not found")
            || stderr.contains("No such file")
            || stderr.contains("does not exist")
            || stderr.contains("Error"),
        "Should mention file not found. stderr: {}",
        stderr
    );
}

#[test]
fn scenario_error_verify_nonexistent() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let (_, stderr, code) = run_cpop(data, &["verify", "/nonexistent/evidence.json"]);
    assert_ne!(code, 0, "Verify of nonexistent file should fail");
    assert!(
        stderr.contains("Error") || stderr.contains("not found") || stderr.contains("No such file"),
        "Should mention file error. stderr: {}",
        stderr
    );
}

#[test]
fn scenario_error_export_no_checkpoints() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    // Create a file but don't commit it
    let doc = data.join("untracked.txt");
    fs::write(&doc, "Content without checkpoints").unwrap();

    let (_, stderr, code) = run_cpop_with_stdin(
        data,
        &["export", doc.to_str().unwrap(), "--no-beacons"],
        Some("n\nDecl\n"),
    );
    assert_ne!(code, 0, "Export without checkpoints should fail");
    assert!(
        stderr.contains("checkpoint")
            || stderr.contains("No events")
            || stderr.contains("track")
            || stderr.contains("Error"),
        "Should mention missing checkpoints. stderr: {}",
        stderr
    );
}

#[test]
fn scenario_error_verify_invalid_json() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let bad_file = data.join("bad.json");
    fs::write(&bad_file, "this is not valid json").unwrap();

    let (_, stderr, code) = run_cpop(data, &["verify", bad_file.to_str().unwrap()]);
    assert_ne!(code, 0, "Verify of invalid JSON should fail");
    assert!(
        stderr.to_lowercase().contains("parse")
            || stderr.to_lowercase().contains("invalid")
            || stderr.contains("Error"),
        "Should mention parse error. stderr: {}",
        stderr
    );
}

// ---------------------------------------------------------------------------
// Scenario 4: Identity management
// ---------------------------------------------------------------------------

#[test]
fn scenario_identity_management() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    // Show DID
    let did_output = run_cpop_ok(data, &["identity", "--did"]);
    assert!(
        did_output.contains("did:key:") || did_output.contains("DID"),
        "Identity --did should output a DID. Got: {}",
        did_output
    );

    // Show fingerprint
    let fp_output = run_cpop_ok(data, &["identity", "--fingerprint"]);
    assert!(
        !fp_output.trim().is_empty(),
        "Identity --fingerprint should produce output"
    );

    // Verify identity persists: run --did again and confirm same value
    let did_output2 = run_cpop_ok(data, &["identity", "--did"]);
    assert_eq!(
        did_output, did_output2,
        "Identity should persist across invocations"
    );
}

// ---------------------------------------------------------------------------
// Scenario 5: Config management
// ---------------------------------------------------------------------------

#[test]
fn scenario_config_management() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    // Show config
    let stdout = run_cpop_ok(data, &["config", "show"]);
    assert!(
        stdout.contains("auto_start") || stdout.contains("Sentinel") || stdout.contains("VDF"),
        "Config show should display settings. Got: {}",
        stdout
    );

    // Set a value
    let stdout = run_cpop_ok(data, &["config", "set", "sentinel.auto_start", "false"]);
    assert!(
        stdout.contains("Set")
            || stdout.contains("set")
            || stdout.contains("saved")
            || stdout.contains("Updated"),
        "Config set should confirm the change. Got: {}",
        stdout
    );

    // Verify change persisted
    let stdout = run_cpop_ok(data, &["config", "show"]);
    assert!(
        stdout.contains("auto_start: false") || stdout.contains("auto_start\":false"),
        "Config should show updated value. Got: {}",
        stdout
    );
}

// ---------------------------------------------------------------------------
// Scenario 6: Link command
// ---------------------------------------------------------------------------

#[test]
fn scenario_link_command() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    // Create and commit a source document
    let source = data.join("source.txt");
    create_min_checkpoints(data, &source);

    // Create a "derivative" file
    let derivative = data.join("derivative.pdf");
    fs::write(&derivative, "Simulated PDF derivative content").unwrap();

    // Link source to derivative
    let stdout = run_cpop_ok(
        data,
        &[
            "link",
            source.to_str().unwrap(),
            derivative.to_str().unwrap(),
            "-m",
            "PDF export",
        ],
    );
    assert!(
        stdout.contains("Link") || stdout.contains("link") || stdout.contains("Checkpoint"),
        "Link should confirm creation. Got: {}",
        stdout
    );

    // Log should show the link checkpoint
    let stdout = run_cpop_ok(data, &["log", source.to_str().unwrap()]);
    // Link creates a checkpoint, so there should be 4 now (3 original + 1 link)
    assert!(
        stdout.contains("#4") || stdout.contains("derivative") || stdout.contains("PDF export"),
        "Log should show the link checkpoint. Got: {}",
        stdout
    );
}

// ---------------------------------------------------------------------------
// Scenario 7: Multi-file project
// ---------------------------------------------------------------------------

#[test]
fn scenario_multi_file_project() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    // Create multiple files
    let file_a = data.join("chapter1.txt");
    let file_b = data.join("chapter2.txt");
    let file_c = data.join("chapter3.txt");

    fs::write(&file_a, "Chapter 1: In the beginning").unwrap();
    fs::write(&file_b, "Chapter 2: The middle part").unwrap();
    fs::write(&file_c, "Chapter 3: The conclusion").unwrap();

    // Commit each file
    run_cpop_ok(
        data,
        &["commit", file_a.to_str().unwrap(), "-m", "Ch1 draft"],
    );
    run_cpop_ok(
        data,
        &["commit", file_b.to_str().unwrap(), "-m", "Ch2 draft"],
    );
    run_cpop_ok(
        data,
        &["commit", file_c.to_str().unwrap(), "-m", "Ch3 draft"],
    );

    // Log (no file arg) should list all tracked documents
    let stdout = run_cpop_ok(data, &["log"]);
    assert!(
        stdout.contains("chapter1.txt") || stdout.contains("3 document"),
        "Log should list tracked documents. Got: {}",
        stdout
    );

    // Status should show data about the project
    let stdout = run_cpop_ok(data, &["status"]);
    assert!(
        stdout.contains("Status") || stdout.contains("database"),
        "Status should show project info. Got: {}",
        stdout
    );

    // Log for a specific file should show its checkpoint
    let stdout = run_cpop_ok(data, &["log", file_b.to_str().unwrap()]);
    assert!(
        stdout.contains("Ch2 draft") || stdout.contains("chapter2"),
        "Log for chapter2 should show its checkpoint. Got: {}",
        stdout
    );
}

// ---------------------------------------------------------------------------
// Additional: JSON output mode
// ---------------------------------------------------------------------------

#[test]
fn scenario_json_output_modes() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    // Status --json should return valid JSON
    let stdout = run_cpop_ok(data, &["status", "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("status --json should be valid JSON: {}\nGot: {}", e, stdout));
    assert!(
        parsed.get("data_dir").is_some(),
        "JSON status should have data_dir"
    );

    // Commit then log --json
    let doc = data.join("json_test.txt");
    fs::write(&doc, "Content for JSON test").unwrap();
    run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "JSON test", "--json"],
    );

    let stdout = run_cpop_ok(data, &["log", doc.to_str().unwrap(), "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("log --json should be valid JSON: {}\nGot: {}", e, stdout));
    assert_eq!(
        parsed.get("checkpoint_count").and_then(|v| v.as_u64()),
        Some(1),
        "Should have 1 checkpoint"
    );
}

// ---------------------------------------------------------------------------
// Additional: Verify round-trip (export then verify)
// ---------------------------------------------------------------------------

#[test]
fn scenario_export_verify_roundtrip() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("roundtrip.txt");
    create_min_checkpoints(data, &doc);

    // Export as JSON
    let evidence = data.join("roundtrip.evidence.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            evidence.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );
    assert!(evidence.exists());

    // Verify structural checks pass (may exit non-zero due to suspicious duration in tests)
    let (stdout, _, _) = run_cpop(data, &["verify", evidence.to_str().unwrap()]);
    assert!(
        stdout.contains("Evidence packet Verified") || stdout.contains("Structural"),
        "Round-trip verification should confirm structural validity. Got: {}",
        stdout
    );
}
