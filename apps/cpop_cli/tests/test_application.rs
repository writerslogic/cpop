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

// ===========================================================================
// Track command edge cases
// ===========================================================================

#[test]
fn test_track_creates_data_dir() {
    let dir = tempdir().unwrap();
    let data = dir.path().join("nested").join("cpop_data");
    // Data dir does not exist yet
    assert!(!data.exists());

    // Running any command with CPOP_DATA_DIR should create it via ensure_dirs
    let doc = dir.path().join("doc.txt");
    fs::write(&doc, "some content").unwrap();
    run_cpop_ok(&data, &["commit", doc.to_str().unwrap(), "-m", "first"]);

    assert!(
        data.exists(),
        "CPOP_DATA_DIR should be created on first use"
    );
}

#[test]
fn test_track_binary_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let bin_file = data.join("random.bin");
    // Write random-looking binary bytes (not valid UTF-8)
    let bytes: Vec<u8> = (0..256).map(|i| i as u8).collect();
    fs::write(&bin_file, &bytes).unwrap();

    let stdout = run_cpop_ok(
        data,
        &["commit", bin_file.to_str().unwrap(), "-m", "binary file"],
    );
    assert!(
        stdout.contains("Checkpoint #1"),
        "Binary file commit should create checkpoint #1. Got: {}",
        stdout
    );
}

#[test]
fn test_track_symlink() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let real_file = data.join("real.txt");
    fs::write(&real_file, "symlink target content").unwrap();

    let link_path = data.join("link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_file, &link_path).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&real_file, &link_path).unwrap();

    // Commit via the symlink; should resolve to the real file
    let (stdout, stderr, code) = run_cpop(
        data,
        &["commit", link_path.to_str().unwrap(), "-m", "via symlink"],
    );
    // Should succeed (resolves symlink) or warn
    assert!(
        code == 0 || stderr.contains("symlink") || stderr.contains("resolve"),
        "Symlink commit should succeed or produce a symlink warning. \
         exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}

#[test]
fn test_track_large_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let large_file = data.join("large.txt");
    // 1 MB of text
    let content = "A".repeat(1_000_000);
    fs::write(&large_file, &content).unwrap();

    let start = std::time::Instant::now();
    let stdout = run_cpop_ok(
        data,
        &["commit", large_file.to_str().unwrap(), "-m", "large file"],
    );
    let elapsed = start.elapsed();

    assert!(
        stdout.contains("Checkpoint #1"),
        "Large file commit should succeed. Got: {}",
        stdout
    );
    assert!(
        elapsed.as_secs() < 30,
        "Large file commit should complete in <30s, took {:?}",
        elapsed
    );
}

#[test]
fn test_track_special_chars_in_path() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    // Create a subdirectory with spaces and a file with unicode and hyphens
    let subdir = data.join("my documents");
    fs::create_dir_all(&subdir).unwrap();
    let special_file = subdir.join("resume-draft_v2.txt");
    fs::write(&special_file, "Content with special path chars").unwrap();

    let stdout = run_cpop_ok(
        data,
        &[
            "commit",
            special_file.to_str().unwrap(),
            "-m",
            "special path",
        ],
    );
    assert!(
        stdout.contains("Checkpoint #1"),
        "File with special chars in path should commit. Got: {}",
        stdout
    );
}

// ===========================================================================
// Commit command edge cases
// ===========================================================================

#[test]
fn test_commit_empty_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let empty = data.join("empty.txt");
    fs::write(&empty, "").unwrap();

    let (stdout, stderr, code) = run_cpop(
        data,
        &["commit", empty.to_str().unwrap(), "-m", "empty file"],
    );
    // May succeed (zero-byte checkpoint) or fail with validation error; both are acceptable
    assert!(
        code == 0 || stderr.contains("empty") || stderr.contains("Error"),
        "Empty file commit should either succeed or give a clear error. \
         exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}

#[test]
fn test_commit_unchanged_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("stable.txt");
    fs::write(&doc, "Unchanging content for both commits").unwrap();

    let stdout1 = run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "first commit"],
    );
    assert!(
        stdout1.contains("Checkpoint #1"),
        "First commit should succeed. Got: {}",
        stdout1
    );

    // Commit same content again without modification
    let stdout2 = run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "second commit"],
    );
    assert!(
        stdout2.contains("Checkpoint #2"),
        "Second commit of unchanged file should still succeed. Got: {}",
        stdout2
    );
}

#[test]
fn test_commit_with_message() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("msg_test.txt");
    fs::write(&doc, "Content for message test").unwrap();
    run_cpop_ok(
        data,
        &[
            "commit",
            doc.to_str().unwrap(),
            "-m",
            "My custom message here",
        ],
    );

    // Log should contain the message
    let stdout = run_cpop_ok(data, &["log", doc.to_str().unwrap()]);
    assert!(
        stdout.contains("My custom message here"),
        "Log should show the commit message. Got: {}",
        stdout
    );
}

#[test]
fn test_commit_rapid_succession() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("rapid.txt");
    for i in 1..=5 {
        let content = format!("Rapid commit version {} with enough unique text", i);
        fs::write(&doc, &content).unwrap();
        let stdout = run_cpop_ok(
            data,
            &[
                "commit",
                doc.to_str().unwrap(),
                "-m",
                &format!("Rapid #{}", i),
            ],
        );
        assert!(
            stdout.contains(&format!("Checkpoint #{}", i)),
            "Rapid commit #{} should create checkpoint #{}. Got: {}",
            i,
            i,
            stdout
        );
    }

    // Verify all 5 are logged
    let stdout = run_cpop_ok(data, &["log", doc.to_str().unwrap(), "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("log --json should parse: {}\nGot: {}", e, stdout));
    assert_eq!(
        parsed.get("checkpoint_count").and_then(|v| v.as_u64()),
        Some(5),
        "Should have 5 checkpoints after rapid succession"
    );
}

#[test]
fn test_commit_after_delete_content() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("delete_test.txt");
    fs::write(&doc, "Full content that will be deleted").unwrap();
    run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "with content"],
    );

    // Delete content (write empty or near-empty)
    fs::write(&doc, "").unwrap();
    let (stdout, stderr, code) = run_cpop(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "after delete"],
    );
    // Should succeed or give a meaningful error
    assert!(
        code == 0 || stderr.contains("empty") || stderr.contains("Error"),
        "Commit after content deletion should handle gracefully. \
         exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}

// ===========================================================================
// Export command variations
// ===========================================================================

#[test]
fn test_export_cpop_binary_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("binary_export.txt");
    create_min_checkpoints(data, &doc);

    let out_path = data.join("evidence.cpop");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "cpop",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    assert!(out_path.exists(), ".cpop file should exist");
    let bytes = fs::read(&out_path).unwrap();
    assert!(
        bytes.len() > 10,
        ".cpop file should be non-trivial binary, got {} bytes",
        bytes.len()
    );
    // CBOR files typically don't start with printable ASCII
    // Just verify it is non-empty binary data
}

#[test]
fn test_export_cwar_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("cwar_export.txt");
    create_min_checkpoints(data, &doc);

    let out_path = data.join("evidence.cwar");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "cwar",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    assert!(out_path.exists(), ".cwar file should exist");
    let size = fs::metadata(&out_path).unwrap().len();
    assert!(
        size > 0,
        ".cwar file should be non-empty, got {} bytes",
        size
    );
}

#[test]
fn test_export_html_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("html_export.txt");
    create_min_checkpoints(data, &doc);

    let out_path = data.join("report.html");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "html",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    assert!(out_path.exists(), ".html file should exist");
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(
        content.contains("<html") || content.contains("<!DOCTYPE") || content.contains("<HTML"),
        "HTML export should contain HTML tags. Got first 200 chars: {}",
        &content[..200.min(content.len())]
    );
}

#[test]
fn test_export_pdf_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("pdf_export.txt");
    create_min_checkpoints(data, &doc);

    let out_path = data.join("report.pdf");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "pdf",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    assert!(out_path.exists(), ".pdf file should exist");
    let bytes = fs::read(&out_path).unwrap();
    assert!(
        bytes.starts_with(b"%PDF"),
        "PDF export should start with %PDF magic bytes. Got first 4 bytes: {:?}",
        &bytes[..4.min(bytes.len())]
    );
}

#[test]
fn test_export_c2pa_assertion_content() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("c2pa_content.txt");
    create_min_checkpoints(data, &doc);

    let out_path = data.join("assertion.c2pa.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "c2pa",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    let content = fs::read_to_string(&out_path).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("C2PA should be valid JSON");
    assert!(parsed.is_object(), "C2PA should be a JSON object");
    // C2PA assertions should have a label field
    assert!(
        parsed.get("label").is_some()
            || parsed.get("assertion").is_some()
            || parsed.get("dc:title").is_some()
            || parsed.get("assertions").is_some(),
        "C2PA JSON should contain assertion-related fields. Keys: {:?}",
        parsed.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
}

#[test]
fn test_export_custom_output_path() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("custom_out.txt");
    create_min_checkpoints(data, &doc);

    // Export to a custom nested path
    let custom_dir = data.join("output").join("nested");
    fs::create_dir_all(&custom_dir).unwrap();
    let out_path = custom_dir.join("my_evidence.json");

    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    assert!(
        out_path.exists(),
        "Evidence should be written to custom output path: {}",
        out_path.display()
    );
    let content = fs::read_to_string(&out_path).unwrap();
    let _: serde_json::Value =
        serde_json::from_str(&content).expect("Custom path output should be valid JSON");
}

#[test]
fn test_export_overwrites_existing() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("overwrite.txt");
    create_min_checkpoints(data, &doc);

    let out_path = data.join("overwrite.evidence.json");

    // Export first time
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );
    let size1 = fs::metadata(&out_path).unwrap().len();
    assert!(size1 > 0, "First export should produce non-empty file");

    // Add another checkpoint and export again to same path
    fs::write(
        &doc,
        "Version 4: even more content added for the overwrite test.",
    )
    .unwrap();
    run_cpop_ok(data, &["commit", doc.to_str().unwrap(), "-m", "Draft 4"]);

    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );
    let size2 = fs::metadata(&out_path).unwrap().len();
    assert!(
        size2 > 0,
        "Second export should produce non-empty file (overwrite)"
    );
}

// ===========================================================================
// Verify command variations
// ===========================================================================

#[test]
fn test_verify_json_output() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("verify_json.txt");
    create_min_checkpoints(data, &doc);

    let evidence = data.join("verify_json.evidence.json");
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

    let (stdout, _, _) = run_cpop(data, &["verify", evidence.to_str().unwrap(), "--json"]);
    // With --json flag, output should be parseable JSON
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "verify --json should produce valid JSON: {}\nGot: {}",
            e, stdout
        )
    });
    assert!(
        parsed.is_object(),
        "verify --json should return a JSON object"
    );
}

#[test]
fn test_verify_corrupted_evidence() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("corrupt_test.txt");
    create_min_checkpoints(data, &doc);

    let evidence = data.join("corrupt.evidence.json");
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

    // Corrupt the evidence by modifying a field
    let mut content = fs::read_to_string(&evidence).unwrap();
    // Replace a hash value to simulate corruption
    content = content.replacen("\"content_hash\"", "\"content_hash_CORRUPTED\"", 1);
    fs::write(&evidence, &content).unwrap();

    let (stdout, stderr, code) = run_cpop(data, &["verify", evidence.to_str().unwrap()]);
    // Should detect corruption (may still exit 0 with warnings or exit non-zero)
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        code != 0
            || combined.to_lowercase().contains("fail")
            || combined.to_lowercase().contains("error")
            || combined.to_lowercase().contains("corrupt")
            || combined.to_lowercase().contains("invalid")
            || combined.contains("CORRUPTED"),
        "Corrupted evidence should be detected. exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}

#[test]
fn test_verify_truncated_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    // Write a truncated JSON file
    let truncated = data.join("truncated.json");
    fs::write(&truncated, r#"{"version": 1, "checkpoints": ["#).unwrap();

    let (_, stderr, code) = run_cpop(data, &["verify", truncated.to_str().unwrap()]);
    assert_ne!(code, 0, "Truncated evidence file should fail verification");
    assert!(
        stderr.to_lowercase().contains("parse")
            || stderr.to_lowercase().contains("invalid")
            || stderr.contains("Error")
            || stderr.to_lowercase().contains("eof"),
        "Should report parse error for truncated file. stderr: {}",
        stderr
    );
}

#[test]
fn test_verify_cwar_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("verify_cwar.txt");
    create_min_checkpoints(data, &doc);

    let cwar_path = data.join("verify_test.cwar");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "cwar",
            "-o",
            cwar_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    assert!(cwar_path.exists(), ".cwar file should exist for verify");
    let (stdout, stderr, code) = run_cpop(data, &["verify", cwar_path.to_str().unwrap()]);
    // Verify should at least attempt to parse the cwar without panicking
    assert!(
        code == 0
            || stderr.contains("Error")
            || stdout.contains("Verified")
            || stdout.contains("attestation"),
        "Verify of .cwar should produce meaningful output. \
         exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}

// ===========================================================================
// Log command variations
// ===========================================================================

#[test]
fn test_log_empty_no_checkpoints() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("no_commits.txt");
    fs::write(&doc, "Never committed content").unwrap();

    let stdout = run_cpop_ok(data, &["log", doc.to_str().unwrap()]);
    assert!(
        stdout.contains("No checkpoints") || stdout.trim().is_empty(),
        "Log with no commits should show empty message. Got: {}",
        stdout
    );
}

#[test]
fn test_log_shows_messages() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("log_msg.txt");
    fs::write(&doc, "First version of the document").unwrap();
    run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "Initial rough draft"],
    );

    fs::write(&doc, "Second version with significant revisions applied").unwrap();
    run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "Major revision pass"],
    );

    let stdout = run_cpop_ok(data, &["log", doc.to_str().unwrap()]);
    assert!(
        stdout.contains("Initial rough draft"),
        "Log should show first message. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("Major revision pass"),
        "Log should show second message. Got: {}",
        stdout
    );
}

#[test]
fn test_log_json_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("log_json.txt");
    fs::write(&doc, "Content for JSON log test").unwrap();
    run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "JSON log entry"],
    );

    let stdout = run_cpop_ok(data, &["log", doc.to_str().unwrap(), "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("log --json should be valid JSON: {}\nGot: {}", e, stdout));
    assert!(
        parsed.get("checkpoint_count").is_some(),
        "JSON log should have checkpoint_count field. Got: {}",
        stdout
    );
    assert!(
        parsed.get("checkpoints").is_some(),
        "JSON log should have checkpoints array. Got: {}",
        stdout
    );
}

#[test]
fn test_log_per_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let file_a = data.join("alpha.txt");
    let file_b = data.join("beta.txt");

    fs::write(&file_a, "Alpha content").unwrap();
    fs::write(&file_b, "Beta content").unwrap();

    run_cpop_ok(
        data,
        &["commit", file_a.to_str().unwrap(), "-m", "Alpha commit"],
    );
    run_cpop_ok(
        data,
        &["commit", file_b.to_str().unwrap(), "-m", "Beta commit"],
    );

    // Log for alpha should only show alpha's checkpoint
    let stdout_a = run_cpop_ok(data, &["log", file_a.to_str().unwrap()]);
    assert!(
        stdout_a.contains("Alpha commit"),
        "Log for alpha should show Alpha commit. Got: {}",
        stdout_a
    );
    assert!(
        !stdout_a.contains("Beta commit"),
        "Log for alpha should NOT show Beta commit. Got: {}",
        stdout_a
    );

    // Log for beta should only show beta's checkpoint
    let stdout_b = run_cpop_ok(data, &["log", file_b.to_str().unwrap()]);
    assert!(
        stdout_b.contains("Beta commit"),
        "Log for beta should show Beta commit. Got: {}",
        stdout_b
    );
    assert!(
        !stdout_b.contains("Alpha commit"),
        "Log for beta should NOT show Alpha commit. Got: {}",
        stdout_b
    );
}

// ===========================================================================
// Status command variations
// ===========================================================================

#[test]
fn test_status_no_tracking() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let stdout = run_cpop_ok(data, &["status"]);
    assert!(
        stdout.contains("Status") || stdout.contains("status") || stdout.contains("No"),
        "Status before any tracking should produce clean output. Got: {}",
        stdout
    );
}

#[test]
fn test_status_shows_tracked_files() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("tracked_status.txt");
    fs::write(&doc, "Content to track").unwrap();
    run_cpop_ok(data, &["commit", doc.to_str().unwrap(), "-m", "Track me"]);

    let stdout = run_cpop_ok(data, &["status"]);
    assert!(
        stdout.contains("tracked_status.txt")
            || stdout.contains("1 document")
            || stdout.contains("Documents: 1")
            || stdout.contains("Tracked documents: 1"),
        "Status should mention tracked file. Got: {}",
        stdout
    );
}

#[test]
fn test_status_json_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let stdout = run_cpop_ok(data, &["status", "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("status --json should be valid JSON: {}\nGot: {}", e, stdout));
    assert!(
        parsed.get("data_dir").is_some(),
        "JSON status should have data_dir. Got: {}",
        stdout
    );
}

// ===========================================================================
// Fingerprint command
// ===========================================================================

#[test]
fn test_fingerprint_list() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let (stdout, stderr, code) = run_cpop(data, &["fingerprint", "list"]);
    // Should run without panicking; may report no profiles or succeed
    assert!(
        code == 0 || stderr.contains("Error"),
        "fingerprint list should not panic. exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}

#[test]
fn test_fingerprint_show() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let (stdout, stderr, code) = run_cpop(data, &["fingerprint", "show"]);
    // Should run without panicking; may report no current profile
    assert!(
        code == 0 || stderr.contains("Error") || stderr.contains("No"),
        "fingerprint show should not panic. exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}

// ===========================================================================
// Help and version flags
// ===========================================================================

#[test]
fn test_help_flag() {
    let dir = tempdir().unwrap();
    let data = dir.path();

    let stdout = run_cpop_ok(data, &["--help"]);
    assert!(
        stdout.contains("CPOP") || stdout.contains("cpop") || stdout.contains("Usage"),
        "--help should show usage information. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("commit") && stdout.contains("export") && stdout.contains("verify"),
        "--help should list main commands. Got: {}",
        stdout
    );
}

#[test]
fn test_version_flag() {
    let dir = tempdir().unwrap();
    let data = dir.path();

    let stdout = run_cpop_ok(data, &["--version"]);
    assert!(
        stdout.contains("cpop") || stdout.contains("CPOP"),
        "--version should contain program name. Got: {}",
        stdout
    );
    // Version string should contain a semver-like pattern
    assert!(
        stdout.contains('.'),
        "--version should contain a version number with dots. Got: {}",
        stdout
    );
}

#[test]
fn test_subcommand_help() {
    let dir = tempdir().unwrap();
    let data = dir.path();

    // commit --help
    let stdout = run_cpop_ok(data, &["commit", "--help"]);
    assert!(
        stdout.contains("checkpoint") || stdout.contains("Checkpoint") || stdout.contains("commit"),
        "commit --help should describe the commit command. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("-m") || stdout.contains("--message"),
        "commit --help should mention the -m flag. Got: {}",
        stdout
    );

    // export --help
    let stdout = run_cpop_ok(data, &["export", "--help"]);
    assert!(
        stdout.contains("export") || stdout.contains("Export") || stdout.contains("evidence"),
        "export --help should describe the export command. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("json") && stdout.contains("cpop") && stdout.contains("cwar"),
        "export --help should list formats. Got: {}",
        stdout
    );

    // verify --help
    let stdout = run_cpop_ok(data, &["verify", "--help"]);
    assert!(
        stdout.contains("Verify") || stdout.contains("verify") || stdout.contains("evidence"),
        "verify --help should describe the verify command. Got: {}",
        stdout
    );
}
