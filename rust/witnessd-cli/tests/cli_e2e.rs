use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_full_workflow() {
    let dir = tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_witnessd-cli");

    // Helper to run command
    let run = |args: &[&str], input: Option<&str>| {
        use std::io::Write;
        use std::process::Stdio;

        let mut child = Command::new(bin)
            .args(args)
            .env("WITNESSD_DATA_DIR", dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn process");

        if let Some(stdin_content) = input {
            let mut stdin = child.stdin.take().expect("Failed to open stdin");
            stdin
                .write_all(stdin_content.as_bytes())
                .expect("Failed to write to stdin");
        }

        let output = child.wait_with_output().expect("failed to wait on child");

        if !output.status.success() {
            panic!(
                "Command failed: witnessd {}\nSTDOUT: {}\nSTDERR: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        String::from_utf8_lossy(&output.stdout).to_string()
    };

    // 1. Init
    println!("Testing init...");
    let stdout = run(&["init"], None);
    assert!(stdout.contains("initialized successfully"));
    assert!(dir.path().join("signing_key").exists());

    // 2. Status
    println!("Testing status...");
    let stdout = run(&["status"], None);
    assert!(stdout.contains("witnessd Status"));
    assert!(stdout.contains("VERIFIED"));

    // 3. Commit
    println!("Testing commit...");
    let doc_path = dir.path().join("test.txt");
    fs::write(&doc_path, "First version content").unwrap();

    let stdout = run(
        &["commit", doc_path.to_str().unwrap(), "-m", "First commit"],
        None,
    );
    assert!(stdout.contains("Checkpoint #1 created"));

    // Update file and commit again
    fs::write(&doc_path, "Second version content - more text").unwrap();
    let stdout = run(
        &["commit", doc_path.to_str().unwrap(), "-m", "Second commit"],
        None,
    );
    assert!(stdout.contains("Checkpoint #2 created"));

    // 4. Log
    println!("Testing log...");
    let stdout = run(&["log", doc_path.to_str().unwrap()], None);
    assert!(stdout.contains("Checkpoint History"));
    assert!(stdout.contains("First commit"));
    assert!(stdout.contains("Second commit"));

    // 5. Export
    println!("Testing export...");
    let evidence_path = dir.path().join("evidence.json");
    // Provide answers for: AI tools (n), Declaration statement
    let stdout = run(
        &[
            "export",
            doc_path.to_str().unwrap(),
            "-o",
            evidence_path.to_str().unwrap(),
        ],
        Some("n\nTest declaration\n"),
    );
    assert!(stdout.contains("Evidence exported to"));
    assert!(evidence_path.exists());

    // 6. Verify
    println!("Testing verify...");
    let stdout = run(&["verify", evidence_path.to_str().unwrap()], None);
    assert!(stdout.contains("Evidence packet VERIFIED"));
}
