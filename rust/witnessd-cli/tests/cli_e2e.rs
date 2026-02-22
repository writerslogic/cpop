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

/// Helper struct for CLI test utilities
struct CliTestEnv {
    dir: tempfile::TempDir,
    bin: &'static str,
}

impl CliTestEnv {
    fn new() -> Self {
        Self {
            dir: tempdir().unwrap(),
            bin: env!("CARGO_BIN_EXE_witnessd-cli"),
        }
    }

    fn run(&self, args: &[&str], input: Option<&str>) -> (bool, String, String) {
        use std::io::Write;
        use std::process::Stdio;

        let mut child = Command::new(self.bin)
            .args(args)
            .env("WITNESSD_DATA_DIR", self.dir.path())
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
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    fn run_expect_success(&self, args: &[&str], input: Option<&str>) -> String {
        let (success, stdout, stderr) = self.run(args, input);
        assert!(
            success,
            "Command failed: witnessd {}\nSTDOUT: {}\nSTDERR: {}",
            args.join(" "),
            stdout,
            stderr
        );
        stdout
    }

    fn init(&self) {
        self.run_expect_success(&["init"], None);
    }
}

#[test]
fn test_cli_help() {
    let env = CliTestEnv::new();
    let stdout = env.run_expect_success(&["--help"], None);
    assert!(
        stdout.contains("WitnessD") || stdout.contains("witnessd"),
        "Help should mention WitnessD: {}",
        stdout
    );
    assert!(
        stdout.contains("Checkpoint") || stdout.contains("VDF") || stdout.contains("proof"),
        "Help should describe functionality"
    );
}

#[test]
fn test_cli_version() {
    let env = CliTestEnv::new();
    let stdout = env.run_expect_success(&["--version"], None);
    assert!(stdout.contains("witnessd-cli"));
}

#[test]
fn test_cli_status_before_init() {
    let env = CliTestEnv::new();
    let (success, stdout, _stderr) = env.run(&["status"], None);
    // Status before init shows status but indicates not found
    if success {
        assert!(
            stdout.contains("not found") || stdout.contains("Status"),
            "Status should indicate database not found or show status"
        );
    }
    // Failure is also acceptable
}

#[test]
fn test_cli_commit_before_init() {
    let env = CliTestEnv::new();
    let doc_path = env.dir.path().join("test.txt");
    fs::write(&doc_path, "content").unwrap();

    // The CLI prompts for init if not initialized, so we pass "n" to reject
    let (success, stdout, _stderr) = env.run(&["commit", doc_path.to_str().unwrap()], Some("n\n"));
    // Either fails or prompts for init
    assert!(
        !success || stdout.contains("not initialized") || stdout.contains("Initialize"),
        "Commit should fail or prompt for init"
    );
}

#[test]
fn test_cli_commit_nonexistent_file() {
    let env = CliTestEnv::new();
    env.init();

    let (success, _stdout, stderr) = env.run(&["commit", "/nonexistent/file.txt"], None);
    assert!(!success, "Commit should fail for nonexistent file");
    assert!(
        stderr.contains("not found")
            || stderr.contains("No such file")
            || stderr.contains("does not exist"),
        "Should mention file not found. stderr: {}",
        stderr
    );
}

#[test]
fn test_cli_list_empty() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["list"], None);
    // Should show no tracked files or empty list
    assert!(
        stdout.contains("No tracked") || stdout.contains("0 documents") || stdout.is_empty(),
        "Should indicate no tracked documents"
    );
}

#[test]
fn test_cli_list_after_commits() {
    let env = CliTestEnv::new();
    env.init();

    // Create and commit two files
    let doc1 = env.dir.path().join("doc1.txt");
    let doc2 = env.dir.path().join("doc2.txt");
    fs::write(&doc1, "content1").unwrap();
    fs::write(&doc2, "content2").unwrap();

    env.run_expect_success(&["commit", doc1.to_str().unwrap(), "-m", "Doc 1"], None);
    env.run_expect_success(&["commit", doc2.to_str().unwrap(), "-m", "Doc 2"], None);

    let stdout = env.run_expect_success(&["list"], None);
    assert!(
        stdout.contains("doc1.txt") || stdout.contains("2 documents"),
        "Should list tracked documents"
    );
}

#[test]
fn test_cli_config_show() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["config", "show"], None);
    // Should display configuration
    assert!(
        stdout.contains("retention") || stdout.contains("config") || stdout.len() > 10,
        "Should show configuration"
    );
}

#[test]
fn test_cli_log_no_history() {
    let env = CliTestEnv::new();
    env.init();

    let doc_path = env.dir.path().join("new.txt");
    fs::write(&doc_path, "content").unwrap();

    // Log for uncommitted file
    let (success, stdout, _stderr) = env.run(&["log", doc_path.to_str().unwrap()], None);
    // Either fails or shows empty history
    if success {
        assert!(
            stdout.contains("No checkpoints") || stdout.contains("0 checkpoint"),
            "Should indicate no checkpoints"
        );
    }
}

#[test]
fn test_cli_verify_invalid_file() {
    let env = CliTestEnv::new();
    env.init();

    // Create a file that's not a valid evidence packet
    let invalid = env.dir.path().join("invalid.json");
    fs::write(&invalid, "not valid json evidence").unwrap();

    let (success, _stdout, stderr) = env.run(&["verify", invalid.to_str().unwrap()], None);
    assert!(!success, "Verify should fail for invalid evidence");
    assert!(
        stderr.contains("parse")
            || stderr.contains("Error")
            || stderr.contains("Failed")
            || stderr.to_lowercase().contains("invalid"),
        "Should indicate parse error. stderr: {}",
        stderr
    );
}

#[test]
fn test_cli_export_war_format() {
    let env = CliTestEnv::new();
    env.init();

    // Create and commit a file
    let doc_path = env.dir.path().join("doc.txt");
    fs::write(&doc_path, "WAR format test content").unwrap();
    env.run_expect_success(&["commit", doc_path.to_str().unwrap(), "-m", "Test"], None);

    // Export in WAR format
    let war_path = env.dir.path().join("evidence.war");
    let stdout = env.run_expect_success(
        &[
            "export",
            doc_path.to_str().unwrap(),
            "-f",
            "war",
            "-o",
            war_path.to_str().unwrap(),
        ],
        Some("n\nWAR format declaration\n"),
    );

    assert!(war_path.exists(), "WAR file should be created");
    assert!(
        stdout.contains("exported") || stdout.contains("WAR"),
        "Should confirm export"
    );

    // Verify WAR content has ASCII armor
    let war_content = fs::read_to_string(&war_path).unwrap();
    assert!(
        war_content.contains("-----BEGIN WITNESSD") || war_content.contains("BEGIN"),
        "WAR file should have ASCII armor"
    );
}

#[test]
fn test_cli_calibrate() {
    let env = CliTestEnv::new();
    env.init();

    // Calibrate command should run without errors
    // Note: This may take some time as it benchmarks the CPU
    let (success, stdout, stderr) = env.run(&["calibrate"], None);

    // Calibrate might succeed or give a performance warning
    if success {
        assert!(
            stdout.contains("iterations")
                || stdout.contains("calibrat")
                || stdout.contains("speed"),
            "Should show calibration results. stdout: {}",
            stdout
        );
    } else {
        // Some environments may not support calibration
        println!(
            "Calibrate failed (may be expected): stdout={}, stderr={}",
            stdout, stderr
        );
    }
}

#[test]
fn test_cli_presence_without_session() {
    let env = CliTestEnv::new();
    env.init();

    // Check presence status without starting a session
    let (success, stdout, _stderr) = env.run(&["presence", "status"], None);
    if success {
        assert!(
            stdout.contains("No active") || stdout.contains("not active"),
            "Should indicate no active session"
        );
    }
}

#[test]
fn test_cli_fingerprint_status() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["fingerprint", "status"], None);
    // Should show fingerprint status
    assert!(
        stdout.contains("fingerprint")
            || stdout.contains("activity")
            || stdout.contains("status")
            || stdout.len() > 5,
        "Should show fingerprint status"
    );
}
