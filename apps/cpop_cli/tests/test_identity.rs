// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! E2E tests for `cpop identity` subcommand.

mod common;

use std::fs;

// ---------------------------------------------------------------------------
// 1. DID format
// ---------------------------------------------------------------------------

#[test]
fn test_identity_did_format_starts_with_did_key() {
    let env = common::TempEnv::with_identity();
    let stdout = env.run_expect_success(&["identity", "--did"], None);
    assert!(
        stdout.contains("did:key:z"),
        "Expected DID starting with 'did:key:z', got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// 2. DID is deterministic
// ---------------------------------------------------------------------------

#[test]
fn test_identity_did_is_deterministic() {
    let env = common::TempEnv::with_identity();
    let first = env.run_expect_success(&["identity", "--did"], None);
    let second = env.run_expect_success(&["identity", "--did"], None);
    assert_eq!(
        first.trim(),
        second.trim(),
        "DID must be deterministic across invocations"
    );
}

// ---------------------------------------------------------------------------
// 3. Fingerprint contains hex characters
// ---------------------------------------------------------------------------

#[test]
fn test_identity_fingerprint_is_hex() {
    let env = common::TempEnv::with_identity();
    let stdout = env.run_expect_success(&["identity", "--fingerprint"], None);
    // Extract the token after "Fingerprint:" and verify it is hex
    let fingerprint_value = stdout
        .split(':')
        .last()
        .expect("expected 'Fingerprint: <value>' in output")
        .trim()
        .to_string();
    assert!(
        !fingerprint_value.is_empty(),
        "Fingerprint value must not be empty"
    );
    assert!(
        fingerprint_value
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':'),
        "Fingerprint must consist of hex characters (and optional colons), got: {fingerprint_value}"
    );
}

// ---------------------------------------------------------------------------
// 4. Mnemonic word count is 12 or 24
// ---------------------------------------------------------------------------

#[test]
fn test_identity_mnemonic_word_count() {
    let env = common::TempEnv::with_identity();
    let stdout = env.run_expect_success(&["identity", "--mnemonic"], None);
    // The mnemonic line is the last non-empty, non-header line of output.
    let mnemonic_line = stdout
        .lines()
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with("===")
                && !l.starts_with("KEEP")
                && !l.starts_with("Note:")
                && !l.starts_with("     ")
        })
        .last()
        .expect("expected a mnemonic line in output");
    let word_count = mnemonic_line.split_whitespace().count();
    assert!(
        word_count == 12 || word_count == 24,
        "Expected 12 or 24 mnemonic words, got {word_count}: {mnemonic_line}"
    );
}

// ---------------------------------------------------------------------------
// 5. Mnemonic words are lowercase ASCII
// ---------------------------------------------------------------------------

#[test]
fn test_identity_mnemonic_words_are_ascii_lowercase() {
    let env = common::TempEnv::with_identity();
    let stdout = env.run_expect_success(&["identity", "--mnemonic"], None);
    let mnemonic_line = stdout
        .lines()
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with("===")
                && !l.starts_with("KEEP")
                && !l.starts_with("Note:")
                && !l.starts_with("     ")
        })
        .last()
        .expect("expected a mnemonic line in output");
    for word in mnemonic_line.split_whitespace() {
        assert!(
            word.chars().all(|c| c.is_ascii_lowercase()),
            "Mnemonic word '{word}' must be all lowercase ASCII"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Recover restores the same DID
// ---------------------------------------------------------------------------

#[test]
fn test_identity_recover_restores_same_did() {
    let env = common::TempEnv::with_identity();

    // Capture the DID before recovery.
    let original_did = env.run_expect_success(&["identity", "--did"], None);
    let original_did = original_did.trim();

    // Capture the mnemonic.
    let mnemonic_stdout = env.run_expect_success(&["identity", "--mnemonic"], None);
    let mnemonic = mnemonic_stdout
        .lines()
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with("===")
                && !l.starts_with("KEEP")
                && !l.starts_with("Note:")
                && !l.starts_with("     ")
        })
        .last()
        .expect("expected mnemonic line")
        .trim()
        .to_string();

    // Delete identity files and PUF seed to simulate a fresh device.
    let data_dir = env.dir.path();
    let _ = fs::remove_file(data_dir.join("signing_key"));
    let _ = fs::remove_file(data_dir.join("signing_key.pub"));
    let _ = fs::remove_file(data_dir.join("identity.json"));
    let _ = fs::remove_file(data_dir.join("puf_seed"));

    // Recover using the mnemonic.
    let stdin_input = format!("{mnemonic}\n");
    env.run_expect_success(&["identity", "--recover"], Some(&stdin_input));

    // Verify the DID matches.
    let recovered_did = env.run_expect_success(&["identity", "--did"], None);
    assert_eq!(
        original_did,
        recovered_did.trim(),
        "DID after recovery must match the original DID"
    );
}

// ---------------------------------------------------------------------------
// 7. Recover with wrong word count errors
// ---------------------------------------------------------------------------

#[test]
fn test_identity_recover_wrong_word_count_errors() {
    let env = common::TempEnv::with_identity();
    // 11 words — not a valid BIP-39 mnemonic length.
    let bad_phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon\n";
    let output = env.run_expect_failure(&["identity", "--recover"], Some(bad_phrase));
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(
        combined.to_lowercase().contains("recover")
            || combined.to_lowercase().contains("invalid")
            || combined.to_lowercase().contains("mnemonic")
            || combined.to_lowercase().contains("word")
            || combined.to_lowercase().contains("failed"),
        "Expected an error message about invalid mnemonic/word count, got:\nSTDOUT: {}\nSTDERR: {}",
        output.stdout,
        output.stderr,
    );
}

// ---------------------------------------------------------------------------
// 8. Recover with an invalid word errors
// ---------------------------------------------------------------------------

#[test]
fn test_identity_recover_invalid_word_errors() {
    let env = common::TempEnv::with_identity();
    // 12 words where the first is not in the BIP-39 wordlist.
    let bad_phrase =
        "zzzznotaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon\n";
    let output = env.run_expect_failure(&["identity", "--recover"], Some(bad_phrase));
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(
        combined.to_lowercase().contains("recover")
            || combined.to_lowercase().contains("invalid")
            || combined.to_lowercase().contains("mnemonic")
            || combined.to_lowercase().contains("word")
            || combined.to_lowercase().contains("failed"),
        "Expected an error about invalid mnemonic word, got:\nSTDOUT: {}\nSTDERR: {}",
        output.stdout,
        output.stderr,
    );
}

// ---------------------------------------------------------------------------
// 9. JSON output has a "did" field
// ---------------------------------------------------------------------------

#[test]
fn test_identity_json_output_has_did_field() {
    let env = common::TempEnv::with_identity();
    let output = env.run(&["identity", "--did", "--json"], None);
    common::assert_exit_success(&output, "identity --did --json");
    let json = common::assert_json_valid(&output, "identity --did --json");
    assert!(
        json.get("did").is_some(),
        "JSON output must contain a 'did' field, got: {json}"
    );
    let did_value = json["did"].as_str().unwrap_or("");
    assert!(
        did_value.starts_with("did:key:z"),
        "JSON 'did' field must start with 'did:key:z', got: {did_value}"
    );
}

// ---------------------------------------------------------------------------
// 10. Identity before init errors
// ---------------------------------------------------------------------------

#[test]
fn test_identity_not_initialized_errors() {
    // TempEnv::new() does NOT call init.
    let env = common::TempEnv::new();
    let output = env.run_expect_failure(&["identity"], None);
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(
        combined.contains("init")
            || combined.to_lowercase().contains("not initialized")
            || combined.to_lowercase().contains("no such file")
            || combined.to_lowercase().contains("identity"),
        "Expected an initialization error, got:\nSTDOUT: {}\nSTDERR: {}",
        output.stdout,
        output.stderr,
    );
}
