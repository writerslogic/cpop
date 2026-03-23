// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Integration tests for the `writerslogic-native-messaging-host` binary.
//!
//! Tests the full NMH protocol: 4-byte LE length prefix + JSON body via stdin/stdout.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn nmh_bin() -> &'static str {
    env!("CARGO_BIN_EXE_writerslogic-native-messaging-host")
}

/// Build a framed NMH message: 4-byte LE length prefix + JSON body.
fn frame_json(value: &serde_json::Value) -> Vec<u8> {
    let body = serde_json::to_vec(value).unwrap();
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.extend_from_slice(&(body.len() as u32).to_le_bytes());
    msg.extend_from_slice(&body);
    msg
}

/// Read one framed NMH response from a reader.
fn read_response(reader: &mut impl Read) -> serde_json::Value {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .expect("read response length prefix");
    let len = u32::from_le_bytes(len_buf) as usize;
    assert!(
        len > 0 && len < 1_048_576,
        "response length {len} out of range"
    );
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).expect("read response body");
    serde_json::from_slice(&buf).expect("parse response JSON")
}

#[test]
fn test_nmh_binary_responds_to_ping() {
    let msg = frame_json(&serde_json::json!({"type": "ping"}));

    let mut child = Command::new(nmh_bin())
        .env("CPOP_NO_KEYCHAIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn NMH binary");

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(&msg).expect("write ping message");
        // Close stdin to signal EOF
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait for NMH");
    assert!(
        output.stdout.len() >= 4,
        "response should have at least 4-byte length prefix"
    );

    let len = u32::from_le_bytes(output.stdout[..4].try_into().unwrap()) as usize;
    assert_eq!(
        len,
        output.stdout.len() - 4,
        "length prefix should match remaining bytes"
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout[4..]).expect("response should be valid JSON");
    assert_eq!(body["type"], "pong", "ping should receive pong response");
    assert!(
        body["version"].is_string(),
        "pong should include version string"
    );
}

#[test]
fn test_nmh_binary_exits_cleanly_on_stdin_close() {
    let mut child = Command::new(nmh_bin())
        .env("CPOP_NO_KEYCHAIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn NMH binary");

    // Close stdin immediately
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait for NMH");
    // Should exit without panicking
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "NMH should not panic on stdin close, stderr: {stderr}"
    );
}

#[test]
fn test_nmh_binary_rejects_oversized_message_length() {
    // Claim 2GB payload - binary should reject without allocating
    let mut msg = Vec::new();
    let fake_len: u32 = 2_000_000_000;
    msg.extend_from_slice(&fake_len.to_le_bytes());
    // Don't send actual payload - just the length prefix

    let mut child = Command::new(nmh_bin())
        .env("CPOP_NO_KEYCHAIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn NMH binary");

    {
        let stdin = child.stdin.as_mut().unwrap();
        let _ = stdin.write_all(&msg);
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait for NMH");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "NMH should not panic on oversized message, stderr: {stderr}"
    );
    // Should have an error response or have exited
    assert!(
        stderr.contains("Invalid message length")
            || stderr.contains("Read error")
            || !output.stdout.is_empty(),
        "should report invalid message length or send error response"
    );
}

#[test]
fn test_nmh_binary_get_status_without_session() {
    let msg = frame_json(&serde_json::json!({"type": "get_status"}));

    let mut child = Command::new(nmh_bin())
        .env("CPOP_NO_KEYCHAIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn NMH binary");

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(&msg).expect("write status message");
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait for NMH");
    assert!(output.stdout.len() >= 4, "should receive a response");

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout[4..]).expect("valid JSON response");
    assert_eq!(body["type"], "status", "should receive status response");
    assert_eq!(
        body["active_session"], false,
        "should report no active session"
    );
}

#[test]
fn test_nmh_binary_multiple_pings() {
    let ping = frame_json(&serde_json::json!({"type": "ping"}));

    let mut child = Command::new(nmh_bin())
        .env("CPOP_NO_KEYCHAIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn NMH binary");

    {
        let stdin = child.stdin.as_mut().unwrap();
        // Send 3 pings
        for _ in 0..3 {
            stdin.write_all(&ping).expect("write ping");
        }
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait for NMH");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "multiple pings should not panic"
    );

    // Should have 3 responses
    let mut cursor = std::io::Cursor::new(&output.stdout);
    let mut count = 0;
    while (cursor.position() as usize) < output.stdout.len() {
        let resp = read_response(&mut cursor);
        assert_eq!(resp["type"], "pong", "each response should be pong");
        count += 1;
    }
    assert_eq!(count, 3, "should receive exactly 3 pong responses");
}

#[test]
fn test_nmh_binary_domain_not_allowed_error() {
    let msg = frame_json(&serde_json::json!({
        "type": "start_session",
        "document_url": "https://evil.example.com/doc",
        "document_title": "Phishing Doc"
    }));

    let mut child = Command::new(nmh_bin())
        .env("CPOP_NO_KEYCHAIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn NMH binary");

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(&msg).expect("write start_session message");
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait for NMH");
    assert!(output.stdout.len() >= 4, "should receive an error response");

    let body: serde_json::Value = serde_json::from_slice(&output.stdout[4..]).expect("valid JSON");
    assert_eq!(
        body["type"], "error",
        "disallowed domain should produce error response"
    );
    assert_eq!(
        body["code"], "DOMAIN_NOT_ALLOWED",
        "error code should be DOMAIN_NOT_ALLOWED"
    );
}
