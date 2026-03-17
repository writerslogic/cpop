// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::crypto;
use super::*;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;

struct TestHandler;
impl IpcMessageHandler for TestHandler {
    fn handle(&self, msg: IpcMessage) -> IpcMessage {
        match msg {
            IpcMessage::Handshake { version } => IpcMessage::HandshakeAck {
                version,
                server_version: "1.0.0-test".to_string(),
            },
            IpcMessage::GetStatus => IpcMessage::StatusResponse {
                running: true,
                tracked_files: vec!["test.txt".to_string()],
                uptime_secs: 42,
            },
            IpcMessage::Heartbeat => IpcMessage::HeartbeatAck {
                timestamp_ns: 123456789,
            },
            _ => IpcMessage::Ok {
                message: Some("Handled".to_string()),
            },
        }
    }
}

#[test]
fn test_json_message_serialization_roundtrip() {
    use crypto::{decode_message_json, encode_message_json};

    let messages = vec![
        IpcMessage::Handshake {
            version: "1.0".to_string(),
        },
        IpcMessage::StartWitnessing {
            file_path: PathBuf::from("/tmp/test"),
        },
        IpcMessage::StopWitnessing { file_path: None },
        IpcMessage::GetStatus,
        IpcMessage::Heartbeat,
        IpcMessage::CheckpointCreated {
            id: 1,
            hash: [0u8; 32],
        },
        IpcMessage::SystemAlert {
            level: "info".to_string(),
            message: "hello".to_string(),
        },
        IpcMessage::Ok {
            message: Some("all good".to_string()),
        },
        IpcMessage::Error {
            code: IpcErrorCode::FileNotFound,
            message: "not found".to_string(),
        },
        IpcMessage::HandshakeAck {
            version: "1.0".to_string(),
            server_version: "1.1".to_string(),
        },
        IpcMessage::HeartbeatAck { timestamp_ns: 999 },
        IpcMessage::StatusResponse {
            running: true,
            tracked_files: vec!["a.txt".to_string(), "b.txt".to_string()],
            uptime_secs: 3600,
        },
    ];

    for msg in messages {
        let encoded = encode_message_json(&msg).expect("JSON encode failed");
        let decoded = decode_message_json(&encoded).expect("JSON decode failed");
        let re_encoded = encode_message_json(&decoded).expect("JSON re-encode failed");
        assert_eq!(encoded, re_encoded, "JSON roundtrip failed for {:?}", msg);
    }
}

#[test]
fn test_protocol_dispatch() {
    use crypto::{decode_for_protocol, encode_for_protocol, WireProtocol};

    let msg = IpcMessage::Heartbeat;

    let bc_bytes = encode_for_protocol(&msg, WireProtocol::Bincode).unwrap();
    let bc_decoded = decode_for_protocol(&bc_bytes, WireProtocol::Bincode).unwrap();
    assert!(matches!(bc_decoded, IpcMessage::Heartbeat));

    let json_bytes = encode_for_protocol(&msg, WireProtocol::Json).unwrap();
    let json_decoded = decode_for_protocol(&json_bytes, WireProtocol::Json).unwrap();
    assert!(matches!(json_decoded, IpcMessage::Heartbeat));

    assert_ne!(bc_bytes, json_bytes);
}

#[test]
fn test_json_protocol_magic_detection() {
    use crypto::JSON_PROTOCOL_MAGIC;

    assert_eq!(JSON_PROTOCOL_MAGIC, [0x57, 0x4A]);
    assert_eq!(&JSON_PROTOCOL_MAGIC, b"WJ");
}

#[test]
fn test_message_serialization_roundtrip() {
    use crate::jitter::SimpleJitterSample;
    use crypto::{decode_message, encode_message};

    let messages = vec![
        IpcMessage::Handshake {
            version: "1.0".to_string(),
        },
        IpcMessage::StartWitnessing {
            file_path: PathBuf::from("/tmp/test"),
        },
        IpcMessage::StopWitnessing { file_path: None },
        IpcMessage::GetStatus,
        IpcMessage::Heartbeat,
        IpcMessage::Pulse(SimpleJitterSample {
            timestamp_ns: 1000,
            duration_since_last_ns: 10,
            zone: 1,
        }),
        IpcMessage::CheckpointCreated {
            id: 1,
            hash: [0u8; 32],
        },
        IpcMessage::SystemAlert {
            level: "info".to_string(),
            message: "hello".to_string(),
        },
        IpcMessage::Ok {
            message: Some("all good".to_string()),
        },
        IpcMessage::Error {
            code: IpcErrorCode::FileNotFound,
            message: "not found".to_string(),
        },
        IpcMessage::HandshakeAck {
            version: "1.0".to_string(),
            server_version: "1.1".to_string(),
        },
        IpcMessage::HeartbeatAck { timestamp_ns: 999 },
        IpcMessage::StatusResponse {
            running: true,
            tracked_files: vec!["a.txt".to_string(), "b.txt".to_string()],
            uptime_secs: 3600,
        },
    ];

    for msg in messages {
        let encoded = encode_message(&msg).expect("encode failed");
        let decoded = decode_message(&encoded).expect("decode failed");
        let re_encoded = encode_message(&decoded).expect("re-encode failed");
        assert_eq!(encoded, re_encoded, "Roundtrip failed for {:?}", msg);
    }
}

#[tokio::test]
#[cfg(not(target_os = "windows"))]
async fn test_ipc_server_client_interaction() {
    use std::time::Duration;

    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("test.sock");

    let server = IpcServer::bind(socket_path.clone()).expect("bind failed");
    let handler = Arc::new(TestHandler);

    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);

    let server_path = socket_path.clone();
    let server_handle = tokio::spawn(async move {
        server
            .run_with_shutdown(handler, shutdown_rx)
            .await
            .expect("server run failed");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = AsyncIpcClient::connect(&server_path)
        .await
        .expect("client connect failed");

    let version = client.handshake("0.1.0").await.expect("handshake failed");
    assert_eq!(version, "1.0.0-test");

    let (running, files, uptime) = client.get_status().await.expect("get_status failed");
    assert!(running);
    assert_eq!(files, vec!["test.txt".to_string()]);
    assert_eq!(uptime, 42);

    let ts = client.heartbeat().await.expect("heartbeat failed");
    assert_eq!(ts, 123456789);

    // Test start_witnessing (must be absolute — server rejects relative paths)
    client
        .start_witnessing(PathBuf::from("/tmp/new.txt"))
        .await
        .expect("start_witnessing failed");

    shutdown_tx.send(()).await.unwrap();
    server_handle.await.unwrap();
}

#[test]
fn test_encode_all_message_variants() {
    use crate::jitter::SimpleJitterSample;
    use crypto::encode_message;

    let variants: Vec<IpcMessage> = vec![
        IpcMessage::Handshake {
            version: "test".to_string(),
        },
        IpcMessage::StartWitnessing {
            file_path: PathBuf::from("/test"),
        },
        IpcMessage::StopWitnessing { file_path: None },
        IpcMessage::StopWitnessing {
            file_path: Some(PathBuf::from("/test")),
        },
        IpcMessage::GetStatus,
        IpcMessage::Pulse(SimpleJitterSample {
            timestamp_ns: 0,
            duration_since_last_ns: 0,
            zone: 0,
        }),
        IpcMessage::CheckpointCreated {
            id: 0,
            hash: [0u8; 32],
        },
        IpcMessage::SystemAlert {
            level: "warn".to_string(),
            message: "test".to_string(),
        },
        IpcMessage::Heartbeat,
        IpcMessage::Ok { message: None },
        IpcMessage::Ok {
            message: Some("test".to_string()),
        },
        IpcMessage::Error {
            code: IpcErrorCode::Unknown,
            message: "error".to_string(),
        },
        IpcMessage::HandshakeAck {
            version: "1".to_string(),
            server_version: "2".to_string(),
        },
        IpcMessage::HeartbeatAck { timestamp_ns: 0 },
        IpcMessage::StatusResponse {
            running: false,
            tracked_files: vec![],
            uptime_secs: 0,
        },
    ];

    for msg in variants {
        let result = encode_message(&msg);
        assert!(result.is_ok(), "Failed to encode {:?}", msg);
        let bytes = result.unwrap();
        assert!(!bytes.is_empty(), "Empty encoding for {:?}", msg);
    }
}

#[test]
fn test_decode_truncated_message() {
    use crypto::{decode_message, encode_message};

    let msg = IpcMessage::StatusResponse {
        running: true,
        tracked_files: vec!["file1.txt".to_string(), "file2.txt".to_string()],
        uptime_secs: 12345,
    };
    let full_bytes = encode_message(&msg).unwrap();

    let truncated = &full_bytes[..full_bytes.len() / 3];
    let result = decode_message(truncated);
    match result {
        Err(_) => {}
        Ok(decoded) => {
            let re_encoded = encode_message(&decoded).unwrap();
            assert_ne!(
                re_encoded, full_bytes,
                "Truncated message should not decode to original"
            );
        }
    }
}

#[test]
fn test_decode_empty_message() {
    use crypto::decode_message;
    let result = decode_message(&[]);
    assert!(result.is_err(), "Should fail on empty message");
}

#[test]
fn test_decode_corrupted_message() {
    use crypto::{decode_message, encode_message};

    let msg = IpcMessage::Heartbeat;
    let mut bytes = encode_message(&msg).unwrap();
    if bytes.len() > 2 {
        bytes[1] = 0xFF;
        bytes[2] = 0xFF;
    }
    let _ = decode_message(&bytes);
}

#[test]
fn test_all_error_codes() {
    use crypto::{decode_message, encode_message};

    let codes = vec![
        IpcErrorCode::Unknown,
        IpcErrorCode::InvalidMessage,
        IpcErrorCode::FileNotFound,
        IpcErrorCode::AlreadyTracking,
        IpcErrorCode::NotTracking,
        IpcErrorCode::PermissionDenied,
        IpcErrorCode::VersionMismatch,
        IpcErrorCode::InternalError,
    ];

    for code in codes {
        let msg = IpcMessage::Error {
            code,
            message: format!("Test error: {:?}", code),
        };
        let encoded = encode_message(&msg).expect("encode");
        let decoded = decode_message(&encoded).expect("decode");
        match decoded {
            IpcMessage::Error {
                code: decoded_code, ..
            } => {
                assert_eq!(decoded_code, code);
            }
            _ => panic!("Wrong message type decoded"),
        }
    }
}

#[test]
fn test_message_handler_trait() {
    let handler = TestHandler;

    let response = handler.handle(IpcMessage::Handshake {
        version: "1.0".to_string(),
    });
    match response {
        IpcMessage::HandshakeAck { version, .. } => {
            assert_eq!(version, "1.0");
        }
        _ => panic!("Expected HandshakeAck"),
    }

    let response = handler.handle(IpcMessage::GetStatus);
    match response {
        IpcMessage::StatusResponse { running, .. } => {
            assert!(running);
        }
        _ => panic!("Expected StatusResponse"),
    }

    let response = handler.handle(IpcMessage::Heartbeat);
    match response {
        IpcMessage::HeartbeatAck { timestamp_ns } => {
            assert_eq!(timestamp_ns, 123456789);
        }
        _ => panic!("Expected HeartbeatAck"),
    }

    let response = handler.handle(IpcMessage::StopWitnessing { file_path: None });
    match response {
        IpcMessage::Ok { message } => {
            assert_eq!(message, Some("Handled".to_string()));
        }
        _ => panic!("Expected Ok"),
    }
}

#[test]
fn test_pulse_message_data_integrity() {
    use crate::jitter::SimpleJitterSample;
    use crypto::{decode_message, encode_message};

    let sample = SimpleJitterSample {
        timestamp_ns: 1234567890123456789,
        duration_since_last_ns: 100000,
        zone: 42,
    };
    let msg = IpcMessage::Pulse(sample.clone());
    let encoded = encode_message(&msg).expect("encode");
    let decoded = decode_message(&encoded).expect("decode");

    match decoded {
        IpcMessage::Pulse(decoded_sample) => {
            assert_eq!(decoded_sample.timestamp_ns, sample.timestamp_ns);
            assert_eq!(
                decoded_sample.duration_since_last_ns,
                sample.duration_since_last_ns
            );
            assert_eq!(decoded_sample.zone, sample.zone);
        }
        _ => panic!("Expected Pulse"),
    }
}

#[test]
fn test_checkpoint_created_hash_integrity() {
    use crypto::{decode_message, encode_message};

    let hash: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let msg = IpcMessage::CheckpointCreated { id: 999, hash };
    let encoded = encode_message(&msg).expect("encode");
    let decoded = decode_message(&encoded).expect("decode");

    match decoded {
        IpcMessage::CheckpointCreated {
            id: decoded_id,
            hash: decoded_hash,
        } => {
            assert_eq!(decoded_id, 999);
            assert_eq!(decoded_hash, hash);
        }
        _ => panic!("Expected CheckpointCreated"),
    }
}

#[test]
fn test_status_response_with_many_files() {
    use crypto::{decode_message, encode_message};

    let files: Vec<String> = (0..100).map(|i| format!("file_{}.txt", i)).collect();
    let msg = IpcMessage::StatusResponse {
        running: true,
        tracked_files: files.clone(),
        uptime_secs: 86400,
    };
    let encoded = encode_message(&msg).expect("encode");
    let decoded = decode_message(&encoded).expect("decode");

    match decoded {
        IpcMessage::StatusResponse {
            tracked_files: decoded_files,
            ..
        } => {
            assert_eq!(decoded_files.len(), 100);
            assert_eq!(decoded_files, files);
        }
        _ => panic!("Expected StatusResponse"),
    }
}

// ── Path traversal validation tests ────────────────────────────────────

#[test]
fn test_validate_paths_rejects_traversal() {
    let traversal_path = if cfg!(windows) {
        PathBuf::from(r"C:\Users\user\..\..\..\Windows\System32\config")
    } else {
        PathBuf::from("/home/user/../../../etc/passwd")
    };
    let msg = IpcMessage::StartWitnessing {
        file_path: traversal_path,
    };
    let result = msg.validate_paths();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("traversal"));
}

#[test]
fn test_validate_paths_rejects_relative_traversal() {
    let msg = IpcMessage::VerifyFile {
        path: PathBuf::from("documents/../../secrets/key.pem"),
    };
    assert!(msg.validate_paths().is_err());
}

#[test]
fn test_validate_paths_accepts_normal_paths() {
    let normal_path = if cfg!(windows) {
        PathBuf::from(r"C:\Users\user\Documents\essay.txt")
    } else {
        PathBuf::from("/home/user/documents/essay.txt")
    };
    let msg = IpcMessage::StartWitnessing {
        file_path: normal_path,
    };
    assert!(msg.validate_paths().is_ok());
}

#[test]
fn test_validate_paths_checks_both_export_file_paths() {
    let (good_path, bad_output, bad_path, good_output) = if cfg!(windows) {
        (
            PathBuf::from(r"C:\Users\user\doc.txt"),
            PathBuf::from(r"C:\Users\user\..\..\Windows\evil"),
            PathBuf::from(r"C:\tmp\..\Windows\shadow"),
            PathBuf::from(r"C:\Users\user\out.pop"),
        )
    } else {
        (
            PathBuf::from("/home/user/doc.txt"),
            PathBuf::from("/home/user/../../etc/cron.d/evil"),
            PathBuf::from("/tmp/../etc/shadow"),
            PathBuf::from("/home/user/out.pop"),
        )
    };
    let msg = IpcMessage::ExportFile {
        path: good_path,
        tier: "gold".to_string(),
        output: bad_output,
    };
    assert!(msg.validate_paths().is_err());

    let msg = IpcMessage::ExportFile {
        path: bad_path,
        tier: "gold".to_string(),
        output: good_output,
    };
    assert!(msg.validate_paths().is_err());
}

#[test]
fn test_validate_paths_allows_messages_without_paths() {
    assert!(IpcMessage::Heartbeat.validate_paths().is_ok());
    assert!(IpcMessage::GetStatus.validate_paths().is_ok());
    assert!(IpcMessage::GetAttestationNonce.validate_paths().is_ok());
    assert!((IpcMessage::StopWitnessing { file_path: None })
        .validate_paths()
        .is_ok());
}

#[test]
fn test_validate_paths_rejects_relative_paths() {
    let msg = IpcMessage::StartWitnessing {
        file_path: PathBuf::from("relative/file.txt"),
    };
    let err = msg.validate_paths().unwrap_err();
    assert!(err.contains("Relative path rejected"), "got: {}", err);

    let msg = IpcMessage::ExportFile {
        path: PathBuf::from("/home/user/doc.txt"),
        tier: "gold".to_string(),
        output: PathBuf::from("output.pop"),
    };
    assert!(msg.validate_paths().is_err());
}

#[cfg(unix)]
#[test]
fn test_validate_paths_rejects_system_directories() {
    let msg = IpcMessage::StartWitnessing {
        file_path: PathBuf::from("/etc/passwd"),
    };
    assert!(msg.validate_paths().is_err());

    let msg = IpcMessage::VerifyFile {
        path: PathBuf::from("/proc/self/environ"),
    };
    assert!(msg.validate_paths().is_err());

    let msg = IpcMessage::GetFileForensics {
        path: PathBuf::from("/System/Library/something"),
    };
    assert!(msg.validate_paths().is_err());
}

#[test]
fn test_secure_channel_nonce_overflow_rejected() {
    use super::secure_channel::SecureChannel;

    let (tx, _rx) = SecureChannel::<u64>::new_pair();
    tx.nonce_counter
        .store(u64::MAX - 1, std::sync::atomic::Ordering::SeqCst);

    assert!(tx.send(42u64).is_err());
}

#[test]
fn test_secure_channel_normal_send_recv() {
    use super::secure_channel::SecureChannel;

    let (tx, rx) = SecureChannel::<String>::new_pair();
    tx.send("hello".to_string()).unwrap();
    let received = rx.recv().unwrap();
    assert_eq!(received, "hello");
}
