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
        // Re-serialize and compare JSON bytes
        let re_encoded = encode_message_json(&decoded).expect("JSON re-encode failed");
        assert_eq!(encoded, re_encoded, "JSON roundtrip failed for {:?}", msg);
    }
}

#[test]
fn test_protocol_dispatch() {
    use crypto::{decode_for_protocol, encode_for_protocol, WireProtocol};

    let msg = IpcMessage::Heartbeat;

    // Bincode roundtrip via protocol dispatch
    let bc_bytes = encode_for_protocol(&msg, WireProtocol::Bincode).unwrap();
    let bc_decoded = decode_for_protocol(&bc_bytes, WireProtocol::Bincode).unwrap();
    assert!(matches!(bc_decoded, IpcMessage::Heartbeat));

    // JSON roundtrip via protocol dispatch
    let json_bytes = encode_for_protocol(&msg, WireProtocol::Json).unwrap();
    let json_decoded = decode_for_protocol(&json_bytes, WireProtocol::Json).unwrap();
    assert!(matches!(json_decoded, IpcMessage::Heartbeat));

    // Verify formats are different
    assert_ne!(bc_bytes, json_bytes);
}

#[test]
fn test_json_protocol_magic_detection() {
    use crypto::JSON_PROTOCOL_MAGIC;

    // Verify the magic bytes are correct ASCII "WJ"
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
        // Check that they are the same by re-serializing and comparing
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

    // Give server a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Use AsyncIpcClient
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

    // Test start_witnessing
    client
        .start_witnessing(PathBuf::from("new.txt"))
        .await
        .expect("start_witnessing failed");

    // Shutdown server
    shutdown_tx.send(()).await.unwrap();
    server_handle.await.unwrap();
}

#[test]
fn test_encode_all_message_variants() {
    use crate::jitter::SimpleJitterSample;
    use crypto::encode_message;

    // Test that all message variants can be encoded
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

    // Create a valid message, then truncate it
    let msg = IpcMessage::StatusResponse {
        running: true,
        tracked_files: vec!["file1.txt".to_string(), "file2.txt".to_string()],
        uptime_secs: 12345,
    };
    let full_bytes = encode_message(&msg).unwrap();

    // Truncate to less than half
    let truncated = &full_bytes[..full_bytes.len() / 3];
    let result = decode_message(truncated);
    // Should either fail or not decode to the same message
    match result {
        Err(_) => {} // Expected failure
        Ok(decoded) => {
            // If it somehow decoded, it shouldn't match original
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

    // Create a valid message then corrupt it
    let msg = IpcMessage::Heartbeat;
    let mut bytes = encode_message(&msg).unwrap();
    // Corrupt some bytes
    if bytes.len() > 2 {
        bytes[1] = 0xFF;
        bytes[2] = 0xFF;
    }
    // May or may not decode to something valid, but shouldn't panic
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

    // Test handshake handling
    let response = handler.handle(IpcMessage::Handshake {
        version: "1.0".to_string(),
    });
    match response {
        IpcMessage::HandshakeAck { version, .. } => {
            assert_eq!(version, "1.0");
        }
        _ => panic!("Expected HandshakeAck"),
    }

    // Test status handling
    let response = handler.handle(IpcMessage::GetStatus);
    match response {
        IpcMessage::StatusResponse { running, .. } => {
            assert!(running);
        }
        _ => panic!("Expected StatusResponse"),
    }

    // Test heartbeat handling
    let response = handler.handle(IpcMessage::Heartbeat);
    match response {
        IpcMessage::HeartbeatAck { timestamp_ns } => {
            assert_eq!(timestamp_ns, 123456789);
        }
        _ => panic!("Expected HeartbeatAck"),
    }

    // Test other message handling (falls through to Ok)
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
