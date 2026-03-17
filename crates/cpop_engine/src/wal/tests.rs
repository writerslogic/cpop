// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;

use ed25519_dalek::SigningKey;
use std::fs;
use std::path::PathBuf;

fn temp_wal_path() -> PathBuf {
    let name = format!("writerslogic-wal-{}.log", uuid::Uuid::new_v4());
    std::env::temp_dir().join(name)
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0u8; 32])
}

#[test]
fn test_wal_append_and_verify() {
    let path = temp_wal_path();
    let session_id = [7u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    wal.append(EntryType::Heartbeat, vec![1, 2, 3])
        .expect("append");
    wal.append(EntryType::DocumentHash, vec![4, 5, 6])
        .expect("append");

    let verification = wal.verify().expect("verify");
    assert!(verification.valid);
    assert_eq!(verification.entries, 2);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_truncate() {
    let path = temp_wal_path();
    let session_id = [3u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    wal.append(EntryType::Heartbeat, vec![1]).expect("append");
    wal.append(EntryType::Heartbeat, vec![2]).expect("append");
    wal.append(EntryType::Heartbeat, vec![3]).expect("append");

    wal.truncate(1).expect("truncate");
    let verification = wal.verify().expect("verify");
    assert!(verification.valid);
    assert_eq!(verification.entries, 2);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_reopen_after_close() {
    let path = temp_wal_path();
    let session_id = [8u8; 32];
    let signing_key = test_signing_key();

    {
        let wal = Wal::open(&path, session_id, signing_key.clone()).expect("open wal");
        wal.append(EntryType::Heartbeat, vec![1, 2, 3])
            .expect("append");
        wal.append(EntryType::DocumentHash, vec![4, 5, 6])
            .expect("append");
        wal.close().expect("close");
    }

    {
        let wal = Wal::open(&path, session_id, signing_key).expect("reopen wal");
        let verification = wal.verify().expect("verify");
        assert!(verification.valid);
        assert_eq!(verification.entries, 2);
        wal.close().expect("close");
    }

    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_append_to_closed() {
    let path = temp_wal_path();
    let session_id = [9u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    wal.close().expect("close");

    let result = wal.append(EntryType::Heartbeat, vec![1, 2, 3]);
    assert!(result.is_err());
    match result {
        Err(WalError::Closed) => {} // Expected
        Err(e) => panic!("Expected WalError::Closed, got {:?}", e),
        Ok(_) => panic!("Expected error on append to closed WAL"),
    }

    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_all_entry_types() {
    let path = temp_wal_path();
    let session_id = [10u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

    wal.append(EntryType::Heartbeat, vec![1])
        .expect("append heartbeat");
    wal.append(EntryType::DocumentHash, vec![2])
        .expect("append document hash");
    wal.append(EntryType::KeystrokeBatch, vec![3])
        .expect("append keystroke batch");
    wal.append(EntryType::JitterSample, vec![4])
        .expect("append jitter sample");
    wal.append(EntryType::SessionStart, vec![5])
        .expect("append session start");
    wal.append(EntryType::SessionEnd, vec![6])
        .expect("append session end");
    wal.append(EntryType::Checkpoint, vec![7])
        .expect("append checkpoint");

    let verification = wal.verify().expect("verify");
    assert!(verification.valid);
    assert_eq!(verification.entries, 7);
    assert_eq!(wal.entry_count(), 7);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_large_payload() {
    let path = temp_wal_path();
    let session_id = [11u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

    let large_payload = vec![0xABu8; 1024 * 1024];
    wal.append(EntryType::KeystrokeBatch, large_payload.clone())
        .expect("append large payload");

    let verification = wal.verify().expect("verify");
    assert!(verification.valid);
    assert_eq!(verification.entries, 1);

    let size = wal.size();
    assert!(size > 1024 * 1024, "Size should be at least 1MB");

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_exists() {
    let path = temp_wal_path();
    let session_id = [12u8; 32];
    let signing_key = test_signing_key();

    assert!(!Wal::exists(&path));

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    wal.append(EntryType::Heartbeat, vec![1]).expect("append");
    wal.close().expect("close");

    assert!(Wal::exists(&path));

    let _ = fs::remove_file(&path);

    assert!(!Wal::exists(&path));
}

#[test]
fn test_wal_size_and_entry_count() {
    let path = temp_wal_path();
    let session_id = [13u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

    assert_eq!(wal.entry_count(), 0);

    wal.append(EntryType::Heartbeat, vec![1, 2, 3])
        .expect("append 1");
    assert_eq!(wal.entry_count(), 1);

    wal.append(EntryType::Heartbeat, vec![4, 5, 6])
        .expect("append 2");
    assert_eq!(wal.entry_count(), 2);

    let size = wal.size();
    assert!(size > 0, "Size should be positive");

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_last_sequence() {
    let path = temp_wal_path();
    let session_id = [14u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

    assert_eq!(wal.last_sequence(), 0);

    wal.append(EntryType::Heartbeat, vec![1]).expect("append 1");
    assert_eq!(wal.last_sequence(), 0);

    wal.append(EntryType::Heartbeat, vec![2]).expect("append 2");
    assert_eq!(wal.last_sequence(), 1);

    wal.append(EntryType::Heartbeat, vec![3]).expect("append 3");
    assert_eq!(wal.last_sequence(), 2);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_truncate_race_condition() {
    use std::sync::Arc;
    use std::thread;

    let path = temp_wal_path();
    let session_id = [17u8; 32];
    let signing_key = test_signing_key();

    let wal = Arc::new(Wal::open(&path, session_id, signing_key).expect("open wal"));

    wal.append(EntryType::Heartbeat, vec![1]).unwrap();
    wal.append(EntryType::Heartbeat, vec![2]).unwrap();

    let wal_clone = Arc::clone(&wal);
    let handle = thread::spawn(move || {
        for i in 0..50 {
            let _ = wal_clone.append(EntryType::Heartbeat, vec![i as u8 + 10]);
        }
    });

    for _ in 0..5 {
        let _ = wal.truncate(1);
    }

    handle.join().unwrap();

    let verification = wal.verify().expect("verify");
    assert!(
        verification.valid,
        "WAL should still be valid even after race"
    );

    // If entries are missing, it's a bug, but hard to assert exact count due to race timing.
    // But we can check if it's at least consistent with what truncate() thinks it has.
    assert_eq!(wal.entry_count(), verification.entries);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_path() {
    let path = temp_wal_path();
    let session_id = [15u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    assert_eq!(wal.path(), path);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_truncate_empty() {
    let path = temp_wal_path();
    let session_id = [16u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

    wal.truncate(0).expect("truncate empty");

    let verification = wal.verify().expect("verify");
    assert!(verification.valid);
    assert_eq!(verification.entries, 0);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}
