// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#[cfg(test)]
#[allow(clippy::manual_range_contains)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use crate::jitter::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    fn temp_document_path() -> PathBuf {
        let name = format!("writerslogic-jitter-test-{}.txt", uuid::Uuid::new_v4());
        std::env::temp_dir().join(name)
    }

    fn test_params() -> Parameters {
        Parameters {
            min_jitter_micros: 500,
            max_jitter_micros: 3000,
            sample_interval: 1,
            inject_enabled: true,
        }
    }

    #[test]
    fn test_session_chain_and_roundtrip() {
        let path = temp_document_path();
        fs::write(&path, b"hello jitter").expect("write temp doc");

        let params = Parameters {
            min_jitter_micros: 500,
            max_jitter_micros: 3000,
            sample_interval: 1,
            inject_enabled: true,
        };

        let mut session = Session::new(&path, params).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }
        session.end();
        session.verify_chain().expect("verify chain");

        let evidence = session.export();
        evidence.verify().expect("evidence verify");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_sample_binary_roundtrip() {
        let path = temp_document_path();
        fs::write(&path, b"hello jitter").expect("write temp doc");

        let params = Parameters {
            min_jitter_micros: 500,
            max_jitter_micros: 3000,
            sample_interval: 1,
            inject_enabled: true,
        };
        let mut session = Session::new(&path, params).expect("session");
        session.record_keystroke().expect("keystroke");
        let sample = session.samples.first().expect("sample");

        let encoded = encode_sample_binary(sample);
        let decoded = decode_sample_binary(&encoded).expect("decode");
        assert_eq!(decoded.hash, sample.hash);
        assert_eq!(decoded.previous_hash, sample.previous_hash);
        assert_eq!(decoded.document_hash, sample.document_hash);
        assert_eq!(decoded.jitter_micros, sample.jitter_micros);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_verify_chain_with_seed() {
        let path = temp_document_path();
        fs::write(&path, b"hello jitter").expect("write temp doc");

        let params = Parameters {
            min_jitter_micros: 500,
            max_jitter_micros: 3000,
            sample_interval: 1,
            inject_enabled: true,
        };

        let mut session = Session::new(&path, params).expect("session");
        for _ in 0..2 {
            session.record_keystroke().expect("keystroke");
        }

        verify_chain(&session.samples, &session.seed, session.params).expect("verify chain");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_reject_zero_sample_interval() {
        let path = temp_document_path();
        fs::write(&path, b"hello jitter").expect("write temp doc");

        let params = Parameters {
            min_jitter_micros: 500,
            max_jitter_micros: 3000,
            sample_interval: 0,
            inject_enabled: true,
        };

        let err = Session::new(&path, params).unwrap_err();
        assert!(err.to_string().contains("sample_interval"));

        let _ = fs::remove_file(&path);
    }

    // Additional tests for jitter.rs

    #[test]
    fn test_session_new_with_id() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let session = Session::new_with_id(&path, test_params(), "custom-id-123").expect("session");
        assert_eq!(session.id, "custom-id-123");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_session_invalid_path() {
        let err = Session::new("/nonexistent/path.txt", test_params()).unwrap_err();
        assert!(err.to_string().contains("invalid document path"));
    }

    #[test]
    fn test_keystroke_count_and_sample_count() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut params = test_params();
        params.sample_interval = 5;

        let mut session = Session::new(&path, params).expect("session");

        for _ in 0..12 {
            session.record_keystroke().expect("keystroke");
        }

        assert_eq!(session.keystroke_count(), 12);
        assert_eq!(session.sample_count(), 2); // 12 / 5 = 2 samples

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_session_duration() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        std::thread::sleep(Duration::from_millis(10));
        session.end();

        assert!(session.duration() >= Duration::from_millis(10));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_session_save_and_load() {
        let dir = TempDir::new().expect("temp dir");
        let doc_path = dir.path().join("doc.txt");
        let session_path = dir.path().join("session.json");

        fs::write(&doc_path, b"test content").expect("write doc");

        let mut session = Session::new(&doc_path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }
        session.save(&session_path).expect("save");

        let loaded = Session::load(&session_path).expect("load");
        assert_eq!(loaded.id, session.id);
        assert_eq!(loaded.samples.len(), session.samples.len());
        assert_eq!(loaded.keystroke_count(), session.keystroke_count());
    }

    #[test]
    fn test_evidence_verify_hash_mismatch() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        session.record_keystroke().expect("keystroke");
        session.record_keystroke().expect("keystroke");

        let mut evidence = session.export();
        // Tamper with sample hash
        evidence.samples[0].hash[0] ^= 0xFF;

        let err = evidence.verify().unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_evidence_verify_broken_chain() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        session.record_keystroke().expect("keystroke");
        session.record_keystroke().expect("keystroke");

        let mut evidence = session.export();
        // Tamper with previous_hash
        evidence.samples[1].previous_hash[0] ^= 0xFF;
        // Recompute hash to pass hash check (but chain link is broken)
        evidence.samples[1].hash = evidence.samples[1].compute_hash();

        let err = evidence.verify().unwrap_err();
        assert!(
            err.to_string().contains("broken chain link"),
            "Expected 'broken chain link', got: {}",
            err
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_evidence_is_plausible_human_typing() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        // Simulate realistic typing at ~200 wpm (1000 chars/min = ~17 chars/sec)
        // So ~60ms per keystroke
        for _ in 0..10 {
            session.record_keystroke().expect("keystroke");
            std::thread::sleep(Duration::from_millis(60));
        }
        session.end();

        let evidence = session.export();
        // With normal timing and limited keystrokes, should be plausible
        // Rate should be ~1000 keystrokes per minute or less
        let rate = evidence.typing_rate();
        assert!(rate >= 10.0, "typing rate {} is too low", rate);
        assert!(rate <= 1000.0, "typing rate {} is too high", rate);
        assert!(
            evidence.is_plausible_human_typing(),
            "typing should be plausible, rate={}",
            rate
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_encode_decode_chain() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..5 {
            session.record_keystroke().expect("keystroke");
        }

        let encoded = encode_chain(&session.samples, session.params).expect("encode");
        let (decoded_samples, decoded_params) = decode_chain(&encoded).expect("decode");

        assert_eq!(decoded_samples.len(), session.samples.len());
        assert_eq!(
            decoded_params.min_jitter_micros,
            session.params.min_jitter_micros
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_encode_decode_chain_binary() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }

        let encoded = encode_chain_binary(&session.samples, session.params).expect("encode");
        let (decoded_samples, decoded_params) = decode_chain_binary(&encoded).expect("decode");

        assert!(compare_chains(&session.samples, &decoded_samples));
        assert_eq!(
            decoded_params.sample_interval,
            session.params.sample_interval
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_decode_sample_binary_invalid_length() {
        let short_data = vec![0u8; 50];
        let err = decode_sample_binary(&short_data).unwrap_err();
        assert!(err.to_string().contains("invalid sample data length"));
    }

    #[test]
    fn test_decode_chain_binary_invalid_version() {
        let mut data = vec![0u8; 20];
        data[0] = 99; // Invalid version
        let err = decode_chain_binary(&data).unwrap_err();
        assert!(err.to_string().contains("unsupported chain version"));
    }

    #[test]
    fn test_compare_samples() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        session.record_keystroke().expect("keystroke");

        let sample = &session.samples[0];
        assert!(compare_samples(sample, sample));

        let mut different = sample.clone();
        different.jitter_micros += 1;
        assert!(!compare_samples(sample, &different));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_find_chain_divergence() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..5 {
            session.record_keystroke().expect("keystroke");
        }

        let samples1 = session.samples.clone();
        let mut samples2 = session.samples.clone();
        samples2[3].jitter_micros += 1;

        assert_eq!(find_chain_divergence(&samples1, &samples2), 3);
        assert_eq!(find_chain_divergence(&samples1, &samples1), -1);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_extract_chain_hashes() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }

        let hashes = extract_chain_hashes(&session.samples);
        assert_eq!(hashes.len(), 3);
        for (i, hash) in hashes.iter().enumerate() {
            assert_eq!(*hash, session.samples[i].hash);
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_hash_chain_root() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }

        let root = hash_chain_root(&session.samples);
        assert_eq!(root, session.samples.last().unwrap().hash);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_hash_chain_root_empty() {
        assert_eq!(hash_chain_root(&[]), [0u8; 32]);
    }

    #[test]
    fn test_verify_chain_empty() {
        let err = verify_chain(&[], &[1u8; 32], test_params()).unwrap_err();
        assert!(err.to_string().contains("empty sample chain"));
    }

    #[test]
    fn test_verify_chain_empty_seed() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        session.record_keystroke().expect("keystroke");

        let err = verify_chain(&session.samples, &[], session.params).unwrap_err();
        assert!(err.to_string().contains("seed is nil or empty"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_verify_chain_detailed() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }

        let result = verify_chain_detailed(&session.samples, &session.seed, session.params);
        assert!(result.valid);
        assert_eq!(result.samples_verified, 3);
        assert!(result.errors.is_empty());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_verify_chain_continuity() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }
        let existing = session.samples.clone();

        for _ in 0..2 {
            session.record_keystroke().expect("keystroke");
        }
        let new_samples = session.samples[3..].to_vec();

        verify_chain_continuity(&existing, &new_samples, &session.seed, session.params)
            .expect("verify continuity");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_validate_sample_format() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        session.record_keystroke().expect("keystroke");

        validate_sample_format(&session.samples[0]).expect("valid format");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_validate_sample_format_zero_timestamp() {
        let sample = Sample {
            timestamp: DateTime::<Utc>::from(SystemTime::UNIX_EPOCH),
            keystroke_count: 1,
            document_hash: [0u8; 32],
            jitter_micros: 1000,
            hash: [1u8; 32],
            previous_hash: [0u8; 32],
        };

        let err = validate_sample_format(&sample).unwrap_err();
        assert!(err.to_string().contains("timestamp is zero or pre-epoch"));
    }

    #[test]
    fn test_validate_sample_format_zero_hash() {
        let sample = Sample {
            timestamp: Utc::now(),
            keystroke_count: 1,
            document_hash: [0u8; 32],
            jitter_micros: 1000,
            hash: [0u8; 32],
            previous_hash: [0u8; 32],
        };

        let err = validate_sample_format(&sample).unwrap_err();
        assert!(err.to_string().contains("sample hash is zero"));
    }

    // Zone and typing profile tests

    #[test]
    fn test_char_to_zone() {
        assert_eq!(char_to_zone('q'), 0);
        assert_eq!(char_to_zone('w'), 1);
        assert_eq!(char_to_zone('e'), 2);
        assert_eq!(char_to_zone('r'), 3);
        assert_eq!(char_to_zone('y'), 4);
        assert_eq!(char_to_zone('i'), 5);
        assert_eq!(char_to_zone('o'), 6);
        assert_eq!(char_to_zone('p'), 7);
        assert_eq!(char_to_zone('1'), -1); // Unknown
    }

    #[test]
    fn test_encode_decode_zone_transition() {
        for from in 0..8 {
            for to in 0..8 {
                let encoded = encode_zone_transition(from, to);
                let (decoded_from, decoded_to) = decode_zone_transition(encoded);
                assert_eq!(decoded_from, from);
                assert_eq!(decoded_to, to);
            }
        }
    }

    #[test]
    fn test_encode_zone_transition_invalid() {
        assert_eq!(encode_zone_transition(-1, 0), 0xFF);
        assert_eq!(encode_zone_transition(0, 8), 0xFF);
    }

    #[test]
    fn test_is_valid_zone_transition() {
        assert!(is_valid_zone_transition(encode_zone_transition(0, 0)));
        assert!(is_valid_zone_transition(encode_zone_transition(3, 5)));
        assert!(!is_valid_zone_transition(0xFF));
    }

    #[test]
    fn test_zone_transition_types() {
        let same_finger = ZoneTransition { from: 2, to: 2 };
        assert!(same_finger.is_same_finger());
        assert!(same_finger.is_same_hand());
        assert!(!same_finger.is_alternating());

        let same_hand = ZoneTransition { from: 0, to: 2 };
        assert!(!same_hand.is_same_finger());
        assert!(same_hand.is_same_hand());
        assert!(!same_hand.is_alternating());

        let alternating = ZoneTransition { from: 1, to: 5 };
        assert!(!alternating.is_same_finger());
        assert!(!alternating.is_same_hand());
        assert!(alternating.is_alternating());
    }

    #[test]
    fn test_text_to_zone_sequence() {
        let text = "hello";
        let transitions = text_to_zone_sequence(text);
        // "hello" = h(4), e(2), l(6), l(6), o(6) → 4 transitions
        assert_eq!(transitions.len(), 4);
    }

    #[test]
    fn test_interval_to_bucket() {
        assert_eq!(interval_to_bucket(Duration::from_millis(0)), 0);
        assert_eq!(interval_to_bucket(Duration::from_millis(25)), 0);
        assert_eq!(interval_to_bucket(Duration::from_millis(50)), 1);
        assert_eq!(interval_to_bucket(Duration::from_millis(100)), 2);
        assert_eq!(interval_to_bucket(Duration::from_secs(1)), 9); // Max bucket
    }

    #[test]
    fn test_jitter_engine() {
        let secret = [42u8; 32];
        let mut engine = JitterEngine::new(secret);

        let doc_hash = [1u8; 32];
        let (jitter1, sample1) = engine.on_keystroke(0x0C, doc_hash); // 'q'

        assert!(jitter1 >= MIN_JITTER && jitter1 <= MAX_JITTER);
        assert!(sample1.is_some());

        let (jitter2, sample2) = engine.on_keystroke(0x0D, doc_hash); // 'w'
        assert!(jitter2 >= MIN_JITTER && jitter2 <= MAX_JITTER);
        assert!(sample2.is_some());
    }

    #[test]
    fn test_jitter_engine_invalid_keycode() {
        let mut engine = JitterEngine::new([1u8; 32]);
        let (jitter, sample) = engine.on_keystroke(0xFF, [0u8; 32]); // Invalid
        assert_eq!(jitter, 0);
        assert!(sample.is_none());
    }

    #[test]
    fn test_typing_profile() {
        let mut engine = JitterEngine::new([42u8; 32]);
        let doc_hash = [1u8; 32];

        // Simulate some keystrokes
        for keycode in [0x0C, 0x0D, 0x0E, 0x0F, 0x10] {
            engine.on_keystroke(keycode, doc_hash);
        }

        let profile = engine.profile();
        // 5 keystrokes → 4 transitions between consecutive pairs
        assert_eq!(profile.total_transitions, 4);
    }

    #[test]
    fn test_is_human_plausible() {
        let mut profile = TypingProfile::default();
        // Very few transitions - should be plausible
        profile.total_transitions = 5;
        profile.hand_alternation = 0.5;
        assert!(is_human_plausible(profile));

        // Extreme hand alternation
        let mut profile2 = TypingProfile::default();
        profile2.total_transitions = 100;
        profile2.hand_alternation = 0.05; // Too low
        assert!(!is_human_plausible(profile2));
    }

    #[test]
    fn test_compare_profiles() {
        let profile1 = TypingProfile {
            same_finger_hist: [10, 20, 30, 10, 5, 3, 2, 1, 0, 0],
            same_hand_hist: [5, 15, 25, 20, 10, 5, 3, 2, 1, 0],
            alternating_hist: [20, 30, 25, 15, 8, 5, 3, 2, 1, 0],
            hand_alternation: 0.45,
            total_transitions: 100,
            alternating_count: 45,
        };

        let similarity = compare_profiles(profile1, profile1);
        assert!((similarity - 1.0).abs() < 0.001); // Same profile should be ~1.0
    }

    #[test]
    fn test_compare_profiles_empty() {
        let empty = TypingProfile::default();
        let similarity = compare_profiles(empty, empty);
        assert_eq!(similarity, 0.0);
    }

    #[test]
    fn test_profile_distance() {
        let profile1 = TypingProfile {
            same_finger_hist: [10, 20, 30, 10, 5, 3, 2, 1, 0, 0],
            same_hand_hist: [5, 15, 25, 20, 10, 5, 3, 2, 1, 0],
            alternating_hist: [20, 30, 25, 15, 8, 5, 3, 2, 1, 0],
            hand_alternation: 0.45,
            total_transitions: 100,
            alternating_count: 45,
        };

        let distance = profile_distance(profile1, profile1);
        assert!(distance < 0.001); // Same profile should have ~0 distance
    }

    #[test]
    fn test_quick_verify_profile() {
        let mut profile = TypingProfile::default();
        profile.total_transitions = 100;
        profile.hand_alternation = 0.10; // Too low

        let issues = quick_verify_profile(profile);
        assert!(!issues.is_empty());
    }

    #[test]
    fn test_analyze_document_zones() {
        let content = b"hello world";
        let profile = analyze_document_zones(content);
        assert!(profile.total_transitions > 0);
    }

    #[test]
    fn test_verify_jitter_chain() {
        let secret = [42u8; 32];
        let mut engine = JitterEngine::new(secret);
        let doc_hash = [1u8; 32];

        let mut samples = Vec::new();
        for keycode in [0x0C, 0x0D, 0x0E] {
            if let (_, Some(sample)) = engine.on_keystroke(keycode, doc_hash) {
                samples.push(sample);
            }
        }

        verify_jitter_chain(&samples).expect("verify chain");
    }

    #[test]
    fn test_verify_jitter_chain_empty() {
        let err = verify_jitter_chain(&[]).unwrap_err();
        assert!(err.to_string().contains("empty sample chain"));
    }

    #[test]
    fn test_verify_with_secret() {
        let secret = [42u8; 32];
        let mut engine = JitterEngine::new(secret);
        let doc_hash = [1u8; 32];

        let mut samples = Vec::new();
        // Small delay ensures timestamps are monotonically increasing in release mode
        for keycode in [0x0C, 0x0D, 0x0E] {
            thread::sleep(Duration::from_millis(1));
            if let (_, Some(sample)) = engine.on_keystroke(keycode, doc_hash) {
                samples.push(sample);
            }
        }

        verify_with_secret(&samples, secret).expect("verify with secret");
    }

    #[test]
    fn test_verify_with_content() {
        let secret = [42u8; 32];
        let mut engine = JitterEngine::new(secret);
        let content = b"hello";
        let doc_hash: [u8; 32] = Sha256::digest(content).into();

        let mut samples = Vec::new();
        // Simulate typing "hello" - h=4, e=2, l=6, l=6, o=6
        // Small delay ensures timestamps are monotonically increasing in release mode
        for keycode in [0x04, 0x0E, 0x25, 0x25, 0x1F] {
            thread::sleep(Duration::from_millis(1));
            if let (_, Some(sample)) = engine.on_keystroke(keycode, doc_hash) {
                samples.push(sample);
            }
        }

        let result = verify_with_content(&samples, content);
        assert!(result.chain_valid);
        assert!(
            result.errors.is_empty(),
            "unexpected errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_simple_jitter_session() {
        let mut session = SimpleJitterSession::new();
        assert!(session.samples.is_empty());

        let ts1 = session.start_time.timestamp_nanos_safe() + 1_000_000;
        session.add_sample(ts1, 1);
        assert_eq!(session.samples.len(), 1);

        let ts2 = ts1 + 500_000;
        session.add_sample(ts2, 2);
        assert_eq!(session.samples.len(), 2);
        assert_eq!(session.samples[1].duration_since_last_ns, 500_000);
    }

    #[test]
    fn test_marshal_sample_for_signing() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        session.record_keystroke().expect("keystroke");

        let marshaled = marshal_sample_for_signing(&session.samples[0]);
        assert!(marshaled.starts_with(b"witnessd-sample-v1\n"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_evidence_encode_decode() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..3 {
            session.record_keystroke().expect("keystroke");
        }
        session.end();

        let evidence = session.export();
        let encoded = evidence.encode().expect("encode");
        let decoded = Evidence::decode(&encoded).expect("decode");

        assert_eq!(decoded.session_id, evidence.session_id);
        assert_eq!(decoded.samples.len(), evidence.samples.len());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_evidence_typing_rate() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..60 {
            session.record_keystroke().expect("keystroke");
        }
        std::thread::sleep(Duration::from_millis(100));
        session.end();

        let evidence = session.export();
        let rate = evidence.typing_rate();
        // 60 keystrokes in ~100ms = very high rate; should be well above 100
        assert!(
            rate > 100.0,
            "typing rate {} is too low for 60 fast keystrokes",
            rate
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_evidence_document_evolution() {
        let path = temp_document_path();
        fs::write(&path, b"test").expect("write");

        let mut session = Session::new(&path, test_params()).expect("session");
        for _ in 0..5 {
            session.record_keystroke().expect("keystroke");
        }
        session.end();

        let evidence = session.export();
        // All samples have same document hash in this test
        assert_eq!(evidence.document_evolution(), 1);

        let _ = fs::remove_file(&path);
    }
}
