// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI functions for keystroke/paste injection from host apps.

use super::sentinel::get_sentinel;
use crate::RwLockRecover;

/// Inject a keystroke event from the host app with hardware verification.
///
/// Used when the host platform captures keystrokes via `NSEvent.addGlobalMonitorForEvents`
/// (sandboxed macOS) and forwards them with CGEvent verification fields.
///
/// Verification fields (from `NSEvent.cgEvent`):
/// - `source_state_id`: CGEvent field 45. HID hardware = 1, injected = -1.
/// - `keyboard_type`: CGEvent field 10. ANSI=40, ISO=41, JIS=42; synthetic=0.
/// - `source_pid`: CGEvent field 41. Hardware = 0 (kernel); injected = injector PID.
///
/// Synthetic events are rejected, matching the CGEventTap `verify_event_source` behavior.
/// Maximum sustained keystroke injection rate (keystrokes per second).
/// Human peak burst is ~15 KPS; anything above 50 is clearly synthetic.
const MAX_INJECT_RATE_PER_SEC: u64 = 50;

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_inject_keystroke(
    timestamp_ns: i64,
    keycode: u16,
    zone: u8,
    source_state_id: i64,
    keyboard_type: i64,
    source_pid: i64,
    char_value: String,
) -> bool {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
    };

    // Rate limiting: reject if injection rate exceeds MAX_INJECT_RATE_PER_SEC.
    // Uses a sliding window counter that resets every second.
    {
        use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
        static WINDOW_START_NS: AtomicI64 = AtomicI64::new(0);
        static WINDOW_COUNT: AtomicU64 = AtomicU64::new(0);

        let window_start = WINDOW_START_NS.load(Ordering::Relaxed);
        let elapsed_ns = timestamp_ns.saturating_sub(window_start);
        if elapsed_ns > 1_000_000_000 {
            // New 1-second window
            WINDOW_START_NS.store(timestamp_ns, Ordering::Relaxed);
            WINDOW_COUNT.store(1, Ordering::Relaxed);
        } else {
            let count = WINDOW_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if count > MAX_INJECT_RATE_PER_SEC {
                log::warn!("FFI keystroke injection rate exceeded ({count}/s); rejecting");
                return false;
            }
        }
    }

    // Feed voice fingerprint collector if enabled.
    // Only the first character matters (NSEvent.characters can be multi-char for
    // dead keys, but we want the primary character for writing style analysis).
    let char_opt = char_value.chars().next();
    if let Some(ref mut collector) = *sentinel.voice_collector.write_recover() {
        collector.record_keystroke(keycode, char_opt);
    }

    // Same verification as CGEventTap's verify_event_source.
    // Constants from CGEventTypes.h -- stable across macOS versions.
    const SOURCE_STATE_PRIVATE: i64 = -1;
    const SOURCE_STATE_HID_SYSTEM: i64 = 1;

    // Debug: log inject_keystroke calls
    #[cfg(debug_assertions)]
    {
        use std::sync::atomic::{AtomicU64, Ordering as AO};
        static INJECT_COUNT: AtomicU64 = AtomicU64::new(0);
        static REJECT_COUNT: AtomicU64 = AtomicU64::new(0);
        let n = INJECT_COUNT.fetch_add(1, AO::Relaxed);
        if source_state_id == SOURCE_STATE_PRIVATE || keyboard_type == 0 || source_pid != 0 {
            REJECT_COUNT.fetch_add(1, AO::Relaxed);
        }
        if n < 5 || n % 50 == 0 {
            use std::io::Write;
            let debug_path = std::env::var("CPOP_DATA_DIR")
                .map(|d| format!("{}/inject_debug.txt", d))
                .unwrap_or_else(|_| "/tmp/cpop_inject_debug.txt".to_string());
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&debug_path)
            {
                let _ = writeln!(
                    f,
                    "inject #{}: state={} kbd_type={} pid={} rejected_so_far={}",
                    n,
                    source_state_id,
                    keyboard_type,
                    source_pid,
                    REJECT_COUNT.load(AO::Relaxed)
                );
            }
        }
    }
    if source_state_id == SOURCE_STATE_PRIVATE {
        return false;
    }
    // When NSEvent.addGlobalMonitorForEvents delivers events without a backing
    // CGEvent (sandboxed apps), all three fields are 0. Accept these as trusted
    // in-process FFI injections from KeystrokeMonitorService. The PreWitnessBuffer
    // will still validate human plausibility before auto-starting a session.
    let is_unverified_ffi = source_state_id == 0 && keyboard_type == 0 && source_pid == 0;
    if !is_unverified_ffi {
        // keyboard_type 0 = no physical keyboard (synthetic). Values up to ~255
        // are valid Apple keyboard types (e.g. 106 = JIS, 44/45 = standard US).
        if keyboard_type == 0 {
            return false;
        }
        if source_pid != 0 {
            return false;
        }
        if source_state_id != SOURCE_STATE_HID_SYSTEM {
            log::debug!(
                "inject_keystroke: suspicious source_state_id={source_state_id} — accepted"
            );
        }
    }

    // Compute inter-keystroke duration from timestamps (the Swift side
    // sends absolute timestamps; we need the delta for cadence analysis).
    //
    // Design limitation: LAST_INJECT_TS is process-global, not per-document.
    // When the user switches between documents, the first keystroke in the new
    // document will produce an inflated duration_since_last_ns spanning the idle
    // period between documents. This causes the per-document cadence analysis to
    // see one anomalously long inter-key interval at each document switch.
    // Impact: negligible for typical use (one outlier per switch is filtered by
    // the jitter analyzer's outlier rejection), but cadence scores near the
    // boundary may be slightly penalized when documents are switched frequently.
    static LAST_INJECT_TS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    let prev_ts = LAST_INJECT_TS.swap(timestamp_ns, std::sync::atomic::Ordering::Relaxed);
    let duration_since_last_ns = if prev_ts > 0 && timestamp_ns > prev_ts {
        (timestamp_ns - prev_ts) as u64
    } else {
        0
    };

    let sample = crate::jitter::SimpleJitterSample {
        timestamp_ns,
        duration_since_last_ns,
        zone,
    };
    sentinel
        .activity_accumulator
        .write_recover()
        .add_sample(&sample);

    // Attribute keystroke to the currently focused document.
    // If no session exists, buffer keystrokes for auto-witnessing.
    if let Some(ref path) = sentinel.current_focus() {
        // Auto-witness: if no session exists, buffer keystrokes and check human plausibility
        if !sentinel.sessions.read_recover().contains_key(path.as_str()) {
            use crate::sentinel::types::{
                AutoWitnessDecision, PreWitnessBuffer, PreWitnessKeystroke,
            };
            use std::collections::HashMap;
            use std::sync::Mutex;

            // Process-global pre-witness buffers for the FFI inject path
            static FFI_PRE_WITNESS: Mutex<Option<HashMap<String, PreWitnessBuffer>>> =
                Mutex::new(None);

            let mut guard = FFI_PRE_WITNESS.lock().unwrap_or_else(|e| e.into_inner());
            let buffers = guard.get_or_insert_with(HashMap::new);

            let buffer = buffers
                .entry(path.clone())
                .or_insert_with(|| PreWitnessBuffer::new(path.clone()));

            if !buffer.rejected {
                buffer.keystrokes.push(PreWitnessKeystroke {
                    timestamp_ns,
                    keycode,
                    zone,
                    source_pid,
                });

                let config = sentinel.config();
                let decision = buffer.should_auto_witness(
                    config.auto_witness_min_keystrokes,
                    config.auto_witness_min_cv,
                    config.auto_witness_max_same_key_pct,
                    config.auto_witness_min_zones,
                );

                match decision {
                    AutoWitnessDecision::HumanPlausible => {
                        let keystroke_count = buffer.keystrokes.len() as u64;
                        let file_path = std::path::Path::new(path.as_str());
                        // Mark buffer as consumed under the lock to prevent
                        // a TOCTOU race where another thread re-buffers
                        // keystrokes between lock drop and start_witnessing.
                        buffer.rejected = true;
                        drop(guard);

                        if file_path.exists() && file_path.is_file() {
                            match sentinel.start_witnessing(file_path) {
                                Ok(()) => {
                                    log::info!(
                                        "Auto-witnessed {} after {} human-plausible keystrokes (FFI path)",
                                        path, keystroke_count
                                    );
                                    // Set the initial keystroke count from the buffer
                                    if let Some(session) =
                                        sentinel.sessions.write_recover().get_mut(path.as_str())
                                    {
                                        session.keystroke_count = keystroke_count;
                                    }
                                }
                                Err(e) => {
                                    log::debug!("Auto-witness failed for {}: {:?}", path, e);
                                }
                            }
                        }
                        return true; // keystroke processed
                    }
                    AutoWitnessDecision::NotEnoughData => {} // keep buffering
                    rejected => {
                        log::debug!("Auto-witness rejected for {}: {:?}", path, rejected);
                        buffer.rejected = true;
                    }
                }
            }

            // Evict stale buffers older than 60 seconds
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            buffers.retain(|_, buf| {
                buf.created_at
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|t| now.as_secs() - t.as_secs() < 60)
                    .unwrap_or(false)
            });

            return true;
        }

        if let Some(session) = sentinel.sessions.write_recover().get_mut(path) {
            session.keystroke_count += 1;
            // Store jitter sample for per-document forensic analysis.
            // Track whether the push actually occurred so the rollback below
            // only pops when there is a matching push to undo.
            let pushed =
                session.jitter_samples.len() < crate::sentinel::types::MAX_DOCUMENT_JITTER_SAMPLES;
            if pushed {
                session.jitter_samples.push(sample.clone());
            }

            let validation = crate::forensics::validate_keystroke_event(
                timestamp_ns,
                keycode,
                zone,
                source_pid,
                None, // frontmost_pid not available in FFI path
                session.has_focus,
                &mut session.event_validation,
            );
            // Drop events with very low confidence (likely synthetic injection)
            if validation.confidence < 0.1 {
                session.keystroke_count -= 1; // undo the increment
                if pushed {
                    session.jitter_samples.pop(); // undo the push
                }
            }
        }
    }
    true
}

/// Notify the sentinel of a paste event detected by the host app.
///
/// `char_count` is the number of characters pasted. The sentinel
/// records this so the next checkpoint can flag it as a paste.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_notify_paste(char_count: i64) -> bool {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
    };

    let sessions = sentinel.sessions();
    if sessions.is_empty() {
        return false;
    }

    // Store the paste char count so ffi_sentinel_witnessing_status can report it
    sentinel.set_last_paste_chars(char_count);
    true
}
