// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! HMAC-based steganographic timing injection for mouse events.
//!
//! Modes: TimingOnly (HMAC delays), SubPixel (LSB coordinate encoding),
//! FirstMoveOnly (single signature per session). Jitter stays within
//! 500-2000us, well below human perception (~10ms).

use crate::platform::{MouseStegoMode, MouseStegoParams};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

/// Compute HMAC-chained jitter value (microseconds) for a mouse event.
pub fn compute_mouse_jitter(
    seed: &[u8; 32],
    doc_hash: [u8; 32],
    mouse_event_count: u64,
    prev_mouse_jitter: [u8; 32],
    params: &MouseStegoParams,
) -> u32 {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(seed) else {
        log::warn!("mouse_stego: HMAC init failed, returning min delay");
        return params.min_delay_micros;
    };
    mac.update(&doc_hash);
    mac.update(&mouse_event_count.to_be_bytes());
    mac.update(&prev_mouse_jitter);
    mac.update(b"mouse");

    let hash = mac.finalize().into_bytes();
    let raw = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);

    let jitter_range = params
        .max_delay_micros
        .saturating_sub(params.min_delay_micros);
    if jitter_range == 0 {
        return params.min_delay_micros;
    }

    params.min_delay_micros + (raw % jitter_range)
}

/// Compute the jitter hash for chaining to the next event.
pub fn compute_jitter_hash(
    seed: &[u8; 32],
    doc_hash: [u8; 32],
    mouse_event_count: u64,
    jitter_micros: u32,
    prev_hash: [u8; 32],
) -> [u8; 32] {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(seed) else {
        log::warn!("mouse_stego: HMAC init failed in jitter_hash, returning zeroed hash");
        return [0u8; 32];
    };
    mac.update(&doc_hash);
    mac.update(&mouse_event_count.to_be_bytes());
    mac.update(&jitter_micros.to_be_bytes());
    mac.update(&prev_hash);

    let hash = mac.finalize().into_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);
    result
}

/// HMAC-based timing injection engine for mouse events.
pub struct MouseStegoEngine {
    seed: [u8; 32],
    params: MouseStegoParams,
    event_count: u64,
    prev_hash: [u8; 32],
    first_move_done: bool,
    doc_hash: [u8; 32],
}

impl MouseStegoEngine {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            params: MouseStegoParams::default(),
            event_count: 0,
            prev_hash: [0u8; 32],
            first_move_done: false,
            doc_hash: [0u8; 32],
        }
    }

    pub fn set_document_hash(&mut self, hash: [u8; 32]) {
        self.doc_hash = hash;
    }

    pub fn set_params(&mut self, params: MouseStegoParams) {
        self.params = params;
    }

    pub fn params(&self) -> &MouseStegoParams {
        &self.params
    }

    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    pub fn reset(&mut self) {
        self.event_count = 0;
        self.prev_hash = [0u8; 32];
        self.first_move_done = false;
    }

    /// Compute jitter for the next mouse event, or `None` if injection is skipped.
    pub fn next_jitter(&mut self) -> Option<u32> {
        if !self.params.enabled {
            self.event_count += 1;
            return None;
        }

        let should_inject = match self.params.mode {
            MouseStegoMode::FirstMoveOnly => {
                if !self.first_move_done && self.params.inject_on_first_move {
                    self.first_move_done = true;
                    true
                } else {
                    false
                }
            }
            MouseStegoMode::TimingOnly => {
                if self.event_count == 0 && self.params.inject_on_first_move {
                    true
                } else {
                    self.params.inject_while_traveling
                }
            }
            MouseStegoMode::SubPixel => false,
        };

        self.event_count += 1;

        if should_inject {
            let jitter = compute_mouse_jitter(
                &self.seed,
                self.doc_hash,
                self.event_count,
                self.prev_hash,
                &self.params,
            );

            self.prev_hash = compute_jitter_hash(
                &self.seed,
                self.doc_hash,
                self.event_count,
                jitter,
                self.prev_hash,
            );

            Some(jitter)
        } else {
            None
        }
    }

    /// Sub-pixel `(dx, dy)` offset for coordinate steganography (SubPixel mode only).
    pub fn sub_pixel_offset(&self) -> (f64, f64) {
        if !self.params.enabled || self.params.mode != MouseStegoMode::SubPixel {
            return (0.0, 0.0);
        }

        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&self.seed) else {
            log::warn!("mouse_stego: HMAC init failed in sub_pixel_offset");
            return (0.0, 0.0);
        };
        mac.update(&self.doc_hash);
        mac.update(&self.event_count.to_be_bytes());
        mac.update(b"subpixel");

        let hash = mac.finalize().into_bytes();

        let x_bits = (hash[0] & 0x03) as f64;
        let y_bits = ((hash[0] >> 2) & 0x03) as f64;

        let dx = (x_bits - 1.5) * 0.25;
        let dy = (y_bits - 1.5) * 0.25;

        (dx, dy)
    }

    /// Verify a sequence of jitter values against the expected HMAC chain.
    pub fn verify_sequence(
        seed: &[u8; 32],
        doc_hash: [u8; 32],
        jitter_values: &[(u64, u32)], // (event_count, jitter_micros)
        params: &MouseStegoParams,
    ) -> bool {
        let tolerance_micros = 100;

        let mut prev_hash = [0u8; 32];

        for &(event_count, actual_jitter) in jitter_values {
            let expected = compute_mouse_jitter(seed, doc_hash, event_count, prev_hash, params);

            let diff = actual_jitter.abs_diff(expected);

            if diff > tolerance_micros {
                return false;
            }

            prev_hash = compute_jitter_hash(seed, doc_hash, event_count, actual_jitter, prev_hash);
        }

        true
    }
}

impl Drop for MouseStegoEngine {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_mouse_jitter() {
        let seed = [0u8; 32];
        let doc_hash = [1u8; 32];
        let prev_hash = [2u8; 32];
        let params = MouseStegoParams::default();

        let jitter = compute_mouse_jitter(&seed, doc_hash, 1, prev_hash, &params);

        assert!(jitter >= params.min_delay_micros);
        assert!(jitter <= params.max_delay_micros);
    }

    #[test]
    fn test_jitter_deterministic() {
        let seed = [42u8; 32];
        let doc_hash = [1u8; 32];
        let prev_hash = [0u8; 32];
        let params = MouseStegoParams::default();

        let jitter1 = compute_mouse_jitter(&seed, doc_hash, 100, prev_hash, &params);
        let jitter2 = compute_mouse_jitter(&seed, doc_hash, 100, prev_hash, &params);

        assert_eq!(jitter1, jitter2);
    }

    #[test]
    fn test_jitter_varies_with_count() {
        let seed = [42u8; 32];
        let doc_hash = [1u8; 32];
        let prev_hash = [0u8; 32];
        let params = MouseStegoParams::default();

        let jitter1 = compute_mouse_jitter(&seed, doc_hash, 1, prev_hash, &params);
        let jitter2 = compute_mouse_jitter(&seed, doc_hash, 2, prev_hash, &params);

        assert_ne!(jitter1, jitter2);
    }

    #[test]
    fn test_engine_first_move_only() {
        let mut engine = MouseStegoEngine::new([0u8; 32]);
        engine.set_params(MouseStegoParams {
            enabled: true,
            mode: MouseStegoMode::FirstMoveOnly,
            inject_on_first_move: true,
            ..Default::default()
        });

        assert!(engine.next_jitter().is_some());

        assert!(engine.next_jitter().is_none());
        assert!(engine.next_jitter().is_none());
    }

    #[test]
    fn test_engine_timing_continuous() {
        let mut engine = MouseStegoEngine::new([0u8; 32]);
        engine.set_params(MouseStegoParams {
            enabled: true,
            mode: MouseStegoMode::TimingOnly,
            inject_on_first_move: true,
            inject_while_traveling: true,
            ..Default::default()
        });

        assert!(engine.next_jitter().is_some());
        assert!(engine.next_jitter().is_some());
        assert!(engine.next_jitter().is_some());
    }

    #[test]
    fn test_engine_disabled() {
        let mut engine = MouseStegoEngine::new([0u8; 32]);
        engine.set_params(MouseStegoParams {
            enabled: false,
            ..Default::default()
        });

        assert!(engine.next_jitter().is_none());
        assert!(engine.next_jitter().is_none());

        assert_eq!(engine.event_count(), 2);
    }

    #[test]
    fn test_sub_pixel_offset() {
        let mut engine = MouseStegoEngine::new([42u8; 32]);
        engine.set_params(MouseStegoParams {
            enabled: true,
            mode: MouseStegoMode::SubPixel,
            ..Default::default()
        });

        let (dx, dy) = engine.sub_pixel_offset();

        assert!(dx.abs() < 0.5);
        assert!(dy.abs() < 0.5);
    }

    #[test]
    fn test_verify_sequence() {
        let seed = [42u8; 32];
        let doc_hash = [1u8; 32];
        let params = MouseStegoParams::default();

        let mut prev_hash = [0u8; 32];
        let mut jitter_values = Vec::new();

        for count in 1..=5 {
            let jitter = compute_mouse_jitter(&seed, doc_hash, count, prev_hash, &params);
            jitter_values.push((count, jitter));
            prev_hash = compute_jitter_hash(&seed, doc_hash, count, jitter, prev_hash);
        }

        assert!(MouseStegoEngine::verify_sequence(
            &seed,
            doc_hash,
            &jitter_values,
            &params
        ));

        let mut tampered = jitter_values.clone();
        tampered[2].1 += 500;
        assert!(!MouseStegoEngine::verify_sequence(
            &seed, doc_hash, &tampered, &params
        ));
    }

    #[test]
    fn test_engine_reset() {
        let mut engine = MouseStegoEngine::new([0u8; 32]);
        engine.set_params(MouseStegoParams {
            enabled: true,
            mode: MouseStegoMode::FirstMoveOnly,
            inject_on_first_move: true,
            ..Default::default()
        });

        assert!(engine.next_jitter().is_some());
        assert!(engine.next_jitter().is_none());

        engine.reset();

        assert!(engine.next_jitter().is_some());
    }
}
