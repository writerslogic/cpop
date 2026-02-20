//! Mouse Steganography Module
//!
//! This module implements HMAC-based steganographic timing injection for mouse events.
//! It follows the same cryptographic pattern as the keystroke jitter in jitter.rs.
//!
//! # Steganography Modes
//!
//! - **TimingOnly**: Inject HMAC-derived delays on mouse movements (safest)
//! - **SubPixel**: Encode in least significant bits of coordinates (higher bandwidth)
//! - **FirstMoveOnly**: Single signature on first move per session (minimal footprint)
//!
//! # Imperceptibility
//!
//! The timing jitter stays within 500-2000 microseconds, well below human perception
//! threshold (~10ms for timing differences).

use crate::platform::types::{MouseStegoMode, MouseStegoParams};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Compute HMAC-based jitter value for mouse steganography.
///
/// This mirrors the approach used in jitter.rs `compute_jitter_value()`.
///
/// # Arguments
///
/// * `seed` - 32-byte secret seed (derived from signing key)
/// * `doc_hash` - 32-byte document hash
/// * `mouse_event_count` - Number of mouse events processed
/// * `prev_mouse_jitter` - Hash from previous jitter computation (for chaining)
/// * `params` - Steganography parameters
///
/// # Returns
///
/// Jitter value in microseconds within the configured range.
pub fn compute_mouse_jitter(
    seed: &[u8; 32],
    doc_hash: [u8; 32],
    mouse_event_count: u64,
    prev_mouse_jitter: [u8; 32],
    params: &MouseStegoParams,
) -> u32 {
    let mut mac = Hmac::<Sha256>::new_from_slice(seed).expect("hmac key");
    mac.update(&doc_hash);
    mac.update(&mouse_event_count.to_be_bytes());
    mac.update(&prev_mouse_jitter);
    mac.update(b"mouse"); // Domain separator to differentiate from keystroke jitter

    let hash = mac.finalize().into_bytes();
    let raw = u32::from_be_bytes(hash[0..4].try_into().unwrap());

    let jitter_range = params
        .max_delay_micros
        .saturating_sub(params.min_delay_micros);
    if jitter_range == 0 {
        return params.min_delay_micros;
    }

    params.min_delay_micros + (raw % jitter_range)
}

/// Compute the jitter hash for chaining.
///
/// This produces the prev_mouse_jitter value for the next computation.
pub fn compute_jitter_hash(
    seed: &[u8; 32],
    doc_hash: [u8; 32],
    mouse_event_count: u64,
    jitter_micros: u32,
    prev_hash: [u8; 32],
) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(seed).expect("hmac key");
    mac.update(&doc_hash);
    mac.update(&mouse_event_count.to_be_bytes());
    mac.update(&jitter_micros.to_be_bytes());
    mac.update(&prev_hash);

    let hash = mac.finalize().into_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);
    result
}

/// Mouse steganography engine.
///
/// Manages state for HMAC-based timing injection on mouse events.
pub struct MouseStegoEngine {
    /// Secret seed for HMAC computations
    seed: [u8; 32],
    /// Current steganography parameters
    params: MouseStegoParams,
    /// Counter of mouse events processed
    event_count: u64,
    /// Previous jitter hash for chaining
    prev_hash: [u8; 32],
    /// Whether first move signature has been injected
    first_move_done: bool,
    /// Current document hash
    doc_hash: [u8; 32],
}

impl MouseStegoEngine {
    /// Create a new mouse steganography engine.
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

    /// Set the document hash for the current session.
    pub fn set_document_hash(&mut self, hash: [u8; 32]) {
        self.doc_hash = hash;
    }

    /// Update steganography parameters.
    pub fn set_params(&mut self, params: MouseStegoParams) {
        self.params = params;
    }

    /// Get current parameters.
    pub fn params(&self) -> &MouseStegoParams {
        &self.params
    }

    /// Get the current event count.
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Reset the engine state for a new session.
    pub fn reset(&mut self) {
        self.event_count = 0;
        self.prev_hash = [0u8; 32];
        self.first_move_done = false;
    }

    /// Compute jitter for the next mouse event.
    ///
    /// Returns `Some(jitter_micros)` if injection should occur, `None` otherwise.
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
            MouseStegoMode::SubPixel => {
                // Sub-pixel mode uses coordinate encoding, not timing
                // Return None for timing injection
                false
            }
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

            // Update chain hash
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

    /// Get sub-pixel offset for coordinate steganography.
    ///
    /// Returns `(dx_offset, dy_offset)` to add to coordinates.
    /// Only effective when mode is `SubPixel`.
    pub fn sub_pixel_offset(&self) -> (f64, f64) {
        if !self.params.enabled || self.params.mode != MouseStegoMode::SubPixel {
            return (0.0, 0.0);
        }

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.seed).expect("hmac key");
        mac.update(&self.doc_hash);
        mac.update(&self.event_count.to_be_bytes());
        mac.update(b"subpixel");

        let hash = mac.finalize().into_bytes();

        // Extract 2 bits each for x and y offset
        // Map to range [-0.5, 0.5] in 0.25 increments
        let x_bits = (hash[0] & 0x03) as f64;
        let y_bits = ((hash[0] >> 2) & 0x03) as f64;

        let dx = (x_bits - 1.5) * 0.25; // -0.375, -0.125, 0.125, 0.375
        let dy = (y_bits - 1.5) * 0.25;

        (dx, dy)
    }

    /// Verify a sequence of mouse jitter values.
    ///
    /// Returns true if the jitter sequence matches the expected HMAC chain.
    pub fn verify_sequence(
        seed: &[u8; 32],
        doc_hash: [u8; 32],
        jitter_values: &[(u64, u32)], // (event_count, jitter_micros)
        params: &MouseStegoParams,
    ) -> bool {
        let tolerance_micros = 100; // ±100μs tolerance

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

// =============================================================================
// Tests
// =============================================================================

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

        // Should be within configured range
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

        // Different counts should produce different jitter (with high probability)
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

        // First call should return jitter
        assert!(engine.next_jitter().is_some());

        // Subsequent calls should return None
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

        // All calls should return jitter
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

        // Event count should still increment
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

        // Offsets should be small (within ±0.5)
        assert!(dx.abs() < 0.5);
        assert!(dy.abs() < 0.5);
    }

    #[test]
    fn test_verify_sequence() {
        let seed = [42u8; 32];
        let doc_hash = [1u8; 32];
        let params = MouseStegoParams::default();

        // Generate some jitter values
        let mut prev_hash = [0u8; 32];
        let mut jitter_values = Vec::new();

        for count in 1..=5 {
            let jitter = compute_mouse_jitter(&seed, doc_hash, count, prev_hash, &params);
            jitter_values.push((count, jitter));
            prev_hash = compute_jitter_hash(&seed, doc_hash, count, jitter, prev_hash);
        }

        // Verification should pass
        assert!(MouseStegoEngine::verify_sequence(
            &seed,
            doc_hash,
            &jitter_values,
            &params
        ));

        // Tampered sequence should fail
        let mut tampered = jitter_values.clone();
        tampered[2].1 += 500; // Add 500μs to third value
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

        // Use the first move
        assert!(engine.next_jitter().is_some());
        assert!(engine.next_jitter().is_none());

        // Reset
        engine.reset();

        // First move should work again
        assert!(engine.next_jitter().is_some());
    }
}
