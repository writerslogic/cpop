//! Shared types for cross-platform keystroke capture and focus monitoring.
//!
//! These types define the common interface for keystroke events, focus information,
//! and synthetic event detection statistics across all supported platforms.

use serde::{Deserialize, Serialize};

// =============================================================================
// Keystroke Event Types
// =============================================================================

/// A captured keystroke event with timing and source information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeEvent {
    /// Timestamp in nanoseconds since Unix epoch
    pub timestamp_ns: i64,
    /// Platform-specific keycode
    pub keycode: u16,
    /// Keyboard zone (0-7 for hand position analysis)
    pub zone: u8,
    /// Character value if available (for voice fingerprinting)
    pub char_value: Option<char>,
    /// Whether this event is verified as hardware-originated
    pub is_hardware: bool,
    /// Device identifier if available
    pub device_id: Option<String>,
}

impl KeystrokeEvent {
    /// Create a new keystroke event.
    pub fn new(timestamp_ns: i64, keycode: u16, zone: u8) -> Self {
        Self {
            timestamp_ns,
            keycode,
            zone,
            char_value: None,
            is_hardware: true,
            device_id: None,
        }
    }

    /// Create a keystroke event with hardware verification status.
    pub fn with_verification(timestamp_ns: i64, keycode: u16, zone: u8, is_hardware: bool) -> Self {
        Self {
            timestamp_ns,
            keycode,
            zone,
            char_value: None,
            is_hardware,
            device_id: None,
        }
    }
}

// =============================================================================
// Focus Information
// =============================================================================

/// Information about the currently focused application and document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FocusInfo {
    /// Name of the application
    pub app_name: String,
    /// Bundle ID (macOS) or executable path (Windows/Linux)
    pub bundle_id: String,
    /// Process ID
    pub pid: i32,
    /// Path to the focused document if available
    pub doc_path: Option<String>,
    /// Title of the document if available
    pub doc_title: Option<String>,
    /// Title of the window
    pub window_title: Option<String>,
}

// =============================================================================
// HID Device Information
// =============================================================================

/// Information about a connected HID keyboard device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HIDDeviceInfo {
    /// USB Vendor ID
    pub vendor_id: u32,
    /// USB Product ID
    pub product_id: u32,
    /// Product name from device descriptor
    pub product_name: String,
    /// Manufacturer name
    pub manufacturer: String,
    /// Serial number if available
    pub serial_number: Option<String>,
    /// Transport type (USB, Bluetooth, etc.)
    pub transport: String,
}

impl HIDDeviceInfo {
    /// Check if this device appears to be virtual/synthetic.
    pub fn appears_virtual(&self) -> bool {
        // Common indicators of virtual devices
        self.vendor_id == 0
            || self.product_id == 0
            || self.product_name.to_lowercase().contains("virtual")
            || self.product_name.to_lowercase().contains("uinput")
            || self.manufacturer.to_lowercase().contains("virtual")
    }
}

// =============================================================================
// Synthetic Event Detection
// =============================================================================

/// Statistics about synthetic event detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyntheticStats {
    /// Total events processed
    pub total_events: u64,
    /// Events verified as hardware-originated
    pub verified_hardware: u64,
    /// Events rejected as synthetic
    pub rejected_synthetic: u64,
    /// Suspicious events that were accepted (non-strict mode)
    pub suspicious_accepted: u64,
    /// Platform-specific rejection reasons
    pub rejection_reasons: RejectionReasons,
}

impl SyntheticStats {
    /// Calculate the hardware event ratio.
    pub fn hardware_ratio(&self) -> f64 {
        if self.total_events == 0 {
            1.0
        } else {
            self.verified_hardware as f64 / self.total_events as f64
        }
    }

    /// Calculate the synthetic event ratio.
    pub fn synthetic_ratio(&self) -> f64 {
        if self.total_events == 0 {
            0.0
        } else {
            self.rejected_synthetic as f64 / self.total_events as f64
        }
    }

    /// Check if synthetic injection has been detected.
    pub fn injection_detected(&self) -> bool {
        self.rejected_synthetic > 0
    }

    /// Merge statistics from another instance.
    pub fn merge(&mut self, other: &SyntheticStats) {
        self.total_events += other.total_events;
        self.verified_hardware += other.verified_hardware;
        self.rejected_synthetic += other.rejected_synthetic;
        self.suspicious_accepted += other.suspicious_accepted;
        self.rejection_reasons.merge(&other.rejection_reasons);
    }
}

/// Platform-specific rejection reasons for synthetic events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RejectionReasons {
    /// macOS: Bad CGEventSourceStateID
    pub bad_source_state: u64,
    /// macOS: Invalid keyboard type
    pub bad_keyboard_type: u64,
    /// macOS: Non-kernel PID
    pub non_kernel_pid: u64,
    /// macOS: Zero timestamp
    pub zero_timestamp: u64,
    /// Linux: Virtual device name
    pub virtual_device: u64,
    /// Linux: Empty phys path
    pub empty_phys_path: u64,
    /// Linux: Invalid VID:PID
    pub invalid_vid_pid: u64,
    /// Windows: Injected flag set
    pub injected_flag: u64,
    /// Statistical: Robotic timing (CV < 0.15)
    pub statistical_robotic: u64,
    /// Statistical: Superhuman speed (< 20ms IKI)
    pub statistical_superhuman: u64,
    /// Statistical: Replay pattern detected
    pub statistical_replay: u64,
}

impl RejectionReasons {
    /// Merge rejection reasons from another instance.
    pub fn merge(&mut self, other: &RejectionReasons) {
        self.bad_source_state += other.bad_source_state;
        self.bad_keyboard_type += other.bad_keyboard_type;
        self.non_kernel_pid += other.non_kernel_pid;
        self.zero_timestamp += other.zero_timestamp;
        self.virtual_device += other.virtual_device;
        self.empty_phys_path += other.empty_phys_path;
        self.invalid_vid_pid += other.invalid_vid_pid;
        self.injected_flag += other.injected_flag;
        self.statistical_robotic += other.statistical_robotic;
        self.statistical_superhuman += other.statistical_superhuman;
        self.statistical_replay += other.statistical_replay;
    }
}

/// Result of verifying an event's source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventVerificationResult {
    /// Verified as hardware event
    Hardware,
    /// Likely synthetic, should be rejected
    Synthetic,
    /// Suspicious but accepted
    Suspicious,
}

impl EventVerificationResult {
    /// Check if the event should be accepted.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Hardware | Self::Suspicious)
    }

    /// Check if the event is verified hardware.
    pub fn is_hardware(&self) -> bool {
        matches!(self, Self::Hardware)
    }
}

// =============================================================================
// Permission Status
// =============================================================================

/// Permission status for platform-specific security features.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionStatus {
    /// Accessibility/automation permissions (macOS)
    pub accessibility: bool,
    /// Input monitoring permissions (macOS)
    pub input_monitoring: bool,
    /// Input device access (Linux /dev/input)
    pub input_devices: bool,
    /// All required permissions granted
    pub all_granted: bool,
}

impl PermissionStatus {
    /// Create a permission status where all permissions are granted.
    pub fn all_permitted() -> Self {
        Self {
            accessibility: true,
            input_monitoring: true,
            input_devices: true,
            all_granted: true,
        }
    }
}

// =============================================================================
// Dual-Layer Validation
// =============================================================================

/// Result of dual-layer keystroke validation (CGEventTap vs IOKit HID on macOS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualLayerValidation {
    /// Count from high-level API (CGEventTap, etc.)
    pub high_level_count: u64,
    /// Count from low-level API (IOKit HID, evdev, etc.)
    pub low_level_count: u64,
    /// Whether synthetic events were detected
    pub synthetic_detected: bool,
    /// Discrepancy between counts
    pub discrepancy: i64,
}

impl DualLayerValidation {
    /// Calculate the discrepancy ratio.
    pub fn discrepancy_ratio(&self) -> f64 {
        if self.low_level_count == 0 {
            if self.high_level_count == 0 {
                0.0
            } else {
                1.0 // 100% discrepancy
            }
        } else {
            self.discrepancy.abs() as f64 / self.low_level_count as f64
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

// =============================================================================
// Mouse Event Types
// =============================================================================

/// A captured mouse movement event with timing and position information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseEvent {
    /// Timestamp in nanoseconds since Unix epoch
    pub timestamp_ns: i64,
    /// Screen X coordinate
    pub x: f64,
    /// Screen Y coordinate
    pub y: f64,
    /// Delta X (movement since last event)
    pub dx: f64,
    /// Delta Y (movement since last event)
    pub dy: f64,
    /// Whether this is an idle jitter event (mouse stationary during typing)
    pub is_idle: bool,
    /// Whether this event is verified as hardware-originated
    pub is_hardware: bool,
    /// Device identifier if available
    pub device_id: Option<String>,
}

impl MouseEvent {
    /// Create a new mouse event.
    pub fn new(timestamp_ns: i64, x: f64, y: f64, dx: f64, dy: f64) -> Self {
        Self {
            timestamp_ns,
            x,
            y,
            dx,
            dy,
            is_idle: false,
            is_hardware: true,
            device_id: None,
        }
    }

    /// Create an idle jitter event (mouse stationary during keyboard activity).
    pub fn idle_jitter(timestamp_ns: i64, x: f64, y: f64, dx: f64, dy: f64) -> Self {
        Self {
            timestamp_ns,
            x,
            y,
            dx,
            dy,
            is_idle: true,
            is_hardware: true,
            device_id: None,
        }
    }

    /// Calculate the magnitude of movement.
    pub fn movement_magnitude(&self) -> f64 {
        (self.dx * self.dx + self.dy * self.dy).sqrt()
    }

    /// Check if this is a micro-movement (likely idle jitter).
    pub fn is_micro_movement(&self) -> bool {
        self.movement_magnitude() < 3.0 // Less than 3 pixels
    }
}

/// Statistics about mouse idle jitter for fingerprinting.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MouseIdleStats {
    /// Total idle jitter events captured
    pub total_events: u64,
    /// Sum of X deltas (for mean calculation)
    pub sum_dx: f64,
    /// Sum of Y deltas (for mean calculation)
    pub sum_dy: f64,
    /// Sum of squared X deltas (for variance calculation)
    pub sum_dx_squared: f64,
    /// Sum of squared Y deltas (for variance calculation)
    pub sum_dy_squared: f64,
    /// Sum of movement magnitudes
    pub sum_magnitude: f64,
    /// Sum of squared magnitudes (for variance)
    pub sum_magnitude_squared: f64,
    /// Maximum movement magnitude observed
    pub max_magnitude: f64,
    /// Minimum movement magnitude observed
    pub min_magnitude: f64,
    /// Count of events in each quadrant (NE, NW, SW, SE)
    pub quadrant_counts: [u64; 4],
}

impl MouseIdleStats {
    /// Create new empty statistics.
    pub fn new() -> Self {
        Self {
            min_magnitude: f64::MAX,
            ..Default::default()
        }
    }

    /// Record an idle jitter event.
    pub fn record(&mut self, event: &MouseEvent) {
        self.total_events += 1;
        self.sum_dx += event.dx;
        self.sum_dy += event.dy;
        self.sum_dx_squared += event.dx * event.dx;
        self.sum_dy_squared += event.dy * event.dy;

        let magnitude = event.movement_magnitude();
        self.sum_magnitude += magnitude;
        self.sum_magnitude_squared += magnitude * magnitude;
        self.max_magnitude = self.max_magnitude.max(magnitude);
        self.min_magnitude = self.min_magnitude.min(magnitude);

        // Quadrant: 0=NE (dx>=0, dy<0), 1=NW (dx<0, dy<0), 2=SW (dx<0, dy>=0), 3=SE (dx>=0, dy>=0)
        let quadrant = match (event.dx >= 0.0, event.dy >= 0.0) {
            (true, false) => 0,  // NE
            (false, false) => 1, // NW
            (false, true) => 2,  // SW
            (true, true) => 3,   // SE
        };
        self.quadrant_counts[quadrant] += 1;
    }

    /// Calculate mean X delta.
    pub fn mean_dx(&self) -> f64 {
        if self.total_events == 0 {
            0.0
        } else {
            self.sum_dx / self.total_events as f64
        }
    }

    /// Calculate mean Y delta.
    pub fn mean_dy(&self) -> f64 {
        if self.total_events == 0 {
            0.0
        } else {
            self.sum_dy / self.total_events as f64
        }
    }

    /// Calculate mean movement magnitude.
    pub fn mean_magnitude(&self) -> f64 {
        if self.total_events == 0 {
            0.0
        } else {
            self.sum_magnitude / self.total_events as f64
        }
    }

    /// Calculate variance of movement magnitude.
    pub fn variance_magnitude(&self) -> f64 {
        if self.total_events < 2 {
            0.0
        } else {
            let mean = self.mean_magnitude();
            (self.sum_magnitude_squared / self.total_events as f64) - (mean * mean)
        }
    }

    /// Calculate standard deviation of movement magnitude.
    pub fn std_magnitude(&self) -> f64 {
        self.variance_magnitude().sqrt()
    }

    /// Calculate quadrant bias (0.0 = uniform, 1.0 = single quadrant).
    pub fn quadrant_bias(&self) -> f64 {
        if self.total_events == 0 {
            return 0.0;
        }
        let expected = self.total_events as f64 / 4.0;
        let chi_squared: f64 = self
            .quadrant_counts
            .iter()
            .map(|&count| {
                let diff = count as f64 - expected;
                (diff * diff) / expected
            })
            .sum();
        // Normalize to 0-1 range
        (chi_squared / (3.0 * self.total_events as f64)).min(1.0)
    }

    /// Merge statistics from another instance.
    pub fn merge(&mut self, other: &MouseIdleStats) {
        self.total_events += other.total_events;
        self.sum_dx += other.sum_dx;
        self.sum_dy += other.sum_dy;
        self.sum_dx_squared += other.sum_dx_squared;
        self.sum_dy_squared += other.sum_dy_squared;
        self.sum_magnitude += other.sum_magnitude;
        self.sum_magnitude_squared += other.sum_magnitude_squared;
        self.max_magnitude = self.max_magnitude.max(other.max_magnitude);
        self.min_magnitude = self.min_magnitude.min(other.min_magnitude);
        for i in 0..4 {
            self.quadrant_counts[i] += other.quadrant_counts[i];
        }
    }
}

// =============================================================================
// Mouse Steganography Parameters
// =============================================================================

/// Mode for mouse steganography.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseStegoMode {
    /// Inject timing jitter only (safest, default)
    #[default]
    TimingOnly,
    /// Inject in sub-pixel coordinates (higher bandwidth, platform-specific)
    SubPixel,
    /// Inject signature on first move only (minimal footprint)
    FirstMoveOnly,
}

/// Parameters for mouse steganography.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseStegoParams {
    /// Whether steganography is enabled
    pub enabled: bool,
    /// Steganography mode
    pub mode: MouseStegoMode,
    /// Minimum injection delay in microseconds
    pub min_delay_micros: u32,
    /// Maximum injection delay in microseconds
    pub max_delay_micros: u32,
    /// Inject on first mouse move after keyboard activity
    pub inject_on_first_move: bool,
    /// Inject while mouse is traveling (continuous)
    pub inject_while_traveling: bool,
}

impl Default for MouseStegoParams {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: MouseStegoMode::TimingOnly,
            min_delay_micros: 500,
            max_delay_micros: 2000,
            inject_on_first_move: true,
            inject_while_traveling: false,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystroke_event_creation() {
        let event = KeystrokeEvent::new(1234567890, 0x04, 2);
        assert_eq!(event.timestamp_ns, 1234567890);
        assert_eq!(event.keycode, 0x04);
        assert_eq!(event.zone, 2);
        assert!(event.is_hardware);
    }

    #[test]
    fn test_synthetic_stats_merge() {
        let mut stats1 = SyntheticStats {
            total_events: 100,
            verified_hardware: 95,
            rejected_synthetic: 5,
            suspicious_accepted: 0,
            rejection_reasons: RejectionReasons::default(),
        };

        let stats2 = SyntheticStats {
            total_events: 50,
            verified_hardware: 45,
            rejected_synthetic: 5,
            suspicious_accepted: 0,
            rejection_reasons: RejectionReasons::default(),
        };

        stats1.merge(&stats2);
        assert_eq!(stats1.total_events, 150);
        assert_eq!(stats1.verified_hardware, 140);
        assert_eq!(stats1.rejected_synthetic, 10);
    }

    #[test]
    fn test_hardware_ratio() {
        let stats = SyntheticStats {
            total_events: 100,
            verified_hardware: 90,
            rejected_synthetic: 10,
            suspicious_accepted: 0,
            rejection_reasons: RejectionReasons::default(),
        };
        assert!((stats.hardware_ratio() - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_hid_device_virtual_detection() {
        let virtual_device = HIDDeviceInfo {
            vendor_id: 0,
            product_id: 0,
            product_name: "Virtual Keyboard".to_string(),
            manufacturer: "Virtual".to_string(),
            serial_number: None,
            transport: "Virtual".to_string(),
        };
        assert!(virtual_device.appears_virtual());

        let real_device = HIDDeviceInfo {
            vendor_id: 0x05ac,
            product_id: 0x0256,
            product_name: "Apple Internal Keyboard".to_string(),
            manufacturer: "Apple Inc.".to_string(),
            serial_number: Some("ABC123".to_string()),
            transport: "USB".to_string(),
        };
        assert!(!real_device.appears_virtual());
    }

    #[test]
    fn test_mouse_event_creation() {
        let event = MouseEvent::new(1234567890, 100.0, 200.0, 1.5, -0.5);
        assert_eq!(event.timestamp_ns, 1234567890);
        assert_eq!(event.x, 100.0);
        assert_eq!(event.y, 200.0);
        assert_eq!(event.dx, 1.5);
        assert_eq!(event.dy, -0.5);
        assert!(!event.is_idle);
        assert!(event.is_hardware);
    }

    #[test]
    fn test_mouse_event_idle_jitter() {
        let event = MouseEvent::idle_jitter(1234567890, 100.0, 200.0, 0.5, 0.3);
        assert!(event.is_idle);
        assert!(event.is_micro_movement());
    }

    #[test]
    fn test_mouse_movement_magnitude() {
        let event = MouseEvent::new(0, 0.0, 0.0, 3.0, 4.0);
        assert!((event.movement_magnitude() - 5.0).abs() < 0.001);
    }

    #[test]
    fn test_mouse_idle_stats_recording() {
        let mut stats = MouseIdleStats::new();

        // Record some events in different quadrants
        stats.record(&MouseEvent::new(0, 0.0, 0.0, 1.0, -1.0)); // NE
        stats.record(&MouseEvent::new(0, 0.0, 0.0, -1.0, -1.0)); // NW
        stats.record(&MouseEvent::new(0, 0.0, 0.0, -1.0, 1.0)); // SW
        stats.record(&MouseEvent::new(0, 0.0, 0.0, 1.0, 1.0)); // SE

        assert_eq!(stats.total_events, 4);
        assert_eq!(stats.quadrant_counts[0], 1); // NE
        assert_eq!(stats.quadrant_counts[1], 1); // NW
        assert_eq!(stats.quadrant_counts[2], 1); // SW
        assert_eq!(stats.quadrant_counts[3], 1); // SE

        // Mean should be 0 since movements cancel out
        assert!((stats.mean_dx()).abs() < 0.001);
        assert!((stats.mean_dy()).abs() < 0.001);
    }

    #[test]
    fn test_mouse_idle_stats_quadrant_bias() {
        let mut stats = MouseIdleStats::new();

        // All events in one quadrant - maximum bias
        for _ in 0..10 {
            stats.record(&MouseEvent::new(0, 0.0, 0.0, 1.0, 1.0)); // SE
        }

        // Bias should be high (close to 1.0)
        assert!(stats.quadrant_bias() > 0.5);

        // Uniform distribution - low bias
        let mut uniform_stats = MouseIdleStats::new();
        for _ in 0..25 {
            uniform_stats.record(&MouseEvent::new(0, 0.0, 0.0, 1.0, -1.0)); // NE
            uniform_stats.record(&MouseEvent::new(0, 0.0, 0.0, -1.0, -1.0)); // NW
            uniform_stats.record(&MouseEvent::new(0, 0.0, 0.0, -1.0, 1.0)); // SW
            uniform_stats.record(&MouseEvent::new(0, 0.0, 0.0, 1.0, 1.0)); // SE
        }

        // Bias should be low (close to 0.0)
        assert!(uniform_stats.quadrant_bias() < 0.1);
    }

    #[test]
    fn test_mouse_stego_params_default() {
        let params = MouseStegoParams::default();
        assert!(params.enabled);
        assert_eq!(params.mode, MouseStegoMode::TimingOnly);
        assert_eq!(params.min_delay_micros, 500);
        assert_eq!(params.max_delay_micros, 2000);
        assert!(params.inject_on_first_move);
        assert!(!params.inject_while_traveling);
    }
}
