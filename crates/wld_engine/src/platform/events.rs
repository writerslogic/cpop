// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::platform::device::TransportType;
use serde::{Deserialize, Serialize};

/// Captured keystroke with timing, source device, and hardware verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeEvent {
    pub timestamp_ns: i64,
    pub keycode: u16,
    pub zone: u8,
    pub char_value: Option<char>,
    pub is_hardware: bool,
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_type: Option<TransportType>,
}

impl KeystrokeEvent {
    pub fn new(timestamp_ns: i64, keycode: u16, zone: u8) -> Self {
        Self {
            timestamp_ns,
            keycode,
            zone,
            char_value: None,
            is_hardware: true,
            device_id: None,
            transport_type: None,
        }
    }

    pub fn with_verification(timestamp_ns: i64, keycode: u16, zone: u8, is_hardware: bool) -> Self {
        Self {
            timestamp_ns,
            keycode,
            zone,
            char_value: None,
            is_hardware,
            device_id: None,
            transport_type: None,
        }
    }

    pub fn with_device(
        timestamp_ns: i64,
        keycode: u16,
        zone: u8,
        is_hardware: bool,
        device_id: Option<String>,
        transport_type: Option<TransportType>,
    ) -> Self {
        Self {
            timestamp_ns,
            keycode,
            zone,
            char_value: None,
            is_hardware,
            device_id,
            transport_type,
        }
    }
}

/// Captured mouse movement with position, delta, and idle/hardware flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseEvent {
    pub timestamp_ns: i64,
    pub x: f64,
    pub y: f64,
    pub dx: f64,
    pub dy: f64,
    pub is_idle: bool,
    pub is_hardware: bool,
    pub device_id: Option<String>,
}

impl MouseEvent {
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

    pub fn movement_magnitude(&self) -> f64 {
        (self.dx * self.dx + self.dy * self.dy).sqrt()
    }

    pub fn is_micro_movement(&self) -> bool {
        self.movement_magnitude() < 3.0
    }
}
