// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};

/// Input device transport/connection type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportType {
    Usb,
    Bluetooth,
    /// Internal I/O bus (i8042, SPI, etc.)
    Internal,
    /// Android Debug Bridge
    Adb,
    /// Software keyboard (uinput, virtual device)
    Virtual,
    #[default]
    Unknown,
}

impl TransportType {
    pub fn from_macos_transport(transport: &str) -> Self {
        let lower = transport.to_lowercase();
        match lower.as_str() {
            "usb" => Self::Usb,
            "bluetooth" | "bluetoothle" => Self::Bluetooth,
            "spi" | "i2c" | "fifo" | "built-in" => Self::Internal,
            "virtual" => Self::Virtual,
            _ => {
                if lower.contains("usb") {
                    Self::Usb
                } else if lower.contains("bluetooth") {
                    Self::Bluetooth
                } else if lower.contains("internal") || lower.contains("built") {
                    Self::Internal
                } else {
                    Self::Unknown
                }
            }
        }
    }

    pub fn from_linux_phys(phys: Option<&str>) -> Self {
        match phys {
            None | Some("") => Self::Virtual,
            Some(p) => {
                let lower = p.to_lowercase();
                if lower.starts_with("usb-") || lower.contains("/usb") {
                    Self::Usb
                } else if lower.starts_with("bluetooth") || lower.contains("/bluetooth") {
                    Self::Bluetooth
                } else if lower.starts_with("isa0060")
                    || lower.starts_with("i8042")
                    || lower.starts_with("serio")
                    || lower.starts_with("spi")
                    || lower.starts_with("i2c")
                {
                    Self::Internal
                } else if lower.contains("adb") {
                    Self::Adb
                } else if lower.contains("virtual") || lower.contains("uinput") {
                    Self::Virtual
                } else {
                    Self::Unknown
                }
            }
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::Bluetooth => "bluetooth",
            Self::Internal => "internal",
            Self::Adb => "adb",
            Self::Virtual => "virtual",
            Self::Unknown => "unknown",
        }
    }

    pub fn to_source_type(&self) -> &'static str {
        match self {
            Self::Usb => "keyboard.usb",
            Self::Bluetooth => "keyboard.bluetooth",
            Self::Internal => "keyboard.internal",
            Self::Adb => "keyboard.adb",
            Self::Virtual => "keyboard.virtual",
            Self::Unknown => "keyboard",
        }
    }

    pub fn is_physical(&self) -> bool {
        !matches!(self, Self::Virtual)
    }
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Connected HID keyboard device metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HidDeviceInfo {
    pub vendor_id: u32,
    pub product_id: u32,
    pub product_name: String,
    pub manufacturer: String,
    pub serial_number: Option<String>,
    pub transport: String,
}

impl HidDeviceInfo {
    pub fn appears_virtual(&self) -> bool {
        self.vendor_id == 0
            || self.product_id == 0
            || self.product_name.to_lowercase().contains("virtual")
            || self.product_name.to_lowercase().contains("uinput")
            || self.manufacturer.to_lowercase().contains("virtual")
    }

    pub fn transport_type(&self) -> TransportType {
        TransportType::from_macos_transport(&self.transport)
    }

    pub fn fingerprint(&self) -> String {
        match &self.serial_number {
            Some(serial) => format!("{:04x}:{:04x}:{}", self.vendor_id, self.product_id, serial),
            None => format!("{:04x}:{:04x}", self.vendor_id, self.product_id),
        }
    }
}
