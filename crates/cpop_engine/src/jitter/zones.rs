// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! QWERTY keyboard zone mapping and zone transition types.

/// Map a macOS virtual key code to a QWERTY keyboard zone (0..7), or -1 if unmapped.
pub fn keycode_to_zone(key_code: u16) -> i32 {
    match key_code {
        0x0C | 0x00 | 0x06 => 0,
        0x0D | 0x01 | 0x07 => 1,
        0x0E | 0x02 | 0x08 => 2,
        0x0F | 0x11 | 0x03 | 0x05 | 0x09 | 0x0B => 3,
        0x10 | 0x20 | 0x04 | 0x26 | 0x2D | 0x2E => 4,
        0x22 | 0x28 | 0x2B => 5,
        0x1F | 0x25 | 0x2F => 6,
        0x23 | 0x29 | 0x2C => 7,
        _ => -1,
    }
}

/// Map a character to a QWERTY keyboard zone (0..7), or -1 if unmapped.
pub fn char_to_zone(c: char) -> i32 {
    match c {
        'q' | 'Q' | 'a' | 'A' | 'z' | 'Z' => 0,
        'w' | 'W' | 's' | 'S' | 'x' | 'X' => 1,
        'e' | 'E' | 'd' | 'D' | 'c' | 'C' => 2,
        'r' | 'R' | 't' | 'T' | 'f' | 'F' | 'g' | 'G' | 'v' | 'V' | 'b' | 'B' => 3,
        'y' | 'Y' | 'u' | 'U' | 'h' | 'H' | 'j' | 'J' | 'n' | 'N' | 'm' | 'M' => 4,
        'i' | 'I' | 'k' | 'K' | ',' | '<' => 5,
        'o' | 'O' | 'l' | 'L' | '.' | '>' => 6,
        'p' | 'P' | ';' | ':' | '/' | '?' => 7,
        _ => -1,
    }
}

/// Pack a zone transition into a single byte (from << 3 | to), or 0xFF if invalid.
pub fn encode_zone_transition(from: i32, to: i32) -> u8 {
    if !(0..=7).contains(&from) || !(0..=7).contains(&to) {
        return 0xFF;
    }
    ((from << 3) | to) as u8
}

/// Unpack a zone transition byte into (from, to) zone indices.
pub fn decode_zone_transition(encoded: u8) -> (i32, i32) {
    let from = ((encoded >> 3) & 0x07) as i32;
    let to = (encoded & 0x07) as i32;
    (from, to)
}

/// Return true if the encoded byte represents a valid zone transition.
pub fn is_valid_zone_transition(encoded: u8) -> bool {
    encoded != 0xFF && (encoded >> 3) < 8
}

/// Convert a text string into a sequence of consecutive zone transitions.
pub fn text_to_zone_sequence(text: &str) -> Vec<ZoneTransition> {
    let mut transitions = Vec::with_capacity(text.len());
    let mut prev_zone = -1;
    for c in text.chars() {
        let zone = char_to_zone(c);
        if zone >= 0 {
            if prev_zone >= 0 {
                transitions.push(ZoneTransition {
                    from: prev_zone,
                    to: zone,
                });
            }
            prev_zone = zone;
        }
    }
    transitions
}

/// A transition between two QWERTY keyboard zones.
#[derive(Debug, Clone, Copy)]
pub struct ZoneTransition {
    /// Source zone index (0..7).
    pub from: i32,
    /// Destination zone index (0..7).
    pub to: i32,
}

impl ZoneTransition {
    /// Return true if both zones are the same (same finger repeat).
    pub fn is_same_finger(&self) -> bool {
        self.from == self.to
    }

    /// Return true if both zones belong to the same hand.
    pub fn is_same_hand(&self) -> bool {
        (self.from < 4) == (self.to < 4)
    }

    /// Return true if the transition crosses from one hand to the other.
    pub fn is_alternating(&self) -> bool {
        !self.is_same_hand()
    }
}
