// Package jitter implements zone-committed cryptographic keystroke watermarking.
package jitter

// Zone assignments based on standard QWERTY touch-typing
// 0-3: left hand (pinky to index)
// 4-7: right hand (index to pinky)

// KeyCodeToZone maps macOS virtual key codes to zones.
// Returns -1 for non-zone keys (space, modifiers, numbers).
func KeyCodeToZone(keyCode uint16) int {
	switch keyCode {
	// Zone 0: Left pinky
	case 0x0C, 0x00, 0x06: // Q, A, Z
		return 0
	// Zone 1: Left ring
	case 0x0D, 0x01, 0x07: // W, S, X
		return 1
	// Zone 2: Left middle
	case 0x0E, 0x02, 0x08: // E, D, C
		return 2
	// Zone 3: Left index (including reach)
	case 0x0F, 0x11, 0x03, 0x05, 0x09, 0x0B: // R, T, F, G, V, B
		return 3
	// Zone 4: Right index (including reach)
	case 0x10, 0x20, 0x04, 0x26, 0x2D, 0x2E: // Y, U, H, J, N, M
		return 4
	// Zone 5: Right middle
	case 0x22, 0x28, 0x2B: // I, K, comma
		return 5
	// Zone 6: Right ring
	case 0x1F, 0x25, 0x2F: // O, L, period
		return 6
	// Zone 7: Right pinky
	case 0x23, 0x29, 0x2C: // P, semicolon, slash
		return 7
	default:
		return -1
	}
}

// CharToZone maps a character to expected zone (for verification).
// Returns -1 for non-zone characters (space, numbers, special).
func CharToZone(c rune) int {
	switch c {
	case 'q', 'Q', 'a', 'A', 'z', 'Z':
		return 0
	case 'w', 'W', 's', 'S', 'x', 'X':
		return 1
	case 'e', 'E', 'd', 'D', 'c', 'C':
		return 2
	case 'r', 'R', 't', 'T', 'f', 'F', 'g', 'G', 'v', 'V', 'b', 'B':
		return 3
	case 'y', 'Y', 'u', 'U', 'h', 'H', 'j', 'J', 'n', 'N', 'm', 'M':
		return 4
	case 'i', 'I', 'k', 'K', ',', '<':
		return 5
	case 'o', 'O', 'l', 'L', '.', '>':
		return 6
	case 'p', 'P', ';', ':', '/', '?':
		return 7
	default:
		return -1
	}
}

// EncodeZoneTransition packs from/to zones into a single byte.
// Format: (from << 3) | to (6 bits used, 8*8=64 possibilities)
func EncodeZoneTransition(from, to int) uint8 {
	if from < 0 || from > 7 || to < 0 || to > 7 {
		return 0xFF // Invalid marker
	}
	return uint8(from<<3) | uint8(to)
}

// DecodeZoneTransition unpacks a zone transition byte.
// Note: Caller should check for 0xFF (invalid marker) before calling.
// If 0xFF is passed, returns (31, 7) which is out of valid range (0-7).
func DecodeZoneTransition(encoded uint8) (from, to int) {
	from = int(encoded >> 3)
	to = int(encoded & 0x07)
	return
}

// IsValidZoneTransition returns true if the encoded value represents a valid transition.
func IsValidZoneTransition(encoded uint8) bool {
	return encoded != 0xFF && (encoded>>3) < 8
}

// TextToZoneSequence extracts the sequence of zone transitions from text.
// Only includes transitions between valid zone characters.
// Returns pairs of (fromZone, toZone) for each valid transition.
func TextToZoneSequence(text string) []ZoneTransition {
	var transitions []ZoneTransition
	prevZone := -1

	for _, c := range text {
		zone := CharToZone(c)
		if zone >= 0 {
			if prevZone >= 0 {
				transitions = append(transitions, ZoneTransition{
					From: prevZone,
					To:   zone,
				})
			}
			prevZone = zone
		}
		// Non-zone characters don't reset prevZone - we track letter-to-letter
	}

	return transitions
}

// ZoneTransition represents a transition between two keyboard zones.
type ZoneTransition struct {
	From int
	To   int
}

// IsSameFinger returns true if transition uses the same finger.
func (t ZoneTransition) IsSameFinger() bool {
	return t.From == t.To
}

// IsSameHand returns true if transition stays on the same hand.
func (t ZoneTransition) IsSameHand() bool {
	return (t.From < 4) == (t.To < 4)
}

// IsAlternating returns true if transition switches hands.
func (t ZoneTransition) IsAlternating() bool {
	return !t.IsSameHand()
}
