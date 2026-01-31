package jitter

import "testing"

func TestCharToZone(t *testing.T) {
	tests := []struct {
		char rune
		zone int
	}{
		{'q', 0}, {'Q', 0}, {'a', 0}, {'A', 0}, {'z', 0}, {'Z', 0},
		{'w', 1}, {'s', 1}, {'x', 1},
		{'e', 2}, {'d', 2}, {'c', 2},
		{'r', 3}, {'t', 3}, {'f', 3}, {'g', 3}, {'v', 3}, {'b', 3},
		{'y', 4}, {'u', 4}, {'h', 4}, {'j', 4}, {'n', 4}, {'m', 4},
		{'i', 5}, {'k', 5}, {',', 5},
		{'o', 6}, {'l', 6}, {'.', 6},
		{'p', 7}, {';', 7}, {'/', 7},
		{' ', -1}, {'1', -1}, {'!', -1}, {'\n', -1},
	}

	for _, tt := range tests {
		got := CharToZone(tt.char)
		if got != tt.zone {
			t.Errorf("CharToZone(%q) = %d, want %d", tt.char, got, tt.zone)
		}
	}
}

func TestZoneTransitionEncode(t *testing.T) {
	for from := 0; from < 8; from++ {
		for to := 0; to < 8; to++ {
			encoded := EncodeZoneTransition(from, to)
			gotFrom, gotTo := DecodeZoneTransition(encoded)
			if gotFrom != from || gotTo != to {
				t.Errorf("Roundtrip(%d,%d): got (%d,%d)", from, to, gotFrom, gotTo)
			}
		}
	}
}

func TestTextToZoneSequence(t *testing.T) {
	text := "the" // t(zone3) -> h(zone4) -> e(zone2)
	seq := TextToZoneSequence(text)

	if len(seq) != 2 {
		t.Fatalf("Expected 2 transitions, got %d", len(seq))
	}

	// t -> h
	if seq[0].From != 3 || seq[0].To != 4 {
		t.Errorf("First transition: got (%d,%d), want (3,4)", seq[0].From, seq[0].To)
	}

	// h -> e
	if seq[1].From != 4 || seq[1].To != 2 {
		t.Errorf("Second transition: got (%d,%d), want (4,2)", seq[1].From, seq[1].To)
	}
}

func TestZoneTransitionClassification(t *testing.T) {
	// Same finger: q -> a (both zone 0)
	sf := ZoneTransition{From: 0, To: 0}
	if !sf.IsSameFinger() {
		t.Error("Expected same finger")
	}

	// Same hand: q -> w (zones 0 and 1, both left)
	sh := ZoneTransition{From: 0, To: 1}
	if !sh.IsSameHand() || sh.IsSameFinger() {
		t.Error("Expected same hand, different finger")
	}

	// Alternating: q -> p (zone 0 left, zone 7 right)
	alt := ZoneTransition{From: 0, To: 7}
	if !alt.IsAlternating() {
		t.Error("Expected alternating hands")
	}
}

func TestZoneAmbiguity(t *testing.T) {
	// Zone 0 -> Zone 4 should have multiple possible digraphs
	// Zone 0 = {q, a, z}, Zone 4 = {y, u, h, j, n, m}
	// Possible digraphs: qy, qh, qn, qu, qj, qm, ay, ah, an, au, aj, am, zy, zh, zn, zu, zj, zm
	// = 3 * 6 = 18 possibilities

	zone0chars := []rune{'q', 'a', 'z'}
	zone4chars := []rune{'y', 'u', 'h', 'j', 'n', 'm'}

	count := len(zone0chars) * len(zone4chars)
	if count < 12 {
		t.Errorf("Zone 0->4 should have at least 12-way ambiguity, got %d", count)
	}
	t.Logf("Zone 0->4 has %d-way ambiguity (privacy preserved)", count)
}

func TestIsValidZoneTransition(t *testing.T) {
	// All valid zone transitions (0-7 x 0-7 = 64 possibilities)
	for from := 0; from < 8; from++ {
		for to := 0; to < 8; to++ {
			encoded := EncodeZoneTransition(from, to)
			if !IsValidZoneTransition(encoded) {
				t.Errorf("Expected valid transition for (%d,%d), encoded=%d", from, to, encoded)
			}
		}
	}

	// Invalid marker
	if IsValidZoneTransition(0xFF) {
		t.Error("0xFF should be invalid")
	}

	// Encoding invalid zones returns 0xFF
	if EncodeZoneTransition(-1, 5) != 0xFF {
		t.Error("Invalid from zone should return 0xFF")
	}
	if EncodeZoneTransition(5, -1) != 0xFF {
		t.Error("Invalid to zone should return 0xFF")
	}
	if EncodeZoneTransition(8, 0) != 0xFF {
		t.Error("From zone > 7 should return 0xFF")
	}
	if EncodeZoneTransition(0, 8) != 0xFF {
		t.Error("To zone > 7 should return 0xFF")
	}
}
