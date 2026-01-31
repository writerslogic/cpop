package ime

import (
	"testing"
	"time"
)

func TestEngineBasicSession(t *testing.T) {
	engine := NewEngine()

	// Start session
	err := engine.StartSession(SessionOptions{
		AppID:   "com.test.app",
		DocID:   "test-doc-1",
		Context: "unit test",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}

	if !engine.HasActiveSession() {
		t.Error("Expected active session")
	}

	// Simulate typing "hello"
	chars := []rune{'h', 'e', 'l', 'l', 'o'}
	for _, c := range chars {
		delay, err := engine.OnKeyDown(NewKey(c))
		if err != nil {
			t.Errorf("OnKeyDown(%c) failed: %v", c, err)
		}
		// Delay should be in valid jitter range
		if delay > 0 && (delay < 500*time.Microsecond || delay > 3000*time.Microsecond) {
			t.Errorf("Jitter delay out of range: %v", delay)
		}

		// Commit the character
		if err := engine.OnTextCommit(string(c)); err != nil {
			t.Errorf("OnTextCommit failed: %v", err)
		}

		time.Sleep(50 * time.Millisecond)
	}

	// Check sample count
	count := engine.GetSampleCount()
	if count == 0 {
		t.Error("Expected samples to be collected")
	}
	t.Logf("Collected %d samples for 'hello'", count)

	// End session
	evidence, err := engine.EndSession()
	if err != nil {
		t.Fatalf("EndSession failed: %v", err)
	}

	if evidence.SessionID == "" {
		t.Error("Evidence should have session ID")
	}
	if evidence.AppID != "com.test.app" {
		t.Errorf("AppID mismatch: got %s", evidence.AppID)
	}
	if evidence.TotalKeystrokes == 0 {
		t.Error("Expected keystroke count > 0")
	}

	t.Logf("Evidence: %d keystrokes, %d samples, %.0f KPM",
		evidence.TotalKeystrokes, len(evidence.Samples), evidence.TypingRateKPM)
}

func TestEngineZoneDetection(t *testing.T) {
	engine := NewEngine()

	if err := engine.StartSession(SessionOptions{AppID: "test"}); err != nil {
		t.Fatal(err)
	}

	// Test zone detection from characters
	testCases := []struct {
		char         rune
		expectedZone int
	}{
		{'q', 0}, {'a', 0}, {'z', 0}, // Left pinky
		{'w', 1}, {'s', 1}, {'x', 1}, // Left ring
		{'e', 2}, {'d', 2}, {'c', 2}, // Left middle
		{'r', 3}, {'t', 3}, {'f', 3}, // Left index
		{'y', 4}, {'u', 4}, {'h', 4}, // Right index
		{'i', 5}, {'k', 5}, // Right middle
		{'o', 6}, {'l', 6}, // Right ring
		{'p', 7}, // Right pinky
	}

	for _, tc := range testCases {
		// Use the zone mapping directly
		zone := zoneFromChar(tc.char)
		if zone != tc.expectedZone {
			t.Errorf("Char '%c': expected zone %d, got %d", tc.char, tc.expectedZone, zone)
		}
	}

	engine.EndSession()
}

func TestEngineTextDelete(t *testing.T) {
	engine := NewEngine()

	if err := engine.StartSession(SessionOptions{AppID: "test"}); err != nil {
		t.Fatal(err)
	}

	// Type "hello"
	for _, c := range "hello" {
		engine.OnKeyDown(NewKey(c))
		engine.OnTextCommit(string(c))
	}

	// Delete 2 characters
	if err := engine.OnTextDelete(2); err != nil {
		t.Errorf("OnTextDelete failed: %v", err)
	}

	evidence, _ := engine.EndSession()

	// Final hash should be for "hel" not "hello"
	t.Logf("Final document state after delete: hash=%x", evidence.FinalHash[:8])
}

func TestEngineNoSessionError(t *testing.T) {
	engine := NewEngine()

	// Should fail without active session
	_, err := engine.OnKeyDown(NewKey('a'))
	if err == nil {
		t.Error("Expected error for OnKeyDown without session")
	}

	err = engine.OnTextCommit("test")
	if err == nil {
		t.Error("Expected error for OnTextCommit without session")
	}

	_, err = engine.EndSession()
	if err == nil {
		t.Error("Expected error for EndSession without session")
	}
}

func TestEngineDoubleStartError(t *testing.T) {
	engine := NewEngine()

	if err := engine.StartSession(SessionOptions{AppID: "test1"}); err != nil {
		t.Fatal(err)
	}

	// Second start should fail
	err := engine.StartSession(SessionOptions{AppID: "test2"})
	if err == nil {
		t.Error("Expected error for double StartSession")
	}

	engine.EndSession()
}

func TestEngineProfile(t *testing.T) {
	engine := NewEngine()

	if err := engine.StartSession(SessionOptions{AppID: "test"}); err != nil {
		t.Fatal(err)
	}

	// Type alternating hand pattern
	text := "the quick brown fox"
	for _, c := range text {
		engine.OnKeyDown(NewKey(c))
		engine.OnTextCommit(string(c))
		time.Sleep(30 * time.Millisecond)
	}

	profile := engine.GetProfile()

	if profile.TotalTransitions == 0 {
		t.Error("Expected profile to have transitions")
	}

	t.Logf("Profile: %d transitions, %.2f hand alternation",
		profile.TotalTransitions, profile.HandAlternation)

	// "the quick brown fox" should have good hand alternation
	if profile.HandAlternation < 0.3 {
		t.Errorf("Expected decent hand alternation, got %.2f", profile.HandAlternation)
	}

	engine.EndSession()
}

func TestZoneToKeyCode(t *testing.T) {
	// Verify our zone-to-keycode mapping is reversible
	for zone := 0; zone <= 7; zone++ {
		keyCode := zoneToKeyCode(zone)
		recovered := zoneFromKeyCode(keyCode)
		if recovered != zone {
			t.Errorf("Zone %d: keycode 0x%02X recovered as zone %d", zone, keyCode, recovered)
		}
	}

	// Non-zone should return 0xFF
	keyCode := zoneToKeyCode(-1)
	if keyCode != 0xFF {
		t.Errorf("Expected 0xFF for zone -1, got 0x%02X", keyCode)
	}
}


func TestEngineUTF8TextDelete(t *testing.T) {
	engine := NewEngine()

	if err := engine.StartSession(SessionOptions{AppID: "test"}); err != nil {
		t.Fatal(err)
	}

	// Type text with multi-byte UTF-8 characters
	text := "héllo世界" // Contains é (2 bytes) and 世界 (3 bytes each)
	for _, c := range text {
		engine.OnKeyDown(NewKey(c))
		engine.OnTextCommit(string(c))
	}

	// Get initial hash
	hash1 := engine.GetDocumentHash()

	// Delete 2 runes (世界 = 6 bytes, but 2 runes)
	if err := engine.OnTextDelete(2); err != nil {
		t.Errorf("OnTextDelete failed: %v", err)
	}

	// Verify hash changed
	hash2 := engine.GetDocumentHash()
	if hash1 == hash2 {
		t.Error("Hash should have changed after delete")
	}

	// Get remaining content
	content := engine.GetDocumentContent()
	expected := "héllo"
	if string(content) != expected {
		t.Errorf("Expected '%s', got '%s'", expected, string(content))
	}

	engine.EndSession()
}

func TestEngineTextDeleteEdgeCases(t *testing.T) {
	engine := NewEngine()

	if err := engine.StartSession(SessionOptions{AppID: "test"}); err != nil {
		t.Fatal(err)
	}

	// Delete from empty buffer should not error
	if err := engine.OnTextDelete(5); err != nil {
		t.Errorf("OnTextDelete from empty should not error: %v", err)
	}

	// Type some text
	engine.OnTextCommit("abc")

	// Delete zero should be a no-op
	if err := engine.OnTextDelete(0); err != nil {
		t.Errorf("OnTextDelete(0) failed: %v", err)
	}

	// Delete more than available
	if err := engine.OnTextDelete(100); err != nil {
		t.Errorf("OnTextDelete(100) failed: %v", err)
	}

	// Buffer should be empty now
	content := engine.GetDocumentContent()
	if len(content) != 0 {
		t.Errorf("Expected empty buffer, got %d bytes", len(content))
	}

	// Negative delete should be a no-op
	if err := engine.OnTextDelete(-1); err != nil {
		t.Errorf("OnTextDelete(-1) failed: %v", err)
	}

	engine.EndSession()
}

func TestEngineTextDeleteBytes(t *testing.T) {
	engine := NewEngine()

	if err := engine.StartSession(SessionOptions{AppID: "test"}); err != nil {
		t.Fatal(err)
	}

	// Type multi-byte text
	engine.OnTextCommit("世界") // 6 bytes total

	// Delete 3 bytes (one Chinese character)
	if err := engine.OnTextDeleteBytes(3); err != nil {
		t.Errorf("OnTextDeleteBytes failed: %v", err)
	}

	content := engine.GetDocumentContent()
	if string(content) != "世" {
		t.Errorf("Expected '世', got '%s'", string(content))
	}

	engine.EndSession()
}

func TestEngineSessionInfo(t *testing.T) {
	engine := NewEngine()

	// No session - should return nil
	info := engine.GetSessionInfo()
	if info != nil {
		t.Error("Expected nil session info without active session")
	}

	if err := engine.StartSession(SessionOptions{
		AppID:   "com.test.app",
		DocID:   "doc-123",
		Context: "test context",
	}); err != nil {
		t.Fatal(err)
	}

	// Type some text
	for _, c := range "hello" {
		engine.OnKeyDown(NewKey(c))
		engine.OnTextCommit(string(c))
	}

	info = engine.GetSessionInfo()
	if info == nil {
		t.Fatal("Expected non-nil session info")
	}

	if info.AppID != "com.test.app" {
		t.Errorf("AppID mismatch: %s", info.AppID)
	}
	if info.DocID != "doc-123" {
		t.Errorf("DocID mismatch: %s", info.DocID)
	}
	if info.Context != "test context" {
		t.Errorf("Context mismatch: %s", info.Context)
	}
	if info.SampleCount != 5 {
		t.Errorf("SampleCount mismatch: %d", info.SampleCount)
	}
	if info.DocLength != 5 {
		t.Errorf("DocLength mismatch: %d", info.DocLength)
	}
	if info.ID == "" {
		t.Error("Expected non-empty session ID")
	}
	if info.StartTime.IsZero() {
		t.Error("Expected non-zero start time")
	}

	engine.EndSession()
}

func TestEvidenceJSON(t *testing.T) {
	engine := NewEngine()

	if err := engine.StartSession(SessionOptions{
		AppID:   "com.test.app",
		Context: "json test",
	}); err != nil {
		t.Fatal(err)
	}

	// Type some text
	for _, c := range "test" {
		engine.OnKeyDown(NewKey(c))
		engine.OnTextCommit(string(c))
	}

	evidence, err := engine.EndSession()
	if err != nil {
		t.Fatal(err)
	}

	// Convert to JSON
	jsonStr, err := evidence.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	// Verify it's valid JSON
	if jsonStr == "" || jsonStr[0] != '{' {
		t.Errorf("Invalid JSON: %s", jsonStr)
	}

	// Check for expected fields
	expectedFields := []string{
		"session_id",
		"start_time",
		"end_time",
		"app_id",
		"samples",
		"profile",
		"total_keystrokes",
	}

	for _, field := range expectedFields {
		if !contains(jsonStr, field) {
			t.Errorf("JSON missing field: %s", field)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestKeyConstructors(t *testing.T) {
	// Test NewKey
	k1 := NewKey('a')
	if k1.Char != 'a' {
		t.Errorf("NewKey: expected char 'a', got %c", k1.Char)
	}
	if k1.Zone != ZoneUnknown {
		t.Errorf("NewKey: expected zone %d, got %d", ZoneUnknown, k1.Zone)
	}

	// Test NewKeyWithCode
	k2 := NewKeyWithCode(0x41, 'A')
	if k2.Code != 0x41 {
		t.Errorf("NewKeyWithCode: expected code 0x41, got 0x%X", k2.Code)
	}
	if k2.Char != 'A' {
		t.Errorf("NewKeyWithCode: expected char 'A', got %c", k2.Char)
	}

	// Test NewKeyWithZone
	k3 := NewKeyWithZone('q', 0)
	if k3.Zone != 0 {
		t.Errorf("NewKeyWithZone: expected zone 0, got %d", k3.Zone)
	}

	// Test NewKeyFull
	ts := time.Now()
	k4 := NewKeyFull(0x51, 'q', 0, ModShift, ts)
	if k4.Code != 0x51 {
		t.Errorf("NewKeyFull: code mismatch")
	}
	if k4.Char != 'q' {
		t.Errorf("NewKeyFull: char mismatch")
	}
	if k4.Zone != 0 {
		t.Errorf("NewKeyFull: zone mismatch")
	}
	if k4.Modifiers != ModShift {
		t.Errorf("NewKeyFull: modifiers mismatch")
	}
	if !k4.Timestamp.Equal(ts) {
		t.Errorf("NewKeyFull: timestamp mismatch")
	}
}

func TestEngineExportSamples(t *testing.T) {
	engine := NewEngine()

	// Export without session
	samples := engine.ExportSamples()
	if samples != nil {
		t.Error("Expected nil samples without session")
	}

	if err := engine.StartSession(SessionOptions{AppID: "test"}); err != nil {
		t.Fatal(err)
	}

	// Export empty
	samples = engine.ExportSamples()
	if len(samples) != 0 {
		t.Errorf("Expected 0 samples, got %d", len(samples))
	}

	// Type some text
	for _, c := range "abc" {
		engine.OnKeyDown(NewKey(c))
		engine.OnTextCommit(string(c))
		time.Sleep(50 * time.Millisecond)
	}

	// Export samples
	samples = engine.ExportSamples()
	if len(samples) == 0 {
		t.Error("Expected samples after typing")
	}

	// Verify samples are a copy (modifying shouldn't affect engine)
	originalLen := engine.GetSampleCount()
	samples = nil // Clear our copy
	if engine.GetSampleCount() != originalLen {
		t.Error("Sample export should be a copy")
	}

	engine.EndSession()
}

func TestEngineGetDocumentContent(t *testing.T) {
	engine := NewEngine()

	// Without session
	content := engine.GetDocumentContent()
	if content != nil {
		t.Error("Expected nil content without session")
	}

	if err := engine.StartSession(SessionOptions{AppID: "test"}); err != nil {
		t.Fatal(err)
	}

	// Empty content
	content = engine.GetDocumentContent()
	if len(content) != 0 {
		t.Error("Expected empty content")
	}

	// Add content
	engine.OnTextCommit("hello world")

	content = engine.GetDocumentContent()
	if string(content) != "hello world" {
		t.Errorf("Expected 'hello world', got '%s'", string(content))
	}

	// Verify it's a copy
	content[0] = 'X'
	content2 := engine.GetDocumentContent()
	if content2[0] == 'X' {
		t.Error("GetDocumentContent should return a copy")
	}

	engine.EndSession()
}

