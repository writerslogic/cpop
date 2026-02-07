//go:build windows

package main

import (
	"encoding/json"
	"testing"
	"time"
)

// TestIPCMessageSerialization tests IPC message JSON serialization.
func TestIPCMessageSerialization(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
	}{
		{
			name: "keystroke message",
			msg: Message{
				Type:      MsgTypeKeystroke,
				Timestamp: time.Now().UnixNano(),
				Data:      json.RawMessage(`{"vk":65,"sc":30,"char":"a","down":true,"ts":1234567890}`),
			},
		},
		{
			name: "focus change message",
			msg: Message{
				Type:      MsgTypeFocusChange,
				Timestamp: time.Now().UnixNano(),
				Data:      json.RawMessage(`{"hwnd":12345,"pid":1000,"app_name":"notepad.exe"}`),
			},
		},
		{
			name: "session start message",
			msg: Message{
				Type:      MsgTypeSessionStart,
				Timestamp: time.Now().UnixNano(),
				Data:      json.RawMessage(`{"app_id":"test.app","doc_id":"test.doc"}`),
			},
		},
		{
			name: "heartbeat message",
			msg: Message{
				Type:      MsgTypeHeartbeat,
				Timestamp: time.Now().UnixNano(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize
			data, err := json.Marshal(tt.msg)
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}

			// Deserialize
			var msg Message
			err = json.Unmarshal(data, &msg)
			if err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}

			// Verify
			if msg.Type != tt.msg.Type {
				t.Errorf("Type = %q, want %q", msg.Type, tt.msg.Type)
			}
		})
	}
}

// TestKeystrokeMessageSerialization tests keystroke message serialization.
func TestKeystrokeMessageSerialization(t *testing.T) {
	ks := KeystrokeMessage{
		VirtualKey:  0x41, // A
		ScanCode:    0x1E,
		Character:   "a",
		IsKeyDown:   true,
		IsInjected:  false,
		Modifiers:   0x00,
		TimestampNs: time.Now().UnixNano(),
	}

	data, err := json.Marshal(ks)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var ks2 KeystrokeMessage
	err = json.Unmarshal(data, &ks2)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if ks2.VirtualKey != ks.VirtualKey {
		t.Errorf("VirtualKey = %#x, want %#x", ks2.VirtualKey, ks.VirtualKey)
	}
	if ks2.Character != ks.Character {
		t.Errorf("Character = %q, want %q", ks2.Character, ks.Character)
	}
	if ks2.IsKeyDown != ks.IsKeyDown {
		t.Errorf("IsKeyDown = %v, want %v", ks2.IsKeyDown, ks.IsKeyDown)
	}
}

// TestFocusChangeMessageSerialization tests focus change message serialization.
func TestFocusChangeMessageSerialization(t *testing.T) {
	fc := FocusChangeMessage{
		WindowHandle: 0x12345678,
		ProcessID:    1234,
		AppPath:      "C:\\Windows\\System32\\notepad.exe",
		AppName:      "notepad",
		WindowTitle:  "Untitled - Notepad",
		DocumentPath: "",
		TimestampNs:  time.Now().UnixNano(),
	}

	data, err := json.Marshal(fc)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var fc2 FocusChangeMessage
	err = json.Unmarshal(data, &fc2)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if fc2.AppName != fc.AppName {
		t.Errorf("AppName = %q, want %q", fc2.AppName, fc.AppName)
	}
	if fc2.WindowTitle != fc.WindowTitle {
		t.Errorf("WindowTitle = %q, want %q", fc2.WindowTitle, fc.WindowTitle)
	}
}

// TestRawKeystrokeFields tests RawKeystroke field handling.
func TestRawKeystrokeFields(t *testing.T) {
	ks := RawKeystroke{
		VirtualKey:  0x41,
		ScanCode:    0x1E,
		Flags:       0x00000000,
		SystemTime:  12345,
		Timestamp:   time.Now().UnixNano(),
		IsKeyDown:   true,
		IsInjected:  false,
		IsExtended:  false,
		IsAltDown:   false,
		Character:   'a',
		Modifiers:   0x00,
	}

	// Test character
	if ks.Character != 'a' {
		t.Errorf("Character = %q, want %q", ks.Character, 'a')
	}

	// Test flags
	if ks.IsInjected {
		t.Error("IsInjected should be false")
	}
	if ks.IsExtended {
		t.Error("IsExtended should be false")
	}
}

// TestFocusInfoExtraction tests extracting app/doc names from paths.
func TestFocusInfoExtraction(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"C:\\Windows\\System32\\notepad.exe", "notepad"},
		{"C:\\Program Files\\Microsoft VS Code\\Code.exe", "Code"},
		{"notepad.exe", "notepad"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := extractAppName(tt.path)
			if result != tt.expected {
				t.Errorf("extractAppName(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

// TestDocNameExtraction tests extracting document names from paths/titles.
func TestDocNameExtraction(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"C:\\Users\\test\\Documents\\file.txt", "file.txt"},
		{"file.txt", "file.txt"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := extractDocName(tt.path)
			if result != tt.expected {
				t.Errorf("extractDocName(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

// TestVirtualKeyNames tests virtual key name lookup.
func TestVirtualKeyNames(t *testing.T) {
	tests := []struct {
		vk   uint16
		name string
	}{
		{0x08, "Backspace"},
		{0x09, "Tab"},
		{0x0D, "Enter"},
		{0x10, "Shift"},
		{0x11, "Control"},
		{0x12, "Alt"},
		{0x1B, "Escape"},
		{0x20, "Space"},
		{0x25, "Left"},
		{0x26, "Up"},
		{0x27, "Right"},
		{0x28, "Down"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := GetKeyName(tt.vk)
			if name != tt.name {
				t.Errorf("GetKeyName(%#x) = %q, want %q", tt.vk, name, tt.name)
			}
		})
	}
}

// TestWellKnownApps tests the well-known application mappings.
func TestWellKnownApps(t *testing.T) {
	tests := []struct {
		class    string
		expected string
	}{
		{"Notepad", "Notepad"},
		{"Chrome_WidgetWin_1", "Google Chrome"},
		{"MozillaWindowClass", "Firefox"},
		{"ConsoleWindowClass", "Terminal"},
		{"OpusApp", "Microsoft Word"},
	}

	for _, tt := range tests {
		t.Run(tt.class, func(t *testing.T) {
			if name, ok := WellKnownApps[tt.class]; ok {
				if name != tt.expected {
					t.Errorf("WellKnownApps[%q] = %q, want %q", tt.class, name, tt.expected)
				}
			} else {
				t.Errorf("WellKnownApps[%q] not found", tt.class)
			}
		})
	}
}

// TestGetAppDisplayName tests getting human-readable app names.
func TestGetAppDisplayName(t *testing.T) {
	tests := []struct {
		name     string
		info     FocusInfo
		expected string
	}{
		{
			name: "known class",
			info: FocusInfo{
				WindowClass: "Notepad",
				AppName:     "notepad",
			},
			expected: "Notepad",
		},
		{
			name: "unknown class with app name",
			info: FocusInfo{
				WindowClass: "UnknownClass",
				AppName:     "myapp",
			},
			expected: "myapp",
		},
		{
			name: "fallback to class",
			info: FocusInfo{
				WindowClass: "SomeClass",
				AppName:     "",
			},
			expected: "SomeClass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetAppDisplayName(tt.info)
			if result != tt.expected {
				t.Errorf("GetAppDisplayName() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestIPCStatsInitial tests initial IPC statistics.
func TestIPCStatsInitial(t *testing.T) {
	client := NewIPCClient()

	stats := client.GetStats()

	if stats.Connected {
		t.Error("new client should not be connected")
	}
	if stats.MessagesSent != 0 {
		t.Errorf("MessagesSent = %d, want 0", stats.MessagesSent)
	}
	if stats.MessagesReceived != 0 {
		t.Errorf("MessagesReceived = %d, want 0", stats.MessagesReceived)
	}
}

// TestConfigMessage tests configuration message handling.
func TestConfigMessage(t *testing.T) {
	config := ConfigMessage{
		SampleInterval:   100,
		MinSamples:       50,
		RejectInjected:   true,
		TrackFocus:       true,
		AutoStartSession: true,
	}

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var config2 ConfigMessage
	err = json.Unmarshal(data, &config2)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if config2.SampleInterval != config.SampleInterval {
		t.Errorf("SampleInterval = %d, want %d", config2.SampleInterval, config.SampleInterval)
	}
	if config2.RejectInjected != config.RejectInjected {
		t.Errorf("RejectInjected = %v, want %v", config2.RejectInjected, config.RejectInjected)
	}
}

// BenchmarkMessageSerialization benchmarks message serialization.
func BenchmarkMessageSerialization(b *testing.B) {
	msg := Message{
		Type:      MsgTypeKeystroke,
		Timestamp: time.Now().UnixNano(),
		Data:      json.RawMessage(`{"vk":65,"sc":30,"char":"a","down":true}`),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(msg)
	}
}

// BenchmarkKeystrokeSerialization benchmarks keystroke serialization.
func BenchmarkKeystrokeSerialization(b *testing.B) {
	ks := KeystrokeMessage{
		VirtualKey:  0x41,
		ScanCode:    0x1E,
		Character:   "a",
		IsKeyDown:   true,
		Modifiers:   0x00,
		TimestampNs: time.Now().UnixNano(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(ks)
	}
}
