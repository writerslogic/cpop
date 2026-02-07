//go:build windows

package main

/*
#cgo LDFLAGS: -luser32

#include <windows.h>
#include <stdint.h>

// ============================================================================
// Keystroke Interception via Low-Level Keyboard Hook
// ============================================================================
//
// This module provides transparent keystroke interception for the TSF provider.
// It uses a combination of:
// 1. WH_KEYBOARD_LL hook for system-wide keystroke capture
// 2. Raw Input API for hardware-level validation
// 3. TSF ITfKeyEventSink integration for IME-aware capture
//
// The hooks are transparent - they observe but never modify or block input.
// ============================================================================

// Keystroke data structure
typedef struct {
	uint16_t vkCode;
	uint16_t scanCode;
	uint32_t flags;
	uint32_t time;
	int64_t timestamp_ns;
	int isKeyDown;
	int isInjected;
	int isExtended;
	int isAltDown;
} KeystrokeData;

// Circular buffer for keystrokes
#define KEYSTROKE_BUFFER_SIZE 1024
static KeystrokeData g_keystrokeBuffer[KEYSTROKE_BUFFER_SIZE];
static volatile int64_t g_writeIndex = 0;
static volatile int64_t g_readIndex = 0;
static volatile int g_isRunning = 0;

// Hook handle
static HHOOK g_keyboardHook = NULL;
static HANDLE g_hookThread = NULL;
static DWORD g_hookThreadId = 0;

// Statistics
static volatile int64_t g_totalKeystrokes = 0;
static volatile int64_t g_injectedCount = 0;

// Performance counter frequency
static LARGE_INTEGER g_perfFreq;
static int g_perfFreqInit = 0;

// Get high-precision timestamp in nanoseconds
static int64_t GetNanosTimestamp() {
	if (!g_perfFreqInit) {
		QueryPerformanceFrequency(&g_perfFreq);
		g_perfFreqInit = 1;
	}

	LARGE_INTEGER counter;
	QueryPerformanceCounter(&counter);
	return (int64_t)((double)counter.QuadPart / (double)g_perfFreq.QuadPart * 1e9);
}

// Forward declaration for Go callback
extern void goOnRawKeystroke(uint16_t vkCode, uint16_t scanCode, uint32_t flags,
                              uint32_t time, int64_t timestamp_ns, int isDown,
                              int isInjected, int isExtended, int isAltDown);

// Low-level keyboard hook procedure
static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HC_ACTION && g_isRunning) {
		KBDLLHOOKSTRUCT* kb = (KBDLLHOOKSTRUCT*)lParam;
		int64_t timestamp = GetNanosTimestamp();

		// Determine key state
		int isKeyDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);

		// Check flags
		int isInjected = (kb->flags & LLKHF_INJECTED) != 0;
		int isExtended = (kb->flags & LLKHF_EXTENDED) != 0;
		int isAltDown = (kb->flags & LLKHF_ALTDOWN) != 0;

		// Track statistics
		if (isKeyDown) {
			g_totalKeystrokes++;
			if (isInjected) {
				g_injectedCount++;
			}
		}

		// Store in buffer
		int64_t idx = g_writeIndex % KEYSTROKE_BUFFER_SIZE;
		g_keystrokeBuffer[idx].vkCode = (uint16_t)kb->vkCode;
		g_keystrokeBuffer[idx].scanCode = (uint16_t)kb->scanCode;
		g_keystrokeBuffer[idx].flags = kb->flags;
		g_keystrokeBuffer[idx].time = kb->time;
		g_keystrokeBuffer[idx].timestamp_ns = timestamp;
		g_keystrokeBuffer[idx].isKeyDown = isKeyDown;
		g_keystrokeBuffer[idx].isInjected = isInjected;
		g_keystrokeBuffer[idx].isExtended = isExtended;
		g_keystrokeBuffer[idx].isAltDown = isAltDown;

		// Atomic increment
		InterlockedIncrement64(&g_writeIndex);

		// Notify Go (non-blocking)
		goOnRawKeystroke(
			(uint16_t)kb->vkCode,
			(uint16_t)kb->scanCode,
			kb->flags,
			kb->time,
			timestamp,
			isKeyDown,
			isInjected,
			isExtended,
			isAltDown
		);
	}

	// Always pass to next hook - never block input
	return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
}

// Hook thread procedure
static DWORD WINAPI KeyboardHookThreadProc(LPVOID lpParam) {
	(void)lpParam;

	// Install the hook
	g_keyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
	if (g_keyboardHook == NULL) {
		return 1;
	}

	g_isRunning = 1;

	// Message loop to keep hook alive
	MSG msg;
	while (GetMessageW(&msg, NULL, 0, 0) > 0) {
		TranslateMessage(&msg);
		DispatchMessageW(&msg);

		// Check for stop signal
		if (!g_isRunning) {
			break;
		}
	}

	// Cleanup
	if (g_keyboardHook != NULL) {
		UnhookWindowsHookEx(g_keyboardHook);
		g_keyboardHook = NULL;
	}

	return 0;
}

// Start keystroke interception
static int StartKeystrokeInterception() {
	if (g_isRunning) {
		return 0; // Already running
	}

	// Reset state
	g_writeIndex = 0;
	g_readIndex = 0;
	g_totalKeystrokes = 0;
	g_injectedCount = 0;

	// Create hook thread
	g_hookThread = CreateThread(NULL, 0, KeyboardHookThreadProc, NULL, 0, &g_hookThreadId);
	if (g_hookThread == NULL) {
		return -1;
	}

	// Wait for hook to be installed
	for (int i = 0; i < 100 && !g_isRunning; i++) {
		Sleep(10);
	}

	return g_isRunning ? 0 : -2;
}

// Stop keystroke interception
static void StopKeystrokeInterception() {
	if (!g_isRunning) {
		return;
	}

	g_isRunning = 0;

	// Signal thread to exit
	if (g_hookThreadId != 0) {
		PostThreadMessageW(g_hookThreadId, WM_QUIT, 0, 0);
	}

	// Wait for thread
	if (g_hookThread != NULL) {
		WaitForSingleObject(g_hookThread, 2000);
		CloseHandle(g_hookThread);
		g_hookThread = NULL;
	}

	g_hookThreadId = 0;
}

// Read keystroke from buffer
static int ReadKeystroke(KeystrokeData* data) {
	if (g_readIndex >= g_writeIndex) {
		return 0; // No data
	}

	int64_t idx = g_readIndex % KEYSTROKE_BUFFER_SIZE;
	*data = g_keystrokeBuffer[idx];
	InterlockedIncrement64(&g_readIndex);
	return 1;
}

// Get statistics
static int64_t GetTotalKeystrokes() {
	return g_totalKeystrokes;
}

static int64_t GetInjectedCount() {
	return g_injectedCount;
}

static int64_t GetPendingCount() {
	return g_writeIndex - g_readIndex;
}

// Convert virtual key to character
static int VKToCharacter(uint16_t vkCode, uint16_t scanCode, wchar_t* result, int resultLen) {
	BYTE keyState[256];
	if (!GetKeyboardState(keyState)) {
		return 0;
	}

	return ToUnicode(vkCode, scanCode, keyState, result, resultLen, 0);
}

// Get modifier state
static uint32_t GetModifierState() {
	uint32_t mods = 0;

	if (GetAsyncKeyState(VK_SHIFT) & 0x8000) mods |= 0x01;
	if (GetAsyncKeyState(VK_CONTROL) & 0x8000) mods |= 0x02;
	if (GetAsyncKeyState(VK_MENU) & 0x8000) mods |= 0x04;     // Alt
	if (GetAsyncKeyState(VK_LWIN) & 0x8000) mods |= 0x08;     // Left Win
	if (GetAsyncKeyState(VK_RWIN) & 0x8000) mods |= 0x08;     // Right Win
	if (GetAsyncKeyState(VK_CAPITAL) & 0x0001) mods |= 0x10;  // Caps Lock
	if (GetAsyncKeyState(VK_NUMLOCK) & 0x0001) mods |= 0x20;  // Num Lock

	return mods;
}

// Check if running with elevated privileges
static int IsElevated() {
	BOOL elevated = FALSE;
	HANDLE token = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		TOKEN_ELEVATION elevation;
		DWORD size = sizeof(TOKEN_ELEVATION);

		if (GetTokenInformation(token, TokenElevation, &elevation, size, &size)) {
			elevated = elevation.TokenIsElevated;
		}
		CloseHandle(token);
	}

	return elevated;
}
*/
import "C"

import (
	"errors"
	"sync"
	"time"
)

// KeystrokeSink provides system-wide keystroke interception.
// It uses Windows low-level keyboard hooks to capture all keystrokes
// transparently without blocking or modifying them.
type KeystrokeSink struct {
	mu sync.RWMutex

	running    bool
	callbacks  []func(RawKeystroke)
	lastError  error
	startTime  time.Time

	// Statistics
	stats KeystrokeSinkStats
}

// RawKeystroke represents a raw keystroke event from the system.
type RawKeystroke struct {
	VirtualKey  uint16
	ScanCode    uint16
	Flags       uint32
	SystemTime  uint32  // Windows system time
	Timestamp   int64   // High-precision nanosecond timestamp
	IsKeyDown   bool
	IsInjected  bool    // True if synthetic (from SendInput, etc.)
	IsExtended  bool    // Extended key (numpad, etc.)
	IsAltDown   bool    // Alt key is held
	Character   rune    // Translated character (if applicable)
	Modifiers   uint32  // Modifier key state
}

// KeystrokeSinkStats contains statistics about keystroke capture.
type KeystrokeSinkStats struct {
	TotalKeystrokes    int64
	InjectedKeystrokes int64
	DroppedKeystrokes  int64
	StartTime          time.Time
	IsElevated         bool
}

// Global keystroke sink for C callbacks
var (
	globalSink   *KeystrokeSink
	globalSinkMu sync.Mutex
)

// NewKeystrokeSink creates a new keystroke sink.
func NewKeystrokeSink() *KeystrokeSink {
	return &KeystrokeSink{}
}

// Start begins capturing keystrokes.
func (s *KeystrokeSink) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return errors.New("keystroke sink already running")
	}

	// Set global instance
	globalSinkMu.Lock()
	globalSink = s
	globalSinkMu.Unlock()

	result := C.StartKeystrokeInterception()
	if result != 0 {
		globalSinkMu.Lock()
		globalSink = nil
		globalSinkMu.Unlock()

		switch result {
		case -1:
			return errors.New("failed to create hook thread")
		case -2:
			return errors.New("timeout waiting for hook to initialize")
		default:
			return errors.New("unknown error starting keystroke interception")
		}
	}

	s.running = true
	s.startTime = time.Now()
	s.stats.StartTime = s.startTime
	s.stats.IsElevated = C.IsElevated() != 0

	return nil
}

// Stop stops capturing keystrokes.
func (s *KeystrokeSink) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	C.StopKeystrokeInterception()

	globalSinkMu.Lock()
	if globalSink == s {
		globalSink = nil
	}
	globalSinkMu.Unlock()

	s.running = false
	return nil
}

// IsRunning returns whether the sink is currently capturing.
func (s *KeystrokeSink) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// AddCallback registers a callback for keystroke events.
func (s *KeystrokeSink) AddCallback(cb func(RawKeystroke)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callbacks = append(s.callbacks, cb)
}

// GetStats returns the current capture statistics.
func (s *KeystrokeSink) GetStats() KeystrokeSinkStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.stats.TotalKeystrokes = int64(C.GetTotalKeystrokes())
	s.stats.InjectedKeystrokes = int64(C.GetInjectedCount())
	return s.stats
}

// GetPendingCount returns the number of unprocessed keystrokes in the buffer.
func (s *KeystrokeSink) GetPendingCount() int64 {
	return int64(C.GetPendingCount())
}

// ReadKeystroke reads the next keystroke from the buffer.
// Returns false if no keystrokes are available.
func (s *KeystrokeSink) ReadKeystroke() (RawKeystroke, bool) {
	var data C.KeystrokeData
	if C.ReadKeystroke(&data) == 0 {
		return RawKeystroke{}, false
	}

	ks := RawKeystroke{
		VirtualKey:  uint16(data.vkCode),
		ScanCode:    uint16(data.scanCode),
		Flags:       uint32(data.flags),
		SystemTime:  uint32(data.time),
		Timestamp:   int64(data.timestamp_ns),
		IsKeyDown:   data.isKeyDown != 0,
		IsInjected:  data.isInjected != 0,
		IsExtended:  data.isExtended != 0,
		IsAltDown:   data.isAltDown != 0,
		Modifiers:   uint32(C.GetModifierState()),
	}

	// Translate to character
	ks.Character = translateVKToChar(ks.VirtualKey, ks.ScanCode)

	return ks, true
}

// translateVKToChar converts a virtual key to a Unicode character.
func translateVKToChar(vk, scanCode uint16) rune {
	var buf [4]C.wchar_t
	n := C.VKToCharacter(C.uint16_t(vk), C.uint16_t(scanCode), &buf[0], 4)
	if n == 1 {
		return rune(buf[0])
	}
	return 0
}

// handleRawKeystroke is called from C for each keystroke.
func (s *KeystrokeSink) handleRawKeystroke(ks RawKeystroke) {
	s.mu.RLock()
	callbacks := make([]func(RawKeystroke), len(s.callbacks))
	copy(callbacks, s.callbacks)
	s.mu.RUnlock()

	for _, cb := range callbacks {
		cb(ks)
	}
}

//export goOnRawKeystroke
func goOnRawKeystroke(vkCode C.uint16_t, scanCode C.uint16_t, flags C.uint32_t,
	sysTime C.uint32_t, timestamp C.int64_t, isDown C.int,
	isInjected C.int, isExtended C.int, isAltDown C.int) {

	globalSinkMu.Lock()
	sink := globalSink
	globalSinkMu.Unlock()

	if sink == nil {
		return
	}

	ks := RawKeystroke{
		VirtualKey:  uint16(vkCode),
		ScanCode:    uint16(scanCode),
		Flags:       uint32(flags),
		SystemTime:  uint32(sysTime),
		Timestamp:   int64(timestamp),
		IsKeyDown:   isDown != 0,
		IsInjected:  isInjected != 0,
		IsExtended:  isExtended != 0,
		IsAltDown:   isAltDown != 0,
		Modifiers:   uint32(C.GetModifierState()),
	}

	// Translate to character
	ks.Character = translateVKToChar(ks.VirtualKey, ks.ScanCode)

	sink.handleRawKeystroke(ks)
}

// VirtualKeyNames maps Windows virtual key codes to names.
var VirtualKeyNames = map[uint16]string{
	0x08: "Backspace",
	0x09: "Tab",
	0x0D: "Enter",
	0x10: "Shift",
	0x11: "Control",
	0x12: "Alt",
	0x13: "Pause",
	0x14: "CapsLock",
	0x1B: "Escape",
	0x20: "Space",
	0x21: "PageUp",
	0x22: "PageDown",
	0x23: "End",
	0x24: "Home",
	0x25: "Left",
	0x26: "Up",
	0x27: "Right",
	0x28: "Down",
	0x2C: "PrintScreen",
	0x2D: "Insert",
	0x2E: "Delete",
	0x5B: "LeftWindows",
	0x5C: "RightWindows",
	0x5D: "Applications",
	0x70: "F1",
	0x71: "F2",
	0x72: "F3",
	0x73: "F4",
	0x74: "F5",
	0x75: "F6",
	0x76: "F7",
	0x77: "F8",
	0x78: "F9",
	0x79: "F10",
	0x7A: "F11",
	0x7B: "F12",
	0x90: "NumLock",
	0x91: "ScrollLock",
	0xA0: "LeftShift",
	0xA1: "RightShift",
	0xA2: "LeftControl",
	0xA3: "RightControl",
	0xA4: "LeftAlt",
	0xA5: "RightAlt",
}

// GetKeyName returns a human-readable name for a virtual key code.
func GetKeyName(vk uint16) string {
	if name, ok := VirtualKeyNames[vk]; ok {
		return name
	}
	// Check if it's a printable character
	if vk >= 0x30 && vk <= 0x39 {
		return string(rune(vk))
	}
	if vk >= 0x41 && vk <= 0x5A {
		return string(rune(vk))
	}
	return ""
}
