//go:build windows

// Package main provides the Windows TSF (Text Services Framework) implementation
// for witnessd keystroke witnessing.
//
// The TSF provider operates as a transparent input processor that monitors
// keystrokes without modifying them. It captures timing data for cryptographic
// evidence generation while passing all input through to the target application.
package main

/*
#cgo LDFLAGS: -lole32 -loleaut32 -ladvapi32 -luser32 -lshlwapi

#include <windows.h>
#include <msctf.h>
#include <stdint.h>
#include <stdlib.h>

// TSF GUIDs for witnessd
// CLSID: {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
// Profile GUID: {B2C3D4E5-F678-90AB-CDEF-123456789012}

// TSF interface function pointers (set up at runtime)
typedef struct {
	ITfThreadMgr* threadMgr;
	TfClientId clientId;
	ITfKeystrokeMgr* keystrokeMgr;
	ITfDocumentMgr* documentMgr;
	ITfContext* context;
	DWORD keystrokeSinkCookie;
	DWORD threadMgrEventSinkCookie;
	DWORD textEditSinkCookie;
	HWND focusWindow;
	int isActivated;
	int isComposing;
} TSFState;

static TSFState g_tsfState = {0};

// Forward declarations for Go callbacks
extern void goOnKeystroke(uint16_t vkCode, uint16_t scanCode, uint32_t flags, int64_t timestamp);
extern void goOnFocusChange(void* hwnd, char* appName, char* docTitle);
extern void goOnCompositionStart();
extern void goOnCompositionEnd(char* text);
extern void goOnTextEdit(char* text, int startPos, int endPos);

// Helper to get window info
static void GetWindowInfo(HWND hwnd, wchar_t* className, int classNameLen, wchar_t* title, int titleLen) {
	if (hwnd != NULL) {
		GetClassNameW(hwnd, className, classNameLen);
		GetWindowTextW(hwnd, title, titleLen);
	}
}

// Initialize COM for TSF
static HRESULT InitializeTSF() {
	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr) && hr != S_FALSE && hr != RPC_E_CHANGED_MODE) {
		return hr;
	}
	return S_OK;
}

// Create thread manager
static HRESULT CreateThreadMgr() {
	if (g_tsfState.threadMgr != NULL) {
		return S_OK;
	}

	HRESULT hr = CoCreateInstance(
		&CLSID_TF_ThreadMgr,
		NULL,
		CLSCTX_INPROC_SERVER,
		&IID_ITfThreadMgr,
		(void**)&g_tsfState.threadMgr
	);

	if (FAILED(hr)) {
		return hr;
	}

	hr = g_tsfState.threadMgr->lpVtbl->Activate(g_tsfState.threadMgr, &g_tsfState.clientId);
	if (FAILED(hr)) {
		g_tsfState.threadMgr->lpVtbl->Release(g_tsfState.threadMgr);
		g_tsfState.threadMgr = NULL;
		return hr;
	}

	return S_OK;
}

// Get foreground window process name
static void GetForegroundProcessName(char* buffer, int bufferLen) {
	HWND hwnd = GetForegroundWindow();
	if (hwnd == NULL) {
		buffer[0] = 0;
		return;
	}

	DWORD processId;
	GetWindowThreadProcessId(hwnd, &processId);

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
	if (hProcess == NULL) {
		buffer[0] = 0;
		return;
	}

	wchar_t wpath[MAX_PATH];
	DWORD pathLen = MAX_PATH;
	if (QueryFullProcessImageNameW(hProcess, 0, wpath, &pathLen)) {
		WideCharToMultiByte(CP_UTF8, 0, wpath, -1, buffer, bufferLen, NULL, NULL);
	} else {
		buffer[0] = 0;
	}

	CloseHandle(hProcess);
}

// Get foreground window title
static void GetForegroundWindowTitle(char* buffer, int bufferLen) {
	HWND hwnd = GetForegroundWindow();
	if (hwnd == NULL) {
		buffer[0] = 0;
		return;
	}

	wchar_t wtitle[256];
	GetWindowTextW(hwnd, wtitle, 256);
	WideCharToMultiByte(CP_UTF8, 0, wtitle, -1, buffer, bufferLen, NULL, NULL);
}

// Check if focus changed
static int CheckFocusChanged() {
	HWND current = GetForegroundWindow();
	if (current != g_tsfState.focusWindow) {
		g_tsfState.focusWindow = current;
		return 1;
	}
	return 0;
}

// Get current timestamp in nanoseconds
static int64_t GetTimestampNanos() {
	LARGE_INTEGER freq, count;
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&count);
	return (int64_t)((double)count.QuadPart / freq.QuadPart * 1e9);
}

// Cleanup TSF
static void CleanupTSF() {
	if (g_tsfState.keystrokeMgr != NULL) {
		g_tsfState.keystrokeMgr->lpVtbl->Release(g_tsfState.keystrokeMgr);
		g_tsfState.keystrokeMgr = NULL;
	}

	if (g_tsfState.context != NULL) {
		g_tsfState.context->lpVtbl->Release(g_tsfState.context);
		g_tsfState.context = NULL;
	}

	if (g_tsfState.documentMgr != NULL) {
		g_tsfState.documentMgr->lpVtbl->Release(g_tsfState.documentMgr);
		g_tsfState.documentMgr = NULL;
	}

	if (g_tsfState.threadMgr != NULL) {
		g_tsfState.threadMgr->lpVtbl->Deactivate(g_tsfState.threadMgr);
		g_tsfState.threadMgr->lpVtbl->Release(g_tsfState.threadMgr);
		g_tsfState.threadMgr = NULL;
	}

	CoUninitialize();
	g_tsfState.isActivated = 0;
}
*/
import "C"

import (
	"fmt"
	"sync"
	"time"
	"unsafe"
)

// TSFProvider manages the Windows TSF integration for keystroke witnessing.
// It implements transparent keystroke monitoring through the Text Services Framework.
type TSFProvider struct {
	mu sync.RWMutex

	// Activation state
	isActive    bool
	clientID    uint32
	isComposing bool

	// Callbacks
	onKeystroke       func(KeystrokeEvent)
	onFocusChange     func(FocusEvent)
	onCompositionEnd  func(string)
	onCompositionStart func()

	// Statistics
	keystrokeCount uint64
	lastFocusTime  time.Time

	// Focus tracking
	currentApp    string
	currentDoc    string
	currentWindow uintptr
}

// KeystrokeEvent represents a captured keystroke.
type KeystrokeEvent struct {
	VirtualKey uint16
	ScanCode   uint16
	Flags      uint32
	Timestamp  time.Time
	Character  rune
	IsKeyDown  bool
	IsRepeat   bool
	IsExtended bool
}

// FocusEvent represents an application or document focus change.
type FocusEvent struct {
	WindowHandle uintptr
	AppName      string
	AppPath      string
	DocTitle     string
	Timestamp    time.Time
}

// Global provider instance for C callbacks
var (
	globalProvider   *TSFProvider
	globalProviderMu sync.Mutex
)

// NewTSFProvider creates a new TSF provider instance.
func NewTSFProvider() *TSFProvider {
	return &TSFProvider{
		lastFocusTime: time.Now(),
	}
}

// Initialize sets up the TSF provider with COM.
func (p *TSFProvider) Initialize() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.isActive {
		return nil
	}

	hr := C.InitializeTSF()
	if hr < 0 {
		return fmt.Errorf("failed to initialize COM: HRESULT 0x%x", uint32(hr))
	}

	hr = C.CreateThreadMgr()
	if hr < 0 {
		return fmt.Errorf("failed to create thread manager: HRESULT 0x%x", uint32(hr))
	}

	// Set global provider for callbacks
	globalProviderMu.Lock()
	globalProvider = p
	globalProviderMu.Unlock()

	p.clientID = uint32(C.g_tsfState.clientId)
	p.isActive = true

	return nil
}

// Shutdown cleans up TSF resources.
func (p *TSFProvider) Shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.isActive {
		return
	}

	C.CleanupTSF()

	globalProviderMu.Lock()
	if globalProvider == p {
		globalProvider = nil
	}
	globalProviderMu.Unlock()

	p.isActive = false
}

// IsActive returns whether the provider is currently active.
func (p *TSFProvider) IsActive() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.isActive
}

// SetKeystrokeCallback sets the callback for keystroke events.
func (p *TSFProvider) SetKeystrokeCallback(cb func(KeystrokeEvent)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onKeystroke = cb
}

// SetFocusCallback sets the callback for focus change events.
func (p *TSFProvider) SetFocusCallback(cb func(FocusEvent)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onFocusChange = cb
}

// SetCompositionCallbacks sets callbacks for IME composition events.
func (p *TSFProvider) SetCompositionCallbacks(onStart func(), onEnd func(string)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onCompositionStart = onStart
	p.onCompositionEnd = onEnd
}

// GetCurrentFocus returns the current focus information.
func (p *TSFProvider) GetCurrentFocus() FocusEvent {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return FocusEvent{
		WindowHandle: p.currentWindow,
		AppPath:      p.currentApp,
		DocTitle:     p.currentDoc,
		Timestamp:    p.lastFocusTime,
	}
}

// GetKeystrokeCount returns the total keystroke count.
func (p *TSFProvider) GetKeystrokeCount() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.keystrokeCount
}

// CheckFocusChange checks if the focused window has changed.
func (p *TSFProvider) CheckFocusChange() bool {
	changed := C.CheckFocusChanged()
	if changed != 0 {
		p.updateFocusInfo()
		return true
	}
	return false
}

// updateFocusInfo updates the cached focus information.
func (p *TSFProvider) updateFocusInfo() {
	var appBuf [260]C.char
	var titleBuf [256]C.char

	C.GetForegroundProcessName(&appBuf[0], 260)
	C.GetForegroundWindowTitle(&titleBuf[0], 256)

	p.mu.Lock()
	p.currentApp = C.GoString(&appBuf[0])
	p.currentDoc = C.GoString(&titleBuf[0])
	p.currentWindow = uintptr(C.g_tsfState.focusWindow)
	p.lastFocusTime = time.Now()

	cb := p.onFocusChange
	p.mu.Unlock()

	if cb != nil {
		cb(FocusEvent{
			WindowHandle: p.currentWindow,
			AppPath:      p.currentApp,
			DocTitle:     p.currentDoc,
			Timestamp:    p.lastFocusTime,
		})
	}
}

// handleKeystroke processes a keystroke from C callback.
func (p *TSFProvider) handleKeystroke(vkCode, scanCode uint16, flags uint32, timestamp int64) {
	p.mu.Lock()
	p.keystrokeCount++
	cb := p.onKeystroke
	p.mu.Unlock()

	if cb == nil {
		return
	}

	event := KeystrokeEvent{
		VirtualKey: vkCode,
		ScanCode:   scanCode,
		Flags:      flags,
		Timestamp:  time.Unix(0, timestamp),
		IsKeyDown:  flags&0x80000000 == 0,
		IsRepeat:   flags&0x40000000 != 0,
		IsExtended: flags&0x01000000 != 0,
	}

	// Try to get the character
	event.Character = vkToChar(vkCode, scanCode)

	cb(event)
}

// handleFocusChange processes a focus change from C callback.
func (p *TSFProvider) handleFocusChange(hwnd unsafe.Pointer, appName, docTitle *C.char) {
	p.mu.Lock()
	p.currentWindow = uintptr(hwnd)
	p.currentApp = C.GoString(appName)
	p.currentDoc = C.GoString(docTitle)
	p.lastFocusTime = time.Now()

	cb := p.onFocusChange
	p.mu.Unlock()

	if cb != nil {
		cb(FocusEvent{
			WindowHandle: p.currentWindow,
			AppPath:      p.currentApp,
			DocTitle:     p.currentDoc,
			Timestamp:    p.lastFocusTime,
		})
	}
}

// handleCompositionStart processes IME composition start.
func (p *TSFProvider) handleCompositionStart() {
	p.mu.Lock()
	p.isComposing = true
	cb := p.onCompositionStart
	p.mu.Unlock()

	if cb != nil {
		cb()
	}
}

// handleCompositionEnd processes IME composition end.
func (p *TSFProvider) handleCompositionEnd(text *C.char) {
	p.mu.Lock()
	p.isComposing = false
	cb := p.onCompositionEnd
	p.mu.Unlock()

	if cb != nil {
		cb(C.GoString(text))
	}
}

// vkToChar converts a virtual key code to a character.
func vkToChar(vkCode, scanCode uint16) rune {
	// Use Windows API to translate
	// This is a simplified version - the actual implementation
	// should use ToUnicodeEx with the current keyboard state
	switch {
	case vkCode >= 0x30 && vkCode <= 0x39: // 0-9
		return rune(vkCode)
	case vkCode >= 0x41 && vkCode <= 0x5A: // A-Z
		return rune(vkCode)
	case vkCode == 0x20: // Space
		return ' '
	case vkCode == 0x0D: // Enter
		return '\n'
	case vkCode == 0x09: // Tab
		return '\t'
	default:
		return 0
	}
}

//export goOnKeystroke
func goOnKeystroke(vkCode C.uint16_t, scanCode C.uint16_t, flags C.uint32_t, timestamp C.int64_t) {
	globalProviderMu.Lock()
	p := globalProvider
	globalProviderMu.Unlock()

	if p != nil {
		p.handleKeystroke(uint16(vkCode), uint16(scanCode), uint32(flags), int64(timestamp))
	}
}

//export goOnFocusChange
func goOnFocusChange(hwnd unsafe.Pointer, appName *C.char, docTitle *C.char) {
	globalProviderMu.Lock()
	p := globalProvider
	globalProviderMu.Unlock()

	if p != nil {
		p.handleFocusChange(hwnd, appName, docTitle)
	}
}

//export goOnCompositionStart
func goOnCompositionStart() {
	globalProviderMu.Lock()
	p := globalProvider
	globalProviderMu.Unlock()

	if p != nil {
		p.handleCompositionStart()
	}
}

//export goOnCompositionEnd
func goOnCompositionEnd(text *C.char) {
	globalProviderMu.Lock()
	p := globalProvider
	globalProviderMu.Unlock()

	if p != nil {
		p.handleCompositionEnd(text)
	}
}

//export goOnTextEdit
func goOnTextEdit(text *C.char, startPos C.int, endPos C.int) {
	// Handle text edit events for document tracking
	// This allows capturing full text changes, not just keystrokes
	_ = text
	_ = startPos
	_ = endPos
}
