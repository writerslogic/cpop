//go:build windows

package main

/*
#cgo LDFLAGS: -luser32 -loleacc -lole32 -loleaut32

#include <windows.h>
#include <oleacc.h>
#include <stdint.h>

// ============================================================================
// Focus Tracking Module
// ============================================================================
//
// This module tracks application and document focus changes using:
// 1. SetWinEventHook for focus change events
// 2. UI Automation for document context extraction
// 3. Window enumeration for additional context
//
// ============================================================================

// Focus event data
typedef struct {
	HWND hwnd;
	wchar_t appPath[MAX_PATH];
	wchar_t windowTitle[256];
	wchar_t windowClass[256];
	wchar_t documentPath[MAX_PATH];
	DWORD processId;
	DWORD threadId;
	int64_t timestamp_ns;
} FocusEventData;

// Callback function types
typedef void (*FocusCallbackFunc)(FocusEventData* data);
static FocusCallbackFunc g_focusCallback = NULL;

// Event hook handles
static HWINEVENTHOOK g_focusEventHook = NULL;
static HWINEVENTHOOK g_nameChangeHook = NULL;
static HANDLE g_eventThread = NULL;
static DWORD g_eventThreadId = 0;
static volatile int g_trackingRunning = 0;

// Current focus state
static FocusEventData g_currentFocus = {0};
static CRITICAL_SECTION g_focusLock;
static int g_lockInitialized = 0;

// Performance counter for timestamps
static LARGE_INTEGER g_focusPerfFreq;
static int g_focusPerfInit = 0;

// Forward declaration for Go callback
extern void goOnFocusEvent(void* hwnd, wchar_t* appPath, wchar_t* windowTitle,
                            wchar_t* windowClass, wchar_t* docPath,
                            uint32_t processId, uint32_t threadId, int64_t timestamp);

// Get high-precision timestamp
static int64_t GetFocusTimestampNanos() {
	if (!g_focusPerfInit) {
		QueryPerformanceFrequency(&g_focusPerfFreq);
		g_focusPerfInit = 1;
	}

	LARGE_INTEGER counter;
	QueryPerformanceCounter(&counter);
	return (int64_t)((double)counter.QuadPart / (double)g_focusPerfFreq.QuadPart * 1e9);
}

// Get process executable path
static void GetProcessPath(DWORD processId, wchar_t* buffer, int bufferLen) {
	buffer[0] = 0;

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
	if (hProcess != NULL) {
		DWORD len = bufferLen;
		QueryFullProcessImageNameW(hProcess, 0, buffer, &len);
		CloseHandle(hProcess);
	}
}

// Try to get document path from various sources
static void GetDocumentPath(HWND hwnd, wchar_t* buffer, int bufferLen) {
	buffer[0] = 0;

	// Try to get from window title (many apps show "filename - AppName")
	wchar_t title[512];
	if (GetWindowTextW(hwnd, title, 512) > 0) {
		// Look for common patterns like "filename.ext - Application"
		wchar_t* dash = wcsrchr(title, L'-');
		if (dash != NULL && dash != title) {
			// Check if there's a file extension before the dash
			wchar_t* dot = wcsrchr(title, L'.');
			if (dot != NULL && dot < dash) {
				// Likely a filename, copy up to the dash
				int len = (int)(dash - title);
				while (len > 0 && title[len-1] == L' ') len--;
				if (len > 0 && len < bufferLen) {
					wcsncpy(buffer, title, len);
					buffer[len] = 0;
				}
			}
		}
	}
}

// Fill focus event data
static void FillFocusEventData(HWND hwnd, FocusEventData* data) {
	memset(data, 0, sizeof(FocusEventData));

	data->hwnd = hwnd;
	data->timestamp_ns = GetFocusTimestampNanos();

	if (hwnd == NULL) {
		return;
	}

	// Get window info
	data->threadId = GetWindowThreadProcessId(hwnd, &data->processId);
	GetWindowTextW(hwnd, data->windowTitle, 256);
	GetClassNameW(hwnd, data->windowClass, 256);

	// Get process path
	GetProcessPath(data->processId, data->appPath, MAX_PATH);

	// Try to get document path
	GetDocumentPath(hwnd, data->documentPath, MAX_PATH);
}

// Win event callback for focus changes
static void CALLBACK WinEventProc(HWINEVENTHOOK hWinEventHook, DWORD event,
                                   HWND hwnd, LONG idObject, LONG idChild,
                                   DWORD dwEventThread, DWORD dwmsEventTime) {
	(void)hWinEventHook;
	(void)idChild;
	(void)dwEventThread;
	(void)dwmsEventTime;

	if (!g_trackingRunning) {
		return;
	}

	// We care about foreground window changes and significant name changes
	if (event == EVENT_SYSTEM_FOREGROUND ||
		(event == EVENT_OBJECT_NAMECHANGE && idObject == OBJID_WINDOW)) {

		// For name changes, only track if it's the current foreground window
		if (event == EVENT_OBJECT_NAMECHANGE) {
			HWND fg = GetForegroundWindow();
			if (fg != hwnd) {
				return;
			}
		}

		FocusEventData eventData;
		FillFocusEventData(hwnd, &eventData);

		// Update current focus
		if (g_lockInitialized) {
			EnterCriticalSection(&g_focusLock);
			g_currentFocus = eventData;
			LeaveCriticalSection(&g_focusLock);
		}

		// Notify Go
		goOnFocusEvent(
			(void*)hwnd,
			eventData.appPath,
			eventData.windowTitle,
			eventData.windowClass,
			eventData.documentPath,
			eventData.processId,
			eventData.threadId,
			eventData.timestamp_ns
		);
	}
}

// Event thread procedure
static DWORD WINAPI FocusEventThreadProc(LPVOID lpParam) {
	(void)lpParam;

	// Install event hooks
	g_focusEventHook = SetWinEventHook(
		EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND,
		NULL, WinEventProc,
		0, 0,
		WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS
	);

	g_nameChangeHook = SetWinEventHook(
		EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_NAMECHANGE,
		NULL, WinEventProc,
		0, 0,
		WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS
	);

	if (g_focusEventHook == NULL) {
		return 1;
	}

	g_trackingRunning = 1;

	// Capture initial focus
	HWND fg = GetForegroundWindow();
	if (fg != NULL) {
		FocusEventData eventData;
		FillFocusEventData(fg, &eventData);

		if (g_lockInitialized) {
			EnterCriticalSection(&g_focusLock);
			g_currentFocus = eventData;
			LeaveCriticalSection(&g_focusLock);
		}

		goOnFocusEvent(
			(void*)fg,
			eventData.appPath,
			eventData.windowTitle,
			eventData.windowClass,
			eventData.documentPath,
			eventData.processId,
			eventData.threadId,
			eventData.timestamp_ns
		);
	}

	// Message loop
	MSG msg;
	while (GetMessageW(&msg, NULL, 0, 0) > 0) {
		TranslateMessage(&msg);
		DispatchMessageW(&msg);

		if (!g_trackingRunning) {
			break;
		}
	}

	// Cleanup
	if (g_focusEventHook != NULL) {
		UnhookWinEvent(g_focusEventHook);
		g_focusEventHook = NULL;
	}
	if (g_nameChangeHook != NULL) {
		UnhookWinEvent(g_nameChangeHook);
		g_nameChangeHook = NULL;
	}

	return 0;
}

// Initialize focus tracking
static int InitFocusTracking() {
	if (!g_lockInitialized) {
		InitializeCriticalSection(&g_focusLock);
		g_lockInitialized = 1;
	}
	return 0;
}

// Start focus tracking
static int StartFocusTracking() {
	if (g_trackingRunning) {
		return 0;
	}

	InitFocusTracking();

	g_eventThread = CreateThread(NULL, 0, FocusEventThreadProc, NULL, 0, &g_eventThreadId);
	if (g_eventThread == NULL) {
		return -1;
	}

	// Wait for thread to start
	for (int i = 0; i < 100 && !g_trackingRunning; i++) {
		Sleep(10);
	}

	return g_trackingRunning ? 0 : -2;
}

// Stop focus tracking
static void StopFocusTracking() {
	if (!g_trackingRunning) {
		return;
	}

	g_trackingRunning = 0;

	// Signal thread to exit
	if (g_eventThreadId != 0) {
		PostThreadMessageW(g_eventThreadId, WM_QUIT, 0, 0);
	}

	// Wait for thread
	if (g_eventThread != NULL) {
		WaitForSingleObject(g_eventThread, 2000);
		CloseHandle(g_eventThread);
		g_eventThread = NULL;
	}

	g_eventThreadId = 0;
}

// Cleanup focus tracking
static void CleanupFocusTracking() {
	StopFocusTracking();

	if (g_lockInitialized) {
		DeleteCriticalSection(&g_focusLock);
		g_lockInitialized = 0;
	}
}

// Get current focus info
static void GetCurrentFocus(FocusEventData* data) {
	if (g_lockInitialized) {
		EnterCriticalSection(&g_focusLock);
		*data = g_currentFocus;
		LeaveCriticalSection(&g_focusLock);
	} else {
		memset(data, 0, sizeof(FocusEventData));
	}
}

// Force refresh current focus
static void RefreshCurrentFocus() {
	HWND fg = GetForegroundWindow();
	if (fg != NULL) {
		FocusEventData eventData;
		FillFocusEventData(fg, &eventData);

		if (g_lockInitialized) {
			EnterCriticalSection(&g_focusLock);
			g_currentFocus = eventData;
			LeaveCriticalSection(&g_focusLock);
		}
	}
}
*/
import "C"

import (
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// FocusTracker monitors application and document focus changes.
// It provides real-time notifications when the user switches between
// windows or documents.
type FocusTracker struct {
	mu sync.RWMutex

	running   bool
	callbacks []func(FocusInfo)

	// Current focus
	currentFocus FocusInfo
}

// FocusInfo contains detailed information about the focused window.
type FocusInfo struct {
	WindowHandle uintptr
	ProcessID    uint32
	ThreadID     uint32
	AppPath      string
	AppName      string
	WindowTitle  string
	WindowClass  string
	DocumentPath string
	DocumentName string
	Timestamp    time.Time
}

// AppInfo provides information about a running application.
type AppInfo struct {
	ProcessID uint32
	Name      string
	Path      string
	IsElevated bool
}

// Global focus tracker for C callbacks
var (
	globalTracker   *FocusTracker
	globalTrackerMu sync.Mutex
)

// NewFocusTracker creates a new focus tracker.
func NewFocusTracker() *FocusTracker {
	return &FocusTracker{}
}

// Start begins tracking focus changes.
func (t *FocusTracker) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		return nil
	}

	// Set global instance
	globalTrackerMu.Lock()
	globalTracker = t
	globalTrackerMu.Unlock()

	result := C.StartFocusTracking()
	if result != 0 {
		globalTrackerMu.Lock()
		globalTracker = nil
		globalTrackerMu.Unlock()
		return &FocusTrackerError{Code: int(result)}
	}

	t.running = true
	return nil
}

// Stop stops tracking focus changes.
func (t *FocusTracker) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return nil
	}

	C.StopFocusTracking()

	globalTrackerMu.Lock()
	if globalTracker == t {
		globalTracker = nil
	}
	globalTrackerMu.Unlock()

	t.running = false
	return nil
}

// IsRunning returns whether the tracker is currently active.
func (t *FocusTracker) IsRunning() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.running
}

// AddCallback registers a callback for focus change events.
func (t *FocusTracker) AddCallback(cb func(FocusInfo)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.callbacks = append(t.callbacks, cb)
}

// GetCurrentFocus returns the current focus information.
func (t *FocusTracker) GetCurrentFocus() FocusInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.currentFocus
}

// Refresh forces a refresh of the current focus information.
func (t *FocusTracker) Refresh() FocusInfo {
	C.RefreshCurrentFocus()

	var data C.FocusEventData
	C.GetCurrentFocus(&data)

	info := focusEventDataToInfo(&data)

	t.mu.Lock()
	t.currentFocus = info
	t.mu.Unlock()

	return info
}

// handleFocusEvent processes a focus event from C.
func (t *FocusTracker) handleFocusEvent(info FocusInfo) {
	t.mu.Lock()
	t.currentFocus = info
	callbacks := make([]func(FocusInfo), len(t.callbacks))
	copy(callbacks, t.callbacks)
	t.mu.Unlock()

	for _, cb := range callbacks {
		cb(info)
	}
}

// focusEventDataToInfo converts C focus data to Go struct.
func focusEventDataToInfo(data *C.FocusEventData) FocusInfo {
	appPath := wcharToString(unsafe.Pointer(&data.appPath[0]))
	docPath := wcharToString(unsafe.Pointer(&data.documentPath[0]))

	return FocusInfo{
		WindowHandle: uintptr(data.hwnd),
		ProcessID:    uint32(data.processId),
		ThreadID:     uint32(data.threadId),
		AppPath:      appPath,
		AppName:      extractAppName(appPath),
		WindowTitle:  wcharToString(unsafe.Pointer(&data.windowTitle[0])),
		WindowClass:  wcharToString(unsafe.Pointer(&data.windowClass[0])),
		DocumentPath: docPath,
		DocumentName: extractDocName(docPath),
		Timestamp:    time.Unix(0, int64(data.timestamp_ns)),
	}
}

// wcharToString converts a wchar_t pointer to a Go string.
func wcharToString(ptr unsafe.Pointer) string {
	if ptr == nil {
		return ""
	}

	wchars := (*[1024]uint16)(ptr)
	for i := 0; i < 1024; i++ {
		if wchars[i] == 0 {
			return string(utf16ToRunes(wchars[:i]))
		}
	}
	return ""
}

// utf16ToRunes converts UTF-16 to runes.
func utf16ToRunes(u16 []uint16) []rune {
	runes := make([]rune, 0, len(u16))
	for i := 0; i < len(u16); {
		r := rune(u16[i])
		if r >= 0xD800 && r <= 0xDBFF && i+1 < len(u16) {
			r2 := rune(u16[i+1])
			if r2 >= 0xDC00 && r2 <= 0xDFFF {
				r = (r-0xD800)*0x400 + (r2 - 0xDC00) + 0x10000
				i += 2
				runes = append(runes, r)
				continue
			}
		}
		runes = append(runes, r)
		i++
	}
	return runes
}

// extractAppName extracts the application name from a full path.
func extractAppName(path string) string {
	if path == "" {
		return ""
	}
	name := filepath.Base(path)
	// Remove .exe extension
	if strings.HasSuffix(strings.ToLower(name), ".exe") {
		name = name[:len(name)-4]
	}
	return name
}

// extractDocName extracts the document name from a path or title.
func extractDocName(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}

// FocusTrackerError represents a focus tracking error.
type FocusTrackerError struct {
	Code int
}

func (e *FocusTrackerError) Error() string {
	switch e.Code {
	case -1:
		return "failed to create event thread"
	case -2:
		return "timeout waiting for focus tracking to start"
	default:
		return "unknown focus tracking error"
	}
}

//export goOnFocusEvent
func goOnFocusEvent(hwnd unsafe.Pointer, appPath *C.wchar_t, windowTitle *C.wchar_t,
	windowClass *C.wchar_t, docPath *C.wchar_t,
	processId C.uint32_t, threadId C.uint32_t, timestamp C.int64_t) {

	globalTrackerMu.Lock()
	tracker := globalTracker
	globalTrackerMu.Unlock()

	if tracker == nil {
		return
	}

	appPathStr := wcharToString(unsafe.Pointer(appPath))
	docPathStr := wcharToString(unsafe.Pointer(docPath))

	info := FocusInfo{
		WindowHandle: uintptr(hwnd),
		ProcessID:    uint32(processId),
		ThreadID:     uint32(threadId),
		AppPath:      appPathStr,
		AppName:      extractAppName(appPathStr),
		WindowTitle:  wcharToString(unsafe.Pointer(windowTitle)),
		WindowClass:  wcharToString(unsafe.Pointer(windowClass)),
		DocumentPath: docPathStr,
		DocumentName: extractDocName(docPathStr),
		Timestamp:    time.Unix(0, int64(timestamp)),
	}

	tracker.handleFocusEvent(info)
}

// WellKnownApps maps application class names to human-readable names.
var WellKnownApps = map[string]string{
	"Notepad":                      "Notepad",
	"CabinetWClass":                "File Explorer",
	"Chrome_WidgetWin_1":           "Google Chrome",
	"MozillaWindowClass":           "Firefox",
	"ConsoleWindowClass":           "Terminal",
	"CASCADIA_HOSTING_WINDOW_CLASS": "Windows Terminal",
	"OpusApp":                      "Microsoft Word",
	"XLMAIN":                       "Microsoft Excel",
	"PPTFrameClass":                "Microsoft PowerPoint",
	"Vim":                          "Vim",
	"Emacs":                        "Emacs",
	"SunAwtFrame":                  "Java Application",
}

// GetAppDisplayName returns a human-readable name for an application.
func GetAppDisplayName(info FocusInfo) string {
	// First check window class
	if name, ok := WellKnownApps[info.WindowClass]; ok {
		return name
	}

	// Fall back to app name
	if info.AppName != "" {
		return info.AppName
	}

	// Fall back to window class
	return info.WindowClass
}
