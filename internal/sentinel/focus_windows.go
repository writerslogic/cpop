//go:build windows && cgo

// Package sentinel provides automatic document tracking for witnessd.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

/*
#cgo LDFLAGS: -luser32 -lole32 -loleaut32

#include <windows.h>
#include <oleauto.h>
#include <stdint.h>
#include <UIAutomation.h>
#include <comdef.h>

// ============================================================================
// Windows Focus Detection
// ============================================================================
//
// We use multiple Win32 APIs for focus detection:
//
// 1. GetForegroundWindow / SetWinEventHook for window focus changes
// 2. UI Automation API for document path extraction
// 3. ReadDirectoryChangesW for file modification monitoring
//
// The SetWinEventHook approach is preferred because it's event-driven
// rather than polling, which is more efficient and responsive.
//
// ============================================================================

// Callback types
typedef void (*FocusCallbackFunc)(const char* path, const char* shadowID,
                                   const char* appID, const char* appName,
                                   const char* windowTitle, int eventType);
typedef void (*ChangeCallbackFunc)(const char* path, int eventType);

static FocusCallbackFunc focusCallback = NULL;
static ChangeCallbackFunc changeCallback = NULL;

// Global state
static HWINEVENTHOOK eventHook = NULL;
static volatile int monitorRunning = 0;
static DWORD threadId = 0;
static HANDLE threadHandle = NULL;
static HWND lastFocusedWindow = NULL;
static IUIAutomation* pAutomation = NULL;

// File change monitoring
#define MAX_WATCH_HANDLES 64
static HANDLE watchHandles[MAX_WATCH_HANDLES];
static wchar_t* watchPaths[MAX_WATCH_HANDLES];
static int watchCount = 0;
static HANDLE stopEvent = NULL;

// Forward declarations
static void CALLBACK WinEventProc(HWINEVENTHOOK hWinEventHook, DWORD event,
                                   HWND hwnd, LONG idObject, LONG idChild,
                                   DWORD idEventThread, DWORD dwmsEventTime);
static DWORD WINAPI MonitorThreadProc(LPVOID lpParam);
static char* GetWindowDocumentPath(HWND hwnd);
static char* GetWindowTitle(HWND hwnd);
static char* GetProcessName(DWORD pid);
static char* GetProcessPath(DWORD pid);

// ============================================================================
// Win32 Event Hook for Focus Changes
// ============================================================================

static void CALLBACK WinEventProc(HWINEVENTHOOK hWinEventHook, DWORD event,
                                   HWND hwnd, LONG idObject, LONG idChild,
                                   DWORD idEventThread, DWORD dwmsEventTime) {
    (void)hWinEventHook;
    (void)idObject;
    (void)idChild;
    (void)idEventThread;
    (void)dwmsEventTime;

    if (!focusCallback) return;
    if (event != EVENT_SYSTEM_FOREGROUND) return;
    if (!hwnd) return;

    // Skip if same window
    if (hwnd == lastFocusedWindow) return;

    // Notify about previous window losing focus
    if (lastFocusedWindow != NULL) {
        focusCallback("", "", "", "", "", 1);  // FocusLost
    }

    lastFocusedWindow = hwnd;

    // Get window information
    char* docPath = GetWindowDocumentPath(hwnd);
    char* windowTitle = GetWindowTitle(hwnd);

    // Get process information
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);

    char* appName = GetProcessName(pid);
    char* appPath = GetProcessPath(pid);

    focusCallback(
        docPath ? docPath : "",
        "",  // shadowID
        appPath ? appPath : "",
        appName ? appName : "",
        windowTitle ? windowTitle : "",
        0  // FocusGained
    );

    if (docPath) free(docPath);
    if (windowTitle) free(windowTitle);
    if (appName) free(appName);
    if (appPath) free(appPath);
}

// ============================================================================
// Window Title and Document Path Extraction
// ============================================================================

static char* GetWindowTitle(HWND hwnd) {
    int length = GetWindowTextLengthW(hwnd);
    if (length <= 0) return NULL;

    wchar_t* titleW = (wchar_t*)malloc((length + 1) * sizeof(wchar_t));
    if (!titleW) return NULL;

    GetWindowTextW(hwnd, titleW, length + 1);

    // Convert to UTF-8
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, titleW, -1, NULL, 0, NULL, NULL);
    if (utf8Len <= 0) {
        free(titleW);
        return NULL;
    }

    char* title = (char*)malloc(utf8Len);
    if (!title) {
        free(titleW);
        return NULL;
    }

    WideCharToMultiByte(CP_UTF8, 0, titleW, -1, title, utf8Len, NULL, NULL);
    free(titleW);

    return title;
}

static char* GetProcessName(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return NULL;

    wchar_t nameW[MAX_PATH];
    DWORD size = MAX_PATH;

    if (!QueryFullProcessImageNameW(hProcess, 0, nameW, &size)) {
        CloseHandle(hProcess);
        return NULL;
    }

    CloseHandle(hProcess);

    // Get just the filename
    wchar_t* baseName = wcsrchr(nameW, L'\\');
    if (baseName) baseName++;
    else baseName = nameW;

    // Remove .exe extension
    wchar_t* ext = wcsrchr(baseName, L'.');
    if (ext && _wcsicmp(ext, L".exe") == 0) {
        *ext = L'\0';
    }

    // Convert to UTF-8
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, baseName, -1, NULL, 0, NULL, NULL);
    if (utf8Len <= 0) return NULL;

    char* name = (char*)malloc(utf8Len);
    if (!name) return NULL;

    WideCharToMultiByte(CP_UTF8, 0, baseName, -1, name, utf8Len, NULL, NULL);
    return name;
}

static char* GetProcessPath(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return NULL;

    wchar_t pathW[MAX_PATH];
    DWORD size = MAX_PATH;

    if (!QueryFullProcessImageNameW(hProcess, 0, pathW, &size)) {
        CloseHandle(hProcess);
        return NULL;
    }

    CloseHandle(hProcess);

    // Convert to UTF-8
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, pathW, -1, NULL, 0, NULL, NULL);
    if (utf8Len <= 0) return NULL;

    char* path = (char*)malloc(utf8Len);
    if (!path) return NULL;

    WideCharToMultiByte(CP_UTF8, 0, pathW, -1, path, utf8Len, NULL, NULL);
    return path;
}

// Get document path from window using UI Automation
static char* GetWindowDocumentPath(HWND hwnd) {
    if (!pAutomation) {
        HRESULT hr = CoCreateInstance(CLSID_CUIAutomation, NULL,
                                      CLSCTX_INPROC_SERVER, IID_IUIAutomation,
                                      (void**)&pAutomation);
        if (FAILED(hr)) return NULL;
    }

    IUIAutomationElement* pElement = NULL;
    HRESULT hr = pAutomation->ElementFromHandle(hwnd, &pElement);
    if (FAILED(hr) || !pElement) return NULL;

    char* docPath = NULL;
    VARIANT val;
    VariantInit(&val);

    // Try ValuePattern (often used for address bars or edit controls)
    IUIAutomationValuePattern* pValuePattern = NULL;
    hr = pElement->GetCurrentPattern(UIA_ValuePatternId, (IUnknown**)&pValuePattern);
    if (SUCCEEDED(hr) && pValuePattern) {
        BSTR value = NULL;
        hr = pValuePattern->get_CurrentValue(&value);
        if (SUCCEEDED(hr) && value) {
            // Check if it looks like a path
            if (SysStringLen(value) > 3 && value[1] == L':') {
                int utf8Len = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
                if (utf8Len > 0) {
                    docPath = (char*)malloc(utf8Len);
                    WideCharToMultiByte(CP_UTF8, 0, value, -1, docPath, utf8Len, NULL, NULL);
                }
            }
            SysFreeString(value);
        }
        pValuePattern->Release();
    }

    if (docPath) {
        pElement->Release();
        return docPath;
    }

    // Try finding a child element with Document control type (Word/Excel)
    IUIAutomationCondition* pCondition = NULL;
    pAutomation->CreatePropertyCondition(UIA_ControlTypePropertyId,
                                         (VARIANT){.vt = VT_I4, .lVal = UIA_DocumentControlTypeId},
                                         &pCondition);

    if (pCondition) {
        IUIAutomationElement* pDocElement = NULL;
        pElement->FindFirst(TreeScope_Descendants, pCondition, &pDocElement);
        if (pDocElement) {
            // Try ValuePattern on document element
            hr = pDocElement->GetCurrentPattern(UIA_ValuePatternId, (IUnknown**)&pValuePattern);
            if (SUCCEEDED(hr) && pValuePattern) {
                BSTR value = NULL;
                hr = pValuePattern->get_CurrentValue(&value);
                if (SUCCEEDED(hr) && value) {
                    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
                    if (utf8Len > 0) {
                        docPath = (char*)malloc(utf8Len);
                        WideCharToMultiByte(CP_UTF8, 0, value, -1, docPath, utf8Len, NULL, NULL);
                    }
                    SysFreeString(value);
                }
                pValuePattern->Release();
            }
            pDocElement->Release();
        }
        pCondition->Release();
    }

    pElement->Release();
    return docPath;
}

// ============================================================================
// File Change Monitoring (ReadDirectoryChangesW)
// ============================================================================

static DWORD WINAPI FileWatchThreadProc(LPVOID lpParam) {
    (void)lpParam;

    HANDLE handles[MAX_WATCH_HANDLES + 1];
    int handleCount = 0;

    // First handle is always the stop event
    handles[0] = stopEvent;
    handleCount = 1;

    // Add directory handles
    for (int i = 0; i < watchCount && handleCount < MAX_WATCH_HANDLES; i++) {
        if (watchHandles[i] != INVALID_HANDLE_VALUE) {
            handles[handleCount++] = watchHandles[i];
        }
    }

    while (monitorRunning) {
        DWORD result = WaitForMultipleObjects(handleCount, handles, FALSE, 1000);

        if (result == WAIT_OBJECT_0) {
            // Stop event signaled
            break;
        }

        if (result >= WAIT_OBJECT_0 + 1 && result < WAIT_OBJECT_0 + handleCount) {
            // A directory handle signaled
            int idx = result - WAIT_OBJECT_0 - 1;

            // Read the changes
            BYTE buffer[4096];
            DWORD bytesReturned = 0;

            if (ReadDirectoryChangesW(
                    watchHandles[idx],
                    buffer,
                    sizeof(buffer),
                    TRUE,  // Watch subtree
                    FILE_NOTIFY_CHANGE_FILE_NAME |
                    FILE_NOTIFY_CHANGE_LAST_WRITE |
                    FILE_NOTIFY_CHANGE_SIZE,
                    &bytesReturned,
                    NULL,
                    NULL)) {

                FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)buffer;

                while (fni) {
                    // Get the filename
                    int nameLen = fni->FileNameLength / sizeof(wchar_t);
                    wchar_t* filename = (wchar_t*)malloc((nameLen + 1) * sizeof(wchar_t));
                    if (filename) {
                        wcsncpy(filename, fni->FileName, nameLen);
                        filename[nameLen] = L'\0';

                        // Build full path
                        size_t dirLen = wcslen(watchPaths[idx]);
                        wchar_t* fullPath = (wchar_t*)malloc((dirLen + nameLen + 2) * sizeof(wchar_t));
                        if (fullPath) {
                            wcscpy(fullPath, watchPaths[idx]);
                            if (fullPath[dirLen - 1] != L'\\') {
                                wcscat(fullPath, L"\\");
                            }
                            wcscat(fullPath, filename);

                            // Convert to UTF-8
                            int utf8Len = WideCharToMultiByte(CP_UTF8, 0, fullPath, -1, NULL, 0, NULL, NULL);
                            char* path = (char*)malloc(utf8Len);
                            if (path) {
                                WideCharToMultiByte(CP_UTF8, 0, fullPath, -1, path, utf8Len, NULL, NULL);

                                int eventType = 0;  // ChangeModified
                                switch (fni->Action) {
                                    case FILE_ACTION_ADDED:
                                    case FILE_ACTION_RENAMED_NEW_NAME:
                                        eventType = 2;  // ChangeCreated
                                        break;
                                    case FILE_ACTION_REMOVED:
                                    case FILE_ACTION_RENAMED_OLD_NAME:
                                        eventType = 3;  // ChangeDeleted
                                        break;
                                    case FILE_ACTION_MODIFIED:
                                        eventType = 1;  // ChangeSaved (assume modification = save)
                                        break;
                                }

                                if (changeCallback) {
                                    changeCallback(path, eventType);
                                }

                                free(path);
                            }

                            free(fullPath);
                        }

                        free(filename);
                    }

                    // Move to next entry
                    if (fni->NextEntryOffset == 0) break;
                    fni = (FILE_NOTIFY_INFORMATION*)((BYTE*)fni + fni->NextEntryOffset);
                }
            }
        }
    }

    return 0;
}

static int addWatchDirectory(const wchar_t* path) {
    if (watchCount >= MAX_WATCH_HANDLES) return -1;

    HANDLE hDir = CreateFileW(
        path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) return -1;

    watchHandles[watchCount] = hDir;
    watchPaths[watchCount] = _wcsdup(path);
    watchCount++;

    return 0;
}

// ============================================================================
// Monitor Thread
// ============================================================================

static DWORD WINAPI MonitorThreadProc(LPVOID lpParam) {
    (void)lpParam;

    // Install the event hook
    eventHook = SetWinEventHook(
        EVENT_SYSTEM_FOREGROUND,
        EVENT_SYSTEM_FOREGROUND,
        NULL,
        WinEventProc,
        0,
        0,
        WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS
    );

    if (!eventHook) {
        monitorRunning = 0;
        return 1;
    }

    monitorRunning = 1;

    // Message loop for the event hook
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);

        if (!monitorRunning) break;
    }

    // Cleanup
    if (eventHook) {
        UnhookWinEvent(eventHook);
        eventHook = NULL;
    }

    return 0;
}

// ============================================================================
// Public API
// ============================================================================

int startWindowsFocusMonitoring(FocusCallbackFunc focus, ChangeCallbackFunc change) {
    if (monitorRunning) return 1;

    focusCallback = focus;
    changeCallback = change;
    lastFocusedWindow = NULL;

    // Create stop event
    stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    // Start monitor thread
    threadHandle = CreateThread(NULL, 0, MonitorThreadProc, NULL, 0, &threadId);
    if (!threadHandle) {
        CloseHandle(stopEvent);
        return -1;
    }

    // Wait for startup
    for (int i = 0; i < 100 && !monitorRunning; i++) {
        Sleep(10);
    }

    // Start file watch thread if we have watches
    if (watchCount > 0) {
        CreateThread(NULL, 0, FileWatchThreadProc, NULL, 0, NULL);
    }

    return monitorRunning ? 0 : -2;
}

void stopWindowsFocusMonitoring(void) {
    if (!monitorRunning) return;

    monitorRunning = 0;

    // Signal stop
    if (stopEvent) {
        SetEvent(stopEvent);
    }

    // Post quit message to event hook thread
    if (threadId) {
        PostThreadMessage(threadId, WM_QUIT, 0, 0);
    }

    // Wait for thread
    if (threadHandle) {
        WaitForSingleObject(threadHandle, 5000);
        CloseHandle(threadHandle);
        threadHandle = NULL;
    }

    // Cleanup
    if (stopEvent) {
        CloseHandle(stopEvent);
        stopEvent = NULL;
    }

    // Close watch handles
    for (int i = 0; i < watchCount; i++) {
        if (watchHandles[i] != INVALID_HANDLE_VALUE) {
            CloseHandle(watchHandles[i]);
        }
        if (watchPaths[i]) {
            free(watchPaths[i]);
        }
    }
    watchCount = 0;

    focusCallback = NULL;
    changeCallback = NULL;
}

int isWindowsFocusMonitorRunning(void) {
    return monitorRunning;
}

int addWindowsWatchPath(const wchar_t* path) {
    return addWatchDirectory(path);
}

// Trigger a focus check on current window
void checkWindowsFocusNow(void) {
    if (!monitorRunning || !focusCallback) return;

    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return;

    if (hwnd == lastFocusedWindow) return;
    lastFocusedWindow = hwnd;

    char* docPath = GetWindowDocumentPath(hwnd);
    char* windowTitle = GetWindowTitle(hwnd);

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);

    char* appName = GetProcessName(pid);
    char* appPath = GetProcessPath(pid);

    focusCallback(
        docPath ? docPath : "",
        "",
        appPath ? appPath : "",
        appName ? appName : "",
        windowTitle ? windowTitle : "",
        0
    );

    if (docPath) free(docPath);
    if (windowTitle) free(windowTitle);
    if (appName) free(appName);
    if (appPath) free(appPath);
}

*/
import "C"

import (
	"context"
	"sync"
	"time"
	"unsafe"
)

// windowsFocusMonitor implements FocusMonitor for Windows.
type windowsFocusMonitor struct {
	mu           sync.RWMutex
	config       *Config
	ctx          context.Context
	cancel       context.CancelFunc
	running      bool
	focusEvents  chan FocusEvent
	changeEvents chan ChangeEvent
}

// newFocusMonitor creates the platform-specific focus monitor.
func newFocusMonitor(cfg *Config) FocusMonitor {
	return &windowsFocusMonitor{
		config:       cfg,
		focusEvents:  make(chan FocusEvent, 100),
		changeEvents: make(chan ChangeEvent, 100),
	}
}

// Start begins monitoring for focus changes.
func (m *windowsFocusMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return ErrAlreadyRunning
	}

	m.ctx, m.cancel = context.WithCancel(ctx)

	// Set up callbacks
	registerWindowsCallbacks(m)

	// Add watch paths
	for _, path := range m.config.WatchPaths {
		pathW := stringToWideChar(path)
		if pathW != nil {
			C.addWindowsWatchPath((*C.wchar_t)(pathW))
			C.free(unsafe.Pointer(pathW))
		}
	}

	// Start the monitor
	result := C.startWindowsFocusMonitoring(
		(C.FocusCallbackFunc)(C.goWindowsFocusCallback),
		(C.ChangeCallbackFunc)(C.goWindowsChangeCallback),
	)

	if result != 0 {
		return ErrNotAvailable
	}

	m.running = true

	// Trigger initial focus check
	go func() {
		time.Sleep(100 * time.Millisecond)
		C.checkWindowsFocusNow()
	}()

	return nil
}

// Stop stops monitoring.
func (m *windowsFocusMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.running = false

	if m.cancel != nil {
		m.cancel()
	}

	C.stopWindowsFocusMonitoring()

	close(m.focusEvents)
	close(m.changeEvents)

	return nil
}

// FocusEvents returns the channel of focus events.
func (m *windowsFocusMonitor) FocusEvents() <-chan FocusEvent {
	return m.focusEvents
}

// ChangeEvents returns the channel of change events.
func (m *windowsFocusMonitor) ChangeEvents() <-chan ChangeEvent {
	return m.changeEvents
}

// Available checks if focus monitoring is available.
func (m *windowsFocusMonitor) Available() (bool, string) {
	// Windows focus monitoring is always available
	return true, "Windows focus monitoring available"
}

// stringToWideChar converts a Go string to a Windows wide character string.
func stringToWideChar(s string) unsafe.Pointer {
	// This is a simplified conversion - in production use syscall.UTF16PtrFromString
	utf16 := make([]uint16, len(s)+1)
	for i, r := range s {
		if r > 0xFFFF {
			utf16[i] = '?'
		} else {
			utf16[i] = uint16(r)
		}
	}
	return unsafe.Pointer(&utf16[0])
}

// Global reference to the current monitor for callbacks
var (
	windowsMonitorMu      sync.RWMutex
	currentWindowsMonitor *windowsFocusMonitor
)

func registerWindowsCallbacks(m *windowsFocusMonitor) {
	windowsMonitorMu.Lock()
	currentWindowsMonitor = m
	windowsMonitorMu.Unlock()
}

//export goWindowsFocusCallback
func goWindowsFocusCallback(path, shadowID, appID, appName, windowTitle *C.char, eventType C.int) {
	windowsMonitorMu.RLock()
	m := currentWindowsMonitor
	windowsMonitorMu.RUnlock()

	if m == nil || !m.running {
		return
	}

	event := FocusEvent{
		Type:        FocusEventType(eventType),
		Path:        C.GoString(path),
		ShadowID:    C.GoString(shadowID),
		AppBundleID: C.GoString(appID),
		AppName:     C.GoString(appName),
		WindowTitle: C.GoString(windowTitle),
		Timestamp:   time.Now(),
	}

	select {
	case m.focusEvents <- event:
	default:
		// Channel full
	}
}

//export goWindowsChangeCallback
func goWindowsChangeCallback(path *C.char, eventType C.int) {
	windowsMonitorMu.RLock()
	m := currentWindowsMonitor
	windowsMonitorMu.RUnlock()

	if m == nil || !m.running {
		return
	}

	// Compute hash for the file
	goPath := C.GoString(path)
	var hash string
	var size int64
	if eventType != 3 { // Not deleted
		if h, s, err := defaultHashFile(goPath); err == nil {
			hash = h
			size = s
		}
	}

	event := ChangeEvent{
		Type:      ChangeEventType(eventType),
		Path:      goPath,
		Hash:      hash,
		Size:      size,
		Timestamp: time.Now(),
	}

	select {
	case m.changeEvents <- event:
	default:
		// Channel full
	}
}
