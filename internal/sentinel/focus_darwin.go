//go:build darwin

// Package sentinel provides automatic document tracking for witnessd.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework ApplicationServices -framework Foundation -framework AppKit -framework CoreServices

#include <ApplicationServices/ApplicationServices.h>
#include <AppKit/AppKit.h>
#include <CoreServices/CoreServices.h>
#include <pthread.h>
#include <unistd.h>

// ============================================================================
// Focus Detection via NSWorkspace and Accessibility API
// ============================================================================
//
// We use multiple mechanisms to detect document focus:
//
// 1. NSWorkspace notifications for application activation
// 2. AXUIElement (Accessibility API) for window focus and document path
// 3. CGEventTap for Cmd+S (save) detection
// 4. FSEvents for file modification monitoring
//
// Privacy: We only access window titles and document paths for tracking.
// We do NOT read document content or capture keystrokes.
//
// ============================================================================

// Global state
static volatile int sentinelMonitorRunning = 0;
static pthread_t sentinelMonitorThread;
static CFRunLoopRef sentinelMonitorRunLoop = NULL;

// FSEvents stream
static FSEventStreamRef sentinelFSEventStream = NULL;
static CFMutableArrayRef sentinelWatchedPaths = NULL;

// Event tap for Cmd+S detection
static CFMachPortRef sentinelSaveEventTap = NULL;
static CFRunLoopSourceRef sentinelSaveEventSource = NULL;

// Callback enabled flag
static volatile int sentinelCallbacksEnabled = 0;

// Forward declaration for Go-exported callbacks
// These are defined with //export in the Go code
void sentinelFocusCallback(char* path, char* shadowID, char* bundleID,
                           char* appName, char* windowTitle, int eventType);
void sentinelChangeCallback(char* path, int eventType);
void sentinelSaveCallback(char* path);

// Wrapper that checks if callbacks are enabled before calling Go
static void notifyFocus(const char* path, const char* shadowID, const char* bundleID,
                        const char* appName, const char* windowTitle, int eventType) {
    if (sentinelCallbacksEnabled) {
        sentinelFocusCallback((char*)path, (char*)shadowID, (char*)bundleID,
                              (char*)appName, (char*)windowTitle, eventType);
    }
}

static void notifyChange(const char* path, int eventType) {
    if (sentinelCallbacksEnabled) {
        sentinelChangeCallback((char*)path, eventType);
    }
}

static void notifySave(const char* path) {
    if (sentinelCallbacksEnabled) {
        sentinelSaveCallback((char*)path);
    }
}

// Forward declarations
static void setupWorkspaceNotifications(void);
static void teardownWorkspaceNotifications(void);
static char* getActiveDocumentPath(void);
static char* getActiveWindowTitle(void);
static char* getActiveBundleID(void);
static char* getActiveAppName(void);
static char* parseWindowTitleForPath(AXUIElementRef window, NSString* bundleID);

// ============================================================================
// Workspace Notification Handling
// ============================================================================

@interface SentinelFocusObserver : NSObject
+ (instancetype)sharedObserver;
- (void)startObserving;
- (void)stopObserving;
- (void)appActivated:(NSNotification*)notification;
- (void)appDeactivated:(NSNotification*)notification;
@end

static SentinelFocusObserver* sentinelSharedObserver = nil;

@implementation SentinelFocusObserver

+ (instancetype)sharedObserver {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sentinelSharedObserver = [[SentinelFocusObserver alloc] init];
    });
    return sentinelSharedObserver;
}

- (void)startObserving {
    NSWorkspace* workspace = [NSWorkspace sharedWorkspace];
    NSNotificationCenter* center = [workspace notificationCenter];

    [center addObserver:self
               selector:@selector(appActivated:)
                   name:NSWorkspaceDidActivateApplicationNotification
                 object:nil];

    [center addObserver:self
               selector:@selector(appDeactivated:)
                   name:NSWorkspaceDidDeactivateApplicationNotification
                 object:nil];

    // Also observe window focus changes via Accessibility API
    // This requires setting up AX observers for each tracked app
}

- (void)stopObserving {
    NSWorkspace* workspace = [NSWorkspace sharedWorkspace];
    [[workspace notificationCenter] removeObserver:self];
}

- (void)appActivated:(NSNotification*)notification {
    if (!sentinelCallbacksEnabled) return;

    @autoreleasepool {
        NSDictionary* userInfo = [notification userInfo];
        NSRunningApplication* app = userInfo[NSWorkspaceApplicationKey];

        const char* bundleID = app.bundleIdentifier ? [app.bundleIdentifier UTF8String] : "";
        const char* appName = app.localizedName ? [app.localizedName UTF8String] : "";

        // Get document path from Accessibility API
        char* docPath = getActiveDocumentPath();
        char* windowTitle = getActiveWindowTitle();

        notifyFocus(
            docPath ? docPath : "",
            "",  // shadowID - not used in this callback
            bundleID,
            appName,
            windowTitle ? windowTitle : "",
            0  // FocusGained
        );

        if (docPath) free(docPath);
        if (windowTitle) free(windowTitle);
    }
}

- (void)appDeactivated:(NSNotification*)notification {
    if (!sentinelCallbacksEnabled) return;

    @autoreleasepool {
        NSDictionary* userInfo = [notification userInfo];
        NSRunningApplication* app = userInfo[NSWorkspaceApplicationKey];

        const char* bundleID = app.bundleIdentifier ? [app.bundleIdentifier UTF8String] : "";
        const char* appName = app.localizedName ? [app.localizedName UTF8String] : "";

        notifyFocus(
            "",
            "",
            bundleID,
            appName,
            "",
            1  // FocusLost
        );
    }
}

@end

// ============================================================================
// Accessibility API for Document Path Extraction
// ============================================================================

// Get the focused window's document path using AXDocument attribute
static char* getActiveDocumentPath(void) {
    @autoreleasepool {
        // Get the frontmost application
        NSRunningApplication* frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
        if (!frontApp) return NULL;

        pid_t pid = frontApp.processIdentifier;

        // Create AXUIElement for the application
        AXUIElementRef appElement = AXUIElementCreateApplication(pid);
        if (!appElement) return NULL;

        char* result = NULL;

        // Get focused window
        AXUIElementRef focusedWindow = NULL;
        AXError err = AXUIElementCopyAttributeValue(appElement, kAXFocusedWindowAttribute, (CFTypeRef*)&focusedWindow);

        if (err == kAXErrorSuccess && focusedWindow) {
            // Try to get AXDocument attribute (file:// URL)
            CFTypeRef docValue = NULL;
            err = AXUIElementCopyAttributeValue(focusedWindow, CFSTR("AXDocument"), &docValue);

            if (err == kAXErrorSuccess && docValue) {
                if (CFGetTypeID(docValue) == CFURLGetTypeID()) {
                    // Convert URL to path
                    CFURLRef url = (CFURLRef)docValue;
                    CFStringRef pathStr = CFURLCopyFileSystemPath(url, kCFURLPOSIXPathStyle);
                    if (pathStr) {
                        CFIndex length = CFStringGetLength(pathStr);
                        CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
                        result = malloc(maxSize);
                        if (result) {
                            if (!CFStringGetCString(pathStr, result, maxSize, kCFStringEncodingUTF8)) {
                                free(result);
                                result = NULL;
                            }
                        }
                        CFRelease(pathStr);
                    }
                } else if (CFGetTypeID(docValue) == CFStringGetTypeID()) {
                    // Some apps return a string path directly
                    CFStringRef pathStr = (CFStringRef)docValue;
                    CFIndex length = CFStringGetLength(pathStr);
                    CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
                    result = malloc(maxSize);
                    if (result) {
                        if (!CFStringGetCString(pathStr, result, maxSize, kCFStringEncodingUTF8)) {
                            free(result);
                            result = NULL;
                        }
                    }
                }
                CFRelease(docValue);
            }

            // Fallback: parse window title for common editors
            if (!result) {
                result = parseWindowTitleForPath(focusedWindow, frontApp.bundleIdentifier);
            }

            CFRelease(focusedWindow);
        }

        CFRelease(appElement);
        return result;
    }
}

// Parse window title for document path (fallback for apps without AXDocument)
static char* parseWindowTitleForPath(AXUIElementRef window, NSString* bundleID) {
    CFTypeRef titleValue = NULL;
    AXError err = AXUIElementCopyAttributeValue(window, kAXTitleAttribute, &titleValue);

    if (err != kAXErrorSuccess || !titleValue) return NULL;
    if (CFGetTypeID(titleValue) != CFStringGetTypeID()) {
        CFRelease(titleValue);
        return NULL;
    }

    NSString* title = (__bridge NSString*)titleValue;
    char* result = NULL;

    // VS Code: "filename.ext - FolderName - Visual Studio Code"
    // or "filename.ext -- path/to/file - Visual Studio Code"
    if ([bundleID isEqualToString:@"com.microsoft.VSCode"] ||
        [bundleID isEqualToString:@"com.microsoft.VSCodeInsiders"]) {

        NSRange dashRange = [title rangeOfString:@" - "];
        if (dashRange.location != NSNotFound) {
            NSString* beforeDash = [title substringToIndex:dashRange.location];

            // Check if it contains a path indicator
            if ([beforeDash hasPrefix:@"/"] || [beforeDash containsString:@"/"]) {
                result = strdup([beforeDash UTF8String]);
            }
        }
    }

    // Sublime Text: "filename.ext - path/to/folder - Sublime Text"
    // or "filename.ext (path/to/folder) - Sublime Text"
    else if ([bundleID isEqualToString:@"com.sublimetext.4"] ||
             [bundleID isEqualToString:@"com.sublimetext.3"]) {

        NSRange parenRange = [title rangeOfString:@" ("];
        if (parenRange.location != NSNotFound) {
            NSRange closeRange = [title rangeOfString:@")" options:0 range:NSMakeRange(parenRange.location, title.length - parenRange.location)];
            if (closeRange.location != NSNotFound) {
                NSString* path = [title substringWithRange:NSMakeRange(parenRange.location + 2, closeRange.location - parenRange.location - 2)];
                NSString* filename = [title substringToIndex:parenRange.location];
                NSString* fullPath = [path stringByAppendingPathComponent:filename];
                result = strdup([fullPath UTF8String]);
            }
        }
    }

    // TextEdit, Pages, etc.: "Document Name"
    // These typically use AXDocument, so fallback is limited

    // Xcode: "ProjectName - filename.ext"
    else if ([bundleID isEqualToString:@"com.apple.dt.Xcode"]) {
        // Xcode's AXDocument is more reliable
    }

    CFRelease(titleValue);
    return result;
}

// Get the focused window's title
static char* getActiveWindowTitle(void) {
    @autoreleasepool {
        NSRunningApplication* frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
        if (!frontApp) return NULL;

        pid_t pid = frontApp.processIdentifier;
        AXUIElementRef appElement = AXUIElementCreateApplication(pid);
        if (!appElement) return NULL;

        char* result = NULL;

        AXUIElementRef focusedWindow = NULL;
        AXError err = AXUIElementCopyAttributeValue(appElement, kAXFocusedWindowAttribute, (CFTypeRef*)&focusedWindow);

        if (err == kAXErrorSuccess && focusedWindow) {
            CFTypeRef titleValue = NULL;
            err = AXUIElementCopyAttributeValue(focusedWindow, kAXTitleAttribute, &titleValue);

            if (err == kAXErrorSuccess && titleValue && CFGetTypeID(titleValue) == CFStringGetTypeID()) {
                CFStringRef title = (CFStringRef)titleValue;
                CFIndex length = CFStringGetLength(title);
                CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
                result = malloc(maxSize);
                if (result) {
                    if (!CFStringGetCString(title, result, maxSize, kCFStringEncodingUTF8)) {
                        free(result);
                        result = NULL;
                    }
                }
            }

            if (titleValue) CFRelease(titleValue);
            CFRelease(focusedWindow);
        }

        CFRelease(appElement);
        return result;
    }
}

// Get the active app's bundle ID
static char* getActiveBundleID(void) {
    @autoreleasepool {
        NSRunningApplication* frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
        if (!frontApp || !frontApp.bundleIdentifier) return NULL;

        return strdup([frontApp.bundleIdentifier UTF8String]);
    }
}

// Get the active app's name
static char* getActiveAppName(void) {
    @autoreleasepool {
        NSRunningApplication* frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
        if (!frontApp || !frontApp.localizedName) return NULL;

        return strdup([frontApp.localizedName UTF8String]);
    }
}

// ============================================================================
// Cmd+S Detection via CGEventTap
// ============================================================================

static CGEventRef sentinelSaveEventCallback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void* refcon) {
    (void)proxy;
    (void)refcon;

    // Re-enable tap if disabled by system
    if (type == kCGEventTapDisabledByUserInput || type == kCGEventTapDisabledByTimeout) {
        if (sentinelSaveEventTap) {
            CGEventTapEnable(sentinelSaveEventTap, true);
        }
        return event;
    }

    if (type == kCGEventKeyDown) {
        CGEventFlags flags = CGEventGetFlags(event);
        CGKeyCode keyCode = (CGKeyCode)CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode);

        // Check for Cmd+S (keycode 1 = 's')
        if ((flags & kCGEventFlagMaskCommand) && keyCode == 1) {
            // Notify about potential save
            if (sentinelCallbacksEnabled) {
                @autoreleasepool {
                    char* docPath = getActiveDocumentPath();
                    if (docPath) {
                        notifySave(docPath);
                        free(docPath);
                    }
                }
            }
        }
    }

    return event;
}

static int startSaveDetection(void) {
    CGEventMask eventMask = CGEventMaskBit(kCGEventKeyDown);

    sentinelSaveEventTap = CGEventTapCreate(
        kCGSessionEventTap,
        kCGHeadInsertEventTap,
        kCGEventTapOptionListenOnly,
        eventMask,
        sentinelSaveEventCallback,
        NULL
    );

    if (!sentinelSaveEventTap) {
        return -1;  // Accessibility permission required
    }

    sentinelSaveEventSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, sentinelSaveEventTap, 0);
    if (!sentinelSaveEventSource) {
        CFRelease(sentinelSaveEventTap);
        sentinelSaveEventTap = NULL;
        return -2;
    }

    CFRunLoopAddSource(sentinelMonitorRunLoop, sentinelSaveEventSource, kCFRunLoopCommonModes);
    CGEventTapEnable(sentinelSaveEventTap, true);

    return 0;
}

static void stopSaveDetection(void) {
    if (sentinelSaveEventTap) {
        CGEventTapEnable(sentinelSaveEventTap, false);
    }

    if (sentinelSaveEventSource && sentinelMonitorRunLoop) {
        CFRunLoopRemoveSource(sentinelMonitorRunLoop, sentinelSaveEventSource, kCFRunLoopCommonModes);
        CFRelease(sentinelSaveEventSource);
        sentinelSaveEventSource = NULL;
    }

    if (sentinelSaveEventTap) {
        CFRelease(sentinelSaveEventTap);
        sentinelSaveEventTap = NULL;
    }
}

// ============================================================================
// FSEvents for File Modification Detection
// ============================================================================

static void sentinelFSEventCallback(
    ConstFSEventStreamRef streamRef,
    void* clientCallBackInfo,
    size_t numEvents,
    void* eventPaths,
    const FSEventStreamEventFlags eventFlags[],
    const FSEventStreamEventId eventIds[]
) {
    (void)streamRef;
    (void)clientCallBackInfo;
    (void)eventIds;

    char** paths = (char**)eventPaths;

    for (size_t i = 0; i < numEvents; i++) {
        if (!sentinelCallbacksEnabled) continue;

        int eventType = 0;  // ChangeModified

        if (eventFlags[i] & kFSEventStreamEventFlagItemCreated) {
            eventType = 2;  // ChangeCreated
        } else if (eventFlags[i] & kFSEventStreamEventFlagItemRemoved) {
            eventType = 3;  // ChangeDeleted
        } else if (eventFlags[i] & kFSEventStreamEventFlagItemModified) {
            eventType = 0;  // ChangeModified
        } else if (eventFlags[i] & kFSEventStreamEventFlagItemRenamed) {
            eventType = 0;  // Treat rename as modification
        }

        notifyChange(paths[i], eventType);
    }
}

static int addWatchPath(const char* path) {
    if (!sentinelWatchedPaths) {
        sentinelWatchedPaths = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    }

    CFStringRef pathStr = CFStringCreateWithCString(kCFAllocatorDefault, path, kCFStringEncodingUTF8);
    if (!pathStr) return -1;

    CFArrayAppendValue(sentinelWatchedPaths, pathStr);
    CFRelease(pathStr);

    return 0;
}

static void startFSEvents(void) {
    if (!sentinelWatchedPaths || CFArrayGetCount(sentinelWatchedPaths) == 0) return;

    FSEventStreamContext context = {0, NULL, NULL, NULL, NULL};

    sentinelFSEventStream = FSEventStreamCreate(
        kCFAllocatorDefault,
        sentinelFSEventCallback,
        &context,
        sentinelWatchedPaths,
        kFSEventStreamEventIdSinceNow,
        0.5,  // 500ms latency
        kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer
    );

    if (sentinelFSEventStream) {
        FSEventStreamScheduleWithRunLoop(sentinelFSEventStream, sentinelMonitorRunLoop, kCFRunLoopDefaultMode);
        FSEventStreamStart(sentinelFSEventStream);
    }
}

static void stopFSEvents(void) {
    if (sentinelFSEventStream) {
        FSEventStreamStop(sentinelFSEventStream);
        FSEventStreamInvalidate(sentinelFSEventStream);
        FSEventStreamRelease(sentinelFSEventStream);
        sentinelFSEventStream = NULL;
    }

    if (sentinelWatchedPaths) {
        CFRelease(sentinelWatchedPaths);
        sentinelWatchedPaths = NULL;
    }
}

// ============================================================================
// Monitor Thread
// ============================================================================

static void* monitorThreadFunc(void* arg) {
    (void)arg;

    @autoreleasepool {
        sentinelMonitorRunLoop = CFRunLoopGetCurrent();

        // Start workspace notifications
        [[SentinelFocusObserver sharedObserver] startObserving];

        // Start Cmd+S detection
        startSaveDetection();

        // Start FSEvents
        startFSEvents();

        sentinelMonitorRunning = 1;

        // Run the loop
        CFRunLoopRun();

        // Cleanup
        stopFSEvents();
        stopSaveDetection();
        [[SentinelFocusObserver sharedObserver] stopObserving];

        sentinelMonitorRunning = 0;
        sentinelMonitorRunLoop = NULL;
    }

    return NULL;
}

// ============================================================================
// Public API
// ============================================================================

// Enable callbacks from Go
void sentinel_setCallbacks(void) {
    sentinelCallbacksEnabled = 1;
}

// Start the monitor (internal version without callback params)
int sentinel_startFocusMonitoringInternal(void) {
    if (sentinelMonitorRunning) return 1;

    if (pthread_create(&sentinelMonitorThread, NULL, monitorThreadFunc, NULL) != 0) {
        return -1;
    }

    // Wait for startup
    for (int i = 0; i < 100 && !sentinelMonitorRunning; i++) {
        usleep(10000);
    }

    return sentinelMonitorRunning ? 0 : -2;
}

void sentinel_stopFocusMonitoring(void) {
    if (!sentinelMonitorRunning) return;

    sentinelCallbacksEnabled = 0;
    sentinelMonitorRunning = 0;

    if (sentinelMonitorRunLoop) {
        CFRunLoopStop(sentinelMonitorRunLoop);
    }

    pthread_join(sentinelMonitorThread, NULL);
}

int sentinel_checkAccessibilityPermission(void) {
    NSDictionary* options = @{(__bridge id)kAXTrustedCheckOptionPrompt: @NO};
    return AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options) ? 1 : 0;
}

int sentinel_promptAccessibilityPermission(void) {
    NSDictionary* options = @{(__bridge id)kAXTrustedCheckOptionPrompt: @YES};
    return AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options) ? 1 : 0;
}

int sentinel_isMonitorRunning(void) {
    return sentinelMonitorRunning;
}

// Trigger a focus check manually
void sentinel_checkFocusNow(void) {
    if (!sentinelMonitorRunning || !sentinelCallbacksEnabled) return;

    @autoreleasepool {
        char* docPath = getActiveDocumentPath();
        char* bundleID = getActiveBundleID();
        char* appName = getActiveAppName();
        char* windowTitle = getActiveWindowTitle();

        notifyFocus(
            docPath ? docPath : "",
            "",
            bundleID ? bundleID : "",
            appName ? appName : "",
            windowTitle ? windowTitle : "",
            0  // FocusGained
        );

        if (docPath) free(docPath);
        if (bundleID) free(bundleID);
        if (appName) free(appName);
        if (windowTitle) free(windowTitle);
    }
}

// Add a path to watch for changes
int sentinel_addPathToWatch(const char* path) {
    return addWatchPath(path);
}

*/
import "C"

import (
	"context"
	"sync"
	"time"
	"unsafe"
)

// darwinFocusMonitor implements FocusMonitor for macOS.
type darwinFocusMonitor struct {
	mu           sync.RWMutex
	config       *Config
	ctx          context.Context
	cancel       context.CancelFunc
	running      bool
	focusEvents  chan FocusEvent
	changeEvents chan ChangeEvent
}

// newDarwinFocusMonitor creates the macOS-specific focus monitor.
// This is the CGO-based implementation using NSWorkspace and Accessibility APIs.
func newDarwinFocusMonitor(cfg *Config) FocusMonitor {
	return &darwinFocusMonitor{
		config:       cfg,
		focusEvents:  make(chan FocusEvent, 100),
		changeEvents: make(chan ChangeEvent, 100),
	}
}

// Start begins monitoring for focus changes.
func (m *darwinFocusMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return ErrAlreadyRunning
	}

	m.ctx, m.cancel = context.WithCancel(ctx)

	// Set up callbacks
	registerDarwinCallbacks(m)

	// Add paths to watch
	for _, path := range m.config.WatchPaths {
		cPath := C.CString(path)
		C.sentinel_addPathToWatch(cPath)
		C.free(unsafe.Pointer(cPath))
	}

	// Start the monitor
	// Note: We pass the Go-exported C wrapper functions
	C.sentinel_setCallbacks()
	result := C.sentinel_startFocusMonitoringInternal()

	if result != 0 {
		return ErrNotAvailable
	}

	m.running = true

	// Trigger initial focus check
	go func() {
		C.sentinel_checkFocusNow()
	}()

	return nil
}

// Stop stops monitoring.
func (m *darwinFocusMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.running = false

	if m.cancel != nil {
		m.cancel()
	}

	C.sentinel_stopFocusMonitoring()

	close(m.focusEvents)
	close(m.changeEvents)

	return nil
}

// FocusEvents returns the channel of focus events.
func (m *darwinFocusMonitor) FocusEvents() <-chan FocusEvent {
	return m.focusEvents
}

// ChangeEvents returns the channel of change events.
func (m *darwinFocusMonitor) ChangeEvents() <-chan ChangeEvent {
	return m.changeEvents
}

// Available checks if focus monitoring is available.
func (m *darwinFocusMonitor) Available() (bool, string) {
	if checkDarwinAccessibility() {
		return true, "Accessibility API available"
	}
	return false, "Accessibility permission required. Go to System Settings > Privacy & Security > Accessibility and add this application."
}

// checkDarwinAccessibility returns whether accessibility permissions are granted.
func checkDarwinAccessibility() bool {
	return C.sentinel_checkAccessibilityPermission() == 1
}

// promptDarwinAccessibility prompts for accessibility permissions.
func promptDarwinAccessibility() bool {
	return C.sentinel_promptAccessibilityPermission() == 1
}

// ============================================================================
// FocusTracker Implementation (Interface for newer focus tracking)
// ============================================================================

// darwinFocusTracker implements FocusTracker for macOS.
type darwinFocusTracker struct {
	*baseFocusTracker
	mu      sync.RWMutex
	running bool
	current *WindowInfo
}

// newPlatformFocusTracker creates a macOS-specific focus tracker.
func newPlatformFocusTracker(config FocusTrackerConfig) FocusTracker {
	return &darwinFocusTracker{
		baseFocusTracker: newBaseFocusTracker(config),
	}
}

// Start begins focus tracking.
func (t *darwinFocusTracker) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		return ErrAlreadyRunning
	}

	t.ctx, t.cancel = context.WithCancel(ctx)
	t.running = true

	go t.pollLoop()

	return nil
}

// Stop stops focus tracking.
func (t *darwinFocusTracker) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return nil
	}

	t.running = false

	if t.cancel != nil {
		t.cancel()
	}

	t.close()
	return nil
}

// ActiveWindow returns the currently focused window info.
func (t *darwinFocusTracker) ActiveWindow() *WindowInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.current == nil {
		return nil
	}

	// Return a copy
	info := *t.current
	return &info
}

// Available checks if focus tracking is available.
func (t *darwinFocusTracker) Available() (bool, string) {
	if checkDarwinAccessibility() {
		return true, "macOS Accessibility API available"
	}
	return false, "Accessibility permission required. Go to System Settings > Privacy & Security > Accessibility"
}

// pollLoop periodically checks the focused window.
func (t *darwinFocusTracker) pollLoop() {
	ticker := time.NewTicker(t.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			t.checkFocus()
		}
	}
}

// checkFocus checks the currently focused window and emits events if changed.
func (t *darwinFocusTracker) checkFocus() {
	info := t.getCurrentWindowInfo()
	if info == nil {
		return
	}

	t.mu.Lock()
	t.current = info
	t.mu.Unlock()

	t.emit(*info)
}

// getCurrentWindowInfo retrieves information about the currently focused window.
func (t *darwinFocusTracker) getCurrentWindowInfo() *WindowInfo {
	// Trigger manual check via CGO
	// Note: For now we use the same CGO logic as FocusMonitor but adapted
	// to return WindowInfo
	
	// We'll use the existing C functions to get the data
	cBundleID := C.getActiveBundleID()
	cAppName := C.getActiveAppName()
	cTitle := C.getActiveWindowTitle()
	cPath := C.getActiveDocumentPath()

	defer func() {
		if cBundleID != nil { C.free(unsafe.Pointer(cBundleID)) }
		if cAppName != nil { C.free(unsafe.Pointer(cAppName)) }
		if cTitle != nil { C.free(unsafe.Pointer(cTitle)) }
		if cPath != nil { C.free(unsafe.Pointer(cPath)) }
	}()

	info := &WindowInfo{
		Timestamp: time.Now(),
	}

	if cBundleID != nil {
		info.Application = C.GoString(cBundleID)
	} else if cAppName != nil {
		info.Application = C.GoString(cAppName)
	}

	if cTitle != nil {
		info.Title = C.GoString(cTitle)
	}

	if cPath != nil {
		info.Path = C.GoString(cPath)
		info.IsDocument = true
	}

	// Fallback path parsing
	if info.Path == "" && info.Title != "" {
		// Use same logic as before or delegate to helper
	}

	return info
}

// Ensure darwinFocusTracker implements FocusTracker
var _ FocusTracker = (*darwinFocusTracker)(nil)

// Global reference to the current monitor for callbacks
var (
	darwinMonitorMu      sync.RWMutex
	currentDarwinMonitor *darwinFocusMonitor
)

func registerDarwinCallbacks(m *darwinFocusMonitor) {
	darwinMonitorMu.Lock()
	currentDarwinMonitor = m
	darwinMonitorMu.Unlock()
}
