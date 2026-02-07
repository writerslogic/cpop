//go:build darwin

package sentinel

/*
#include <ApplicationServices/ApplicationServices.h>
*/
import "C"

//export sentinelFocusCallback
func sentinelFocusCallback(path, shadowID, bundleID, appName, windowTitle *C.char, eventType C.int) {
	darwinMonitorMu.RLock()
	m := currentDarwinMonitor
	darwinMonitorMu.RUnlock()

	if m == nil || !m.running {
		return
	}

	event := FocusEvent{
		Type:        FocusEventType(eventType),
		Path:        C.GoString(path),
		ShadowID:    C.GoString(shadowID),
		AppBundleID: C.GoString(bundleID),
		AppName:     C.GoString(appName),
		WindowTitle: C.GoString(windowTitle),
	}

	select {
	case m.focusEvents <- event:
	default:
		// Channel full, drop event
	}
}

//export sentinelChangeCallback
func sentinelChangeCallback(path *C.char, eventType C.int) {
	darwinMonitorMu.RLock()
	m := currentDarwinMonitor
	darwinMonitorMu.RUnlock()

	if m == nil || !m.running {
		return
	}

	event := ChangeEvent{
		Type: ChangeEventType(eventType),
		Path: C.GoString(path),
	}

	select {
	case m.changeEvents <- event:
	default:
		// Channel full, drop event
	}
}

//export sentinelSaveCallback
func sentinelSaveCallback(path *C.char) {
	darwinMonitorMu.RLock()
	m := currentDarwinMonitor
	darwinMonitorMu.RUnlock()

	if m == nil || !m.running {
		return
	}

	event := ChangeEvent{
		Type: ChangeSaved,
		Path: C.GoString(path),
	}

	select {
	case m.changeEvents <- event:
	default:
		// Channel full, drop event
	}
}
