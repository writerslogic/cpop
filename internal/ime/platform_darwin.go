//go:build darwin

package ime

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Carbon -framework Foundation

#include <Carbon/Carbon.h>
#include <Foundation/Foundation.h>

// Get current input source ID
const char* getCurrentInputSourceID() {
    TISInputSourceRef currentSource = TISCopyCurrentKeyboardInputSource();
    if (currentSource == NULL) {
        return NULL;
    }

    CFStringRef sourceID = (CFStringRef)TISGetInputSourceProperty(currentSource, kTISPropertyInputSourceID);
    if (sourceID == NULL) {
        CFRelease(currentSource);
        return NULL;
    }

    const char* result = NULL;
    CFIndex length = CFStringGetLength(sourceID);
    CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
    char* buffer = malloc(maxSize);
    if (buffer != NULL && CFStringGetCString(sourceID, buffer, maxSize, kCFStringEncodingUTF8)) {
        result = buffer;
    }

    CFRelease(currentSource);
    return result;
}

// Free string allocated by getCurrentInputSourceID
void freeString(const char* str) {
    if (str != NULL) {
        free((void*)str);
    }
}

// Check if an input source with the given bundle ID exists
int inputSourceExists(const char* bundleID) {
    CFStringRef bundleIDRef = CFStringCreateWithCString(NULL, bundleID, kCFStringEncodingUTF8);
    if (bundleIDRef == NULL) {
        return 0;
    }

    CFMutableDictionaryRef filterDict = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(filterDict, kTISPropertyBundleID, bundleIDRef);

    CFArrayRef sources = TISCreateInputSourceList(filterDict, true);

    int exists = sources != NULL && CFArrayGetCount(sources) > 0;

    if (sources != NULL) {
        CFRelease(sources);
    }
    CFRelease(filterDict);
    CFRelease(bundleIDRef);

    return exists;
}

// Enable an input source (add to enabled list)
int enableInputSource(const char* bundleID) {
    CFStringRef bundleIDRef = CFStringCreateWithCString(NULL, bundleID, kCFStringEncodingUTF8);
    if (bundleIDRef == NULL) {
        return -1;
    }

    CFMutableDictionaryRef filterDict = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(filterDict, kTISPropertyBundleID, bundleIDRef);

    CFArrayRef sources = TISCreateInputSourceList(filterDict, true);
    int result = -1;

    if (sources != NULL && CFArrayGetCount(sources) > 0) {
        TISInputSourceRef source = (TISInputSourceRef)CFArrayGetValueAtIndex(sources, 0);
        if (TISEnableInputSource(source) == noErr) {
            result = 0;
        }
    }

    if (sources != NULL) {
        CFRelease(sources);
    }
    CFRelease(filterDict);
    CFRelease(bundleIDRef);

    return result;
}

// Select (activate) an input source
int selectInputSource(const char* bundleID) {
    CFStringRef bundleIDRef = CFStringCreateWithCString(NULL, bundleID, kCFStringEncodingUTF8);
    if (bundleIDRef == NULL) {
        return -1;
    }

    CFMutableDictionaryRef filterDict = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(filterDict, kTISPropertyBundleID, bundleIDRef);

    CFArrayRef sources = TISCreateInputSourceList(filterDict, false);
    int result = -1;

    if (sources != NULL && CFArrayGetCount(sources) > 0) {
        TISInputSourceRef source = (TISInputSourceRef)CFArrayGetValueAtIndex(sources, 0);
        if (TISSelectInputSource(source) == noErr) {
            result = 0;
        }
    }

    if (sources != NULL) {
        CFRelease(sources);
    }
    CFRelease(filterDict);
    CFRelease(bundleIDRef);

    return result;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"
)

// DarwinPlatform implements the Platform interface for macOS.
// Uses Input Method Kit (IMKit) framework.
type DarwinPlatform struct {
	config PlatformConfig
	engine *Engine
}

// NewDarwinPlatform creates a new macOS IME platform.
func NewDarwinPlatform(config PlatformConfig, engine *Engine) *DarwinPlatform {
	if config.BundleID == "" {
		config.BundleID = "com.witnessd.inputmethod"
	}
	if config.DisplayName == "" {
		config.DisplayName = "Witnessd"
	}
	return &DarwinPlatform{
		config: config,
		engine: engine,
	}
}

func (p *DarwinPlatform) Name() string {
	return "macos"
}

func (p *DarwinPlatform) Available() bool {
	return true
}

// Install creates the input method bundle and registers it.
func (p *DarwinPlatform) Install() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	installDir := filepath.Join(home, "Library", "Input Methods")
	bundlePath := filepath.Join(installDir, "Witnessd.app")

	// Create bundle structure
	dirs := []string{
		filepath.Join(bundlePath, "Contents", "MacOS"),
		filepath.Join(bundlePath, "Contents", "Resources"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	// Create Info.plist
	plistPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	plist := p.generateInfoPlist()
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return err
	}

	// Find and copy the IME binary
	execPath, err := p.findIMEBinary()
	if err != nil {
		return fmt.Errorf("failed to find IME binary: %w", err)
	}

	destExec := filepath.Join(bundlePath, "Contents", "MacOS", "Witnessd")
	if err := copyFile(execPath, destExec); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}
	if err := os.Chmod(destExec, 0755); err != nil {
		return err
	}

	// Register with Launch Services to refresh input method list
	p.refreshInputMethods(bundlePath)

	return nil
}

func (p *DarwinPlatform) findIMEBinary() (string, error) {
	// Look for witnessd-ime binary first
	candidates := []string{
		"/usr/local/bin/witnessd-ime",
		"/opt/homebrew/bin/witnessd-ime",
	}

	// Check relative to current executable
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		candidates = append([]string{
			filepath.Join(execDir, "witnessd-ime"),
		}, candidates...)
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// Fall back to current executable
	return os.Executable()
}

func (p *DarwinPlatform) refreshInputMethods(bundlePath string) {
	// Touch the bundle to trigger LaunchServices refresh
	exec.Command("touch", bundlePath).Run()

	// Register with lsregister
	exec.Command("/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
		"-f", bundlePath).Run()
}

func (p *DarwinPlatform) Uninstall() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	bundlePath := filepath.Join(home, "Library", "Input Methods", "Witnessd.app")
	return os.RemoveAll(bundlePath)
}

func (p *DarwinPlatform) IsInstalled() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	bundlePath := filepath.Join(home, "Library", "Input Methods", "Witnessd.app")
	_, err = os.Stat(bundlePath)
	if err != nil {
		return false
	}

	// Also check if registered with the system
	bundleID := C.CString(p.config.BundleID)
	defer C.free(unsafe.Pointer(bundleID))
	return C.inputSourceExists(bundleID) == 1
}

func (p *DarwinPlatform) IsActive() bool {
	currentID := C.getCurrentInputSourceID()
	if currentID == nil {
		return false
	}
	defer C.freeString(currentID)

	goID := C.GoString(currentID)
	return strings.Contains(goID, "witnessd") || strings.Contains(goID, p.config.BundleID)
}

func (p *DarwinPlatform) Activate() error {
	bundleID := C.CString(p.config.BundleID)
	defer C.free(unsafe.Pointer(bundleID))

	// First, enable the input source if not enabled
	C.enableInputSource(bundleID)

	// Then select it
	if C.selectInputSource(bundleID) != 0 {
		// Open System Preferences as fallback
		exec.Command("open", "x-apple.systempreferences:com.apple.preference.keyboard?Text").Run()
		return errors.New("please select Witnessd from Keyboard settings")
	}

	return nil
}

func (p *DarwinPlatform) generateInfoPlist() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleDisplayName</key>
    <string>` + p.config.DisplayName + `</string>
    <key>CFBundleExecutable</key>
    <string>Witnessd</string>
    <key>CFBundleIdentifier</key>
    <string>` + p.config.BundleID + `</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Witnessd</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSBackgroundOnly</key>
    <true/>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
    <key>InputMethodConnectionName</key>
    <string>` + p.config.BundleID + `_Connection</string>
    <key>InputMethodServerControllerClass</key>
    <string>WitnessdInputController</string>
    <key>tsInputMethodCharacterRepertoireKey</key>
    <array>
        <string>Latn</string>
    </array>
    <key>tsInputMethodIconFileKey</key>
    <string>icon</string>
    <key>TISInputSourceID</key>
    <string>` + p.config.BundleID + `</string>
    <key>TISIntendedLanguage</key>
    <string>en</string>
</dict>
</plist>`
}

// DarwinZoneMapping provides macOS-specific keycode mapping.
// macOS uses virtual key codes defined in Carbon/HIToolbox/Events.h
type DarwinZoneMapping struct{}

func (DarwinZoneMapping) KeyCodeToZone(keyCode uint16) int {
	// macOS virtual key codes (same as jitter package)
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

func (DarwinZoneMapping) CharToZone(char rune) int {
	return zoneFromChar(char)
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// Ensure DarwinPlatform implements Platform
var _ Platform = (*DarwinPlatform)(nil)
