//go:build windows

package keystroke

import (
	"syscall"
	"unsafe"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	openClipboard    = user32.NewProc("OpenClipboard")
	closeClipboard   = user32.NewProc("CloseClipboard")
	getClipboardData = user32.NewProc("GetClipboardData")
	isClipboardFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")
	globalLock       = kernel32.NewProc("GlobalLock")
	globalUnlock     = kernel32.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	cfText        = 1
	cfBitmap      = 2
	cfHDROP       = 15
)

// windowsClipboardAccessor implements ClipboardAccessor for Windows.
type windowsClipboardAccessor struct{}

func newPlatformClipboardAccessor() ClipboardAccessor {
	return &windowsClipboardAccessor{}
}

func (w *windowsClipboardAccessor) GetText() (string, error) {
	ret, _, _ := openClipboard.Call(0)
	if ret == 0 {
		return "", nil
	}
	defer closeClipboard.Call()

	// Try Unicode first
	handle, _, _ := getClipboardData.Call(cfUnicodeText)
	if handle == 0 {
		// Fall back to ANSI
		handle, _, _ = getClipboardData.Call(cfText)
		if handle == 0 {
			return "", nil
		}
		return w.readANSI(handle)
	}

	return w.readUnicode(handle)
}

func (w *windowsClipboardAccessor) readUnicode(handle uintptr) (string, error) {
	ptr, _, _ := globalLock.Call(handle)
	if ptr == 0 {
		return "", nil
	}
	defer globalUnlock.Call(handle)

	// Read UTF-16 string
	var runes []uint16
	for i := 0; ; i++ {
		char := *(*uint16)(unsafe.Pointer(ptr + uintptr(i*2)))
		if char == 0 {
			break
		}
		runes = append(runes, char)
	}

	return syscall.UTF16ToString(runes), nil
}

func (w *windowsClipboardAccessor) readANSI(handle uintptr) (string, error) {
	ptr, _, _ := globalLock.Call(handle)
	if ptr == 0 {
		return "", nil
	}
	defer globalUnlock.Call(handle)

	// Read ANSI string
	var bytes []byte
	for i := 0; ; i++ {
		char := *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
		if char == 0 {
			break
		}
		bytes = append(bytes, char)
	}

	return string(bytes), nil
}

func (w *windowsClipboardAccessor) GetContentType() string {
	ret, _, _ := isClipboardFormatAvailable.Call(cfUnicodeText)
	if ret != 0 {
		return "text"
	}

	ret, _, _ = isClipboardFormatAvailable.Call(cfText)
	if ret != 0 {
		return "text"
	}

	ret, _, _ = isClipboardFormatAvailable.Call(cfBitmap)
	if ret != 0 {
		return "image"
	}

	ret, _, _ = isClipboardFormatAvailable.Call(cfHDROP)
	if ret != 0 {
		return "files"
	}

	return "unknown"
}

func (w *windowsClipboardAccessor) GetSourceApp() string {
	// Windows doesn't easily expose clipboard source
	return ""
}
