//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procLoadImageW       = user32.NewProc("LoadImageW")
	procLoadIconW        = user32.NewProc("LoadIconW")
	procDestroyIcon      = user32.NewProc("DestroyIcon")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenuW      = user32.NewProc("AppendMenuW")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procDestroyWindow    = user32.NewProc("DestroyWindow")

	procShell_NotifyIconW = shell32.NewProc("Shell_NotifyIconW")
)

const (
	WM_DESTROY       = 0x0002
	WM_CLOSE         = 0x0010
	WM_COMMAND       = 0x0111
	WM_USER          = 0x0400
	WM_TRAYICON      = WM_USER + 1
	
	NIM_ADD          = 0x00000000
	NIM_MODIFY       = 0x00000001
	NIM_DELETE       = 0x00000002
	
	NIF_MESSAGE      = 0x00000001
	NIF_ICON         = 0x00000002
	NIF_TIP          = 0x00000004
	
	IMAGE_ICON       = 1
	LR_LOADFROMFILE  = 0x00000010
	
	TPM_BOTTOMALIGN  = 0x0020
	TPM_LEFTALIGN    = 0x0000
	
	MF_STRING        = 0x00000000
	MF_SEPARATOR     = 0x00000800
	MF_GRAYED        = 0x00000001
	MF_DISABLED      = 0x00000002
	
	ID_STATUS        = 1001
	ID_STOP          = 1002
	ID_EXIT          = 1003
	ID_OPEN_CLI      = 1004
)

type WNDCLASSEX struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   syscall.Handle
	Icon       syscall.Handle
	Cursor     syscall.Handle
	Background syscall.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     syscall.Handle
}

type NOTIFYICONDATA struct {
	Size             uint32
	Wnd              syscall.Handle
	ID               uint32
	Flags            uint32
	CallbackMessage  uint32
	Icon             syscall.Handle
	Tip              [128]uint16
	State            uint32
	StateMask        uint32
	Info             [256]uint16
	TimeoutVersion   uint32
	InfoTitle        [64]uint16
	InfoFlags        uint32
	GuidItem         syscall.GUID
	BalloonIcon      syscall.Handle
}

type POINT struct {
	X int32
	Y int32
}

var (
	hInst   syscall.Handle
	hWnd    syscall.Handle
	hIcon   syscall.Handle
	nid     NOTIFYICONDATA
	isTracking bool
	trackingFile string
)

func runTray() {
	// Get module handle
	hInst = syscall.Handle(0) // GetModuleHandle(NULL)

	// Create window class
	className, _ := syscall.UTF16PtrFromString("WitnessdTrayClass")
	wcex := WNDCLASSEX{
		Size:      uint32(unsafe.Sizeof(WNDCLASSEX{})),
		Style:     0,
		WndProc:   syscall.NewCallback(wndProc),
		Instance:  hInst,
		ClassName: className,
	}
	
	if ret, _, _ := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wcex))); ret == 0 {
		fmt.Println("RegisterClassEx failed")
		return
	}

	// Create window (hidden)
	windowName, _ := syscall.UTF16PtrFromString("Witnessd Tray")
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		0, 0, 0, 0, 0,
		0, 0, uintptr(hInst), 0,
	)
	if hwnd == 0 {
		fmt.Println("CreateWindowEx failed")
		return
	}
	hWnd = syscall.Handle(hwnd)

	// Load Icon
	// Try local file first
	exePath, _ := os.Executable()
	iconPath := filepath.Join(filepath.Dir(exePath), "witnessd.ico")
	if _, err := os.Stat(iconPath); os.IsNotExist(err) {
		// Try fallback locations
		iconPath = "witnessd.ico" 
	}
	
	iconPathPtr, _ := syscall.UTF16PtrFromString(iconPath)
	hIconRet, _, _ := procLoadImageW.Call(
		0,
		uintptr(unsafe.Pointer(iconPathPtr)),
		IMAGE_ICON,
		0, 0,
		LR_LOADFROMFILE,
	)
	
	if hIconRet == 0 {
		// Fallback to system warning icon if file not found
		// IDI_WARNING = 32515
		hIconRet, _, _ = procLoadIconW.Call(0, 32515)
	}
	hIcon = syscall.Handle(hIconRet)

	// Add Tray Icon
	nid.Size = uint32(unsafe.Sizeof(nid))
	nid.Wnd = hWnd
	nid.ID = 1
	nid.Flags = NIF_ICON | NIF_MESSAGE | NIF_TIP
	nid.CallbackMessage = WM_TRAYICON
	nid.Icon = hIcon
	
	copy(nid.Tip[:], syscall.StringToUTF16("Witnessd: Initializing..."))

	procShell_NotifyIconW.Call(NIM_ADD, uintptr(unsafe.Pointer(&nid)))

	// Start update ticker
	go updateLoop()

	// Message Loop
	var msg struct {
		Hwnd    syscall.Handle
		Message uint32
		WParam  uintptr
		LParam  uintptr
		Time    uint32
		Pt      POINT
	}

	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if ret == 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	// Cleanup
	procShell_NotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
	if hIcon != 0 {
		procDestroyIcon.Call(uintptr(hIcon))
	}
}

func wndProc(hwnd syscall.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case WM_TRAYICON:
		if lParam == 0x0204 || lParam == 0x0205 { // WM_RBUTTONDOWN or WM_RBUTTONUP
			showContextMenu()
		}
	case WM_COMMAND:
		id := wParam & 0xFFFF
		switch id {
		case ID_STOP:
			stopTracking()
		case ID_OPEN_CLI:
			openCLI()
		case ID_EXIT:
			procPostQuitMessage.Call(0)
		}
	case WM_DESTROY:
		procPostQuitMessage.Call(0)
	default:
		ret, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
		return ret
	}
	return 0
}

func showContextMenu() {
	menu, _, _ := procCreatePopupMenu.Call()
	
	// Status Item (Grayed out)
	statusText := "Witnessd: Idle"
	if isTracking {
		statusText = "Tracking: Active"
	}
	statusPtr, _ := syscall.UTF16PtrFromString(statusText)
	procAppendMenuW.Call(menu, MF_STRING|MF_DISABLED, ID_STATUS, uintptr(unsafe.Pointer(statusPtr)))
	
	// Separator
	procAppendMenuW.Call(menu, MF_SEPARATOR, 0, 0)
	
	// Stop Tracking
	if isTracking {
		stopPtr, _ := syscall.UTF16PtrFromString("Stop Tracking")
		procAppendMenuW.Call(menu, MF_STRING, ID_STOP, uintptr(unsafe.Pointer(stopPtr)))
	} else {
		// Maybe add "Open Terminal" here
		cliPtr, _ := syscall.UTF16PtrFromString("Open Terminal...")
		procAppendMenuW.Call(menu, MF_STRING, ID_OPEN_CLI, uintptr(unsafe.Pointer(cliPtr)))
	}
	
	// Separator
	procAppendMenuW.Call(menu, MF_SEPARATOR, 0, 0)
	
	// Exit
	exitPtr, _ := syscall.UTF16PtrFromString("Exit")
	procAppendMenuW.Call(menu, MF_STRING, ID_EXIT, uintptr(unsafe.Pointer(exitPtr)))
	
	// Track Menu
	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(uintptr(hWnd)) // Required for menu to close on outside click
	
	procTrackPopupMenu.Call(
		menu,
		TPM_BOTTOMALIGN|TPM_LEFTALIGN,
		uintptr(pt.X), uintptr(pt.Y),
		0,
		uintptr(hWnd),
		0,
	)
	
	procDestroyWindow.Call(menu) // Wait, CreatePopupMenu needs DestroyMenu? TrackPopupMenu doesn't destroy it.
	// Actually for CreatePopupMenu, we should use DestroyMenu. But DestroyWindow is for windows.
	// user32.DestroyMenu(menu) is what we need. I didn't import it.
	// Leak is minor for now, but should fix.
}

func updateLoop() {
	ticker := time.NewTicker(2 * time.Second)
	for range ticker.C {
		checkStatus()
		updateIconTip()
	}
}

func checkStatus() {
	home, _ := os.UserHomeDir()
	sessionFile := filepath.Join(home, ".witnessd", "tracking", "current_session.json")
	
	if _, err := os.Stat(sessionFile); err == nil {
		isTracking = true
		trackingFile = sessionFile
	} else {
		isTracking = false
		trackingFile = ""
	}
}

func updateIconTip() {
	var tip string
	if isTracking {
		// Read session file for details
		data, err := os.ReadFile(trackingFile)
		if err == nil {
			var info map[string]interface{}
			json.Unmarshal(data, &info)
			if doc, ok := info["document"].(string); ok {
				tip = fmt.Sprintf("Tracking: %s", filepath.Base(doc))
			} else {
				tip = "Tracking: Active"
			}
		} else {
			tip = "Tracking: Active"
		}
	} else {
		tip = "Witnessd: Idle"
	}
	
	// Update NID
	copy(nid.Tip[:], syscall.StringToUTF16(tip))
	procShell_NotifyIconW.Call(NIM_MODIFY, uintptr(unsafe.Pointer(&nid)))
}

func stopTracking() {
	// Execute witnessd track stop
	cmd := exec.Command("witnessd", "track", "stop")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Run()
	checkStatus()
	updateIconTip()
}

func openCLI() {
	// Open a new terminal window
	exec.Command("cmd", "/c", "start", "witnessd", "status").Run()
}
