//go:build windows

package main

/*
#cgo LDFLAGS: -lole32 -loleaut32 -ladvapi32 -lshell32 -lshlwapi

#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <stdint.h>
#include <stdio.h>

// ============================================================================
// Installation and Registration Utilities for Witnessd TSF
// ============================================================================

// CLSID string for Witnessd TSF
#define CLSID_STR L"{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
#define PROFILE_GUID_STR L"{B2C3D4E5-F678-90AB-CDEF-123456789012}"

// Registry paths
#define CTF_TIP_PATH L"SOFTWARE\\Microsoft\\CTF\\TIP\\" CLSID_STR
#define CLSID_PATH L"CLSID\\" CLSID_STR

// Get installation directory
static int GetInstallDir(wchar_t* buffer, int bufferLen) {
	wchar_t localAppData[MAX_PATH];
	if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
		return -1;
	}

	_snwprintf(buffer, bufferLen, L"%s\\Witnessd\\TSF", localAppData);
	return 0;
}

// Ensure directory exists
static int EnsureDirectory(const wchar_t* path) {
	return SHCreateDirectoryExW(NULL, path, NULL) == ERROR_SUCCESS ||
	       GetLastError() == ERROR_ALREADY_EXISTS ? 0 : -1;
}

// Check if running as administrator
static int IsRunningAsAdmin() {
	BOOL isAdmin = FALSE;
	PSID adminGroup = NULL;

	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	if (AllocateAndInitializeSid(&ntAuthority, 2,
	                              SECURITY_BUILTIN_DOMAIN_RID,
	                              DOMAIN_ALIAS_RID_ADMINS,
	                              0, 0, 0, 0, 0, 0,
	                              &adminGroup)) {
		CheckTokenMembership(NULL, adminGroup, &isAdmin);
		FreeSid(adminGroup);
	}

	return isAdmin;
}

// Request elevation
static int RequestElevation(const wchar_t* args) {
	wchar_t exePath[MAX_PATH];
	GetModuleFileNameW(NULL, exePath, MAX_PATH);

	SHELLEXECUTEINFOW sei = {0};
	sei.cbSize = sizeof(SHELLEXECUTEINFOW);
	sei.fMask = SEE_MASK_NOCLOSEPROCESS;
	sei.lpVerb = L"runas";
	sei.lpFile = exePath;
	sei.lpParameters = args;
	sei.nShow = SW_SHOWNORMAL;

	if (!ShellExecuteExW(&sei)) {
		return -1;
	}

	// Wait for elevated process
	WaitForSingleObject(sei.hProcess, INFINITE);

	DWORD exitCode;
	GetExitCodeProcess(sei.hProcess, &exitCode);
	CloseHandle(sei.hProcess);

	return exitCode == 0 ? 0 : -1;
}

// Create user registry entries (no admin required)
static int CreateUserRegistryEntries(const wchar_t* installDir) {
	HKEY hKey;
	LONG result;

	// Create TIP key
	result = RegCreateKeyExW(HKEY_CURRENT_USER, CTF_TIP_PATH, 0, NULL,
	                          REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (result != ERROR_SUCCESS) {
		return -1;
	}

	RegSetValueExW(hKey, NULL, 0, REG_SZ,
	               (const BYTE*)L"Witnessd Authorship Witness",
	               (DWORD)((wcslen(L"Witnessd Authorship Witness") + 1) * sizeof(wchar_t)));

	RegCloseKey(hKey);

	// Create language profile key
	wchar_t langProfilePath[512];
	_snwprintf(langProfilePath, 512, L"%s\\LanguageProfile\\0x00000409\\%s",
	           CTF_TIP_PATH, PROFILE_GUID_STR);

	result = RegCreateKeyExW(HKEY_CURRENT_USER, langProfilePath, 0, NULL,
	                          REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (result != ERROR_SUCCESS) {
		return -2;
	}

	// Set profile properties
	RegSetValueExW(hKey, L"Description", 0, REG_SZ,
	               (const BYTE*)L"Witnessd Authorship Witness - Transparent keystroke witnessing",
	               (DWORD)((wcslen(L"Witnessd Authorship Witness - Transparent keystroke witnessing") + 1) * sizeof(wchar_t)));

	// Icon path
	wchar_t iconPath[MAX_PATH];
	_snwprintf(iconPath, MAX_PATH, L"%s\\witnessd.dll", installDir);
	RegSetValueExW(hKey, L"IconFile", 0, REG_EXPAND_SZ,
	               (const BYTE*)iconPath, (DWORD)((wcslen(iconPath) + 1) * sizeof(wchar_t)));

	DWORD iconIndex = 0;
	RegSetValueExW(hKey, L"IconIndex", 0, REG_DWORD, (const BYTE*)&iconIndex, sizeof(DWORD));

	RegCloseKey(hKey);
	return 0;
}

// Remove user registry entries
static int RemoveUserRegistryEntries() {
	SHDeleteKeyW(HKEY_CURRENT_USER, CTF_TIP_PATH);
	return 0;
}

// Create system registry entries (admin required)
static int CreateSystemRegistryEntries(const wchar_t* installDir) {
	HKEY hKey, hInprocKey;
	LONG result;

	// Create CLSID key
	result = RegCreateKeyExW(HKEY_CLASSES_ROOT, CLSID_PATH, 0, NULL,
	                          REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (result != ERROR_SUCCESS) {
		return -1;
	}

	RegSetValueExW(hKey, NULL, 0, REG_SZ,
	               (const BYTE*)L"Witnessd Text Service",
	               (DWORD)((wcslen(L"Witnessd Text Service") + 1) * sizeof(wchar_t)));

	// Create InProcServer32 key
	wchar_t inprocPath[256];
	_snwprintf(inprocPath, 256, L"%s\\InProcServer32", CLSID_PATH);

	result = RegCreateKeyExW(HKEY_CLASSES_ROOT, inprocPath, 0, NULL,
	                          REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hInprocKey, NULL);
	if (result != ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return -2;
	}

	// DLL path
	wchar_t dllPath[MAX_PATH];
	_snwprintf(dllPath, MAX_PATH, L"%s\\witnessd.dll", installDir);
	RegSetValueExW(hInprocKey, NULL, 0, REG_SZ,
	               (const BYTE*)dllPath, (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t)));

	RegSetValueExW(hInprocKey, L"ThreadingModel", 0, REG_SZ,
	               (const BYTE*)L"Apartment",
	               (DWORD)((wcslen(L"Apartment") + 1) * sizeof(wchar_t)));

	RegCloseKey(hInprocKey);
	RegCloseKey(hKey);

	return 0;
}

// Remove system registry entries
static int RemoveSystemRegistryEntries() {
	SHDeleteKeyW(HKEY_CLASSES_ROOT, CLSID_PATH);
	return 0;
}

// Copy DLL to install directory
static int CopyDllToInstallDir(const wchar_t* sourceDll, const wchar_t* installDir) {
	wchar_t destPath[MAX_PATH];
	_snwprintf(destPath, MAX_PATH, L"%s\\witnessd.dll", installDir);

	if (!CopyFileW(sourceDll, destPath, FALSE)) {
		return -1;
	}

	return 0;
}

// Register DLL with regsvr32
static int RegisterDll(const wchar_t* dllPath) {
	wchar_t cmd[512];
	_snwprintf(cmd, 512, L"/s \"%s\"", dllPath);

	SHELLEXECUTEINFOW sei = {0};
	sei.cbSize = sizeof(SHELLEXECUTEINFOW);
	sei.fMask = SEE_MASK_NOCLOSEPROCESS;
	sei.lpVerb = L"open";
	sei.lpFile = L"regsvr32.exe";
	sei.lpParameters = cmd;
	sei.nShow = SW_HIDE;

	if (!ShellExecuteExW(&sei)) {
		return -1;
	}

	WaitForSingleObject(sei.hProcess, 10000);

	DWORD exitCode;
	GetExitCodeProcess(sei.hProcess, &exitCode);
	CloseHandle(sei.hProcess);

	return exitCode == 0 ? 0 : -1;
}

// Unregister DLL
static int UnregisterDll(const wchar_t* dllPath) {
	wchar_t cmd[512];
	_snwprintf(cmd, 512, L"/s /u \"%s\"", dllPath);

	SHELLEXECUTEINFOW sei = {0};
	sei.cbSize = sizeof(SHELLEXECUTEINFOW);
	sei.fMask = SEE_MASK_NOCLOSEPROCESS;
	sei.lpVerb = L"open";
	sei.lpFile = L"regsvr32.exe";
	sei.lpParameters = cmd;
	sei.nShow = SW_HIDE;

	if (!ShellExecuteExW(&sei)) {
		return -1;
	}

	WaitForSingleObject(sei.hProcess, 10000);

	DWORD exitCode;
	GetExitCodeProcess(sei.hProcess, &exitCode);
	CloseHandle(sei.hProcess);

	return exitCode == 0 ? 0 : -1;
}

// Check if TSF is installed
static int IsTsfInstalled() {
	HKEY hKey;
	LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, CTF_TIP_PATH, 0, KEY_READ, &hKey);
	if (result == ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return 1;
	}
	return 0;
}

// Open keyboard settings
static void OpenKeyboardSettings() {
	ShellExecuteW(NULL, L"open", L"ms-settings:keyboard", NULL, NULL, SW_SHOWNORMAL);
}

// Create Start Menu shortcut
static int CreateStartMenuShortcut(const wchar_t* installDir) {
	// Get Start Menu programs path
	wchar_t startMenuPath[MAX_PATH];
	if (FAILED(SHGetFolderPathW(NULL, CSIDL_PROGRAMS, NULL, 0, startMenuPath))) {
		return -1;
	}

	// Create Witnessd folder
	wchar_t folderPath[MAX_PATH];
	_snwprintf(folderPath, MAX_PATH, L"%s\\Witnessd", startMenuPath);
	SHCreateDirectoryExW(NULL, folderPath, NULL);

	// Note: Creating actual .lnk shortcut requires COM IShellLink interface
	// For simplicity, we just create the folder here
	// The actual shortcut creation would be done by the MSI installer

	(void)installDir;
	return 0;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

// Installer handles TSF installation and uninstallation.
type Installer struct {
	installDir string
	dllPath    string
}

// InstallationStatus represents the current installation state.
type InstallationStatus struct {
	Installed     bool
	InstallDir    string
	DLLPresent    bool
	RegistryOK    bool
	AdminRequired bool
}

// NewInstaller creates a new installer instance.
func NewInstaller() (*Installer, error) {
	var installDirBuf [260]C.wchar_t
	if C.GetInstallDir(&installDirBuf[0], 260) != 0 {
		return nil, errors.New("failed to get installation directory")
	}

	installDir := wcharToString(unsafe.Pointer(&installDirBuf[0]))

	return &Installer{
		installDir: installDir,
		dllPath:    filepath.Join(installDir, "witnessd.dll"),
	}, nil
}

// GetStatus returns the current installation status.
func (i *Installer) GetStatus() InstallationStatus {
	status := InstallationStatus{
		InstallDir: i.installDir,
	}

	// Check if registry entries exist
	status.RegistryOK = C.IsTsfInstalled() != 0

	// Check if DLL exists
	_, err := os.Stat(i.dllPath)
	status.DLLPresent = err == nil

	status.Installed = status.RegistryOK && status.DLLPresent
	status.AdminRequired = !C.IsRunningAsAdmin() != 0

	return status
}

// Install performs the full installation.
func (i *Installer) Install(sourceDLL string) error {
	// Ensure install directory exists
	installDirW := stringToWchar(i.installDir)
	defer C.free(unsafe.Pointer(installDirW))

	if C.EnsureDirectory(installDirW) != 0 {
		return errors.New("failed to create installation directory")
	}

	// Copy DLL
	sourceDLLW := stringToWchar(sourceDLL)
	defer C.free(unsafe.Pointer(sourceDLLW))

	if C.CopyDllToInstallDir(sourceDLLW, installDirW) != 0 {
		return errors.New("failed to copy DLL to installation directory")
	}

	// Create user registry entries (no admin required)
	if result := C.CreateUserRegistryEntries(installDirW); result != 0 {
		return fmt.Errorf("failed to create user registry entries: %d", result)
	}

	// Register DLL (may require admin)
	dllPathW := stringToWchar(i.dllPath)
	defer C.free(unsafe.Pointer(dllPathW))

	if C.RegisterDll(dllPathW) != 0 {
		// Try with elevation
		if !i.IsAdmin() {
			return i.InstallWithElevation(sourceDLL)
		}
		return errors.New("failed to register DLL")
	}

	// Create Start Menu shortcut
	C.CreateStartMenuShortcut(installDirW)

	return nil
}

// InstallWithElevation requests admin privileges and retries installation.
func (i *Installer) InstallWithElevation(sourceDLL string) error {
	args := fmt.Sprintf("--install-elevated \"%s\"", sourceDLL)
	argsW := stringToWchar(args)
	defer C.free(unsafe.Pointer(argsW))

	if C.RequestElevation(argsW) != 0 {
		return errors.New("failed to install with elevated privileges")
	}

	return nil
}

// Uninstall removes the TSF installation.
func (i *Installer) Uninstall() error {
	// Unregister DLL
	dllPathW := stringToWchar(i.dllPath)
	defer C.free(unsafe.Pointer(dllPathW))

	C.UnregisterDll(dllPathW)

	// Remove registry entries
	C.RemoveUserRegistryEntries()

	if i.IsAdmin() {
		C.RemoveSystemRegistryEntries()
	}

	// Remove files
	os.RemoveAll(i.installDir)

	return nil
}

// UninstallWithElevation requests admin privileges and uninstalls.
func (i *Installer) UninstallWithElevation() error {
	argsW := stringToWchar("--uninstall-elevated")
	defer C.free(unsafe.Pointer(argsW))

	if C.RequestElevation(argsW) != 0 {
		return errors.New("failed to uninstall with elevated privileges")
	}

	return nil
}

// IsAdmin returns true if running with administrator privileges.
func (i *Installer) IsAdmin() bool {
	return C.IsRunningAsAdmin() != 0
}

// OpenSettings opens the Windows keyboard settings.
func (i *Installer) OpenSettings() {
	C.OpenKeyboardSettings()
}

// GetInstallDir returns the installation directory.
func (i *Installer) GetInstallDir() string {
	return i.installDir
}

// GetDLLPath returns the path to the installed DLL.
func (i *Installer) GetDLLPath() string {
	return i.dllPath
}

// stringToWchar converts a Go string to a wide character string.
func stringToWchar(s string) *C.wchar_t {
	// Convert to UTF-16
	utf16 := make([]uint16, len(s)+1)
	for i, r := range s {
		utf16[i] = uint16(r)
	}

	// Allocate and copy
	size := (len(utf16)) * 2
	ptr := C.malloc(C.size_t(size))
	wchars := (*[1 << 20]C.wchar_t)(ptr)

	for i, v := range utf16 {
		wchars[i] = C.wchar_t(v)
	}

	return (*C.wchar_t)(ptr)
}

// GenerateInstallScript generates a PowerShell installation script.
func GenerateInstallScript(outputPath string) error {
	script := `# Witnessd TSF Installation Script
# Run as Administrator

$ErrorActionPreference = "Stop"

# Configuration
$ClsidStr = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
$ProfileGuid = "{B2C3D4E5-F678-90AB-CDEF-123456789012}"
$InstallDir = "$env:LOCALAPPDATA\Witnessd\TSF"
$DllName = "witnessd.dll"

Write-Host "Witnessd TSF Installation Script" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Check admin
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "Please run as Administrator." -ForegroundColor Red
    exit 1
}

# Create install directory
Write-Host "Creating installation directory..." -ForegroundColor Yellow
New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null

# Copy DLL (assumes DLL is in same directory as script)
$SourceDll = Join-Path $PSScriptRoot $DllName
$DestDll = Join-Path $InstallDir $DllName

if (Test-Path $SourceDll) {
    Write-Host "Copying DLL to installation directory..." -ForegroundColor Yellow
    Copy-Item $SourceDll $DestDll -Force
} else {
    Write-Host "Warning: DLL not found at $SourceDll" -ForegroundColor Yellow
    Write-Host "Please copy $DllName to $InstallDir manually." -ForegroundColor Yellow
}

# Register CLSID
Write-Host "Registering COM server..." -ForegroundColor Yellow
$ClsidPath = "HKCR:\CLSID\$ClsidStr"
New-Item -Path $ClsidPath -Force | Out-Null
Set-ItemProperty -Path $ClsidPath -Name "(Default)" -Value "Witnessd Text Service"

$InprocPath = "$ClsidPath\InProcServer32"
New-Item -Path $InprocPath -Force | Out-Null
Set-ItemProperty -Path $InprocPath -Name "(Default)" -Value $DestDll
Set-ItemProperty -Path $InprocPath -Name "ThreadingModel" -Value "Apartment"

# Register TIP
Write-Host "Registering Text Input Processor..." -ForegroundColor Yellow
$TipPath = "HKCU:\SOFTWARE\Microsoft\CTF\TIP\$ClsidStr"
New-Item -Path $TipPath -Force | Out-Null
Set-ItemProperty -Path $TipPath -Name "(Default)" -Value "Witnessd Authorship Witness"

$LangProfilePath = "$TipPath\LanguageProfile\0x00000409\$ProfileGuid"
New-Item -Path $LangProfilePath -Force | Out-Null
Set-ItemProperty -Path $LangProfilePath -Name "Description" -Value "Witnessd Authorship Witness - Transparent keystroke witnessing"
Set-ItemProperty -Path $LangProfilePath -Name "IconFile" -Value $DestDll
Set-ItemProperty -Path $LangProfilePath -Name "IconIndex" -Value 0 -Type DWord

# Register DLL
Write-Host "Registering DLL..." -ForegroundColor Yellow
if (Test-Path $DestDll) {
    & regsvr32.exe /s $DestDll
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Warning: regsvr32 returned non-zero exit code" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "To enable Witnessd:" -ForegroundColor Cyan
Write-Host "1. Open Windows Settings" -ForegroundColor White
Write-Host "2. Go to Time & Language > Language & region" -ForegroundColor White
Write-Host "3. Click on your language, then Keyboard" -ForegroundColor White
Write-Host "4. Add 'Witnessd Authorship Witness'" -ForegroundColor White
Write-Host ""
Write-Host "Opening keyboard settings..." -ForegroundColor Yellow
Start-Process "ms-settings:keyboard"
`

	return os.WriteFile(outputPath, []byte(script), 0755)
}

// GenerateUninstallScript generates a PowerShell uninstallation script.
func GenerateUninstallScript(outputPath string) error {
	script := `# Witnessd TSF Uninstallation Script
# Run as Administrator

$ErrorActionPreference = "Stop"

# Configuration
$ClsidStr = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
$InstallDir = "$env:LOCALAPPDATA\Witnessd\TSF"
$DllPath = Join-Path $InstallDir "witnessd.dll"

Write-Host "Witnessd TSF Uninstallation Script" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan

# Check admin
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "Please run as Administrator." -ForegroundColor Red
    exit 1
}

# Unregister DLL
Write-Host "Unregistering DLL..." -ForegroundColor Yellow
if (Test-Path $DllPath) {
    & regsvr32.exe /s /u $DllPath
}

# Remove registry entries
Write-Host "Removing registry entries..." -ForegroundColor Yellow

# Remove TIP registration
$TipPath = "HKCU:\SOFTWARE\Microsoft\CTF\TIP\$ClsidStr"
if (Test-Path $TipPath) {
    Remove-Item -Path $TipPath -Recurse -Force
}

# Remove CLSID
$ClsidPath = "HKCR:\CLSID\$ClsidStr"
if (Test-Path $ClsidPath) {
    Remove-Item -Path $ClsidPath -Recurse -Force
}

# Remove installation directory
Write-Host "Removing installation files..." -ForegroundColor Yellow
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
}

Write-Host ""
Write-Host "Uninstallation complete!" -ForegroundColor Green
`

	return os.WriteFile(outputPath, []byte(script), 0755)
}
