//go:build windows

package ime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// WindowsPlatform implements the Platform interface for Windows.
// Uses Text Services Framework (TSF).
type WindowsPlatform struct {
	config PlatformConfig
	engine *Engine
}

// TSF registration constants
const (
	// CLSID for our Text Input Processor
	witnessdCLSID = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"

	// Language profile GUID
	witnessdLangProfileGUID = "{12345678-90AB-CDEF-1234-567890ABCDEF}"

	// Registry paths
	ctfTIPPath = `SOFTWARE\Microsoft\CTF\TIP\` + witnessdCLSID
)

// NewWindowsPlatform creates a new Windows IME platform.
func NewWindowsPlatform(config PlatformConfig, engine *Engine) *WindowsPlatform {
	return &WindowsPlatform{
		config: config,
		engine: engine,
	}
}

func (p *WindowsPlatform) Name() string {
	return "windows"
}

func (p *WindowsPlatform) Available() bool {
	// Check if TSF is available (Windows 8+)
	// TSF is available on all modern Windows versions
	return true
}

func (p *WindowsPlatform) Install() error {
	// Get install location
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return errors.New("LOCALAPPDATA not set")
	}

	installDir := filepath.Join(localAppData, "Witnessd", "IME")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("failed to create install directory: %w", err)
	}

	// Copy the current executable to install location
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	destExec := filepath.Join(installDir, "witnessd-tsf.exe")
	if err := copyFileWindows(execPath, destExec); err != nil {
		return fmt.Errorf("failed to copy executable: %w", err)
	}

	// Create registry entries for user-level installation
	if err := p.createRegistryEntries(installDir); err != nil {
		return fmt.Errorf("failed to create registry entries: %w", err)
	}

	// Generate install script for admin-level registration if needed
	scriptPath := filepath.Join(installDir, "install-admin.ps1")
	if err := p.generateInstallScript(scriptPath, installDir); err != nil {
		return fmt.Errorf("failed to generate install script: %w", err)
	}

	return nil
}

func (p *WindowsPlatform) createRegistryEntries(installDir string) error {
	// Try HKEY_CURRENT_USER first (no admin required)
	key, _, err := registry.CreateKey(registry.CURRENT_USER, ctfTIPPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("failed to create TIP registry key: %w", err)
	}
	defer key.Close()

	// Set basic TIP properties
	if err := key.SetStringValue("", p.config.DisplayName); err != nil {
		return err
	}

	// Create LanguageProfile subkey
	langProfilePath := ctfTIPPath + `\LanguageProfile\0x00000409\` + witnessdLangProfileGUID
	langKey, _, err := registry.CreateKey(registry.CURRENT_USER, langProfilePath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("failed to create language profile key: %w", err)
	}
	defer langKey.Close()

	if err := langKey.SetStringValue("Description", "Witnessd Cryptographic Input Method"); err != nil {
		return err
	}

	iconPath := filepath.Join(installDir, "witnessd-tsf.exe")
	if err := langKey.SetExpandStringValue("IconFile", iconPath); err != nil {
		return err
	}
	if err := langKey.SetDWordValue("IconIndex", 0); err != nil {
		return err
	}

	return nil
}

func (p *WindowsPlatform) generateInstallScript(scriptPath, installDir string) error {
	script := fmt.Sprintf(`# Witnessd TSF Admin Installation Script
# Run this script as Administrator for system-wide installation

$ErrorActionPreference = "Stop"

# CLSID for Witnessd TSF
$clsid = "%s"
$langProfileGUID = "%s"
$installDir = "%s"

Write-Host "Installing Witnessd Input Method..."

# Register COM server (requires the DLL to be built)
# regsvr32.exe /s "$installDir\witnessd-tsf.dll"

# Create system-wide registry entries
$tipPath = "HKLM:\SOFTWARE\Microsoft\CTF\TIP\$clsid"
New-Item -Path $tipPath -Force | Out-Null
Set-ItemProperty -Path $tipPath -Name "(Default)" -Value "Witnessd"

$langPath = "$tipPath\LanguageProfile\0x00000409\$langProfileGUID"
New-Item -Path $langPath -Force | Out-Null
Set-ItemProperty -Path $langPath -Name "Description" -Value "Witnessd Cryptographic Input Method"
Set-ItemProperty -Path $langPath -Name "IconFile" -Value "$installDir\witnessd-tsf.exe"
Set-ItemProperty -Path $langPath -Name "IconIndex" -Value 0

Write-Host "Installation complete. Please restart your applications."
Write-Host "To enable: Settings > Time & Language > Language > Keyboard"
`, witnessdCLSID, witnessdLangProfileGUID, strings.ReplaceAll(installDir, `\`, `\\`))

	return os.WriteFile(scriptPath, []byte(script), 0755)
}

func (p *WindowsPlatform) Uninstall() error {
	// Remove registry entries
	if err := registry.DeleteKey(registry.CURRENT_USER, ctfTIPPath); err != nil {
		// Key might not exist, ignore error
	}

	// Remove install directory
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData != "" {
		installDir := filepath.Join(localAppData, "Witnessd", "IME")
		os.RemoveAll(installDir)
	}

	return nil
}

func (p *WindowsPlatform) IsInstalled() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, ctfTIPPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	key.Close()
	return true
}

func (p *WindowsPlatform) IsActive() bool {
	// Query the current input method using PowerShell
	// This is a workaround since proper COM queries require more setup
	cmd := exec.Command("powershell", "-Command",
		"Get-WinUserLanguageList | Select-Object -ExpandProperty InputMethodTips")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), "Witnessd")
}

func (p *WindowsPlatform) Activate() error {
	// Open Windows keyboard settings
	cmd := exec.Command("cmd", "/c", "start", "ms-settings:keyboard")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to open keyboard settings: %w", err)
	}

	return errors.New("please select Witnessd from the keyboard settings that just opened")
}

// copyFileWindows copies a file on Windows.
func copyFileWindows(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}

// WindowsZoneMapping provides Windows-specific virtual key code mapping.
// Uses Windows VK_* constants.
type WindowsZoneMapping struct{}

func (WindowsZoneMapping) KeyCodeToZone(keyCode uint16) int {
	// Windows virtual key codes (VK_*)
	// VK_A = 0x41, VK_Z = 0x5A
	switch keyCode {
	// Zone 0: Left pinky - Q(0x51), A(0x41), Z(0x5A)
	case 0x51, 0x41, 0x5A:
		return 0
	// Zone 1: Left ring - W(0x57), S(0x53), X(0x58)
	case 0x57, 0x53, 0x58:
		return 1
	// Zone 2: Left middle - E(0x45), D(0x44), C(0x43)
	case 0x45, 0x44, 0x43:
		return 2
	// Zone 3: Left index - R(0x52), T(0x54), F(0x46), G(0x47), V(0x56), B(0x42)
	case 0x52, 0x54, 0x46, 0x47, 0x56, 0x42:
		return 3
	// Zone 4: Right index - Y(0x59), U(0x55), H(0x48), J(0x4A), N(0x4E), M(0x4D)
	case 0x59, 0x55, 0x48, 0x4A, 0x4E, 0x4D:
		return 4
	// Zone 5: Right middle - I(0x49), K(0x4B), comma(0xBC)
	case 0x49, 0x4B, 0xBC:
		return 5
	// Zone 6: Right ring - O(0x4F), L(0x4C), period(0xBE)
	case 0x4F, 0x4C, 0xBE:
		return 6
	// Zone 7: Right pinky - P(0x50), semicolon(0xBA), slash(0xBF)
	case 0x50, 0xBA, 0xBF:
		return 7
	default:
		return -1
	}
}

func (WindowsZoneMapping) CharToZone(char rune) int {
	return zoneFromChar(char)
}

var _ Platform = (*WindowsPlatform)(nil)
