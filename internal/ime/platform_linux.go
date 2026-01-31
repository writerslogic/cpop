//go:build linux

package ime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// LinuxPlatform implements the Platform interface for Linux.
// Supports both IBus and Fcitx5 frameworks.
type LinuxPlatform struct {
	config    PlatformConfig
	engine    *Engine
	framework string // "ibus" or "fcitx5"
}

// NewLinuxPlatform creates a new Linux IME platform.
func NewLinuxPlatform(config PlatformConfig, engine *Engine) *LinuxPlatform {
	framework := detectFramework()
	return &LinuxPlatform{
		config:    config,
		engine:    engine,
		framework: framework,
	}
}

// detectFramework determines which IME framework is available.
func detectFramework() string {
	// Check for Fcitx5 first (newer, preferred on KDE Plasma)
	if _, err := os.Stat("/usr/share/fcitx5"); err == nil {
		return "fcitx5"
	}
	// Check for legacy Fcitx
	if _, err := os.Stat("/usr/share/fcitx/addon"); err == nil {
		return "fcitx"
	}
	// Check for IBus (most common on GNOME)
	if _, err := os.Stat("/usr/share/ibus/component"); err == nil {
		return "ibus"
	}
	// Check if ibus-daemon is available
	if _, err := exec.LookPath("ibus-daemon"); err == nil {
		return "ibus"
	}
	return "ibus" // Default to IBus
}

func (p *LinuxPlatform) Name() string {
	return "linux"
}

func (p *LinuxPlatform) Available() bool {
	return p.framework != ""
}

func (p *LinuxPlatform) Install() error {
	switch p.framework {
	case "ibus":
		return p.installIBus()
	case "fcitx5":
		return p.installFcitx5()
	case "fcitx":
		return p.installFcitx()
	default:
		return errors.New("no supported IME framework found")
	}
}

func (p *LinuxPlatform) installIBus() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Create component directory
	componentDir := filepath.Join(home, ".local", "share", "ibus", "component")
	if err := os.MkdirAll(componentDir, 0755); err != nil {
		return err
	}

	// Get or determine the engine binary path
	enginePath := p.getEnginePath()

	// Create component XML
	componentXML := p.generateIBusComponent(enginePath)
	componentPath := filepath.Join(componentDir, "witnessd.xml")
	if err := os.WriteFile(componentPath, []byte(componentXML), 0644); err != nil {
		return err
	}

	// Copy the IME engine binary
	if err := p.installEngineBinary(enginePath); err != nil {
		return fmt.Errorf("failed to install engine binary: %w", err)
	}

	// Restart IBus to pick up the new component
	p.restartIBus()

	return nil
}

func (p *LinuxPlatform) getEnginePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin", "witnessd-ibus")
}

func (p *LinuxPlatform) installEngineBinary(destPath string) error {
	// Create destination directory
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	// Try to find the witnessd-ibus binary
	candidates := []string{
		"/usr/local/bin/witnessd-ibus",
		"/usr/bin/witnessd-ibus",
	}

	// Also check relative to current executable
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		candidates = append([]string{
			filepath.Join(execDir, "witnessd-ibus"),
		}, candidates...)
	}

	for _, src := range candidates {
		if _, err := os.Stat(src); err == nil {
			data, err := os.ReadFile(src)
			if err != nil {
				continue
			}
			if err := os.WriteFile(destPath, data, 0755); err != nil {
				return err
			}
			return nil
		}
	}

	// If not found, create a wrapper script
	wrapper := fmt.Sprintf(`#!/bin/bash
# Witnessd IBus Engine Wrapper
exec witnessd ime --ibus "$@"
`)
	return os.WriteFile(destPath, []byte(wrapper), 0755)
}

func (p *LinuxPlatform) generateIBusComponent(enginePath string) string {
	home, _ := os.UserHomeDir()
	iconPath := filepath.Join(home, ".local", "share", "icons", "witnessd.png")

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<component>
    <name>com.witnessd.ibus</name>
    <description>Witnessd Cryptographic Input Method</description>
    <exec>%s --ibus</exec>
    <version>1.0</version>
    <author>Witnessd</author>
    <license>MIT</license>
    <homepage>https://github.com/witnessd/witnessd</homepage>
    <textdomain>witnessd</textdomain>
    <engines>
        <engine>
            <name>witnessd</name>
            <language>en</language>
            <license>MIT</license>
            <author>Witnessd</author>
            <icon>%s</icon>
            <layout>us</layout>
            <longname>Witnessd</longname>
            <description>Cryptographic authorship witnessing keyboard</description>
            <rank>99</rank>
            <symbol>W</symbol>
        </engine>
    </engines>
</component>`, enginePath, iconPath)
}

func (p *LinuxPlatform) restartIBus() {
	// Try to restart ibus-daemon gracefully
	exec.Command("ibus", "restart").Run()
}

func (p *LinuxPlatform) installFcitx5() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Fcitx5 addon directory
	addonDir := filepath.Join(home, ".local", "share", "fcitx5", "addon")
	if err := os.MkdirAll(addonDir, 0755); err != nil {
		return err
	}

	// Create addon configuration
	addonConf := p.generateFcitx5Addon()
	addonPath := filepath.Join(addonDir, "witnessd.conf")
	if err := os.WriteFile(addonPath, []byte(addonConf), 0644); err != nil {
		return err
	}

	// Create input method configuration
	imDir := filepath.Join(home, ".local", "share", "fcitx5", "inputmethod")
	if err := os.MkdirAll(imDir, 0755); err != nil {
		return err
	}

	imConf := p.generateFcitx5InputMethod()
	imPath := filepath.Join(imDir, "witnessd.conf")
	if err := os.WriteFile(imPath, []byte(imConf), 0644); err != nil {
		return err
	}

	// Install engine binary
	enginePath := filepath.Join(home, ".local", "lib", "fcitx5", "witnessd")
	if err := os.MkdirAll(filepath.Dir(enginePath), 0755); err != nil {
		return err
	}
	if err := p.installEngineBinary(enginePath); err != nil {
		return fmt.Errorf("failed to install engine binary: %w", err)
	}

	// Restart Fcitx5
	exec.Command("fcitx5-remote", "-r").Run()

	return nil
}

func (p *LinuxPlatform) generateFcitx5Addon() string {
	return `[Addon]
Name=Witnessd
Category=InputMethod
Library=witnessd
Type=SharedLibrary
OnDemand=True
Configurable=True
`
}

func (p *LinuxPlatform) generateFcitx5InputMethod() string {
	return `[InputMethod]
Name=Witnessd
Icon=witnessd
Label=W
LangCode=en
Addon=witnessd
`
}

func (p *LinuxPlatform) installFcitx() error {
	// Legacy Fcitx (Fcitx4) installation
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Fcitx addon directory
	addonDir := filepath.Join(home, ".config", "fcitx", "addon")
	if err := os.MkdirAll(addonDir, 0755); err != nil {
		return err
	}

	addonConf := `[Addon]
Name=witnessd
GeneralName=Witnessd
Comment=Cryptographic authorship witnessing keyboard
Category=InputMethod
Enabled=True
Library=fcitx-witnessd.so
Type=IME
IMRegisterMethod=ConfigFile
`
	addonPath := filepath.Join(addonDir, "fcitx-witnessd.conf")
	return os.WriteFile(addonPath, []byte(addonConf), 0644)
}

func (p *LinuxPlatform) Uninstall() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Remove IBus component
	ibusPath := filepath.Join(home, ".local", "share", "ibus", "component", "witnessd.xml")
	os.Remove(ibusPath)

	// Remove Fcitx5 files
	os.Remove(filepath.Join(home, ".local", "share", "fcitx5", "addon", "witnessd.conf"))
	os.Remove(filepath.Join(home, ".local", "share", "fcitx5", "inputmethod", "witnessd.conf"))
	os.RemoveAll(filepath.Join(home, ".local", "lib", "fcitx5", "witnessd"))

	// Remove Fcitx4 files
	os.Remove(filepath.Join(home, ".config", "fcitx", "addon", "fcitx-witnessd.conf"))

	// Remove engine binary
	os.Remove(filepath.Join(home, ".local", "bin", "witnessd-ibus"))

	// Restart IME framework
	switch p.framework {
	case "ibus":
		exec.Command("ibus", "restart").Run()
	case "fcitx5":
		exec.Command("fcitx5-remote", "-r").Run()
	case "fcitx":
		exec.Command("fcitx-remote", "-r").Run()
	}

	return nil
}

func (p *LinuxPlatform) IsInstalled() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	switch p.framework {
	case "ibus":
		componentPath := filepath.Join(home, ".local", "share", "ibus", "component", "witnessd.xml")
		_, err = os.Stat(componentPath)
		return err == nil
	case "fcitx5":
		addonPath := filepath.Join(home, ".local", "share", "fcitx5", "addon", "witnessd.conf")
		_, err = os.Stat(addonPath)
		return err == nil
	case "fcitx":
		addonPath := filepath.Join(home, ".config", "fcitx", "addon", "fcitx-witnessd.conf")
		_, err = os.Stat(addonPath)
		return err == nil
	}
	return false
}

func (p *LinuxPlatform) IsActive() bool {
	switch p.framework {
	case "ibus":
		// Query IBus for current engine using ibus command
		cmd := exec.Command("ibus", "read-config")
		output, err := cmd.Output()
		if err != nil {
			// Try alternative: get current engine
			cmd = exec.Command("ibus", "engine")
			output, err = cmd.Output()
			if err != nil {
				return false
			}
		}
		return strings.Contains(strings.ToLower(string(output)), "witnessd")

	case "fcitx5":
		// Query Fcitx5 for current input method
		cmd := exec.Command("fcitx5-remote", "-n")
		output, err := cmd.Output()
		if err != nil {
			return false
		}
		return strings.Contains(strings.ToLower(string(output)), "witnessd")

	case "fcitx":
		// Query legacy Fcitx
		cmd := exec.Command("fcitx-remote", "-n")
		output, err := cmd.Output()
		if err != nil {
			return false
		}
		return strings.Contains(strings.ToLower(string(output)), "witnessd")
	}

	return false
}

func (p *LinuxPlatform) Activate() error {
	switch p.framework {
	case "ibus":
		// Try to set IBus engine
		cmd := exec.Command("ibus", "engine", "witnessd")
		if err := cmd.Run(); err != nil {
			// Open GNOME settings as fallback
			exec.Command("gnome-control-center", "region").Start()
			return errors.New("please select Witnessd from Region & Language settings")
		}
		return nil

	case "fcitx5":
		// Try to switch to Witnessd using fcitx5-remote
		cmd := exec.Command("fcitx5-remote", "-s", "witnessd")
		if err := cmd.Run(); err != nil {
			// Open Fcitx5 configuration
			exec.Command("fcitx5-config-qt").Start()
			return errors.New("please add Witnessd from Fcitx5 Configuration")
		}
		return nil

	case "fcitx":
		// Legacy Fcitx
		cmd := exec.Command("fcitx-remote", "-s", "witnessd")
		if err := cmd.Run(); err != nil {
			exec.Command("fcitx-configtool").Start()
			return errors.New("please add Witnessd from Fcitx Configuration")
		}
		return nil
	}

	return errors.New("please use your desktop environment settings to select the input method")
}

// LinuxZoneMapping provides Linux-specific keycode mapping.
// Uses X11 keycodes (evdev).
type LinuxZoneMapping struct{}

func (LinuxZoneMapping) KeyCodeToZone(keyCode uint16) int {
	// X11/evdev keycodes (offset by 8 from raw scancodes)
	// These are the keycodes you'd get from XKeyEvent.keycode
	switch keyCode {
	// Zone 0: Left pinky - Q(24), A(38), Z(52)
	case 24, 38, 52:
		return 0
	// Zone 1: Left ring - W(25), S(39), X(53)
	case 25, 39, 53:
		return 1
	// Zone 2: Left middle - E(26), D(40), C(54)
	case 26, 40, 54:
		return 2
	// Zone 3: Left index - R(27), T(28), F(41), G(42), V(55), B(56)
	case 27, 28, 41, 42, 55, 56:
		return 3
	// Zone 4: Right index - Y(29), U(30), H(43), J(44), N(57), M(58)
	case 29, 30, 43, 44, 57, 58:
		return 4
	// Zone 5: Right middle - I(31), K(45), comma(59)
	case 31, 45, 59:
		return 5
	// Zone 6: Right ring - O(32), L(46), period(60)
	case 32, 46, 60:
		return 6
	// Zone 7: Right pinky - P(33), semicolon(47), slash(61)
	case 33, 47, 61:
		return 7
	default:
		return -1
	}
}

func (LinuxZoneMapping) CharToZone(char rune) int {
	return zoneFromChar(char)
}

var _ Platform = (*LinuxPlatform)(nil)
