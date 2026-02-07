//go:build linux

// witnessd-ibus is the Linux IBus Input Method Engine.
//
// This connects to the IBus daemon via D-Bus and handles key events,
// routing them through the witnessd engine for cryptographic witnessing.
//
// The engine runs in pass-through mode - it observes and records
// typing patterns but forwards all input unchanged to applications.
//
// Installation:
//
//	make install          # User installation (recommended)
//	make install-system   # System-wide installation
//
// After installation:
//  1. Restart IBus: ibus restart
//  2. Enable via: ibus-setup or GNOME Settings > Keyboard > Input Sources
//
// Manual operation:
//
//	witnessd-ibus --ibus           # Run as IBus engine
//	witnessd-ibus --install        # Install component files
//	witnessd-ibus --uninstall      # Remove component files
//	witnessd-ibus --status         # Show status information
//	witnessd-ibus --configure      # Open configuration UI
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"

	"witnessd/internal/ime"
)

// Build-time variables (set by -ldflags)
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// Command-line flags
var (
	ibusMode      = flag.Bool("ibus", false, "Run as IBus engine (started by IBus)")
	installFlag   = flag.Bool("install", false, "Install IBus component and related files")
	uninstallFlag = flag.Bool("uninstall", false, "Uninstall IBus component and related files")
	statusFlag    = flag.Bool("status", false, "Show status information")
	configureFlag = flag.Bool("configure", false, "Open configuration")
	debugFlag     = flag.Bool("debug", false, "Enable debug logging")
	versionFlag   = flag.Bool("version", false, "Show version information")
	socketPath    = flag.String("socket", "", "Override daemon socket path")
	dataDir       = flag.String("data-dir", "", "Override data directory")
)

func main() {
	flag.Parse()

	// Version information
	if *versionFlag {
		fmt.Printf("witnessd-ibus version %s\n", Version)
		fmt.Printf("  Commit:     %s\n", Commit)
		fmt.Printf("  Build time: %s\n", BuildTime)
		return
	}

	// Status
	if *statusFlag {
		showStatus()
		return
	}

	// Install
	if *installFlag {
		if err := installComponent(); err != nil {
			log.Fatalf("Installation failed: %v", err)
		}
		fmt.Println("Installation complete. Run 'ibus restart' to load the engine.")
		fmt.Println("Then enable Witnessd in your input method settings.")
		return
	}

	// Uninstall
	if *uninstallFlag {
		if err := uninstallComponent(); err != nil {
			log.Fatalf("Uninstallation failed: %v", err)
		}
		fmt.Println("Uninstallation complete.")
		return
	}

	// Configure
	if *configureFlag {
		openConfiguration()
		return
	}

	// Run as IBus engine (default or with --ibus flag)
	runIBusEngine()
}

// runIBusEngine starts the IBus engine and handles key events.
func runIBusEngine() {
	// Initialize logging
	if err := initLogging(*debugFlag); err != nil {
		log.Printf("Warning: could not initialize file logging: %v", err)
	}

	log.Printf("Witnessd IBus Engine v%s starting...", Version)

	// Build configuration
	config := ime.DefaultIBusConfig()
	if *socketPath != "" {
		config.SocketPath = *socketPath
	}
	if *dataDir != "" {
		config.DataDir = *dataDir
	}
	config.Debug = *debugFlag

	// Create engine
	engine, err := ime.NewIBusEngine(config)
	if err != nil {
		log.Fatalf("Failed to create IBus engine: %v", err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start engine
	if err := engine.Start(ctx); err != nil {
		log.Fatalf("Failed to start IBus engine: %v", err)
	}

	log.Println("Witnessd IBus engine running")

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	sig := <-sigChan
	log.Printf("Received signal %v, shutting down...", sig)

	// Graceful shutdown
	cancel()

	if err := engine.Stop(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	// Print final stats
	stats := engine.GetStats()
	log.Printf("Final stats: keystrokes=%d sessions=%d", stats.TotalKeystrokes, stats.SessionsEnded)

	log.Println("Shutdown complete")
}

// initLogging sets up file logging.
func initLogging(debug bool) error {
	// Determine log directory
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	logDir := filepath.Join(home, ".local", "share", "witnessd", "logs")
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		logDir = filepath.Join(xdgData, "witnessd", "logs")
	}

	if err := os.MkdirAll(logDir, 0700); err != nil {
		return err
	}

	// Open log file
	logPath := filepath.Join(logDir, "ibus.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	if debug {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	}

	return nil
}

// installComponent installs the IBus component and supporting files.
func installComponent() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Determine binary path
	binPath, err := os.Executable()
	if err != nil {
		binPath = filepath.Join(home, ".local", "bin", "witnessd-ibus")
	}

	fmt.Println("Installing Witnessd IBus Engine...")
	fmt.Printf("  Binary: %s\n", binPath)

	// Create directories
	componentDir := filepath.Join(home, ".local", "share", "ibus", "component")
	dataDir := filepath.Join(home, ".local", "share", "witnessd")
	configDir := filepath.Join(home, ".config", "witnessd")
	logDir := filepath.Join(dataDir, "logs")
	systemdDir := filepath.Join(home, ".config", "systemd", "user")
	desktopDir := filepath.Join(home, ".local", "share", "applications")
	iconsDir := filepath.Join(home, ".local", "share", "icons", "hicolor", "scalable", "apps")

	dirs := []string{componentDir, dataDir, configDir, logDir, systemdDir, desktopDir, iconsDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create %s: %w", dir, err)
		}
	}

	// Install component XML
	componentXML := generateComponentXML(binPath)
	componentPath := filepath.Join(componentDir, "witnessd.xml")
	if err := os.WriteFile(componentPath, []byte(componentXML), 0644); err != nil {
		return fmt.Errorf("failed to write component: %w", err)
	}
	fmt.Printf("  Component: %s\n", componentPath)

	// Install systemd service
	systemdService := generateSystemdService(binPath)
	servicePath := filepath.Join(systemdDir, "witnessd-ibus.service")
	if err := os.WriteFile(servicePath, []byte(systemdService), 0644); err != nil {
		return fmt.Errorf("failed to write service: %w", err)
	}
	fmt.Printf("  Service: %s\n", servicePath)

	// Install desktop file
	desktopEntry := generateDesktopEntry(binPath)
	desktopPath := filepath.Join(desktopDir, "witnessd-ibus-setup.desktop")
	if err := os.WriteFile(desktopPath, []byte(desktopEntry), 0644); err != nil {
		return fmt.Errorf("failed to write desktop file: %w", err)
	}
	fmt.Printf("  Desktop: %s\n", desktopPath)

	// Create default config
	if err := writeDefaultConfig(configDir); err != nil {
		log.Printf("Warning: failed to write default config: %v", err)
	}

	fmt.Println("\nInstallation complete!")
	return nil
}

// generateComponentXML generates the IBus component XML.
func generateComponentXML(binPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<component>
    <name>com.witnessd.ibus</name>
    <description>Witnessd Cryptographic Authorship Witnessing</description>
    <exec>%s --ibus</exec>
    <version>%s</version>
    <author>Witnessd Project</author>
    <license>MIT</license>
    <homepage>https://github.com/witnessd/witnessd</homepage>
    <textdomain>witnessd</textdomain>
    <engines>
        <engine>
            <name>witnessd</name>
            <language>en</language>
            <license>MIT</license>
            <author>Witnessd Project</author>
            <icon>witnessd</icon>
            <layout>us</layout>
            <longname>Witnessd</longname>
            <description>Cryptographic authorship witnessing keyboard</description>
            <rank>99</rank>
            <symbol>W</symbol>
            <setup>%s --configure</setup>
        </engine>
    </engines>
</component>`, binPath, Version, binPath)
}

// generateSystemdService generates the systemd user service file.
func generateSystemdService(binPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Witnessd IBus Input Method Engine
Documentation=https://github.com/witnessd/witnessd
After=ibus.service dbus.service

[Service]
Type=simple
ExecStart=%s --ibus
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`, binPath)
}

// generateDesktopEntry generates the desktop entry file.
func generateDesktopEntry(binPath string) string {
	return fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=Witnessd IBus Settings
GenericName=Witnessd Configuration
Comment=Configure Witnessd cryptographic authorship witnessing
Exec=%s --configure
Icon=witnessd
Terminal=false
Categories=Settings;IBus;Utility;
`, binPath)
}

// writeDefaultConfig writes the default configuration file.
func writeDefaultConfig(configDir string) error {
	configPath := filepath.Join(configDir, "config.json")

	// Don't overwrite existing config
	if _, err := os.Stat(configPath); err == nil {
		return nil
	}

	config := map[string]interface{}{
		"version": Version,
		"engine": map[string]interface{}{
			"batch_size":     50,
			"flush_interval": "5s",
			"debug":          false,
		},
		"storage": map[string]interface{}{
			"evidence_dir":    "~/.local/share/witnessd/evidence",
			"retention_days":  90,
			"compress":        true,
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0600)
}

// uninstallComponent removes installed files.
func uninstallComponent() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	fmt.Println("Uninstalling Witnessd IBus Engine...")

	// Files to remove
	files := []string{
		filepath.Join(home, ".local", "share", "ibus", "component", "witnessd.xml"),
		filepath.Join(home, ".config", "systemd", "user", "witnessd-ibus.service"),
		filepath.Join(home, ".local", "share", "applications", "witnessd-ibus-setup.desktop"),
		filepath.Join(home, ".local", "share", "applications", "witnessd.desktop"),
	}

	for _, f := range files {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: failed to remove %s: %v", f, err)
		} else if err == nil {
			fmt.Printf("  Removed: %s\n", f)
		}
	}

	fmt.Println("\nUninstallation complete!")
	fmt.Println("Note: Data directory was preserved. To remove:")
	fmt.Printf("  rm -rf %s\n", filepath.Join(home, ".local", "share", "witnessd"))
	fmt.Printf("  rm -rf %s\n", filepath.Join(home, ".config", "witnessd"))

	return nil
}

// showStatus displays status information.
func showStatus() {
	home, _ := os.UserHomeDir()

	fmt.Println("=== Witnessd IBus Engine Status ===")
	fmt.Printf("Version: %s (commit %s)\n\n", Version, Commit)

	// Check component installation
	componentPath := filepath.Join(home, ".local", "share", "ibus", "component", "witnessd.xml")
	if _, err := os.Stat(componentPath); err == nil {
		fmt.Println("Component: Installed")
		fmt.Printf("  Path: %s\n", componentPath)
	} else {
		fmt.Println("Component: Not installed")
	}

	// Check systemd service
	servicePath := filepath.Join(home, ".config", "systemd", "user", "witnessd-ibus.service")
	if _, err := os.Stat(servicePath); err == nil {
		fmt.Println("\nSystemd service: Installed")
	} else {
		fmt.Println("\nSystemd service: Not installed")
	}

	// Check if IBus daemon is running
	fmt.Println("\nIBus Daemon:")
	conn, err := dbus.SessionBus()
	if err != nil {
		fmt.Printf("  Cannot connect to session bus: %v\n", err)
	} else {
		defer conn.Close()

		// Check for IBus bus name
		var names []string
		err = conn.BusObject().Call("org.freedesktop.DBus.ListNames", 0).Store(&names)
		if err == nil {
			hasIBus := false
			for _, name := range names {
				if name == "org.freedesktop.IBus" {
					hasIBus = true
					break
				}
			}
			if hasIBus {
				fmt.Println("  Status: Running")
			} else {
				fmt.Println("  Status: Not running")
			}
		}
	}

	// Check data directory
	dataDir := filepath.Join(home, ".local", "share", "witnessd")
	evidenceDir := filepath.Join(dataDir, "evidence")
	fmt.Println("\nData directory:")
	if info, err := os.Stat(dataDir); err == nil {
		fmt.Printf("  Path: %s\n", dataDir)
		fmt.Printf("  Modified: %s\n", info.ModTime().Format(time.RFC3339))

		// Count evidence files
		if entries, err := os.ReadDir(evidenceDir); err == nil {
			fmt.Printf("  Evidence files: %d\n", len(entries))
		}
	} else {
		fmt.Println("  Not created")
	}

	// Check logs
	logPath := filepath.Join(dataDir, "logs", "ibus.log")
	if info, err := os.Stat(logPath); err == nil {
		fmt.Println("\nLog file:")
		fmt.Printf("  Path: %s\n", logPath)
		fmt.Printf("  Size: %d bytes\n", info.Size())
		fmt.Printf("  Modified: %s\n", info.ModTime().Format(time.RFC3339))
	}

	fmt.Println("\n=== Environment ===")
	fmt.Printf("DISPLAY: %s\n", os.Getenv("DISPLAY"))
	fmt.Printf("WAYLAND_DISPLAY: %s\n", os.Getenv("WAYLAND_DISPLAY"))
	fmt.Printf("XDG_SESSION_TYPE: %s\n", os.Getenv("XDG_SESSION_TYPE"))
	fmt.Printf("DBUS_SESSION_BUS_ADDRESS: %s\n", os.Getenv("DBUS_SESSION_BUS_ADDRESS"))
}

// openConfiguration opens the configuration UI.
func openConfiguration() {
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".config", "witnessd", "config.json")

	fmt.Println("Witnessd IBus Configuration")
	fmt.Println("============================")
	fmt.Printf("\nConfiguration file: %s\n", configPath)

	// Read current config
	if data, err := os.ReadFile(configPath); err == nil {
		fmt.Println("\nCurrent configuration:")
		fmt.Println(string(data))
	} else {
		fmt.Println("\nNo configuration file found.")
		fmt.Println("A default configuration will be created on first run.")
	}

	fmt.Println("\nTo edit configuration:")
	fmt.Printf("  $EDITOR %s\n", configPath)

	// Show data directory stats
	dataDir := filepath.Join(home, ".local", "share", "witnessd")
	evidenceDir := filepath.Join(dataDir, "evidence")

	if entries, err := os.ReadDir(evidenceDir); err == nil && len(entries) > 0 {
		var totalSize int64
		for _, entry := range entries {
			if info, err := entry.Info(); err == nil {
				totalSize += info.Size()
			}
		}
		fmt.Printf("\nEvidence storage: %d files, %.2f MB\n", len(entries), float64(totalSize)/(1024*1024))
	}

	fmt.Println("\nUseful commands:")
	fmt.Println("  witnessd-ibus --status    # Show status")
	fmt.Println("  witnessd-ibus --install   # Reinstall")
	fmt.Println("  ibus restart              # Restart IBus")
	fmt.Println("  ibus-setup                # Open IBus preferences")
}
