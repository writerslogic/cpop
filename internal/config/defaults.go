// Package config handles configuration loading and validation for witnessd.
package config

import (
	"os"
	"path/filepath"
	"runtime"
)

// PlatformDataDir returns the platform-specific data directory.
//
// Platform paths:
//   - macOS:   ~/Library/Application Support/witnessd/
//   - Linux:   ~/.local/share/witnessd/
//   - Windows: %APPDATA%\witnessd\
//
// Falls back to ~/.witnessd if platform detection fails.
func PlatformDataDir() string {
	switch runtime.GOOS {
	case "darwin":
		return macOSDataDir()
	case "linux":
		return linuxDataDir()
	case "windows":
		return windowsDataDir()
	default:
		return fallbackDataDir()
	}
}

// PlatformCacheDir returns the platform-specific cache directory.
//
// Platform paths:
//   - macOS:   ~/Library/Caches/witnessd/
//   - Linux:   ~/.cache/witnessd/
//   - Windows: %LOCALAPPDATA%\witnessd\cache\
func PlatformCacheDir() string {
	switch runtime.GOOS {
	case "darwin":
		return macOSCacheDir()
	case "linux":
		return linuxCacheDir()
	case "windows":
		return windowsCacheDir()
	default:
		return filepath.Join(fallbackDataDir(), "cache")
	}
}

// PlatformConfigDir returns the platform-specific config directory.
//
// Platform paths:
//   - macOS:   ~/Library/Application Support/witnessd/
//   - Linux:   ~/.config/witnessd/
//   - Windows: %APPDATA%\witnessd\
func PlatformConfigDir() string {
	switch runtime.GOOS {
	case "darwin":
		return macOSDataDir() // macOS uses same dir for config and data
	case "linux":
		return linuxConfigDir()
	case "windows":
		return windowsDataDir() // Windows uses same dir for config and data
	default:
		return fallbackDataDir()
	}
}

// PlatformLogDir returns the platform-specific log directory.
//
// Platform paths:
//   - macOS:   ~/Library/Logs/witnessd/
//   - Linux:   ~/.local/share/witnessd/logs/
//   - Windows: %LOCALAPPDATA%\witnessd\logs\
func PlatformLogDir() string {
	switch runtime.GOOS {
	case "darwin":
		return macOSLogDir()
	case "linux":
		return filepath.Join(linuxDataDir(), "logs")
	case "windows":
		return windowsLogDir()
	default:
		return filepath.Join(fallbackDataDir(), "logs")
	}
}

// PlatformRuntimeDir returns the platform-specific runtime directory for sockets/pipes.
//
// Platform paths:
//   - macOS:   /tmp/witnessd-$UID/
//   - Linux:   $XDG_RUNTIME_DIR/witnessd/ or /tmp/witnessd-$UID/
//   - Windows: (uses named pipes, not applicable)
func PlatformRuntimeDir() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join("/tmp", "witnessd-"+getUserID())
	case "linux":
		return linuxRuntimeDir()
	case "windows":
		return "" // Windows uses named pipes
	default:
		return filepath.Join("/tmp", "witnessd-"+getUserID())
	}
}

// macOS-specific paths

func macOSDataDir() string {
	home := os.Getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return filepath.Join(home, "Library", "Application Support", "witnessd")
}

func macOSCacheDir() string {
	home := os.Getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return filepath.Join(home, "Library", "Caches", "witnessd")
}

func macOSLogDir() string {
	home := os.Getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return filepath.Join(home, "Library", "Logs", "witnessd")
}

// Linux-specific paths following XDG Base Directory Specification

func linuxDataDir() string {
	// XDG_DATA_HOME or ~/.local/share
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		return filepath.Join(xdgData, "witnessd")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "witnessd")
}

func linuxConfigDir() string {
	// XDG_CONFIG_HOME or ~/.config
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "witnessd")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "witnessd")
}

func linuxCacheDir() string {
	// XDG_CACHE_HOME or ~/.cache
	if xdgCache := os.Getenv("XDG_CACHE_HOME"); xdgCache != "" {
		return filepath.Join(xdgCache, "witnessd")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "witnessd")
}

func linuxRuntimeDir() string {
	// XDG_RUNTIME_DIR (usually /run/user/$UID)
	if xdgRuntime := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntime != "" {
		return filepath.Join(xdgRuntime, "witnessd")
	}
	// Fallback to /tmp
	return filepath.Join("/tmp", "witnessd-"+getUserID())
}

// Windows-specific paths

func windowsDataDir() string {
	// %APPDATA% (roaming)
	if appData := os.Getenv("APPDATA"); appData != "" {
		return filepath.Join(appData, "witnessd")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "AppData", "Roaming", "witnessd")
}

func windowsCacheDir() string {
	// %LOCALAPPDATA% (local)
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		return filepath.Join(localAppData, "witnessd", "cache")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "AppData", "Local", "witnessd", "cache")
}

func windowsLogDir() string {
	// %LOCALAPPDATA% (local)
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		return filepath.Join(localAppData, "witnessd", "logs")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "AppData", "Local", "witnessd", "logs")
}

// Fallback path (legacy compatibility)

func fallbackDataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".witnessd")
}

// Helper to get user ID as string
func getUserID() string {
	// On Unix systems
	if uid := os.Getuid(); uid >= 0 {
		return string(rune(uid))
	}
	// Fallback
	return "0"
}

// DefaultPaths returns all default paths for a platform.
type DefaultPaths struct {
	DataDir    string
	ConfigDir  string
	CacheDir   string
	LogDir     string
	RuntimeDir string

	// Specific file paths
	ConfigFile     string
	DatabaseFile   string
	MMRFile        string
	SigningKeyFile string
	PublicKeyFile  string
	IdentityFile   string
	PUFSeedFile    string
	SocketPath     string
	PIDFile        string
}

// GetDefaultPaths returns all default paths for the current platform.
func GetDefaultPaths() *DefaultPaths {
	dataDir := PlatformDataDir()
	configDir := PlatformConfigDir()
	cacheDir := PlatformCacheDir()
	logDir := PlatformLogDir()
	runtimeDir := PlatformRuntimeDir()

	return &DefaultPaths{
		DataDir:    dataDir,
		ConfigDir:  configDir,
		CacheDir:   cacheDir,
		LogDir:     logDir,
		RuntimeDir: runtimeDir,

		ConfigFile:     filepath.Join(configDir, "config.toml"),
		DatabaseFile:   filepath.Join(dataDir, "events.db"),
		MMRFile:        filepath.Join(dataDir, "mmr.db"),
		SigningKeyFile: filepath.Join(dataDir, "signing_key"),
		PublicKeyFile:  filepath.Join(dataDir, "signing_key.pub"),
		IdentityFile:   filepath.Join(dataDir, "identity.json"),
		PUFSeedFile:    filepath.Join(dataDir, "puf_seed"),
		SocketPath:     getDefaultSocketPath(runtimeDir),
		PIDFile:        filepath.Join(runtimeDir, "witnessd.pid"),
	}
}

func getDefaultSocketPath(runtimeDir string) string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\witnessd`
	}
	if runtimeDir != "" {
		return filepath.Join(runtimeDir, "witnessd.sock")
	}
	return "/tmp/witnessd.sock"
}

// DefaultDocumentPatterns returns default include patterns for documents.
func DefaultDocumentPatterns() []string {
	return []string{
		// Text documents
		"*.txt",
		"*.md",
		"*.markdown",
		"*.rst",
		"*.adoc",
		"*.asciidoc",

		// Word processors
		"*.doc",
		"*.docx",
		"*.odt",
		"*.rtf",

		// LaTeX
		"*.tex",
		"*.latex",
		"*.bib",

		// Source code (for technical writing)
		"*.py",
		"*.js",
		"*.ts",
		"*.go",
		"*.rs",
		"*.c",
		"*.cpp",
		"*.h",
		"*.java",

		// Web documents
		"*.html",
		"*.htm",
		"*.xml",
		"*.json",
		"*.yaml",
		"*.yml",
	}
}

// DefaultExcludePatterns returns default exclude patterns.
func DefaultExcludePatterns() []string {
	return []string{
		// Hidden files
		".*",
		"*/.*",

		// Temporary files
		"*~",
		"*.tmp",
		"*.temp",
		"*.swp",
		"*.swo",
		"*.bak",
		"*.backup",

		// Build artifacts
		"*.o",
		"*.a",
		"*.so",
		"*.dll",
		"*.exe",
		"*.pyc",
		"*.pyo",
		"__pycache__/*",

		// Version control
		".git/*",
		".svn/*",
		".hg/*",

		// IDE/Editor
		".idea/*",
		".vscode/*",
		"*.sublime-*",

		// Node.js
		"node_modules/*",

		// Python
		".venv/*",
		"venv/*",
		".env/*",

		// macOS
		".DS_Store",
		"._*",

		// Windows
		"Thumbs.db",
		"desktop.ini",
	}
}

// Platform constants for feature detection
const (
	PlatformMacOS   = "darwin"
	PlatformLinux   = "linux"
	PlatformWindows = "windows"
)

// HasTPMSupport returns true if the platform may have TPM support.
func HasTPMSupport() bool {
	switch runtime.GOOS {
	case "linux", "windows":
		return true
	default:
		return false
	}
}

// HasSecureEnclaveSupport returns true if the platform may have Secure Enclave.
func HasSecureEnclaveSupport() bool {
	return runtime.GOOS == "darwin"
}

// HasAccessibilityAPISupport returns true if the platform supports keystroke monitoring.
func HasAccessibilityAPISupport() bool {
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		return true
	default:
		return false
	}
}

// RecommendedVDFIterations returns platform-specific VDF recommendations.
func RecommendedVDFIterations() (min, max, perSecond uint64) {
	// These are conservative defaults; actual values come from calibration
	switch runtime.GOARCH {
	case "amd64", "arm64":
		// Modern 64-bit systems
		return 100000, 3600000000, 1000000
	case "386", "arm":
		// Older 32-bit systems
		return 50000, 1800000000, 500000
	default:
		return 100000, 3600000000, 1000000
	}
}

// DefaultWALSettings returns platform-appropriate WAL settings.
func DefaultWALSettings() (maxSize int64, syncMode string) {
	switch runtime.GOOS {
	case "darwin":
		// macOS has good filesystem support
		return 64 * 1024 * 1024, "normal"
	case "linux":
		// Linux may have various filesystems
		return 64 * 1024 * 1024, "normal"
	case "windows":
		// Windows NTFS
		return 32 * 1024 * 1024, "full"
	default:
		return 32 * 1024 * 1024, "full"
	}
}

// SupportedConfigFormats returns the list of supported config file formats.
func SupportedConfigFormats() []string {
	return []string{
		"toml",
		"json",
		"yaml",
		"yml",
	}
}

// FindConfigFile searches for a config file in standard locations.
// Returns the path to the first found config file, or empty string if none found.
func FindConfigFile() string {
	paths := GetDefaultPaths()

	// Search order:
	// 1. Current directory
	// 2. Config directory
	// 3. Data directory (legacy)
	searchDirs := []string{
		".",
		paths.ConfigDir,
		paths.DataDir,
	}

	for _, dir := range searchDirs {
		for _, ext := range SupportedConfigFormats() {
			path := filepath.Join(dir, "config."+ext)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}

	return ""
}
