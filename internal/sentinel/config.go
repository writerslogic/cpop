// Package sentinel configuration.
//
// The Active Document Sentinel monitors which documents have user focus and
// manages tracking sessions automatically. This file contains all configuration
// options for the sentinel daemon.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"os"
	"path/filepath"
	"time"
)

// Config configures the sentinel daemon.
type Config struct {
	// WitnessdDir is the base witnessd data directory
	WitnessdDir string

	// ShadowDir is where unsaved document content is cached
	ShadowDir string

	// WatchPaths are directories to monitor for file changes
	WatchPaths []string

	// RecursiveWatch enables watching subdirectories
	RecursiveWatch bool

	// DebounceDuration is how long to wait before applying focus changes
	// This prevents rapid focus switches from creating noise
	// Default: 500ms
	DebounceDuration time.Duration

	// IdleTimeout closes sessions after this much inactivity (0 = never)
	// Documents that haven't been focused for this duration will have
	// their sessions automatically closed
	IdleTimeout time.Duration

	// HeartbeatInterval is how often to write heartbeat entries to WAL
	HeartbeatInterval time.Duration

	// CheckpointInterval is how often to auto-commit checkpoints
	CheckpointInterval time.Duration

	// AllowedApps limits tracking to specific apps (empty = all apps)
	// Use bundle IDs on macOS (e.g., "com.microsoft.VSCode")
	// Use executable names on Linux/Windows (e.g., "code", "notepad++")
	AllowedApps []string

	// BlockedApps excludes specific apps from tracking
	// Takes precedence over AllowedApps
	BlockedApps []string

	// TrackUnknownApps controls whether to track apps not in allowlist
	// If true, apps not in AllowedApps are tracked (unless blocked)
	// If false, only apps in AllowedApps are tracked
	TrackUnknownApps bool

	// AutoStart indicates whether sentinel should start automatically
	AutoStart bool

	// AutoStartDocuments lists documents to track on startup
	AutoStartDocuments []string

	// WAL configuration
	WALDir            string
	WALSyncInterval   time.Duration
	WALTruncateOnExit bool

	// MinFocusDuration is the minimum time a document must be focused
	// before a session is created. Prevents sessions for fleeting focus.
	// Default: 0 (create session immediately)
	MinFocusDuration time.Duration

	// MaxSessionDuration limits how long a session can run
	// Sessions exceeding this duration are automatically closed and restarted
	// Default: 0 (no limit)
	MaxSessionDuration time.Duration

	// HashOnFocus computes document hash when focus is gained
	// Useful for detecting external changes
	HashOnFocus bool

	// HashOnSave computes document hash when document is saved
	// Required for proper change tracking
	HashOnSave bool
}

// DefaultConfig returns sensible defaults for the sentinel.
func DefaultConfig() *Config {
	// Determine witnessd directory
	home, _ := os.UserHomeDir()
	witnessdDir := filepath.Join(home, ".witnessd")

	return &Config{
		WitnessdDir:        witnessdDir,
		ShadowDir:          filepath.Join(witnessdDir, "shadow"),
		WALDir:             filepath.Join(witnessdDir, "sentinel", "wal"),
		WatchPaths:         []string{},
		RecursiveWatch:     true,
		DebounceDuration:   500 * time.Millisecond,
		IdleTimeout:        30 * time.Minute,
		HeartbeatInterval:  60 * time.Second,
		CheckpointInterval: 60 * time.Second,
		WALSyncInterval:    100 * time.Millisecond,
		TrackUnknownApps:   true,
		WALTruncateOnExit:  true,
		HashOnFocus:        true,
		HashOnSave:         true,
		AllowedApps: []string{
			// macOS text editors and IDEs
			"com.apple.TextEdit",
			"com.microsoft.Word",
			"com.sublimetext.4",
			"com.sublimetext.3",
			"com.microsoft.VSCode",
			"com.microsoft.VSCodeInsiders",
			"com.jetbrains.intellij",
			"com.jetbrains.pycharm",
			"com.jetbrains.goland",
			"com.jetbrains.webstorm",
			"com.apple.dt.Xcode",
			"org.vim.MacVim",
			"com.panic.Nova",
			"com.barebones.bbedit",
			"abnerworks.Typora",
			"com.ulyssesapp.mac",
			"md.obsidian",
			// Linux/Windows equivalents (by executable name)
			"code",
			"sublime_text",
			"atom",
			"notepad++",
			"gedit",
			"kate",
			"vim",
			"nvim",
			"emacs",
		},
		BlockedApps: []string{
			// macOS system apps
			"com.apple.finder",
			"com.apple.systempreferences",
			"com.apple.SystemPreferences",
			"com.apple.Spotlight",
			"com.apple.controlcenter",
			"com.apple.notificationcenterui",
			// Linux system apps
			"nautilus",
			"dolphin",
			"thunar",
			// Windows system apps
			"explorer",
			"SearchUI",
		},
	}
}

// WithWitnessdDir sets the witnessd directory.
func (c *Config) WithWitnessdDir(dir string) *Config {
	c.WitnessdDir = dir
	c.ShadowDir = filepath.Join(dir, "shadow")
	c.WALDir = filepath.Join(dir, "sentinel", "wal")
	return c
}

// WithAutoStart enables auto-start of sentinel.
func (c *Config) WithAutoStart(enabled bool) *Config {
	c.AutoStart = enabled
	return c
}

// WithAutoStartDocuments sets documents to track on startup.
func (c *Config) WithAutoStartDocuments(docs []string) *Config {
	c.AutoStartDocuments = docs
	return c
}

// WithIdleTimeout sets the idle timeout.
func (c *Config) WithIdleTimeout(timeout time.Duration) *Config {
	c.IdleTimeout = timeout
	return c
}

// WithHeartbeatInterval sets the heartbeat interval.
func (c *Config) WithHeartbeatInterval(interval time.Duration) *Config {
	c.HeartbeatInterval = interval
	return c
}

// WithCheckpointInterval sets the checkpoint interval.
func (c *Config) WithCheckpointInterval(interval time.Duration) *Config {
	c.CheckpointInterval = interval
	return c
}

// WithWatchPaths sets directories to monitor for file changes.
func (c *Config) WithWatchPaths(paths []string) *Config {
	c.WatchPaths = paths
	return c
}

// WithRecursiveWatch enables or disables recursive directory watching.
func (c *Config) WithRecursiveWatch(enabled bool) *Config {
	c.RecursiveWatch = enabled
	return c
}

// WithDebounceDuration sets the focus change debounce duration.
func (c *Config) WithDebounceDuration(d time.Duration) *Config {
	c.DebounceDuration = d
	return c
}

// WithAllowedApps sets the list of apps to track.
func (c *Config) WithAllowedApps(apps []string) *Config {
	c.AllowedApps = apps
	return c
}

// WithBlockedApps sets the list of apps to exclude from tracking.
func (c *Config) WithBlockedApps(apps []string) *Config {
	c.BlockedApps = apps
	return c
}

// WithTrackUnknownApps enables or disables tracking of unknown apps.
func (c *Config) WithTrackUnknownApps(enabled bool) *Config {
	c.TrackUnknownApps = enabled
	return c
}

// AddAllowedApp adds an app to the allowed list.
func (c *Config) AddAllowedApp(app string) *Config {
	for _, a := range c.AllowedApps {
		if a == app {
			return c
		}
	}
	c.AllowedApps = append(c.AllowedApps, app)
	return c
}

// AddBlockedApp adds an app to the blocked list.
func (c *Config) AddBlockedApp(app string) *Config {
	for _, a := range c.BlockedApps {
		if a == app {
			return c
		}
	}
	c.BlockedApps = append(c.BlockedApps, app)
	return c
}

// AddWatchPath adds a path to the watch list.
func (c *Config) AddWatchPath(path string) *Config {
	for _, p := range c.WatchPaths {
		if p == path {
			return c
		}
	}
	c.WatchPaths = append(c.WatchPaths, path)
	return c
}

// IsAppAllowed returns whether an app should be tracked.
func (c *Config) IsAppAllowed(bundleID, appName string) bool {
	// Check blocklist first
	for _, blocked := range c.BlockedApps {
		if blocked == bundleID || blocked == appName {
			return false
		}
	}

	// If allowlist is empty, track all non-blocked apps (if enabled)
	if len(c.AllowedApps) == 0 {
		return c.TrackUnknownApps
	}

	// Check allowlist
	for _, allowed := range c.AllowedApps {
		if allowed == bundleID || allowed == appName {
			return true
		}
	}

	return c.TrackUnknownApps
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c.DebounceDuration < 0 {
		return ErrInvalidConfig{"debounce duration cannot be negative"}
	}
	if c.IdleTimeout < 0 {
		return ErrInvalidConfig{"idle timeout cannot be negative"}
	}
	if c.HeartbeatInterval < 0 {
		return ErrInvalidConfig{"heartbeat interval cannot be negative"}
	}
	if c.CheckpointInterval < 0 {
		return ErrInvalidConfig{"checkpoint interval cannot be negative"}
	}
	return nil
}

// ErrInvalidConfig represents a configuration error.
type ErrInvalidConfig struct {
	Message string
}

func (e ErrInvalidConfig) Error() string {
	return "sentinel: invalid config: " + e.Message
}

// EnsureDirectories creates all required directories.
func (c *Config) EnsureDirectories() error {
	dirs := []string{
		c.WitnessdDir,
		c.ShadowDir,
		c.WALDir,
	}

	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	return nil
}
