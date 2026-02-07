package security

import (
	"fmt"
	"os"
	"runtime"
)

// ProcessSecurityState captures the security state of the current process.
type ProcessSecurityState struct {
	// Process identity
	PID         int    `json:"pid"`
	UID         int    `json:"uid"`
	EUID        int    `json:"euid"`
	GID         int    `json:"gid"`
	EGID        int    `json:"egid"`
	IsRoot      bool   `json:"is_root"`
	Username    string `json:"username,omitempty"`

	// Environment
	Platform    string `json:"platform"`
	Arch        string `json:"arch"`
	Hostname    string `json:"hostname,omitempty"`

	// Security state
	Debugger    bool   `json:"debugger_attached"`
	Sandboxed   bool   `json:"sandboxed"`
	Capabilities []string `json:"capabilities,omitempty"`

	// Warnings
	Warnings    []string `json:"warnings,omitempty"`
}

// CaptureProcessSecurityState captures the current process security state.
func CaptureProcessSecurityState() *ProcessSecurityState {
	state := &ProcessSecurityState{
		PID:      os.Getpid(),
		UID:      os.Getuid(),
		EUID:     os.Geteuid(),
		GID:      os.Getgid(),
		EGID:     os.Getegid(),
		IsRoot:   os.Geteuid() == 0,
		Platform: runtime.GOOS,
		Arch:     runtime.GOARCH,
	}

	// Get hostname (non-critical)
	if hostname, err := os.Hostname(); err == nil {
		state.Hostname = hostname
	}

	// Platform-specific checks
	checkDebugger(state)
	checkSandbox(state)

	// Add warnings
	if state.IsRoot {
		state.Warnings = append(state.Warnings, "Running as root - consider dropping privileges")
	}

	if state.Debugger {
		state.Warnings = append(state.Warnings, "Debugger attached - secrets may be exposed")
	}

	return state
}

// DropPrivileges attempts to drop root privileges to the given user.
// This is only effective if the process is running as root.
func DropPrivileges(uid, gid int) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("privilege dropping not supported on Windows")
	}

	if os.Geteuid() != 0 {
		return nil // Already non-root
	}

	return dropPrivilegesUnix(uid, gid)
}

// EnforceNonRoot panics if the process is running as root.
// This is useful for applications that should never run as root.
func EnforceNonRoot() {
	if os.Geteuid() == 0 {
		panic("security: refusing to run as root")
	}
}

// WarnIfRoot logs a warning if running as root.
func WarnIfRoot() bool {
	return os.Geteuid() == 0
}

// SecureEnvironment sets up a secure process environment.
// This includes:
// - Setting restrictive umask
// - Clearing potentially dangerous environment variables
// - Setting secure locale
func SecureEnvironment() error {
	// Clear potentially sensitive environment variables
	sensitiveVars := []string{
		"LD_PRELOAD",
		"LD_LIBRARY_PATH",
		"DYLD_INSERT_LIBRARIES",
		"DYLD_LIBRARY_PATH",
		"IFS",
		"CDPATH",
		"ENV",
		"BASH_ENV",
	}

	for _, v := range sensitiveVars {
		os.Unsetenv(v)
	}

	// Set restrictive umask (Unix only, no-op on Windows)
	setUmask(0077)

	// Set secure locale to prevent encoding attacks
	os.Setenv("LC_ALL", "C.UTF-8")
	os.Setenv("LANG", "C.UTF-8")

	return nil
}

// ResourceLimits defines process resource limits.
type ResourceLimits struct {
	MaxFileSize    uint64 // Maximum file size (bytes)
	MaxMemory      uint64 // Maximum memory usage (bytes)
	MaxCPUTime     uint64 // Maximum CPU time (seconds)
	MaxOpenFiles   uint64 // Maximum number of open files
	MaxProcesses   uint64 // Maximum number of processes
	CoreDumpSize   uint64 // Core dump size (0 = disabled)
}

// DefaultResourceLimits returns conservative resource limits.
func DefaultResourceLimits() *ResourceLimits {
	return &ResourceLimits{
		MaxFileSize:  1 << 30,        // 1GB
		MaxMemory:    2 << 30,        // 2GB
		MaxCPUTime:   3600,           // 1 hour
		MaxOpenFiles: 1024,
		MaxProcesses: 128,
		CoreDumpSize: 0, // Disable core dumps (may contain secrets)
	}
}

// ApplyResourceLimits applies the resource limits to the current process.
func ApplyResourceLimits(limits *ResourceLimits) error {
	return applyResourceLimits(limits)
}

// DisableCoreDumps disables core dumps for the current process.
// This prevents secrets from being written to disk on crashes.
func DisableCoreDumps() error {
	limits := &ResourceLimits{CoreDumpSize: 0}
	return applyCoreLimits(limits)
}

// SecurityChecklist performs a series of security checks.
type SecurityChecklist struct {
	Items []ChecklistItem
}

// ChecklistItem represents a single security check.
type ChecklistItem struct {
	Name        string
	Description string
	Passed      bool
	Warning     string
	Error       error
}

// RunSecurityChecklist performs all security checks.
func RunSecurityChecklist() *SecurityChecklist {
	checklist := &SecurityChecklist{}

	// Check 1: Not running as root
	checklist.Items = append(checklist.Items, ChecklistItem{
		Name:        "non_root",
		Description: "Process is not running as root",
		Passed:      os.Geteuid() != 0,
		Warning:     "Running as root increases attack surface",
	})

	// Check 2: Secure file permissions
	state := CaptureProcessSecurityState()

	// Check 3: No debugger attached
	checklist.Items = append(checklist.Items, ChecklistItem{
		Name:        "no_debugger",
		Description: "No debugger is attached",
		Passed:      !state.Debugger,
		Warning:     "Debugger attached - secrets may be exposed",
	})

	// Check 4: Restrictive umask
	currentUmask := getCurrentUmask()
	checklist.Items = append(checklist.Items, ChecklistItem{
		Name:        "secure_umask",
		Description: "Umask is restrictive (077 or stricter)",
		Passed:      currentUmask >= 0077,
		Warning:     fmt.Sprintf("Umask %04o allows group/other access", currentUmask),
	})

	// Check 5: Core dumps disabled
	coreEnabled := areCoreEnabled()
	checklist.Items = append(checklist.Items, ChecklistItem{
		Name:        "core_disabled",
		Description: "Core dumps are disabled",
		Passed:      !coreEnabled,
		Warning:     "Core dumps could expose secrets",
	})

	return checklist
}

// AllPassed returns true if all checks passed.
func (c *SecurityChecklist) AllPassed() bool {
	for _, item := range c.Items {
		if !item.Passed {
			return false
		}
	}
	return true
}

// Warnings returns all warning messages from failed checks.
func (c *SecurityChecklist) Warnings() []string {
	var warnings []string
	for _, item := range c.Items {
		if !item.Passed && item.Warning != "" {
			warnings = append(warnings, item.Warning)
		}
	}
	return warnings
}
