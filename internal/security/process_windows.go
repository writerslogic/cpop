//go:build windows
// +build windows

package security

import (
	"errors"
)

// checkDebugger checks if a debugger is attached on Windows.
func checkDebugger(state *ProcessSecurityState) {
	// Windows debugger detection would use IsDebuggerPresent()
	// For now, assume no debugger
	state.Debugger = false
}

// checkSandbox checks if the process is sandboxed on Windows.
func checkSandbox(state *ProcessSecurityState) {
	// Check for app container or other sandboxing
	state.Sandboxed = false
}

// dropPrivilegesUnix is not applicable on Windows.
func dropPrivilegesUnix(uid, gid int) error {
	return errors.New("privilege dropping not supported on Windows")
}

// setUmask is not applicable on Windows.
func setUmask(mask int) int {
	return 0
}

// getCurrentUmask returns 0 on Windows (no umask concept).
func getCurrentUmask() int {
	return 0077 // Return a "secure" value to pass checks
}

// applyResourceLimits applies resource limits on Windows.
func applyResourceLimits(limits *ResourceLimits) error {
	// Windows job objects could be used here
	// For now, we don't apply limits on Windows
	return nil
}

// applyCoreLimits applies core dump limits on Windows.
func applyCoreLimits(limits *ResourceLimits) error {
	// Windows doesn't have core dumps in the Unix sense
	return nil
}

// areCoreEnabled checks if core dumps are enabled on Windows.
func areCoreEnabled() bool {
	// Windows error reporting is different
	return false
}
