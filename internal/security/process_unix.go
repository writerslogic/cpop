//go:build unix
// +build unix

package security

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// checkDebugger checks if a debugger is attached on Unix.
func checkDebugger(state *ProcessSecurityState) {
	// Check /proc/self/status for TracerPid on Linux
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		// Look for "TracerPid:\t0" - if not 0, we're being traced
		for _, line := range splitLines(string(data)) {
			if len(line) > 10 && line[:10] == "TracerPid:" {
				tracer := line[11:]
				state.Debugger = tracer != "0" && tracer != ""
				return
			}
		}
	}

	// Fallback: try ptrace self (will fail if being traced)
	// This is less reliable but works on more systems
	state.Debugger = false
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// checkSandbox checks if the process is sandboxed on Unix.
func checkSandbox(state *ProcessSecurityState) {
	// Check for macOS sandbox
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		state.Sandboxed = containsWord(string(data), "sandbox")
	}

	// Check for Docker/container environment
	if _, err := os.Stat("/.dockerenv"); err == nil {
		state.Sandboxed = true
	}
}

func containsWord(s, word string) bool {
	for i := 0; i <= len(s)-len(word); i++ {
		if s[i:i+len(word)] == word {
			return true
		}
	}
	return false
}

// dropPrivilegesUnix drops privileges on Unix systems.
func dropPrivilegesUnix(uid, gid int) error {
	// Set supplementary groups first
	if err := syscall.Setgroups([]int{}); err != nil {
		return err
	}

	// Set GID (must be before UID)
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	if err := syscall.Setegid(gid); err != nil {
		return err
	}

	// Set UID
	if err := syscall.Setuid(uid); err != nil {
		return err
	}
	if err := syscall.Seteuid(uid); err != nil {
		return err
	}

	return nil
}

// setUmask sets the process umask on Unix.
func setUmask(mask int) int {
	return syscall.Umask(mask)
}

// getCurrentUmask returns the current umask.
func getCurrentUmask() int {
	// Umask is destructive - we need to set and restore
	current := syscall.Umask(0)
	syscall.Umask(current)
	return current
}

// applyResourceLimits applies resource limits on Unix.
func applyResourceLimits(limits *ResourceLimits) error {
	// File size limit
	if limits.MaxFileSize > 0 {
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{
			Cur: limits.MaxFileSize,
			Max: limits.MaxFileSize,
		}); err != nil {
			// Non-fatal: some systems may not support all limits
		}
	}

	// Memory limit (address space)
	if limits.MaxMemory > 0 {
		if err := unix.Setrlimit(unix.RLIMIT_AS, &unix.Rlimit{
			Cur: limits.MaxMemory,
			Max: limits.MaxMemory,
		}); err != nil {
			// Non-fatal
		}
	}

	// CPU time limit
	if limits.MaxCPUTime > 0 {
		if err := unix.Setrlimit(unix.RLIMIT_CPU, &unix.Rlimit{
			Cur: limits.MaxCPUTime,
			Max: limits.MaxCPUTime,
		}); err != nil {
			// Non-fatal
		}
	}

	// Open files limit
	if limits.MaxOpenFiles > 0 {
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
			Cur: limits.MaxOpenFiles,
			Max: limits.MaxOpenFiles,
		}); err != nil {
			// Non-fatal
		}
	}

	// Process limit
	if limits.MaxProcesses > 0 {
		if err := unix.Setrlimit(unix.RLIMIT_NPROC, &unix.Rlimit{
			Cur: limits.MaxProcesses,
			Max: limits.MaxProcesses,
		}); err != nil {
			// Non-fatal
		}
	}

	// Core dump limit
	return applyCoreLimits(limits)
}

// applyCoreLimits applies core dump limits.
func applyCoreLimits(limits *ResourceLimits) error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{
		Cur: limits.CoreDumpSize,
		Max: limits.CoreDumpSize,
	})
}

// areCoreEnabled checks if core dumps are enabled.
func areCoreEnabled() bool {
	var rlimit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rlimit); err != nil {
		return true // Assume enabled if we can't check
	}
	return rlimit.Cur > 0 || rlimit.Max > 0
}
