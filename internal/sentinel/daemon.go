// Package sentinel daemon management.
//
// Provides utilities for running the sentinel as a background daemon,
// including PID file management, signal handling, and IPC.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DaemonState represents the persistent state of the sentinel daemon.
type DaemonState struct {
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Version   string    `json:"version"`
	Identity  string    `json:"identity,omitempty"`
}

// DaemonManager handles daemon lifecycle operations.
type DaemonManager struct {
	witnessdDir string
	pidFile     string
	stateFile   string
	socketPath  string
}

// NewDaemonManager creates a daemon manager.
func NewDaemonManager(witnessdDir string) *DaemonManager {
	sentinelDir := filepath.Join(witnessdDir, "sentinel")
	return &DaemonManager{
		witnessdDir: witnessdDir,
		pidFile:     filepath.Join(sentinelDir, "daemon.pid"),
		stateFile:   filepath.Join(sentinelDir, "daemon.state"),
		socketPath:  filepath.Join(sentinelDir, "daemon.sock"),
	}
}

// IsRunning checks if the sentinel daemon is running.
func (m *DaemonManager) IsRunning() bool {
	pid, err := m.ReadPID()
	if err != nil {
		return false
	}

	return isProcessRunning(pid)
}

// ReadPID reads the daemon's PID from the PID file.
func (m *DaemonManager) ReadPID() (int, error) {
	data, err := os.ReadFile(m.pidFile)
	if err != nil {
		return 0, err
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid PID file: %w", err)
	}

	return pid, nil
}

// WritePID writes the current process PID to the PID file.
func (m *DaemonManager) WritePID() error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(m.pidFile), 0700); err != nil {
		return fmt.Errorf("create pid dir: %w", err)
	}

	return os.WriteFile(m.pidFile, []byte(strconv.Itoa(os.Getpid())), 0600)
}

// RemovePID removes the PID file.
func (m *DaemonManager) RemovePID() error {
	return os.Remove(m.pidFile)
}

// WriteState writes the daemon state.
func (m *DaemonManager) WriteState(state *DaemonState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	return os.WriteFile(m.stateFile, data, 0600)
}

// ReadState reads the daemon state.
func (m *DaemonManager) ReadState() (*DaemonState, error) {
	data, err := os.ReadFile(m.stateFile)
	if err != nil {
		return nil, err
	}

	var state DaemonState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}

	return &state, nil
}

// SignalStop sends SIGTERM to the daemon.
func (m *DaemonManager) SignalStop() error {
	pid, err := m.ReadPID()
	if err != nil {
		return fmt.Errorf("read PID: %w", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process: %w", err)
	}

	return process.Signal(syscall.SIGTERM)
}

// SignalReload sends SIGHUP to the daemon.
func (m *DaemonManager) SignalReload() error {
	pid, err := m.ReadPID()
	if err != nil {
		return fmt.Errorf("read PID: %w", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process: %w", err)
	}

	return process.Signal(syscall.SIGHUP)
}

// WaitForStop waits for the daemon to stop.
func (m *DaemonManager) WaitForStop(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if !m.IsRunning() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("daemon did not stop within %v", timeout)
}

// Cleanup removes PID and state files.
func (m *DaemonManager) Cleanup() {
	os.Remove(m.pidFile)
	os.Remove(m.stateFile)
	os.Remove(m.socketPath)
}

// Status returns the current daemon status.
func (m *DaemonManager) Status() (*DaemonStatus, error) {
	status := &DaemonStatus{}

	// Check if running
	pid, pidErr := m.ReadPID()
	if pidErr == nil && isProcessRunning(pid) {
		status.Running = true
		status.PID = pid
	}

	// Read state if available
	if state, err := m.ReadState(); err == nil {
		status.StartedAt = state.StartedAt
		status.Version = state.Version
		status.Identity = state.Identity
		if status.Running {
			status.Uptime = time.Since(state.StartedAt)
		}
	}

	return status, nil
}

// DaemonStatus represents the daemon status for display.
type DaemonStatus struct {
	Running   bool
	PID       int
	StartedAt time.Time
	Uptime    time.Duration
	Version   string
	Identity  string
}

// isProcessRunning checks if a process with the given PID is running.
func isProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// On Unix, FindProcess always succeeds. Send signal 0 to check if process exists.
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// SentinelDir returns the sentinel data directory path.
func SentinelDir(witnessdDir string) string {
	return filepath.Join(witnessdDir, "sentinel")
}

// WALDir returns the WAL directory path.
func WALDir(witnessdDir string) string {
	return filepath.Join(witnessdDir, "sentinel", "wal")
}
