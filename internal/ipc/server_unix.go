//go:build !windows

// Package ipc provides Unix-specific server implementation.
//
// Patent Pending: USPTO Application No. 19/460,364
package ipc

import (
	"fmt"
	"net"
	"os"
)

// PeerCredentials holds the credentials of a peer process
type PeerCredentials struct {
	PID int
	UID int
	GID int
}

// SetSocketPermissions sets the socket file permissions
func SetSocketPermissions(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

// CleanupSocket removes a stale socket file
func CleanupSocket(path string) error {
	// Check if socket file exists and is actually a socket
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	// Only remove if it's a socket
	if info.Mode()&os.ModeSocket != 0 {
		return os.Remove(path)
	}

	return fmt.Errorf("path exists but is not a socket: %s", path)
}

// IsSocketListening checks if a socket is already listening
func IsSocketListening(path string) bool {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
