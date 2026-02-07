//go:build darwin

// Package ipc provides Darwin/macOS-specific server implementation.
//
// Patent Pending: USPTO Application No. 19/460,364
package ipc

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// GetPeerCredentials retrieves the credentials of the peer process
// connected to a Unix socket. This allows verification that the
// connecting process is from the same user.
// On macOS, we use LOCAL_PEERCRED via the x/sys/unix package.
func GetPeerCredentials(conn net.Conn) (*PeerCredentials, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("not a unix connection")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("get raw conn: %w", err)
	}

	var cred *unix.Xucred
	var credErr error

	err = rawConn.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	if credErr != nil {
		return nil, fmt.Errorf("getsockopt: %w", credErr)
	}

	return &PeerCredentials{
		PID: 0, // macOS Xucred doesn't include PID
		UID: int(cred.Uid),
		GID: int(cred.Groups[0]), // Primary group
	}, nil
}

// GetPeerPID attempts to get the peer process ID on macOS.
// This is a best-effort function; may return 0 if unavailable.
func GetPeerPID(conn net.Conn) (int, error) {
	// macOS LOCAL_PEERPID requires a different approach
	// For now, return 0 as PID is not critical for security checks
	return 0, nil
}

// VerifyPeerIsCurrentUser checks if the peer is running as the current user
func VerifyPeerIsCurrentUser(conn net.Conn) (bool, error) {
	cred, err := GetPeerCredentials(conn)
	if err != nil {
		return false, err
	}

	return cred.UID == os.Getuid(), nil
}
