//go:build linux

// Package ipc provides Linux-specific server implementation.
//
// Patent Pending: USPTO Application No. 19/460,364
package ipc

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// GetPeerCredentials retrieves the credentials of the peer process
// connected to a Unix socket. This allows verification that the
// connecting process is from the same user.
func GetPeerCredentials(conn net.Conn) (*PeerCredentials, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("not a unix connection")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("get raw conn: %w", err)
	}

	var cred *syscall.Ucred
	var credErr error

	err = rawConn.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	if credErr != nil {
		return nil, fmt.Errorf("getsockopt: %w", credErr)
	}

	return &PeerCredentials{
		PID: int(cred.Pid),
		UID: int(cred.Uid),
		GID: int(cred.Gid),
	}, nil
}

// VerifyPeerIsCurrentUser checks if the peer is running as the current user
func VerifyPeerIsCurrentUser(conn net.Conn) (bool, error) {
	cred, err := GetPeerCredentials(conn)
	if err != nil {
		return false, err
	}

	return cred.UID == os.Getuid(), nil
}
