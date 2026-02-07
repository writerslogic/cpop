//go:build windows

// Package ipc provides Windows-specific client implementation.
//
// Patent Pending: USPTO Application No. 19/460,364
package ipc

import (
	"net"
	"syscall"
	"time"
)

// connectWindows establishes a Windows named pipe connection
func (c *IPCClient) connectWindows() (net.Conn, error) {
	pipeName := WindowsPipePath(c.socketPath)

	// Try to connect with retry for busy pipe
	var handle syscall.Handle
	var err error

	for i := 0; i < 3; i++ {
		handle, err = syscall.CreateFile(
			syscall.StringToUTF16Ptr(pipeName),
			syscall.GENERIC_READ|syscall.GENERIC_WRITE,
			0,
			nil,
			syscall.OPEN_EXISTING,
			0,
			0,
		)
		if err == nil {
			break
		}

		// If pipe is busy, wait and retry
		errno, ok := err.(syscall.Errno)
		if !ok || errno != 231 { // ERROR_PIPE_BUSY
			return nil, err
		}

		time.Sleep(100 * time.Millisecond)
	}

	if err != nil {
		return nil, err
	}

	return &WindowsPipeConn{
		handle:   handle,
		pipeName: pipeName,
	}, nil
}
