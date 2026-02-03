//go:build !windows

package main

import "syscall"

// getDaemonSysProcAttr returns the SysProcAttr for detaching a daemon process on Unix-like systems.
func getDaemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}
