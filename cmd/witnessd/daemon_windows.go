//go:build windows

package main

import "syscall"

// getDaemonSysProcAttr returns the SysProcAttr for detaching a daemon process on Windows.
// On Windows, we use HideWindow to run the process without a console window.
func getDaemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow: true,
	}
}
