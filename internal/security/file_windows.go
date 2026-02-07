//go:build windows
// +build windows

package security

import (
	"os"
	"syscall"
)

// lockFile acquires an exclusive lock on a file using LockFileEx.
func lockFile(f *os.File) error {
	handle := syscall.Handle(f.Fd())
	var overlapped syscall.Overlapped

	// LOCKFILE_EXCLUSIVE_LOCK = 0x2
	const LOCKFILE_EXCLUSIVE_LOCK = 0x2

	err := syscall.LockFileEx(
		handle,
		LOCKFILE_EXCLUSIVE_LOCK,
		0,           // reserved
		1,           // lock 1 byte
		0,           // high-order 32 bits of byte range
		&overlapped,
	)
	return err
}

// unlockFile releases the lock on a file.
func unlockFile(f *os.File) error {
	handle := syscall.Handle(f.Fd())
	var overlapped syscall.Overlapped

	err := syscall.UnlockFileEx(
		handle,
		0, // reserved
		1, // unlock 1 byte
		0, // high-order 32 bits of byte range
		&overlapped,
	)
	return err
}
