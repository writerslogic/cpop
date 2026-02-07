//go:build unix
// +build unix

package security

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile acquires an exclusive lock on a file using flock.
func lockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX)
}

// unlockFile releases the lock on a file.
func unlockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
