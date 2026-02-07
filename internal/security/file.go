package security

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// File permission constants
const (
	// PermSecretFile is the permission for files containing secrets (owner read/write only)
	PermSecretFile os.FileMode = 0600

	// PermSecretDir is the permission for directories containing secrets
	PermSecretDir os.FileMode = 0700

	// PermPublicFile is the permission for non-secret files
	PermPublicFile os.FileMode = 0644

	// PermPublicDir is the permission for non-secret directories
	PermPublicDir os.FileMode = 0755
)

// File operation errors
var (
	ErrInsecurePermissions = errors.New("security: insecure file permissions")
	ErrAtomicWriteFailed   = errors.New("security: atomic write failed")
	ErrTempFileFailed      = errors.New("security: temporary file creation failed")
	ErrFileTooLarge        = errors.New("security: file exceeds maximum size")
)

// SecureFileWriter handles atomic file writes with secure permissions.
type SecureFileWriter struct {
	path     string
	perm     os.FileMode
	tempFile *os.File
	tempPath string
}

// NewSecureFileWriter creates a writer for secure atomic file writes.
// The file is written to a temporary file first, then renamed atomically.
func NewSecureFileWriter(path string, perm os.FileMode) (*SecureFileWriter, error) {
	// Validate the path
	validator := DefaultPathValidator()
	cleanPath, err := validator.ValidatePath(path)
	if err != nil {
		return nil, err
	}

	// Ensure directory exists with secure permissions
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, PermSecretDir); err != nil {
		return nil, fmt.Errorf("create directory: %w", err)
	}

	// Create temporary file in same directory (for atomic rename)
	tempPath := cleanPath + ".tmp." + randomSuffix()
	tempFile, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTempFileFailed, err)
	}

	return &SecureFileWriter{
		path:     cleanPath,
		perm:     perm,
		tempFile: tempFile,
		tempPath: tempPath,
	}, nil
}

// Write writes data to the temporary file.
func (w *SecureFileWriter) Write(p []byte) (n int, err error) {
	return w.tempFile.Write(p)
}

// Commit atomically moves the temporary file to the final path.
func (w *SecureFileWriter) Commit() error {
	// Sync to ensure data is on disk
	if err := w.tempFile.Sync(); err != nil {
		w.Abort()
		return fmt.Errorf("sync: %w", err)
	}

	// Close the file
	if err := w.tempFile.Close(); err != nil {
		os.Remove(w.tempPath)
		return fmt.Errorf("close: %w", err)
	}

	// Atomic rename
	if err := os.Rename(w.tempPath, w.path); err != nil {
		os.Remove(w.tempPath)
		return fmt.Errorf("%w: %v", ErrAtomicWriteFailed, err)
	}

	return nil
}

// Abort cancels the write and removes the temporary file.
func (w *SecureFileWriter) Abort() {
	w.tempFile.Close()
	os.Remove(w.tempPath)
}

// randomSuffix generates a random suffix for temporary files.
func randomSuffix() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// WriteSecureFile writes data to a file atomically with secure permissions.
func WriteSecureFile(path string, data []byte, perm os.FileMode) error {
	writer, err := NewSecureFileWriter(path, perm)
	if err != nil {
		return err
	}

	if _, err := writer.Write(data); err != nil {
		writer.Abort()
		return err
	}

	return writer.Commit()
}

// WriteSecretFile writes data to a file with secret permissions (0600).
func WriteSecretFile(path string, data []byte) error {
	return WriteSecureFile(path, data, PermSecretFile)
}

// ReadSecureFile reads a file and verifies its permissions are secure.
// It returns an error if the file has insecure permissions.
func ReadSecureFile(path string, maxSize int64) ([]byte, error) {
	// Validate path
	validator := DefaultPathValidator()
	cleanPath, err := validator.ValidatePath(path)
	if err != nil {
		return nil, err
	}

	// Check permissions
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, err
	}

	// On Unix, verify file permissions
	if runtime.GOOS != "windows" {
		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			return nil, fmt.Errorf("%w: file %s has mode %04o, expected %04o",
				ErrInsecurePermissions, cleanPath, mode, PermSecretFile)
		}
	}

	// Check file size
	if maxSize > 0 && info.Size() > maxSize {
		return nil, fmt.Errorf("%w: size %d exceeds limit %d", ErrFileTooLarge, info.Size(), maxSize)
	}

	// Read the file
	return os.ReadFile(cleanPath)
}

// EnsureSecureDir ensures a directory exists with secure permissions.
func EnsureSecureDir(path string) error {
	validator := DefaultPathValidator()
	cleanPath, err := validator.ValidatePath(path)
	if err != nil {
		return err
	}

	// Check if directory exists
	info, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create with secure permissions
			return os.MkdirAll(cleanPath, PermSecretDir)
		}
		return err
	}

	// Verify it's a directory
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrInvalidPath, cleanPath)
	}

	// On Unix, verify and fix permissions if needed
	if runtime.GOOS != "windows" {
		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			// Tighten permissions
			if err := os.Chmod(cleanPath, PermSecretDir); err != nil {
				return fmt.Errorf("fix directory permissions: %w", err)
			}
		}
	}

	return nil
}

// VerifyFilePermissions checks if a file has the expected permissions.
func VerifyFilePermissions(path string, expectedPerm os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		// Windows doesn't have Unix permissions
		return nil
	}

	mode := info.Mode().Perm()
	if mode != expectedPerm {
		return fmt.Errorf("%w: file %s has mode %04o, expected %04o",
			ErrInsecurePermissions, path, mode, expectedPerm)
	}

	return nil
}

// SecureTempFile creates a temporary file with secure permissions.
// The caller is responsible for removing the file when done.
func SecureTempFile(dir, pattern string) (*os.File, error) {
	if dir == "" {
		// Use a secure default
		dir = os.TempDir()
	}

	// Ensure directory exists
	if err := EnsureSecureDir(dir); err != nil {
		return nil, err
	}

	// Generate random name
	name := pattern + "." + randomSuffix()
	path := filepath.Join(dir, name)

	// Create with restrictive permissions
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, PermSecretFile)
}

// SecureCopy copies a file with secure permissions.
func SecureCopy(src, dst string, perm os.FileMode) error {
	// Validate paths
	validator := DefaultPathValidator()
	srcPath, err := validator.ValidatePath(src)
	if err != nil {
		return fmt.Errorf("invalid source: %w", err)
	}

	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	writer, err := NewSecureFileWriter(dst, perm)
	if err != nil {
		return err
	}

	if _, err := io.Copy(writer, srcFile); err != nil {
		writer.Abort()
		return err
	}

	return writer.Commit()
}

// LockFile attempts to acquire an exclusive lock on a file.
// This is platform-specific and uses flock on Unix.
func LockFile(f *os.File) error {
	return lockFile(f)
}

// UnlockFile releases the exclusive lock on a file.
func UnlockFile(f *os.File) error {
	return unlockFile(f)
}
