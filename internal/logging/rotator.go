// Package logging provides structured logging with slog for witnessd.
package logging

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FileRotator handles log file rotation.
type FileRotator struct {
	config   *Config
	mu       sync.Mutex
	file     *os.File
	size     int64
	lastTime time.Time
}

// NewFileRotator creates a new FileRotator.
func NewFileRotator(cfg *Config) (*FileRotator, error) {
	r := &FileRotator{
		config: cfg,
	}

	if err := r.ensureDir(); err != nil {
		return nil, err
	}

	if err := r.openFile(); err != nil {
		return nil, err
	}

	return r, nil
}

// ensureDir creates the log directory if it doesn't exist.
func (r *FileRotator) ensureDir() error {
	dir := filepath.Dir(r.config.FilePath)
	return os.MkdirAll(dir, 0750)
}

// openFile opens or creates the log file.
func (r *FileRotator) openFile() error {
	file, err := os.OpenFile(r.config.FilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("stat log file: %w", err)
	}

	r.file = file
	r.size = info.Size()
	r.lastTime = time.Now()

	return nil
}

// Write implements io.Writer.
func (r *FileRotator) Write(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file == nil {
		if err := r.openFile(); err != nil {
			return 0, err
		}
	}

	// Check if rotation is needed
	if r.shouldRotate(int64(len(p))) {
		if err := r.rotate(); err != nil {
			return 0, fmt.Errorf("rotate log: %w", err)
		}
	}

	n, err = r.file.Write(p)
	r.size += int64(n)
	return n, err
}

// shouldRotate checks if the log file should be rotated.
func (r *FileRotator) shouldRotate(writeSize int64) bool {
	// Size-based rotation
	maxBytes := r.config.MaxSize * 1024 * 1024
	if r.size+writeSize > maxBytes {
		return true
	}

	// Time-based rotation (daily)
	now := time.Now()
	if r.lastTime.Day() != now.Day() {
		return true
	}

	return false
}

// rotate performs the log rotation.
func (r *FileRotator) rotate() error {
	// Close current file
	if r.file != nil {
		if err := r.file.Close(); err != nil {
			return fmt.Errorf("close current log: %w", err)
		}
	}

	// Generate rotated filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	base := filepath.Base(r.config.FilePath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	dir := filepath.Dir(r.config.FilePath)

	rotatedName := fmt.Sprintf("%s-%s%s", name, timestamp, ext)
	rotatedPath := filepath.Join(dir, rotatedName)

	// Rename current file
	if err := os.Rename(r.config.FilePath, rotatedPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rename log file: %w", err)
	}

	// Compress if enabled
	if r.config.Compress {
		go r.compressFile(rotatedPath)
	}

	// Open new file
	if err := r.openFile(); err != nil {
		return err
	}

	// Clean up old files
	go r.cleanup()

	return nil
}

// compressFile compresses a log file with gzip.
func (r *FileRotator) compressFile(path string) {
	input, err := os.Open(path)
	if err != nil {
		return
	}
	defer input.Close()

	output, err := os.Create(path + ".gz")
	if err != nil {
		return
	}
	defer output.Close()

	gz := gzip.NewWriter(output)
	gz.Name = filepath.Base(path)
	gz.ModTime = time.Now()

	if _, err := io.Copy(gz, input); err != nil {
		gz.Close()
		os.Remove(path + ".gz")
		return
	}

	if err := gz.Close(); err != nil {
		os.Remove(path + ".gz")
		return
	}

	// Remove original after successful compression
	os.Remove(path)
}

// cleanup removes old log files based on retention policy.
func (r *FileRotator) cleanup() {
	dir := filepath.Dir(r.config.FilePath)
	base := filepath.Base(r.config.FilePath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)

	// Find all rotated log files
	pattern := filepath.Join(dir, name+"-*"+ext+"*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	// Sort by modification time (oldest first)
	type fileInfo struct {
		path    string
		modTime time.Time
	}
	files := make([]fileInfo, 0, len(matches))

	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			continue
		}
		files = append(files, fileInfo{path: match, modTime: info.ModTime()})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.Before(files[j].modTime)
	})

	// Remove files exceeding max backups
	if len(files) > r.config.MaxBackups {
		for i := 0; i < len(files)-r.config.MaxBackups; i++ {
			os.Remove(files[i].path)
		}
	}

	// Remove files older than max age
	cutoff := time.Now().AddDate(0, 0, -r.config.MaxAge)
	for _, f := range files {
		if f.modTime.Before(cutoff) {
			os.Remove(f.path)
		}
	}
}

// Close closes the rotator and its underlying file.
func (r *FileRotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file != nil {
		err := r.file.Close()
		r.file = nil
		return err
	}
	return nil
}

// Sync flushes any buffered data to the file.
func (r *FileRotator) Sync() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file != nil {
		return r.file.Sync()
	}
	return nil
}

// GetLogFiles returns a list of all log files (current and rotated).
func (r *FileRotator) GetLogFiles() ([]string, error) {
	dir := filepath.Dir(r.config.FilePath)
	base := filepath.Base(r.config.FilePath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)

	files := []string{r.config.FilePath}

	// Find rotated files
	pattern := filepath.Join(dir, name+"-*"+ext+"*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return files, err
	}

	files = append(files, matches...)
	return files, nil
}
