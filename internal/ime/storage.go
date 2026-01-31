package ime

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// EvidenceStorage handles persistent storage of evidence records.
type EvidenceStorage struct {
	mu      sync.Mutex
	baseDir string
}

// NewEvidenceStorage creates a new storage instance.
// If baseDir is empty, uses the default platform-specific directory.
func NewEvidenceStorage(baseDir string) (*EvidenceStorage, error) {
	if baseDir == "" {
		var err error
		baseDir, err = defaultStorageDir()
		if err != nil {
			return nil, err
		}
	}

	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, err
	}

	return &EvidenceStorage{baseDir: baseDir}, nil
}

// defaultStorageDir returns the platform-specific evidence storage directory.
func defaultStorageDir() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "Witnessd", "evidence"), nil

	case "linux":
		// Follow XDG Base Directory Specification
		if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
			return filepath.Join(xdgData, "witnessd", "evidence"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "share", "witnessd", "evidence"), nil

	case "windows":
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			return "", errors.New("LOCALAPPDATA not set")
		}
		return filepath.Join(localAppData, "Witnessd", "evidence"), nil

	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".witnessd", "evidence"), nil
	}
}

// SaveEvidence implements the Storage interface.
func (s *EvidenceStorage) SaveEvidence(evidence *Evidence) error {
	return s.Save(evidence)
}

// Save persists an evidence record to storage.
func (s *EvidenceStorage) Save(evidence *Evidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if evidence == nil {
		return errors.New("nil evidence")
	}

	// Create filename from session ID
	filename := evidence.SessionID + ".json"
	filepath := filepath.Join(s.baseDir, filename)

	// Marshal to JSON
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}

	// Write atomically using temp file + rename
	tempPath := filepath + ".tmp"
	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tempPath, filepath)
}

// Load reads an evidence record from storage by session ID.
func (s *EvidenceStorage) Load(sessionID string) (*Evidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	filename := sessionID + ".json"
	filepath := filepath.Join(s.baseDir, filename)

	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var evidence Evidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return nil, err
	}

	return &evidence, nil
}

// List returns all stored session IDs, optionally filtered by time range.
func (s *EvidenceStorage) List(since, until time.Time) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var sessions []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !isJSONFile(name) {
			continue
		}

		// Extract session ID (remove .json extension)
		sessionID := name[:len(name)-5]

		// If time filtering is requested, load and check
		if !since.IsZero() || !until.IsZero() {
			evidence, err := s.loadUnlocked(sessionID)
			if err != nil {
				continue
			}

			if !since.IsZero() && evidence.StartTime.Before(since) {
				continue
			}
			if !until.IsZero() && evidence.EndTime.After(until) {
				continue
			}
		}

		sessions = append(sessions, sessionID)
	}

	return sessions, nil
}

// loadUnlocked loads evidence without locking (caller must hold lock).
func (s *EvidenceStorage) loadUnlocked(sessionID string) (*Evidence, error) {
	filename := sessionID + ".json"
	filepath := filepath.Join(s.baseDir, filename)

	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var evidence Evidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return nil, err
	}

	return &evidence, nil
}

// Delete removes an evidence record from storage.
func (s *EvidenceStorage) Delete(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filename := sessionID + ".json"
	filepath := filepath.Join(s.baseDir, filename)

	return os.Remove(filepath)
}

// Prune removes evidence records older than the given duration.
func (s *EvidenceStorage) Prune(olderThan time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)

	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	var pruned int
	for _, entry := range entries {
		if entry.IsDir() || !isJSONFile(entry.Name()) {
			continue
		}

		sessionID := entry.Name()[:len(entry.Name())-5]
		evidence, err := s.loadUnlocked(sessionID)
		if err != nil {
			continue
		}

		if evidence.EndTime.Before(cutoff) {
			filepath := filepath.Join(s.baseDir, entry.Name())
			if err := os.Remove(filepath); err == nil {
				pruned++
			}
		}
	}

	return pruned, nil
}

// Stats returns storage statistics.
func (s *EvidenceStorage) Stats() (StorageStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var stats StorageStats

	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return stats, nil
		}
		return stats, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !isJSONFile(entry.Name()) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		stats.Count++
		stats.TotalBytes += info.Size()

		if stats.OldestTime.IsZero() || info.ModTime().Before(stats.OldestTime) {
			stats.OldestTime = info.ModTime()
		}
		if info.ModTime().After(stats.NewestTime) {
			stats.NewestTime = info.ModTime()
		}
	}

	return stats, nil
}

// StorageStats contains storage statistics.
type StorageStats struct {
	Count      int
	TotalBytes int64
	OldestTime time.Time
	NewestTime time.Time
}

func isJSONFile(name string) bool {
	return len(name) > 5 && name[len(name)-5:] == ".json"
}
