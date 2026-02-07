// Package sentinel shadow buffer management.
//
// Shadow buffers cache unsaved document content to enable tracking
// of documents before they have been saved to disk.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ShadowManager manages shadow buffers for unsaved documents.
type ShadowManager struct {
	mu sync.RWMutex

	// Base directory for shadow files
	baseDir string

	// Active shadows by ID
	shadows map[string]*shadowBuffer
}

// shadowBuffer represents a single shadow buffer.
type shadowBuffer struct {
	ID          string
	AppName     string
	WindowTitle string
	Path        string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Size        int64
}

// NewShadowManager creates a new shadow buffer manager.
func NewShadowManager(baseDir string) (*ShadowManager, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("create shadow dir: %w", err)
	}

	return &ShadowManager{
		baseDir: baseDir,
		shadows: make(map[string]*shadowBuffer),
	}, nil
}

// Create creates a new shadow buffer for an unsaved document.
func (m *ShadowManager) Create(appName, windowTitle string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate unique ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", fmt.Errorf("generate ID: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	// Create shadow file
	path := filepath.Join(m.baseDir, id+".shadow")
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create shadow file: %w", err)
	}
	f.Close()

	shadow := &shadowBuffer{
		ID:          id,
		AppName:     appName,
		WindowTitle: windowTitle,
		Path:        path,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	m.shadows[id] = shadow

	return id, nil
}

// Update updates the content of a shadow buffer.
func (m *ShadowManager) Update(id string, content []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	shadow, exists := m.shadows[id]
	if !exists {
		return fmt.Errorf("shadow not found: %s", id)
	}

	if err := os.WriteFile(shadow.Path, content, 0600); err != nil {
		return fmt.Errorf("write shadow: %w", err)
	}

	shadow.UpdatedAt = time.Now()
	shadow.Size = int64(len(content))

	return nil
}

// GetPath returns the file path for a shadow buffer.
func (m *ShadowManager) GetPath(id string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if shadow, exists := m.shadows[id]; exists {
		return shadow.Path
	}
	return ""
}

// Delete removes a shadow buffer.
func (m *ShadowManager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	shadow, exists := m.shadows[id]
	if !exists {
		return nil
	}

	os.Remove(shadow.Path)
	delete(m.shadows, id)

	return nil
}

// Migrate converts a shadow buffer to a real file path.
// Called when an unsaved document is saved.
func (m *ShadowManager) Migrate(id, newPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	shadow, exists := m.shadows[id]
	if !exists {
		return fmt.Errorf("shadow not found: %s", id)
	}

	// Remove shadow file (content is now in newPath)
	os.Remove(shadow.Path)
	delete(m.shadows, id)

	return nil
}

// CleanupAll removes all shadow buffers.
func (m *ShadowManager) CleanupAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, shadow := range m.shadows {
		os.Remove(shadow.Path)
		delete(m.shadows, id)
	}
}

// CleanupOld removes shadow buffers older than maxAge.
func (m *ShadowManager) CleanupOld(maxAge time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for id, shadow := range m.shadows {
		if shadow.UpdatedAt.Before(cutoff) {
			os.Remove(shadow.Path)
			delete(m.shadows, id)
			removed++
		}
	}

	return removed
}

// List returns all active shadow buffers.
func (m *ShadowManager) List() []shadowBuffer {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]shadowBuffer, 0, len(m.shadows))
	for _, shadow := range m.shadows {
		result = append(result, *shadow)
	}

	return result
}
