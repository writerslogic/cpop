//go:build darwin || linux || windows

// Package keystroke provides secure, tamper-evident keystroke counting and tracking.
package keystroke

import (
	"crypto/sha256"
	"sync"
	"time"
)

// ClipboardMonitor watches for clipboard changes to detect paste operations.
// This provides more accurate paste detection than document-size heuristics alone.
type ClipboardMonitor struct {
	mu sync.RWMutex

	// Current clipboard state
	lastContent     []byte
	lastContentHash [32]byte
	lastChangeTime  time.Time

	// History of clipboard changes
	changes []ClipboardChange

	// Platform-specific clipboard access
	accessor ClipboardAccessor

	// Control
	running bool
	stopCh  chan struct{}
}

// ClipboardChange records a clipboard modification.
type ClipboardChange struct {
	Timestamp   time.Time `json:"timestamp"`
	ContentHash [32]byte  `json:"content_hash"`
	ContentSize int       `json:"content_size"`
	ContentType string    `json:"content_type"` // "text", "image", "files", "unknown"
	SourceApp   string    `json:"source_app,omitempty"`
}

// ClipboardAccessor is the platform-specific interface for clipboard access.
type ClipboardAccessor interface {
	// GetText returns the current text clipboard content
	GetText() (string, error)

	// GetContentType returns the type of content on the clipboard
	GetContentType() string

	// GetSourceApp returns the app that last modified the clipboard (if available)
	GetSourceApp() string
}

// NewClipboardMonitor creates a clipboard monitor.
func NewClipboardMonitor() *ClipboardMonitor {
	return &ClipboardMonitor{
		changes:  make([]ClipboardChange, 0),
		accessor: newPlatformClipboardAccessor(),
		stopCh:   make(chan struct{}),
	}
}

// Start begins monitoring clipboard changes.
func (cm *ClipboardMonitor) Start() {
	cm.mu.Lock()
	if cm.running {
		cm.mu.Unlock()
		return
	}
	cm.running = true
	cm.stopCh = make(chan struct{})
	cm.mu.Unlock()

	go cm.monitorLoop()
}

// Stop stops monitoring.
func (cm *ClipboardMonitor) Stop() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if !cm.running {
		return
	}

	cm.running = false
	close(cm.stopCh)
}

// monitorLoop polls the clipboard for changes.
func (cm *ClipboardMonitor) monitorLoop() {
	ticker := time.NewTicker(100 * time.Millisecond) // Check every 100ms
	defer ticker.Stop()

	for {
		select {
		case <-cm.stopCh:
			return
		case <-ticker.C:
			cm.checkClipboard()
		}
	}
}

// checkClipboard checks if clipboard content has changed.
func (cm *ClipboardMonitor) checkClipboard() {
	if cm.accessor == nil {
		return
	}

	text, err := cm.accessor.GetText()
	if err != nil {
		return
	}

	content := []byte(text)
	hash := sha256.Sum256(content)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Check if content changed
	if hash != cm.lastContentHash {
		change := ClipboardChange{
			Timestamp:   time.Now(),
			ContentHash: hash,
			ContentSize: len(content),
			ContentType: cm.accessor.GetContentType(),
			SourceApp:   cm.accessor.GetSourceApp(),
		}

		cm.changes = append(cm.changes, change)
		cm.lastContent = content
		cm.lastContentHash = hash
		cm.lastChangeTime = time.Now()

		// Limit history size
		if len(cm.changes) > 1000 {
			cm.changes = cm.changes[len(cm.changes)-500:]
		}
	}
}

// LastChange returns the most recent clipboard change.
func (cm *ClipboardMonitor) LastChange() *ClipboardChange {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if len(cm.changes) == 0 {
		return nil
	}
	return &cm.changes[len(cm.changes)-1]
}

// LastContentHash returns the hash of the last clipboard content.
func (cm *ClipboardMonitor) LastContentHash() [32]byte {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.lastContentHash
}

// LastContentSize returns the size of the last clipboard content.
func (cm *ClipboardMonitor) LastContentSize() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.lastContent)
}

// RecentChanges returns clipboard changes since the given time.
func (cm *ClipboardMonitor) RecentChanges(since time.Time) []ClipboardChange {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var recent []ClipboardChange
	for _, change := range cm.changes {
		if change.Timestamp.After(since) {
			recent = append(recent, change)
		}
	}
	return recent
}

// WasPastedRecently checks if content matching the given hash was pasted recently.
// This helps correlate document changes with clipboard operations.
func (cm *ClipboardMonitor) WasPastedRecently(contentHash [32]byte, window time.Duration) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	cutoff := time.Now().Add(-window)
	for i := len(cm.changes) - 1; i >= 0; i-- {
		change := cm.changes[i]
		if change.Timestamp.Before(cutoff) {
			break
		}
		if change.ContentHash == contentHash {
			return true
		}
	}
	return false
}

// Changes returns all recorded clipboard changes.
func (cm *ClipboardMonitor) Changes() []ClipboardChange {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make([]ClipboardChange, len(cm.changes))
	copy(result, cm.changes)
	return result
}
