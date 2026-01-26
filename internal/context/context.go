// Package context provides context declaration handling for witnessd.
// Contexts allow users to declare the nature of editing sessions,
// such as external content (paste/import), AI-assisted edits, or review passes.
package context

import (
	"errors"
	"time"

	"witnessd/internal/store"
)

// ContextType represents the type of editing context.
type ContextType = store.ContextType

// Re-export constants for convenience
const (
	External = store.ContextExternal // Paste, import, dictation
	Assisted = store.ContextAssisted // AI or tool generated
	Review   = store.ContextReview   // Revision pass
)

// Errors
var (
	ErrNoActiveContext = errors.New("no active context")
	ErrInvalidType     = errors.New("invalid context type")
)

// Manager handles context declarations.
type Manager struct {
	store *store.Store
}

// NewManager creates a context manager.
func NewManager(s *store.Store) *Manager {
	return &Manager{store: s}
}

// Begin starts a new context declaration.
// Returns the context ID and error.
// If there's already an active context, it will be closed first.
func (m *Manager) Begin(ctxType ContextType, note string) (int64, error) {
	// Check for and auto-close any active context
	active, err := m.store.GetActiveContext()
	if err != nil {
		return 0, err
	}
	if active != nil {
		endNs := time.Now().UnixNano()
		if err := m.store.CloseContext(active.ID, endNs); err != nil {
			return 0, err
		}
	}

	// Create new context
	ctx := &store.Context{
		Type:    ctxType,
		Note:    note,
		StartNs: time.Now().UnixNano(),
		EndNs:   nil,
	}

	id, err := m.store.InsertContext(ctx)
	if err != nil {
		return 0, err
	}

	return id, nil
}

// End closes the currently active context.
// Returns ErrNoActiveContext if no context is open.
func (m *Manager) End() error {
	active, err := m.store.GetActiveContext()
	if err != nil {
		return err
	}
	if active == nil {
		return ErrNoActiveContext
	}

	endNs := time.Now().UnixNano()
	return m.store.CloseContext(active.ID, endNs)
}

// Active returns the currently active context, or nil if none.
func (m *Manager) Active() (*store.Context, error) {
	return m.store.GetActiveContext()
}

// GetForEvent returns the context that was active at the given timestamp.
// Returns nil if no context was active at that time.
func (m *Manager) GetForEvent(timestampNs int64) (*store.Context, error) {
	return m.store.GetContextForTimestamp(timestampNs)
}

// List returns all contexts within a time range.
func (m *Manager) List(startNs, endNs int64) ([]store.Context, error) {
	return m.store.GetContextsInRange(startNs, endNs)
}

// ValidateType checks if a context type string is valid.
func ValidateType(s string) (ContextType, error) {
	switch s {
	case "external", "ext":
		return External, nil
	case "assisted", "ai":
		return Assisted, nil
	case "review", "rev":
		return Review, nil
	default:
		return "", ErrInvalidType
	}
}

// TypeDescription returns a human-readable description of a context type.
func TypeDescription(t ContextType) string {
	switch t {
	case External:
		return "External content (paste, import, dictation)"
	case Assisted:
		return "AI or tool assisted"
	case Review:
		return "Revision pass"
	default:
		return "Unknown"
	}
}
