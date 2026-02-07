//go:build !unix
// +build !unix

package security

// Fallback implementations for non-Unix systems

import (
	"runtime"
	"sync"
	"unsafe"
)

// SecureBytes is a byte slice that gets zeroed when freed.
// Use this for sensitive data like keys, passwords, and seeds.
type SecureBytes struct {
	data   []byte
	locked bool
	mu     sync.Mutex
}

// NewSecureBytes creates a new SecureBytes with the given capacity.
func NewSecureBytes(size int) (*SecureBytes, error) {
	sb := &SecureBytes{
		data: make([]byte, size),
	}

	// Register finalizer to ensure cleanup
	runtime.SetFinalizer(sb, func(s *SecureBytes) {
		s.Destroy()
	})

	return sb, nil
}

// FromBytes creates SecureBytes from existing data.
// The original data is zeroed after copying.
func FromBytes(data []byte) (*SecureBytes, error) {
	sb, err := NewSecureBytes(len(data))
	if err != nil {
		return nil, err
	}

	copy(sb.data, data)
	Wipe(data)

	return sb, nil
}

// Bytes returns the underlying byte slice.
func (s *SecureBytes) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

// Copy creates a copy of the data.
func (s *SecureBytes) Copy() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data == nil {
		return nil
	}

	result := make([]byte, len(s.data))
	copy(result, s.data)
	return result
}

// Len returns the length of the secure bytes.
func (s *SecureBytes) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data)
}

// Destroy securely wipes the memory.
func (s *SecureBytes) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data == nil {
		return
	}

	wipeBytes(s.data)
	s.data = nil
}

// lock is a no-op on non-Unix systems
func (s *SecureBytes) lock() error {
	return nil
}

// unlock is a no-op on non-Unix systems
func (s *SecureBytes) unlock() {
}
