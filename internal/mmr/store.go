package mmr

import (
	"bufio"
	"io"
	"os"
	"sync"
)

// Store defines the interface for MMR node persistence.
type Store interface {
	// Append adds a node to the store.
	Append(node *Node) error

	// Get retrieves a node by its index.
	Get(index uint64) (*Node, error)

	// Size returns the total number of nodes in the store.
	Size() (uint64, error)

	// Sync ensures all data is flushed to persistent storage.
	Sync() error

	// Close releases resources held by the store.
	Close() error
}

// FileStore implements Store using an append-only binary file.
// Format: [8-byte Index][1-byte Height][32-byte Hash] = 41 bytes per node.
type FileStore struct {
	path string
	file *os.File
	mu   sync.RWMutex
	size uint64

	// Write buffer for batching
	writer *bufio.Writer
}

// OpenFileStore opens or creates an MMR file store at the given path.
func OpenFileStore(path string) (*FileStore, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}

	// Determine current size
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}

	fileSize := info.Size()
	if fileSize%NodeSize != 0 {
		file.Close()
		return nil, ErrCorruptedStore
	}

	nodeCount := uint64(fileSize) / NodeSize

	// Seek to end for appending
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		file.Close()
		return nil, err
	}

	return &FileStore{
		path:   path,
		file:   file,
		size:   nodeCount,
		writer: bufio.NewWriterSize(file, 4096), // 4KB buffer (~100 nodes)
	}, nil
}

// Append adds a node to the store.
func (s *FileStore) Append(node *Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify sequential append
	if node.Index != s.size {
		return ErrCorruptedStore
	}

	data := node.Serialize()
	if _, err := s.writer.Write(data); err != nil {
		return err
	}

	s.size++
	return nil
}

// Get retrieves a node by its index.
func (s *FileStore) Get(index uint64) (*Node, error) {
	// Use write lock to safely flush and read.
	// This prevents the race condition that existed with the previous
	// RLock -> Unlock -> Lock -> Unlock -> RLock pattern.
	s.mu.Lock()
	defer s.mu.Unlock()

	if index >= s.size {
		return nil, ErrIndexOutOfRange
	}

	// Flush writer to ensure we can read recent data
	if err := s.writer.Flush(); err != nil {
		return nil, err
	}

	// Calculate file offset
	offset := int64(index) * NodeSize

	// Read the node data
	data := make([]byte, NodeSize)
	n, err := s.file.ReadAt(data, offset)
	if err != nil {
		return nil, err
	}
	if n != NodeSize {
		return nil, ErrCorruptedStore
	}

	return DeserializeNode(data)
}

// Size returns the total number of nodes in the store.
func (s *FileStore) Size() (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.size, nil
}

// Sync flushes all buffered data to disk.
func (s *FileStore) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.writer.Flush(); err != nil {
		return err
	}
	return s.file.Sync()
}

// Close syncs and closes the store.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.writer.Flush(); err != nil {
		return err
	}
	if err := s.file.Sync(); err != nil {
		return err
	}
	return s.file.Close()
}

// MemoryStore implements Store using in-memory storage.
// Useful for testing and ephemeral operations.
type MemoryStore struct {
	nodes []*Node
	mu    sync.RWMutex
}

// NewMemoryStore creates a new in-memory MMR store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		nodes: make([]*Node, 0),
	}
}

// Append adds a node to the store.
func (s *MemoryStore) Append(node *Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if node.Index != uint64(len(s.nodes)) {
		return ErrCorruptedStore
	}

	// Deep copy the node
	nodeCopy := &Node{
		Index:  node.Index,
		Height: node.Height,
		Hash:   node.Hash,
	}
	s.nodes = append(s.nodes, nodeCopy)
	return nil
}

// Get retrieves a node by its index.
func (s *MemoryStore) Get(index uint64) (*Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if index >= uint64(len(s.nodes)) {
		return nil, ErrIndexOutOfRange
	}

	node := s.nodes[index]
	// Return a copy
	return &Node{
		Index:  node.Index,
		Height: node.Height,
		Hash:   node.Hash,
	}, nil
}

// Size returns the total number of nodes in the store.
func (s *MemoryStore) Size() (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint64(len(s.nodes)), nil
}

// Sync is a no-op for memory store.
func (s *MemoryStore) Sync() error {
	return nil
}

// Close is a no-op for memory store.
func (s *MemoryStore) Close() error {
	return nil
}

// Nodes returns a copy of all nodes (for testing).
func (s *MemoryStore) Nodes() []*Node {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a deep copy to prevent external modification of internal state
	result := make([]*Node, len(s.nodes))
	for i, node := range s.nodes {
		result[i] = &Node{
			Index:  node.Index,
			Height: node.Height,
			Hash:   node.Hash,
		}
	}
	return result
}
