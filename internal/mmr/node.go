// Package mmr implements a Merkle Mountain Range (MMR), an append-only
// authenticated data structure for proving document state at any historical point.
package mmr

import (
	"crypto/sha256"
	"encoding/binary"
)

// DomainSeparators prevent second-preimage attacks by ensuring leaf hashes
// and internal node hashes are computed in distinct domains.
const (
	LeafPrefix     byte = 0x00
	InternalPrefix byte = 0x01
)

// HashSize is the size of SHA-256 output in bytes.
const HashSize = 32

// Node represents a single node in the Merkle Mountain Range.
type Node struct {
	Index  uint64   // Position in the MMR (0-indexed)
	Height uint8    // Height in the tree (0 = leaf)
	Hash   [32]byte // SHA-256 hash of the node
}

// NewLeafNode creates a leaf node from raw data.
// The hash is computed as SHA256(LeafPrefix || data) to prevent
// second-preimage attacks where internal nodes could be confused with leaves.
func NewLeafNode(index uint64, data []byte) *Node {
	h := sha256.New()
	h.Write([]byte{LeafPrefix})
	h.Write(data)

	var hash [32]byte
	copy(hash[:], h.Sum(nil))

	return &Node{
		Index:  index,
		Height: 0,
		Hash:   hash,
	}
}

// NewInternalNode creates an internal node by hashing two child nodes.
// The hash is computed as SHA256(InternalPrefix || leftHash || rightHash).
func NewInternalNode(index uint64, height uint8, left, right *Node) *Node {
	h := sha256.New()
	h.Write([]byte{InternalPrefix})
	h.Write(left.Hash[:])
	h.Write(right.Hash[:])

	var hash [32]byte
	copy(hash[:], h.Sum(nil))

	return &Node{
		Index:  index,
		Height: height,
		Hash:   hash,
	}
}

// HashLeaf computes the domain-separated hash of leaf data.
func HashLeaf(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{LeafPrefix})
	h.Write(data)

	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

// HashInternal computes the domain-separated hash of two child hashes.
func HashInternal(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{InternalPrefix})
	h.Write(left[:])
	h.Write(right[:])

	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

// Serialize converts a node to its binary representation for storage.
// Format: [8-byte Index][1-byte Height][32-byte Hash] = 41 bytes total
func (n *Node) Serialize() []byte {
	buf := make([]byte, 41)
	binary.BigEndian.PutUint64(buf[0:8], n.Index)
	buf[8] = n.Height
	copy(buf[9:41], n.Hash[:])
	return buf
}

// DeserializeNode reconstructs a node from its binary representation.
func DeserializeNode(data []byte) (*Node, error) {
	if len(data) < 41 {
		return nil, ErrInvalidNodeData
	}

	var hash [32]byte
	copy(hash[:], data[9:41])

	return &Node{
		Index:  binary.BigEndian.Uint64(data[0:8]),
		Height: data[8],
		Hash:   hash,
	}, nil
}

// NodeSize is the serialized size of a single node in bytes.
const NodeSize = 41
