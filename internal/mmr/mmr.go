package mmr

import (
	"math/bits"
)

// MMR represents a Merkle Mountain Range structure.
// An MMR is an append-only authenticated data structure consisting of
// multiple perfect binary trees ("mountains") of decreasing size.
type MMR struct {
	store Store    // Backing store for nodes
	size  uint64   // Total number of nodes (not leaves)
	peaks []uint64 // Indices of current peak nodes
}

// New creates a new MMR with the given backing store.
func New(store Store) (*MMR, error) {
	mmr := &MMR{
		store: store,
		size:  0,
		peaks: make([]uint64, 0),
	}

	// Reconstruct state from store
	if err := mmr.restore(); err != nil {
		return nil, err
	}

	return mmr, nil
}

// restore rebuilds the MMR state from the backing store.
func (m *MMR) restore() error {
	size, err := m.store.Size()
	if err != nil {
		return err
	}
	m.size = size

	if size == 0 {
		m.peaks = make([]uint64, 0)
		return nil
	}

	m.peaks = findPeaks(size)
	return nil
}

// Append adds a new leaf to the MMR and returns its index.
// After inserting the leaf, it merges peaks of equal height.
func (m *MMR) Append(data []byte) (uint64, error) {
	// Create the new leaf node
	leafIndex := m.size
	leaf := NewLeafNode(leafIndex, data)

	if err := m.store.Append(leaf); err != nil {
		return 0, err
	}
	m.size++

	// Merge peaks of equal height
	if err := m.mergePeaks(); err != nil {
		return 0, err
	}

	// Recalculate peaks
	m.peaks = findPeaks(m.size)

	return leafIndex, nil
}

// mergePeaks merges adjacent peaks of equal height until all peaks have different heights.
func (m *MMR) mergePeaks() error {
	for {
		peaks := findPeaks(m.size)
		if len(peaks) < 2 {
			return nil
		}

		// Check if the last two peaks have the same height
		lastIdx := peaks[len(peaks)-1]
		prevIdx := peaks[len(peaks)-2]

		lastNode, err := m.store.Get(lastIdx)
		if err != nil {
			return err
		}

		prevNode, err := m.store.Get(prevIdx)
		if err != nil {
			return err
		}

		if lastNode.Height != prevNode.Height {
			return nil
		}

		// Merge: create a new internal node
		newNode := NewInternalNode(m.size, lastNode.Height+1, prevNode, lastNode)
		if err := m.store.Append(newNode); err != nil {
			return err
		}
		m.size++
	}
}

// GetPeaks returns the hash values of all current mountain peaks.
func (m *MMR) GetPeaks() ([][32]byte, error) {
	if m.size == 0 {
		return nil, nil
	}

	peaks := findPeaks(m.size)
	hashes := make([][32]byte, len(peaks))

	for i, idx := range peaks {
		node, err := m.store.Get(idx)
		if err != nil {
			return nil, err
		}
		hashes[i] = node.Hash
	}

	return hashes, nil
}

// GetRoot computes the "Witness Root" by hashing all peaks together.
// This single 32-byte value represents the entire document history.
func (m *MMR) GetRoot() ([32]byte, error) {
	if m.size == 0 {
		return [32]byte{}, ErrEmptyMMR
	}

	peaks, err := m.GetPeaks()
	if err != nil {
		return [32]byte{}, err
	}

	if len(peaks) == 1 {
		return peaks[0], nil
	}

	// Bag the peaks from right to left (standard MMR convention)
	root := peaks[len(peaks)-1]
	for i := len(peaks) - 2; i >= 0; i-- {
		root = HashInternal(peaks[i], root)
	}

	return root, nil
}

// Size returns the total number of nodes in the MMR.
func (m *MMR) Size() uint64 {
	return m.size
}

// LeafCount returns the number of leaf nodes in the MMR.
func (m *MMR) LeafCount() uint64 {
	return leafCountFromSize(m.size)
}

// Get retrieves a node by its index.
func (m *MMR) Get(index uint64) (*Node, error) {
	if index >= m.size {
		return nil, ErrIndexOutOfRange
	}
	return m.store.Get(index)
}

// GenerateProof creates an inclusion proof for the leaf at the given index.
// The proof contains the Merkle path from the leaf to the peaks, plus peak bagging.
func (m *MMR) GenerateProof(leafIndex uint64) (*InclusionProof, error) {
	if m.size == 0 {
		return nil, ErrEmptyMMR
	}

	if leafIndex >= m.size {
		return nil, ErrIndexOutOfRange
	}

	node, err := m.store.Get(leafIndex)
	if err != nil {
		return nil, err
	}

	// Only leaves can be proven
	if node.Height != 0 {
		return nil, ErrInvalidProof
	}

	// Find which mountain (peak) this leaf belongs to
	path, peakIndex, err := m.generateMerklePath(leafIndex)
	if err != nil {
		return nil, err
	}

	// Get peak hashes for bagging
	peaks, err := m.GetPeaks()
	if err != nil {
		return nil, err
	}

	peakIndices := findPeaks(m.size)
	var peakPosition int
	for i, idx := range peakIndices {
		if idx == peakIndex {
			peakPosition = i
			break
		}
	}

	root, err := m.GetRoot()
	if err != nil {
		return nil, err
	}

	return &InclusionProof{
		LeafIndex:    leafIndex,
		LeafHash:     node.Hash,
		MerklePath:   path,
		Peaks:        peaks,
		PeakPosition: peakPosition,
		MMRSize:      m.size,
		Root:         root,
	}, nil
}

// generateMerklePath computes the path from a leaf to its peak.
// MMR structure example (7 nodes):
//
//	    6
//	   / \
//	  2   5
//	 / \ / \
//	0  1 3  4
func (m *MMR) generateMerklePath(leafIndex uint64) ([]ProofElement, uint64, error) {
	var path []ProofElement
	pos := leafIndex

	// Get the node to verify it's a leaf
	node, err := m.store.Get(pos)
	if err != nil {
		return nil, 0, err
	}
	height := node.Height

	for {
		// Try to find sibling and parent by checking both possibilities
		siblingPos, parentPos, isRightChild, found := m.findFamily(pos, height)

		if !found {
			// No valid sibling/parent found, we're at a peak
			return path, pos, nil
		}

		// Get sibling hash
		siblingNode, err := m.store.Get(siblingPos)
		if err != nil {
			return path, pos, nil
		}

		// IsLeft in proof means sibling is on the left
		path = append(path, ProofElement{
			Hash:   siblingNode.Hash,
			IsLeft: isRightChild,
		})

		// Move to parent
		pos = parentPos
		height++
	}
}

// findFamily determines sibling and parent by checking both left/right possibilities.
func (m *MMR) findFamily(pos uint64, height uint8) (sibling, parent uint64, isRightChild, found bool) {
	offset := uint64(1) << (height + 1)

	// Try as left child first: parent = pos + offset, sibling = pos + offset - 1
	leftParent := pos + offset
	rightSibling := leftParent - 1

	if rightSibling < m.size && rightSibling != pos {
		rightNode, err := m.store.Get(rightSibling)
		if err == nil && rightNode.Height == height {
			if leftParent < m.size {
				parentNode, err := m.store.Get(leftParent)
				if err == nil && parentNode.Height == height+1 {
					return rightSibling, leftParent, false, true
				}
			}
		}
	}

	// Try as right child: parent = pos + 1, sibling = pos + 1 - offset
	rightParent := pos + 1
	if offset <= pos+1 {
		leftSibling := rightParent - offset

		if leftSibling < m.size && leftSibling != pos {
			leftNode, err := m.store.Get(leftSibling)
			if err == nil && leftNode.Height == height {
				if rightParent < m.size {
					parentNode, err := m.store.Get(rightParent)
					if err == nil && parentNode.Height == height+1 {
						return leftSibling, rightParent, true, true
					}
				}
			}
		}
	}

	// No valid family found - we're at a peak
	return 0, 0, false, false
}

// InclusionProof contains all data needed to verify a leaf's inclusion in the MMR.
type InclusionProof struct {
	LeafIndex    uint64         // Index of the proven leaf
	LeafHash     [32]byte       // Hash of the leaf node
	MerklePath   []ProofElement // Path from leaf to its peak
	Peaks        [][32]byte     // All peak hashes for bagging
	PeakPosition int            // Position of the relevant peak in Peaks slice
	MMRSize      uint64         // Size of the MMR when proof was generated
	Root         [32]byte       // The root at time of proof generation
}

// ProofElement represents a single step in a Merkle proof.
type ProofElement struct {
	Hash   [32]byte // Sibling hash
	IsLeft bool     // True if sibling is on the left
}

// Verify checks that this proof is valid for the given leaf data.
func (p *InclusionProof) Verify(leafData []byte) error {
	// Recompute leaf hash
	expectedLeafHash := HashLeaf(leafData)
	if expectedLeafHash != p.LeafHash {
		return ErrHashMismatch
	}

	// Walk up the Merkle path to the peak
	currentHash := p.LeafHash
	for _, elem := range p.MerklePath {
		if elem.IsLeft {
			currentHash = HashInternal(elem.Hash, currentHash)
		} else {
			currentHash = HashInternal(currentHash, elem.Hash)
		}
	}

	// Verify we reached the correct peak
	if p.PeakPosition >= len(p.Peaks) {
		return ErrInvalidProof
	}
	if currentHash != p.Peaks[p.PeakPosition] {
		return ErrInvalidProof
	}

	// Verify peak bagging produces the root
	if len(p.Peaks) == 1 {
		if p.Peaks[0] != p.Root {
			return ErrInvalidProof
		}
		return nil
	}

	// Bag peaks from right to left
	root := p.Peaks[len(p.Peaks)-1]
	for i := len(p.Peaks) - 2; i >= 0; i-- {
		root = HashInternal(p.Peaks[i], root)
	}

	if root != p.Root {
		return ErrInvalidProof
	}

	return nil
}

// ---------- MMR Geometry Functions ----------

// findPeaks returns the indices of all peak nodes for an MMR of the given size.
func findPeaks(size uint64) []uint64 {
	if size == 0 {
		return nil
	}

	var peaks []uint64
	pos := uint64(0)

	// Process each "mountain" from left to right
	for pos < size {
		// Find the largest perfect tree that fits
		height := highestPeak(size - pos)
		if height == 0 {
			peaks = append(peaks, pos)
			pos++
			continue
		}

		// Size of a perfect tree of this height
		treeSize := (uint64(1) << (height + 1)) - 1
		if pos+treeSize > size {
			// Tree doesn't fit, try smaller
			height--
			treeSize = (uint64(1) << (height + 1)) - 1
		}

		// Peak is at the rightmost position of this tree
		peakPos := pos + treeSize - 1
		peaks = append(peaks, peakPos)
		pos += treeSize
	}

	return peaks
}

// highestPeak returns the height of the largest perfect binary tree
// that can fit in the given size.
func highestPeak(size uint64) uint8 {
	if size == 0 {
		return 0
	}
	// The largest tree with 2^(h+1)-1 nodes that fits
	h := uint8(bits.Len64(size+1) - 1)
	for h > 0 {
		treeSize := (uint64(1) << (h + 1)) - 1
		if treeSize <= size {
			return h
		}
		h--
	}
	return 0
}

// leafCountFromSize converts MMR size (total nodes) to leaf count.
func leafCountFromSize(size uint64) uint64 {
	if size == 0 {
		return 0
	}

	// Count leaves by summing leaves in each mountain
	count := uint64(0)
	pos := uint64(0)

	for pos < size {
		height := highestPeak(size - pos)
		treeSize := (uint64(1) << (height + 1)) - 1
		if pos+treeSize > size {
			height--
			treeSize = (uint64(1) << (height + 1)) - 1
		}
		if treeSize == 0 {
			treeSize = 1
		}

		// Leaves in a perfect tree of height h is 2^h
		leaves := uint64(1) << height
		count += leaves
		pos += treeSize
	}

	return count
}

// findPeakContaining finds the peak index that contains the given leaf index.
func findPeakContaining(leafIndex, size uint64) uint64 {
	peaks := findPeaks(size)
	pos := uint64(0)

	for _, peak := range peaks {
		// Tree size from current position to peak
		treeSize := peak - pos + 1
		if leafIndex >= pos && leafIndex < pos+treeSize {
			return peak
		}
		pos += treeSize
	}

	// Default to last peak
	if len(peaks) > 0 {
		return peaks[len(peaks)-1]
	}
	return 0
}

// GetNodeHeight calculates the height of a node given its index in the MMR.
// Uses the property that a node at position p has height h if
// the binary representation of (p+1) has h trailing ones.
func GetNodeHeight(index uint64) uint8 {
	pos := index + 1
	height := uint8(0)

	// Count trailing ones in binary representation
	for pos&1 == 1 {
		height++
		pos >>= 1
	}

	// Adjust for MMR structure
	if height > 0 {
		height--
	}

	return height
}
