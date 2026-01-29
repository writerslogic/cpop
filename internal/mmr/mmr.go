package mmr

import (
	"fmt"
	"math/bits"
	"sort"
	"sync"
)

// MMR represents a Merkle Mountain Range structure.
// An MMR is an append-only authenticated data structure consisting of
// multiple perfect binary trees ("mountains") of decreasing size.
// All methods are safe for concurrent use.
type MMR struct {
	mu    sync.RWMutex
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
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create the new leaf node
	leafIndex := m.size
	leaf := NewLeafNode(leafIndex, data)

	if err := m.store.Append(leaf); err != nil {
		return 0, err
	}
	m.size++

	// Merge peaks of equal height and get final peaks
	peaks, err := m.mergePeaks()
	if err != nil {
		return 0, err
	}
	m.peaks = peaks

	return leafIndex, nil
}

// mergePeaks merges adjacent peaks of equal height until all peaks have different heights.
// Returns the final peak indices after all merges are complete.
func (m *MMR) mergePeaks() ([]uint64, error) {
	for {
		peaks := findPeaks(m.size)
		if len(peaks) < 2 {
			return peaks, nil
		}

		// Check if the last two peaks have the same height
		lastIdx := peaks[len(peaks)-1]
		prevIdx := peaks[len(peaks)-2]

		lastNode, err := m.store.Get(lastIdx)
		if err != nil {
			return nil, err
		}

		prevNode, err := m.store.Get(prevIdx)
		if err != nil {
			return nil, err
		}

		if lastNode.Height != prevNode.Height {
			return peaks, nil
		}

		// Merge: create a new internal node
		newNode := NewInternalNode(m.size, lastNode.Height+1, prevNode, lastNode)
		if err := m.store.Append(newNode); err != nil {
			return nil, err
		}
		m.size++
	}
}

// GetPeaks returns the hash values of all current mountain peaks.
func (m *MMR) GetPeaks() ([][32]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getPeaksLocked()
}

// getPeaksLocked is the internal version (caller must hold lock).
func (m *MMR) getPeaksLocked() ([][32]byte, error) {
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
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getRootLocked()
}

// getRootLocked is the internal version (caller must hold lock).
func (m *MMR) getRootLocked() ([32]byte, error) {
	if m.size == 0 {
		return [32]byte{}, ErrEmptyMMR
	}

	peaks, err := m.getPeaksLocked()
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
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.size
}

// LeafCount returns the number of leaf nodes in the MMR.
func (m *MMR) LeafCount() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return leafCountFromSize(m.size)
}

// GetLeafIndex converts a leaf ordinal (0th, 1st, 2nd leaf, etc.) to its MMR index.
// This is useful because MMR indices are not contiguous for leaves due to internal nodes.
func (m *MMR) GetLeafIndex(leafOrdinal uint64) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.size == 0 {
		return 0, ErrEmptyMMR
	}

	leafCount := leafCountFromSize(m.size)
	if leafOrdinal >= leafCount {
		return 0, fmt.Errorf("mmr: leaf ordinal %d out of range (max %d)", leafOrdinal, leafCount-1)
	}

	// Iterate through the MMR to find the nth leaf
	currentLeaf := uint64(0)
	for idx := uint64(0); idx < m.size; idx++ {
		node, err := m.store.Get(idx)
		if err != nil {
			return 0, err
		}
		if node.Height == 0 { // It's a leaf
			if currentLeaf == leafOrdinal {
				return idx, nil
			}
			currentLeaf++
		}
	}

	return 0, ErrIndexOutOfRange
}

// GetLeafIndices returns the MMR indices for all leaves in the given ordinal range (inclusive).
func (m *MMR) GetLeafIndices(startOrdinal, endOrdinal uint64) ([]uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getLeafIndicesLocked(startOrdinal, endOrdinal)
}

// getLeafIndicesLocked is the internal version (caller must hold lock).
func (m *MMR) getLeafIndicesLocked(startOrdinal, endOrdinal uint64) ([]uint64, error) {
	if startOrdinal > endOrdinal {
		return nil, fmt.Errorf("mmr: invalid range: start %d > end %d", startOrdinal, endOrdinal)
	}

	leafCount := leafCountFromSize(m.size)
	if endOrdinal >= leafCount {
		return nil, fmt.Errorf("mmr: leaf ordinal %d out of range (max %d)", endOrdinal, leafCount-1)
	}

	indices := make([]uint64, 0, endOrdinal-startOrdinal+1)
	currentLeaf := uint64(0)

	for idx := uint64(0); idx < m.size && currentLeaf <= endOrdinal; idx++ {
		node, err := m.store.Get(idx)
		if err != nil {
			return nil, err
		}
		if node.Height == 0 { // It's a leaf
			if currentLeaf >= startOrdinal && currentLeaf <= endOrdinal {
				indices = append(indices, idx)
			}
			currentLeaf++
		}
	}

	return indices, nil
}

// Get retrieves a node by its index.
func (m *MMR) Get(index uint64) (*Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if index >= m.size {
		return nil, ErrIndexOutOfRange
	}
	return m.store.Get(index)
}

// GenerateProof creates an inclusion proof for the leaf at the given index.
// The proof contains the Merkle path from the leaf to the peaks, plus peak bagging.
func (m *MMR) GenerateProof(leafIndex uint64) (*InclusionProof, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

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
	peaks, err := m.getPeaksLocked()
	if err != nil {
		return nil, err
	}

	peakIndices := findPeaks(m.size)
	peakPosition := -1
	for i, idx := range peakIndices {
		if idx == peakIndex {
			peakPosition = i
			break
		}
	}
	if peakPosition < 0 {
		return nil, fmt.Errorf("mmr: internal error: peak index %d not found in peaks", peakIndex)
	}

	root, err := m.getRootLocked()
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

		// Get sibling hash - if this fails, it's a genuine error since
		// findFamily already verified the sibling exists
		siblingNode, err := m.store.Get(siblingPos)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get sibling node at %d: %w", siblingPos, err)
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

// RangeProof proves inclusion of a contiguous range of leaves in the MMR.
// This is more efficient than generating individual proofs for each leaf
// when proving multiple consecutive versions.
type RangeProof struct {
	StartLeaf    uint64         // Ordinal of the first leaf (0-indexed)
	EndLeaf      uint64         // Ordinal of the last leaf (inclusive)
	LeafIndices  []uint64       // MMR indices of the leaves
	LeafHashes   [][32]byte     // Hashes of leaves in the range
	SiblingPath  []ProofElement // Shared Merkle path elements (deduplicated)
	Peaks        [][32]byte     // All peak hashes for bagging
	PeakPosition int            // Position of the relevant peak
	MMRSize      uint64         // Size of the MMR when proof was generated
	Root         [32]byte       // The root at time of proof generation
}

// GenerateRangeProof creates an inclusion proof for a contiguous range of leaves.
// startLeaf and endLeaf are leaf ordinals (0th leaf, 1st leaf, etc.), inclusive.
func (m *MMR) GenerateRangeProof(startLeaf, endLeaf uint64) (*RangeProof, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.size == 0 {
		return nil, ErrEmptyMMR
	}

	if startLeaf > endLeaf {
		return nil, fmt.Errorf("mmr: invalid range: start %d > end %d", startLeaf, endLeaf)
	}

	leafCount := leafCountFromSize(m.size)
	if endLeaf >= leafCount {
		return nil, fmt.Errorf("mmr: leaf ordinal %d out of range (max %d)", endLeaf, leafCount-1)
	}

	// Get the MMR indices for all leaves in the range
	leafIndices, err := m.getLeafIndicesLocked(startLeaf, endLeaf)
	if err != nil {
		return nil, err
	}

	// Get leaf hashes
	leafHashes := make([][32]byte, len(leafIndices))
	for i, idx := range leafIndices {
		node, err := m.store.Get(idx)
		if err != nil {
			return nil, err
		}
		leafHashes[i] = node.Hash
	}

	// Build the combined proof path by finding shared ancestors
	siblingPath, peakIndex, err := m.generateRangeMerklePath(leafIndices)
	if err != nil {
		return nil, err
	}

	// Get peak hashes for bagging
	peaks, err := m.getPeaksLocked()
	if err != nil {
		return nil, err
	}

	peakIndices := findPeaks(m.size)
	peakPosition := -1
	for i, idx := range peakIndices {
		if idx == peakIndex {
			peakPosition = i
			break
		}
	}
	if peakPosition < 0 {
		return nil, fmt.Errorf("mmr: internal error: peak index %d not found in peaks", peakIndex)
	}

	root, err := m.getRootLocked()
	if err != nil {
		return nil, err
	}

	return &RangeProof{
		StartLeaf:    startLeaf,
		EndLeaf:      endLeaf,
		LeafIndices:  leafIndices,
		LeafHashes:   leafHashes,
		SiblingPath:  siblingPath,
		Peaks:        peaks,
		PeakPosition: peakPosition,
		MMRSize:      m.size,
		Root:         root,
	}, nil
}

// generateRangeMerklePath computes the Merkle path for a range of leaves.
// It collects sibling hashes needed to verify the range, deduplicating shared ancestors.
func (m *MMR) generateRangeMerklePath(leafIndices []uint64) ([]ProofElement, uint64, error) {
	if len(leafIndices) == 0 {
		return nil, 0, fmt.Errorf("mmr: no leaf indices provided")
	}

	// Track which nodes are covered by our range at each level
	covered := make(map[uint64]bool)
	for _, idx := range leafIndices {
		covered[idx] = true
	}

	var path []ProofElement
	currentLevel := make([]uint64, len(leafIndices))
	copy(currentLevel, leafIndices)

	height := uint8(0)
	var peakIndex uint64

	for len(currentLevel) > 0 {
		// Sort current level for deterministic order
		sort.Slice(currentLevel, func(i, j int) bool { return currentLevel[i] < currentLevel[j] })

		nextLevel := make([]uint64, 0)
		processedParents := make(map[uint64]bool)

		for _, pos := range currentLevel {
			siblingPos, parentPos, isRightChild, found := m.findFamily(pos, height)

			if !found {
				// We're at a peak
				peakIndex = pos
				continue
			}

			// Skip if we already processed this parent
			if processedParents[parentPos] {
				continue
			}
			processedParents[parentPos] = true

			// Check if sibling is also in our covered set
			if !covered[siblingPos] {
				// Need to include sibling in proof
				siblingNode, err := m.store.Get(siblingPos)
				if err != nil {
					return nil, 0, fmt.Errorf("failed to get sibling node at %d: %w", siblingPos, err)
				}
				path = append(path, ProofElement{
					Hash:   siblingNode.Hash,
					IsLeft: isRightChild,
				})
			}

			// Parent is now covered
			covered[parentPos] = true
			nextLevel = append(nextLevel, parentPos)
		}

		currentLevel = nextLevel
		height++
	}

	return path, peakIndex, nil
}

// Verify checks that this range proof is valid for the given leaf data.
func (p *RangeProof) Verify(leafData [][]byte) error {
	// Verify we have the right number of leaves
	expectedCount := int(p.EndLeaf - p.StartLeaf + 1)
	if len(leafData) != expectedCount {
		return fmt.Errorf("mmr: expected %d leaves, got %d", expectedCount, len(leafData))
	}
	if len(p.LeafHashes) != expectedCount {
		return ErrInvalidProof
	}

	// Verify each leaf hash
	for i, data := range leafData {
		expectedHash := HashLeaf(data)
		if expectedHash != p.LeafHashes[i] {
			return ErrHashMismatch
		}
	}

	// Verify we have leaf indices
	if len(p.LeafIndices) != len(p.LeafHashes) {
		return ErrInvalidProof
	}

	// Rebuild the tree from leaves up using siblings from the proof
	// Track hashes at each level
	currentHashes := make(map[uint64][32]byte)
	for i, hash := range p.LeafHashes {
		currentHashes[p.LeafIndices[i]] = hash
	}

	siblingIdx := 0
	height := uint8(0)

	for len(currentHashes) > 1 || siblingIdx < len(p.SiblingPath) {
		nextHashes := make(map[uint64][32]byte)
		processedPositions := make(map[uint64]bool)

		// Sort positions for deterministic processing (ascending order)
		positions := make([]uint64, 0, len(currentHashes))
		for pos := range currentHashes {
			positions = append(positions, pos)
		}
		sort.Slice(positions, func(i, j int) bool { return positions[i] < positions[j] })

		for _, pos := range positions {
			if processedPositions[pos] {
				continue
			}

			hash := currentHashes[pos]
			offset := uint64(1) << (height + 1)

			// Determine parent position and sibling
			var parentPos uint64
			var combinedHash [32]byte

			// Try as left child
			leftParent := pos + offset
			rightSibling := leftParent - 1

			if siblingHash, hasSibling := currentHashes[rightSibling]; hasSibling && rightSibling != pos {
				// Sibling is in our set
				combinedHash = HashInternal(hash, siblingHash)
				parentPos = leftParent
				processedPositions[rightSibling] = true
			} else {
				// Try as right child
				rightParent := pos + 1
				if offset <= pos+1 {
					leftSibling := rightParent - offset
					if siblingHash, hasSibling := currentHashes[leftSibling]; hasSibling && leftSibling != pos {
						combinedHash = HashInternal(siblingHash, hash)
						parentPos = rightParent
						processedPositions[leftSibling] = true
					} else {
						// Need sibling from proof
						if siblingIdx >= len(p.SiblingPath) {
							// At a peak or end
							nextHashes[pos] = hash
							continue
						}
						elem := p.SiblingPath[siblingIdx]
						siblingIdx++
						if elem.IsLeft {
							combinedHash = HashInternal(elem.Hash, hash)
							parentPos = rightParent
						} else {
							combinedHash = HashInternal(hash, elem.Hash)
							parentPos = leftParent
						}
					}
				} else {
					// Need sibling from proof
					if siblingIdx >= len(p.SiblingPath) {
						nextHashes[pos] = hash
						continue
					}
					elem := p.SiblingPath[siblingIdx]
					siblingIdx++
					if elem.IsLeft {
						combinedHash = HashInternal(elem.Hash, hash)
					} else {
						combinedHash = HashInternal(hash, elem.Hash)
					}
					parentPos = leftParent
				}
			}

			processedPositions[pos] = true
			nextHashes[parentPos] = combinedHash
		}

		if len(nextHashes) == 0 {
			break
		}

		currentHashes = nextHashes
		height++
	}

	// Verify we have exactly one hash remaining (the peak)
	if len(currentHashes) != 1 {
		return fmt.Errorf("mmr: range proof verification failed: expected 1 hash, got %d", len(currentHashes))
	}

	// Get the computed peak hash
	var computedPeak [32]byte
	for _, hash := range currentHashes {
		computedPeak = hash
	}

	// Verify we reached the correct peak
	if p.PeakPosition >= len(p.Peaks) {
		return ErrInvalidProof
	}
	if computedPeak != p.Peaks[p.PeakPosition] {
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
