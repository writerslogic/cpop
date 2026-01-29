package mmr

import (
	"encoding/binary"
	"fmt"
)

// Proof serialization format version
const proofFormatVersion = 1

// Proof type identifiers
const (
	proofTypeInclusion byte = 0x01
	proofTypeRange     byte = 0x02
)

// Serialize converts an InclusionProof to a compact binary format.
// Format:
//
//	[1 byte version][1 byte type][8 bytes LeafIndex][32 bytes LeafHash]
//	[2 bytes PathLen][PathLen * 33 bytes (32 hash + 1 isLeft)]
//	[2 bytes PeaksLen][PeaksLen * 32 bytes]
//	[2 bytes PeakPosition][8 bytes MMRSize][32 bytes Root]
func (p *InclusionProof) Serialize() []byte {
	// Calculate total size
	pathSize := len(p.MerklePath) * 33
	peaksSize := len(p.Peaks) * 32
	totalSize := 1 + 1 + 8 + 32 + 2 + pathSize + 2 + peaksSize + 2 + 8 + 32

	buf := make([]byte, totalSize)
	offset := 0

	// Version and type
	buf[offset] = proofFormatVersion
	offset++
	buf[offset] = proofTypeInclusion
	offset++

	// LeafIndex
	binary.BigEndian.PutUint64(buf[offset:], p.LeafIndex)
	offset += 8

	// LeafHash
	copy(buf[offset:], p.LeafHash[:])
	offset += 32

	// MerklePath length and data
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(p.MerklePath)))
	offset += 2
	for _, elem := range p.MerklePath {
		copy(buf[offset:], elem.Hash[:])
		offset += 32
		if elem.IsLeft {
			buf[offset] = 1
		} else {
			buf[offset] = 0
		}
		offset++
	}

	// Peaks length and data
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(p.Peaks)))
	offset += 2
	for _, peak := range p.Peaks {
		copy(buf[offset:], peak[:])
		offset += 32
	}

	// PeakPosition
	binary.BigEndian.PutUint16(buf[offset:], uint16(p.PeakPosition))
	offset += 2

	// MMRSize
	binary.BigEndian.PutUint64(buf[offset:], p.MMRSize)
	offset += 8

	// Root
	copy(buf[offset:], p.Root[:])

	return buf
}

// DeserializeInclusionProof reconstructs an InclusionProof from binary data.
func DeserializeInclusionProof(data []byte) (*InclusionProof, error) {
	if len(data) < 86 { // Minimum size: version + type + LeafIndex + LeafHash + PathLen + PeaksLen + PeakPosition + MMRSize + Root
		return nil, ErrInvalidNodeData
	}

	offset := 0

	// Version check
	version := data[offset]
	offset++
	if version != proofFormatVersion {
		return nil, fmt.Errorf("mmr: unsupported proof version: %d", version)
	}

	// Type check
	proofType := data[offset]
	offset++
	if proofType != proofTypeInclusion {
		return nil, fmt.Errorf("mmr: expected inclusion proof, got type %d", proofType)
	}

	p := &InclusionProof{}

	// LeafIndex
	p.LeafIndex = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// LeafHash
	copy(p.LeafHash[:], data[offset:offset+32])
	offset += 32

	// MerklePath
	if offset+2 > len(data) {
		return nil, ErrInvalidNodeData
	}
	pathLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if offset+pathLen*33 > len(data) {
		return nil, ErrInvalidNodeData
	}
	p.MerklePath = make([]ProofElement, pathLen)
	for i := 0; i < pathLen; i++ {
		copy(p.MerklePath[i].Hash[:], data[offset:offset+32])
		offset += 32
		p.MerklePath[i].IsLeft = data[offset] == 1
		offset++
	}

	// Peaks
	if offset+2 > len(data) {
		return nil, ErrInvalidNodeData
	}
	peaksLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if offset+peaksLen*32 > len(data) {
		return nil, ErrInvalidNodeData
	}
	p.Peaks = make([][32]byte, peaksLen)
	for i := 0; i < peaksLen; i++ {
		copy(p.Peaks[i][:], data[offset:offset+32])
		offset += 32
	}

	// PeakPosition
	if offset+2 > len(data) {
		return nil, ErrInvalidNodeData
	}
	p.PeakPosition = int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	// Validate PeakPosition is within bounds
	if peaksLen == 0 {
		return nil, fmt.Errorf("mmr: invalid proof: no peaks")
	}
	if p.PeakPosition < 0 || p.PeakPosition >= peaksLen {
		return nil, fmt.Errorf("mmr: invalid proof: peak position %d out of range (0-%d)", p.PeakPosition, peaksLen-1)
	}

	// MMRSize
	if offset+8 > len(data) {
		return nil, ErrInvalidNodeData
	}
	p.MMRSize = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Root
	if offset+32 > len(data) {
		return nil, ErrInvalidNodeData
	}
	copy(p.Root[:], data[offset:offset+32])

	return p, nil
}

// Serialize converts a RangeProof to a compact binary format.
// Format:
//
//	[1 byte version][1 byte type][8 bytes StartLeaf][8 bytes EndLeaf]
//	[2 bytes LeavesLen][LeavesLen * 8 bytes indices][LeavesLen * 32 bytes hashes]
//	[2 bytes PathLen][PathLen * 33 bytes (32 hash + 1 isLeft)]
//	[2 bytes PeaksLen][PeaksLen * 32 bytes]
//	[2 bytes PeakPosition][8 bytes MMRSize][32 bytes Root]
func (p *RangeProof) Serialize() []byte {
	// Calculate total size
	leavesCount := len(p.LeafHashes)
	indicesSize := leavesCount * 8
	hashesSize := leavesCount * 32
	pathSize := len(p.SiblingPath) * 33
	peaksSize := len(p.Peaks) * 32
	totalSize := 1 + 1 + 8 + 8 + 2 + indicesSize + hashesSize + 2 + pathSize + 2 + peaksSize + 2 + 8 + 32

	buf := make([]byte, totalSize)
	offset := 0

	// Version and type
	buf[offset] = proofFormatVersion
	offset++
	buf[offset] = proofTypeRange
	offset++

	// StartLeaf
	binary.BigEndian.PutUint64(buf[offset:], p.StartLeaf)
	offset += 8

	// EndLeaf
	binary.BigEndian.PutUint64(buf[offset:], p.EndLeaf)
	offset += 8

	// Leaves count, indices, and hashes
	binary.BigEndian.PutUint16(buf[offset:], uint16(leavesCount))
	offset += 2
	for _, idx := range p.LeafIndices {
		binary.BigEndian.PutUint64(buf[offset:], idx)
		offset += 8
	}
	for _, hash := range p.LeafHashes {
		copy(buf[offset:], hash[:])
		offset += 32
	}

	// SiblingPath length and data
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(p.SiblingPath)))
	offset += 2
	for _, elem := range p.SiblingPath {
		copy(buf[offset:], elem.Hash[:])
		offset += 32
		if elem.IsLeft {
			buf[offset] = 1
		} else {
			buf[offset] = 0
		}
		offset++
	}

	// Peaks length and data
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(p.Peaks)))
	offset += 2
	for _, peak := range p.Peaks {
		copy(buf[offset:], peak[:])
		offset += 32
	}

	// PeakPosition
	binary.BigEndian.PutUint16(buf[offset:], uint16(p.PeakPosition))
	offset += 2

	// MMRSize
	binary.BigEndian.PutUint64(buf[offset:], p.MMRSize)
	offset += 8

	// Root
	copy(buf[offset:], p.Root[:])

	return buf
}

// DeserializeRangeProof reconstructs a RangeProof from binary data.
func DeserializeRangeProof(data []byte) (*RangeProof, error) {
	if len(data) < 94 { // Minimum size
		return nil, ErrInvalidNodeData
	}

	offset := 0

	// Version check
	version := data[offset]
	offset++
	if version != proofFormatVersion {
		return nil, fmt.Errorf("mmr: unsupported proof version: %d", version)
	}

	// Type check
	proofType := data[offset]
	offset++
	if proofType != proofTypeRange {
		return nil, fmt.Errorf("mmr: expected range proof, got type %d", proofType)
	}

	p := &RangeProof{}

	// StartLeaf
	p.StartLeaf = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// EndLeaf
	p.EndLeaf = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Validate StartLeaf <= EndLeaf
	if p.StartLeaf > p.EndLeaf {
		return nil, fmt.Errorf("mmr: invalid range proof: start %d > end %d", p.StartLeaf, p.EndLeaf)
	}

	// Leaves count
	if offset+2 > len(data) {
		return nil, ErrInvalidNodeData
	}
	leavesLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	// Validate leaves count matches range
	expectedLeaves := int(p.EndLeaf - p.StartLeaf + 1)
	if leavesLen != expectedLeaves {
		return nil, fmt.Errorf("mmr: invalid range proof: expected %d leaves for range, got %d", expectedLeaves, leavesLen)
	}

	// Leaf indices
	if offset+leavesLen*8 > len(data) {
		return nil, ErrInvalidNodeData
	}
	p.LeafIndices = make([]uint64, leavesLen)
	for i := 0; i < leavesLen; i++ {
		p.LeafIndices[i] = binary.BigEndian.Uint64(data[offset:])
		offset += 8
	}

	// Leaf hashes
	if offset+leavesLen*32 > len(data) {
		return nil, ErrInvalidNodeData
	}
	p.LeafHashes = make([][32]byte, leavesLen)
	for i := 0; i < leavesLen; i++ {
		copy(p.LeafHashes[i][:], data[offset:offset+32])
		offset += 32
	}

	// SiblingPath
	if offset+2 > len(data) {
		return nil, ErrInvalidNodeData
	}
	pathLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if offset+pathLen*33 > len(data) {
		return nil, ErrInvalidNodeData
	}
	p.SiblingPath = make([]ProofElement, pathLen)
	for i := 0; i < pathLen; i++ {
		copy(p.SiblingPath[i].Hash[:], data[offset:offset+32])
		offset += 32
		p.SiblingPath[i].IsLeft = data[offset] == 1
		offset++
	}

	// Peaks
	if offset+2 > len(data) {
		return nil, ErrInvalidNodeData
	}
	peaksLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if offset+peaksLen*32 > len(data) {
		return nil, ErrInvalidNodeData
	}
	p.Peaks = make([][32]byte, peaksLen)
	for i := 0; i < peaksLen; i++ {
		copy(p.Peaks[i][:], data[offset:offset+32])
		offset += 32
	}

	// PeakPosition
	if offset+2 > len(data) {
		return nil, ErrInvalidNodeData
	}
	p.PeakPosition = int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	// Validate PeakPosition is within bounds
	if peaksLen == 0 {
		return nil, fmt.Errorf("mmr: invalid proof: no peaks")
	}
	if p.PeakPosition < 0 || p.PeakPosition >= peaksLen {
		return nil, fmt.Errorf("mmr: invalid proof: peak position %d out of range (0-%d)", p.PeakPosition, peaksLen-1)
	}

	// MMRSize
	if offset+8 > len(data) {
		return nil, ErrInvalidNodeData
	}
	p.MMRSize = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Root
	if offset+32 > len(data) {
		return nil, ErrInvalidNodeData
	}
	copy(p.Root[:], data[offset:offset+32])

	return p, nil
}

// ProofSize returns the serialized size of an InclusionProof in bytes.
func (p *InclusionProof) ProofSize() int {
	return 1 + 1 + 8 + 32 + 2 + len(p.MerklePath)*33 + 2 + len(p.Peaks)*32 + 2 + 8 + 32
}

// ProofSize returns the serialized size of a RangeProof in bytes.
func (p *RangeProof) ProofSize() int {
	leavesCount := len(p.LeafHashes)
	return 1 + 1 + 8 + 8 + 2 + leavesCount*8 + leavesCount*32 + 2 + len(p.SiblingPath)*33 + 2 + len(p.Peaks)*32 + 2 + 8 + 32
}
