// Package witness provides topology extraction for file changes.
// It computes edit regions without revealing content, preserving privacy
// while enabling structural change analysis.
package witness

import (
	"sort"
)

// Size thresholds for diff strategy selection.
const (
	// MaxMyersSize is the maximum file size for full Myers diff (256KB).
	MaxMyersSize = 256 * 1024

	// MaxChunkedSize is the maximum file size for chunked diff (10MB).
	MaxChunkedSize = 10 * 1024 * 1024

	// CoalesceProximity is the default proximity threshold for merging regions.
	CoalesceProximity = 0.05 // 5%
)

// DeltaSign values for EditRegion.
const (
	DeltaUnchanged byte = 0
	DeltaIncrease  byte = 1
	DeltaDecrease  byte = 2
)

// DiffOp represents a single diff operation.
type DiffOp struct {
	Type   OpType
	OldPos int // Position in old content
	NewPos int // Position in new content
	Length int // Number of bytes
}

// OpType represents the type of diff operation.
type OpType int

const (
	OpEqual  OpType = 0
	OpInsert OpType = 1
	OpDelete OpType = 2
)

// ExtractTopology computes edit regions between previous and current content.
// Uses Myers diff for small files, chunk-based diff for medium files.
// Returns nil for size-only comparison (files > 10MB).
func ExtractTopology(prev, curr []byte) []EditRegion {
	prevLen := len(prev)
	currLen := len(curr)

	// Handle edge cases
	if prevLen == 0 && currLen == 0 {
		return nil // No change
	}

	if prevLen == 0 {
		// New file: single insertion covering entire new content
		return []EditRegion{{
			StartPct:  0.0,
			EndPct:    1.0, // Normalized to 1.0 for new file
			DeltaSign: DeltaIncrease,
			ByteCount: int32(currLen),
		}}
	}

	if currLen == 0 {
		// Deleted file: single deletion covering entire old content
		return []EditRegion{{
			StartPct:  0.0,
			EndPct:    1.0,
			DeltaSign: DeltaDecrease,
			ByteCount: int32(prevLen),
		}}
	}

	// Choose diff strategy based on size
	totalSize := prevLen + currLen

	if totalSize <= MaxMyersSize*2 {
		// Full Myers diff for small files
		ops := myersDiff(prev, curr)
		return opsToRegions(ops, prevLen, CoalesceProximity)
	}

	if totalSize <= MaxChunkedSize*2 {
		// Chunked diff for medium files
		prevChunks := computeChunks(prev)
		currChunks := computeChunks(curr)
		return chunkedDiff(prev, curr, prevChunks, currChunks)
	}

	// Size-only comparison for very large files
	return nil
}

// myersDiff implements the Myers diff algorithm.
// Returns a sequence of DiffOps describing the transformation.
// O(ND) where N is total length and D is edit distance.
func myersDiff(a, b []byte) []DiffOp {
	n := len(a)
	m := len(b)

	// Handle trivial cases
	if n == 0 && m == 0 {
		return nil
	}
	if n == 0 {
		return []DiffOp{{Type: OpInsert, OldPos: 0, NewPos: 0, Length: m}}
	}
	if m == 0 {
		return []DiffOp{{Type: OpDelete, OldPos: 0, NewPos: 0, Length: n}}
	}

	// Quick check for identical content
	if n == m && bytesEqual(a, b) {
		return []DiffOp{{Type: OpEqual, OldPos: 0, NewPos: 0, Length: n}}
	}

	// Myers algorithm
	max := n + m
	vSize := 2*max + 1

	// v[k + max] stores x coordinate of furthest point on diagonal k
	v := make([]int, vSize)

	// trace stores the v array at each step for backtracking
	var trace [][]int

	// Find the shortest edit script
	for d := 0; d <= max; d++ {
		// Save current state for backtracking BEFORE modifications
		vCopy := make([]int, vSize)
		copy(vCopy, v)
		trace = append(trace, vCopy)

		for k := -d; k <= d; k += 2 {
			// Determine whether to go down or right
			var x int
			if k == -d || (k != d && v[k-1+max] < v[k+1+max]) {
				// Move down (insert from b) - take x from k+1 diagonal
				x = v[k+1+max]
			} else {
				// Move right (delete from a) - take x from k-1 diagonal and add 1
				x = v[k-1+max] + 1
			}
			y := x - k

			// Follow diagonal (matching characters)
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}

			v[k+max] = x

			// Check if we've reached the end
			if x >= n && y >= m {
				// Backtrack to build the edit script
				return backtrack(trace, v, n, m, d, max)
			}
		}
	}

	// Should never reach here for valid inputs
	return nil
}

// backtrack reconstructs the diff operations from the trace.
func backtrack(trace [][]int, finalV []int, n, m, d, max int) []DiffOp {
	// Build operations by backtracking through the trace
	var ops []DiffOp
	x, y := n, m

	for di := d; di > 0; di-- {
		k := x - y

		// Get the v array from before step di was executed
		// trace[di] contains v BEFORE step di was executed
		vPrev := trace[di]

		// Determine which diagonal we came from
		var prevK int
		if k == -di || (k != di && vPrev[k-1+max] < vPrev[k+1+max]) {
			// Came from k+1 (insert)
			prevK = k + 1
		} else {
			// Came from k-1 (delete)
			prevK = k - 1
		}

		// Get the x position at end of step di-1 on diagonal prevK
		prevX := vPrev[prevK+max]
		prevY := prevX - prevK

		// First, walk back the diagonal matches from current position to
		// where we landed after the edit
		for x > prevX && y > prevY {
			x--
			y--
		}

		// Now we're at the position right after the edit
		// Record the edit operation
		if prevK == k+1 {
			// We moved from k+1 to k (down), meaning we inserted
			// The insert happened at (prevX, prevY) in the new sequence
			ops = append(ops, DiffOp{Type: OpInsert, OldPos: prevX, NewPos: prevY, Length: 1})
		} else {
			// We moved from k-1 to k (right), meaning we deleted
			// The delete happened at position prevX in the old sequence
			ops = append(ops, DiffOp{Type: OpDelete, OldPos: prevX, NewPos: prevY, Length: 1})
		}

		x, y = prevX, prevY
	}

	// Reverse to get operations in forward order
	for i, j := 0, len(ops)-1; i < j; i, j = i+1, j-1 {
		ops[i], ops[j] = ops[j], ops[i]
	}

	// Coalesce consecutive operations of same type
	return coalesceOps(ops)
}

// coalesceOps merges consecutive operations of the same type.
func coalesceOps(ops []DiffOp) []DiffOp {
	if len(ops) == 0 {
		return nil
	}

	var result []DiffOp
	current := ops[0]

	for i := 1; i < len(ops); i++ {
		op := ops[i]
		// Check if we can merge with current operation
		if op.Type == current.Type {
			canMerge := false
			if op.Type == OpInsert {
				// Inserts can merge if at consecutive new positions with same old position
				if op.OldPos == current.OldPos && op.NewPos == current.NewPos+current.Length {
					canMerge = true
				}
			} else if op.Type == OpDelete {
				// Deletes can merge if at consecutive old positions with same new position
				if op.OldPos == current.OldPos+current.Length && op.NewPos == current.NewPos {
					canMerge = true
				}
			}
			if canMerge {
				current.Length += op.Length
				continue
			}
		}
		result = append(result, current)
		current = op
	}
	result = append(result, current)

	return result
}

// opsToRegions converts DiffOps to EditRegions.
// Coalesces adjacent operations of same type within proximity threshold.
func opsToRegions(ops []DiffOp, oldLen int, proximityPct float32) []EditRegion {
	if len(ops) == 0 || oldLen == 0 {
		return nil
	}

	var regions []EditRegion

	for i := 0; i < len(ops); i++ {
		op := ops[i]

		switch op.Type {
		case OpInsert:
			// Insertion at position in old document
			pos := float32(op.OldPos) / float32(oldLen)
			if pos < 0 {
				pos = 0
			}
			if pos > 1.0 {
				pos = 1.0
			}

			// Check if this is part of a replacement (delete immediately before at same position)
			if len(regions) > 0 {
				lastIdx := len(regions) - 1
				lastRegion := regions[lastIdx]
				// If last region was a delete ending at this position, it's a replacement
				if lastRegion.DeltaSign == DeltaDecrease {
					expectedEndPct := float32(op.OldPos) / float32(oldLen)
					if lastRegion.EndPct == expectedEndPct {
						// Convert to replacement
						regions[lastIdx].DeltaSign = DeltaUnchanged
						regions[lastIdx].ByteCount += int32(op.Length)
						continue
					}
				}
			}

			regions = append(regions, EditRegion{
				StartPct:  pos,
				EndPct:    pos, // Point insertion
				DeltaSign: DeltaIncrease,
				ByteCount: int32(op.Length),
			})

		case OpDelete:
			startPct := float32(op.OldPos) / float32(oldLen)
			endPct := float32(op.OldPos+op.Length) / float32(oldLen)
			if startPct < 0 {
				startPct = 0
			}
			if endPct > 1.0 {
				endPct = 1.0
			}

			regions = append(regions, EditRegion{
				StartPct:  startPct,
				EndPct:    endPct,
				DeltaSign: DeltaDecrease,
				ByteCount: int32(op.Length),
			})

		case OpEqual:
			// No region for equal content
			continue
		}
	}

	// Coalesce nearby regions of same type
	return coalesceRegions(regions, proximityPct)
}

// coalesceRegions merges adjacent regions of same type if within proximity threshold.
func coalesceRegions(regions []EditRegion, proximityPct float32) []EditRegion {
	if len(regions) <= 1 {
		return regions
	}

	// Sort by StartPct
	sort.Slice(regions, func(i, j int) bool {
		return regions[i].StartPct < regions[j].StartPct
	})

	var result []EditRegion
	current := regions[0]

	for i := 1; i < len(regions); i++ {
		r := regions[i]

		// Check if regions should be merged
		gap := r.StartPct - current.EndPct
		if gap < proximityPct && r.DeltaSign == current.DeltaSign {
			// Merge regions
			current.EndPct = r.EndPct
			current.ByteCount += r.ByteCount
		} else {
			result = append(result, current)
			current = r
		}
	}
	result = append(result, current)

	return result
}

// ComputeChunks uses content-defined chunking (Rabin fingerprint style).
// Target chunk size ~4KB, min 1KB, max 16KB.
func ComputeChunks(content []byte) []ChunkRef {
	return computeChunks(content)
}

// DiffChunked compares content using content-defined chunks when previous content is missing.
// prevSize: size of previous file.
// curr: current content.
// prevChunks: chunks of previous file.
// currChunks: chunks of current file.
func DiffChunked(prevSize int64, curr []byte, prevChunks, currChunks []ChunkRef) []EditRegion {
	if prevSize == 0 {
		return []EditRegion{{
			StartPct:  0.0,
			EndPct:    1.0,
			DeltaSign: DeltaIncrease,
			ByteCount: int32(len(curr)),
		}}
	}

	// Build hash set of current chunks for quick lookup
	currHashes := make(map[[32]byte]bool)
	for _, c := range currChunks {
		currHashes[c.Hash] = true
	}

	// Build hash set of previous chunks
	prevHashes := make(map[[32]byte]bool)
	for _, c := range prevChunks {
		prevHashes[c.Hash] = true
	}

	var regions []EditRegion

	// Find deleted chunks (in prev but not in curr)
	for _, c := range prevChunks {
		if !currHashes[c.Hash] {
			startPct := float32(c.Offset) / float32(prevSize)
			endPct := float32(c.Offset+c.Length) / float32(prevSize)
			regions = append(regions, EditRegion{
				StartPct:  startPct,
				EndPct:    endPct,
				DeltaSign: DeltaDecrease,
				ByteCount: int32(c.Length),
			})
		}
	}

	// Find inserted chunks (in curr but not in prev)
	currLen := int64(len(curr))
	for _, c := range currChunks {
		if !prevHashes[c.Hash] {
			// Map position from curr to prev space
			pos := float32(c.Offset) / float32(currLen)
			if pos > 1.0 {
				pos = 1.0
			}
			regions = append(regions, EditRegion{
				StartPct:  pos,
				EndPct:    pos,
				DeltaSign: DeltaIncrease,
				ByteCount: int32(c.Length),
			})
		}
	}

	return coalesceRegions(regions, CoalesceProximity)
}

// chunkedDiff compares content using content-defined chunks.
// Returns approximate edit regions based on which chunks changed.
// Used for files 256KB - 10MB.
func chunkedDiff(prev, curr []byte, prevChunks, currChunks []ChunkRef) []EditRegion {
	return DiffChunked(int64(len(prev)), curr, prevChunks, currChunks)
}

// bytesEqual checks if two byte slices are equal.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ComputeSizeDelta calculates the size change between previous and current.
func ComputeSizeDelta(prevSize, currSize int64) int32 {
	delta := currSize - prevSize
	if delta > 2147483647 {
		return 2147483647
	}
	if delta < -2147483648 {
		return -2147483648
	}
	return int32(delta)
}

// TopologyStats provides aggregate statistics about edit regions.
type TopologyStats struct {
	TotalRegions   int
	Insertions     int
	Deletions      int
	Replacements   int
	TotalBytesAdd  int64
	TotalBytesDel  int64
	MaxRegionSize  int32
	CoverageStart  float32 // Earliest edit position
	CoverageEnd    float32 // Latest edit position
}

// ComputeStats calculates aggregate statistics for a set of edit regions.
func ComputeStats(regions []EditRegion) TopologyStats {
	stats := TopologyStats{
		CoverageStart: 1.0,
		CoverageEnd:   0.0,
	}

	for _, r := range regions {
		stats.TotalRegions++

		switch r.DeltaSign {
		case DeltaIncrease: // +1 insertion
			stats.Insertions++
			stats.TotalBytesAdd += int64(r.ByteCount)
		case DeltaDecrease: // -1 deletion (represented as 2)
			stats.Deletions++
			stats.TotalBytesDel += int64(r.ByteCount)
		case DeltaUnchanged: // 0 replacement
			stats.Replacements++
			// For replacements, count as both add and delete
			stats.TotalBytesAdd += int64(r.ByteCount / 2)
			stats.TotalBytesDel += int64(r.ByteCount / 2)
		}

		if r.ByteCount > stats.MaxRegionSize {
			stats.MaxRegionSize = r.ByteCount
		}

		if r.StartPct < stats.CoverageStart {
			stats.CoverageStart = r.StartPct
		}
		if r.EndPct > stats.CoverageEnd {
			stats.CoverageEnd = r.EndPct
		}
	}

	if stats.TotalRegions == 0 {
		stats.CoverageStart = 0
		stats.CoverageEnd = 0
	}

	return stats
}
