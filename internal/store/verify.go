package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
)

// VerifyEventIntegrity verifies that an event and its regions match the expected leaf hash.
func VerifyEventIntegrity(event *Event, regions []EditRegion, expectedLeafHash [32]byte) error {
	computedHash := computeLeafHash(event, regions)

	if !bytes.Equal(computedHash[:], expectedLeafHash[:]) {
		return fmt.Errorf("leaf hash mismatch for event %d (mmr_index=%d): computed %x, expected %x",
			event.ID, event.MMRIndex, computedHash, expectedLeafHash)
	}

	return nil
}

// VerifyAllEvents verifies all events in the store against their MMR leaf hashes.
// Returns a slice of corrupted MMR indices.
func (s *Store) VerifyAllEvents(mmrGetter func(uint64) ([32]byte, error)) ([]uint64, error) {
	rows, err := s.db.Query(`
		SELECT id, device_id, mmr_index, mmr_leaf_hash, timestamp_ns, file_path, content_hash, file_size, size_delta, context_id
		FROM events
		ORDER BY mmr_index ASC`)
	if err != nil {
		return nil, fmt.Errorf("query all events: %w", err)
	}
	defer rows.Close()

	var corrupted []uint64

	for rows.Next() {
		var e Event
		var deviceID, leafHash, contentHash []byte

		if err := rows.Scan(&e.ID, &deviceID, &e.MMRIndex, &leafHash, &e.TimestampNs, &e.FilePath, &contentHash, &e.FileSize, &e.SizeDelta, &e.ContextID); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}

		copy(e.DeviceID[:], deviceID)
		copy(e.MMRLeafHash[:], leafHash)
		copy(e.ContentHash[:], contentHash)

		// Get edit regions for this event
		regions, err := s.GetEditRegions(e.ID)
		if err != nil {
			return nil, fmt.Errorf("get edit regions for event %d: %w", e.ID, err)
		}

		// Verify against stored leaf hash
		if err := VerifyEventIntegrity(&e, regions, e.MMRLeafHash); err != nil {
			corrupted = append(corrupted, e.MMRIndex)
			continue
		}

		// If an MMR getter is provided, also verify against the MMR
		if mmrGetter != nil {
			mmrHash, err := mmrGetter(e.MMRIndex)
			if err != nil {
				return nil, fmt.Errorf("get mmr hash for index %d: %w", e.MMRIndex, err)
			}

			if !bytes.Equal(e.MMRLeafHash[:], mmrHash[:]) {
				corrupted = append(corrupted, e.MMRIndex)
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}

	return corrupted, nil
}

// computeLeafHash computes the MMR leaf hash for an event and its regions.
// The hash is computed as: H(device_id || timestamp_ns || file_path || content_hash || file_size || size_delta || regions_hash)
func computeLeafHash(event *Event, regions []EditRegion) [32]byte {
	h := sha256.New()

	// Device ID (16 bytes)
	h.Write(event.DeviceID[:])

	// Timestamp (8 bytes, big-endian)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(event.TimestampNs))
	h.Write(tsBuf[:])

	// File path (length-prefixed)
	var pathLenBuf [4]byte
	binary.BigEndian.PutUint32(pathLenBuf[:], uint32(len(event.FilePath)))
	h.Write(pathLenBuf[:])
	h.Write([]byte(event.FilePath))

	// Content hash (32 bytes)
	h.Write(event.ContentHash[:])

	// File size (8 bytes, big-endian)
	var sizeBuf [8]byte
	binary.BigEndian.PutUint64(sizeBuf[:], uint64(event.FileSize))
	h.Write(sizeBuf[:])

	// Size delta (4 bytes, big-endian, signed as unsigned)
	var deltaBuf [4]byte
	binary.BigEndian.PutUint32(deltaBuf[:], uint32(event.SizeDelta))
	h.Write(deltaBuf[:])

	// Regions hash
	regionsHash := computeRegionsHash(regions)
	h.Write(regionsHash[:])

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// computeRegionsHash computes a hash of the edit regions.
// Returns a zero hash if there are no regions.
func computeRegionsHash(regions []EditRegion) [32]byte {
	if len(regions) == 0 {
		return [32]byte{}
	}

	h := sha256.New()

	// Number of regions (4 bytes)
	var countBuf [4]byte
	binary.BigEndian.PutUint32(countBuf[:], uint32(len(regions)))
	h.Write(countBuf[:])

	for _, r := range regions {
		// Ordinal (2 bytes)
		var ordBuf [2]byte
		binary.BigEndian.PutUint16(ordBuf[:], uint16(r.Ordinal))
		h.Write(ordBuf[:])

		// Start percentage (4 bytes as float32 bits)
		var startBuf [4]byte
		binary.BigEndian.PutUint32(startBuf[:], floatBits(r.StartPct))
		h.Write(startBuf[:])

		// End percentage (4 bytes as float32 bits)
		var endBuf [4]byte
		binary.BigEndian.PutUint32(endBuf[:], floatBits(r.EndPct))
		h.Write(endBuf[:])

		// Delta sign (1 byte)
		h.Write([]byte{byte(r.DeltaSign)})

		// Byte count (4 bytes)
		var byteBuf [4]byte
		binary.BigEndian.PutUint32(byteBuf[:], uint32(r.ByteCount))
		h.Write(byteBuf[:])
	}

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// floatBits converts a float32 to its IEEE 754 bit representation.
func floatBits(f float32) uint32 {
	return math.Float32bits(f)
}
