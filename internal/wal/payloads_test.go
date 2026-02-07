// Package wal tests for payload serialization/deserialization.
package wal

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// KeystrokeBatchPayload Tests
// =============================================================================

func TestKeystrokeBatchPayload_Serialize_Deserialize(t *testing.T) {
	tests := []struct {
		name    string
		payload KeystrokeBatchPayload
	}{
		{
			name: "zero values",
			payload: KeystrokeBatchPayload{
				StartSequence: 0,
				EndSequence:   0,
				Count:         0,
				StartTime:     0,
				EndTime:       0,
				DocumentHash:  [32]byte{},
				ZoneHistogram: [8]uint16{},
			},
		},
		{
			name: "typical values",
			payload: KeystrokeBatchPayload{
				StartSequence: 100,
				EndSequence:   150,
				Count:         51,
				StartTime:     time.Now().UnixNano(),
				EndTime:       time.Now().UnixNano() + int64(time.Second),
				DocumentHash:  sha256.Sum256([]byte("document content")),
				ZoneHistogram: [8]uint16{10, 20, 30, 5, 15, 25, 8, 12},
			},
		},
		{
			name: "max values",
			payload: KeystrokeBatchPayload{
				StartSequence: ^uint64(0),
				EndSequence:   ^uint64(0),
				Count:         ^uint32(0),
				StartTime:     ^int64(0) >> 1, // Max positive int64
				EndTime:       ^int64(0) >> 1,
				DocumentHash:  [32]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
				ZoneHistogram: [8]uint16{65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535},
			},
		},
		{
			name: "negative timestamps",
			payload: KeystrokeBatchPayload{
				StartSequence: 42,
				EndSequence:   84,
				Count:         43,
				StartTime:     -1000000000, // Before Unix epoch
				EndTime:       -500000000,
				DocumentHash:  sha256.Sum256([]byte("old doc")),
				ZoneHistogram: [8]uint16{1, 2, 3, 4, 5, 6, 7, 8},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize
			data := tt.payload.Serialize()
			require.NotEmpty(t, data)
			assert.Equal(t, 8+8+4+8+8+32+16, len(data))

			// Deserialize
			result, err := DeserializeKeystrokeBatch(data)
			require.NoError(t, err)

			// Verify
			assert.Equal(t, tt.payload.StartSequence, result.StartSequence)
			assert.Equal(t, tt.payload.EndSequence, result.EndSequence)
			assert.Equal(t, tt.payload.Count, result.Count)
			assert.Equal(t, tt.payload.StartTime, result.StartTime)
			assert.Equal(t, tt.payload.EndTime, result.EndTime)
			assert.Equal(t, tt.payload.DocumentHash, result.DocumentHash)
			assert.Equal(t, tt.payload.ZoneHistogram, result.ZoneHistogram)
		})
	}
}

func TestKeystrokeBatchPayload_Deserialize_TooShort(t *testing.T) {
	shortData := make([]byte, 50) // Too short
	_, err := DeserializeKeystrokeBatch(shortData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestKeystrokeBatchPayload_ExtraData(t *testing.T) {
	payload := KeystrokeBatchPayload{
		StartSequence: 1,
		EndSequence:   10,
		Count:         10,
		StartTime:     time.Now().UnixNano(),
		EndTime:       time.Now().UnixNano(),
		DocumentHash:  sha256.Sum256([]byte("test")),
		ZoneHistogram: [8]uint16{1, 2, 3, 4, 5, 6, 7, 8},
	}

	data := payload.Serialize()
	// Append extra data (should be ignored)
	dataWithExtra := append(data, []byte("extra garbage data")...)

	result, err := DeserializeKeystrokeBatch(dataWithExtra)
	require.NoError(t, err)
	assert.Equal(t, payload.StartSequence, result.StartSequence)
}

// =============================================================================
// DocumentHashPayload Tests
// =============================================================================

func TestDocumentHashPayload_Serialize_Deserialize(t *testing.T) {
	tests := []struct {
		name    string
		payload DocumentHashPayload
	}{
		{
			name: "zero values",
			payload: DocumentHashPayload{
				Hash:    [32]byte{},
				Size:    0,
				ModTime: 0,
			},
		},
		{
			name: "typical values",
			payload: DocumentHashPayload{
				Hash:    sha256.Sum256([]byte("document content here")),
				Size:    1024 * 1024, // 1MB
				ModTime: time.Now().UnixNano(),
			},
		},
		{
			name: "large file",
			payload: DocumentHashPayload{
				Hash:    sha256.Sum256([]byte("large document")),
				Size:    10 * 1024 * 1024 * 1024, // 10GB
				ModTime: time.Now().UnixNano(),
			},
		},
		{
			name: "max values",
			payload: DocumentHashPayload{
				Hash:    [32]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
				Size:    ^uint64(0),
				ModTime: ^int64(0) >> 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.payload.Serialize()
			require.NotEmpty(t, data)
			assert.Equal(t, 32+8+8, len(data))

			result, err := DeserializeDocumentHash(data)
			require.NoError(t, err)

			assert.Equal(t, tt.payload.Hash, result.Hash)
			assert.Equal(t, tt.payload.Size, result.Size)
			assert.Equal(t, tt.payload.ModTime, result.ModTime)
		})
	}
}

func TestDocumentHashPayload_Deserialize_TooShort(t *testing.T) {
	shortData := make([]byte, 40) // Too short
	_, err := DeserializeDocumentHash(shortData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// =============================================================================
// JitterSamplePayload Tests
// =============================================================================

func TestJitterSamplePayload_Serialize_Deserialize(t *testing.T) {
	tests := []struct {
		name    string
		payload JitterSamplePayload
	}{
		{
			name: "zero values",
			payload: JitterSamplePayload{
				Ordinal:        0,
				KeystrokeCount: 0,
				DocumentHash:   [32]byte{},
				ZoneTransition: 0,
				IntervalBucket: 0,
				JitterMicros:   0,
				SampleHash:     [32]byte{},
			},
		},
		{
			name: "typical values",
			payload: JitterSamplePayload{
				Ordinal:        12345,
				KeystrokeCount: 67890,
				DocumentHash:   sha256.Sum256([]byte("document")),
				ZoneTransition: 5,
				IntervalBucket: 3,
				JitterMicros:   150000,
				SampleHash:     sha256.Sum256([]byte("sample")),
			},
		},
		{
			name: "max values",
			payload: JitterSamplePayload{
				Ordinal:        ^uint64(0),
				KeystrokeCount: ^uint64(0),
				DocumentHash:   [32]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
				ZoneTransition: 255,
				IntervalBucket: 255,
				JitterMicros:   ^uint32(0),
				SampleHash:     [32]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			},
		},
		{
			name: "all zone transitions",
			payload: JitterSamplePayload{
				Ordinal:        100,
				KeystrokeCount: 200,
				DocumentHash:   sha256.Sum256([]byte("doc")),
				ZoneTransition: 7, // All zones
				IntervalBucket: 15,
				JitterMicros:   500,
				SampleHash:     sha256.Sum256([]byte("hash")),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.payload.Serialize()
			require.NotEmpty(t, data)
			assert.Equal(t, 8+8+32+1+1+4+32, len(data))

			result, err := DeserializeJitterSample(data)
			require.NoError(t, err)

			assert.Equal(t, tt.payload.Ordinal, result.Ordinal)
			assert.Equal(t, tt.payload.KeystrokeCount, result.KeystrokeCount)
			assert.Equal(t, tt.payload.DocumentHash, result.DocumentHash)
			assert.Equal(t, tt.payload.ZoneTransition, result.ZoneTransition)
			assert.Equal(t, tt.payload.IntervalBucket, result.IntervalBucket)
			assert.Equal(t, tt.payload.JitterMicros, result.JitterMicros)
			assert.Equal(t, tt.payload.SampleHash, result.SampleHash)
		})
	}
}

func TestJitterSamplePayload_Deserialize_TooShort(t *testing.T) {
	shortData := make([]byte, 50) // Too short
	_, err := DeserializeJitterSample(shortData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// =============================================================================
// CheckpointPayload Tests
// =============================================================================

func TestCheckpointPayload_Serialize_Deserialize(t *testing.T) {
	tests := []struct {
		name    string
		payload CheckpointPayload
	}{
		{
			name: "zero values",
			payload: CheckpointPayload{
				MMRIndex:       0,
				CheckpointHash: [32]byte{},
				WALSequence:    0,
				Timestamp:      0,
			},
		},
		{
			name: "typical values",
			payload: CheckpointPayload{
				MMRIndex:       12345,
				CheckpointHash: sha256.Sum256([]byte("checkpoint data")),
				WALSequence:    67890,
				Timestamp:      time.Now().UnixNano(),
			},
		},
		{
			name: "max values",
			payload: CheckpointPayload{
				MMRIndex:       ^uint64(0),
				CheckpointHash: [32]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
				WALSequence:    ^uint64(0),
				Timestamp:      ^int64(0) >> 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.payload.Serialize()
			require.NotEmpty(t, data)
			assert.Equal(t, 8+32+8+8, len(data))

			result, err := DeserializeCheckpoint(data)
			require.NoError(t, err)

			assert.Equal(t, tt.payload.MMRIndex, result.MMRIndex)
			assert.Equal(t, tt.payload.CheckpointHash, result.CheckpointHash)
			assert.Equal(t, tt.payload.WALSequence, result.WALSequence)
			assert.Equal(t, tt.payload.Timestamp, result.Timestamp)
		})
	}
}

func TestCheckpointPayload_Deserialize_TooShort(t *testing.T) {
	shortData := make([]byte, 30) // Too short
	_, err := DeserializeCheckpoint(shortData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// =============================================================================
// SessionStartPayload Tests
// =============================================================================

func TestSessionStartPayload_Serialize_Deserialize(t *testing.T) {
	tests := []struct {
		name    string
		payload SessionStartPayload
	}{
		{
			name: "empty path",
			payload: SessionStartPayload{
				SessionID:    sha256.Sum256([]byte("session1")),
				DocumentPath: "",
				DocumentHash: sha256.Sum256([]byte("doc")),
				StartTime:    time.Now().UnixNano(),
			},
		},
		{
			name: "typical path",
			payload: SessionStartPayload{
				SessionID:    sha256.Sum256([]byte("session2")),
				DocumentPath: "/Users/test/Documents/important.txt",
				DocumentHash: sha256.Sum256([]byte("content")),
				StartTime:    time.Now().UnixNano(),
			},
		},
		{
			name: "long path",
			payload: SessionStartPayload{
				SessionID:    sha256.Sum256([]byte("session3")),
				DocumentPath: "/very/long/path/" + string(bytes.Repeat([]byte("a"), 500)) + "/document.txt",
				DocumentHash: sha256.Sum256([]byte("long path doc")),
				StartTime:    time.Now().UnixNano(),
			},
		},
		{
			name: "unicode path",
			payload: SessionStartPayload{
				SessionID:    sha256.Sum256([]byte("session4")),
				DocumentPath: "/Users/test/Documents/файл.txt", // Russian
				DocumentHash: sha256.Sum256([]byte("unicode doc")),
				StartTime:    time.Now().UnixNano(),
			},
		},
		{
			name: "path with special characters",
			payload: SessionStartPayload{
				SessionID:    sha256.Sum256([]byte("session5")),
				DocumentPath: "/path/with spaces/and-dashes/under_scores/file.name.ext",
				DocumentHash: sha256.Sum256([]byte("special doc")),
				StartTime:    time.Now().UnixNano(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.payload.Serialize()
			require.NotEmpty(t, data)

			result, err := DeserializeSessionStart(data)
			require.NoError(t, err)

			assert.Equal(t, tt.payload.SessionID, result.SessionID)
			assert.Equal(t, tt.payload.DocumentPath, result.DocumentPath)
			assert.Equal(t, tt.payload.DocumentHash, result.DocumentHash)
			assert.Equal(t, tt.payload.StartTime, result.StartTime)
		})
	}
}

func TestSessionStartPayload_Deserialize_TooShort(t *testing.T) {
	// Less than minimum header (32 + 4)
	shortData := make([]byte, 30)
	_, err := DeserializeSessionStart(shortData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestSessionStartPayload_Deserialize_Truncated(t *testing.T) {
	// Header claims longer path than provided
	payload := SessionStartPayload{
		SessionID:    sha256.Sum256([]byte("session")),
		DocumentPath: "/very/long/path/to/document.txt",
		DocumentHash: sha256.Sum256([]byte("doc")),
		StartTime:    time.Now().UnixNano(),
	}
	data := payload.Serialize()

	// Truncate the data
	truncatedData := data[:len(data)-20]

	_, err := DeserializeSessionStart(truncatedData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "truncated")
}

// =============================================================================
// SessionEndPayload Tests
// =============================================================================

func TestSessionEndPayload_Serialize_Deserialize(t *testing.T) {
	tests := []struct {
		name    string
		payload SessionEndPayload
	}{
		{
			name: "clean session",
			payload: SessionEndPayload{
				SessionID:       sha256.Sum256([]byte("session1")),
				EndTime:         time.Now().UnixNano(),
				TotalKeystrokes: 10000,
				TotalSamples:    500,
				Clean:           true,
			},
		},
		{
			name: "recovered session",
			payload: SessionEndPayload{
				SessionID:       sha256.Sum256([]byte("session2")),
				EndTime:         time.Now().UnixNano(),
				TotalKeystrokes: 5000,
				TotalSamples:    250,
				Clean:           false,
			},
		},
		{
			name: "zero counts",
			payload: SessionEndPayload{
				SessionID:       sha256.Sum256([]byte("session3")),
				EndTime:         time.Now().UnixNano(),
				TotalKeystrokes: 0,
				TotalSamples:    0,
				Clean:           true,
			},
		},
		{
			name: "max values",
			payload: SessionEndPayload{
				SessionID:       [32]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
				EndTime:         ^int64(0) >> 1,
				TotalKeystrokes: ^uint64(0),
				TotalSamples:    ^uint64(0),
				Clean:           true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.payload.Serialize()
			require.NotEmpty(t, data)
			assert.Equal(t, 32+8+8+8+1, len(data))

			result, err := DeserializeSessionEnd(data)
			require.NoError(t, err)

			assert.Equal(t, tt.payload.SessionID, result.SessionID)
			assert.Equal(t, tt.payload.EndTime, result.EndTime)
			assert.Equal(t, tt.payload.TotalKeystrokes, result.TotalKeystrokes)
			assert.Equal(t, tt.payload.TotalSamples, result.TotalSamples)
			assert.Equal(t, tt.payload.Clean, result.Clean)
		})
	}
}

func TestSessionEndPayload_Deserialize_TooShort(t *testing.T) {
	shortData := make([]byte, 50) // Too short
	_, err := DeserializeSessionEnd(shortData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestSessionEndPayload_CleanFlag(t *testing.T) {
	// Test that Clean flag is correctly serialized
	cleanPayload := SessionEndPayload{
		SessionID:       sha256.Sum256([]byte("clean")),
		EndTime:         time.Now().UnixNano(),
		TotalKeystrokes: 100,
		TotalSamples:    10,
		Clean:           true,
	}

	uncleanPayload := SessionEndPayload{
		SessionID:       sha256.Sum256([]byte("unclean")),
		EndTime:         time.Now().UnixNano(),
		TotalKeystrokes: 100,
		TotalSamples:    10,
		Clean:           false,
	}

	cleanData := cleanPayload.Serialize()
	uncleanData := uncleanPayload.Serialize()

	// Last byte should differ
	assert.Equal(t, byte(1), cleanData[len(cleanData)-1])
	assert.Equal(t, byte(0), uncleanData[len(uncleanData)-1])

	cleanResult, _ := DeserializeSessionEnd(cleanData)
	uncleanResult, _ := DeserializeSessionEnd(uncleanData)

	assert.True(t, cleanResult.Clean)
	assert.False(t, uncleanResult.Clean)
}

// =============================================================================
// HeartbeatPayload Tests
// =============================================================================

func TestHeartbeatPayload_Serialize_Deserialize(t *testing.T) {
	tests := []struct {
		name    string
		payload HeartbeatPayload
	}{
		{
			name: "zero values",
			payload: HeartbeatPayload{
				Timestamp:       0,
				KeystrokesSince: 0,
				SamplesSince:    0,
			},
		},
		{
			name: "typical values",
			payload: HeartbeatPayload{
				Timestamp:       time.Now().UnixNano(),
				KeystrokesSince: 150,
				SamplesSince:    8,
			},
		},
		{
			name: "max values",
			payload: HeartbeatPayload{
				Timestamp:       ^int64(0) >> 1,
				KeystrokesSince: ^uint64(0),
				SamplesSince:    ^uint64(0),
			},
		},
		{
			name: "negative timestamp",
			payload: HeartbeatPayload{
				Timestamp:       -time.Now().UnixNano(),
				KeystrokesSince: 100,
				SamplesSince:    5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.payload.Serialize()
			require.NotEmpty(t, data)
			assert.Equal(t, 8+8+8, len(data))

			result, err := DeserializeHeartbeat(data)
			require.NoError(t, err)

			assert.Equal(t, tt.payload.Timestamp, result.Timestamp)
			assert.Equal(t, tt.payload.KeystrokesSince, result.KeystrokesSince)
			assert.Equal(t, tt.payload.SamplesSince, result.SamplesSince)
		})
	}
}

func TestHeartbeatPayload_Deserialize_TooShort(t *testing.T) {
	shortData := make([]byte, 20) // Too short
	_, err := DeserializeHeartbeat(shortData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// =============================================================================
// Table-Driven Payload Round-Trip Tests
// =============================================================================

func TestPayloadRoundTrip_AllTypes(t *testing.T) {
	// Generate random hash for testing
	randomHash := func() [32]byte {
		var h [32]byte
		rand.Read(h[:])
		return h
	}

	t.Run("KeystrokeBatch", func(t *testing.T) {
		cases := []KeystrokeBatchPayload{
			{0, 0, 0, 0, 0, [32]byte{}, [8]uint16{}},
			{1, 100, 100, time.Now().UnixNano(), time.Now().UnixNano(), randomHash(), [8]uint16{1, 2, 3, 4, 5, 6, 7, 8}},
			{^uint64(0), ^uint64(0), ^uint32(0), ^int64(0) >> 1, ^int64(0) >> 1, randomHash(), [8]uint16{65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535}},
		}

		for i, c := range cases {
			data := c.Serialize()
			result, err := DeserializeKeystrokeBatch(data)
			require.NoError(t, err, "case %d", i)
			assert.Equal(t, c, *result, "case %d", i)
		}
	})

	t.Run("DocumentHash", func(t *testing.T) {
		cases := []DocumentHashPayload{
			{[32]byte{}, 0, 0},
			{randomHash(), 1024 * 1024, time.Now().UnixNano()},
			{randomHash(), ^uint64(0), ^int64(0) >> 1},
		}

		for i, c := range cases {
			data := c.Serialize()
			result, err := DeserializeDocumentHash(data)
			require.NoError(t, err, "case %d", i)
			assert.Equal(t, c, *result, "case %d", i)
		}
	})

	t.Run("JitterSample", func(t *testing.T) {
		cases := []JitterSamplePayload{
			{0, 0, [32]byte{}, 0, 0, 0, [32]byte{}},
			{12345, 67890, randomHash(), 5, 10, 150000, randomHash()},
			{^uint64(0), ^uint64(0), randomHash(), 255, 255, ^uint32(0), randomHash()},
		}

		for i, c := range cases {
			data := c.Serialize()
			result, err := DeserializeJitterSample(data)
			require.NoError(t, err, "case %d", i)
			assert.Equal(t, c, *result, "case %d", i)
		}
	})

	t.Run("Checkpoint", func(t *testing.T) {
		cases := []CheckpointPayload{
			{0, [32]byte{}, 0, 0},
			{12345, randomHash(), 67890, time.Now().UnixNano()},
			{^uint64(0), randomHash(), ^uint64(0), ^int64(0) >> 1},
		}

		for i, c := range cases {
			data := c.Serialize()
			result, err := DeserializeCheckpoint(data)
			require.NoError(t, err, "case %d", i)
			assert.Equal(t, c, *result, "case %d", i)
		}
	})

	t.Run("SessionStart", func(t *testing.T) {
		cases := []SessionStartPayload{
			{randomHash(), "", randomHash(), 0},
			{randomHash(), "/path/to/doc.txt", randomHash(), time.Now().UnixNano()},
			{randomHash(), string(bytes.Repeat([]byte("a"), 1000)), randomHash(), ^int64(0) >> 1},
		}

		for i, c := range cases {
			data := c.Serialize()
			result, err := DeserializeSessionStart(data)
			require.NoError(t, err, "case %d", i)
			assert.Equal(t, c, *result, "case %d", i)
		}
	})

	t.Run("SessionEnd", func(t *testing.T) {
		cases := []SessionEndPayload{
			{[32]byte{}, 0, 0, 0, false},
			{randomHash(), time.Now().UnixNano(), 10000, 500, true},
			{randomHash(), ^int64(0) >> 1, ^uint64(0), ^uint64(0), false},
		}

		for i, c := range cases {
			data := c.Serialize()
			result, err := DeserializeSessionEnd(data)
			require.NoError(t, err, "case %d", i)
			assert.Equal(t, c, *result, "case %d", i)
		}
	})

	t.Run("Heartbeat", func(t *testing.T) {
		cases := []HeartbeatPayload{
			{0, 0, 0},
			{time.Now().UnixNano(), 150, 8},
			{^int64(0) >> 1, ^uint64(0), ^uint64(0)},
		}

		for i, c := range cases {
			data := c.Serialize()
			result, err := DeserializeHeartbeat(data)
			require.NoError(t, err, "case %d", i)
			assert.Equal(t, c, *result, "case %d", i)
		}
	})
}

// =============================================================================
// RecoveryInfo Tests
// =============================================================================

func TestRecoveryInfo_Fields(t *testing.T) {
	info := RecoveryInfo{
		RecoveredAt:         time.Now(),
		EntriesRecovered:    100,
		LastCheckpointSeq:   50,
		KeystrokesRecovered: 5000,
		SamplesRecovered:    250,
		DataLossEstimate:    "< 100ms",
		CorruptedEntries:    2,
		TamperedEntries:     0,
	}

	assert.Equal(t, uint64(100), info.EntriesRecovered)
	assert.Equal(t, uint64(50), info.LastCheckpointSeq)
	assert.Equal(t, uint64(5000), info.KeystrokesRecovered)
	assert.Equal(t, uint64(250), info.SamplesRecovered)
	assert.Equal(t, "< 100ms", info.DataLossEstimate)
	assert.Equal(t, uint64(2), info.CorruptedEntries)
	assert.Equal(t, uint64(0), info.TamperedEntries)
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkKeystrokeBatchPayload_Serialize(b *testing.B) {
	payload := KeystrokeBatchPayload{
		StartSequence: 100,
		EndSequence:   200,
		Count:         101,
		StartTime:     time.Now().UnixNano(),
		EndTime:       time.Now().UnixNano(),
		DocumentHash:  sha256.Sum256([]byte("document")),
		ZoneHistogram: [8]uint16{10, 20, 30, 40, 50, 60, 70, 80},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = payload.Serialize()
	}
}

func BenchmarkKeystrokeBatchPayload_Deserialize(b *testing.B) {
	payload := KeystrokeBatchPayload{
		StartSequence: 100,
		EndSequence:   200,
		Count:         101,
		StartTime:     time.Now().UnixNano(),
		EndTime:       time.Now().UnixNano(),
		DocumentHash:  sha256.Sum256([]byte("document")),
		ZoneHistogram: [8]uint16{10, 20, 30, 40, 50, 60, 70, 80},
	}
	data := payload.Serialize()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeserializeKeystrokeBatch(data)
	}
}

func BenchmarkDocumentHashPayload_Serialize(b *testing.B) {
	payload := DocumentHashPayload{
		Hash:    sha256.Sum256([]byte("document content")),
		Size:    1024 * 1024,
		ModTime: time.Now().UnixNano(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = payload.Serialize()
	}
}

func BenchmarkDocumentHashPayload_Deserialize(b *testing.B) {
	payload := DocumentHashPayload{
		Hash:    sha256.Sum256([]byte("document content")),
		Size:    1024 * 1024,
		ModTime: time.Now().UnixNano(),
	}
	data := payload.Serialize()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeserializeDocumentHash(data)
	}
}

func BenchmarkJitterSamplePayload_Serialize(b *testing.B) {
	payload := JitterSamplePayload{
		Ordinal:        12345,
		KeystrokeCount: 67890,
		DocumentHash:   sha256.Sum256([]byte("document")),
		ZoneTransition: 5,
		IntervalBucket: 3,
		JitterMicros:   150000,
		SampleHash:     sha256.Sum256([]byte("sample")),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = payload.Serialize()
	}
}

func BenchmarkJitterSamplePayload_Deserialize(b *testing.B) {
	payload := JitterSamplePayload{
		Ordinal:        12345,
		KeystrokeCount: 67890,
		DocumentHash:   sha256.Sum256([]byte("document")),
		ZoneTransition: 5,
		IntervalBucket: 3,
		JitterMicros:   150000,
		SampleHash:     sha256.Sum256([]byte("sample")),
	}
	data := payload.Serialize()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeserializeJitterSample(data)
	}
}

func BenchmarkSessionStartPayload_Serialize(b *testing.B) {
	payload := SessionStartPayload{
		SessionID:    sha256.Sum256([]byte("session")),
		DocumentPath: "/Users/test/Documents/important.txt",
		DocumentHash: sha256.Sum256([]byte("content")),
		StartTime:    time.Now().UnixNano(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = payload.Serialize()
	}
}

func BenchmarkSessionStartPayload_Deserialize(b *testing.B) {
	payload := SessionStartPayload{
		SessionID:    sha256.Sum256([]byte("session")),
		DocumentPath: "/Users/test/Documents/important.txt",
		DocumentHash: sha256.Sum256([]byte("content")),
		StartTime:    time.Now().UnixNano(),
	}
	data := payload.Serialize()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeserializeSessionStart(data)
	}
}

func BenchmarkHeartbeatPayload_Serialize(b *testing.B) {
	payload := HeartbeatPayload{
		Timestamp:       time.Now().UnixNano(),
		KeystrokesSince: 150,
		SamplesSince:    8,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = payload.Serialize()
	}
}

func BenchmarkHeartbeatPayload_Deserialize(b *testing.B) {
	payload := HeartbeatPayload{
		Timestamp:       time.Now().UnixNano(),
		KeystrokesSince: 150,
		SamplesSince:    8,
	}
	data := payload.Serialize()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeserializeHeartbeat(data)
	}
}

// =============================================================================
// Integration Tests: Payload with WAL Entry
// =============================================================================

func TestPayload_WALIntegration(t *testing.T) {
	// Test that payloads work correctly when used with WAL entries
	t.Run("KeystrokeBatch in WAL", func(t *testing.T) {
		w, _, cleanup := createTestWAL(t)
		defer cleanup()

		payload := KeystrokeBatchPayload{
			StartSequence: 1,
			EndSequence:   100,
			Count:         100,
			StartTime:     time.Now().UnixNano(),
			EndTime:       time.Now().UnixNano(),
			DocumentHash:  sha256.Sum256([]byte("doc")),
			ZoneHistogram: [8]uint16{1, 2, 3, 4, 5, 6, 7, 8},
		}

		err := w.Append(EntryKeystrokeBatch, payload.Serialize())
		require.NoError(t, err)

		entries, err := w.ReadAll()
		require.NoError(t, err)
		require.Len(t, entries, 1)

		recovered, err := DeserializeKeystrokeBatch(entries[0].Payload)
		require.NoError(t, err)
		assert.Equal(t, payload, *recovered)
	})

	t.Run("DocumentHash in WAL", func(t *testing.T) {
		w, _, cleanup := createTestWAL(t)
		defer cleanup()

		payload := DocumentHashPayload{
			Hash:    sha256.Sum256([]byte("document content")),
			Size:    1024,
			ModTime: time.Now().UnixNano(),
		}

		err := w.Append(EntryDocumentHash, payload.Serialize())
		require.NoError(t, err)

		entries, err := w.ReadAll()
		require.NoError(t, err)
		require.Len(t, entries, 1)

		recovered, err := DeserializeDocumentHash(entries[0].Payload)
		require.NoError(t, err)
		assert.Equal(t, payload, *recovered)
	})

	t.Run("JitterSample in WAL", func(t *testing.T) {
		w, _, cleanup := createTestWAL(t)
		defer cleanup()

		payload := JitterSamplePayload{
			Ordinal:        100,
			KeystrokeCount: 500,
			DocumentHash:   sha256.Sum256([]byte("doc")),
			ZoneTransition: 3,
			IntervalBucket: 7,
			JitterMicros:   12345,
			SampleHash:     sha256.Sum256([]byte("sample")),
		}

		err := w.Append(EntryJitterSample, payload.Serialize())
		require.NoError(t, err)

		entries, err := w.ReadAll()
		require.NoError(t, err)
		require.Len(t, entries, 1)

		recovered, err := DeserializeJitterSample(entries[0].Payload)
		require.NoError(t, err)
		assert.Equal(t, payload, *recovered)
	})

	t.Run("Checkpoint in WAL", func(t *testing.T) {
		w, _, cleanup := createTestWAL(t)
		defer cleanup()

		payload := CheckpointPayload{
			MMRIndex:       42,
			CheckpointHash: sha256.Sum256([]byte("checkpoint")),
			WALSequence:    100,
			Timestamp:      time.Now().UnixNano(),
		}

		err := w.Append(EntryCheckpoint, payload.Serialize())
		require.NoError(t, err)

		entries, err := w.ReadAll()
		require.NoError(t, err)
		require.Len(t, entries, 1)

		recovered, err := DeserializeCheckpoint(entries[0].Payload)
		require.NoError(t, err)
		assert.Equal(t, payload, *recovered)
	})

	t.Run("SessionStart in WAL", func(t *testing.T) {
		w, _, cleanup := createTestWAL(t)
		defer cleanup()

		payload := SessionStartPayload{
			SessionID:    sha256.Sum256([]byte("session")),
			DocumentPath: "/path/to/document.txt",
			DocumentHash: sha256.Sum256([]byte("doc content")),
			StartTime:    time.Now().UnixNano(),
		}

		err := w.Append(EntrySessionStart, payload.Serialize())
		require.NoError(t, err)

		entries, err := w.ReadAll()
		require.NoError(t, err)
		require.Len(t, entries, 1)

		recovered, err := DeserializeSessionStart(entries[0].Payload)
		require.NoError(t, err)
		assert.Equal(t, payload, *recovered)
	})

	t.Run("SessionEnd in WAL", func(t *testing.T) {
		w, _, cleanup := createTestWAL(t)
		defer cleanup()

		payload := SessionEndPayload{
			SessionID:       sha256.Sum256([]byte("session")),
			EndTime:         time.Now().UnixNano(),
			TotalKeystrokes: 10000,
			TotalSamples:    500,
			Clean:           true,
		}

		err := w.Append(EntrySessionEnd, payload.Serialize())
		require.NoError(t, err)

		entries, err := w.ReadAll()
		require.NoError(t, err)
		require.Len(t, entries, 1)

		recovered, err := DeserializeSessionEnd(entries[0].Payload)
		require.NoError(t, err)
		assert.Equal(t, payload, *recovered)
	})

	t.Run("Heartbeat in WAL", func(t *testing.T) {
		w, _, cleanup := createTestWAL(t)
		defer cleanup()

		payload := HeartbeatPayload{
			Timestamp:       time.Now().UnixNano(),
			KeystrokesSince: 150,
			SamplesSince:    8,
		}

		err := w.Append(EntryHeartbeat, payload.Serialize())
		require.NoError(t, err)

		entries, err := w.ReadAll()
		require.NoError(t, err)
		require.Len(t, entries, 1)

		recovered, err := DeserializeHeartbeat(entries[0].Payload)
		require.NoError(t, err)
		assert.Equal(t, payload, *recovered)
	})
}

func TestPayload_WALRecoveryIntegration(t *testing.T) {
	// Test payloads survive WAL crash recovery
	dir := t.TempDir()
	path := dir + "/test.wal"
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create payloads
	payloads := []struct {
		entryType EntryType
		data      []byte
	}{
		{
			EntryKeystrokeBatch,
			(&KeystrokeBatchPayload{
				StartSequence: 1, EndSequence: 100, Count: 100,
				StartTime: time.Now().UnixNano(), EndTime: time.Now().UnixNano(),
				DocumentHash: sha256.Sum256([]byte("doc")), ZoneHistogram: [8]uint16{1, 2, 3, 4, 5, 6, 7, 8},
			}).Serialize(),
		},
		{
			EntryDocumentHash,
			(&DocumentHashPayload{
				Hash: sha256.Sum256([]byte("content")), Size: 1024, ModTime: time.Now().UnixNano(),
			}).Serialize(),
		},
		{
			EntryHeartbeat,
			(&HeartbeatPayload{
				Timestamp: time.Now().UnixNano(), KeystrokesSince: 50, SamplesSince: 3,
			}).Serialize(),
		},
	}

	// Write to WAL
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	for _, p := range payloads {
		err := w.Append(p.entryType, p.data)
		require.NoError(t, err)
	}
	w.Close()

	// Reopen (simulating recovery)
	w2, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w2.Close()

	entries, err := w2.ReadAll()
	require.NoError(t, err)
	require.Len(t, entries, len(payloads))

	// Verify each payload type can be deserialized
	_, err = DeserializeKeystrokeBatch(entries[0].Payload)
	require.NoError(t, err)

	_, err = DeserializeDocumentHash(entries[1].Payload)
	require.NoError(t, err)

	_, err = DeserializeHeartbeat(entries[2].Payload)
	require.NoError(t, err)
}
