// Package wal provides payload types for WAL entries.
package wal

import (
	"encoding/binary"
	"errors"
	"time"
)

// KeystrokeBatchPayload represents a batch of keystroke events.
type KeystrokeBatchPayload struct {
	StartSequence uint64
	EndSequence   uint64
	Count         uint32
	StartTime     int64
	EndTime       int64
	DocumentHash  [32]byte
	ZoneHistogram [8]uint16 // Counts per zone (privacy-preserving)
}

// Serialize encodes the payload to bytes.
func (p *KeystrokeBatchPayload) Serialize() []byte {
	buf := make([]byte, 8+8+4+8+8+32+16)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:], p.StartSequence)
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], p.EndSequence)
	offset += 8

	binary.BigEndian.PutUint32(buf[offset:], p.Count)
	offset += 4

	binary.BigEndian.PutUint64(buf[offset:], uint64(p.StartTime))
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], uint64(p.EndTime))
	offset += 8

	copy(buf[offset:], p.DocumentHash[:])
	offset += 32

	for i, count := range p.ZoneHistogram {
		binary.BigEndian.PutUint16(buf[offset+i*2:], count)
	}

	return buf
}

// DeserializeKeystrokeBatch decodes a keystroke batch payload.
func DeserializeKeystrokeBatch(data []byte) (*KeystrokeBatchPayload, error) {
	if len(data) < 8+8+4+8+8+32+16 {
		return nil, errors.New("keystroke batch payload too short")
	}

	p := &KeystrokeBatchPayload{}
	offset := 0

	p.StartSequence = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	p.EndSequence = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	p.Count = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	p.StartTime = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	p.EndTime = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	copy(p.DocumentHash[:], data[offset:offset+32])
	offset += 32

	for i := range p.ZoneHistogram {
		p.ZoneHistogram[i] = binary.BigEndian.Uint16(data[offset+i*2:])
	}

	return p, nil
}

// DocumentHashPayload represents a document state snapshot.
type DocumentHashPayload struct {
	Hash    [32]byte
	Size    uint64
	ModTime int64
}

// Serialize encodes the payload to bytes.
func (p *DocumentHashPayload) Serialize() []byte {
	buf := make([]byte, 32+8+8)
	copy(buf[0:32], p.Hash[:])
	binary.BigEndian.PutUint64(buf[32:40], p.Size)
	binary.BigEndian.PutUint64(buf[40:48], uint64(p.ModTime))
	return buf
}

// DeserializeDocumentHash decodes a document hash payload.
func DeserializeDocumentHash(data []byte) (*DocumentHashPayload, error) {
	if len(data) < 32+8+8 {
		return nil, errors.New("document hash payload too short")
	}

	p := &DocumentHashPayload{}
	copy(p.Hash[:], data[0:32])
	p.Size = binary.BigEndian.Uint64(data[32:40])
	p.ModTime = int64(binary.BigEndian.Uint64(data[40:48]))

	return p, nil
}

// JitterSamplePayload represents a jitter seal sample.
type JitterSamplePayload struct {
	Ordinal        uint64
	KeystrokeCount uint64
	DocumentHash   [32]byte
	ZoneTransition uint8
	IntervalBucket uint8
	JitterMicros   uint32
	SampleHash     [32]byte
}

// Serialize encodes the payload to bytes.
func (p *JitterSamplePayload) Serialize() []byte {
	buf := make([]byte, 8+8+32+1+1+4+32)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:], p.Ordinal)
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], p.KeystrokeCount)
	offset += 8

	copy(buf[offset:], p.DocumentHash[:])
	offset += 32

	buf[offset] = p.ZoneTransition
	offset++

	buf[offset] = p.IntervalBucket
	offset++

	binary.BigEndian.PutUint32(buf[offset:], p.JitterMicros)
	offset += 4

	copy(buf[offset:], p.SampleHash[:])

	return buf
}

// DeserializeJitterSample decodes a jitter sample payload.
func DeserializeJitterSample(data []byte) (*JitterSamplePayload, error) {
	if len(data) < 8+8+32+1+1+4+32 {
		return nil, errors.New("jitter sample payload too short")
	}

	p := &JitterSamplePayload{}
	offset := 0

	p.Ordinal = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	p.KeystrokeCount = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	copy(p.DocumentHash[:], data[offset:offset+32])
	offset += 32

	p.ZoneTransition = data[offset]
	offset++

	p.IntervalBucket = data[offset]
	offset++

	p.JitterMicros = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	copy(p.SampleHash[:], data[offset:offset+32])

	return p, nil
}

// CheckpointPayload represents a committed checkpoint record.
type CheckpointPayload struct {
	MMRIndex       uint64
	CheckpointHash [32]byte
	WALSequence    uint64
	Timestamp      int64
}

// Serialize encodes the payload to bytes.
func (p *CheckpointPayload) Serialize() []byte {
	buf := make([]byte, 8+32+8+8)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:], p.MMRIndex)
	offset += 8

	copy(buf[offset:], p.CheckpointHash[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:], p.WALSequence)
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], uint64(p.Timestamp))

	return buf
}

// DeserializeCheckpoint decodes a checkpoint payload.
func DeserializeCheckpoint(data []byte) (*CheckpointPayload, error) {
	if len(data) < 8+32+8+8 {
		return nil, errors.New("checkpoint payload too short")
	}

	p := &CheckpointPayload{}
	offset := 0

	p.MMRIndex = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	copy(p.CheckpointHash[:], data[offset:offset+32])
	offset += 32

	p.WALSequence = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	p.Timestamp = int64(binary.BigEndian.Uint64(data[offset:]))

	return p, nil
}

// SessionStartPayload represents session initialization.
type SessionStartPayload struct {
	SessionID    [32]byte
	DocumentPath string
	DocumentHash [32]byte
	StartTime    int64
}

// Serialize encodes the payload to bytes.
func (p *SessionStartPayload) Serialize() []byte {
	pathBytes := []byte(p.DocumentPath)
	buf := make([]byte, 32+4+len(pathBytes)+32+8)
	offset := 0

	copy(buf[offset:], p.SessionID[:])
	offset += 32

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(pathBytes)))
	offset += 4

	copy(buf[offset:], pathBytes)
	offset += len(pathBytes)

	copy(buf[offset:], p.DocumentHash[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:], uint64(p.StartTime))

	return buf
}

// DeserializeSessionStart decodes a session start payload.
func DeserializeSessionStart(data []byte) (*SessionStartPayload, error) {
	if len(data) < 32+4 {
		return nil, errors.New("session start payload too short")
	}

	p := &SessionStartPayload{}
	offset := 0

	copy(p.SessionID[:], data[offset:offset+32])
	offset += 32

	pathLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if len(data) < offset+int(pathLen)+32+8 {
		return nil, errors.New("session start payload truncated")
	}

	p.DocumentPath = string(data[offset : offset+int(pathLen)])
	offset += int(pathLen)

	copy(p.DocumentHash[:], data[offset:offset+32])
	offset += 32

	p.StartTime = int64(binary.BigEndian.Uint64(data[offset:]))

	return p, nil
}

// SessionEndPayload represents session termination.
type SessionEndPayload struct {
	SessionID      [32]byte
	EndTime        int64
	TotalKeystrokes uint64
	TotalSamples   uint64
	Clean          bool // true if session ended cleanly, false if recovered
}

// Serialize encodes the payload to bytes.
func (p *SessionEndPayload) Serialize() []byte {
	buf := make([]byte, 32+8+8+8+1)
	offset := 0

	copy(buf[offset:], p.SessionID[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:], uint64(p.EndTime))
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], p.TotalKeystrokes)
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], p.TotalSamples)
	offset += 8

	if p.Clean {
		buf[offset] = 1
	}

	return buf
}

// DeserializeSessionEnd decodes a session end payload.
func DeserializeSessionEnd(data []byte) (*SessionEndPayload, error) {
	if len(data) < 32+8+8+8+1 {
		return nil, errors.New("session end payload too short")
	}

	p := &SessionEndPayload{}
	offset := 0

	copy(p.SessionID[:], data[offset:offset+32])
	offset += 32

	p.EndTime = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	p.TotalKeystrokes = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	p.TotalSamples = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	p.Clean = data[offset] == 1

	return p, nil
}

// HeartbeatPayload represents a periodic heartbeat marker.
type HeartbeatPayload struct {
	Timestamp       int64
	KeystrokesSince uint64
	SamplesSince    uint64
}

// Serialize encodes the payload to bytes.
func (p *HeartbeatPayload) Serialize() []byte {
	buf := make([]byte, 8+8+8)
	binary.BigEndian.PutUint64(buf[0:8], uint64(p.Timestamp))
	binary.BigEndian.PutUint64(buf[8:16], p.KeystrokesSince)
	binary.BigEndian.PutUint64(buf[16:24], p.SamplesSince)
	return buf
}

// DeserializeHeartbeat decodes a heartbeat payload.
func DeserializeHeartbeat(data []byte) (*HeartbeatPayload, error) {
	if len(data) < 8+8+8 {
		return nil, errors.New("heartbeat payload too short")
	}

	p := &HeartbeatPayload{}
	p.Timestamp = int64(binary.BigEndian.Uint64(data[0:8]))
	p.KeystrokesSince = binary.BigEndian.Uint64(data[8:16])
	p.SamplesSince = binary.BigEndian.Uint64(data[16:24])

	return p, nil
}

// RecoveryInfo holds information about WAL recovery.
type RecoveryInfo struct {
	RecoveredAt          time.Time
	EntriesRecovered     uint64
	LastCheckpointSeq    uint64
	KeystrokesRecovered  uint64
	SamplesRecovered     uint64
	DataLossEstimate     string // e.g., "< 100ms", "~60s"
	CorruptedEntries     uint64
	TamperedEntries      uint64
}
