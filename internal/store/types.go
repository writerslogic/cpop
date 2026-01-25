// Package store provides SQLite-based event storage for witnessd.
package store

// Event represents a file change event recorded in the MMR.
type Event struct {
	ID          int64
	DeviceID    [16]byte
	MMRIndex    uint64
	MMRLeafHash [32]byte
	TimestampNs int64
	FilePath    string
	ContentHash [32]byte
	FileSize    int64
	SizeDelta   int32
	ContextID   *int64
}

// EditRegion represents a portion of a file that was modified.
type EditRegion struct {
	EventID   int64
	Ordinal   int16
	StartPct  float32
	EndPct    float32
	DeltaSign int8
	ByteCount int32
}

// Context represents an editing session context.
type Context struct {
	ID      int64
	Type    ContextType
	Note    string
	StartNs int64
	EndNs   *int64
}

// ContextType defines the type of editing context.
type ContextType string

const (
	// ContextExternal indicates edits from external sources.
	ContextExternal ContextType = "external"
	// ContextAssisted indicates AI-assisted edits.
	ContextAssisted ContextType = "assisted"
	// ContextReview indicates edits during review.
	ContextReview ContextType = "review"
)

// Device represents a registered device in the system.
type Device struct {
	DeviceID      [16]byte
	CreatedAt     int64
	SigningPubkey [32]byte
	Hostname      string
}

// VerificationEntry stores verification metadata for an MMR leaf.
type VerificationEntry struct {
	MMRIndex     uint64
	LeafHash     [32]byte
	MetadataHash [32]byte
	RegionsRoot  *[32]byte
	VerifiedAt   *int64
}

// Weave represents a cross-device state synchronization record.
type Weave struct {
	ID          int64
	TimestampNs int64
	DeviceRoots map[string]string // hex device ID -> hex root
	WeaveHash   [32]byte
	Signature   []byte
}
