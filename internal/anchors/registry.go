package anchors

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Common errors
var (
	ErrAnchorNotFound     = errors.New("anchor not found")
	ErrAnchorDisabled     = errors.New("anchor is disabled")
	ErrNoAnchorsEnabled   = errors.New("no anchors enabled")
	ErrAllAnchorsFailed   = errors.New("all anchors failed")
	ErrInvalidHash        = errors.New("invalid hash")
	ErrPendingUpgrade     = errors.New("anchor pending upgrade")
	ErrMaxRetriesExceeded = errors.New("maximum retries exceeded")
)

// AnchorStatus represents the status of an anchor operation.
type AnchorStatus string

const (
	StatusPending   AnchorStatus = "pending"
	StatusConfirmed AnchorStatus = "confirmed"
	StatusFailed    AnchorStatus = "failed"
	StatusRetrying  AnchorStatus = "retrying"
	StatusExpired   AnchorStatus = "expired"
)

// AnchorType identifies the type of anchor.
type AnchorType string

const (
	TypeOTS        AnchorType = "ots"        // OpenTimestamps
	TypeRFC3161    AnchorType = "rfc3161"    // RFC 3161 TSA
	TypeDrand      AnchorType = "drand"      // drand beacon
	TypeBlockchain AnchorType = "blockchain" // Blockchain anchoring
)

// Anchor is the common interface for all anchor types.
type Anchor interface {
	// Name returns the anchor identifier.
	Name() string

	// Commit submits a hash for anchoring.
	// Returns serialized proof data.
	Commit(hash []byte) ([]byte, error)

	// Verify verifies a proof against a hash.
	Verify(hash, proof []byte) error
}

// UpgradableAnchor can upgrade pending proofs.
type UpgradableAnchor interface {
	Anchor

	// UpgradeProof attempts to upgrade a pending proof.
	// Returns upgraded proof, whether it's confirmed, and any error.
	UpgradeProof(proof []byte) ([]byte, bool, error)

	// GetPendingCount returns the number of pending proofs.
	GetPendingCount() int
}

// AnchorRecord tracks an anchor submission.
type AnchorRecord struct {
	// Identification
	ID       string     `json:"id"`
	Type     AnchorType `json:"type"`
	Hash     [32]byte   `json:"hash"`

	// Status tracking
	Status       AnchorStatus `json:"status"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	ConfirmedAt  *time.Time   `json:"confirmed_at,omitempty"`

	// Proof data
	Proof    []byte `json:"proof"`
	ProofHex string `json:"proof_hex,omitempty"` // For JSON readability

	// Retry tracking
	Attempts     int       `json:"attempts"`
	LastAttempt  time.Time `json:"last_attempt,omitempty"`
	NextRetry    time.Time `json:"next_retry,omitempty"`
	LastError    string    `json:"last_error,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// RegistryConfig configures the anchor registry.
type RegistryConfig struct {
	// Enabled anchor types
	EnableOTS        bool
	EnableRFC3161    bool
	EnableDrand      bool
	EnableBlockchain bool

	// OTS configuration
	OTSConfig OTSConfig

	// RFC 3161 configuration
	RFC3161Config RFC3161Config

	// drand configuration
	DrandConfig DrandConfig

	// Blockchain configuration
	BlockchainConfig BlockchainConfig

	// Retry configuration
	MaxRetries       int
	RetryBaseDelay   time.Duration
	RetryMaxDelay    time.Duration
	RetryMultiplier  float64

	// Upgrade configuration
	UpgradeInterval  time.Duration
	AutoUpgrade      bool

	// Priority order for verification (first valid wins)
	VerifyPriority []AnchorType
}

// Registry manages multiple anchor types.
type Registry struct {
	mu sync.RWMutex

	// Anchors by type
	anchors map[AnchorType]Anchor

	// Enabled anchors
	enabled map[AnchorType]bool

	// Records by hash
	records map[string][]*AnchorRecord

	// Configuration
	config RegistryConfig

	// Upgrade goroutine control
	upgradeStop chan struct{}
	upgradeWg   sync.WaitGroup
}

// NewRegistry creates a new anchor registry with default configuration.
func NewRegistry() *Registry {
	return NewRegistryWithConfig(RegistryConfig{
		EnableOTS:     true,
		EnableRFC3161: true,
		EnableDrand:   true,
		MaxRetries:    3,
		RetryBaseDelay: 30 * time.Second,
		RetryMaxDelay:  time.Hour,
		RetryMultiplier: 2.0,
		UpgradeInterval: 5 * time.Minute,
		AutoUpgrade:    true,
		VerifyPriority: []AnchorType{TypeOTS, TypeRFC3161, TypeDrand, TypeBlockchain},
	})
}

// NewRegistryWithConfig creates a registry with custom configuration.
func NewRegistryWithConfig(config RegistryConfig) *Registry {
	r := &Registry{
		anchors:     make(map[AnchorType]Anchor),
		enabled:     make(map[AnchorType]bool),
		records:     make(map[string][]*AnchorRecord),
		config:      config,
		upgradeStop: make(chan struct{}),
	}

	// Initialize enabled anchors
	if config.EnableOTS {
		r.anchors[TypeOTS] = NewOTSAnchorWithConfig(config.OTSConfig)
		r.enabled[TypeOTS] = true
	}
	if config.EnableRFC3161 {
		r.anchors[TypeRFC3161] = NewRFC3161AnchorWithConfig(config.RFC3161Config)
		r.enabled[TypeRFC3161] = true
	}
	if config.EnableDrand {
		r.anchors[TypeDrand] = NewDrandAnchorWithConfig(config.DrandConfig)
		r.enabled[TypeDrand] = true
	}
	if config.EnableBlockchain {
		r.anchors[TypeBlockchain] = NewBlockchainAnchorWithConfig(config.BlockchainConfig)
		r.enabled[TypeBlockchain] = true
	}

	// Start auto-upgrade if enabled
	if config.AutoUpgrade {
		r.startUpgradeWorker()
	}

	return r
}

// Close shuts down the registry.
func (r *Registry) Close() {
	close(r.upgradeStop)
	r.upgradeWg.Wait()
}

// startUpgradeWorker starts the background upgrade worker.
func (r *Registry) startUpgradeWorker() {
	r.upgradeWg.Add(1)
	go func() {
		defer r.upgradeWg.Done()
		ticker := time.NewTicker(r.config.UpgradeInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				r.upgradePendingRecords()
			case <-r.upgradeStop:
				return
			}
		}
	}()
}

// upgradePendingRecords attempts to upgrade all pending records.
func (r *Registry) upgradePendingRecords() {
	r.mu.RLock()
	var pending []*AnchorRecord
	for _, records := range r.records {
		for _, record := range records {
			if record.Status == StatusPending {
				pending = append(pending, record)
			}
		}
	}
	r.mu.RUnlock()

	for _, record := range pending {
		r.upgradeRecord(record)
	}
}

// upgradeRecord attempts to upgrade a single record.
func (r *Registry) upgradeRecord(record *AnchorRecord) {
	anchor, ok := r.anchors[record.Type]
	if !ok {
		return
	}

	upgradable, ok := anchor.(UpgradableAnchor)
	if !ok {
		return
	}

	newProof, confirmed, err := upgradable.UpgradeProof(record.Proof)
	if err != nil {
		record.LastError = err.Error()
		record.UpdatedAt = time.Now()
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	record.Proof = newProof
	record.UpdatedAt = time.Now()
	record.Attempts++

	if confirmed {
		record.Status = StatusConfirmed
		now := time.Now()
		record.ConfirmedAt = &now
	}
}

// Enable enables an anchor type.
func (r *Registry) Enable(anchorType AnchorType) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.anchors[anchorType]; !ok {
		return fmt.Errorf("%w: %s", ErrAnchorNotFound, anchorType)
	}
	r.enabled[anchorType] = true
	return nil
}

// Disable disables an anchor type.
func (r *Registry) Disable(anchorType AnchorType) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled[anchorType] = false
}

// IsEnabled checks if an anchor type is enabled.
func (r *Registry) IsEnabled(anchorType AnchorType) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled[anchorType]
}

// EnabledTypes returns all enabled anchor types.
func (r *Registry) EnabledTypes() []AnchorType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]AnchorType, 0)
	for t, enabled := range r.enabled {
		if enabled {
			types = append(types, t)
		}
	}
	return types
}

// Commit submits a hash to all enabled anchors.
// Returns records for all successful submissions.
func (r *Registry) Commit(hash []byte) ([]*AnchorRecord, error) {
	if len(hash) != 32 {
		return nil, ErrInvalidHash
	}

	r.mu.RLock()
	enabledAnchors := make(map[AnchorType]Anchor)
	for t, a := range r.anchors {
		if r.enabled[t] {
			enabledAnchors[t] = a
		}
	}
	r.mu.RUnlock()

	if len(enabledAnchors) == 0 {
		return nil, ErrNoAnchorsEnabled
	}

	var h [32]byte
	copy(h[:], hash)
	hashKey := hex.EncodeToString(hash)

	// Submit to all anchors concurrently
	type result struct {
		anchorType AnchorType
		proof      []byte
		err        error
	}
	results := make(chan result, len(enabledAnchors))

	for t, a := range enabledAnchors {
		go func(anchorType AnchorType, anchor Anchor) {
			proof, err := anchor.Commit(hash)
			results <- result{anchorType, proof, err}
		}(t, a)
	}

	// Collect results
	var records []*AnchorRecord
	var lastErr error

	for i := 0; i < len(enabledAnchors); i++ {
		res := <-results
		if res.err != nil {
			lastErr = res.err
			continue
		}

		record := &AnchorRecord{
			ID:        generateID(),
			Type:      res.anchorType,
			Hash:      h,
			Status:    StatusPending,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Proof:     res.proof,
			Attempts:  1,
		}

		// Check if already confirmed (e.g., RFC 3161 is immediately confirmed)
		if err := r.anchors[res.anchorType].Verify(hash, res.proof); err == nil {
			// For non-upgradable anchors, mark as confirmed
			if _, ok := r.anchors[res.anchorType].(UpgradableAnchor); !ok {
				record.Status = StatusConfirmed
				now := time.Now()
				record.ConfirmedAt = &now
			}
		}

		records = append(records, record)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("%w: %v", ErrAllAnchorsFailed, lastErr)
	}

	// Store records
	r.mu.Lock()
	r.records[hashKey] = append(r.records[hashKey], records...)
	r.mu.Unlock()

	return records, nil
}

// CommitWithRetry commits with automatic retry on failure.
func (r *Registry) CommitWithRetry(ctx context.Context, hash []byte) ([]*AnchorRecord, error) {
	var records []*AnchorRecord
	var lastErr error
	delay := r.config.RetryBaseDelay

	for attempt := 0; attempt <= r.config.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return records, ctx.Err()
			case <-time.After(delay):
			}
			delay = time.Duration(float64(delay) * r.config.RetryMultiplier)
			if delay > r.config.RetryMaxDelay {
				delay = r.config.RetryMaxDelay
			}
		}

		newRecords, err := r.Commit(hash)
		if err == nil || len(newRecords) > 0 {
			records = append(records, newRecords...)
			// If we got at least one anchor, consider it a success
			if len(records) > 0 {
				return records, nil
			}
		}
		lastErr = err
	}

	if len(records) > 0 {
		return records, nil
	}
	return nil, fmt.Errorf("%w: %v", ErrMaxRetriesExceeded, lastErr)
}

// CommitSingle commits to a single anchor type.
func (r *Registry) CommitSingle(anchorType AnchorType, hash []byte) (*AnchorRecord, error) {
	if len(hash) != 32 {
		return nil, ErrInvalidHash
	}

	r.mu.RLock()
	anchor, ok := r.anchors[anchorType]
	enabled := r.enabled[anchorType]
	r.mu.RUnlock()

	if !ok {
		return nil, ErrAnchorNotFound
	}
	if !enabled {
		return nil, ErrAnchorDisabled
	}

	proof, err := anchor.Commit(hash)
	if err != nil {
		return nil, err
	}

	var h [32]byte
	copy(h[:], hash)

	record := &AnchorRecord{
		ID:        generateID(),
		Type:      anchorType,
		Hash:      h,
		Status:    StatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Proof:     proof,
		Attempts:  1,
	}

	// Check if immediately confirmed
	if err := anchor.Verify(hash, proof); err == nil {
		if _, ok := anchor.(UpgradableAnchor); !ok {
			record.Status = StatusConfirmed
			now := time.Now()
			record.ConfirmedAt = &now
		}
	}

	hashKey := hex.EncodeToString(hash)
	r.mu.Lock()
	r.records[hashKey] = append(r.records[hashKey], record)
	r.mu.Unlock()

	return record, nil
}

// Verify verifies a hash against stored records.
// Uses priority order to return first valid verification.
func (r *Registry) Verify(hash []byte) (*VerifyResult, error) {
	hashKey := hex.EncodeToString(hash)

	r.mu.RLock()
	records := r.records[hashKey]
	anchors := r.anchors
	priority := r.config.VerifyPriority
	r.mu.RUnlock()

	if len(records) == 0 {
		return nil, ErrAnchorNotFound
	}

	// Sort records by priority
	sortedRecords := make([]*AnchorRecord, len(records))
	copy(sortedRecords, records)
	sort.Slice(sortedRecords, func(i, j int) bool {
		iPriority := indexOf(priority, sortedRecords[i].Type)
		jPriority := indexOf(priority, sortedRecords[j].Type)
		return iPriority < jPriority
	})

	// Try each record in priority order
	for _, record := range sortedRecords {
		anchor, ok := anchors[record.Type]
		if !ok {
			continue
		}

		if err := anchor.Verify(hash, record.Proof); err == nil {
			return &VerifyResult{
				Valid:     true,
				Record:    record,
				Timestamp: record.CreatedAt,
			}, nil
		}
	}

	return &VerifyResult{
		Valid: false,
	}, errors.New("no valid proofs found")
}

// VerifyProof verifies a specific proof.
func (r *Registry) VerifyProof(anchorType AnchorType, hash, proof []byte) error {
	r.mu.RLock()
	anchor, ok := r.anchors[anchorType]
	r.mu.RUnlock()

	if !ok {
		return ErrAnchorNotFound
	}

	return anchor.Verify(hash, proof)
}

// GetRecords returns all records for a hash.
func (r *Registry) GetRecords(hash []byte) []*AnchorRecord {
	hashKey := hex.EncodeToString(hash)

	r.mu.RLock()
	defer r.mu.RUnlock()

	records := r.records[hashKey]
	result := make([]*AnchorRecord, len(records))
	copy(result, records)
	return result
}

// GetRecord returns a specific record by ID.
func (r *Registry) GetRecord(id string) *AnchorRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, records := range r.records {
		for _, record := range records {
			if record.ID == id {
				return record
			}
		}
	}
	return nil
}

// GetPendingRecords returns all pending records.
func (r *Registry) GetPendingRecords() []*AnchorRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var pending []*AnchorRecord
	for _, records := range r.records {
		for _, record := range records {
			if record.Status == StatusPending {
				pending = append(pending, record)
			}
		}
	}
	return pending
}

// GetConfirmedRecords returns all confirmed records.
func (r *Registry) GetConfirmedRecords() []*AnchorRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var confirmed []*AnchorRecord
	for _, records := range r.records {
		for _, record := range records {
			if record.Status == StatusConfirmed {
				confirmed = append(confirmed, record)
			}
		}
	}
	return confirmed
}

// UpgradeRecord manually triggers an upgrade for a record.
func (r *Registry) UpgradeRecord(id string) error {
	record := r.GetRecord(id)
	if record == nil {
		return ErrAnchorNotFound
	}

	if record.Status != StatusPending {
		return nil // Already processed
	}

	r.upgradeRecord(record)
	return nil
}

// UpgradeAll manually triggers upgrade for all pending records.
func (r *Registry) UpgradeAll() {
	r.upgradePendingRecords()
}

// Stats returns registry statistics.
func (r *Registry) Stats() *RegistryStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := &RegistryStats{
		EnabledTypes: make([]AnchorType, 0),
		ByType:       make(map[AnchorType]TypeStats),
	}

	for t, enabled := range r.enabled {
		if enabled {
			stats.EnabledTypes = append(stats.EnabledTypes, t)
		}
	}

	for _, records := range r.records {
		stats.TotalRecords += len(records)
		for _, record := range records {
			ts, ok := stats.ByType[record.Type]
			if !ok {
				ts = TypeStats{}
			}
			ts.Total++
			switch record.Status {
			case StatusPending:
				ts.Pending++
				stats.TotalPending++
			case StatusConfirmed:
				ts.Confirmed++
				stats.TotalConfirmed++
			case StatusFailed:
				ts.Failed++
				stats.TotalFailed++
			}
			stats.ByType[record.Type] = ts
		}
	}

	return stats
}

// RegistryStats contains registry statistics.
type RegistryStats struct {
	TotalRecords   int                    `json:"total_records"`
	TotalPending   int                    `json:"total_pending"`
	TotalConfirmed int                    `json:"total_confirmed"`
	TotalFailed    int                    `json:"total_failed"`
	EnabledTypes   []AnchorType           `json:"enabled_types"`
	ByType         map[AnchorType]TypeStats `json:"by_type"`
}

// TypeStats contains statistics for a single anchor type.
type TypeStats struct {
	Total     int `json:"total"`
	Pending   int `json:"pending"`
	Confirmed int `json:"confirmed"`
	Failed    int `json:"failed"`
}

// VerifyResult contains verification result.
type VerifyResult struct {
	Valid     bool          `json:"valid"`
	Record    *AnchorRecord `json:"record,omitempty"`
	Timestamp time.Time     `json:"timestamp,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// Export exports all records to JSON.
func (r *Registry) Export() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	export := struct {
		ExportedAt time.Time                    `json:"exported_at"`
		Stats      *RegistryStats               `json:"stats"`
		Records    map[string][]*AnchorRecord   `json:"records"`
	}{
		ExportedAt: time.Now(),
		Stats:      r.Stats(),
		Records:    r.records,
	}

	return json.MarshalIndent(export, "", "  ")
}

// Import imports records from JSON.
func (r *Registry) Import(data []byte) error {
	var imported struct {
		Records map[string][]*AnchorRecord `json:"records"`
	}

	if err := json.Unmarshal(data, &imported); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for hashKey, records := range imported.Records {
		r.records[hashKey] = append(r.records[hashKey], records...)
	}

	return nil
}

// Helper functions

func generateID() string {
	var buf [16]byte
	// Use time-based ID for simplicity
	t := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		buf[i] = byte(t >> (i * 8))
	}
	return hex.EncodeToString(buf[:])
}

func indexOf(slice []AnchorType, item AnchorType) int {
	for i, v := range slice {
		if v == item {
			return i
		}
	}
	return len(slice) // Put at end if not found
}

// SerializeRecord serializes a record for storage.
func SerializeRecord(record *AnchorRecord) ([]byte, error) {
	return json.Marshal(record)
}

// DeserializeRecord deserializes a record.
func DeserializeRecord(data []byte) (*AnchorRecord, error) {
	var record AnchorRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// CombineProofs combines multiple proofs for the same hash.
type CombinedProof struct {
	Hash    [32]byte        `json:"hash"`
	Proofs  []*AnchorRecord `json:"proofs"`
	Created time.Time       `json:"created"`
}

// CreateCombinedProof creates a combined proof from multiple records.
func CreateCombinedProof(hash []byte, records []*AnchorRecord) (*CombinedProof, error) {
	if len(hash) != 32 {
		return nil, ErrInvalidHash
	}

	var h [32]byte
	copy(h[:], hash)

	// Filter to matching hash
	var matching []*AnchorRecord
	for _, r := range records {
		if bytes.Equal(r.Hash[:], hash) {
			matching = append(matching, r)
		}
	}

	if len(matching) == 0 {
		return nil, ErrAnchorNotFound
	}

	return &CombinedProof{
		Hash:    h,
		Proofs:  matching,
		Created: time.Now(),
	}, nil
}

// VerifyCombinedProof verifies a combined proof.
func (r *Registry) VerifyCombinedProof(proof *CombinedProof) (*VerifyResult, error) {
	for _, record := range proof.Proofs {
		if err := r.VerifyProof(record.Type, proof.Hash[:], record.Proof); err == nil {
			return &VerifyResult{
				Valid:     true,
				Record:    record,
				Timestamp: record.CreatedAt,
			}, nil
		}
	}
	return &VerifyResult{Valid: false}, errors.New("no valid proofs")
}
