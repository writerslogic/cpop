// Package jitter implements cryptographically-bound delay injection.
//
// The core insight: we don't need to capture keystrokes to prove someone typed.
// Instead, we inject tiny delays (jitter) whose exact values are derived from:
// - A secret seed (known only to the prover)
// - The current document hash (binds to content state)
// - A keystroke counter (proves sequence)
// - A timestamp (proves timing)
// - The previous jitter value (creates a chain)
//
// This creates an unforgeable record: the jitter sequence can only be
// produced by someone who was actually typing at the keyboard while
// the document evolved through its intermediate states.
//
// Attack resistance:
// - Replay: Jitter is bound to specific document hash at each sample point
// - Precomputation: Need real wall-clock time (like VDF, but physical)
// - AI-assisted: Still requires physically typing the content
package jitter

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Zone-committed jitter constants
const (
	MinJitter   = 500  // microseconds
	MaxJitter   = 3000 // microseconds
	JitterRange = MaxJitter - MinJitter

	// Interval buckets: 10 buckets of 50ms each (0-500ms range)
	IntervalBucketSize = 50 // milliseconds
	NumIntervalBuckets = 10
)

// Parameters controls jitter computation.
type Parameters struct {
	// Minimum and maximum jitter in microseconds
	MinJitterMicros uint32 `json:"min_jitter_micros"`
	MaxJitterMicros uint32 `json:"max_jitter_micros"`

	// How often to sample (every N keystrokes)
	SampleInterval uint64 `json:"sample_interval"`

	// Whether jitter injection is enabled (privacy mode can disable)
	InjectEnabled bool `json:"inject_enabled"`
}

// DefaultParameters returns sensible defaults.
func DefaultParameters() Parameters {
	return Parameters{
		MinJitterMicros: 500,  // 0.5ms
		MaxJitterMicros: 3000, // 3ms - imperceptible to typist
		SampleInterval:  50,   // Sample every 50 keystrokes
		InjectEnabled:   true,
	}
}

// Sample represents one jitter sample point.
type Sample struct {
	// When this sample was recorded
	Timestamp time.Time `json:"timestamp"`

	// Keystroke count at this point
	KeystrokeCount uint64 `json:"keystroke_count"`

	// Document hash at this point (binds jitter to content)
	DocumentHash [32]byte `json:"document_hash"`

	// The computed jitter value
	JitterMicros uint32 `json:"jitter_micros"`

	// Hash of this sample (for chaining)
	Hash [32]byte `json:"hash"`

	// Hash of previous sample (chain linkage)
	PreviousHash [32]byte `json:"previous_hash"`
}

// computeHash computes the sample's binding hash.
func (s *Sample) computeHash() [32]byte {
	h := sha256.New()
	h.Write([]byte("witnessd-jitter-sample-v1"))

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(s.Timestamp.UnixNano()))
	h.Write(buf[:])

	binary.BigEndian.PutUint64(buf[:], s.KeystrokeCount)
	h.Write(buf[:])

	h.Write(s.DocumentHash[:])

	binary.BigEndian.PutUint32(buf[:4], s.JitterMicros)
	h.Write(buf[:4])

	h.Write(s.PreviousHash[:])

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// Session tracks jitter samples during a writing session.
type Session struct {
	mu sync.Mutex

	// Session identity
	ID        string    `json:"id"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitempty"`

	// What document we're tracking
	DocumentPath string `json:"document_path"`

	// Secret seed for this session (never exported)
	seed [32]byte

	// Parameters
	Params Parameters `json:"params"`

	// Keystroke counter
	keystrokeCount uint64

	// Samples (the evidence)
	Samples []Sample `json:"samples"`

	// Last jitter for chaining
	lastJitter uint32
}

// NewSession creates a new jitter tracking session.
func NewSession(documentPath string, params Parameters) (*Session, error) {
	absPath, err := filepath.Abs(documentPath)
	if err != nil {
		return nil, fmt.Errorf("invalid document path: %w", err)
	}

	// Generate session ID
	var idBytes [8]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Generate secret seed
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	return &Session{
		ID:           hex.EncodeToString(idBytes[:]),
		StartedAt:    time.Now(),
		DocumentPath: absPath,
		seed:         seed,
		Params:       params,
		Samples:      make([]Sample, 0),
	}, nil
}

// RecordKeystroke records a keystroke event.
// Returns the jitter to inject (if enabled), or 0.
// IMPORTANT: This does NOT capture which key was pressed.
func (s *Session) RecordKeystroke() (jitterMicros uint32, shouldSample bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.keystrokeCount++

	// Check if we should sample
	if s.keystrokeCount%s.Params.SampleInterval != 0 {
		return 0, false
	}

	// Read current document hash
	docHash, err := s.hashDocument()
	if err != nil {
		// Document not readable - skip this sample
		return 0, false
	}

	// Create sample - capture timestamp first for determinism
	now := time.Now()

	// Get previous hash for chaining
	var prevHash [32]byte
	if len(s.Samples) > 0 {
		prevHash = s.Samples[len(s.Samples)-1].Hash
	}

	// Compute jitter using the timestamp we'll store
	jitter := s.computeJitter(docHash, now)

	sample := Sample{
		Timestamp:      now,
		KeystrokeCount: s.keystrokeCount,
		DocumentHash:   docHash,
		JitterMicros:   jitter,
		PreviousHash:   prevHash,
	}
	sample.Hash = sample.computeHash()

	s.Samples = append(s.Samples, sample)
	s.lastJitter = jitter

	return jitter, true
}

// computeJitter derives jitter from the session state.
// The jitter value is deterministic given the inputs, creating
// an unforgeable chain bound to the document's evolution.
func (s *Session) computeJitter(docHash [32]byte, timestamp time.Time) uint32 {
	var prevJitter [32]byte
	if len(s.Samples) > 0 {
		prevJitter = s.Samples[len(s.Samples)-1].Hash
	}
	return ComputeJitterValue(s.seed[:], docHash, s.keystrokeCount, timestamp, prevJitter, s.Params)
}

// ComputeJitterValue computes a jitter value from the given inputs.
// This is the core HMAC computation: HMAC-SHA256(seed, doc_hash || count || timestamp || prev_jitter)
// The function is deterministic and can be used for both generation and verification.
func ComputeJitterValue(seed []byte, docHash [32]byte, keystrokeCount uint64, timestamp time.Time, prevJitter [32]byte, params Parameters) uint32 {
	h := hmac.New(sha256.New, seed)

	// Order: doc_hash || count || timestamp || prev_jitter
	h.Write(docHash[:])

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], keystrokeCount)
	h.Write(buf[:])

	binary.BigEndian.PutUint64(buf[:], uint64(timestamp.UnixNano()))
	h.Write(buf[:])

	h.Write(prevJitter[:])

	// Derive jitter value from first 4 bytes
	hash := h.Sum(nil)
	raw := binary.BigEndian.Uint32(hash[:4])

	// Map to range [min, max]
	jitterRange := params.MaxJitterMicros - params.MinJitterMicros
	if jitterRange == 0 {
		return params.MinJitterMicros
	}
	jitter := params.MinJitterMicros + (raw % jitterRange)

	return jitter
}

// hashDocument reads and hashes the tracked document.
func (s *Session) hashDocument() ([32]byte, error) {
	content, err := os.ReadFile(s.DocumentPath)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(content), nil
}

// End marks the session as complete.
func (s *Session) End() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EndedAt = time.Now()
}

// KeystrokeCount returns the total keystrokes recorded.
func (s *Session) KeystrokeCount() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keystrokeCount
}

// SampleCount returns the number of samples.
func (s *Session) SampleCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Samples)
}

// Duration returns the session duration.
func (s *Session) Duration() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	end := s.EndedAt
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(s.StartedAt)
}

// Evidence represents the exportable jitter evidence.
// This excludes the secret seed - only the samples are exported.
type Evidence struct {
	SessionID    string        `json:"session_id"`
	StartedAt    time.Time     `json:"started_at"`
	EndedAt      time.Time     `json:"ended_at"`
	DocumentPath string        `json:"document_path"`
	Params       Parameters    `json:"params"`
	Samples      []Sample      `json:"samples"`
	Statistics   Statistics    `json:"statistics"`
}

// Statistics summarizes the jitter evidence.
type Statistics struct {
	TotalKeystrokes    uint64        `json:"total_keystrokes"`
	TotalSamples       int           `json:"total_samples"`
	Duration           time.Duration `json:"duration"`
	KeystrokesPerMin   float64       `json:"keystrokes_per_minute"`
	UniqueDocHashes    int           `json:"unique_doc_hashes"`
	ChainValid         bool          `json:"chain_valid"`
}

// Export creates exportable evidence from the session.
func (s *Session) Export() Evidence {
	s.mu.Lock()
	defer s.mu.Unlock()

	end := s.EndedAt
	if end.IsZero() {
		end = time.Now()
	}

	ev := Evidence{
		SessionID:    s.ID,
		StartedAt:    s.StartedAt,
		EndedAt:      end,
		DocumentPath: s.DocumentPath,
		Params:       s.Params,
		Samples:      make([]Sample, len(s.Samples)),
	}
	copy(ev.Samples, s.Samples)

	// Compute statistics
	ev.Statistics = s.computeStats()

	return ev
}

func (s *Session) computeStats() Statistics {
	stats := Statistics{
		TotalKeystrokes: s.keystrokeCount,
		TotalSamples:    len(s.Samples),
	}

	end := s.EndedAt
	if end.IsZero() {
		end = time.Now()
	}
	stats.Duration = end.Sub(s.StartedAt)

	if stats.Duration > 0 {
		minutes := stats.Duration.Minutes()
		if minutes > 0 {
			stats.KeystrokesPerMin = float64(s.keystrokeCount) / minutes
		}
	}

	// Count unique document hashes
	seen := make(map[[32]byte]bool)
	for _, sample := range s.Samples {
		seen[sample.DocumentHash] = true
	}
	stats.UniqueDocHashes = len(seen)

	// Verify chain
	stats.ChainValid = s.verifyChain() == nil

	return stats
}

// verifyChain checks the sample chain integrity.
func (s *Session) verifyChain() error {
	for i, sample := range s.Samples {
		// Verify hash
		computed := sample.computeHash()
		if computed != sample.Hash {
			return fmt.Errorf("sample %d: hash mismatch", i)
		}

		// Verify chain linkage
		if i > 0 {
			if sample.PreviousHash != s.Samples[i-1].Hash {
				return fmt.Errorf("sample %d: broken chain link", i)
			}
		} else if sample.PreviousHash != ([32]byte{}) {
			return fmt.Errorf("sample 0: non-zero previous hash")
		}
	}
	return nil
}

// Verify checks the evidence integrity (without the seed).
func (e *Evidence) Verify() error {
	for i, sample := range e.Samples {
		// Verify hash
		computed := sample.computeHash()
		if computed != sample.Hash {
			return fmt.Errorf("sample %d: hash mismatch", i)
		}

		// Verify chain linkage
		if i > 0 {
			if sample.PreviousHash != e.Samples[i-1].Hash {
				return fmt.Errorf("sample %d: broken chain link", i)
			}
		} else if sample.PreviousHash != ([32]byte{}) {
			return fmt.Errorf("sample 0: non-zero previous hash")
		}

		// Verify timestamps are monotonic
		if i > 0 && sample.Timestamp.Before(e.Samples[i-1].Timestamp) {
			return fmt.Errorf("sample %d: timestamp not monotonic", i)
		}

		// Verify keystroke counts are monotonic
		if i > 0 && sample.KeystrokeCount <= e.Samples[i-1].KeystrokeCount {
			return fmt.Errorf("sample %d: keystroke count not monotonic", i)
		}
	}
	return nil
}

// Encode serializes the evidence to JSON.
func (e *Evidence) Encode() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

// DecodeEvidence deserializes evidence from JSON.
func DecodeEvidence(data []byte) (*Evidence, error) {
	var e Evidence
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// SessionData is what gets persisted to disk (includes seed).
type SessionData struct {
	ID           string     `json:"id"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      time.Time  `json:"ended_at,omitempty"`
	DocumentPath string     `json:"document_path"`
	Seed         string     `json:"seed"` // Hex-encoded
	Params       Parameters `json:"params"`
	Samples      []Sample   `json:"samples"`
	KeystrokeCount uint64   `json:"keystroke_count"`
	LastJitter   uint32     `json:"last_jitter"`
}

// Save persists the session to disk.
func (s *Session) Save(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data := SessionData{
		ID:             s.ID,
		StartedAt:      s.StartedAt,
		EndedAt:        s.EndedAt,
		DocumentPath:   s.DocumentPath,
		Seed:           hex.EncodeToString(s.seed[:]),
		Params:         s.Params,
		Samples:        s.Samples,
		KeystrokeCount: s.keystrokeCount,
		LastJitter:     s.lastJitter,
	}

	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(path, bytes, 0600); err != nil {
		return fmt.Errorf("failed to write session: %w", err)
	}

	return nil
}

// LoadSession reads a session from disk.
func LoadSession(path string) (*Session, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read session: %w", err)
	}

	var data SessionData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	seedBytes, err := hex.DecodeString(data.Seed)
	if err != nil {
		return nil, fmt.Errorf("invalid seed: %w", err)
	}
	if len(seedBytes) != 32 {
		return nil, errors.New("seed must be 32 bytes")
	}

	var seed [32]byte
	copy(seed[:], seedBytes)

	return &Session{
		ID:             data.ID,
		StartedAt:      data.StartedAt,
		EndedAt:        data.EndedAt,
		DocumentPath:   data.DocumentPath,
		seed:           seed,
		Params:         data.Params,
		Samples:        data.Samples,
		keystrokeCount: data.KeystrokeCount,
		lastJitter:     data.LastJitter,
	}, nil
}

// TypingRate computes keystrokes per minute from evidence.
func (e *Evidence) TypingRate() float64 {
	if e.Statistics.Duration > 0 {
		return float64(e.Statistics.TotalKeystrokes) / e.Statistics.Duration.Minutes()
	}
	return 0
}

// DocumentEvolution returns the number of unique document states observed.
func (e *Evidence) DocumentEvolution() int {
	return e.Statistics.UniqueDocHashes
}

// IsPlausibleHumanTyping does a basic sanity check on typing patterns.
// Returns true if the typing rate and patterns are within human norms.
func (e *Evidence) IsPlausibleHumanTyping() bool {
	// Average typing speed: 40-80 WPM
	// Characters per word: ~5
	// So keystrokes per minute: 200-400 for average typist
	// Professional: up to 100 WPM = 500+ KPM
	// Burst: up to 150 WPM = 750 KPM

	rate := e.TypingRate()

	// Suspiciously slow (likely automated with delays)
	if rate < 10 && e.Statistics.TotalKeystrokes > 100 {
		return false
	}

	// Suspiciously fast (likely paste/automation)
	if rate > 1000 {
		return false
	}

	// Need to see document evolution
	if e.Statistics.UniqueDocHashes < 2 && e.Statistics.TotalKeystrokes > 500 {
		return false
	}

	return true
}

// =============================================================================
// Zone-Committed Jitter Engine
// =============================================================================

// JitterEngine computes zone-committed jitter values.
type JitterEngine struct {
	secret     [32]byte
	ordinal    uint64
	prevJitter uint32
	prevZone   int
	prevTime   time.Time
	profile    TypingProfile
}

// NewJitterEngine creates a new engine with the given secret.
func NewJitterEngine(secret [32]byte) *JitterEngine {
	return &JitterEngine{
		secret:   secret,
		prevZone: -1,
	}
}

// JitterSample is a single jitter measurement.
// ZoneTransition and IntervalBucket are stored for statistical verification.
// The jitter value cryptographically commits to these via HMAC.
type JitterSample struct {
	Ordinal        uint64    `json:"ordinal"`
	Timestamp      time.Time `json:"timestamp"`
	DocHash        [32]byte  `json:"document_hash"`
	ZoneTransition uint8     `json:"zone_transition"` // Encoded (from<<3)|to, 0xFF if none
	IntervalBucket uint8     `json:"interval_bucket"` // 0-9, timing bin
	JitterMicros   uint32    `json:"jitter_micros"`
	SampleHash     [32]byte  `json:"sample_hash"`
}

// TypingProfile captures aggregate typing characteristics.
type TypingProfile struct {
	SameFingerHist   [10]uint32 `json:"same_finger_histogram"`
	SameHandHist     [10]uint32 `json:"same_hand_histogram"`
	AlternatingHist  [10]uint32 `json:"alternating_histogram"`
	HandAlternation  float32    `json:"hand_alternation_ratio"`
	TotalTransitions uint64     `json:"total_transitions"`
	alternatingCount uint64     // internal counter
}

// OnKeystroke processes a keystroke and returns the jitter delay to inject.
// The zone transition and interval are committed in the jitter value but not stored.
func (e *JitterEngine) OnKeystroke(keyCode uint16, docHash [32]byte) (jitterMicros uint32, sample *JitterSample) {
	now := time.Now()
	zone := KeyCodeToZone(keyCode)

	// Skip non-zone keys for jitter computation
	if zone < 0 {
		return 0, nil
	}

	var zoneTransition uint8 = 0xFF
	var intervalBucket uint8 = 0

	if e.prevZone >= 0 {
		// Encode zone transition
		zoneTransition = EncodeZoneTransition(e.prevZone, zone)

		// Bucket the interval
		interval := now.Sub(e.prevTime)
		intervalBucket = IntervalToBucket(interval)

		// Update typing profile
		e.updateProfile(e.prevZone, zone, intervalBucket)
	}

	// Compute jitter (commits to zone and interval)
	jitter := e.computeJitter(docHash, zoneTransition, intervalBucket, now)

	// Create sample at configured intervals
	e.ordinal++
	sample = &JitterSample{
		Ordinal:        e.ordinal,
		Timestamp:      now,
		DocHash:        docHash,
		ZoneTransition: zoneTransition,
		IntervalBucket: intervalBucket,
		JitterMicros:   jitter,
	}
	sample.SampleHash = e.computeSampleHash(sample)

	// Update state for next keystroke
	e.prevZone = zone
	e.prevTime = now
	e.prevJitter = jitter

	return jitter, sample
}

func (e *JitterEngine) computeJitter(
	docHash [32]byte,
	zoneTransition uint8,
	intervalBucket uint8,
	timestamp time.Time,
) uint32 {
	h := hmac.New(sha256.New, e.secret[:])

	// Ordinal (position in sequence)
	binary.Write(h, binary.BigEndian, e.ordinal)

	// Document state
	h.Write(docHash[:])

	// Timestamp
	binary.Write(h, binary.BigEndian, timestamp.UnixNano())

	// Zone transition (COMMITTED, not stored in evidence)
	h.Write([]byte{zoneTransition})

	// Interval bucket (COMMITTED, not stored in evidence)
	h.Write([]byte{intervalBucket})

	// Chain link to previous jitter
	binary.Write(h, binary.BigEndian, e.prevJitter)

	// Compute final jitter value
	hash := h.Sum(nil)
	raw := binary.BigEndian.Uint32(hash[:4])
	return MinJitter + (raw % JitterRange)
}

func (e *JitterEngine) computeSampleHash(s *JitterSample) [32]byte {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, s.Ordinal)
	binary.Write(h, binary.BigEndian, s.Timestamp.UnixNano())
	h.Write(s.DocHash[:])
	h.Write([]byte{s.ZoneTransition, s.IntervalBucket})
	binary.Write(h, binary.BigEndian, s.JitterMicros)

	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

// IntervalToBucket converts a duration to an interval bucket (0-9).
func IntervalToBucket(d time.Duration) uint8 {
	ms := d.Milliseconds()
	bucket := ms / IntervalBucketSize
	if bucket >= NumIntervalBuckets {
		bucket = NumIntervalBuckets - 1
	}
	if bucket < 0 {
		bucket = 0
	}
	return uint8(bucket)
}

func (e *JitterEngine) updateProfile(fromZone, toZone int, bucket uint8) {
	trans := ZoneTransition{From: fromZone, To: toZone}

	if trans.IsSameFinger() {
		e.profile.SameFingerHist[bucket]++
	} else if trans.IsSameHand() {
		e.profile.SameHandHist[bucket]++
	} else {
		e.profile.AlternatingHist[bucket]++
		e.profile.alternatingCount++
	}

	e.profile.TotalTransitions++
	if e.profile.TotalTransitions > 0 {
		e.profile.HandAlternation = float32(e.profile.alternatingCount) / float32(e.profile.TotalTransitions)
	}
}

// Profile returns the current typing profile.
func (e *JitterEngine) Profile() TypingProfile {
	return e.profile
}

// =============================================================================
// Profile Comparison and Plausibility
// =============================================================================

// CompareProfiles computes similarity between two typing profiles.
// Returns a value between 0.0 (completely different) and 1.0 (identical).
func CompareProfiles(a, b TypingProfile) float64 {
	if a.TotalTransitions == 0 || b.TotalTransitions == 0 {
		return 0.0
	}

	// Compare histogram distributions using cosine similarity
	sameFingerSim := histogramCosineSimilarity(a.SameFingerHist[:], b.SameFingerHist[:])
	sameHandSim := histogramCosineSimilarity(a.SameHandHist[:], b.SameHandHist[:])
	alternatingSim := histogramCosineSimilarity(a.AlternatingHist[:], b.AlternatingHist[:])

	// Compare hand alternation ratio (inverse of absolute difference)
	handAltDiff := float64(a.HandAlternation) - float64(b.HandAlternation)
	if handAltDiff < 0 {
		handAltDiff = -handAltDiff
	}
	handAltSim := 1.0 - handAltDiff // Difference is 0-1, so similarity is 1-diff

	// Weighted average (histograms matter more than single ratio)
	return 0.3*sameFingerSim + 0.3*sameHandSim + 0.3*alternatingSim + 0.1*handAltSim
}

// histogramCosineSimilarity computes cosine similarity between two histograms.
func histogramCosineSimilarity(a, b []uint32) float64 {
	var dotProduct, normA, normB float64

	for i := range a {
		fa := float64(a[i])
		fb := float64(b[i])
		dotProduct += fa * fb
		normA += fa * fa
		normB += fb * fb
	}

	if normA == 0 || normB == 0 {
		return 0.0
	}

	return dotProduct / (sqrt(normA) * sqrt(normB))
}

// sqrt is a simple square root approximation for float64
func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Newton-Raphson
	z := x / 2
	for i := 0; i < 10; i++ {
		z = z - (z*z-x)/(2*z)
	}
	return z
}

// IsHumanPlausible checks if a typing profile is consistent with human typing.
// Returns true if the profile looks like it came from a real person typing.
func IsHumanPlausible(p TypingProfile) bool {
	if p.TotalTransitions < 10 {
		// Not enough data to judge
		return true
	}

	// Human typing characteristics:
	// 1. Hand alternation should be between 30-70% (most text alternates hands)
	if p.HandAlternation < 0.15 || p.HandAlternation > 0.85 {
		// Extremely one-handed typing is suspicious
		return false
	}

	// 2. Same-finger transitions should be relatively rare (< 15% typically)
	var sameFingerTotal uint64
	var sameHandTotal uint64
	var alternatingTotal uint64

	for i := 0; i < 10; i++ {
		sameFingerTotal += uint64(p.SameFingerHist[i])
		sameHandTotal += uint64(p.SameHandHist[i])
		alternatingTotal += uint64(p.AlternatingHist[i])
	}

	totalTransitions := sameFingerTotal + sameHandTotal + alternatingTotal
	if totalTransitions == 0 {
		return true
	}

	sameFingerRatio := float64(sameFingerTotal) / float64(totalTransitions)
	if sameFingerRatio > 0.30 {
		// Too many same-finger transitions - unusual for natural typing
		return false
	}

	// 3. Interval distribution should show variation (not all in one bucket)
	// Compute entropy-like measure
	var nonZeroBuckets int
	for i := 0; i < 10; i++ {
		if p.SameFingerHist[i] > 0 || p.SameHandHist[i] > 0 || p.AlternatingHist[i] > 0 {
			nonZeroBuckets++
		}
	}

	if nonZeroBuckets < 3 && totalTransitions > 100 {
		// All typing happening at exactly the same speed is suspicious
		return false
	}

	// 4. Check for robotic timing patterns (all intervals identical)
	maxBucketPct := maxHistogramConcentration(p)
	if maxBucketPct > 0.80 && totalTransitions > 50 {
		// Over 80% of timing in a single bucket is robotic
		return false
	}

	return true
}

// maxHistogramConcentration finds the maximum concentration in any single bucket.
func maxHistogramConcentration(p TypingProfile) float64 {
	var total uint64
	var maxBucket uint64

	for i := 0; i < 10; i++ {
		bucketTotal := uint64(p.SameFingerHist[i]) + uint64(p.SameHandHist[i]) + uint64(p.AlternatingHist[i])
		total += bucketTotal
		if bucketTotal > maxBucket {
			maxBucket = bucketTotal
		}
	}

	if total == 0 {
		return 0.0
	}

	return float64(maxBucket) / float64(total)
}

// ProfileDistance computes Euclidean distance between normalized profiles.
// Smaller values indicate more similar profiles.
func ProfileDistance(a, b TypingProfile) float64 {
	// Normalize histograms
	aNorm := normalizeHistograms(a)
	bNorm := normalizeHistograms(b)

	var sumSquares float64

	// Same finger histogram distance
	for i := 0; i < 10; i++ {
		diff := aNorm.sameFinger[i] - bNorm.sameFinger[i]
		sumSquares += diff * diff
	}

	// Same hand histogram distance
	for i := 0; i < 10; i++ {
		diff := aNorm.sameHand[i] - bNorm.sameHand[i]
		sumSquares += diff * diff
	}

	// Alternating histogram distance
	for i := 0; i < 10; i++ {
		diff := aNorm.alternating[i] - bNorm.alternating[i]
		sumSquares += diff * diff
	}

	// Hand alternation difference
	diff := float64(a.HandAlternation) - float64(b.HandAlternation)
	sumSquares += diff * diff

	return sqrt(sumSquares)
}

type normalizedProfile struct {
	sameFinger  [10]float64
	sameHand    [10]float64
	alternating [10]float64
}

func normalizeHistograms(p TypingProfile) normalizedProfile {
	var np normalizedProfile

	// Compute totals
	var sfTotal, shTotal, altTotal uint64
	for i := 0; i < 10; i++ {
		sfTotal += uint64(p.SameFingerHist[i])
		shTotal += uint64(p.SameHandHist[i])
		altTotal += uint64(p.AlternatingHist[i])
	}

	// Normalize
	for i := 0; i < 10; i++ {
		if sfTotal > 0 {
			np.sameFinger[i] = float64(p.SameFingerHist[i]) / float64(sfTotal)
		}
		if shTotal > 0 {
			np.sameHand[i] = float64(p.SameHandHist[i]) / float64(shTotal)
		}
		if altTotal > 0 {
			np.alternating[i] = float64(p.AlternatingHist[i]) / float64(altTotal)
		}
	}

	return np
}
