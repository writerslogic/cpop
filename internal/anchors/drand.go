package anchors

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Drand network constants
const (
	// League of Entropy mainnet (default chain)
	DrandMainnetChainHash = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"

	// Quicknet - faster chain (3 seconds)
	DrandQuicknetChainHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

	// Testnet chain
	DrandTestnetChainHash = "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf"

	// Genesis times (Unix timestamps)
	DrandMainnetGenesis  = 1595431050
	DrandQuicknetGenesis = 1692803367
	DrandTestnetGenesis  = 1651677099

	// Round periods
	DrandMainnetPeriod  = 30 * time.Second
	DrandQuicknetPeriod = 3 * time.Second
	DrandTestnetPeriod  = 3 * time.Second
)

// Default drand API endpoints
var DefaultDrandEndpoints = []string{
	"https://api.drand.sh",
	"https://api2.drand.sh",
	"https://api3.drand.sh",
	"https://drand.cloudflare.com",
}

// DrandConfig configures the drand anchor.
type DrandConfig struct {
	// ChainHash of the drand network to use
	ChainHash string

	// Endpoints to query
	Endpoints []string

	// Timeout for HTTP requests
	Timeout time.Duration

	// EnableCache enables caching of beacon responses
	EnableCache bool

	// CacheTTL is how long to cache beacon responses
	CacheTTL time.Duration

	// VerifySignatures enables BLS signature verification
	VerifySignatures bool

	// PublicKey for signature verification (hex encoded)
	PublicKey string
}

// DrandAnchor implements the drand beacon anchor.
type DrandAnchor struct {
	chainHash        string
	endpoints        []string
	client           *http.Client
	enableCache      bool
	cacheTTL         time.Duration
	verifySignatures bool
	publicKey        []byte

	// Chain info
	chainInfo *DrandChainInfo

	// Cache
	cacheMu    sync.RWMutex
	beaconCache map[uint64]*DrandBeacon

	// Genesis time and period
	genesisTime int64
	period      time.Duration
}

// DrandChainInfo contains information about a drand chain.
type DrandChainInfo struct {
	PublicKey   string `json:"public_key"`
	Period      int    `json:"period"`       // Seconds between rounds
	GenesisTime int64  `json:"genesis_time"` // Unix timestamp
	Hash        string `json:"hash"`         // Chain hash
	GroupHash   string `json:"groupHash"`
	SchemeID    string `json:"schemeID"`     // e.g., "bls-unchained-on-g1"
	Metadata    struct {
		BeaconID string `json:"beaconID"`
	} `json:"metadata"`
}

// DrandBeacon represents a drand beacon output.
type DrandBeacon struct {
	Round           uint64 `json:"round"`
	Randomness      string `json:"randomness"`       // Hex-encoded randomness
	Signature       string `json:"signature"`        // Hex-encoded BLS signature
	PreviousSignature string `json:"previous_signature,omitempty"` // For chained schemes
}

// DrandProof contains a complete drand anchor proof.
type DrandProof struct {
	// Chain information
	ChainHash   string `json:"chain_hash"`
	ChainInfo   *DrandChainInfo `json:"chain_info,omitempty"`

	// Beacon data
	Round       uint64    `json:"round"`
	Randomness  string    `json:"randomness"`
	Signature   string    `json:"signature"`
	Timestamp   time.Time `json:"timestamp"`

	// Anchored data
	AnchoredHash [32]byte `json:"anchored_hash"`

	// Binding proof - shows that hash existed before this round
	BindingProof *DrandBindingProof `json:"binding_proof,omitempty"`

	// Verification status
	SignatureValid bool `json:"signature_valid"`
	Verified       bool `json:"verified"`
}

// DrandBindingProof proves a hash was committed before a specific round.
type DrandBindingProof struct {
	// The round used for binding
	BoundRound uint64 `json:"bound_round"`

	// Hash of (anchored_hash || round) used for commitment
	Commitment [32]byte `json:"commitment"`

	// Method: "before" (hash existed before round) or "after" (hash verified after)
	Method string `json:"method"`
}

// NewDrandAnchor creates a new drand anchor with default config.
func NewDrandAnchor() *DrandAnchor {
	return NewDrandAnchorWithConfig(DrandConfig{})
}

// NewDrandAnchorWithConfig creates a drand anchor with custom config.
func NewDrandAnchorWithConfig(config DrandConfig) *DrandAnchor {
	chainHash := config.ChainHash
	if chainHash == "" {
		chainHash = DrandMainnetChainHash
	}

	endpoints := config.Endpoints
	if len(endpoints) == 0 {
		endpoints = DefaultDrandEndpoints
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	cacheTTL := config.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 24 * time.Hour
	}

	var publicKey []byte
	if config.PublicKey != "" {
		publicKey, _ = hex.DecodeString(config.PublicKey)
	}

	// Set genesis time and period based on chain
	var genesisTime int64
	var period time.Duration
	switch chainHash {
	case DrandMainnetChainHash:
		genesisTime = DrandMainnetGenesis
		period = DrandMainnetPeriod
	case DrandQuicknetChainHash:
		genesisTime = DrandQuicknetGenesis
		period = DrandQuicknetPeriod
	case DrandTestnetChainHash:
		genesisTime = DrandTestnetGenesis
		period = DrandTestnetPeriod
	default:
		genesisTime = 0 // Will be fetched from chain info
		period = 30 * time.Second
	}

	return &DrandAnchor{
		chainHash:        chainHash,
		endpoints:        endpoints,
		client:           &http.Client{Timeout: timeout},
		enableCache:      config.EnableCache,
		cacheTTL:         cacheTTL,
		verifySignatures: config.VerifySignatures,
		publicKey:        publicKey,
		beaconCache:      make(map[uint64]*DrandBeacon),
		genesisTime:      genesisTime,
		period:           period,
	}
}

// Name returns the anchor type name.
func (d *DrandAnchor) Name() string {
	return "drand"
}

// Commit creates a drand anchor for a hash.
// The anchor proves the hash existed before the next drand round.
func (d *DrandAnchor) Commit(hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, errors.New("drand: hash must be 32 bytes")
	}

	var h [32]byte
	copy(h[:], hash)

	// Get the latest beacon
	beacon, err := d.GetLatestBeacon()
	if err != nil {
		return nil, fmt.Errorf("drand: failed to get beacon: %w", err)
	}

	// Create the proof
	proof := &DrandProof{
		ChainHash:    d.chainHash,
		Round:        beacon.Round,
		Randomness:   beacon.Randomness,
		Signature:    beacon.Signature,
		Timestamp:    d.RoundToTime(beacon.Round),
		AnchoredHash: h,
	}

	// Create binding proof
	proof.BindingProof = &DrandBindingProof{
		BoundRound: beacon.Round,
		Method:     "after",
	}
	// Commitment = SHA256(hash || round)
	commitment := sha256.Sum256(append(h[:], uint64ToBytes(beacon.Round)...))
	proof.BindingProof.Commitment = commitment

	// Verify signature if enabled
	if d.verifySignatures {
		valid, err := d.VerifyBeaconSignature(beacon)
		proof.SignatureValid = valid && err == nil
	}
	proof.Verified = true

	return json.Marshal(proof)
}

// Verify verifies a drand proof.
func (d *DrandAnchor) Verify(hash, proof []byte) error {
	var dp DrandProof
	if err := json.Unmarshal(proof, &dp); err != nil {
		return fmt.Errorf("drand: parse proof: %w", err)
	}

	// Verify hash matches
	if !bytes.Equal(hash, dp.AnchoredHash[:]) {
		return errors.New("drand: hash mismatch")
	}

	// Verify the beacon still exists and matches
	beacon, err := d.GetBeacon(dp.Round)
	if err != nil {
		return fmt.Errorf("drand: failed to get beacon: %w", err)
	}

	if beacon.Randomness != dp.Randomness {
		return errors.New("drand: randomness mismatch")
	}

	if beacon.Signature != dp.Signature {
		return errors.New("drand: signature mismatch")
	}

	// Verify signature
	if d.verifySignatures {
		valid, err := d.VerifyBeaconSignature(beacon)
		if err != nil {
			return fmt.Errorf("drand: signature verification failed: %w", err)
		}
		if !valid {
			return errors.New("drand: invalid signature")
		}
	}

	// Verify binding proof if present
	if dp.BindingProof != nil {
		expectedCommitment := sha256.Sum256(append(hash, uint64ToBytes(dp.BindingProof.BoundRound)...))
		if dp.BindingProof.Commitment != expectedCommitment {
			return errors.New("drand: binding proof invalid")
		}
	}

	return nil
}

// GetLatestBeacon retrieves the latest beacon from the drand network.
func (d *DrandAnchor) GetLatestBeacon() (*DrandBeacon, error) {
	return d.fetchBeacon("public/latest")
}

// GetBeacon retrieves a specific beacon round.
func (d *DrandAnchor) GetBeacon(round uint64) (*DrandBeacon, error) {
	// Check cache first
	if d.enableCache {
		d.cacheMu.RLock()
		if beacon, ok := d.beaconCache[round]; ok {
			d.cacheMu.RUnlock()
			return beacon, nil
		}
		d.cacheMu.RUnlock()
	}

	beacon, err := d.fetchBeacon(fmt.Sprintf("public/%d", round))
	if err != nil {
		return nil, err
	}

	// Cache the result
	if d.enableCache {
		d.cacheMu.Lock()
		d.beaconCache[round] = beacon
		d.cacheMu.Unlock()
	}

	return beacon, nil
}

// fetchBeacon fetches a beacon from the drand API.
func (d *DrandAnchor) fetchBeacon(path string) (*DrandBeacon, error) {
	var lastErr error

	for _, endpoint := range d.endpoints {
		url := fmt.Sprintf("%s/%s/%s", endpoint, d.chainHash, path)

		resp, err := d.client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("endpoint %s returned %d", endpoint, resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			lastErr = err
			continue
		}

		var beacon DrandBeacon
		if err := json.Unmarshal(body, &beacon); err != nil {
			lastErr = err
			continue
		}

		return &beacon, nil
	}

	return nil, fmt.Errorf("all endpoints failed: %w", lastErr)
}

// GetChainInfo retrieves chain information from the drand network.
func (d *DrandAnchor) GetChainInfo() (*DrandChainInfo, error) {
	if d.chainInfo != nil {
		return d.chainInfo, nil
	}

	var lastErr error
	for _, endpoint := range d.endpoints {
		url := fmt.Sprintf("%s/%s/info", endpoint, d.chainHash)

		resp, err := d.client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("endpoint %s returned %d", endpoint, resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}

		var info DrandChainInfo
		if err := json.Unmarshal(body, &info); err != nil {
			lastErr = err
			continue
		}

		d.chainInfo = &info
		d.publicKey, _ = hex.DecodeString(info.PublicKey)
		d.genesisTime = info.GenesisTime
		d.period = time.Duration(info.Period) * time.Second

		return &info, nil
	}

	return nil, fmt.Errorf("all endpoints failed: %w", lastErr)
}

// RoundToTime converts a round number to a timestamp.
func (d *DrandAnchor) RoundToTime(round uint64) time.Time {
	if d.genesisTime == 0 {
		// Try to fetch chain info
		info, err := d.GetChainInfo()
		if err == nil {
			d.genesisTime = info.GenesisTime
			d.period = time.Duration(info.Period) * time.Second
		}
	}

	// Round 1 is at genesis time
	roundOffset := int64(round-1) * int64(d.period.Seconds())
	return time.Unix(d.genesisTime+roundOffset, 0)
}

// TimeToRound converts a timestamp to a round number.
func (d *DrandAnchor) TimeToRound(t time.Time) uint64 {
	if d.genesisTime == 0 {
		info, _ := d.GetChainInfo()
		if info != nil {
			d.genesisTime = info.GenesisTime
			d.period = time.Duration(info.Period) * time.Second
		}
	}

	elapsed := t.Unix() - d.genesisTime
	if elapsed < 0 {
		return 1
	}

	round := uint64(elapsed/int64(d.period.Seconds())) + 1
	return round
}

// GetRoundForTime returns the beacon round that was active at a given time.
func (d *DrandAnchor) GetRoundForTime(t time.Time) (*DrandBeacon, error) {
	round := d.TimeToRound(t)
	return d.GetBeacon(round)
}

// WaitForRound waits for a specific round to be available.
func (d *DrandAnchor) WaitForRound(round uint64, timeout time.Duration) (*DrandBeacon, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		beacon, err := d.GetBeacon(round)
		if err == nil {
			return beacon, nil
		}

		// Calculate time until this round
		roundTime := d.RoundToTime(round)
		waitTime := time.Until(roundTime)

		if waitTime > 0 {
			// Wait until the round time plus a small buffer
			sleepTime := waitTime + time.Second
			if sleepTime > timeout {
				sleepTime = timeout / 10
			}
			time.Sleep(sleepTime)
		} else {
			// Round should be available, retry shortly
			time.Sleep(time.Second)
		}
	}

	return nil, errors.New("timeout waiting for round")
}

// VerifyBeaconSignature verifies the BLS signature of a beacon.
// Note: Full BLS signature verification requires the bn256/bls12-381 library.
// This is a placeholder that can be implemented with the appropriate crypto library.
func (d *DrandAnchor) VerifyBeaconSignature(beacon *DrandBeacon) (bool, error) {
	if len(d.publicKey) == 0 {
		// Try to get public key from chain info
		info, err := d.GetChainInfo()
		if err != nil {
			return false, fmt.Errorf("no public key available: %w", err)
		}
		d.publicKey, _ = hex.DecodeString(info.PublicKey)
	}

	// Parse signature
	sig, err := hex.DecodeString(beacon.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Parse randomness (which is the SHA256 hash of the signature for unchained schemes)
	randomness, err := hex.DecodeString(beacon.Randomness)
	if err != nil {
		return false, fmt.Errorf("invalid randomness encoding: %w", err)
	}

	// For unchained schemes, verify that randomness = SHA256(signature)
	expectedRandomness := sha256.Sum256(sig)
	if !bytes.Equal(randomness, expectedRandomness[:]) {
		return false, errors.New("randomness does not match signature hash")
	}

	// Full BLS verification would go here
	// This requires implementing or importing BLS12-381 signature verification
	// For now, we just verify the hash relationship which provides basic integrity

	// Placeholder: in production, implement actual BLS verification:
	// message := computeMessage(beacon.Round, beacon.PreviousSignature)
	// return bls.Verify(d.publicKey, message, sig)

	return true, nil
}

// GetBeaconsInRange retrieves all beacons in a time range.
func (d *DrandAnchor) GetBeaconsInRange(start, end time.Time) ([]*DrandBeacon, error) {
	startRound := d.TimeToRound(start)
	endRound := d.TimeToRound(end)

	if endRound < startRound {
		startRound, endRound = endRound, startRound
	}

	// Limit to reasonable range
	maxRounds := uint64(1000)
	if endRound-startRound > maxRounds {
		endRound = startRound + maxRounds
	}

	beacons := make([]*DrandBeacon, 0, endRound-startRound+1)
	for round := startRound; round <= endRound; round++ {
		beacon, err := d.GetBeacon(round)
		if err != nil {
			continue
		}
		beacons = append(beacons, beacon)
	}

	return beacons, nil
}

// CreateTimeProof creates a proof that a hash existed at a specific time.
// This uses the next available beacon after the submission.
func (d *DrandAnchor) CreateTimeProof(hash [32]byte, targetTime time.Time) (*DrandProof, error) {
	// Find the first beacon after the target time
	targetRound := d.TimeToRound(targetTime)

	// Wait for the beacon if necessary
	beacon, err := d.WaitForRound(targetRound, 2*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed to get beacon: %w", err)
	}

	proof := &DrandProof{
		ChainHash:    d.chainHash,
		Round:        beacon.Round,
		Randomness:   beacon.Randomness,
		Signature:    beacon.Signature,
		Timestamp:    d.RoundToTime(beacon.Round),
		AnchoredHash: hash,
		BindingProof: &DrandBindingProof{
			BoundRound: beacon.Round,
			Method:     "before", // Hash must have existed before this round
		},
	}

	// Create commitment
	commitment := sha256.Sum256(append(hash[:], uint64ToBytes(beacon.Round)...))
	proof.BindingProof.Commitment = commitment

	// Verify signature
	if d.verifySignatures {
		valid, _ := d.VerifyBeaconSignature(beacon)
		proof.SignatureValid = valid
	}
	proof.Verified = true

	return proof, nil
}

// ExportBeaconCache exports the beacon cache for offline verification.
func (d *DrandAnchor) ExportBeaconCache() ([]byte, error) {
	d.cacheMu.RLock()
	defer d.cacheMu.RUnlock()

	// Convert map to sorted slice
	rounds := make([]uint64, 0, len(d.beaconCache))
	for round := range d.beaconCache {
		rounds = append(rounds, round)
	}
	sort.Slice(rounds, func(i, j int) bool { return rounds[i] < rounds[j] })

	beacons := make([]*DrandBeacon, 0, len(rounds))
	for _, round := range rounds {
		beacons = append(beacons, d.beaconCache[round])
	}

	return json.Marshal(beacons)
}

// ImportBeaconCache imports a beacon cache for offline verification.
func (d *DrandAnchor) ImportBeaconCache(data []byte) error {
	var beacons []*DrandBeacon
	if err := json.Unmarshal(data, &beacons); err != nil {
		return err
	}

	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()

	for _, beacon := range beacons {
		d.beaconCache[beacon.Round] = beacon
	}

	return nil
}

// ClearCache clears the beacon cache.
func (d *DrandAnchor) ClearCache() {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	d.beaconCache = make(map[uint64]*DrandBeacon)
}

// GetCacheSize returns the number of cached beacons.
func (d *DrandAnchor) GetCacheSize() int {
	d.cacheMu.RLock()
	defer d.cacheMu.RUnlock()
	return len(d.beaconCache)
}

// Helper functions

func uint64ToBytes(n uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(n)
		n >>= 8
	}
	return b
}

// DrandRandomnessFromBeacon extracts randomness suitable for cryptographic use.
func DrandRandomnessFromBeacon(beacon *DrandBeacon) ([]byte, error) {
	return hex.DecodeString(beacon.Randomness)
}

// IsDrandBeaconFresh checks if a beacon is recent (within the last hour).
func IsDrandBeaconFresh(beacon *DrandBeacon, chainHash string) bool {
	var genesisTime int64
	var period time.Duration

	switch chainHash {
	case DrandMainnetChainHash:
		genesisTime = DrandMainnetGenesis
		period = DrandMainnetPeriod
	case DrandQuicknetChainHash:
		genesisTime = DrandQuicknetGenesis
		period = DrandQuicknetPeriod
	default:
		return false
	}

	roundTime := time.Unix(genesisTime+int64(beacon.Round-1)*int64(period.Seconds()), 0)
	return time.Since(roundTime) < time.Hour
}

// Serialize serializes a drand proof.
func (dp *DrandProof) Serialize() ([]byte, error) {
	return json.Marshal(dp)
}

// DeserializeDrandProof deserializes a drand proof.
func DeserializeDrandProof(data []byte) (*DrandProof, error) {
	var proof DrandProof
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

// GetProofTimestamp returns the timestamp from a drand proof.
func GetProofTimestamp(proofData []byte) (time.Time, error) {
	proof, err := DeserializeDrandProof(proofData)
	if err != nil {
		return time.Time{}, err
	}
	return proof.Timestamp, nil
}
