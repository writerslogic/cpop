// Package anchors provides a drand beacon anchor provider.
//
// drand (https://drand.love) is a distributed randomness beacon operated by
// the League of Entropy. Unlike traditional timestamp services, drand provides
// publicly verifiable randomness every few seconds, which can be used to prove
// that data existed AFTER a specific point in time.
//
// Key characteristics:
// - FREE: No cost to use
// - DECENTRALIZED: Operated by League of Entropy consortium
// - FREQUENT: New beacons every 3 seconds (fastnet) or 30 seconds (mainnet)
// - NO SUBMISSION: Unlike TSAs, you don't submit data - you bind to published beacons
//
// How it works:
// 1. Fetch the latest beacon from drand
// 2. Compute commitment: hash(your_data || beacon_randomness)
// 3. Store the beacon round/randomness and commitment
// 4. Verification: re-fetch beacon for that round, recompute commitment
//
// This proves your data existed after the beacon was published (lower bound on time).
// Combine with OpenTimestamps for upper bound to bracket the time window.
package anchors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DrandConfig configures the drand anchor provider.
type DrandConfig struct {
	// Endpoints for drand HTTP API (multiple for redundancy)
	Endpoints []string `json:"endpoints,omitempty"`

	// ChainHash identifies which drand network to use
	ChainHash string `json:"chain_hash,omitempty"`

	// Timeout for HTTP requests
	Timeout time.Duration `json:"timeout,omitempty"`
}

// DrandProvider implements the Provider interface for drand beacons.
type DrandProvider struct {
	config     DrandConfig
	httpClient *http.Client
	chainInfo  *drandChainInfo
}

// drandChainInfo contains network metadata.
type drandChainInfo struct {
	PublicKey   string `json:"public_key"`
	Period      int    `json:"period"`
	GenesisTime int64  `json:"genesis_time"`
	Hash        string `json:"hash"`
	SchemeID    string `json:"schemeID"`
}

// drandBeaconJSON is the JSON representation from the API.
type drandBeaconJSON struct {
	Round             uint64 `json:"round"`
	Randomness        string `json:"randomness"`
	Signature         string `json:"signature"`
	PreviousSignature string `json:"previous_signature,omitempty"`
}

// defaultDrandEndpoints for League of Entropy mainnet.
var defaultDrandEndpoints = []string{
	"https://api.drand.sh",
	"https://drand.cloudflare.com",
	"https://api2.drand.sh",
	"https://api3.drand.sh",
}

// Fastnet chain hash (3-second rounds)
const fastnetChainHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

// NewDrandProvider creates a new drand anchor provider with default config.
func NewDrandProvider() *DrandProvider {
	return &DrandProvider{
		config: DrandConfig{
			Endpoints: defaultDrandEndpoints,
			ChainHash: fastnetChainHash,
			Timeout:   10 * time.Second,
		},
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Name returns the provider identifier.
func (p *DrandProvider) Name() string {
	return "drand"
}

// DisplayName returns a human-readable name.
func (p *DrandProvider) DisplayName() string {
	return "drand (League of Entropy)"
}

// Type returns the provider category.
func (p *DrandProvider) Type() ProviderType {
	return TypeDecentralized
}

// Regions returns jurisdictions where this provider has legal standing.
func (p *DrandProvider) Regions() []string {
	return []string{"GLOBAL"}
}

// LegalStanding returns the legal recognition level.
func (p *DrandProvider) LegalStanding() LegalStanding {
	// drand provides cryptographic proof of time ordering
	// but doesn't have explicit legal framework like RFC 3161
	return StandingEvidentiary
}

// RequiresPayment indicates if this provider charges fees.
func (p *DrandProvider) RequiresPayment() bool {
	return false
}

// RequiresNetwork indicates if this provider needs internet access.
func (p *DrandProvider) RequiresNetwork() bool {
	return true
}

// RequiresCredentials indicates if API keys/certificates are needed.
func (p *DrandProvider) RequiresCredentials() bool {
	return false
}

// Configure sets provider-specific configuration.
func (p *DrandProvider) Configure(config map[string]interface{}) error {
	if endpoints, ok := config["endpoints"].([]string); ok && len(endpoints) > 0 {
		p.config.Endpoints = endpoints
	}
	if chainHash, ok := config["chain_hash"].(string); ok && chainHash != "" {
		p.config.ChainHash = chainHash
	}
	if timeout, ok := config["timeout"].(time.Duration); ok && timeout > 0 {
		p.config.Timeout = timeout
		p.httpClient.Timeout = timeout
	}
	return nil
}

// Timestamp creates a drand-based temporal anchor.
// Unlike traditional TSAs, this binds your hash to a publicly verifiable beacon.
func (p *DrandProvider) Timestamp(ctx context.Context, hash [32]byte) (*Proof, error) {
	// Fetch the latest beacon
	beacon, err := p.fetchLatestBeacon(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch drand beacon: %w", err)
	}

	// Decode randomness from hex
	randomness, err := hex.DecodeString(beacon.Randomness)
	if err != nil {
		return nil, fmt.Errorf("invalid beacon randomness: %w", err)
	}

	// Create commitment: hash(data_hash || beacon_randomness)
	h := sha256.New()
	h.Write(hash[:])
	h.Write(randomness)
	commitment := h.Sum(nil)

	// Calculate expected beacon time
	beaconTime := p.roundToTime(beacon.Round)

	// Build the proof
	proof := &Proof{
		Provider:  "drand",
		Version:   1,
		Hash:      hash,
		Timestamp: beaconTime,
		Status:    StatusConfirmed, // drand beacons are immediately verifiable
		Metadata: map[string]interface{}{
			"chain_hash":  p.config.ChainHash,
			"round":       beacon.Round,
			"randomness":  beacon.Randomness,
			"signature":   beacon.Signature,
			"commitment":  hex.EncodeToString(commitment),
		},
		VerifyURL: fmt.Sprintf("https://api.drand.sh/%s/public/%d", p.config.ChainHash, beacon.Round),
	}

	// Serialize beacon data as raw proof
	beaconData, _ := json.Marshal(beacon)
	proof.RawProof = beaconData

	return proof, nil
}

// Verify checks a drand proof.
func (p *DrandProvider) Verify(ctx context.Context, proof *Proof) (*VerifyResult, error) {
	if proof == nil || proof.Provider != "drand" {
		return nil, ErrInvalidProof
	}

	// Extract metadata
	chainHash, _ := proof.Metadata["chain_hash"].(string)
	roundFloat, _ := proof.Metadata["round"].(float64)
	round := uint64(roundFloat)
	storedRandomness, _ := proof.Metadata["randomness"].(string)
	storedCommitment, _ := proof.Metadata["commitment"].(string)

	if round == 0 || storedRandomness == "" {
		return nil, ErrInvalidProof
	}

	// Fetch the beacon for this round to verify
	beacon, err := p.fetchBeaconByRound(ctx, round)
	if err != nil {
		return &VerifyResult{
			Valid:        false,
			VerifiedHash: proof.Hash,
			Provider:     "drand",
			Status:       StatusFailed,
			Error:        fmt.Sprintf("failed to fetch beacon for round %d: %v", round, err),
		}, nil
	}

	// Verify randomness matches
	if beacon.Randomness != storedRandomness {
		return &VerifyResult{
			Valid:        false,
			VerifiedHash: proof.Hash,
			Provider:     "drand",
			Status:       StatusFailed,
			Error:        "beacon randomness mismatch",
		}, nil
	}

	// Verify commitment
	randomness, _ := hex.DecodeString(beacon.Randomness)
	h := sha256.New()
	h.Write(proof.Hash[:])
	h.Write(randomness)
	expectedCommitment := hex.EncodeToString(h.Sum(nil))

	if storedCommitment != expectedCommitment {
		return &VerifyResult{
			Valid:        false,
			VerifiedHash: proof.Hash,
			Provider:     "drand",
			Status:       StatusFailed,
			Error:        "commitment verification failed",
		}, nil
	}

	// Calculate beacon time
	beaconTime := p.roundToTime(round)

	result := &VerifyResult{
		Valid:        true,
		Timestamp:    beaconTime,
		VerifiedHash: proof.Hash,
		Provider:     "drand",
		Status:       StatusConfirmed,
	}

	// Add warning if chain hash changed
	if chainHash != "" && chainHash != p.config.ChainHash {
		result.Warnings = append(result.Warnings, "proof uses different chain hash than current config")
	}

	return result, nil
}

// Upgrade is a no-op for drand (proofs are immediately confirmed).
func (p *DrandProvider) Upgrade(ctx context.Context, proof *Proof) (*Proof, error) {
	// drand proofs don't need upgrading
	return proof, nil
}

// Status returns the current provider status.
func (p *DrandProvider) Status(ctx context.Context) (*ProviderStatus, error) {
	// Try to fetch chain info
	info, err := p.fetchChainInfo(ctx)
	if err != nil {
		return &ProviderStatus{
			Available:  false,
			Configured: true,
			LastCheck:  time.Now(),
			Message:    fmt.Sprintf("failed to connect: %v", err),
		}, nil
	}

	return &ProviderStatus{
		Available:  true,
		Configured: true,
		LastCheck:  time.Now(),
		Message:    fmt.Sprintf("connected to %s (period: %ds)", info.SchemeID, info.Period),
	}, nil
}

// fetchChainInfo retrieves chain metadata.
func (p *DrandProvider) fetchChainInfo(ctx context.Context) (*drandChainInfo, error) {
	var lastErr error
	for _, endpoint := range p.config.Endpoints {
		url := fmt.Sprintf("%s/%s/info", endpoint, p.config.ChainHash)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			lastErr = err
			continue
		}

		resp, err := p.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
			continue
		}

		var info drandChainInfo
		if err := json.Unmarshal(body, &info); err != nil {
			lastErr = err
			continue
		}

		p.chainInfo = &info
		return &info, nil
	}

	return nil, fmt.Errorf("all endpoints failed: %w", lastErr)
}

// fetchLatestBeacon retrieves the most recent beacon.
func (p *DrandProvider) fetchLatestBeacon(ctx context.Context) (*drandBeaconJSON, error) {
	return p.fetchBeacon(ctx, 0)
}

// fetchBeaconByRound retrieves a specific beacon.
func (p *DrandProvider) fetchBeaconByRound(ctx context.Context, round uint64) (*drandBeaconJSON, error) {
	return p.fetchBeacon(ctx, round)
}

// fetchBeacon retrieves a beacon (0 = latest).
func (p *DrandProvider) fetchBeacon(ctx context.Context, round uint64) (*drandBeaconJSON, error) {
	var lastErr error

	for _, endpoint := range p.config.Endpoints {
		var url string
		if round == 0 {
			url = fmt.Sprintf("%s/%s/public/latest", endpoint, p.config.ChainHash)
		} else {
			url = fmt.Sprintf("%s/%s/public/%d", endpoint, p.config.ChainHash, round)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			lastErr = err
			continue
		}

		resp, err := p.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
			continue
		}

		var beacon drandBeaconJSON
		if err := json.Unmarshal(body, &beacon); err != nil {
			lastErr = err
			continue
		}

		return &beacon, nil
	}

	return nil, fmt.Errorf("all endpoints failed: %w", lastErr)
}

// roundToTime converts a beacon round to its expected timestamp.
func (p *DrandProvider) roundToTime(round uint64) time.Time {
	if p.chainInfo == nil {
		// Default to fastnet parameters
		genesisTime := int64(1692803367) // Fastnet genesis
		period := int64(3)               // 3-second rounds
		return time.Unix(genesisTime+int64(round)*period, 0)
	}

	genesisTime := p.chainInfo.GenesisTime
	period := int64(p.chainInfo.Period)
	return time.Unix(genesisTime+int64(round)*period, 0)
}

// init registers the drand provider with the default registry.
func init() {
	// Will be called by RegisterDefaults
}
