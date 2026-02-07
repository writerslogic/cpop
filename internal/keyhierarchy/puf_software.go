// Package keyhierarchy implements a three-tier ratcheting key hierarchy for witnessd.
//
// This file provides a software-based PUF fallback for platforms without
// hardware security modules. While this provides weaker guarantees than
// hardware PUFs, it still offers consistent device identity.
//
// Patent Pending: USPTO Application No. 19/460,364
package keyhierarchy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Errors for software PUF operations
var (
	ErrSoftwarePUFInit = errors.New("keyhierarchy: failed to initialize software PUF")
)

// SoftwarePUF implements PUFProvider using software-based device fingerprinting.
// WARNING: This provides weaker guarantees than hardware PUFs. The seed file
// can be copied to another device, unlike hardware-bound secrets.
type SoftwarePUF struct {
	mu       sync.Mutex
	deviceID string
	seed     []byte
	seedPath string
}

// softwarePUFSeedName is the filename for the software PUF seed
const softwarePUFSeedName = "puf_seed"

// NewSoftwarePUF creates a software PUF from the default seed path.
func NewSoftwarePUF() (*SoftwarePUF, error) {
	witnessdDir := getWitnessdDir()
	seedPath := filepath.Join(witnessdDir, softwarePUFSeedName)
	return NewSoftwarePUFWithPath(seedPath)
}

// NewSoftwarePUFWithPath creates a software PUF with a specific seed path.
func NewSoftwarePUFWithPath(seedPath string) (*SoftwarePUF, error) {
	puf := &SoftwarePUF{
		seedPath: seedPath,
	}

	if err := puf.loadOrCreateSeed(); err != nil {
		return nil, fmt.Errorf("failed to initialize software PUF: %w", err)
	}

	return puf, nil
}

// NewSoftwarePUFFromSeed creates a software PUF from an existing seed.
// This is useful for testing or migration scenarios.
func NewSoftwarePUFFromSeed(deviceID string, seed []byte) *SoftwarePUF {
	seedCopy := make([]byte, len(seed))
	copy(seedCopy, seed)

	return &SoftwarePUF{
		deviceID: deviceID,
		seed:     seedCopy,
	}
}

// loadOrCreateSeed loads an existing seed or creates a new one
func (p *SoftwarePUF) loadOrCreateSeed() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Ensure directory exists
	dir := filepath.Dir(p.seedPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Try to load existing seed
	if data, err := os.ReadFile(p.seedPath); err == nil && len(data) == 32 {
		p.seed = data
		p.deviceID = p.computeDeviceID()
		return nil
	}

	// Generate new seed with high entropy
	seed, err := p.generateSeed()
	if err != nil {
		return fmt.Errorf("failed to generate seed: %w", err)
	}

	// Save seed atomically
	tmpPath := p.seedPath + ".tmp"
	if err := os.WriteFile(tmpPath, seed, 0600); err != nil {
		return fmt.Errorf("failed to write seed: %w", err)
	}
	if err := os.Rename(tmpPath, p.seedPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to save seed: %w", err)
	}

	p.seed = seed
	p.deviceID = p.computeDeviceID()
	return nil
}

// generateSeed creates a new seed with entropy from multiple sources
func (p *SoftwarePUF) generateSeed() ([]byte, error) {
	h := sha256.New()

	// Primary entropy: cryptographic random
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("random generation failed: %w", err)
	}
	h.Write(randomBytes)

	// Domain separation
	h.Write([]byte("witnessd-software-puf-v1"))

	// System characteristics for additional uniqueness
	// These don't provide security, but help with uniqueness
	hostname, _ := os.Hostname()
	h.Write([]byte(hostname))

	home, _ := os.UserHomeDir()
	h.Write([]byte(home))

	exe, _ := os.Executable()
	h.Write([]byte(exe))

	// Platform info
	h.Write([]byte(runtime.GOOS))
	h.Write([]byte(runtime.GOARCH))

	// Creation timestamp for uniqueness
	h.Write([]byte(time.Now().Format(time.RFC3339Nano)))

	return h.Sum(nil), nil
}

// computeDeviceID generates the device ID from the seed
func (p *SoftwarePUF) computeDeviceID() string {
	h := sha256.Sum256(p.seed)
	return fmt.Sprintf("swpuf-%s", hex.EncodeToString(h[:4]))
}

// GetResponse returns a deterministic response for a challenge.
// Uses HKDF to derive a response from the seed and challenge.
func (p *SoftwarePUF) GetResponse(challenge []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.seed) == 0 {
		return nil, ErrSoftwarePUFInit
	}

	// Use HKDF to derive a response
	reader := hkdf.New(sha256.New, p.seed, challenge, []byte("puf-response-v1"))

	response := make([]byte, 32)
	if _, err := io.ReadFull(reader, response); err != nil {
		return nil, fmt.Errorf("HKDF expand failed: %w", err)
	}

	return response, nil
}

// DeviceID returns the device identifier.
func (p *SoftwarePUF) DeviceID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.deviceID
}

// Seed returns a copy of the PUF seed.
// WARNING: Handle this value carefully; it represents the device identity.
func (p *SoftwarePUF) Seed() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]byte, len(p.seed))
	copy(result, p.seed)
	return result
}

// SeedPath returns the path where the seed is stored.
func (p *SoftwarePUF) SeedPath() string {
	return p.seedPath
}

// getWitnessdDir returns the witnessd data directory
func getWitnessdDir() string {
	// Check for override via environment variable (used by sandboxed macOS app)
	if envDir := os.Getenv("WITNESSD_DATA_DIR"); envDir != "" {
		return envDir
	}
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".witnessd")
}

// GetOrCreatePUF returns the best available PUF for the current platform.
// It tries hardware PUF first, then falls back to software PUF.
func GetOrCreatePUF() (PUFProvider, error) {
	// Try hardware PUF first
	hwPUF, err := DetectHardwarePUF()
	if err == nil {
		return hwPUF, nil
	}

	// Fall back to software PUF
	return NewSoftwarePUF()
}

// secureWipeSoftware overwrites memory with zeros to prevent recovery.
// This is a platform-independent implementation for the software PUF.
// Note: Uses a different name to avoid redeclaration with keyhierarchy.go
func secureWipeSoftware(data []byte) {
	secureWipe(data)
}
