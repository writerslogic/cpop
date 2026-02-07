// Package hardware provides software-based PUF fallback implementation.
//
// This file implements a software PUF that generates consistent device
// identity through device fingerprinting. While not as secure as hardware
// PUFs, it provides a consistent fallback for platforms without hardware
// security features.
//
// Security Considerations:
// - The seed file can be copied to another device (unlike hardware PUF)
// - Provides device identity but weaker anti-cloning guarantees
// - Should be used only when hardware options are unavailable
// - Recommended to encrypt seed with user password for additional protection
package hardware

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Software PUF errors
var (
	ErrSoftwarePUFSeedCorrupted = errors.New("hardware: software PUF seed file corrupted")
	ErrSoftwarePUFSeedMissing   = errors.New("hardware: software PUF seed file missing")
	ErrSoftwarePUFWriteFailed   = errors.New("hardware: failed to write software PUF seed")
)

// SoftwarePUFConfig configures the software PUF.
type SoftwarePUFConfig struct {
	// SeedPath is the path to store the seed file
	SeedPath string

	// IncludeMAC includes MAC addresses in fingerprint (may change with network adapters)
	IncludeMAC bool

	// IncludeDiskSerial includes disk serial numbers (requires root on some platforms)
	IncludeDiskSerial bool

	// IncludeHostID includes OS-provided host ID
	IncludeHostID bool

	// MigrationEnabled allows migration from one seed to another
	MigrationEnabled bool

	// PasswordProtect encrypts the seed with a password
	PasswordProtect bool
}

// DefaultSoftwarePUFConfig returns sensible defaults.
func DefaultSoftwarePUFConfig() SoftwarePUFConfig {
	return SoftwarePUFConfig{
		SeedPath:          getDefaultSeedPath(),
		IncludeMAC:        false, // Can change if network adapters change
		IncludeDiskSerial: false, // Requires elevated privileges
		IncludeHostID:     true,
		MigrationEnabled:  false,
		PasswordProtect:   false,
	}
}

// getDefaultSeedPath returns the default seed path based on platform.
func getDefaultSeedPath() string {
	// Check for override via environment variable (used by sandboxed macOS app)
	if envDir := os.Getenv("WITNESSD_DATA_DIR"); envDir != "" {
		return filepath.Join(envDir, ".puf_seed")
	}

	var baseDir string
	switch runtime.GOOS {
	case "darwin":
		homeDir, _ := os.UserHomeDir()
		baseDir = filepath.Join(homeDir, "Library", "Application Support", "witnessd")
	case "linux":
		// XDG_DATA_HOME or ~/.local/share
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			baseDir = filepath.Join(xdg, "witnessd")
		} else {
			homeDir, _ := os.UserHomeDir()
			baseDir = filepath.Join(homeDir, ".local", "share", "witnessd")
		}
	case "windows":
		baseDir = filepath.Join(os.Getenv("LOCALAPPDATA"), "witnessd")
	default:
		homeDir, _ := os.UserHomeDir()
		baseDir = filepath.Join(homeDir, ".witnessd")
	}

	return filepath.Join(baseDir, ".puf_seed")
}

// SoftwarePUF implements PUF interface using software-based device fingerprinting.
type SoftwarePUF struct {
	mu sync.RWMutex

	config   SoftwarePUFConfig
	seed     [32]byte
	deviceID string
	loaded   bool

	// Device fingerprint attributes
	fingerprint map[string]string
}

// NewSoftwarePUF creates a new software PUF with default configuration.
func NewSoftwarePUF() (*SoftwarePUF, error) {
	return NewSoftwarePUFWithConfig(DefaultSoftwarePUFConfig())
}

// NewSoftwarePUFWithConfig creates a software PUF with custom configuration.
func NewSoftwarePUFWithConfig(config SoftwarePUFConfig) (*SoftwarePUF, error) {
	puf := &SoftwarePUF{
		config:      config,
		fingerprint: make(map[string]string),
	}

	// Collect device fingerprint
	if err := puf.collectFingerprint(); err != nil {
		return nil, fmt.Errorf("failed to collect fingerprint: %w", err)
	}

	// Load or create seed
	if err := puf.loadOrCreateSeed(); err != nil {
		return nil, fmt.Errorf("failed to initialize seed: %w", err)
	}

	return puf, nil
}

// NewSoftwarePUFFromSeed creates a software PUF from an existing seed (for testing/migration).
func NewSoftwarePUFFromSeed(seed [32]byte, deviceID string) *SoftwarePUF {
	return &SoftwarePUF{
		config:   DefaultSoftwarePUFConfig(),
		seed:     seed,
		deviceID: deviceID,
		loaded:   true,
		fingerprint: map[string]string{
			"source": "imported",
		},
	}
}

// collectFingerprint gathers device attributes for fingerprinting.
func (p *SoftwarePUF) collectFingerprint() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Basic system info (always included)
	p.fingerprint["os"] = runtime.GOOS
	p.fingerprint["arch"] = runtime.GOARCH

	// Hostname
	if hostname, err := os.Hostname(); err == nil {
		p.fingerprint["hostname"] = hostname
	}

	// Home directory
	if home, err := os.UserHomeDir(); err == nil {
		p.fingerprint["home"] = home
	}

	// Executable path
	if exe, err := os.Executable(); err == nil {
		p.fingerprint["exe"] = exe
	}

	// User info
	p.fingerprint["uid"] = fmt.Sprintf("%d", os.Getuid())
	p.fingerprint["gid"] = fmt.Sprintf("%d", os.Getgid())

	// MAC addresses (if enabled)
	if p.config.IncludeMAC {
		if macs := getMACAddresses(); len(macs) > 0 {
			p.fingerprint["macs"] = strings.Join(macs, ",")
		}
	}

	// Disk serial (if enabled)
	if p.config.IncludeDiskSerial {
		if serial := getDiskSerial(); serial != "" {
			p.fingerprint["disk_serial"] = serial
		}
	}

	// Host ID (if enabled)
	if p.config.IncludeHostID {
		if hostID := getHostID(); hostID != "" {
			p.fingerprint["host_id"] = hostID
		}
	}

	return nil
}

// loadOrCreateSeed loads an existing seed or creates a new one.
func (p *SoftwarePUF) loadOrCreateSeed() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Ensure directory exists
	dir := filepath.Dir(p.config.SeedPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Try to load existing seed
	if data, err := os.ReadFile(p.config.SeedPath); err == nil {
		if len(data) == 32 {
			copy(p.seed[:], data)
			p.computeDeviceID()
			p.loaded = true
			return nil
		} else if len(data) > 0 {
			// File exists but wrong size
			return ErrSoftwarePUFSeedCorrupted
		}
	}

	// Generate new seed
	if err := p.generateSeed(); err != nil {
		return err
	}

	// Save seed atomically
	tmpPath := p.config.SeedPath + ".tmp." + fmt.Sprintf("%d", time.Now().UnixNano())
	if err := os.WriteFile(tmpPath, p.seed[:], 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrSoftwarePUFWriteFailed, err)
	}
	if err := os.Rename(tmpPath, p.config.SeedPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("%w: %v", ErrSoftwarePUFWriteFailed, err)
	}

	p.computeDeviceID()
	p.loaded = true
	return nil
}

// generateSeed creates a new seed with entropy from multiple sources.
func (p *SoftwarePUF) generateSeed() error {
	h := sha256.New()

	// Primary entropy: cryptographic random
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return fmt.Errorf("random generation failed: %w", err)
	}
	h.Write(randomBytes)

	// Domain separation
	h.Write([]byte("witnessd-software-puf-v1"))

	// Include all fingerprint attributes
	for k, v := range p.fingerprint {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(v))
		h.Write([]byte{0})
	}

	// Creation timestamp for uniqueness
	h.Write([]byte(time.Now().Format(time.RFC3339Nano)))

	// Process ID for additional uniqueness
	h.Write([]byte(fmt.Sprintf("%d", os.Getpid())))

	copy(p.seed[:], h.Sum(nil))
	return nil
}

// computeDeviceID generates the device ID from the seed.
func (p *SoftwarePUF) computeDeviceID() {
	h := sha256.Sum256(p.seed[:])
	p.deviceID = fmt.Sprintf("swpuf-%s", hex.EncodeToString(h[:8]))
}

// Type implements PUF.Type.
func (p *SoftwarePUF) Type() PUFType {
	return PUFTypeSoftware
}

// DeviceID implements PUF.DeviceID.
func (p *SoftwarePUF) DeviceID() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.deviceID
}

// Challenge implements PUF.Challenge.
func (p *SoftwarePUF) Challenge(challenge []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.loaded {
		return nil, ErrSoftwarePUFSeedMissing
	}

	if len(challenge) == 0 {
		return nil, ErrPUFChallengeInvalid
	}

	// Use HKDF to derive response from seed and challenge
	reader := hkdf.New(sha256.New, p.seed[:], challenge, []byte("software-puf-response-v1"))

	response := make([]byte, 32)
	if _, err := io.ReadFull(reader, response); err != nil {
		return nil, fmt.Errorf("HKDF expand failed: %w", err)
	}

	return response, nil
}

// Capabilities implements PUF.Capabilities.
func (p *SoftwarePUF) Capabilities() PUFCapabilities {
	return PUFCapabilities{
		Type:                 PUFTypeSoftware,
		SecurityLevel:        SecurityLevelSoftware,
		SupportsAttestation:  false,
		SupportsBiometric:    false,
		SupportsKeyGeneration: true,
		SupportsSealing:      false,
		MaxChallengeSize:     4096,
		ResponseSize:         32,
		Description:          "Software-based PUF using device fingerprinting",
	}
}

// Available implements PUF.Available.
func (p *SoftwarePUF) Available() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.loaded
}

// Close implements PUF.Close.
func (p *SoftwarePUF) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Securely wipe the seed from memory
	for i := range p.seed {
		p.seed[i] = 0
	}
	p.loaded = false
	return nil
}

// Fingerprint returns the collected device fingerprint (for debugging).
func (p *SoftwarePUF) Fingerprint() map[string]string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make(map[string]string, len(p.fingerprint))
	for k, v := range p.fingerprint {
		result[k] = v
	}
	return result
}

// SeedPath returns the path where the seed is stored.
func (p *SoftwarePUF) SeedPath() string {
	return p.config.SeedPath
}

// ExportSeed exports the seed for backup (use with extreme caution).
func (p *SoftwarePUF) ExportSeed() ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.loaded {
		return nil, ErrSoftwarePUFSeedMissing
	}

	result := make([]byte, 32)
	copy(result, p.seed[:])
	return result, nil
}

// ImportSeed imports a seed from backup.
func (p *SoftwarePUF) ImportSeed(seed []byte) error {
	if len(seed) != 32 {
		return ErrSoftwarePUFSeedCorrupted
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	copy(p.seed[:], seed)
	p.computeDeviceID()
	p.loaded = true

	// Save to disk
	tmpPath := p.config.SeedPath + ".tmp." + fmt.Sprintf("%d", time.Now().UnixNano())
	if err := os.WriteFile(tmpPath, p.seed[:], 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrSoftwarePUFWriteFailed, err)
	}
	if err := os.Rename(tmpPath, p.config.SeedPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("%w: %v", ErrSoftwarePUFWriteFailed, err)
	}

	return nil
}

// MigrateTo migrates from this PUF to a hardware PUF.
func (p *SoftwarePUF) MigrateTo(newPUF PUF) (*PUFMigrationRecord, error) {
	if !p.config.MigrationEnabled {
		return nil, errors.New("migration not enabled for this PUF")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Generate migration challenge
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, err
	}

	// Get responses from both PUFs
	oldResponse, err := p.Challenge(challenge[:])
	if err != nil {
		return nil, fmt.Errorf("old PUF challenge failed: %w", err)
	}

	newResponse, err := newPUF.Challenge(challenge[:])
	if err != nil {
		return nil, fmt.Errorf("new PUF challenge failed: %w", err)
	}

	// Create migration record
	record := &PUFMigrationRecord{
		MigrationID:   generateMigrationID(),
		Timestamp:     time.Now(),
		OldDeviceID:   p.deviceID,
		NewDeviceID:   newPUF.DeviceID(),
		OldPUFType:    p.Type(),
		NewPUFType:    newPUF.Type(),
		Challenge:     challenge[:],
		OldResponse:   oldResponse,
		NewResponse:   newResponse,
	}

	// Sign the migration
	record.ComputeSignature(p.seed[:])

	return record, nil
}

// PUFMigrationRecord records a migration from one PUF to another.
type PUFMigrationRecord struct {
	MigrationID string    `json:"migration_id"`
	Timestamp   time.Time `json:"timestamp"`
	OldDeviceID string    `json:"old_device_id"`
	NewDeviceID string    `json:"new_device_id"`
	OldPUFType  PUFType   `json:"old_puf_type"`
	NewPUFType  PUFType   `json:"new_puf_type"`
	Challenge   []byte    `json:"challenge"`
	OldResponse []byte    `json:"old_response"`
	NewResponse []byte    `json:"new_response"`
	Signature   []byte    `json:"signature"`
}

// ComputeSignature signs the migration record.
func (r *PUFMigrationRecord) ComputeSignature(key []byte) {
	h := sha256.New()
	h.Write([]byte("witnessd-migration-v1"))
	h.Write([]byte(r.MigrationID))
	h.Write([]byte(r.OldDeviceID))
	h.Write([]byte(r.NewDeviceID))
	h.Write(r.Challenge)
	h.Write(r.OldResponse)
	h.Write(r.NewResponse)

	// HMAC with old PUF key
	mac := sha256.New()
	mac.Write(key)
	mac.Write(h.Sum(nil))
	r.Signature = mac.Sum(nil)
}

// VerifySignature verifies the migration record signature.
func (r *PUFMigrationRecord) VerifySignature(key []byte) bool {
	h := sha256.New()
	h.Write([]byte("witnessd-migration-v1"))
	h.Write([]byte(r.MigrationID))
	h.Write([]byte(r.OldDeviceID))
	h.Write([]byte(r.NewDeviceID))
	h.Write(r.Challenge)
	h.Write(r.OldResponse)
	h.Write(r.NewResponse)

	mac := sha256.New()
	mac.Write(key)
	mac.Write(h.Sum(nil))
	expected := mac.Sum(nil)

	if len(r.Signature) != len(expected) {
		return false
	}
	for i := range expected {
		if r.Signature[i] != expected[i] {
			return false
		}
	}
	return true
}

// generateMigrationID generates a unique migration ID.
func generateMigrationID() string {
	var buf [16]byte
	rand.Read(buf[:])
	return fmt.Sprintf("mig-%s-%d", hex.EncodeToString(buf[:8]), time.Now().Unix())
}

// Helper functions for device fingerprinting

// getMACAddresses returns all MAC addresses on the system.
func getMACAddresses() []string {
	var macs []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range interfaces {
		// Skip loopback and virtual interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		// Skip virtual adapters (common patterns)
		name := strings.ToLower(iface.Name)
		if strings.HasPrefix(name, "veth") ||
			strings.HasPrefix(name, "docker") ||
			strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "virbr") {
			continue
		}

		macs = append(macs, iface.HardwareAddr.String())
	}

	return macs
}

// getDiskSerial returns the primary disk serial number (platform-specific).
func getDiskSerial() string {
	// Platform-specific implementations in separate files
	return getDiskSerialPlatform()
}

// getHostID returns the system host ID (platform-specific).
func getHostID() string {
	// Platform-specific implementations in separate files
	return getHostIDPlatform()
}

// Platform-specific stubs (implemented in platform files)

func getDiskSerialPlatform() string {
	return "" // Override in platform-specific files
}

func getHostIDPlatform() string {
	return "" // Override in platform-specific files
}
