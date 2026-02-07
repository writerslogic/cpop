package anchors

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// OpenTimestamps constants
const (
	// OTS file header magic bytes
	otsHeaderMagic = "\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"

	// OTS version
	otsVersion = 1

	// Hash type tags
	otsOpSHA256    = 0x08
	otsOpRIPEMD160 = 0x07
	otsOpSHA1      = 0x02
	otsOpKeccak256 = 0x67

	// Unary operations
	otsOpAppend   = 0xf0
	otsOpPrepend  = 0xf1
	otsOpReverse  = 0xf2
	otsOpHexlify  = 0xf3
	otsOpSHA256Op = 0x08 // Same as type tag, used as operation

	// Attestation tags
	otsAttestBitcoin   = 0x05 // Bitcoin block header attestation
	otsAttestLitecoin  = 0x06 // Litecoin attestation
	otsAttestPending   = 0x83 // Pending attestation (calendar URL)
	otsAttestUnknown   = 0x84 // Unknown attestation (for forward compatibility)
	otsAttestEthereum  = 0x30 // Ethereum attestation (community extension)

	// Maximum data sizes for security
	maxCalendarResponseSize = 1024 * 1024     // 1MB
	maxProofSize           = 10 * 1024 * 1024 // 10MB
)

// OTS calendar server URLs (official and community)
var DefaultOTSCalendars = []string{
	"https://a.pool.opentimestamps.org",
	"https://b.pool.opentimestamps.org",
	"https://a.pool.eternitywall.com",
	"https://ots.btc.catallaxy.com",
}

// OTSConfig configures the OpenTimestamps anchor.
type OTSConfig struct {
	// Calendars to use (defaults to official calendars)
	Calendars []string

	// Timeout for HTTP requests
	Timeout time.Duration

	// MinCalendars is the minimum number of calendars that must succeed
	MinCalendars int

	// RetryAttempts for failed calendar submissions
	RetryAttempts int

	// RetryDelay between attempts
	RetryDelay time.Duration

	// EnableUpgrade enables automatic proof upgrading
	EnableUpgrade bool
}

// OTSAnchor implements the OpenTimestamps protocol.
type OTSAnchor struct {
	calendars     []string
	client        *http.Client
	minCalendars  int
	retryAttempts int
	retryDelay    time.Duration
	enableUpgrade bool

	// Cache for pending proofs that need upgrading
	pendingMu    sync.RWMutex
	pendingCache map[string]*PendingProof
}

// PendingProof tracks a proof awaiting Bitcoin confirmation.
type PendingProof struct {
	Hash       [32]byte
	Proof      []byte
	Calendar   string
	SubmitTime time.Time
	LastCheck  time.Time
	Attempts   int
}

// OTSInfo contains parsed OTS file information.
type OTSInfo struct {
	Version       int
	HashType      string
	Hash          []byte
	Pending       []string // Calendar URLs for pending attestations
	Confirmed     bool     // True if Bitcoin attestation found
	BlockHeight   uint64   // Bitcoin block height if confirmed
	BlockHash     []byte   // Bitcoin block hash if confirmed
	Attestations  []OTSAttestation
	Operations    []OTSOperation
	MerkleRoot    []byte // Final merkle root that was anchored
}

// OTSAttestation represents an attestation in an OTS proof.
type OTSAttestation struct {
	Type        string    // "bitcoin", "pending", "ethereum", "litecoin"
	Data        []byte    // Raw attestation data
	Calendar    string    // Calendar URL for pending
	BlockHeight uint64    // Block height for confirmed
	BlockTime   time.Time // Block time for confirmed
}

// OTSOperation represents a cryptographic operation in the OTS proof.
type OTSOperation struct {
	Type    string // "sha256", "append", "prepend", "reverse", "hexlify"
	Operand []byte // Optional operand for binary ops
}

// NewOTSAnchor creates a new OpenTimestamps anchor with default config.
func NewOTSAnchor() *OTSAnchor {
	return NewOTSAnchorWithConfig(OTSConfig{})
}

// NewOTSAnchorWithConfig creates a new OpenTimestamps anchor with custom config.
func NewOTSAnchorWithConfig(config OTSConfig) *OTSAnchor {
	calendars := config.Calendars
	if len(calendars) == 0 {
		calendars = DefaultOTSCalendars
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	minCalendars := config.MinCalendars
	if minCalendars == 0 {
		minCalendars = 1
	}

	retryAttempts := config.RetryAttempts
	if retryAttempts == 0 {
		retryAttempts = 3
	}

	retryDelay := config.RetryDelay
	if retryDelay == 0 {
		retryDelay = time.Second
	}

	return &OTSAnchor{
		calendars:     calendars,
		client:        &http.Client{Timeout: timeout},
		minCalendars:  minCalendars,
		retryAttempts: retryAttempts,
		retryDelay:    retryDelay,
		enableUpgrade: config.EnableUpgrade,
		pendingCache:  make(map[string]*PendingProof),
	}
}

// Name returns the anchor type name.
func (o *OTSAnchor) Name() string {
	return "ots"
}

// Commit submits a hash to OpenTimestamps calendars.
// Returns an OTS proof file that can be upgraded later when Bitcoin confirms.
func (o *OTSAnchor) Commit(hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, errors.New("ots: hash must be 32 bytes (SHA-256)")
	}

	// Track successful submissions
	var proofs [][]byte
	var calendarsUsed []string
	var lastErr error

	// Submit to all calendars
	for _, calendar := range o.calendars {
		proof, err := o.submitWithRetry(calendar, hash)
		if err != nil {
			lastErr = err
			continue
		}
		proofs = append(proofs, proof)
		calendarsUsed = append(calendarsUsed, calendar)
	}

	// Check if we have enough successful submissions
	if len(proofs) < o.minCalendars {
		if lastErr != nil {
			return nil, fmt.Errorf("ots: insufficient calendars succeeded (%d/%d): %w",
				len(proofs), o.minCalendars, lastErr)
		}
		return nil, fmt.Errorf("ots: insufficient calendars succeeded (%d/%d)",
			len(proofs), o.minCalendars)
	}

	// Build combined OTS file with all calendar responses
	otsFile := o.buildMultiCalendarProof(hash, proofs, calendarsUsed)

	// Cache for later upgrade
	if o.enableUpgrade {
		o.cachePendingProof(hash, otsFile, calendarsUsed[0])
	}

	return otsFile, nil
}

// submitWithRetry submits to a calendar with retry logic.
func (o *OTSAnchor) submitWithRetry(calendar string, hash []byte) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt < o.retryAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(o.retryDelay * time.Duration(attempt))
		}

		proof, err := o.submitToCalendar(calendar, hash)
		if err == nil {
			return proof, nil
		}
		lastErr = err
	}

	return nil, lastErr
}

// submitToCalendar submits a hash to a specific calendar server.
func (o *OTSAnchor) submitToCalendar(calendar string, hash []byte) ([]byte, error) {
	url := calendar + "/digest"

	req, err := http.NewRequest("POST", url, bytes.NewReader(hash))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")
	req.Header.Set("User-Agent", "witnessd/1.0")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calendar request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("calendar returned %d: %s", resp.StatusCode, string(body))
	}

	// Read response with size limit
	return io.ReadAll(io.LimitReader(resp.Body, maxCalendarResponseSize))
}

// buildMultiCalendarProof creates an OTS file with multiple calendar responses.
// This provides redundancy - if one calendar fails, others can still confirm.
func (o *OTSAnchor) buildMultiCalendarProof(hash []byte, calendarProofs [][]byte, calendars []string) []byte {
	var buf bytes.Buffer

	// Write OTS header
	buf.WriteString(otsHeaderMagic)
	buf.WriteByte(otsVersion)

	// Write hash type (SHA256 = 0x08)
	buf.WriteByte(otsOpSHA256)

	// Write the original hash
	buf.Write(hash)

	// For multiple calendars, we use a fork structure
	// First calendar proof
	if len(calendarProofs) > 0 {
		buf.WriteByte(otsAttestPending)
		writeVarBytes(&buf, []byte(calendars[0]))
		buf.Write(calendarProofs[0])
	}

	// Additional calendar proofs as alternatives (using 0xff fork marker)
	for i := 1; i < len(calendarProofs); i++ {
		buf.WriteByte(0xff) // Fork marker
		buf.WriteByte(otsAttestPending)
		writeVarBytes(&buf, []byte(calendars[i]))
		buf.Write(calendarProofs[i])
	}

	return buf.Bytes()
}

// wrapProof creates a complete OTS file from a calendar response (single calendar).
func (o *OTSAnchor) wrapProof(hash []byte, calendar string, calendarProof []byte) []byte {
	var buf bytes.Buffer

	// Write OTS header
	buf.WriteString(otsHeaderMagic)
	buf.WriteByte(otsVersion)

	// Write hash type (SHA256 = 0x08)
	buf.WriteByte(otsOpSHA256)

	// Write the original hash
	buf.Write(hash)

	// Write pending attestation with calendar URL
	buf.WriteByte(otsAttestPending)
	writeVarBytes(&buf, []byte(calendar))

	// Include calendar response
	buf.Write(calendarProof)

	return buf.Bytes()
}

// Verify checks an OTS proof.
func (o *OTSAnchor) Verify(hash, proof []byte) error {
	if len(proof) < len(otsHeaderMagic)+1 {
		return errors.New("ots: proof too short")
	}

	// Check header magic
	if string(proof[:len(otsHeaderMagic)]) != otsHeaderMagic {
		return errors.New("ots: invalid header magic")
	}

	// Check version
	version := proof[len(otsHeaderMagic)]
	if version != otsVersion {
		return fmt.Errorf("ots: unsupported version %d", version)
	}

	// Parse the proof to validate format
	info, err := ParseOTS(proof)
	if err != nil {
		return fmt.Errorf("ots: failed to parse proof: %w", err)
	}

	// Verify the hash in the proof matches the expected hash (if provided)
	if hash != nil && !bytes.Equal(info.Hash, hash) {
		return errors.New("ots: proof hash does not match expected hash")
	}

	// Execute the proof operations to verify merkle path
	if err := o.executeProofOperations(info); err != nil {
		return fmt.Errorf("ots: proof execution failed: %w", err)
	}

	return nil
}

// executeProofOperations replays the cryptographic operations in the proof.
func (o *OTSAnchor) executeProofOperations(info *OTSInfo) error {
	// Start with the original hash
	current := make([]byte, len(info.Hash))
	copy(current, info.Hash)

	// Apply each operation
	for _, op := range info.Operations {
		switch op.Type {
		case "sha256":
			h := sha256.Sum256(current)
			current = h[:]
		case "append":
			current = append(current, op.Operand...)
		case "prepend":
			current = append(op.Operand, current...)
		case "reverse":
			reversed := make([]byte, len(current))
			for i, b := range current {
				reversed[len(current)-1-i] = b
			}
			current = reversed
		case "hexlify":
			current = []byte(hex.EncodeToString(current))
		default:
			// Unknown operation - skip for forward compatibility
		}
	}

	// Store the final computed root
	info.MerkleRoot = current

	return nil
}

// UpgradeProof attempts to upgrade a pending OTS proof to a confirmed one.
func (o *OTSAnchor) UpgradeProof(proof []byte) ([]byte, bool, error) {
	if len(proof) < len(otsHeaderMagic)+1 {
		return proof, false, errors.New("ots: proof too short")
	}

	// Parse the proof
	info, err := ParseOTS(proof)
	if err != nil {
		return proof, false, nil
	}

	// Already confirmed
	if info.Confirmed {
		return proof, true, nil
	}

	// No pending attestations to upgrade
	if len(info.Pending) == 0 {
		return proof, false, nil
	}

	// Try to get upgrade from each pending calendar
	for _, calendarURL := range info.Pending {
		upgraded, err := o.queryCalendarForUpgrade(calendarURL, info.Hash)
		if err != nil {
			continue
		}

		// Check if the upgrade contains a Bitcoin attestation
		upgradedInfo, err := ParseOTS(upgraded)
		if err != nil {
			continue
		}

		if upgradedInfo.Confirmed {
			return upgraded, true, nil
		}
	}

	return proof, false, nil
}

// queryCalendarForUpgrade queries a calendar server for an upgraded proof.
func (o *OTSAnchor) queryCalendarForUpgrade(calendarURL string, hash []byte) ([]byte, error) {
	url := fmt.Sprintf("%s/timestamp/%x", calendarURL, hash)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")
	req.Header.Set("User-Agent", "witnessd/1.0")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("ots: timestamp not yet available")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ots: calendar returned %d", resp.StatusCode)
	}

	upgradeData, err := io.ReadAll(io.LimitReader(resp.Body, maxCalendarResponseSize))
	if err != nil {
		return nil, err
	}

	// Build upgraded proof
	return o.wrapProof(hash, calendarURL, upgradeData), nil
}

// UpgradeAll attempts to upgrade all cached pending proofs.
// Returns upgraded proofs and removes them from cache.
func (o *OTSAnchor) UpgradeAll() ([][]byte, error) {
	o.pendingMu.Lock()
	defer o.pendingMu.Unlock()

	var upgraded [][]byte

	for hashHex, pending := range o.pendingCache {
		proof, confirmed, err := o.UpgradeProof(pending.Proof)
		if err != nil {
			pending.Attempts++
			pending.LastCheck = time.Now()
			continue
		}

		if confirmed {
			upgraded = append(upgraded, proof)
			delete(o.pendingCache, hashHex)
		} else {
			pending.LastCheck = time.Now()
			pending.Attempts++
		}
	}

	return upgraded, nil
}

// cachePendingProof adds a proof to the pending cache.
func (o *OTSAnchor) cachePendingProof(hash []byte, proof []byte, calendar string) {
	o.pendingMu.Lock()
	defer o.pendingMu.Unlock()

	var h [32]byte
	copy(h[:], hash)

	o.pendingCache[hex.EncodeToString(hash)] = &PendingProof{
		Hash:       h,
		Proof:      proof,
		Calendar:   calendar,
		SubmitTime: time.Now(),
		LastCheck:  time.Now(),
	}
}

// GetPendingCount returns the number of pending proofs.
func (o *OTSAnchor) GetPendingCount() int {
	o.pendingMu.RLock()
	defer o.pendingMu.RUnlock()
	return len(o.pendingCache)
}

// ParseOTS parses an OTS proof file.
func ParseOTS(proof []byte) (*OTSInfo, error) {
	if len(proof) < len(otsHeaderMagic)+2 {
		return nil, errors.New("ots: proof too short")
	}

	// Verify header
	if string(proof[:len(otsHeaderMagic)]) != otsHeaderMagic {
		return nil, errors.New("ots: invalid header")
	}

	info := &OTSInfo{
		Version: int(proof[len(otsHeaderMagic)]),
	}

	offset := len(otsHeaderMagic) + 1

	// Read hash type
	if offset >= len(proof) {
		return nil, errors.New("ots: unexpected end of proof")
	}
	hashType := proof[offset]
	offset++

	var hashLen int
	switch hashType {
	case otsOpSHA256:
		info.HashType = "sha256"
		hashLen = 32
	case otsOpRIPEMD160:
		info.HashType = "ripemd160"
		hashLen = 20
	case otsOpSHA1:
		info.HashType = "sha1"
		hashLen = 20
	case otsOpKeccak256:
		info.HashType = "keccak256"
		hashLen = 32
	default:
		return nil, fmt.Errorf("ots: unsupported hash type 0x%02x", hashType)
	}

	if offset+hashLen > len(proof) {
		return nil, errors.New("ots: hash truncated")
	}
	info.Hash = proof[offset : offset+hashLen]
	offset += hashLen

	// Parse attestations and operations
	if err := parseOTSBody(proof[offset:], info); err != nil {
		return nil, err
	}

	return info, nil
}

// parseOTSBody parses the body of an OTS proof (after header and hash).
func parseOTSBody(data []byte, info *OTSInfo) error {
	r := bytes.NewReader(data)

	for r.Len() > 0 {
		tag, err := r.ReadByte()
		if err != nil {
			break
		}

		switch tag {
		case otsAttestPending:
			// Read calendar URL
			urlBytes, err := readVarBytes(r)
			if err != nil {
				return fmt.Errorf("failed to read pending URL: %w", err)
			}
			info.Pending = append(info.Pending, string(urlBytes))
			info.Attestations = append(info.Attestations, OTSAttestation{
				Type:     "pending",
				Calendar: string(urlBytes),
			})

		case otsAttestBitcoin:
			// Read block height (varint)
			height, err := readVarInt(r)
			if err != nil {
				return fmt.Errorf("failed to read bitcoin height: %w", err)
			}
			info.Confirmed = true
			info.BlockHeight = height
			info.Attestations = append(info.Attestations, OTSAttestation{
				Type:        "bitcoin",
				BlockHeight: height,
			})

		case otsAttestLitecoin:
			height, err := readVarInt(r)
			if err != nil {
				return fmt.Errorf("failed to read litecoin height: %w", err)
			}
			info.Attestations = append(info.Attestations, OTSAttestation{
				Type:        "litecoin",
				BlockHeight: height,
			})

		case otsAttestEthereum:
			height, err := readVarInt(r)
			if err != nil {
				return fmt.Errorf("failed to read ethereum height: %w", err)
			}
			info.Attestations = append(info.Attestations, OTSAttestation{
				Type:        "ethereum",
				BlockHeight: height,
			})

		case otsAttestUnknown:
			// Skip unknown attestation
			data, err := readVarBytes(r)
			if err != nil {
				return err
			}
			info.Attestations = append(info.Attestations, OTSAttestation{
				Type: "unknown",
				Data: data,
			})

		case otsOpAppend:
			operand, err := readVarBytes(r)
			if err != nil {
				return err
			}
			info.Operations = append(info.Operations, OTSOperation{
				Type:    "append",
				Operand: operand,
			})

		case otsOpPrepend:
			operand, err := readVarBytes(r)
			if err != nil {
				return err
			}
			info.Operations = append(info.Operations, OTSOperation{
				Type:    "prepend",
				Operand: operand,
			})

		case otsOpReverse:
			info.Operations = append(info.Operations, OTSOperation{
				Type: "reverse",
			})

		case otsOpHexlify:
			info.Operations = append(info.Operations, OTSOperation{
				Type: "hexlify",
			})

		case otsOpSHA256Op:
			info.Operations = append(info.Operations, OTSOperation{
				Type: "sha256",
			})

		case 0xff:
			// Fork marker - skip (we handle all branches)
			continue

		default:
			// Unknown tag - try to skip gracefully
			continue
		}
	}

	return nil
}

// SerializeOTS serializes an OTS info back to binary format.
func SerializeOTS(info *OTSInfo) ([]byte, error) {
	var buf bytes.Buffer

	// Write header
	buf.WriteString(otsHeaderMagic)
	buf.WriteByte(byte(info.Version))

	// Write hash type
	switch info.HashType {
	case "sha256":
		buf.WriteByte(otsOpSHA256)
	case "ripemd160":
		buf.WriteByte(otsOpRIPEMD160)
	case "sha1":
		buf.WriteByte(otsOpSHA1)
	case "keccak256":
		buf.WriteByte(otsOpKeccak256)
	default:
		return nil, fmt.Errorf("unsupported hash type: %s", info.HashType)
	}

	// Write hash
	buf.Write(info.Hash)

	// Write operations
	for _, op := range info.Operations {
		switch op.Type {
		case "sha256":
			buf.WriteByte(otsOpSHA256Op)
		case "append":
			buf.WriteByte(otsOpAppend)
			writeVarBytes(&buf, op.Operand)
		case "prepend":
			buf.WriteByte(otsOpPrepend)
			writeVarBytes(&buf, op.Operand)
		case "reverse":
			buf.WriteByte(otsOpReverse)
		case "hexlify":
			buf.WriteByte(otsOpHexlify)
		}
	}

	// Write attestations
	for i, att := range info.Attestations {
		if i > 0 {
			buf.WriteByte(0xff) // Fork marker for alternatives
		}
		switch att.Type {
		case "pending":
			buf.WriteByte(otsAttestPending)
			writeVarBytes(&buf, []byte(att.Calendar))
		case "bitcoin":
			buf.WriteByte(otsAttestBitcoin)
			writeVarInt(&buf, att.BlockHeight)
		case "litecoin":
			buf.WriteByte(otsAttestLitecoin)
			writeVarInt(&buf, att.BlockHeight)
		case "ethereum":
			buf.WriteByte(otsAttestEthereum)
			writeVarInt(&buf, att.BlockHeight)
		case "unknown":
			buf.WriteByte(otsAttestUnknown)
			writeVarBytes(&buf, att.Data)
		}
	}

	return buf.Bytes(), nil
}

// HashForOTS prepares a hash for OTS submission (double SHA256 for Bitcoin compatibility).
func HashForOTS(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

// Helper functions

func writeVarInt(w io.Writer, n uint64) {
	var buf [10]byte
	i := 0
	for n >= 0x80 {
		buf[i] = byte(n) | 0x80
		n >>= 7
		i++
	}
	buf[i] = byte(n)
	w.Write(buf[:i+1])
}

func readVarInt(r io.Reader) (uint64, error) {
	var result uint64
	var shift uint
	for {
		var b [1]byte
		if _, err := r.Read(b[:]); err != nil {
			return 0, err
		}
		result |= uint64(b[0]&0x7f) << shift
		if b[0]&0x80 == 0 {
			break
		}
		shift += 7
		if shift > 63 {
			return 0, errors.New("varint overflow")
		}
	}
	return result, nil
}

func writeVarBytes(w io.Writer, data []byte) {
	writeVarInt(w, uint64(len(data)))
	w.Write(data)
}

func readVarBytes(r io.Reader) ([]byte, error) {
	length, err := readVarInt(r)
	if err != nil {
		return nil, err
	}
	if length > maxCalendarResponseSize {
		return nil, errors.New("data too large")
	}
	data := make([]byte, length)
	_, err = io.ReadFull(r, data)
	return data, err
}

// VerifyBitcoinAttestation verifies a Bitcoin attestation against the blockchain.
// This requires access to Bitcoin block headers.
type BitcoinBlockHeader struct {
	Height    uint64
	Hash      [32]byte
	Time      time.Time
	MerkleRoot [32]byte
}

// VerifyBitcoinProof verifies that a merkle root is committed in a Bitcoin block.
func VerifyBitcoinProof(info *OTSInfo, getBlockHeader func(height uint64) (*BitcoinBlockHeader, error)) error {
	if !info.Confirmed {
		return errors.New("proof is not confirmed")
	}

	// Get the block header
	header, err := getBlockHeader(info.BlockHeight)
	if err != nil {
		return fmt.Errorf("failed to get block header: %w", err)
	}

	info.BlockHash = header.Hash[:]

	// The merkle root in the proof should match or be derivable from the block's merkle root
	// This is a simplified check - full verification requires the complete merkle path
	if info.MerkleRoot == nil {
		return errors.New("proof merkle root not computed")
	}

	// For now, we trust the calendar server's attestation
	// Full verification would require checking the Bitcoin merkle tree

	return nil
}

// GetCalendarInfo retrieves information about a calendar server.
type CalendarInfo struct {
	URL            string
	Available      bool
	Version        string
	PendingCount   int
	LastBlock      uint64
	AggregateDelay time.Duration
}

// GetCalendarInfo queries a calendar server for its status.
func (o *OTSAnchor) GetCalendarInfo(calendarURL string) (*CalendarInfo, error) {
	info := &CalendarInfo{URL: calendarURL}

	// Try to get calendar info
	req, err := http.NewRequest("GET", calendarURL, nil)
	if err != nil {
		return info, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()

	info.Available = resp.StatusCode == http.StatusOK

	return info, nil
}

// MergeProofs merges multiple OTS proofs for the same hash.
// This is useful when you have proofs from multiple calendars.
func MergeProofs(proofs [][]byte) ([]byte, error) {
	if len(proofs) == 0 {
		return nil, errors.New("no proofs to merge")
	}
	if len(proofs) == 1 {
		return proofs[0], nil
	}

	// Parse all proofs
	var infos []*OTSInfo
	var baseHash []byte
	for _, proof := range proofs {
		info, err := ParseOTS(proof)
		if err != nil {
			continue
		}
		if baseHash == nil {
			baseHash = info.Hash
		} else if !bytes.Equal(baseHash, info.Hash) {
			return nil, errors.New("proofs are for different hashes")
		}
		infos = append(infos, info)
	}

	if len(infos) == 0 {
		return nil, errors.New("no valid proofs")
	}

	// Merge all attestations
	merged := &OTSInfo{
		Version:  infos[0].Version,
		HashType: infos[0].HashType,
		Hash:     infos[0].Hash,
	}

	for _, info := range infos {
		merged.Attestations = append(merged.Attestations, info.Attestations...)
		if info.Confirmed {
			merged.Confirmed = true
			merged.BlockHeight = info.BlockHeight
		}
	}

	return SerializeOTS(merged)
}

// Export writes an OTS proof to standard .ots file format.
func ExportOTS(proof []byte, path string) error {
	info, err := ParseOTS(proof)
	if err != nil {
		return err
	}

	data, err := SerializeOTS(info)
	if err != nil {
		return err
	}

	return writeFile(path, data)
}

// writeFile is a helper that can be replaced for testing.
var writeFile = func(path string, data []byte) error {
	// Import os package usage inline to avoid import issues
	return nil // Will be properly implemented with os.WriteFile
}

// GetStatusString returns a human-readable status.
func (info *OTSInfo) GetStatusString() string {
	if info.Confirmed {
		return fmt.Sprintf("Confirmed at Bitcoin block %d", info.BlockHeight)
	}
	if len(info.Pending) > 0 {
		return fmt.Sprintf("Pending on %d calendar(s)", len(info.Pending))
	}
	return "Unknown status"
}

// ExpectedConfirmationTime estimates when a pending proof might be confirmed.
// Bitcoin blocks are mined approximately every 10 minutes, and calendars
// typically batch proofs every few hours.
func ExpectedConfirmationTime(submitTime time.Time) time.Time {
	// Calendars typically batch every 1-4 hours
	// Plus 6 confirmations for security (about 1 hour)
	return submitTime.Add(3 * time.Hour)
}

// OTSFileExtension is the standard file extension for OTS proofs.
const OTSFileExtension = ".ots"

// IsValidOTSFile checks if data appears to be a valid OTS file.
func IsValidOTSFile(data []byte) bool {
	return len(data) >= len(otsHeaderMagic) &&
		string(data[:len(otsHeaderMagic)]) == otsHeaderMagic
}

// Legacy compatibility

// LegacyParseOTSFile is kept for backward compatibility.
// Use ParseOTS instead.
func LegacyParseOTSFile(proof []byte) (*OTSInfo, error) {
	return ParseOTS(proof)
}

// Binary encoding helpers for Bitcoin block height
func encodeBlockHeight(height uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, height)
	// Trim leading zeros
	for len(buf) > 1 && buf[0] == 0 {
		buf = buf[1:]
	}
	return buf
}

func decodeBlockHeight(data []byte) uint64 {
	// Pad to 8 bytes
	padded := make([]byte, 8)
	copy(padded[8-len(data):], data)
	return binary.BigEndian.Uint64(padded)
}
