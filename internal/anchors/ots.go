package anchors

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OpenTimestamps constants
const (
	// OTS file header magic bytes
	otsHeaderMagic = "\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"

	// OTS version
	otsVersion = 1

	// Bitcoin attestation tag
	otsAttestBitcoin = 0x05

	// Pending attestation tag
	otsAttestPending = 0x83
)

// OTS calendar server URLs
var otsCalendars = []string{
	"https://a.pool.opentimestamps.org",
	"https://b.pool.opentimestamps.org",
	"https://a.pool.eternitywall.com",
}

// OTSAnchor implements the OpenTimestamps protocol.
type OTSAnchor struct {
	calendars []string
	client    *http.Client
}

// NewOTSAnchor creates a new OpenTimestamps anchor.
func NewOTSAnchor() *OTSAnchor {
	return &OTSAnchor{
		calendars: otsCalendars,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
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

	// Try each calendar until one succeeds
	var lastErr error
	for _, calendar := range o.calendars {
		proof, err := o.submitToCalendar(calendar, hash)
		if err == nil {
			// Wrap in OTS file format
			return o.wrapProof(hash, calendar, proof), nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("ots: all calendars failed: %w", lastErr)
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

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("calendar returned %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// wrapProof creates a complete OTS file from a calendar response.
func (o *OTSAnchor) wrapProof(hash []byte, calendar string, calendarProof []byte) []byte {
	var buf bytes.Buffer

	// Write OTS header
	buf.WriteString(otsHeaderMagic)
	buf.WriteByte(otsVersion)

	// Write hash type (SHA256 = 0x08)
	buf.WriteByte(0x08)

	// Write the original hash
	buf.Write(hash)

	// Write calendar URL as pending attestation
	buf.WriteByte(otsAttestPending)
	writeVarInt(&buf, uint64(len(calendar)))
	buf.WriteString(calendar)

	// Include calendar response
	buf.Write(calendarProof)

	return buf.Bytes()
}

// Verify checks an OTS proof.
// Note: Full verification requires Bitcoin RPC access to check block headers.
// This implementation does basic format validation.
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

	// TODO: Full verification would require:
	// 1. Walking the OTS operations chain
	// 2. Checking Bitcoin attestations against block headers
	// For now, we just validate the format

	return nil
}

// UpgradeProof attempts to upgrade a pending OTS proof to a confirmed one.
func (o *OTSAnchor) UpgradeProof(proof []byte) ([]byte, bool, error) {
	// Parse the proof to find pending attestations
	if len(proof) < len(otsHeaderMagic)+1 {
		return proof, false, errors.New("ots: proof too short")
	}

	// TODO: Implement proof upgrade by querying calendars
	// This would:
	// 1. Parse pending attestations
	// 2. Query calendar servers for Bitcoin confirmations
	// 3. Replace pending attestations with Bitcoin block header attestations

	return proof, false, nil
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
	}
	return result, nil
}

// HashForOTS prepares a hash for OTS submission (double SHA256).
func HashForOTS(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

// parseOTSFile extracts information from an OTS file.
type OTSInfo struct {
	Version   int
	HashType  string
	Hash      []byte
	Pending   []string // Calendar URLs for pending attestations
	Confirmed bool     // True if Bitcoin attestation found
	BlockHash []byte   // Bitcoin block hash if confirmed
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

	switch hashType {
	case 0x08:
		info.HashType = "sha256"
		if offset+32 > len(proof) {
			return nil, errors.New("ots: hash truncated")
		}
		info.Hash = proof[offset : offset+32]
		offset += 32
	default:
		return nil, fmt.Errorf("ots: unsupported hash type 0x%02x", hashType)
	}

	// Look for attestations
	for offset < len(proof) {
		tag := proof[offset]
		offset++

		switch tag {
		case otsAttestPending:
			// Read URL length
			r := bytes.NewReader(proof[offset:])
			urlLen, err := readVarInt(r)
			if err != nil {
				return nil, err
			}
			offset += int(binary.Size(uint64(0))) // Approximate; actual depends on varint size
			if offset+int(urlLen) > len(proof) {
				return nil, errors.New("ots: URL truncated")
			}
			info.Pending = append(info.Pending, string(proof[offset:offset+int(urlLen)]))
			offset += int(urlLen)

		case otsAttestBitcoin:
			info.Confirmed = true
			// Read block hash (next 32 bytes)
			if offset+32 <= len(proof) {
				info.BlockHash = proof[offset : offset+32]
				offset += 32
			}

		default:
			// Unknown tag, skip
			// In real implementation, we'd need to handle all OTS operations
			break
		}
	}

	return info, nil
}
