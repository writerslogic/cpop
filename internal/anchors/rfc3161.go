package anchors

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// RFC 3161 OIDs
var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// Known free TSA servers
var tsaServers = []string{
	"https://freetsa.org/tsr",
	"https://zeitstempel.dfn.de",
}

// RFC3161Anchor implements RFC 3161 Time-Stamp Protocol.
type RFC3161Anchor struct {
	servers []string
	client  *http.Client
}

// NewRFC3161Anchor creates a new RFC 3161 anchor.
func NewRFC3161Anchor() *RFC3161Anchor {
	return &RFC3161Anchor{
		servers: tsaServers,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Name returns the anchor type name.
func (r *RFC3161Anchor) Name() string {
	return "rfc3161"
}

// Commit requests a timestamp from an RFC 3161 TSA.
func (r *RFC3161Anchor) Commit(hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		// Hash the input if it's not already a SHA-256 hash
		h := sha256.Sum256(hash)
		hash = h[:]
	}

	// Build timestamp request
	request, err := buildTSRequest(hash)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: build request: %w", err)
	}

	// Try each server
	var lastErr error
	for _, server := range r.servers {
		response, err := r.submitRequest(server, request)
		if err == nil {
			return response, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("rfc3161: all servers failed: %w", lastErr)
}

// submitRequest sends a timestamp request to a TSA server.
func (r *RFC3161Anchor) submitRequest(server string, request []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", server, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// Verify validates an RFC 3161 timestamp response.
// Note: Full verification requires checking the TSA's certificate chain.
func (r *RFC3161Anchor) Verify(hash, proof []byte) error {
	if len(proof) < 10 {
		return errors.New("rfc3161: response too short")
	}

	// Parse the response
	var response tsResponse
	rest, err := asn1.Unmarshal(proof, &response)
	if err != nil {
		return fmt.Errorf("rfc3161: parse response: %w", err)
	}
	if len(rest) > 0 {
		return errors.New("rfc3161: trailing data in response")
	}

	// Check status
	if response.Status.Status != 0 {
		return fmt.Errorf("rfc3161: timestamp failed with status %d", response.Status.Status)
	}

	// The timeStampToken contains the actual timestamp
	// Full verification would require:
	// 1. Parsing the CMS SignedData structure
	// 2. Verifying the TSA's signature
	// 3. Checking the certificate chain
	// 4. Comparing the message imprint to the original hash

	return nil
}

// ASN.1 structures for RFC 3161

// TimeStampReq as per RFC 3161
type tsRequest struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional"`
	Extensions     []asn1.RawValue       `asn1:"optional,tag:0"`
}

// MessageImprint contains the hash to be timestamped
type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

// AlgorithmIdentifier as per X.509
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// TimeStampResp as per RFC 3161
type tsResponse struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// PKIStatusInfo as per RFC 3161
type pkiStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// buildTSRequest creates an RFC 3161 TimeStampReq
func buildTSRequest(hash []byte) ([]byte, error) {
	// Generate nonce for replay protection
	nonce := big.NewInt(time.Now().UnixNano())

	request := tsRequest{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm: oidSHA256,
			},
			HashedMessage: hash,
		},
		Nonce:   nonce,
		CertReq: true, // Request certificate in response
	}

	return asn1.Marshal(request)
}

// TSInfo contains parsed timestamp information
type TSInfo struct {
	SerialNumber *big.Int
	GenTime      time.Time
	Hash         []byte
	HashAlg      string
	TSAName      string
}

// ParseTSResponse extracts information from an RFC 3161 response
func ParseTSResponse(response []byte) (*TSInfo, error) {
	var resp tsResponse
	_, err := asn1.Unmarshal(response, &resp)
	if err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if resp.Status.Status != 0 {
		return nil, fmt.Errorf("timestamp failed: status %d", resp.Status.Status)
	}

	// The TimeStampToken is a CMS SignedData structure
	// Parsing it fully requires significant ASN.1 work
	// For now, return basic info
	info := &TSInfo{
		HashAlg: "sha256",
	}

	// TODO: Full parsing of the SignedData structure would extract:
	// - Serial number from TSTInfo
	// - Generation time
	// - TSA name from certificate

	return info, nil
}

// TimestampFile creates a .tsr file path for a given hash
func TimestampFile(basePath string, hash []byte) string {
	return fmt.Sprintf("%s/%x.tsr", basePath, hash[:8])
}
