package anchors

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// RFC 3161 OIDs
var (
	// Hash algorithm OIDs
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

	// Content type OIDs
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// Signature algorithm OIDs
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// PKIStatus values as per RFC 3161
const (
	PKIStatusGranted        = 0
	PKIStatusGrantedWithMods = 1
	PKIStatusRejection      = 2
	PKIStatusWaiting        = 3
	PKIStatusRevocationWarning = 4
	PKIStatusRevocationNotification = 5
)

// PKIFailInfo bits as per RFC 3161
const (
	PKIFailBadAlg         = 0
	PKIFailBadRequest     = 2
	PKIFailBadDataFormat  = 5
	PKIFailTimeNotAvailable = 14
	PKIFailUnacceptedPolicy = 15
	PKIFailUnacceptedExtension = 16
	PKIFailAddInfoNotAvailable = 17
	PKIFailSystemFailure  = 25
)

// Known TSA servers with metadata
var WellKnownTSAServers = map[string]TSAInfo{
	"freetsa": {
		URL:      "https://freetsa.org/tsr",
		Name:     "FreeTSA",
		Free:     true,
		Regions:  []string{"GLOBAL"},
		Standing: "evidentiary",
	},
	"digicert": {
		URL:      "https://timestamp.digicert.com",
		Name:     "DigiCert Timestamp",
		Free:     false,
		Regions:  []string{"GLOBAL", "US"},
		Standing: "legal",
	},
	"sectigo": {
		URL:      "https://timestamp.sectigo.com",
		Name:     "Sectigo Timestamp",
		Free:     true, // Limited free tier
		Regions:  []string{"GLOBAL"},
		Standing: "legal",
	},
	"globalsign": {
		URL:      "https://timestamp.globalsign.com/?signature=sha2",
		Name:     "GlobalSign Timestamp",
		Free:     false,
		Regions:  []string{"GLOBAL", "EU"},
		Standing: "qualified",
	},
	"comodo": {
		URL:      "http://timestamp.comodoca.com",
		Name:     "Comodo Timestamp",
		Free:     true,
		Regions:  []string{"GLOBAL"},
		Standing: "legal",
	},
	"apple": {
		URL:      "http://timestamp.apple.com/ts01",
		Name:     "Apple Timestamp",
		Free:     true,
		Regions:  []string{"GLOBAL", "US"},
		Standing: "evidentiary",
	},
}

// TSAInfo contains metadata about a TSA server.
type TSAInfo struct {
	URL      string
	Name     string
	Free     bool
	Regions  []string
	Standing string // "evidentiary", "legal", "qualified"
}

// RFC3161Config configures the RFC 3161 anchor.
type RFC3161Config struct {
	// Servers to use (URLs)
	Servers []string

	// Timeout for HTTP requests
	Timeout time.Duration

	// Username for HTTP Basic auth (if required)
	Username string

	// Password for HTTP Basic auth
	Password string

	// HashAlgorithm to use (default SHA256)
	HashAlgorithm string

	// RequestCertificate in response
	RequestCertificate bool

	// PolicyOID to request (optional)
	PolicyOID string

	// VerifyCertificates enables certificate chain validation
	VerifyCertificates bool

	// TrustedRoots for certificate validation
	TrustedRoots *x509.CertPool

	// RetryAttempts for failed requests
	RetryAttempts int

	// RetryDelay between attempts
	RetryDelay time.Duration
}

// RFC3161Anchor implements RFC 3161 Time-Stamp Protocol.
type RFC3161Anchor struct {
	servers           []string
	client            *http.Client
	username          string
	password          string
	hashAlgorithm     string
	requestCert       bool
	policyOID         string
	verifyCerts       bool
	trustedRoots      *x509.CertPool
	retryAttempts     int
	retryDelay        time.Duration

	// Cache for responses
	cacheMu    sync.RWMutex
	tokenCache map[string]*TSToken
}

// TSToken represents a parsed timestamp token.
type TSToken struct {
	// Response metadata
	Status       int
	StatusString string
	FailInfo     int

	// TSTInfo contents
	Version      int
	PolicyOID    string
	SerialNumber *big.Int
	GenTime      time.Time
	Accuracy     TSAccuracy
	Ordering     bool
	Nonce        *big.Int
	TSAName      string

	// Message imprint
	HashAlgorithm string
	MessageHash   []byte

	// Certificate chain
	Certificates []*x509.Certificate
	SignerCert   *x509.Certificate

	// Signature
	SignatureAlgorithm string
	Signature          []byte

	// Raw data
	RawResponse []byte
	RawTSTInfo  []byte
}

// TSAccuracy represents timestamp accuracy.
type TSAccuracy struct {
	Seconds int
	Millis  int
	Micros  int
}

// Duration returns the accuracy as a time.Duration.
func (a TSAccuracy) Duration() time.Duration {
	return time.Duration(a.Seconds)*time.Second +
		time.Duration(a.Millis)*time.Millisecond +
		time.Duration(a.Micros)*time.Microsecond
}

// NewRFC3161Anchor creates a new RFC 3161 anchor with default config.
func NewRFC3161Anchor() *RFC3161Anchor {
	return NewRFC3161AnchorWithConfig(RFC3161Config{})
}

// NewRFC3161AnchorWithConfig creates a new RFC 3161 anchor with custom config.
func NewRFC3161AnchorWithConfig(config RFC3161Config) *RFC3161Anchor {
	servers := config.Servers
	if len(servers) == 0 {
		// Default to free TSAs
		servers = []string{
			"https://freetsa.org/tsr",
			"https://timestamp.sectigo.com",
		}
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	hashAlg := config.HashAlgorithm
	if hashAlg == "" {
		hashAlg = "sha256"
	}

	retryAttempts := config.RetryAttempts
	if retryAttempts == 0 {
		retryAttempts = 3
	}

	retryDelay := config.RetryDelay
	if retryDelay == 0 {
		retryDelay = time.Second
	}

	return &RFC3161Anchor{
		servers:       servers,
		client:        &http.Client{Timeout: timeout},
		username:      config.Username,
		password:      config.Password,
		hashAlgorithm: hashAlg,
		requestCert:   config.RequestCertificate,
		policyOID:     config.PolicyOID,
		verifyCerts:   config.VerifyCertificates,
		trustedRoots:  config.TrustedRoots,
		retryAttempts: retryAttempts,
		retryDelay:    retryDelay,
		tokenCache:    make(map[string]*TSToken),
	}
}

// Name returns the anchor type name.
func (r *RFC3161Anchor) Name() string {
	return "rfc3161"
}

// Commit requests a timestamp from an RFC 3161 TSA.
func (r *RFC3161Anchor) Commit(hash []byte) ([]byte, error) {
	// Ensure hash is correct length for algorithm
	expectedLen := r.hashLength()
	if len(hash) != expectedLen {
		// Hash the input
		h := r.newHash()
		h.Write(hash)
		hash = h.Sum(nil)
	}

	// Build timestamp request
	request, nonce, err := r.buildTSRequest(hash)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: build request: %w", err)
	}

	// Try each server
	var lastErr error
	for _, server := range r.servers {
		response, err := r.submitWithRetry(server, request, nonce, hash)
		if err == nil {
			return response, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("rfc3161: all servers failed: %w", lastErr)
}

// submitWithRetry submits a request with retry logic.
func (r *RFC3161Anchor) submitWithRetry(server string, request []byte, nonce *big.Int, hash []byte) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt < r.retryAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(r.retryDelay * time.Duration(attempt))
		}

		response, err := r.submitRequest(server, request)
		if err != nil {
			lastErr = err
			continue
		}

		// Validate response
		if err := r.validateResponse(response, nonce, hash); err != nil {
			lastErr = err
			continue
		}

		return response, nil
	}

	return nil, lastErr
}

// submitRequest sends a timestamp request to a TSA server.
func (r *RFC3161Anchor) submitRequest(server string, request []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", server, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")

	if r.username != "" {
		req.SetBasicAuth(r.username, r.password)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
}

// validateResponse validates a timestamp response.
func (r *RFC3161Anchor) validateResponse(response []byte, expectedNonce *big.Int, expectedHash []byte) error {
	token, err := ParseTSToken(response)
	if err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	// Check status
	if token.Status != PKIStatusGranted && token.Status != PKIStatusGrantedWithMods {
		return fmt.Errorf("timestamp rejected: status %d (%s)", token.Status, token.StatusString)
	}

	// Verify nonce if provided
	if expectedNonce != nil && token.Nonce != nil {
		if expectedNonce.Cmp(token.Nonce) != 0 {
			return errors.New("nonce mismatch - possible replay attack")
		}
	}

	// Verify message hash
	if !bytes.Equal(expectedHash, token.MessageHash) {
		return errors.New("message hash mismatch")
	}

	// Verify certificate chain if enabled
	if r.verifyCerts && len(token.Certificates) > 0 {
		if err := r.verifyCertificateChain(token); err != nil {
			return fmt.Errorf("certificate verification failed: %w", err)
		}
	}

	return nil
}

// verifyCertificateChain verifies the TSA certificate chain.
func (r *RFC3161Anchor) verifyCertificateChain(token *TSToken) error {
	if len(token.Certificates) == 0 {
		return errors.New("no certificates in response")
	}

	// Build certificate pool from response
	intermediates := x509.NewCertPool()
	for _, cert := range token.Certificates[1:] {
		intermediates.AddCert(cert)
	}

	// Get root pool
	roots := r.trustedRoots
	if roots == nil {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("failed to get system roots: %w", err)
		}
	}

	// Verify the signing certificate
	signerCert := token.Certificates[0]
	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   token.GenTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}

	chains, err := signerCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	if len(chains) == 0 {
		return errors.New("no valid certificate chains found")
	}

	token.SignerCert = signerCert
	return nil
}

// Verify validates an RFC 3161 timestamp response.
func (r *RFC3161Anchor) Verify(hash, proof []byte) error {
	if len(proof) < 10 {
		return errors.New("rfc3161: response too short")
	}

	// Parse the response
	token, err := ParseTSToken(proof)
	if err != nil {
		return fmt.Errorf("rfc3161: parse response: %w", err)
	}

	// Check status
	if token.Status != PKIStatusGranted && token.Status != PKIStatusGrantedWithMods {
		return fmt.Errorf("rfc3161: timestamp failed with status %d", token.Status)
	}

	// Verify hash if provided
	if hash != nil {
		expectedHash := hash
		if len(hash) != len(token.MessageHash) {
			h := r.newHash()
			h.Write(hash)
			expectedHash = h.Sum(nil)
		}
		if !bytes.Equal(expectedHash, token.MessageHash) {
			return errors.New("rfc3161: message imprint does not match hash")
		}
	}

	// Verify timestamp is not in the future (allowing 5 minute clock skew)
	if !token.GenTime.IsZero() && token.GenTime.After(time.Now().Add(5*time.Minute)) {
		return errors.New("rfc3161: timestamp is in the future")
	}

	// Verify certificate chain if enabled
	if r.verifyCerts && len(token.Certificates) > 0 {
		if err := r.verifyCertificateChain(token); err != nil {
			return fmt.Errorf("rfc3161: %w", err)
		}
	}

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

// ContentInfo wraps CMS content
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// SignedData structure (CMS/PKCS#7)
type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type encapContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type signerInfo struct {
	Version            int
	SignerIdentifier   asn1.RawValue
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        []attribute `asn1:"optional,tag:0"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttrs      []attribute `asn1:"optional,tag:1"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// TSTInfo as per RFC 3161 - the actual timestamp content
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       accuracy        `asn1:"optional"`
	Ordering       bool            `asn1:"optional"`
	Nonce          *big.Int        `asn1:"optional"`
	TSA            asn1.RawValue   `asn1:"optional,tag:0"`
	Extensions     []asn1.RawValue `asn1:"optional,tag:1"`
}

type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// buildTSRequest creates an RFC 3161 TimeStampReq
func (r *RFC3161Anchor) buildTSRequest(hash []byte) ([]byte, *big.Int, error) {
	// Generate nonce for replay protection
	nonce, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Get hash algorithm OID
	hashOID := r.hashAlgorithmOID()

	request := tsRequest{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm: hashOID,
			},
			HashedMessage: hash,
		},
		Nonce:   nonce,
		CertReq: r.requestCert,
	}

	// Add policy OID if specified
	if r.policyOID != "" {
		oid, err := parseOID(r.policyOID)
		if err == nil {
			request.ReqPolicy = oid
		}
	}

	data, err := asn1.Marshal(request)
	return data, nonce, err
}

// ParseTSToken parses a complete timestamp response.
func ParseTSToken(response []byte) (*TSToken, error) {
	var resp tsResponse
	_, err := asn1.Unmarshal(response, &resp)
	if err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	token := &TSToken{
		Status:      resp.Status.Status,
		RawResponse: response,
	}

	// Extract status string
	if len(resp.Status.StatusString) > 0 {
		token.StatusString = resp.Status.StatusString[0]
	}

	// Extract fail info
	if resp.Status.FailInfo.BitLength > 0 {
		for i := 0; i < resp.Status.FailInfo.BitLength; i++ {
			if resp.Status.FailInfo.At(i) != 0 {
				token.FailInfo |= 1 << i
			}
		}
	}

	// If status is not granted, return early
	if token.Status != PKIStatusGranted && token.Status != PKIStatusGrantedWithMods {
		return token, nil
	}

	// Parse TimeStampToken (ContentInfo containing SignedData)
	if len(resp.TimeStampToken.Bytes) == 0 {
		return token, nil
	}

	// Parse ContentInfo
	var ci contentInfo
	_, err = asn1.Unmarshal(resp.TimeStampToken.Bytes, &ci)
	if err != nil {
		return token, nil // Return partial token
	}

	// Check content type is SignedData
	if !ci.ContentType.Equal(oidSignedData) {
		return token, nil
	}

	// Parse SignedData
	var sd signedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return token, nil
	}

	// Extract certificates
	if len(sd.Certificates.Bytes) > 0 {
		certs, _ := parseCertificates(sd.Certificates.Bytes)
		token.Certificates = certs
	}

	// Extract TSTInfo from EncapsulatedContentInfo
	if sd.EncapContentInfo.ContentType.Equal(oidTSTInfo) && len(sd.EncapContentInfo.Content.Bytes) > 0 {
		token.RawTSTInfo = sd.EncapContentInfo.Content.Bytes

		// The content might be wrapped in an OCTET STRING
		var tstBytes []byte
		_, err := asn1.Unmarshal(sd.EncapContentInfo.Content.Bytes, &tstBytes)
		if err != nil {
			tstBytes = sd.EncapContentInfo.Content.Bytes
		}

		var tst tstInfo
		_, err = asn1.Unmarshal(tstBytes, &tst)
		if err == nil {
			token.Version = tst.Version
			token.PolicyOID = tst.Policy.String()
			token.SerialNumber = tst.SerialNumber
			token.GenTime = tst.GenTime
			token.Accuracy = TSAccuracy{
				Seconds: tst.Accuracy.Seconds,
				Millis:  tst.Accuracy.Millis,
				Micros:  tst.Accuracy.Micros,
			}
			token.Ordering = tst.Ordering
			token.Nonce = tst.Nonce
			token.MessageHash = tst.MessageImprint.HashedMessage
			token.HashAlgorithm = oidToHashName(tst.MessageImprint.HashAlgorithm.Algorithm)
		}
	}

	// Extract signature info
	if len(sd.SignerInfos) > 0 {
		si := sd.SignerInfos[0]
		token.Signature = si.Signature
		token.SignatureAlgorithm = oidToSigName(si.SignatureAlgorithm.Algorithm)
	}

	return token, nil
}

// parseCertificates parses a set of certificates from ASN.1.
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data

	for len(rest) > 0 {
		cert, err := x509.ParseCertificate(rest)
		if err != nil {
			// Try to parse as a sequence of certificates
			var rawCert asn1.RawValue
			var newRest []byte
			newRest, err = asn1.Unmarshal(rest, &rawCert)
			if err != nil {
				break
			}
			cert, err = x509.ParseCertificate(rawCert.FullBytes)
			if err != nil {
				rest = newRest
				continue
			}
			rest = newRest
		} else {
			// Single certificate consumed all input
			rest = nil
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// Helper functions

func (r *RFC3161Anchor) hashLength() int {
	switch r.hashAlgorithm {
	case "sha384":
		return 48
	case "sha512":
		return 64
	case "sha1":
		return 20
	default:
		return 32
	}
}

func (r *RFC3161Anchor) newHash() hash.Hash {
	switch r.hashAlgorithm {
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	case "sha1":
		return crypto.SHA1.New()
	default:
		return sha256.New()
	}
}

func (r *RFC3161Anchor) hashAlgorithmOID() asn1.ObjectIdentifier {
	switch r.hashAlgorithm {
	case "sha384":
		return oidSHA384
	case "sha512":
		return oidSHA512
	case "sha1":
		return oidSHA1
	default:
		return oidSHA256
	}
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	var current int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			current = current*10 + int(c-'0')
		} else if c == '.' {
			oid = append(oid, current)
			current = 0
		}
	}
	oid = append(oid, current)
	return oid, nil
}

func oidToHashName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidSHA256):
		return "sha256"
	case oid.Equal(oidSHA384):
		return "sha384"
	case oid.Equal(oidSHA512):
		return "sha512"
	case oid.Equal(oidSHA1):
		return "sha1"
	default:
		return oid.String()
	}
}

func oidToSigName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidSHA256WithRSA):
		return "sha256WithRSA"
	case oid.Equal(oidSHA384WithRSA):
		return "sha384WithRSA"
	case oid.Equal(oidSHA512WithRSA):
		return "sha512WithRSA"
	case oid.Equal(oidECDSAWithSHA256):
		return "ecdsaWithSHA256"
	case oid.Equal(oidECDSAWithSHA384):
		return "ecdsaWithSHA384"
	case oid.Equal(oidECDSAWithSHA512):
		return "ecdsaWithSHA512"
	default:
		return oid.String()
	}
}

// GetGenTime extracts the generation time from a timestamp response.
func GetGenTime(response []byte) (time.Time, error) {
	token, err := ParseTSToken(response)
	if err != nil {
		return time.Time{}, err
	}
	return token.GenTime, nil
}

// GetSerialNumber extracts the serial number from a timestamp response.
func GetSerialNumber(response []byte) (*big.Int, error) {
	token, err := ParseTSToken(response)
	if err != nil {
		return nil, err
	}
	return token.SerialNumber, nil
}

// TSInfo is an alias for TSToken for backward compatibility.
type TSInfo = TSToken

// ParseTSResponse is an alias for ParseTSToken for backward compatibility.
func ParseTSResponse(response []byte) (*TSInfo, error) {
	return ParseTSToken(response)
}

// TimestampFile creates a .tsr file path for a given hash.
func TimestampFile(basePath string, hash []byte) string {
	return fmt.Sprintf("%s/%x.tsr", basePath, hash[:8])
}

// ExportTSR exports a timestamp response to a file.
func ExportTSR(response []byte, path string) error {
	// Validate response first
	_, err := ParseTSToken(response)
	if err != nil {
		return err
	}
	// writeFile is defined in ots.go
	return writeFile(path, response)
}

// VerifyTSRFile verifies a .tsr file against a hash.
func VerifyTSRFile(response []byte, hash []byte) error {
	anchor := NewRFC3161Anchor()
	return anchor.Verify(hash, response)
}

// GetCertificateChain extracts the certificate chain from a timestamp response.
func GetCertificateChain(response []byte) ([]*x509.Certificate, error) {
	token, err := ParseTSToken(response)
	if err != nil {
		return nil, err
	}
	return token.Certificates, nil
}

// GetTSAName extracts the TSA name from a timestamp response.
func GetTSAName(response []byte) (string, error) {
	token, err := ParseTSToken(response)
	if err != nil {
		return "", err
	}
	if token.SignerCert != nil {
		return token.SignerCert.Subject.CommonName, nil
	}
	if len(token.Certificates) > 0 {
		return token.Certificates[0].Subject.CommonName, nil
	}
	return "", nil
}

// GetPolicyOID extracts the policy OID from a timestamp response.
func GetPolicyOID(response []byte) (string, error) {
	token, err := ParseTSToken(response)
	if err != nil {
		return "", err
	}
	return token.PolicyOID, nil
}

// IsQualified checks if a timestamp token indicates qualified status.
// This is a heuristic based on policy OID and certificate extensions.
func IsQualified(response []byte) bool {
	token, err := ParseTSToken(response)
	if err != nil {
		return false
	}

	// Check for known qualified policy OIDs
	// These are examples - real qualified OIDs vary by QTSP
	qualifiedPolicyPrefixes := []string{
		"0.4.0.2023", // ETSI qualified signatures
		"1.3.6.1.4.1.13762.3", // Example QTSP
	}

	for _, prefix := range qualifiedPolicyPrefixes {
		if len(token.PolicyOID) >= len(prefix) && token.PolicyOID[:len(prefix)] == prefix {
			return true
		}
	}

	// Check certificate for extended key usage
	for _, cert := range token.Certificates {
		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageTimeStamping {
				// Has time stamping usage - check for qualified indicator
				// This would require parsing certificate extensions
			}
		}
	}

	return false
}

// Unexported helpers from pkix package
func marshalCert(cert *x509.Certificate) (pkix.RDNSequence, error) {
	var seq pkix.RDNSequence
	_, err := asn1.Unmarshal(cert.RawSubject, &seq)
	return seq, err
}
