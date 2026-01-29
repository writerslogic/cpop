//go:build linux

// Platform-specific TPM implementation for Linux.
// Uses /dev/tpmrm0 (TPM Resource Manager) or /dev/tpm0 (direct access).

package tpm

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPM device paths in order of preference
var tpmDevicePaths = []string{
	"/dev/tpmrm0", // TPM Resource Manager (preferred)
	"/dev/tpm0",   // Direct TPM access (fallback)
}

// NV index for witnessd monotonic counter
// Using user-defined NV space: 0x01500000 - 0x01FFFFFF
const (
	nvCounterIndex = 0x01500001
	nvCounterSize  = 8 // uint64
)

// HardwareProvider implements Provider using a real TPM 2.0 device.
type HardwareProvider struct {
	mu           sync.Mutex
	devicePath   string
	transport    transport.TPM
	isOpen       bool
	ekHandle     tpm2.TPMHandle
	akHandle     tpm2.TPMHandle
	akPublic     *rsa.PublicKey
	counterInit  bool
	manufacturer string
	fwVersion    string
}

// detectHardwareTPM attempts to detect a hardware TPM on Linux.
func detectHardwareTPM() Provider {
	for _, path := range tpmDevicePaths {
		if _, err := os.Stat(path); err == nil {
			// Check if we can actually open it
			f, err := os.OpenFile(path, os.O_RDWR, 0)
			if err == nil {
				f.Close()
				return &HardwareProvider{
					devicePath: path,
				}
			}
		}
	}
	return nil
}

// Available returns true if the TPM device exists and is accessible.
func (h *HardwareProvider) Available() bool {
	if h.devicePath == "" {
		return false
	}
	_, err := os.Stat(h.devicePath)
	return err == nil
}

// Open initializes the TPM connection.
func (h *HardwareProvider) Open() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.isOpen {
		return ErrTPMAlreadyOpen
	}

	// Open the TPM device
	tpmTransport, err := transport.OpenTPM(h.devicePath)
	if err != nil {
		return fmt.Errorf("tpm: failed to open %s: %w", h.devicePath, err)
	}
	h.transport = tpmTransport
	h.isOpen = true

	// Read TPM properties
	if err := h.readTPMProperties(); err != nil {
		h.transport.Close()
		h.isOpen = false
		return fmt.Errorf("tpm: failed to read properties: %w", err)
	}

	// Create or load attestation key
	if err := h.initializeKeys(); err != nil {
		h.transport.Close()
		h.isOpen = false
		return fmt.Errorf("tpm: failed to initialize keys: %w", err)
	}

	return nil
}

// Close releases TPM resources.
func (h *HardwareProvider) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.isOpen {
		return nil
	}

	// Flush loaded keys
	if h.akHandle != 0 {
		tpm2.FlushContext{FlushHandle: h.akHandle}.Execute(h.transport)
	}

	if h.transport != nil {
		h.transport.Close()
	}

	h.isOpen = false
	h.akHandle = 0
	h.ekHandle = 0
	return nil
}

// DeviceID returns the TPM's EK certificate hash as device identifier.
func (h *HardwareProvider) DeviceID() ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.isOpen {
		return nil, ErrTPMNotOpen
	}

	// Read EK certificate from NV (standard location)
	// If not available, compute hash from EK public key
	ekPub, err := h.getEKPublic()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to get EK public: %w", err)
	}

	// Hash the EK public key as device ID
	pubBytes, err := ekPub.Marshal()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to marshal EK public: %w", err)
	}

	hash := sha256.Sum256(pubBytes)
	return hash[:], nil
}

// PublicKey returns the Attestation Key's public key.
func (h *HardwareProvider) PublicKey() (crypto.PublicKey, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.isOpen {
		return nil, ErrTPMNotOpen
	}

	return h.akPublic, nil
}

// IncrementCounter atomically increments the monotonic counter.
func (h *HardwareProvider) IncrementCounter() (uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.isOpen {
		return 0, ErrTPMNotOpen
	}

	// Initialize counter if needed
	if !h.counterInit {
		if err := h.initializeCounter(); err != nil {
			return 0, err
		}
	}

	// Increment NV counter
	incrementCmd := tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(nvCounterIndex),
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.TPMHandle(nvCounterIndex),
	}

	if _, err := incrementCmd.Execute(h.transport); err != nil {
		return 0, fmt.Errorf("tpm: NV increment failed: %w", err)
	}

	// Read back the counter value
	return h.readCounter()
}

// GetCounter returns the current counter value.
func (h *HardwareProvider) GetCounter() (uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.isOpen {
		return 0, ErrTPMNotOpen
	}

	if !h.counterInit {
		if err := h.initializeCounter(); err != nil {
			return 0, err
		}
	}

	return h.readCounter()
}

// GetClock returns TPM clock information.
func (h *HardwareProvider) GetClock() (*ClockInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.isOpen {
		return nil, ErrTPMNotOpen
	}

	// Read clock using ReadClock command
	readClockCmd := tpm2.ReadClock{}
	rsp, err := readClockCmd.Execute(h.transport)
	if err != nil {
		return nil, fmt.Errorf("tpm: ReadClock failed: %w", err)
	}

	return &ClockInfo{
		Clock:        rsp.CurrentTime.ClockInfo.Clock,
		ResetCount:   rsp.CurrentTime.ClockInfo.ResetCount,
		RestartCount: rsp.CurrentTime.ClockInfo.RestartCount,
		Safe:         rsp.CurrentTime.ClockInfo.Safe == tpm2.TPMYes,
	}, nil
}

// Quote creates a TPM quote over the given data.
func (h *HardwareProvider) Quote(data []byte) (*Attestation, error) {
	return h.QuoteWithPCRs(data, DefaultPCRSelection())
}

// QuoteWithPCRs creates a TPM quote with specific PCR selection.
func (h *HardwareProvider) QuoteWithPCRs(data []byte, pcrs PCRSelection) (*Attestation, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.isOpen {
		return nil, ErrTPMNotOpen
	}

	// Build PCR selection
	pcrSel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs.PCRs...),
			},
		},
	}

	// Ensure data fits in qualifying data (64 bytes max for TPM2_Quote)
	qualifyingData := data
	if len(qualifyingData) > 64 {
		// Hash the data if too large
		hash := sha256.Sum256(data)
		qualifyingData = hash[:]
	}

	// Create quote command
	quoteCmd := tpm2.Quote{
		SignHandle: tpm2.AuthHandle{
			Handle: h.akHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		QualifyingData: tpm2.TPM2BData{Buffer: qualifyingData},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
		PCRSelect: pcrSel,
	}

	rsp, err := quoteCmd.Execute(h.transport)
	if err != nil {
		return nil, fmt.Errorf("tpm: Quote failed: %w", err)
	}

	// Read PCR values
	pcrValues, err := h.readPCRsInternal(pcrs)
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to read PCRs: %w", err)
	}

	// Compute PCR digest
	pcrDigest := h.computePCRDigest(pcrValues, pcrs)

	// Get clock info
	clockInfo, err := h.getClockInternal()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to get clock: %w", err)
	}

	// Get and increment counter
	counter, err := h.incrementCounterInternal()
	if err != nil {
		// Non-fatal - counter may not be initialized
		counter = 0
	}

	// Get device ID
	deviceID, _ := h.getDeviceIDInternal()

	// Marshal the attestation data (TPMS_ATTEST)
	quoteData, err := rsp.Quoted.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to get quote contents: %w", err)
	}

	attestData, err := quoteData.Marshal()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to marshal quote: %w", err)
	}

	// Marshal signature
	sigData, err := rsp.Signature.Marshal()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to marshal signature: %w", err)
	}

	return &Attestation{
		DeviceID:         deviceID,
		PublicKey:        nil, // Could include AK public key
		MonotonicCounter: counter,
		FirmwareVersion:  h.fwVersion,
		ClockInfo:        *clockInfo,
		Data:             data, // Original data (not truncated)
		Signature:        sigData,
		Quote:            attestData,
		PCRValues:        pcrValues,
		PCRDigest:        pcrDigest,
		CreatedAt:        time.Now(),
	}, nil
}

// ReadPCRs reads the specified PCR values.
func (h *HardwareProvider) ReadPCRs(pcrs PCRSelection) (map[int][]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.isOpen {
		return nil, ErrTPMNotOpen
	}

	return h.readPCRsInternal(pcrs)
}

// SealKey seals data to the current PCR state.
func (h *HardwareProvider) SealKey(data []byte, pcrs PCRSelection) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.isOpen {
		return nil, ErrTPMNotOpen
	}

	// Create primary key (SRK) for sealing
	srkHandle, _, err := h.createPrimaryKey()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to create SRK: %w", err)
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: srkHandle}
		flushCmd.Execute(h.transport)
	}()

	// Build PCR policy
	policySession, policyDigest, err := h.createPCRPolicy(pcrs)
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to create PCR policy: %w", err)
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: policySession}
		flushCmd.Execute(h.transport)
	}()

	// Create sealed object
	createCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(
					&tpm2.TPM2BSensitiveData{Buffer: data},
				),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: false,
			},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: policyDigest},
		}),
	}

	createRsp, err := createCmd.Execute(h.transport)
	if err != nil {
		return nil, fmt.Errorf("tpm: Create failed: %w", err)
	}

	// Combine public and private portions into sealed blob
	pubBytes, err := createRsp.OutPublic.Marshal()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to marshal public: %w", err)
	}

	privBytes, err := createRsp.OutPrivate.Marshal()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to marshal private: %w", err)
	}

	// Format: len(pub) || pub || len(priv) || priv
	sealed := make([]byte, 4+len(pubBytes)+4+len(privBytes))
	binary.BigEndian.PutUint32(sealed[0:4], uint32(len(pubBytes)))
	copy(sealed[4:], pubBytes)
	offset := 4 + len(pubBytes)
	binary.BigEndian.PutUint32(sealed[offset:offset+4], uint32(len(privBytes)))
	copy(sealed[offset+4:], privBytes)

	return sealed, nil
}

// UnsealKey unseals previously sealed data.
func (h *HardwareProvider) UnsealKey(sealed []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.isOpen {
		return nil, ErrTPMNotOpen
	}

	if len(sealed) < 8 {
		return nil, errors.New("tpm: sealed data too short")
	}

	// Parse sealed blob
	pubLen := binary.BigEndian.Uint32(sealed[0:4])
	if len(sealed) < int(4+pubLen+4) {
		return nil, errors.New("tpm: sealed data corrupted")
	}

	pubBytes := sealed[4 : 4+pubLen]
	offset := 4 + pubLen
	privLen := binary.BigEndian.Uint32(sealed[offset : offset+4])
	if len(sealed) < int(offset+4+privLen) {
		return nil, errors.New("tpm: sealed data corrupted")
	}
	privBytes := sealed[offset+4 : offset+4+privLen]

	// Unmarshal public and private portions
	var outPublic tpm2.TPM2BPublic
	if _, err := outPublic.Unmarshal(pubBytes); err != nil {
		return nil, fmt.Errorf("tpm: failed to unmarshal public: %w", err)
	}

	// Create primary key (SRK)
	srkHandle, _, err := h.createPrimaryKey()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to create SRK: %w", err)
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: srkHandle}
		flushCmd.Execute(h.transport)
	}()

	// Load the sealed object
	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: outPublic,
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: privBytes,
		},
	}

	loadRsp, err := loadCmd.Execute(h.transport)
	if err != nil {
		return nil, fmt.Errorf("tpm: Load failed: %w", err)
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}
		flushCmd.Execute(h.transport)
	}()

	// Create policy session for unsealing
	policySession, err := h.createPolicySession(DefaultPCRSelection())
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to create policy session: %w", err)
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: policySession}
		flushCmd.Execute(h.transport)
	}()

	// Unseal
	unsealCmd := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Auth:   tpm2.Session{Handle: policySession},
		},
	}

	unsealRsp, err := unsealCmd.Execute(h.transport)
	if err != nil {
		// Check if it's a policy failure (PCR mismatch)
		return nil, ErrPCRMismatch
	}

	return unsealRsp.OutData.Buffer, nil
}

// Manufacturer returns TPM manufacturer information.
func (h *HardwareProvider) Manufacturer() string {
	return h.manufacturer
}

// FirmwareVersion returns TPM firmware version.
func (h *HardwareProvider) FirmwareVersion() string {
	return h.fwVersion
}

// Internal helper methods

func (h *HardwareProvider) readTPMProperties() error {
	// Read TPM manufacturer
	getCapCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTManufacturer),
		PropertyCount: 1,
	}

	rsp, err := getCapCmd.Execute(h.transport)
	if err != nil {
		return err
	}

	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err == nil && len(props.TPMProperty) > 0 {
		// Convert manufacturer ID to string
		mfr := props.TPMProperty[0].Value
		h.manufacturer = fmt.Sprintf("%c%c%c%c",
			byte(mfr>>24), byte(mfr>>16), byte(mfr>>8), byte(mfr))
	}

	// Read firmware version
	getCapCmd = tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTFirmwareVersion1),
		PropertyCount: 2,
	}

	rsp, err = getCapCmd.Execute(h.transport)
	if err == nil {
		props, err := rsp.CapabilityData.Data.TPMProperties()
		if err == nil && len(props.TPMProperty) >= 2 {
			h.fwVersion = fmt.Sprintf("%d.%d",
				props.TPMProperty[0].Value, props.TPMProperty[1].Value)
		}
	}

	return nil
}

func (h *HardwareProvider) initializeKeys() error {
	// Create Attestation Key (AK)
	srkHandle, _, err := h.createPrimaryKey()
	if err != nil {
		return err
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: srkHandle}
		flushCmd.Execute(h.transport)
	}()

	// Create AK under SRK
	createAKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				STClear:             false,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Restricted:          true,
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					Scheme: tpm2.TPMTRSAScheme{
						Scheme: tpm2.TPMAlgRSASSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgRSASSA,
							&tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256},
						),
					},
					KeyBits: 2048,
				},
			),
		}),
	}

	akRsp, err := createAKCmd.Execute(h.transport)
	if err != nil {
		return fmt.Errorf("failed to create AK: %w", err)
	}

	h.akHandle = akRsp.ObjectHandle

	// Extract RSA public key
	akPub, err := akRsp.OutPublic.Contents()
	if err != nil {
		return fmt.Errorf("failed to get AK public contents: %w", err)
	}

	rsaParms, err := akPub.Parameters.RSADetail()
	if err != nil {
		return fmt.Errorf("failed to get RSA parameters: %w", err)
	}

	rsaUnique, err := akPub.Unique.RSA()
	if err != nil {
		return fmt.Errorf("failed to get RSA unique: %w", err)
	}

	// Convert the buffer to big.Int for RSA public key
	n := new(big.Int).SetBytes(rsaUnique.Buffer)
	exponent := int(rsaParms.Exponent)
	if exponent == 0 {
		exponent = 65537 // Default RSA exponent
	}

	h.akPublic = &rsa.PublicKey{
		N: n,
		E: exponent,
	}

	return nil
}

func (h *HardwareProvider) createPrimaryKey() (tpm2.TPMHandle, *tpm2.TPMTPublic, error) {
	createPrimaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				STClear:             false,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Restricted:          true,
				Decrypt:             true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgNull,
					},
				},
			),
		}),
	}

	rsp, err := createPrimaryCmd.Execute(h.transport)
	if err != nil {
		return 0, nil, err
	}

	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return 0, nil, err
	}

	return rsp.ObjectHandle, pub, nil
}

func (h *HardwareProvider) getEKPublic() (*tpm2.TPM2BPublic, error) {
	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic: tpm2.New2B(tpm2.RSAEKTemplate),
	}

	rsp, err := createEKCmd.Execute(h.transport)
	if err != nil {
		return nil, err
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
		flushCmd.Execute(h.transport)
	}()

	return &rsp.OutPublic, nil
}

func (h *HardwareProvider) initializeCounter() error {
	// Check if counter already exists
	readPubCmd := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(nvCounterIndex),
	}

	_, err := readPubCmd.Execute(h.transport)
	if err == nil {
		// Counter exists
		h.counterInit = true
		return nil
	}

	// Create NV counter
	defineCmd := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth: tpm2.TPM2BAuth{
			Buffer: nil,
		},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex:    tpm2.TPMHandle(nvCounterIndex),
			NameAlg:    tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{NT: tpm2.TPMNTCounter},
			DataSize:   nvCounterSize,
		}),
	}

	if _, err := defineCmd.Execute(h.transport); err != nil {
		return fmt.Errorf("NVDefineSpace failed: %w", err)
	}

	h.counterInit = true
	return nil
}

func (h *HardwareProvider) readCounter() (uint64, error) {
	readCmd := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(nvCounterIndex),
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.TPMHandle(nvCounterIndex),
		Size:    nvCounterSize,
		Offset:  0,
	}

	rsp, err := readCmd.Execute(h.transport)
	if err != nil {
		return 0, fmt.Errorf("NVRead failed: %w", err)
	}

	if len(rsp.Data.Buffer) < 8 {
		return 0, errors.New("counter data too short")
	}

	return binary.BigEndian.Uint64(rsp.Data.Buffer), nil
}

func (h *HardwareProvider) incrementCounterInternal() (uint64, error) {
	if !h.counterInit {
		if err := h.initializeCounter(); err != nil {
			return 0, err
		}
	}

	incrementCmd := tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(nvCounterIndex),
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.TPMHandle(nvCounterIndex),
	}

	if _, err := incrementCmd.Execute(h.transport); err != nil {
		return 0, err
	}

	return h.readCounter()
}

func (h *HardwareProvider) getClockInternal() (*ClockInfo, error) {
	readClockCmd := tpm2.ReadClock{}
	rsp, err := readClockCmd.Execute(h.transport)
	if err != nil {
		return nil, err
	}

	return &ClockInfo{
		Clock:        rsp.CurrentTime.ClockInfo.Clock,
		ResetCount:   rsp.CurrentTime.ClockInfo.ResetCount,
		RestartCount: rsp.CurrentTime.ClockInfo.RestartCount,
		Safe:         rsp.CurrentTime.ClockInfo.Safe == tpm2.TPMYes,
	}, nil
}

func (h *HardwareProvider) getDeviceIDInternal() ([]byte, error) {
	ekPub, err := h.getEKPublic()
	if err != nil {
		return nil, err
	}

	pubBytes, err := ekPub.Marshal()
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(pubBytes)
	return hash[:], nil
}

func (h *HardwareProvider) readPCRsInternal(pcrs PCRSelection) (map[int][]byte, error) {
	result := make(map[int][]byte)

	pcrSel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs.PCRs...),
			},
		},
	}

	pcrReadCmd := tpm2.PCRRead{
		PCRSelectionIn: pcrSel,
	}

	rsp, err := pcrReadCmd.Execute(h.transport)
	if err != nil {
		return nil, err
	}

	// Map PCR values to result
	for i, pcrIdx := range pcrs.PCRs {
		if i < len(rsp.PCRValues.Digests) {
			result[pcrIdx] = rsp.PCRValues.Digests[i].Buffer
		}
	}

	return result, nil
}

func (h *HardwareProvider) computePCRDigest(pcrValues map[int][]byte, pcrs PCRSelection) []byte {
	hasher := sha256.New()
	for _, pcrIdx := range pcrs.PCRs {
		if val, ok := pcrValues[pcrIdx]; ok {
			hasher.Write(val)
		}
	}
	return hasher.Sum(nil)
}

func (h *HardwareProvider) createPCRPolicy(pcrs PCRSelection) (tpm2.TPMHandle, []byte, error) {
	// Start policy session
	startAuthCmd := tpm2.StartAuthSession{
		SessionType: tpm2.TPMSEPolicy,
		AuthHash:    tpm2.TPMAlgSHA256,
		TPMKey:      tpm2.TPMRHNull,
		Bind:        tpm2.TPMRHNull,
	}

	startRsp, err := startAuthCmd.Execute(h.transport)
	if err != nil {
		return 0, nil, err
	}

	sessionHandle := startRsp.SessionHandle

	// Build PCR selection
	pcrSel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs.PCRs...),
			},
		},
	}

	// PolicyPCR command
	policyPCRCmd := tpm2.PolicyPCR{
		PolicySession: sessionHandle,
		Pcrs:          pcrSel,
	}

	if _, err := policyPCRCmd.Execute(h.transport); err != nil {
		return 0, nil, err
	}

	// Get policy digest
	getDigestCmd := tpm2.PolicyGetDigest{
		PolicySession: sessionHandle,
	}

	digestRsp, err := getDigestCmd.Execute(h.transport)
	if err != nil {
		return 0, nil, err
	}

	return sessionHandle, digestRsp.PolicyDigest.Buffer, nil
}

func (h *HardwareProvider) createPolicySession(pcrs PCRSelection) (tpm2.TPMHandle, error) {
	session, _, err := h.createPCRPolicy(pcrs)
	return session, err
}

// Ensure HardwareProvider implements Provider
var _ Provider = (*HardwareProvider)(nil)
