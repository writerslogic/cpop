//go:build windows

// Platform-specific TPM implementation for Windows.
// Uses TPM Base Services (TBS) through go-tpm.

package tpm

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// NV index for witnessd monotonic counter
const (
	nvCounterIndex = 0x01500001
	nvCounterSize  = 8 // uint64
)

// HardwareProvider implements Provider using Windows TPM via TBS.
type HardwareProvider struct {
	mu           sync.Mutex
	transport    transport.TPMCloser
	isOpen       bool
	ekHandle     tpm2.TPMHandle
	akHandle     tpm2.TPMHandle
	akPublic     crypto.PublicKey
	counterInit  bool
	manufacturer string
	fwVersion    string
}

// detectHardwareTPM attempts to detect a hardware TPM on Windows.
func detectHardwareTPM() Provider {
	// Try to open TPM through Windows TBS
	tpmTransport, err := transport.OpenTPM()
	if err != nil {
		return nil
	}
	tpmTransport.Close()

	return &HardwareProvider{}
}

// Available returns true if the TPM is accessible.
func (h *HardwareProvider) Available() bool {
	tpmTransport, err := transport.OpenTPM()
	if err != nil {
		return false
	}
	tpmTransport.Close()
	return true
}

// Open initializes the TPM connection.
func (h *HardwareProvider) Open() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.isOpen {
		return ErrTPMAlreadyOpen
	}

	tpmTransport, err := transport.OpenTPM()
	if err != nil {
		return fmt.Errorf("tpm: failed to open Windows TPM: %w", err)
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

	if h.akHandle != 0 {
		flushCmd := tpm2.FlushContext{FlushHandle: h.akHandle}
		flushCmd.Execute(h.transport)
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

	ekPub, err := h.getEKPublic()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to get EK public: %w", err)
	}

	pubBytes := tpm2.Marshal(*ekPub)

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
		return 0, fmt.Errorf("tpm: NV increment failed: %w", err)
	}

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

	return h.getClockInternal()
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

	pcrSel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(intToUint(pcrs.PCRs)...),
			},
		},
	}

	qualifyingData := data
	if len(qualifyingData) > 64 {
		hash := sha256.Sum256(data)
		qualifyingData = hash[:]
	}

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
	deviceID, err := h.getDeviceIDInternal()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to get device ID: %w", err)
	}

	// Marshal the attestation data (TPMS_ATTEST)
	quoteData, err := rsp.Quoted.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to get quote contents: %w", err)
	}

	attestData := tpm2.Marshal(*quoteData)

	// Marshal signature
	sigData := tpm2.Marshal(rsp.Signature)

	return &Attestation{
		DeviceID:         deviceID,
		MonotonicCounter: counter,
		FirmwareVersion:  h.fwVersion,
		ClockInfo:        *clockInfo,
		Data:             data,
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

	srkHandle, _, err := h.createPrimaryKey()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to create SRK: %w", err)
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: srkHandle}
		flushCmd.Execute(h.transport)
	}()

	policySession, policyDigest, err := h.createPCRPolicy(pcrs)
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to create PCR policy: %w", err)
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: policySession}
		flushCmd.Execute(h.transport)
	}()

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

	pubBytes := tpm2.Marshal(createRsp.OutPublic)
	privBytes := tpm2.Marshal(createRsp.OutPrivate)

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

	outPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBytes)
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to unmarshal public: %w", err)
	}

	srkHandle, _, err := h.createPrimaryKey()
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to create SRK: %w", err)
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: srkHandle}
		flushCmd.Execute(h.transport)
	}()

	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: *outPublic,
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

	// Create policy session for unsealing using the proper go-tpm API
	pcrs := DefaultPCRSelection()
	policySession, closeSession, err := tpm2.PolicySession(h.transport, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, fmt.Errorf("tpm: failed to create policy session: %w", err)
	}
	defer closeSession()

	// Build PCR selection and apply policy
	pcrSel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(intToUint(pcrs.PCRs)...),
			},
		},
	}

	// Apply PCR policy to session
	policyPCRCmd := tpm2.PolicyPCR{
		PolicySession: policySession.Handle(),
		Pcrs:          pcrSel,
	}
	if _, err := policyPCRCmd.Execute(h.transport); err != nil {
		return nil, fmt.Errorf("tpm: PolicyPCR failed: %w", err)
	}

	unsealCmd := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Auth:   policySession,
		},
	}

	unsealRsp, err := unsealCmd.Execute(h.transport)
	if err != nil {
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

// Internal helper methods (same as Linux implementation)

func (h *HardwareProvider) readTPMProperties() error {
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
		mfr := props.TPMProperty[0].Value
		h.manufacturer = fmt.Sprintf("%c%c%c%c",
			byte(mfr>>24), byte(mfr>>16), byte(mfr>>8), byte(mfr))
	}

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
		return 0, nil, fmt.Errorf("failed to get public contents: %w", err)
	}
	return rsp.ObjectHandle, pub, nil
}

func (h *HardwareProvider) getEKPublic() (*tpm2.TPM2BPublic, error) {
	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
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
	readPubCmd := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(nvCounterIndex),
	}

	_, err := readPubCmd.Execute(h.transport)
	if err == nil {
		h.counterInit = true
		return nil
	}

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
		return 0, err
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
	// Use GetTime command which provides clock info in newer go-tpm versions
	getTimeCmd := tpm2.GetTime{
		PrivacyAdminHandle: tpm2.TPMRHEndorsement,
		SignHandle:         tpm2.TPMRHNull,
	}

	rsp, err := getTimeCmd.Execute(h.transport)
	if err != nil {
		// Return a default clock info if not available
		return &ClockInfo{
			Clock:        0,
			ResetCount:   0,
			RestartCount: 0,
			Safe:         false,
		}, nil
	}

	// Extract clock info from attestation data
	attData, err := rsp.TimeInfo.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to get time info: %w", err)
	}

	return &ClockInfo{
		Clock:        attData.ClockInfo.Clock,
		ResetCount:   attData.ClockInfo.ResetCount,
		RestartCount: attData.ClockInfo.RestartCount,
		Safe:         bool(attData.ClockInfo.Safe),
	}, nil
}

func (h *HardwareProvider) getDeviceIDInternal() ([]byte, error) {
	ekPub, err := h.getEKPublic()
	if err != nil {
		return nil, err
	}

	pubBytes := tpm2.Marshal(*ekPub)
	hash := sha256.Sum256(pubBytes)
	return hash[:], nil
}

func (h *HardwareProvider) readPCRsInternal(pcrs PCRSelection) (map[int][]byte, error) {
	result := make(map[int][]byte)

	pcrSel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(intToUint(pcrs.PCRs)...),
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

	pcrSel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(intToUint(pcrs.PCRs)...),
			},
		},
	}

	policyPCRCmd := tpm2.PolicyPCR{
		PolicySession: sessionHandle,
		Pcrs:          pcrSel,
	}

	if _, err := policyPCRCmd.Execute(h.transport); err != nil {
		return 0, nil, err
	}

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

var _ Provider = (*HardwareProvider)(nil)
