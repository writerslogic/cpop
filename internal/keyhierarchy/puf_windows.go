//go:build windows

// Package keyhierarchy implements a three-tier ratcheting key hierarchy for witnessd.
//
// This file provides Windows TPM 2.0 integration for hardware-bound PUF.
// The TPM provides a hardware-backed unique device identity that cannot be
// extracted or cloned.
//
// Patent Pending: USPTO Application No. 19/460,364
package keyhierarchy

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Errors for TPM PUF operations
var (
	ErrTPMNotAvailable = errors.New("keyhierarchy: TPM not available")
	ErrTPMOperation    = errors.New("keyhierarchy: TPM operation failed")
)

// TPMPUF implements PUFProvider using Windows TPM 2.0 via TBS.
type TPMPUF struct {
	mu        sync.Mutex
	deviceID  string
	transport transport.TPMCloser
	isOpen    bool
}

// NewTPMPUF creates a TPM-based PUF provider on Windows.
func NewTPMPUF() (*TPMPUF, error) {
	// Check if TPM is available through Windows TBS
	tpmTransport, err := transport.OpenTPM()
	if err != nil {
		return nil, ErrTPMNotAvailable
	}

	puf := &TPMPUF{
		transport: tpmTransport,
		isOpen:    true,
	}

	// Get device ID
	if err := puf.initDeviceID(); err != nil {
		tpmTransport.Close()
		return nil, fmt.Errorf("failed to get device ID: %w", err)
	}

	return puf, nil
}

// TPMAvailable checks if a TPM 2.0 is available on this Windows system.
func TPMAvailable() bool {
	tpmTransport, err := transport.OpenTPM()
	if err != nil {
		return false
	}
	tpmTransport.Close()
	return true
}

// initDeviceID initializes the device ID from the TPM
func (p *TPMPUF) initDeviceID() error {
	deviceID, err := p.getDeviceIDInternal()
	if err != nil {
		return err
	}
	p.deviceID = fmt.Sprintf("tpm-%x", deviceID[:8])
	return nil
}

// Close releases TPM resources
func (p *TPMPUF) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.isOpen && p.transport != nil {
		p.transport.Close()
		p.isOpen = false
	}
	return nil
}

// GetResponse returns a deterministic response for a challenge using the TPM.
// This uses the TPM's key derivation capabilities to produce a device-bound response.
func (p *TPMPUF) GetResponse(challenge []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.isOpen {
		return nil, ErrTPMNotAvailable
	}

	// Create a primary key for derivation
	primaryKey, err := p.createPrimaryKey()
	if err != nil {
		return nil, fmt.Errorf("failed to create primary key: %w", err)
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: primaryKey}
		flushCmd.Execute(p.transport)
	}()

	// Use HMAC with the primary key to derive a response
	response, err := p.deriveResponse(primaryKey, challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to derive response: %w", err)
	}

	return response, nil
}

// DeviceID returns the device identifier for this TPM.
func (p *TPMPUF) DeviceID() string {
	return p.deviceID
}

// createPrimaryKey creates a deterministic primary key for PUF derivation
func (p *TPMPUF) createPrimaryKey() (tpm2.TPMHandle, error) {
	createCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{Buffer: nil},
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Sign:                true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgHMAC,
						Details: tpm2.NewTPMUSchemeKeyedHash(
							tpm2.TPMAlgHMAC,
							&tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256},
						),
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgKeyedHash,
				&tpm2.TPM2BDigest{Buffer: []byte("witnessd-puf-v1")},
			),
		}),
	}

	rsp, err := createCmd.Execute(p.transport)
	if err != nil {
		return 0, err
	}

	return rsp.ObjectHandle, nil
}

// deriveResponse uses the primary key to derive a response from a challenge
func (p *TPMPUF) deriveResponse(keyHandle tpm2.TPMHandle, challenge []byte) ([]byte, error) {
	hmacCmd := tpm2.HMAC{
		Handle: tpm2.AuthHandle{
			Handle: keyHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Buffer:  tpm2.TPM2BMaxBuffer{Buffer: challenge},
		HashAlg: tpm2.TPMAlgSHA256,
	}

	rsp, err := hmacCmd.Execute(p.transport)
	if err != nil {
		return nil, err
	}

	return rsp.OutHMAC.Buffer, nil
}

// getDeviceIDInternal gets the TPM device ID from the EK
func (p *TPMPUF) getDeviceIDInternal() ([]byte, error) {
	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}

	rsp, err := createEKCmd.Execute(p.transport)
	if err != nil {
		return nil, err
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
		flushCmd.Execute(p.transport)
	}()

	pubBytes := tpm2.Marshal(rsp.OutPublic)
	hash := sha256.Sum256(pubBytes)

	return hash[:], nil
}

// DetectHardwarePUF attempts to detect and return a hardware PUF on Windows.
func DetectHardwarePUF() (PUFProvider, error) {
	tpmPUF, err := NewTPMPUF()
	if err == nil {
		return tpmPUF, nil
	}

	return nil, ErrTPMNotAvailable
}

// SealToTPM seals data to the TPM's PCR state
func (p *TPMPUF) SealToTPM(data []byte, pcrs []int) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.isOpen {
		return nil, ErrTPMNotAvailable
	}

	// Create SRK for sealing
	srkHandle, err := p.createSRK()
	if err != nil {
		return nil, fmt.Errorf("failed to create SRK: %w", err)
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: srkHandle}
		flushCmd.Execute(p.transport)
	}()

	// Create PCR policy
	policySession, policyDigest, err := p.createPCRPolicy(pcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to create PCR policy: %w", err)
	}
	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: policySession}
		flushCmd.Execute(p.transport)
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

	createRsp, err := createCmd.Execute(p.transport)
	if err != nil {
		return nil, fmt.Errorf("TPM Create failed: %w", err)
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

// createSRK creates a Storage Root Key
func (p *TPMPUF) createSRK() (tpm2.TPMHandle, error) {
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

	rsp, err := createPrimaryCmd.Execute(p.transport)
	if err != nil {
		return 0, err
	}

	return rsp.ObjectHandle, nil
}

// createPCRPolicy creates a policy session bound to PCR values
func (p *TPMPUF) createPCRPolicy(pcrs []int) (tpm2.TPMHandle, []byte, error) {
	startAuthCmd := tpm2.StartAuthSession{
		SessionType: tpm2.TPMSEPolicy,
		AuthHash:    tpm2.TPMAlgSHA256,
		TPMKey:      tpm2.TPMRHNull,
		Bind:        tpm2.TPMRHNull,
	}

	startRsp, err := startAuthCmd.Execute(p.transport)
	if err != nil {
		return 0, nil, err
	}

	sessionHandle := startRsp.SessionHandle

	uintPCRs := make([]uint, len(pcrs))
	for i, v := range pcrs {
		uintPCRs[i] = uint(v)
	}

	pcrSel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(uintPCRs...),
			},
		},
	}

	policyPCRCmd := tpm2.PolicyPCR{
		PolicySession: sessionHandle,
		Pcrs:          pcrSel,
	}

	if _, err := policyPCRCmd.Execute(p.transport); err != nil {
		flushCmd := tpm2.FlushContext{FlushHandle: sessionHandle}
		flushCmd.Execute(p.transport)
		return 0, nil, err
	}

	getDigestCmd := tpm2.PolicyGetDigest{
		PolicySession: sessionHandle,
	}

	digestRsp, err := getDigestCmd.Execute(p.transport)
	if err != nil {
		flushCmd := tpm2.FlushContext{FlushHandle: sessionHandle}
		flushCmd.Execute(p.transport)
		return 0, nil, err
	}

	return sessionHandle, digestRsp.PolicyDigest.Buffer, nil
}

// secureWipeWindows uses Windows-specific secure memory clearing
func secureWipeWindows(data []byte) {
	// Use explicit zeroing with memory barrier
	for i := range data {
		data[i] = 0
	}
	// Memory barrier - runtime.KeepAlive prevents the compiler from
	// optimizing away the writes
	runtime.KeepAlive(data)
}
