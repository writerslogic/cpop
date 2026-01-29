//go:build linux || windows

// Common TPM hardware operations shared between Linux and Windows.
// This file contains helper functions that operate on a TPM transport.

package tpm

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Common NV index constants
const (
	commonNVCounterIndex = 0x01500001
	commonNVCounterSize  = 8 // uint64
)

// tpmReadProperties reads TPM manufacturer and firmware version.
func tpmReadProperties(t transport.TPM) (manufacturer, fwVersion string, err error) {
	// Read manufacturer
	getCapCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTManufacturer),
		PropertyCount: 1,
	}

	rsp, err := getCapCmd.Execute(t)
	if err != nil {
		return "", "", err
	}

	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err == nil && len(props.TPMProperty) > 0 {
		mfr := props.TPMProperty[0].Value
		manufacturer = fmt.Sprintf("%c%c%c%c",
			byte(mfr>>24), byte(mfr>>16), byte(mfr>>8), byte(mfr))
	}

	// Read firmware version
	getCapCmd = tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTFirmwareVersion1),
		PropertyCount: 2,
	}

	rsp, err = getCapCmd.Execute(t)
	if err == nil {
		props, err := rsp.CapabilityData.Data.TPMProperties()
		if err == nil && len(props.TPMProperty) >= 2 {
			fwVersion = fmt.Sprintf("%d.%d",
				props.TPMProperty[0].Value, props.TPMProperty[1].Value)
		}
	}

	return manufacturer, fwVersion, nil
}

// tpmCreateSRK creates a Storage Root Key (primary key under owner hierarchy).
func tpmCreateSRK(t transport.TPM) (tpm2.TPMHandle, *tpm2.TPMTPublic, error) {
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

	rsp, err := createPrimaryCmd.Execute(t)
	if err != nil {
		return 0, nil, err
	}

	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		// Flush the handle if we can't get contents
		tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t)
		return 0, nil, fmt.Errorf("failed to get public contents: %w", err)
	}

	return rsp.ObjectHandle, pub, nil
}

// tpmGetEKPublic creates and returns the Endorsement Key public portion.
func tpmGetEKPublic(t transport.TPM) (*tpm2.TPM2BPublic, error) {
	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}

	rsp, err := createEKCmd.Execute(t)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t)

	return &rsp.OutPublic, nil
}

// tpmGetDeviceID returns a unique device identifier based on EK public key hash.
func tpmGetDeviceID(t transport.TPM) ([]byte, error) {
	ekPub, err := tpmGetEKPublic(t)
	if err != nil {
		return nil, err
	}

	pubBytes, err := ekPub.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EK public: %w", err)
	}

	hash := sha256.Sum256(pubBytes)
	return hash[:], nil
}

// tpmReadClock returns the current TPM clock information.
func tpmReadClock(t transport.TPM) (*ClockInfo, error) {
	readClockCmd := tpm2.ReadClock{}
	rsp, err := readClockCmd.Execute(t)
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

// tpmReadPCRs reads the specified PCR values.
func tpmReadPCRs(t transport.TPM, pcrs PCRSelection) (map[int][]byte, error) {
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

	rsp, err := pcrReadCmd.Execute(t)
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

// tpmComputePCRDigest computes the digest of PCR values.
func tpmComputePCRDigest(pcrValues map[int][]byte, pcrs PCRSelection) []byte {
	hasher := sha256.New()
	for _, pcrIdx := range pcrs.PCRs {
		if val, ok := pcrValues[pcrIdx]; ok {
			hasher.Write(val)
		}
	}
	return hasher.Sum(nil)
}

// tpmInitializeCounter creates the NV counter if it doesn't exist.
func tpmInitializeCounter(t transport.TPM) error {
	// Check if counter already exists
	readPubCmd := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(commonNVCounterIndex),
	}

	_, err := readPubCmd.Execute(t)
	if err == nil {
		return nil // Counter exists
	}

	// Create NV counter
	defineCmd := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth: tpm2.TPM2BAuth{
			Buffer: nil,
		},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex:    tpm2.TPMHandle(commonNVCounterIndex),
			NameAlg:    tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{NT: tpm2.TPMNTCounter},
			DataSize:   commonNVCounterSize,
		}),
	}

	if _, err := defineCmd.Execute(t); err != nil {
		return fmt.Errorf("NVDefineSpace failed: %w", err)
	}

	return nil
}

// tpmReadCounter reads the current NV counter value.
func tpmReadCounter(t transport.TPM) (uint64, error) {
	readCmd := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(commonNVCounterIndex),
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.TPMHandle(commonNVCounterIndex),
		Size:    commonNVCounterSize,
		Offset:  0,
	}

	rsp, err := readCmd.Execute(t)
	if err != nil {
		return 0, fmt.Errorf("NVRead failed: %w", err)
	}

	if len(rsp.Data.Buffer) < 8 {
		return 0, errors.New("counter data too short")
	}

	return binary.BigEndian.Uint64(rsp.Data.Buffer), nil
}

// tpmIncrementCounter atomically increments and returns the counter value.
func tpmIncrementCounter(t transport.TPM) (uint64, error) {
	incrementCmd := tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(commonNVCounterIndex),
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.TPMHandle(commonNVCounterIndex),
	}

	if _, err := incrementCmd.Execute(t); err != nil {
		return 0, fmt.Errorf("NVIncrement failed: %w", err)
	}

	return tpmReadCounter(t)
}

// tpmCreatePCRPolicy creates a policy session bound to PCR values.
// Returns the session handle and policy digest.
func tpmCreatePCRPolicy(t transport.TPM, pcrs PCRSelection) (tpm2.TPMHandle, []byte, error) {
	startAuthCmd := tpm2.StartAuthSession{
		SessionType: tpm2.TPMSEPolicy,
		AuthHash:    tpm2.TPMAlgSHA256,
		TPMKey:      tpm2.TPMRHNull,
		Bind:        tpm2.TPMRHNull,
	}

	startRsp, err := startAuthCmd.Execute(t)
	if err != nil {
		return 0, nil, err
	}

	sessionHandle := startRsp.SessionHandle

	pcrSel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs.PCRs...),
			},
		},
	}

	policyPCRCmd := tpm2.PolicyPCR{
		PolicySession: sessionHandle,
		Pcrs:          pcrSel,
	}

	if _, err := policyPCRCmd.Execute(t); err != nil {
		tpm2.FlushContext{FlushHandle: sessionHandle}.Execute(t)
		return 0, nil, err
	}

	getDigestCmd := tpm2.PolicyGetDigest{
		PolicySession: sessionHandle,
	}

	digestRsp, err := getDigestCmd.Execute(t)
	if err != nil {
		tpm2.FlushContext{FlushHandle: sessionHandle}.Execute(t)
		return 0, nil, err
	}

	return sessionHandle, digestRsp.PolicyDigest.Buffer, nil
}

// tpmFlushContext flushes a TPM handle, ignoring any errors.
func tpmFlushContext(t transport.TPM, handle tpm2.TPMHandle) {
	if handle != 0 && t != nil {
		tpm2.FlushContext{FlushHandle: handle}.Execute(t)
	}
}
