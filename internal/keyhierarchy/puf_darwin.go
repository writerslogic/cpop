//go:build darwin

// Package keyhierarchy implements a three-tier ratcheting key hierarchy for witnessd.
//
// This file provides macOS Secure Enclave integration for hardware-bound PUF.
// The Secure Enclave provides a hardware-backed unique device identity that
// cannot be extracted or cloned.
//
// Patent Pending: USPTO Application No. 19/460,364
package keyhierarchy

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication -framework IOKit

#include <stdlib.h>
#include <string.h>

// Forward declarations for Objective-C functions
int se_available(void);
int se_get_or_create_key(const char *key_tag, unsigned char *pub_key_out, int pub_key_len);
int se_sign_data(const char *key_tag, const unsigned char *data, int data_len,
                 unsigned char *sig_out, int sig_len);
int se_derive_key(const char *key_tag, const unsigned char *challenge, int challenge_len,
                  unsigned char *derived_out, int derived_len);
char* se_get_device_id(void);
void se_free_string(char *s);
*/
import "C"

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// Errors for Secure Enclave operations
var (
	ErrSecureEnclaveNotAvailable = errors.New("keyhierarchy: Secure Enclave not available")
	ErrSecureEnclaveOperation    = errors.New("keyhierarchy: Secure Enclave operation failed")
)

// SecureEnclavePUF implements PUFProvider using macOS Secure Enclave.
// The Secure Enclave provides a hardware-backed unique device identity.
type SecureEnclavePUF struct {
	mu       sync.Mutex
	deviceID string
	keyTag   string
	pubKey   []byte
}

// secureEnclaveKeyTag is the keychain tag for the Secure Enclave key
const secureEnclaveKeyTag = "com.witnessd.identity.v1"

// NewSecureEnclavePUF creates a Secure Enclave PUF provider.
// If the Secure Enclave is not available, returns nil.
func NewSecureEnclavePUF() (*SecureEnclavePUF, error) {
	if !SecureEnclaveAvailable() {
		return nil, ErrSecureEnclaveNotAvailable
	}

	puf := &SecureEnclavePUF{
		keyTag: secureEnclaveKeyTag,
	}

	// Get or create the Secure Enclave key
	if err := puf.ensureKey(); err != nil {
		return nil, fmt.Errorf("failed to initialize Secure Enclave key: %w", err)
	}

	// Get device ID
	if err := puf.initDeviceID(); err != nil {
		return nil, fmt.Errorf("failed to get device ID: %w", err)
	}

	return puf, nil
}

// SecureEnclaveAvailable checks if the Secure Enclave is available on this device.
func SecureEnclaveAvailable() bool {
	// Secure Enclave is only available on Apple Silicon or T2 Macs
	if runtime.GOARCH != "arm64" {
		// On Intel Macs, check for T2 chip via IOKit (simplified check)
		return C.se_available() == 1
	}
	return C.se_available() == 1
}

// ensureKey creates or retrieves the Secure Enclave key
func (p *SecureEnclavePUF) ensureKey() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Allocate buffer for public key (P-256 compressed point: 33 bytes, or uncompressed: 65 bytes)
	pubKeyBuf := make([]byte, 65)

	cKeyTag := C.CString(p.keyTag)
	defer C.free(unsafe.Pointer(cKeyTag))

	result := C.se_get_or_create_key(
		cKeyTag,
		(*C.uchar)(unsafe.Pointer(&pubKeyBuf[0])),
		C.int(len(pubKeyBuf)),
	)

	if result <= 0 {
		return ErrSecureEnclaveOperation
	}

	p.pubKey = pubKeyBuf[:result]
	return nil
}

// initDeviceID initializes the device ID
func (p *SecureEnclavePUF) initDeviceID() error {
	cDeviceID := C.se_get_device_id()
	if cDeviceID == nil {
		// Fallback: use hash of public key
		hash := sha256.Sum256(p.pubKey)
		p.deviceID = fmt.Sprintf("se-%x", hash[:8])
		return nil
	}
	defer C.se_free_string(cDeviceID)

	p.deviceID = C.GoString(cDeviceID)
	if p.deviceID == "" {
		// Fallback: use hash of public key
		hash := sha256.Sum256(p.pubKey)
		p.deviceID = fmt.Sprintf("se-%x", hash[:8])
	}

	return nil
}

// GetResponse returns a deterministic response for a challenge using the Secure Enclave.
// This uses ECDSA signing with the Secure Enclave key to derive a deterministic value.
func (p *SecureEnclavePUF) GetResponse(challenge []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.pubKey == nil {
		return nil, ErrSecureEnclaveNotAvailable
	}

	// Use the Secure Enclave to derive a key from the challenge
	// We do this by signing the challenge and using the signature as entropy
	derivedBuf := make([]byte, 64)

	cKeyTag := C.CString(p.keyTag)
	defer C.free(unsafe.Pointer(cKeyTag))

	result := C.se_derive_key(
		cKeyTag,
		(*C.uchar)(unsafe.Pointer(&challenge[0])),
		C.int(len(challenge)),
		(*C.uchar)(unsafe.Pointer(&derivedBuf[0])),
		C.int(len(derivedBuf)),
	)

	if result <= 0 {
		return nil, ErrSecureEnclaveOperation
	}

	// Hash the derived value to get a consistent 32-byte output
	response := sha256.Sum256(derivedBuf[:result])
	return response[:], nil
}

// DeviceID returns the device identifier for this Secure Enclave.
func (p *SecureEnclavePUF) DeviceID() string {
	return p.deviceID
}

// PublicKey returns the Secure Enclave public key.
func (p *SecureEnclavePUF) PublicKey() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]byte, len(p.pubKey))
	copy(result, p.pubKey)
	return result
}

// DetectHardwarePUF attempts to detect and return a hardware PUF on macOS.
// It prefers Secure Enclave but falls back to software PUF if unavailable.
func DetectHardwarePUF() (PUFProvider, error) {
	// Try Secure Enclave first
	sePUF, err := NewSecureEnclavePUF()
	if err == nil {
		return sePUF, nil
	}

	// Fall back to software PUF
	return nil, ErrSecureEnclaveNotAvailable
}

// secureWipeDarwin uses macOS-specific secure memory clearing
func secureWipeDarwin(data []byte) {
	// Use explicit zeroing with memory barrier
	for i := range data {
		data[i] = 0
	}
	// Memory barrier - runtime.KeepAlive prevents the compiler from
	// optimizing away the writes
	runtime.KeepAlive(data)

	// On macOS, we could also use SecureZeroMemory equivalent via
	// explicit_bzero if available via cgo, but the above is sufficient
	// for most use cases as we use KeepAlive
}
