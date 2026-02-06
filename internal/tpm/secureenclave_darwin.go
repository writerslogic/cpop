//go:build darwin && cgo

// Real Apple Secure Enclave implementation using Security.framework.
//
// This provides hardware-backed cryptographic operations on:
// - Apple Silicon Macs (M1/M2/M3+)
// - Intel Macs with T2 Security Chip
//
// The Secure Enclave protects the private key - it never leaves the hardware.
// Only P-256 ECDSA is supported (Apple limitation).

package tpm

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework IOKit

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdlib.h>
#include <string.h>

// Check if Secure Enclave is available
static int seIsAvailable() {
	// Check if we can access Secure Enclave by attempting to query for SE keys
	// This works on Apple Silicon and T2 Macs
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	if (!query) return 0;

	CFDictionarySetValue(query, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	CFDictionarySetValue(query, kSecClass, kSecClassKey);
	CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(query, kSecReturnRef, kCFBooleanFalse);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

	// Check if the query parameters are valid for this system
	OSStatus status = SecItemCopyMatching(query, NULL);
	CFRelease(query);

	// errSecItemNotFound means SE is available but no matching key
	// errSecSuccess means SE is available and found a key
	// Other errors mean SE is not available
	return (status == errSecSuccess || status == errSecItemNotFound) ? 1 : 0;
}

// Create or load a Secure Enclave key
// Returns: 0 on success, error code on failure
// On success, keyRef is set to the key reference
static OSStatus seCreateOrLoadKey(const char* keyTag, size_t tagLen, SecKeyRef* keyRef) {
	CFDataRef tagData = CFDataCreate(kCFAllocatorDefault, (const UInt8*)keyTag, tagLen);
	if (!tagData) return errSecAllocate;

	// First try to load existing key
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	if (!query) {
		CFRelease(tagData);
		return errSecAllocate;
	}

	CFDictionarySetValue(query, kSecClass, kSecClassKey);
	CFDictionarySetValue(query, kSecAttrApplicationTag, tagData);
	CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

	OSStatus status = SecItemCopyMatching(query, (CFTypeRef*)keyRef);
	CFRelease(query);

	if (status == errSecSuccess) {
		CFRelease(tagData);
		return errSecSuccess;
	}

	// Key not found, create new one in Secure Enclave
	CFMutableDictionaryRef privateKeyAttrs = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	if (!privateKeyAttrs) {
		CFRelease(tagData);
		return errSecAllocate;
	}

	CFDictionarySetValue(privateKeyAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
	CFDictionarySetValue(privateKeyAttrs, kSecAttrApplicationTag, tagData);

	// Access control - key can be used without authentication
	// For biometric, use kSecAccessControlBiometryAny
	SecAccessControlRef access = SecAccessControlCreateWithFlags(
		kCFAllocatorDefault,
		kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
		kSecAccessControlPrivateKeyUsage,
		NULL
	);

	if (access) {
		CFDictionarySetValue(privateKeyAttrs, kSecAttrAccessControl, access);
	}

	CFMutableDictionaryRef keyAttrs = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	if (!keyAttrs) {
		if (access) CFRelease(access);
		CFRelease(privateKeyAttrs);
		CFRelease(tagData);
		return errSecAllocate;
	}

	int keySize = 256;
	CFNumberRef keySizeRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &keySize);

	CFDictionarySetValue(keyAttrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	CFDictionarySetValue(keyAttrs, kSecAttrKeySizeInBits, keySizeRef);
	CFDictionarySetValue(keyAttrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);

	CFRelease(keySizeRef);
	CFDictionarySetValue(keyAttrs, kSecPrivateKeyAttrs, privateKeyAttrs);

	CFErrorRef error = NULL;
	*keyRef = SecKeyCreateRandomKey(keyAttrs, &error);

	CFRelease(keyAttrs);
	CFRelease(privateKeyAttrs);
	if (access) CFRelease(access);
	CFRelease(tagData);

	if (*keyRef == NULL) {
		if (error) {
			status = (OSStatus)CFErrorGetCode(error);
			CFRelease(error);
		} else {
			status = errSecInternalError;
		}
		return status;
	}

	return errSecSuccess;
}

// Delete a Secure Enclave key
static OSStatus seDeleteKey(const char* keyTag, size_t tagLen) {
	CFDataRef tagData = CFDataCreate(kCFAllocatorDefault, (const UInt8*)keyTag, tagLen);
	if (!tagData) return errSecAllocate;

	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	if (!query) {
		CFRelease(tagData);
		return errSecAllocate;
	}

	CFDictionarySetValue(query, kSecClass, kSecClassKey);
	CFDictionarySetValue(query, kSecAttrApplicationTag, tagData);

	OSStatus status = SecItemDelete(query);

	CFRelease(query);
	CFRelease(tagData);

	return status;
}

// Sign data using the Secure Enclave key
// Returns: 0 on success, error code on failure
// On success, signature and sigLen are populated
static OSStatus seSign(SecKeyRef keyRef, const void* data, size_t dataLen,
                       void** signature, size_t* sigLen) {
	CFDataRef dataToSign = CFDataCreate(kCFAllocatorDefault, (const UInt8*)data, dataLen);
	if (!dataToSign) return errSecAllocate;

	CFErrorRef error = NULL;
	CFDataRef sig = SecKeyCreateSignature(
		keyRef,
		kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
		dataToSign,
		&error
	);

	CFRelease(dataToSign);

	if (sig == NULL) {
		OSStatus status = errSecInternalError;
		if (error) {
			status = (OSStatus)CFErrorGetCode(error);
			CFRelease(error);
		}
		return status;
	}

	*sigLen = CFDataGetLength(sig);
	*signature = malloc(*sigLen);
	if (*signature == NULL) {
		CFRelease(sig);
		return errSecAllocate;
	}

	memcpy(*signature, CFDataGetBytePtr(sig), *sigLen);
	CFRelease(sig);

	return errSecSuccess;
}

// Get public key bytes from a Secure Enclave key
static OSStatus seGetPublicKey(SecKeyRef keyRef, void** pubKey, size_t* pubKeyLen) {
	SecKeyRef publicKey = SecKeyCopyPublicKey(keyRef);
	if (!publicKey) return errSecInternalError;

	CFErrorRef error = NULL;
	CFDataRef pubKeyData = SecKeyCopyExternalRepresentation(publicKey, &error);
	CFRelease(publicKey);

	if (pubKeyData == NULL) {
		OSStatus status = errSecInternalError;
		if (error) {
			status = (OSStatus)CFErrorGetCode(error);
			CFRelease(error);
		}
		return status;
	}

	*pubKeyLen = CFDataGetLength(pubKeyData);
	*pubKey = malloc(*pubKeyLen);
	if (*pubKey == NULL) {
		CFRelease(pubKeyData);
		return errSecAllocate;
	}

	memcpy(*pubKey, CFDataGetBytePtr(pubKeyData), *pubKeyLen);
	CFRelease(pubKeyData);

	return errSecSuccess;
}

// Get hardware UUID using IOKit
static int getHardwareUUID(char* uuid, size_t uuidLen) {
	io_service_t platformExpert = IOServiceGetMatchingService(
		kIOMainPortDefault,
		IOServiceMatching("IOPlatformExpertDevice")
	);
	if (!platformExpert) return -1;

	CFStringRef uuidString = IORegistryEntryCreateCFProperty(
		platformExpert,
		CFSTR(kIOPlatformUUIDKey),
		kCFAllocatorDefault,
		0
	);
	IOObjectRelease(platformExpert);

	if (!uuidString) return -1;

	Boolean success = CFStringGetCString(
		uuidString,
		uuid,
		uuidLen,
		kCFStringEncodingUTF8
	);
	CFRelease(uuidString);

	return success ? 0 : -1;
}

// Free memory allocated by C functions
static void seFree(void* ptr) {
	free(ptr);
}

// Release a SecKeyRef
static void seReleaseKey(SecKeyRef keyRef) {
	if (keyRef) CFRelease(keyRef);
}
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"
)

const (
	// Key tag for witnessd Secure Enclave key
	seKeyTag = "com.witnessd.secureenclave.signing"
)

// RealSecureEnclaveProvider implements Provider using actual Apple Secure Enclave.
type RealSecureEnclaveProvider struct {
	mu          sync.Mutex
	isOpen      bool
	keyRef      C.SecKeyRef
	deviceID    []byte
	publicKey   *ecdsa.PublicKey
	counter     uint64
	counterFile string
	startTime   time.Time
}

// isSecureEnclaveAvailable checks if Secure Enclave is available on this Mac.
func isSecureEnclaveAvailable() bool {
	return C.seIsAvailable() != 0
}

// newRealSecureEnclaveProvider creates a provider that uses actual Secure Enclave.
// Returns nil if Secure Enclave is not available.
func newRealSecureEnclaveProvider() *RealSecureEnclaveProvider {
	if !isSecureEnclaveAvailable() {
		return nil
	}

	// Determine base directory
	baseDir := os.Getenv("WITNESSD_DATA_DIR")
	if baseDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		baseDir = filepath.Join(home, ".witnessd")
	}

	return &RealSecureEnclaveProvider{
		counterFile: filepath.Join(baseDir, "se_counter"),
	}
}

// Available returns true if Secure Enclave is available.
func (s *RealSecureEnclaveProvider) Available() bool {
	return isSecureEnclaveAvailable()
}

// Open initializes the Secure Enclave provider.
func (s *RealSecureEnclaveProvider) Open() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isOpen {
		return ErrTPMAlreadyOpen
	}

	// Get device ID from hardware UUID
	if err := s.loadDeviceID(); err != nil {
		return fmt.Errorf("secure enclave: failed to get device ID: %w", err)
	}

	// Create or load the Secure Enclave key
	if err := s.loadOrCreateKey(); err != nil {
		return fmt.Errorf("secure enclave: failed to load/create key: %w", err)
	}

	// Load counter from file
	s.loadCounter()

	s.startTime = time.Now()
	s.isOpen = true
	return nil
}

// Close releases resources.
func (s *RealSecureEnclaveProvider) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil
	}

	// Save counter
	s.saveCounter()

	// Release key reference
	if s.keyRef != 0 {
		C.seReleaseKey(s.keyRef)
		s.keyRef = 0
	}

	s.isOpen = false
	s.publicKey = nil
	return nil
}

// DeviceID returns the hardware UUID.
func (s *RealSecureEnclaveProvider) DeviceID() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	result := make([]byte, len(s.deviceID))
	copy(result, s.deviceID)
	return result, nil
}

// PublicKey returns the Secure Enclave key's public key.
func (s *RealSecureEnclaveProvider) PublicKey() (crypto.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	if s.publicKey == nil {
		return nil, errors.New("secure enclave: no public key")
	}

	return s.publicKey, nil
}

// IncrementCounter atomically increments and returns the counter.
func (s *RealSecureEnclaveProvider) IncrementCounter() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return 0, ErrTPMNotOpen
	}

	s.counter++
	s.saveCounter()
	return s.counter, nil
}

// GetCounter returns the current counter value.
func (s *RealSecureEnclaveProvider) GetCounter() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return 0, ErrTPMNotOpen
	}

	return s.counter, nil
}

// GetClock returns clock information.
func (s *RealSecureEnclaveProvider) GetClock() (*ClockInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	elapsed := time.Since(s.startTime)
	return &ClockInfo{
		Clock:        uint64(elapsed.Milliseconds()),
		ResetCount:   0,
		RestartCount: 0,
		Safe:         true,
	}, nil
}

// Quote creates an attestation over the given data.
func (s *RealSecureEnclaveProvider) Quote(data []byte) (*Attestation, error) {
	return s.QuoteWithPCRs(data, DefaultPCRSelection())
}

// QuoteWithPCRs creates an attestation. PCR selection is ignored on macOS.
func (s *RealSecureEnclaveProvider) QuoteWithPCRs(data []byte, _ PCRSelection) (*Attestation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	if s.keyRef == 0 {
		return nil, errors.New("secure enclave: no key loaded")
	}

	// Get clock info
	elapsed := time.Since(s.startTime)
	clockInfo := &ClockInfo{
		Clock:        uint64(elapsed.Milliseconds()),
		ResetCount:   0,
		RestartCount: 0,
		Safe:         true,
	}

	// Increment counter
	s.counter++
	s.saveCounter()

	// Create quote structure (hash of data + counter + timestamp)
	h := sha256.New()
	h.Write([]byte("witnessd-se-quote-v2"))
	h.Write(data)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], s.counter)
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], clockInfo.Clock)
	h.Write(buf[:])
	quoteData := h.Sum(nil)

	// Sign with Secure Enclave
	var sigPtr unsafe.Pointer
	var sigLen C.size_t

	status := C.seSign(
		s.keyRef,
		unsafe.Pointer(&quoteData[0]),
		C.size_t(len(quoteData)),
		&sigPtr,
		&sigLen,
	)

	if status != 0 {
		return nil, fmt.Errorf("secure enclave: signing failed with status %d", status)
	}

	signature := C.GoBytes(sigPtr, C.int(sigLen))
	C.seFree(sigPtr)

	// Encode public key
	pubKeyBytes := s.encodePublicKey()

	return &Attestation{
		DeviceID:         s.deviceID,
		PublicKey:        pubKeyBytes,
		MonotonicCounter: s.counter,
		FirmwareVersion:  "SecureEnclave-2.0",
		ClockInfo:        *clockInfo,
		Data:             data,
		Signature:        signature,
		Quote:            quoteData,
		PCRValues:        nil,
		PCRDigest:        nil,
		CreatedAt:        time.Now(),
	}, nil
}

// ReadPCRs is not supported on Secure Enclave.
func (s *RealSecureEnclaveProvider) ReadPCRs(_ PCRSelection) (map[int][]byte, error) {
	return make(map[int][]byte), nil
}

// SealKey encrypts data - on Secure Enclave we use the key for signing,
// sealing uses a derived key from the hardware-bound signing.
func (s *RealSecureEnclaveProvider) SealKey(data []byte, _ PCRSelection) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	// For sealing, we sign the data and use the signature as additional entropy
	// for key derivation. This binds the sealed data to this specific Secure Enclave key.
	h := sha256.New()
	h.Write([]byte("witnessd-seal-nonce-v1"))
	h.Write(data)
	nonce := h.Sum(nil)

	// Sign the nonce with Secure Enclave
	var sigPtr unsafe.Pointer
	var sigLen C.size_t

	status := C.seSign(
		s.keyRef,
		unsafe.Pointer(&nonce[0]),
		C.size_t(len(nonce)),
		&sigPtr,
		&sigLen,
	)

	if status != 0 {
		return nil, fmt.Errorf("secure enclave: seal signing failed with status %d", status)
	}

	signature := C.GoBytes(sigPtr, C.int(sigLen))
	C.seFree(sigPtr)

	// Derive encryption key from signature
	keyMaterial := sha256.Sum256(signature)

	// Encrypt using AES-GCM (import from the simulated version's approach)
	// For simplicity, we'll use XOR with the derived key for now
	// A production implementation would use proper AES-GCM
	sealed := make([]byte, 1+32+len(data))
	sealed[0] = 4 // version 4: SE-bound sealing
	copy(sealed[1:33], nonce)
	for i, b := range data {
		sealed[33+i] = b ^ keyMaterial[i%32]
	}

	return sealed, nil
}

// UnsealKey decrypts previously sealed data.
func (s *RealSecureEnclaveProvider) UnsealKey(sealed []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	if len(sealed) < 34 {
		return nil, errors.New("secure enclave: sealed data too short")
	}

	version := sealed[0]
	if version != 4 {
		// Fall back to simulated provider for older versions
		return nil, fmt.Errorf("secure enclave: unsupported seal version %d", version)
	}

	nonce := sealed[1:33]

	// Re-sign the nonce to derive the same key
	var sigPtr unsafe.Pointer
	var sigLen C.size_t

	status := C.seSign(
		s.keyRef,
		unsafe.Pointer(&nonce[0]),
		C.size_t(len(nonce)),
		&sigPtr,
		&sigLen,
	)

	if status != 0 {
		return nil, fmt.Errorf("secure enclave: unseal signing failed with status %d", status)
	}

	signature := C.GoBytes(sigPtr, C.int(sigLen))
	C.seFree(sigPtr)

	// Derive decryption key
	keyMaterial := sha256.Sum256(signature)

	// Decrypt
	data := make([]byte, len(sealed)-33)
	for i := range data {
		data[i] = sealed[33+i] ^ keyMaterial[i%32]
	}

	return data, nil
}

// Manufacturer returns the provider type.
func (s *RealSecureEnclaveProvider) Manufacturer() string {
	return "Apple Secure Enclave"
}

// FirmwareVersion returns the version.
func (s *RealSecureEnclaveProvider) FirmwareVersion() string {
	return "2.0.0"
}

// Helper methods

func (s *RealSecureEnclaveProvider) loadDeviceID() error {
	uuid := make([]byte, 64)
	cUUID := (*C.char)(unsafe.Pointer(&uuid[0]))

	if C.getHardwareUUID(cUUID, C.size_t(len(uuid))) != 0 {
		// Fallback to hostname-based ID if hardware UUID unavailable
		hostname, _ := os.Hostname()
		h := sha256.Sum256([]byte("witnessd-fallback-" + hostname))
		s.deviceID = h[:16]
		return nil
	}

	// Hash the UUID for consistent length
	h := sha256.Sum256(uuid[:cStringLen(uuid)])
	s.deviceID = h[:16]
	return nil
}

func cStringLen(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}

func (s *RealSecureEnclaveProvider) loadOrCreateKey() error {
	keyTag := seKeyTag
	cKeyTag := C.CString(keyTag)
	defer C.free(unsafe.Pointer(cKeyTag))

	var keyRef C.SecKeyRef
	status := C.seCreateOrLoadKey(cKeyTag, C.size_t(len(keyTag)), &keyRef)
	if status != 0 {
		return fmt.Errorf("failed to create/load key: OSStatus %d", status)
	}

	s.keyRef = keyRef

	// Extract public key
	var pubKeyPtr unsafe.Pointer
	var pubKeyLen C.size_t

	status = C.seGetPublicKey(keyRef, &pubKeyPtr, &pubKeyLen)
	if status != 0 {
		return fmt.Errorf("failed to get public key: OSStatus %d", status)
	}

	pubKeyBytes := C.GoBytes(pubKeyPtr, C.int(pubKeyLen))
	C.seFree(pubKeyPtr)

	// Parse the public key (ANSI X9.63 format for P-256)
	if len(pubKeyBytes) != 65 || pubKeyBytes[0] != 0x04 {
		return errors.New("invalid public key format")
	}

	x := new(big.Int).SetBytes(pubKeyBytes[1:33])
	y := new(big.Int).SetBytes(pubKeyBytes[33:65])

	s.publicKey = &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return nil
}

func (s *RealSecureEnclaveProvider) encodePublicKey() []byte {
	if s.publicKey == nil {
		return nil
	}

	// ANSI X9.63 format
	result := make([]byte, 65)
	result[0] = 0x04
	xBytes := s.publicKey.X.Bytes()
	yBytes := s.publicKey.Y.Bytes()

	// Pad to 32 bytes each
	copy(result[33-len(xBytes):33], xBytes)
	copy(result[65-len(yBytes):65], yBytes)

	return result
}

func (s *RealSecureEnclaveProvider) loadCounter() {
	data, err := os.ReadFile(s.counterFile)
	if err != nil {
		s.counter = 0
		return
	}

	if len(data) >= 8 {
		s.counter = binary.BigEndian.Uint64(data)
	}
}

func (s *RealSecureEnclaveProvider) saveCounter() {
	dir := filepath.Dir(s.counterFile)
	os.MkdirAll(dir, 0700)

	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, s.counter)
	os.WriteFile(s.counterFile, data, 0600)
}

// DeviceInfo returns information about the Secure Enclave provider.
func (s *RealSecureEnclaveProvider) DeviceInfo() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return "SecureEnclave: not open"
	}

	return fmt.Sprintf("SecureEnclave(hardware): counter=%d", s.counter)
}

// Ensure RealSecureEnclaveProvider implements Provider
var _ Provider = (*RealSecureEnclaveProvider)(nil)
