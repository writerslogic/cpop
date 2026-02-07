// Package keyhierarchy implements a three-tier ratcheting key hierarchy for witnessd.
//
// This file provides cross-platform secure memory wiping functionality.
// Secure memory wiping ensures that sensitive cryptographic material is
// overwritten before being released to the garbage collector.
//
// Patent Pending: USPTO Application No. 19/460,364
package keyhierarchy

import (
	"runtime"
	"unsafe"
)

// SecureWipeConfig contains configuration for secure wiping
type SecureWipeConfig struct {
	// MultiPass enables multiple wipe passes (DoD 5220.22-M style)
	MultiPass bool
	// NumPasses is the number of wipe passes when MultiPass is true
	NumPasses int
}

// DefaultWipeConfig returns the default wipe configuration
func DefaultWipeConfig() SecureWipeConfig {
	return SecureWipeConfig{
		MultiPass: false,
		NumPasses: 3,
	}
}

// SecureWipeBytes securely wipes a byte slice with configurable options.
// This function uses multiple techniques to prevent compiler optimization
// from removing the wipe operations:
//
//  1. Direct memory writes through unsafe pointer
//  2. Memory barrier using runtime.KeepAlive
//  3. Volatile-style writes that prevent reordering
//
// Note: Go's garbage collector does not guarantee secure deallocation,
// so this function should be called before sensitive data leaves scope.
func SecureWipeBytes(data []byte, config SecureWipeConfig) {
	if len(data) == 0 {
		return
	}

	if config.MultiPass && config.NumPasses > 1 {
		// Multi-pass wipe (DoD style)
		multiPassWipe(data, config.NumPasses)
	} else {
		// Single pass zero wipe
		singlePassWipe(data)
	}

	// Final memory barrier to ensure writes complete
	runtime.KeepAlive(data)
}

// singlePassWipe performs a single-pass zero wipe
func singlePassWipe(data []byte) {
	// Use explicit indexing to prevent compiler optimization
	for i := 0; i < len(data); i++ {
		// Use volatile-style write through pointer arithmetic
		ptr := uintptr(unsafe.Pointer(&data[0])) + uintptr(i)
		*(*byte)(unsafe.Pointer(ptr)) = 0
	}
}

// multiPassWipe performs multiple passes with different patterns
func multiPassWipe(data []byte, passes int) {
	patterns := []byte{0x00, 0xFF, 0x55, 0xAA, 0x00}

	for pass := 0; pass < passes; pass++ {
		pattern := patterns[pass%len(patterns)]
		for i := 0; i < len(data); i++ {
			ptr := uintptr(unsafe.Pointer(&data[0])) + uintptr(i)
			*(*byte)(unsafe.Pointer(ptr)) = pattern
		}
		// Memory barrier between passes
		runtime.KeepAlive(data)
	}
}

// SecureWipeSlice32 securely wipes a [32]byte array
func SecureWipeSlice32(data *[32]byte) {
	if data == nil {
		return
	}

	// Use volatile-style writes
	for i := 0; i < 32; i++ {
		ptr := uintptr(unsafe.Pointer(&data[0])) + uintptr(i)
		*(*byte)(unsafe.Pointer(ptr)) = 0
	}

	runtime.KeepAlive(data)
}

// SecureWipeSlice64 securely wipes a [64]byte array
func SecureWipeSlice64(data *[64]byte) {
	if data == nil {
		return
	}

	for i := 0; i < 64; i++ {
		ptr := uintptr(unsafe.Pointer(&data[0])) + uintptr(i)
		*(*byte)(unsafe.Pointer(ptr)) = 0
	}

	runtime.KeepAlive(data)
}

// WipedKey is a wrapper for Ed25519 private keys that provides
// automatic secure wiping through a finalizer
type WipedKey struct {
	key     []byte
	isWiped bool
}

// NewWipedKey creates a new WipedKey from an Ed25519 private key.
// The key will be securely wiped when Wipe() is called or when
// the WipedKey is garbage collected.
func NewWipedKey(key []byte) *WipedKey {
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	wk := &WipedKey{
		key:     keyCopy,
		isWiped: false,
	}

	// Set finalizer to wipe key on garbage collection
	runtime.SetFinalizer(wk, func(k *WipedKey) {
		k.Wipe()
	})

	return wk
}

// Key returns the underlying key bytes.
// Returns nil if the key has been wiped.
func (wk *WipedKey) Key() []byte {
	if wk.isWiped {
		return nil
	}
	return wk.key
}

// Wipe securely wipes the key material.
// After calling Wipe(), Key() will return nil.
func (wk *WipedKey) Wipe() {
	if wk.isWiped || wk.key == nil {
		return
	}

	singlePassWipe(wk.key)
	wk.isWiped = true

	// Clear the finalizer since we've already wiped
	runtime.SetFinalizer(wk, nil)
}

// IsWiped returns true if the key has been wiped.
func (wk *WipedKey) IsWiped() bool {
	return wk.isWiped
}

// WipedSecret provides a similar wrapper for arbitrary secret data
type WipedSecret struct {
	data    []byte
	isWiped bool
}

// NewWipedSecret creates a new WipedSecret.
func NewWipedSecret(data []byte) *WipedSecret {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	ws := &WipedSecret{
		data:    dataCopy,
		isWiped: false,
	}

	runtime.SetFinalizer(ws, func(s *WipedSecret) {
		s.Wipe()
	})

	return ws
}

// Data returns the underlying data.
func (ws *WipedSecret) Data() []byte {
	if ws.isWiped {
		return nil
	}
	return ws.data
}

// Wipe securely wipes the secret.
func (ws *WipedSecret) Wipe() {
	if ws.isWiped || ws.data == nil {
		return
	}

	singlePassWipe(ws.data)
	ws.isWiped = true
	runtime.SetFinalizer(ws, nil)
}

// SecureCompare performs a constant-time comparison of two byte slices.
// This is important for comparing MACs and signatures to prevent timing attacks.
func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}

	return diff == 0
}
