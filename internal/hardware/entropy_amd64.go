//go:build amd64

// Package hardware provides x86-64 specific entropy functions.
//
// This file implements RDRAND and RDSEED instruction support for AMD64.
package hardware

import (
	"errors"
)

// CPUID feature bits
const (
	cpuidRDRAND = 1 << 30 // ECX bit 30 in CPUID function 1
	cpuidRDSEED = 1 << 18 // EBX bit 18 in CPUID function 7
)

// cpuid executes the CPUID instruction.
// This is implemented in assembly on amd64.
func cpuid(eaxIn, ecxIn uint32) (eax, ebx, ecx, edx uint32)

// rdrand64 executes RDRAND and returns a 64-bit random number.
// Returns false if RDRAND underflows (needs retry).
func rdrand64() (uint64, bool)

// rdseed64 executes RDSEED and returns a 64-bit random number.
// Returns false if RDSEED underflows (needs retry).
func rdseed64() (uint64, bool)

// hasRDRANDPlatform checks if RDRAND is available.
func hasRDRANDPlatform() bool {
	_, _, ecx, _ := cpuid(1, 0)
	return ecx&cpuidRDRAND != 0
}

// hasRDSEEDPlatform checks if RDSEED is available.
func hasRDSEEDPlatform() bool {
	// First check if CPUID function 7 is supported
	maxFunc, _, _, _ := cpuid(0, 0)
	if maxFunc < 7 {
		return false
	}

	_, ebx, _, _ := cpuid(7, 0)
	return ebx&cpuidRDSEED != 0
}

// rdrandBytesPlatform fills buf with random bytes using RDRAND.
func rdrandBytesPlatform(buf []byte) error {
	if !hasRDRANDPlatform() {
		return ErrHardwareRNGNotAvail
	}

	// Fill 8 bytes at a time
	for i := 0; i < len(buf); {
		// Retry up to 10 times on underflow
		var val uint64
		ok := false
		for retry := 0; retry < 10; retry++ {
			val, ok = rdrand64()
			if ok {
				break
			}
		}
		if !ok {
			return errors.New("RDRAND underflow after retries")
		}

		// Copy bytes
		for j := 0; j < 8 && i < len(buf); j++ {
			buf[i] = byte(val >> (j * 8))
			i++
		}
	}

	return nil
}

// rdseedBytesPlatform fills buf with random bytes using RDSEED.
func rdseedBytesPlatform(buf []byte) error {
	if !hasRDSEEDPlatform() {
		return ErrHardwareRNGNotAvail
	}

	// Fill 8 bytes at a time
	for i := 0; i < len(buf); {
		// Retry up to 100 times on underflow (RDSEED underflows more often)
		var val uint64
		ok := false
		for retry := 0; retry < 100; retry++ {
			val, ok = rdseed64()
			if ok {
				break
			}
		}
		if !ok {
			return errors.New("RDSEED underflow after retries")
		}

		// Copy bytes
		for j := 0; j < 8 && i < len(buf); j++ {
			buf[i] = byte(val >> (j * 8))
			i++
		}
	}

	return nil
}
