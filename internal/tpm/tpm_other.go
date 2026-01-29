//go:build !linux && !darwin && !windows

// Platform-specific TPM implementation for unsupported platforms.

package tpm

// detectHardwareTPM returns nil on unsupported platforms.
func detectHardwareTPM() Provider {
	return nil
}
