//go:build darwin && !cgo

// Stub for when CGO is disabled - falls back to simulated Secure Enclave.

package tpm

// newRealSecureEnclaveProvider returns nil when CGO is not available.
// The simulated SecureEnclaveProvider will be used instead.
func newRealSecureEnclaveProvider() *RealSecureEnclaveProvider {
	return nil
}

// RealSecureEnclaveProvider is a placeholder when CGO is disabled.
// The actual implementation is in secureenclave_darwin.go (CGO build).
type RealSecureEnclaveProvider struct{}
