package tpm

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"
)

// TestSoftwareProviderBasics tests basic SoftwareProvider functionality.
func TestSoftwareProviderBasics(t *testing.T) {
	provider := NewSoftwareProvider()

	if !provider.Available() {
		t.Error("SoftwareProvider should be available")
	}

	// Test Open/Close
	if err := provider.Open(); err != nil {
		t.Errorf("Open failed: %v", err)
	}

	if err := provider.Open(); err != ErrTPMAlreadyOpen {
		t.Errorf("Expected ErrTPMAlreadyOpen, got: %v", err)
	}

	if err := provider.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

// TestSoftwareProviderDeviceID tests device ID generation.
func TestSoftwareProviderDeviceID(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	deviceID, err := provider.DeviceID()
	if err != nil {
		t.Errorf("DeviceID failed: %v", err)
	}

	if len(deviceID) != 16 {
		t.Errorf("Expected 16-byte device ID, got %d bytes", len(deviceID))
	}

	// Should be consistent
	deviceID2, _ := provider.DeviceID()
	if !bytes.Equal(deviceID, deviceID2) {
		t.Error("DeviceID should be consistent")
	}
}

// TestSoftwareProviderCounter tests monotonic counter.
func TestSoftwareProviderCounter(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	// Initial counter should be 0
	counter, err := provider.GetCounter()
	if err != nil {
		t.Errorf("GetCounter failed: %v", err)
	}
	if counter != 0 {
		t.Errorf("Initial counter should be 0, got %d", counter)
	}

	// Increment counter
	newCounter, err := provider.IncrementCounter()
	if err != nil {
		t.Errorf("IncrementCounter failed: %v", err)
	}
	if newCounter != 1 {
		t.Errorf("Counter should be 1 after increment, got %d", newCounter)
	}

	// Counter should be strictly increasing
	for i := 0; i < 10; i++ {
		prev := newCounter
		newCounter, _ = provider.IncrementCounter()
		if newCounter <= prev {
			t.Errorf("Counter not strictly increasing: %d -> %d", prev, newCounter)
		}
	}
}

// TestSoftwareProviderClock tests clock info.
func TestSoftwareProviderClock(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	clock1, err := provider.GetClock()
	if err != nil {
		t.Errorf("GetClock failed: %v", err)
	}

	if !clock1.Safe {
		t.Error("Clock should be in safe state")
	}

	// Wait and check clock advances
	time.Sleep(50 * time.Millisecond)

	clock2, _ := provider.GetClock()
	if clock2.Clock <= clock1.Clock {
		t.Error("Clock should advance over time")
	}
}

// TestSoftwareProviderQuote tests quote generation.
func TestSoftwareProviderQuote(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	testData := []byte("test checkpoint hash data")

	attestation, err := provider.Quote(testData)
	if err != nil {
		t.Errorf("Quote failed: %v", err)
	}

	// Verify attestation fields
	if len(attestation.DeviceID) == 0 {
		t.Error("Attestation should have device ID")
	}
	if attestation.MonotonicCounter == 0 {
		t.Error("Attestation should increment counter")
	}
	if len(attestation.Data) == 0 {
		t.Error("Attestation should include data")
	}
	if len(attestation.Signature) == 0 {
		t.Error("Attestation should have signature")
	}
	if len(attestation.Quote) == 0 {
		t.Error("Attestation should have quote structure")
	}
	if len(attestation.PCRValues) == 0 {
		t.Error("Attestation should include PCR values")
	}
	if !attestation.ClockInfo.Safe {
		t.Error("Clock should be safe")
	}

	// Data should match input
	if !bytes.Equal(attestation.Data, testData) {
		t.Error("Attestation data should match input")
	}
}

// TestSoftwareProviderQuoteWithPCRs tests quote with custom PCR selection.
func TestSoftwareProviderQuoteWithPCRs(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	testData := []byte("custom pcr test")
	customPCRs := PCRSelection{
		Hash: HashSHA256,
		PCRs: []int{0, 7},
	}

	attestation, err := provider.QuoteWithPCRs(testData, customPCRs)
	if err != nil {
		t.Errorf("QuoteWithPCRs failed: %v", err)
	}

	// Should include requested PCRs
	if _, ok := attestation.PCRValues[0]; !ok {
		t.Error("Should include PCR 0")
	}
	if _, ok := attestation.PCRValues[7]; !ok {
		t.Error("Should include PCR 7")
	}
}

// TestSoftwareProviderReadPCRs tests PCR reading.
func TestSoftwareProviderReadPCRs(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	pcrs := DefaultPCRSelection()
	pcrValues, err := provider.ReadPCRs(pcrs)
	if err != nil {
		t.Errorf("ReadPCRs failed: %v", err)
	}

	// Should have values for all requested PCRs
	for _, idx := range pcrs.PCRs {
		if _, ok := pcrValues[idx]; !ok {
			t.Errorf("Missing PCR %d", idx)
		}
	}

	// PCR values should be 32 bytes (SHA-256)
	for idx, val := range pcrValues {
		if len(val) != 32 {
			t.Errorf("PCR %d should be 32 bytes, got %d", idx, len(val))
		}
	}
}

// TestSoftwareProviderSealUnseal tests key sealing and unsealing.
func TestSoftwareProviderSealUnseal(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	// Test data to seal
	secretKey := []byte("this is a secret ed25519 seed!!")

	sealed, err := provider.SealKey(secretKey, DefaultPCRSelection())
	if err != nil {
		t.Errorf("SealKey failed: %v", err)
	}

	if len(sealed) <= len(secretKey) {
		t.Error("Sealed data should be larger than input")
	}

	// Unseal should recover original data
	unsealed, err := provider.UnsealKey(sealed)
	if err != nil {
		t.Errorf("UnsealKey failed: %v", err)
	}

	if !bytes.Equal(unsealed, secretKey) {
		t.Error("Unsealed data should match original")
	}
}

// TestSoftwareProviderManufacturer tests manufacturer info.
func TestSoftwareProviderManufacturer(t *testing.T) {
	provider := NewSoftwareProvider()

	if provider.Manufacturer() != "Software Simulator" {
		t.Errorf("Unexpected manufacturer: %s", provider.Manufacturer())
	}
	if provider.FirmwareVersion() != "1.0.0-sim" {
		t.Errorf("Unexpected firmware version: %s", provider.FirmwareVersion())
	}
}

// TestNoOpProvider tests NoOpProvider fallback.
func TestNoOpProvider(t *testing.T) {
	provider := NoOpProvider{}

	if provider.Available() {
		t.Error("NoOpProvider should not be available")
	}

	if err := provider.Open(); err != ErrTPMNotAvailable {
		t.Errorf("Expected ErrTPMNotAvailable, got: %v", err)
	}

	if _, err := provider.DeviceID(); err != ErrTPMNotAvailable {
		t.Errorf("Expected ErrTPMNotAvailable, got: %v", err)
	}

	if _, err := provider.Quote(nil); err != ErrTPMNotAvailable {
		t.Errorf("Expected ErrTPMNotAvailable, got: %v", err)
	}
}

// TestBinder tests the TPM binder.
func TestBinder(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	binder := NewBinder(provider)

	if !binder.Available() {
		t.Error("Binder should be available with SoftwareProvider")
	}

	// Create a checkpoint hash
	checkpointHash := sha256.Sum256([]byte("test checkpoint"))

	binding, err := binder.Bind(checkpointHash)
	if err != nil {
		t.Errorf("Bind failed: %v", err)
	}

	if binding.CheckpointHash != checkpointHash {
		t.Error("Binding should include checkpoint hash")
	}
	if binding.PreviousCounter != 0 {
		t.Error("First binding should have zero previous counter")
	}
	if binding.Attestation.MonotonicCounter == 0 {
		t.Error("Binding should have non-zero counter")
	}
}

// TestBinderChain tests binding multiple checkpoints.
func TestBinderChain(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	binder := NewBinder(provider)

	var bindings []Binding
	for i := 0; i < 5; i++ {
		hash := sha256.Sum256([]byte("checkpoint " + string(rune(i))))
		binding, err := binder.Bind(hash)
		if err != nil {
			t.Errorf("Bind %d failed: %v", i, err)
		}
		bindings = append(bindings, *binding)
	}

	// Verify counter chain
	for i := 1; i < len(bindings); i++ {
		if bindings[i].PreviousCounter != bindings[i-1].Attestation.MonotonicCounter {
			t.Errorf("Binding %d: previous counter mismatch", i)
		}
	}

	// Verify chain using VerifyBindingChain
	if err := VerifyBindingChain(bindings, nil); err != nil {
		t.Errorf("VerifyBindingChain failed: %v", err)
	}
}

// TestVerifyBinding tests binding verification.
func TestVerifyBinding(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	binder := NewBinder(provider)
	hash := sha256.Sum256([]byte("test"))
	binding, _ := binder.Bind(hash)

	// Valid binding should verify
	if err := VerifyBinding(binding, nil); err != nil {
		t.Errorf("VerifyBinding failed: %v", err)
	}

	// Tampered binding should fail
	tamperedBinding := *binding
	tamperedBinding.CheckpointHash = sha256.Sum256([]byte("tampered"))
	if err := VerifyBinding(&tamperedBinding, nil); err == nil {
		t.Error("Tampered binding should fail verification")
	}

	// Missing signature should fail
	noSigBinding := *binding
	noSigBinding.Attestation.Signature = nil
	if err := VerifyBinding(&noSigBinding, nil); err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got: %v", err)
	}
}

// TestVerifyBindingCounterRollback tests counter rollback detection.
func TestVerifyBindingCounterRollback(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	binder := NewBinder(provider)

	hash1 := sha256.Sum256([]byte("checkpoint1"))
	binding1, _ := binder.Bind(hash1)

	hash2 := sha256.Sum256([]byte("checkpoint2"))
	binding2, _ := binder.Bind(hash2)

	// Simulate rollback by setting counter lower than previous
	rollbackBinding := *binding2
	rollbackBinding.PreviousCounter = binding1.Attestation.MonotonicCounter + 10

	if err := VerifyBinding(&rollbackBinding, nil); err != ErrCounterRollback {
		t.Errorf("Expected ErrCounterRollback, got: %v", err)
	}
}

// TestBindingEncoding tests binding serialization.
func TestBindingEncoding(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	binder := NewBinder(provider)
	hash := sha256.Sum256([]byte("test"))
	binding, _ := binder.Bind(hash)

	// Encode
	encoded, err := binding.Encode()
	if err != nil {
		t.Errorf("Encode failed: %v", err)
	}

	// Decode
	decoded, err := DecodeBinding(encoded)
	if err != nil {
		t.Errorf("DecodeBinding failed: %v", err)
	}

	// Compare
	if decoded.CheckpointHash != binding.CheckpointHash {
		t.Error("Decoded checkpoint hash mismatch")
	}
	if decoded.PreviousCounter != binding.PreviousCounter {
		t.Error("Decoded previous counter mismatch")
	}
	if decoded.Attestation.MonotonicCounter != binding.Attestation.MonotonicCounter {
		t.Error("Decoded monotonic counter mismatch")
	}
}

// TestAttestationEncoding tests attestation serialization.
func TestAttestationEncoding(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	attestation, _ := provider.Quote([]byte("test data"))

	// Encode
	encoded, err := attestation.Encode()
	if err != nil {
		t.Errorf("Encode failed: %v", err)
	}

	// Decode
	decoded, err := DecodeAttestation(encoded)
	if err != nil {
		t.Errorf("DecodeAttestation failed: %v", err)
	}

	// Compare key fields
	if decoded.MonotonicCounter != attestation.MonotonicCounter {
		t.Error("Decoded monotonic counter mismatch")
	}
	if !bytes.Equal(decoded.Data, attestation.Data) {
		t.Error("Decoded data mismatch")
	}
	if decoded.ClockInfo.Safe != attestation.ClockInfo.Safe {
		t.Error("Decoded clock safe flag mismatch")
	}
}

// TestAttestationHash tests attestation hashing.
func TestAttestationHash(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	attestation1, _ := provider.Quote([]byte("test1"))
	attestation2, _ := provider.Quote([]byte("test2"))

	hash1 := attestation1.Hash()
	hash2 := attestation2.Hash()

	// Different attestations should have different hashes
	if hash1 == hash2 {
		t.Error("Different attestations should have different hashes")
	}

	// Same attestation should have consistent hash
	hash1Again := attestation1.Hash()
	if hash1 != hash1Again {
		t.Error("Hash should be consistent")
	}
}

// TestDefaultPCRSelection tests default PCR selection.
func TestDefaultPCRSelection(t *testing.T) {
	pcrs := DefaultPCRSelection()

	if pcrs.Hash != HashSHA256 {
		t.Error("Default should use SHA-256")
	}

	// Should include PCRs 0, 4, 7
	expected := []int{0, 4, 7}
	if len(pcrs.PCRs) != len(expected) {
		t.Errorf("Expected %d PCRs, got %d", len(expected), len(pcrs.PCRs))
	}

	for i, idx := range expected {
		if pcrs.PCRs[i] != idx {
			t.Errorf("PCR %d: expected %d, got %d", i, idx, pcrs.PCRs[i])
		}
	}
}

// TestHashAlgorithmString tests hash algorithm string representation.
func TestHashAlgorithmString(t *testing.T) {
	tests := []struct {
		alg    HashAlgorithm
		expect string
	}{
		{HashSHA1, "SHA-1"},
		{HashSHA256, "SHA-256"},
		{HashSHA384, "SHA-384"},
		{HashSHA512, "SHA-512"},
		{HashAlgorithm(0x9999), "Unknown(0x9999)"},
	}

	for _, tc := range tests {
		if tc.alg.String() != tc.expect {
			t.Errorf("Hash %d: expected %s, got %s", tc.alg, tc.expect, tc.alg.String())
		}
	}
}

// TestDetectTPM tests TPM detection (should return NoOp or HardwareProvider).
func TestDetectTPM(t *testing.T) {
	provider := DetectTPM()
	if provider == nil {
		t.Fatal("DetectTPM should never return nil")
	}

	// Either available (hardware TPM) or not (NoOp)
	// Just verify it doesn't panic
	_ = provider.Available()
	_ = provider.Manufacturer()
	_ = provider.FirmwareVersion()
}

// TestBinderUnavailable tests binder with unavailable TPM.
func TestBinderUnavailable(t *testing.T) {
	binder := NewBinder(NoOpProvider{})

	if binder.Available() {
		t.Error("Binder should not be available with NoOpProvider")
	}

	hash := sha256.Sum256([]byte("test"))
	_, err := binder.Bind(hash)
	if err != ErrTPMNotAvailable {
		t.Errorf("Expected ErrTPMNotAvailable, got: %v", err)
	}
}

// TestConcurrentQuotes tests concurrent quote generation.
func TestConcurrentQuotes(t *testing.T) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			data := []byte("concurrent test " + string(rune(n)))
			_, err := provider.Quote(data)
			if err != nil {
				t.Errorf("Concurrent Quote %d failed: %v", n, err)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// BenchmarkQuote benchmarks quote generation.
func BenchmarkQuote(b *testing.B) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	data := []byte("benchmark test data")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = provider.Quote(data)
	}
}

// BenchmarkSealUnseal benchmarks seal/unseal operations.
func BenchmarkSealUnseal(b *testing.B) {
	provider := NewSoftwareProvider()
	provider.Open()
	defer provider.Close()

	data := []byte("32-byte-secret-key-for-ed25519!")
	pcrs := DefaultPCRSelection()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sealed, _ := provider.SealKey(data, pcrs)
		_, _ = provider.UnsealKey(sealed)
	}
}
