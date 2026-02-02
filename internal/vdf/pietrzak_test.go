package vdf

import (
	"crypto/sha256"
	"math/big"
	"testing"
	"time"
)

func TestDefaultPietrzakParams(t *testing.T) {
	params := DefaultPietrzakParams()

	if params.N == nil {
		t.Error("N should not be nil")
	}
	if params.T == 0 {
		t.Error("T should not be 0")
	}
	if params.Lambda == 0 {
		t.Error("Lambda should not be 0")
	}
}

func TestNewPietrzakVDF(t *testing.T) {
	params := DefaultPietrzakParams()
	vdf, err := NewPietrzakVDF(params)
	if err != nil {
		t.Fatalf("NewPietrzakVDF failed: %v", err)
	}
	if vdf == nil {
		t.Error("VDF should not be nil")
	}
}

func TestNewPietrzakVDFInvalidParams(t *testing.T) {
	// Nil modulus
	params := PietrzakParams{N: nil, T: 100}
	_, err := NewPietrzakVDF(params)
	if err == nil {
		t.Error("expected error for nil modulus")
	}

	// Zero T
	params = PietrzakParams{N: defaultModulus, T: 0}
	_, err = NewPietrzakVDF(params)
	if err == nil {
		t.Error("expected error for T=0")
	}

	// Negative modulus
	params = PietrzakParams{N: big.NewInt(-1), T: 100}
	_, err = NewPietrzakVDF(params)
	if err == nil {
		t.Error("expected error for negative modulus")
	}

	// Untrusted modulus (not RSA challenge number)
	// This simulates someone generating their own primes - they would know the factorization!
	untrustedModulus := big.NewInt(3 * 5) // Obviously factorable
	params = PietrzakParams{N: untrustedModulus, T: 100, Lambda: 128}
	_, err = NewPietrzakVDF(params)
	if err == nil {
		t.Error("expected error for untrusted modulus")
	}

	// Same modulus with AllowUntrustedModulus=true (dangerous but allowed)
	params = PietrzakParams{N: untrustedModulus, T: 100, Lambda: 128, AllowUntrustedModulus: true}
	_, err = NewPietrzakVDF(params)
	if err != nil {
		t.Error("should allow untrusted modulus when AllowUntrustedModulus=true")
	}
}

func TestIsKnownSafeModulus(t *testing.T) {
	// RSA-2048 challenge should be safe
	if !IsKnownSafeModulus(rsaChallenge2048) {
		t.Error("RSA-2048 challenge should be known safe")
	}

	// Default modulus should be safe
	if !IsKnownSafeModulus(defaultModulus) {
		t.Error("default modulus should be known safe")
	}

	// Arbitrary number should not be safe
	if IsKnownSafeModulus(big.NewInt(12345)) {
		t.Error("arbitrary number should not be known safe")
	}

	// Nil should not be safe
	if IsKnownSafeModulus(nil) {
		t.Error("nil should not be known safe")
	}
}

func TestKnownSafeModuli(t *testing.T) {
	moduli := KnownSafeModuli()
	if len(moduli) == 0 {
		t.Error("should have at least one known safe modulus")
	}

	// All returned moduli should pass validation
	for i, m := range moduli {
		if !IsKnownSafeModulus(m) {
			t.Errorf("modulus %d should be known safe", i)
		}
	}
}

func TestPietrzakEvaluateSmall(t *testing.T) {
	// Use small T for faster test
	params := PietrzakParams{
		N:      defaultModulus,
		T:      64, // Small but enough for meaningful proof
		Lambda: 128,
	}

	vdf, err := NewPietrzakVDF(params)
	if err != nil {
		t.Fatalf("NewPietrzakVDF failed: %v", err)
	}

	x := big.NewInt(2)
	proof, err := vdf.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if proof == nil {
		t.Fatal("proof should not be nil")
	}
	if proof.Input.Cmp(x) != 0 {
		t.Error("input mismatch")
	}
	if proof.Output == nil {
		t.Error("output should not be nil")
	}
	if proof.T != params.T {
		t.Errorf("T mismatch: expected %d, got %d", params.T, proof.T)
	}
	if len(proof.Intermediates) == 0 {
		t.Error("should have intermediate values")
	}
	if proof.ComputeTime <= 0 {
		t.Error("compute time should be positive")
	}
}

func TestPietrzakVerifySmall(t *testing.T) {
	params := PietrzakParams{
		N:      defaultModulus,
		T:      64,
		Lambda: 128,
	}

	vdf, err := NewPietrzakVDF(params)
	if err != nil {
		t.Fatalf("NewPietrzakVDF failed: %v", err)
	}

	x := big.NewInt(2)
	proof, err := vdf.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// Verify should succeed
	if !vdf.Verify(proof) {
		t.Error("valid proof should verify")
	}
}

func TestPietrzakVerifyCorruptedOutput(t *testing.T) {
	params := PietrzakParams{
		N:      defaultModulus,
		T:      32,
		Lambda: 128,
	}

	vdf, err := NewPietrzakVDF(params)
	if err != nil {
		t.Fatalf("NewPietrzakVDF failed: %v", err)
	}

	x := big.NewInt(2)
	proof, err := vdf.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// Corrupt the output
	proof.Output.Add(proof.Output, big.NewInt(1))

	if vdf.Verify(proof) {
		t.Error("corrupted proof should not verify")
	}
}

func TestPietrzakVerifyCorruptedIntermediate(t *testing.T) {
	params := PietrzakParams{
		N:      defaultModulus,
		T:      64,
		Lambda: 128,
	}

	vdf, err := NewPietrzakVDF(params)
	if err != nil {
		t.Fatalf("NewPietrzakVDF failed: %v", err)
	}

	x := big.NewInt(2)
	proof, err := vdf.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// Corrupt an intermediate value
	if len(proof.Intermediates) > 0 {
		proof.Intermediates[0].Add(proof.Intermediates[0], big.NewInt(1))
	}

	if vdf.Verify(proof) {
		t.Error("proof with corrupted intermediate should not verify")
	}
}

func TestPietrzakVerifyNilProof(t *testing.T) {
	params := DefaultPietrzakParams()
	vdf, _ := NewPietrzakVDF(params)

	if vdf.Verify(nil) {
		t.Error("nil proof should not verify")
	}
}

func TestPietrzakVerifyNilFields(t *testing.T) {
	params := DefaultPietrzakParams()
	vdf, _ := NewPietrzakVDF(params)

	// Nil input
	proof := &PietrzakProof{
		Input:  nil,
		Output: big.NewInt(1),
		T:      100,
	}
	if vdf.Verify(proof) {
		t.Error("proof with nil input should not verify")
	}

	// Nil output
	proof = &PietrzakProof{
		Input:  big.NewInt(1),
		Output: nil,
		T:      100,
	}
	if vdf.Verify(proof) {
		t.Error("proof with nil output should not verify")
	}
}

func TestPietrzakProofSize(t *testing.T) {
	params := PietrzakParams{
		N:      defaultModulus,
		T:      1024,
		Lambda: 128,
	}

	vdf, err := NewPietrzakVDF(params)
	if err != nil {
		t.Fatalf("NewPietrzakVDF failed: %v", err)
	}

	x := big.NewInt(2)
	proof, err := vdf.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// Proof size should be O(log T)
	size := proof.PietrzakProofSize()
	if size <= 0 {
		t.Error("proof size should be positive")
	}

	// For T=1024, we expect about log2(1024) = 10 intermediates
	// Each intermediate is ~256 bytes, so ~2560 bytes
	expectedMin := 5 * 256  // At least 5 intermediates
	expectedMax := 20 * 256 // At most 20 intermediates
	if size < expectedMin || size > expectedMax {
		t.Errorf("proof size %d outside expected range [%d, %d]", size, expectedMin, expectedMax)
	}
}

func TestPietrzakVerificationOps(t *testing.T) {
	params := PietrzakParams{
		N:      defaultModulus,
		T:      1024,
		Lambda: 128,
	}

	vdf, err := NewPietrzakVDF(params)
	if err != nil {
		t.Fatalf("NewPietrzakVDF failed: %v", err)
	}

	x := big.NewInt(2)
	proof, err := vdf.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	ops := proof.VerificationOps()

	// Should be O(log T)
	// For T=1024, about 20 operations (2 per level, ~10 levels)
	if ops < 10 || ops > 30 {
		t.Errorf("verification ops %d outside expected range", ops)
	}
}

func TestPietrzakEncodeDecode(t *testing.T) {
	params := PietrzakParams{
		N:      defaultModulus,
		T:      64,
		Lambda: 128,
	}

	vdf, err := NewPietrzakVDF(params)
	if err != nil {
		t.Fatalf("NewPietrzakVDF failed: %v", err)
	}

	x := big.NewInt(12345)
	original, err := vdf.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// Encode
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Decode
	decoded, err := DecodePietrzakProof(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// Compare
	if decoded.Input.Cmp(original.Input) != 0 {
		t.Error("input mismatch after roundtrip")
	}
	if decoded.Output.Cmp(original.Output) != 0 {
		t.Error("output mismatch after roundtrip")
	}
	if decoded.T != original.T {
		t.Error("T mismatch after roundtrip")
	}
	if len(decoded.Intermediates) != len(original.Intermediates) {
		t.Errorf("intermediates count mismatch: %d vs %d",
			len(decoded.Intermediates), len(original.Intermediates))
	}
	for i := range decoded.Intermediates {
		if decoded.Intermediates[i].Cmp(original.Intermediates[i]) != 0 {
			t.Errorf("intermediate %d mismatch", i)
		}
	}
}

func TestPietrzakDecodeInvalid(t *testing.T) {
	// Too short
	_, err := DecodePietrzakProof([]byte("short"))
	if err == nil {
		t.Error("expected error for short data")
	}

	// Invalid length fields
	_, err = DecodePietrzakProof(make([]byte, 24))
	if err == nil {
		t.Error("expected error for invalid data")
	}
}

func TestPietrzakGenerateRandomInput(t *testing.T) {
	params := DefaultPietrzakParams()
	vdf, _ := NewPietrzakVDF(params)

	x1, err := vdf.GenerateRandomInput()
	if err != nil {
		t.Fatalf("GenerateRandomInput failed: %v", err)
	}

	x2, err := vdf.GenerateRandomInput()
	if err != nil {
		t.Fatalf("GenerateRandomInput failed: %v", err)
	}

	// Should be different
	if x1.Cmp(x2) == 0 {
		t.Error("random inputs should be different")
	}

	// Should be in valid range
	if x1.Cmp(big.NewInt(2)) < 0 || x1.Cmp(params.N) >= 0 {
		t.Error("x1 out of range")
	}
	if x2.Cmp(big.NewInt(2)) < 0 || x2.Cmp(params.N) >= 0 {
		t.Error("x2 out of range")
	}
}

func TestPietrzakInputFromBytes(t *testing.T) {
	params := DefaultPietrzakParams()
	vdf, _ := NewPietrzakVDF(params)

	data := []byte("test content")
	x1 := vdf.InputFromBytes(data)
	x2 := vdf.InputFromBytes(data)

	// Should be deterministic
	if x1.Cmp(x2) != 0 {
		t.Error("InputFromBytes should be deterministic")
	}

	// Different data should produce different input
	x3 := vdf.InputFromBytes([]byte("different"))
	if x1.Cmp(x3) == 0 {
		t.Error("different data should produce different input")
	}
}

func TestPietrzakMinElapsedTime(t *testing.T) {
	proof := &PietrzakProof{
		T: 1000000, // 1M squarings
	}

	// At 1M squarings/sec, should be 1 second
	duration := proof.MinElapsedTime(1000000)
	if duration != time.Second {
		t.Errorf("expected 1 second, got %v", duration)
	}

	// At 500K squarings/sec, should be 2 seconds
	duration = proof.MinElapsedTime(500000)
	if duration != 2*time.Second {
		t.Errorf("expected 2 seconds, got %v", duration)
	}

	// Default rate
	duration = proof.MinElapsedTime(0)
	if duration != time.Second {
		t.Errorf("expected 1 second with default rate, got %v", duration)
	}
}

func TestCalibrateSquaringsPerSecond(t *testing.T) {
	rate, err := CalibrateSquaringsPerSecond(100 * time.Millisecond)
	if err != nil {
		t.Fatalf("Calibrate failed: %v", err)
	}

	if rate == 0 {
		t.Error("rate should not be 0")
	}

	// On modern hardware, expect at least 100K squarings/sec
	if rate < 100000 {
		t.Logf("Warning: rate %d seems slow", rate)
	}
}

func TestCalibrateSquaringsPerSecondTooShort(t *testing.T) {
	_, err := CalibrateSquaringsPerSecond(time.Microsecond)
	if err == nil {
		t.Error("expected error for too short duration")
	}
}

func TestPietrzakEvaluateInvalidInput(t *testing.T) {
	params := PietrzakParams{
		N:      defaultModulus,
		T:      32,
		Lambda: 128,
	}

	vdf, _ := NewPietrzakVDF(params)

	// Zero input
	_, err := vdf.Evaluate(big.NewInt(0))
	if err == nil {
		t.Error("expected error for zero input")
	}

	// Negative input
	_, err = vdf.Evaluate(big.NewInt(-1))
	if err == nil {
		t.Error("expected error for negative input")
	}

	// Input >= N
	bigInput := new(big.Int).Add(params.N, big.NewInt(1))
	_, err = vdf.Evaluate(bigInput)
	if err == nil {
		t.Error("expected error for input >= N")
	}
}

func TestPietrzakComputeWithDuration(t *testing.T) {
	params := DefaultPietrzakParams()
	vdf, _ := NewPietrzakVDF(params)

	x := big.NewInt(2)

	// Use a very high squarings rate to make the test fast
	// (otherwise it would take the actual target duration)
	proof, err := vdf.ComputeWithDuration(x, 100*time.Millisecond, 10000000) // 10M/sec
	if err != nil {
		t.Fatalf("ComputeWithDuration failed: %v", err)
	}

	if proof == nil {
		t.Fatal("proof should not be nil")
	}

	// T should be approximately 100ms * 10M = 1M squarings
	expectedT := uint64(1000000)
	if proof.T < expectedT/2 || proof.T > expectedT*2 {
		t.Errorf("T=%d not close to expected %d", proof.T, expectedT)
	}
}

func TestPietrzakVerifyMinDuration(t *testing.T) {
	// Use T=128 for faster test (represents ~128μs at 1M squarings/sec)
	params := PietrzakParams{
		N:      defaultModulus,
		T:      128,
		Lambda: 128,
	}

	vdf, _ := NewPietrzakVDF(params)
	x := big.NewInt(2)
	proof, err := vdf.Evaluate(x)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// First verify the proof is valid
	if !vdf.Verify(proof) {
		t.Fatal("proof should verify")
	}

	// T=128 at 1M/sec = 128μs
	// Should pass with minimum 50μs
	err = vdf.VerifyMinDuration(proof, 50*time.Microsecond, 1000000)
	if err != nil {
		t.Errorf("should verify with 50μs min: %v", err)
	}

	// Should fail with minimum 1ms (proof only represents 128μs)
	err = vdf.VerifyMinDuration(proof, time.Millisecond, 1000000)
	if err == nil {
		t.Error("should fail with 1ms min")
	}
}

func TestBitLength(t *testing.T) {
	tests := []struct {
		n        uint64
		expected int
	}{
		{0, 0},
		{1, 1},
		{2, 2},
		{3, 2},
		{4, 3},
		{7, 3},
		{8, 4},
		{255, 8},
		{256, 9},
		{1024, 11},
	}

	for _, tc := range tests {
		result := bitLength(tc.n)
		if result != tc.expected {
			t.Errorf("bitLength(%d) = %d, expected %d", tc.n, result, tc.expected)
		}
	}
}

func TestPietrzakDeterministic(t *testing.T) {
	params := PietrzakParams{
		N:      defaultModulus,
		T:      64,
		Lambda: 128,
	}

	vdf, _ := NewPietrzakVDF(params)
	x := big.NewInt(42)

	proof1, _ := vdf.Evaluate(x)
	proof2, _ := vdf.Evaluate(x)

	// Output should be deterministic
	if proof1.Output.Cmp(proof2.Output) != 0 {
		t.Error("VDF output should be deterministic")
	}
}

func TestPietrzakInputFromContentHash(t *testing.T) {
	params := DefaultPietrzakParams()
	vdf, _ := NewPietrzakVDF(params)

	// Simulate binding VDF to document content
	documentContent := []byte("This is the document being witnessed.")
	contentHash := sha256.Sum256(documentContent)

	x := vdf.InputFromBytes(contentHash[:])

	// Should be deterministic
	x2 := vdf.InputFromBytes(contentHash[:])
	if x.Cmp(x2) != 0 {
		t.Error("input from content hash should be deterministic")
	}

	// Different content = different input
	otherContent := []byte("Different document.")
	otherHash := sha256.Sum256(otherContent)
	x3 := vdf.InputFromBytes(otherHash[:])

	if x.Cmp(x3) == 0 {
		t.Error("different content should produce different VDF input")
	}
}

// Benchmark tests

func BenchmarkPietrzakEvaluate64(b *testing.B) {
	params := PietrzakParams{
		N:      defaultModulus,
		T:      64,
		Lambda: 128,
	}
	vdf, _ := NewPietrzakVDF(params)
	x := big.NewInt(2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vdf.Evaluate(x)
	}
}

func BenchmarkPietrzakEvaluate1024(b *testing.B) {
	params := PietrzakParams{
		N:      defaultModulus,
		T:      1024,
		Lambda: 128,
	}
	vdf, _ := NewPietrzakVDF(params)
	x := big.NewInt(2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vdf.Evaluate(x)
	}
}

func BenchmarkPietrzakVerify64(b *testing.B) {
	params := PietrzakParams{
		N:      defaultModulus,
		T:      64,
		Lambda: 128,
	}
	vdf, _ := NewPietrzakVDF(params)
	x := big.NewInt(2)
	proof, _ := vdf.Evaluate(x)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vdf.Verify(proof)
	}
}

func BenchmarkPietrzakVerify1024(b *testing.B) {
	params := PietrzakParams{
		N:      defaultModulus,
		T:      1024,
		Lambda: 128,
	}
	vdf, _ := NewPietrzakVDF(params)
	x := big.NewInt(2)
	proof, _ := vdf.Evaluate(x)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vdf.Verify(proof)
	}
}

// Compare Pietrzak O(log T) verification to hash-based O(T) verification
func BenchmarkVerificationComparison(b *testing.B) {
	// Pietrzak VDF - O(log T) verification
	b.Run("Pietrzak-T1024", func(b *testing.B) {
		params := PietrzakParams{N: defaultModulus, T: 1024, Lambda: 128}
		vdf, _ := NewPietrzakVDF(params)
		x := big.NewInt(2)
		proof, _ := vdf.Evaluate(x)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			vdf.Verify(proof)
		}
	})

	// Hash-based VDF - O(T) verification
	b.Run("HashBased-T1024", func(b *testing.B) {
		input := sha256.Sum256([]byte("test"))
		proof := ComputeIterations(input, 1024)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			Verify(proof)
		}
	})
}
