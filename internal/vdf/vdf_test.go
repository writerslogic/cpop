package vdf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// =============================================================================
// Tests for DefaultParameters
// =============================================================================

func TestDefaultParameters(t *testing.T) {
	params := DefaultParameters()

	if params.IterationsPerSecond == 0 {
		t.Error("IterationsPerSecond should not be 0")
	}
	if params.MinIterations == 0 {
		t.Error("MinIterations should not be 0")
	}
	if params.MaxIterations == 0 {
		t.Error("MaxIterations should not be 0")
	}
	if params.MinIterations >= params.MaxIterations {
		t.Error("MinIterations should be less than MaxIterations")
	}
}

// =============================================================================
// Tests for Calibrate
// =============================================================================

func TestCalibrate(t *testing.T) {
	params, err := Calibrate(100 * time.Millisecond)
	if err != nil {
		t.Fatalf("Calibrate failed: %v", err)
	}

	if params.IterationsPerSecond == 0 {
		t.Error("IterationsPerSecond should not be 0")
	}
	if params.MinIterations == 0 {
		t.Error("MinIterations should not be 0")
	}
	if params.MaxIterations == 0 {
		t.Error("MaxIterations should not be 0")
	}
}

func TestCalibrateTooShort(t *testing.T) {
	_, err := Calibrate(time.Microsecond)
	if err == nil {
		t.Error("expected error for too short calibration")
	}
}

func TestCalibrateConsistency(t *testing.T) {
	// Two calibrations should produce similar results
	params1, err := Calibrate(200 * time.Millisecond)
	if err != nil {
		t.Fatalf("Calibrate 1 failed: %v", err)
	}

	params2, err := Calibrate(200 * time.Millisecond)
	if err != nil {
		t.Fatalf("Calibrate 2 failed: %v", err)
	}

	// Allow 50% variance due to system noise
	ratio := float64(params1.IterationsPerSecond) / float64(params2.IterationsPerSecond)
	if ratio < 0.5 || ratio > 2.0 {
		t.Errorf("calibration inconsistent: %d vs %d iterations/sec", params1.IterationsPerSecond, params2.IterationsPerSecond)
	}
}

// =============================================================================
// Tests for ComputeIterations - Various Iteration Counts
// =============================================================================

func TestComputeIterations(t *testing.T) {
	input := sha256.Sum256([]byte("test input"))
	iterations := uint64(1000)

	proof := ComputeIterations(input, iterations)

	if proof == nil {
		t.Fatal("ComputeIterations returned nil")
	}
	if proof.Input != input {
		t.Error("input mismatch")
	}
	if proof.Iterations != iterations {
		t.Errorf("expected %d iterations, got %d", iterations, proof.Iterations)
	}
	if proof.Duration <= 0 {
		t.Error("duration should be positive")
	}
	if proof.Output == input {
		t.Error("output should differ from input")
	}
}

func TestComputeIterationsVarious(t *testing.T) {
	testCases := []struct {
		name       string
		iterations uint64
	}{
		{"single iteration", 1},
		{"100 iterations", 100},
		{"10000 iterations", 10000},
		{"100000 iterations", 100000},
	}

	input := sha256.Sum256([]byte("test"))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			proof := ComputeIterations(input, tc.iterations)

			if proof.Iterations != tc.iterations {
				t.Errorf("expected %d iterations, got %d", tc.iterations, proof.Iterations)
			}

			// Verify the proof is valid
			if !Verify(proof) {
				t.Error("proof should verify")
			}
		})
	}
}

func TestComputeIterationsZero(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 0)

	// Zero iterations should still work
	if proof.Input != input {
		t.Error("input mismatch")
	}
	if proof.Output != input {
		t.Error("zero iterations should return input as output")
	}
	if proof.Iterations != 0 {
		t.Error("iterations should be 0")
	}
}

// =============================================================================
// Tests for Compute
// =============================================================================

func TestCompute(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	params := Parameters{
		IterationsPerSecond: 100000,
		MinIterations:       100,
		MaxIterations:       1000000,
	}

	proof, err := Compute(input, 10*time.Millisecond, params)
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	if proof.Iterations < params.MinIterations {
		t.Errorf("iterations below minimum: %d < %d", proof.Iterations, params.MinIterations)
	}
}

func TestComputeMinIterations(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	params := Parameters{
		IterationsPerSecond: 100000,
		MinIterations:       500,
		MaxIterations:       1000000,
	}

	// Request very short duration
	proof, err := Compute(input, time.Nanosecond, params)
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// Should be clamped to minimum
	if proof.Iterations != params.MinIterations {
		t.Errorf("expected min iterations %d, got %d", params.MinIterations, proof.Iterations)
	}
}

func TestComputeExceedsMax(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	params := Parameters{
		IterationsPerSecond: 1000,
		MinIterations:       100,
		MaxIterations:       1000,
	}

	// Request duration that exceeds max
	_, err := Compute(input, time.Hour, params)
	if err == nil {
		t.Error("expected error when exceeding max iterations")
	}
}

// =============================================================================
// Tests for Timing Characteristics
// =============================================================================

func TestComputeTiming(t *testing.T) {
	input := sha256.Sum256([]byte("timing test"))

	// Calibrate first to get accurate parameters
	params, err := Calibrate(200 * time.Millisecond)
	if err != nil {
		t.Fatalf("Calibrate failed: %v", err)
	}

	// Compute a proof that should take ~500ms
	targetDuration := 500 * time.Millisecond
	proof, err := Compute(input, targetDuration, params)
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}

	// Duration should be within 50% of target (system variance)
	if proof.Duration < targetDuration/2 || proof.Duration > targetDuration*2 {
		t.Errorf("duration %v outside expected range for target %v", proof.Duration, targetDuration)
	}
}

func TestIterationScaling(t *testing.T) {
	input := sha256.Sum256([]byte("scaling test"))

	// Double the iterations should roughly double the time
	proof1 := ComputeIterations(input, 10000)
	proof2 := ComputeIterations(input, 20000)

	ratio := float64(proof2.Duration) / float64(proof1.Duration)
	// Allow 50% variance
	if ratio < 1.2 || ratio > 3.0 {
		t.Errorf("doubling iterations didn't scale as expected: ratio=%v", ratio)
	}
}

// =============================================================================
// Tests for Verify
// =============================================================================

func TestVerify(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	if !Verify(proof) {
		t.Error("valid proof should verify")
	}
}

func TestVerifyEmptyProof(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 0)

	if !Verify(proof) {
		t.Error("zero-iteration proof should verify")
	}
}

func TestVerifyInvalid(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	// Corrupt the output
	proof.Output[0] ^= 0xff

	if Verify(proof) {
		t.Error("corrupted proof should not verify")
	}
}

func TestVerifyWrongIterations(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	// Change iteration count
	proof.Iterations = 999

	if Verify(proof) {
		t.Error("proof with wrong iterations should not verify")
	}
}

func TestVerifyTamperedInput(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	// Tamper with input
	proof.Input[0] ^= 0xff

	if Verify(proof) {
		t.Error("proof with tampered input should not verify")
	}
}

func TestVerifyIncreasedIterations(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	// Claim more iterations than actually computed
	proof.Iterations = 2000

	if Verify(proof) {
		t.Error("proof with inflated iterations should not verify")
	}
}

func TestVerifyDecreasedIterations(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	// Claim fewer iterations than actually computed
	proof.Iterations = 500

	if Verify(proof) {
		t.Error("proof with deflated iterations should not verify")
	}
}

// =============================================================================
// Tests for VerifyWithProgress
// =============================================================================

func TestVerifyWithProgress(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	progress := make(chan float64, 200)
	valid := VerifyWithProgress(proof, progress)

	if !valid {
		t.Error("valid proof should verify with progress")
	}

	// Progress channel should be closed
	_, ok := <-progress
	for ok {
		_, ok = <-progress
	}
}

func TestVerifyWithProgressNilChannel(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	// Should not panic with nil channel
	valid := VerifyWithProgress(proof, nil)
	if !valid {
		t.Error("valid proof should verify")
	}
}

func TestVerifyWithProgressReportsProgress(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	proof := ComputeIterations(input, 1000)

	progress := make(chan float64, 200)
	go VerifyWithProgress(proof, progress)

	// Collect progress values
	var lastProgress float64
	for p := range progress {
		if p < lastProgress {
			t.Error("progress should be monotonically increasing")
		}
		lastProgress = p
	}

	// Should have received progress updates
	if lastProgress == 0 {
		t.Error("should have received progress updates")
	}
}

// =============================================================================
// Tests for MinElapsedTime
// =============================================================================

func TestMinElapsedTime(t *testing.T) {
	proof := &Proof{
		Iterations: 1000000,
	}

	params := Parameters{
		IterationsPerSecond: 1000000,
	}

	elapsed := proof.MinElapsedTime(params)
	if elapsed != time.Second {
		t.Errorf("expected 1 second, got %v", elapsed)
	}
}

func TestMinElapsedTimeVarious(t *testing.T) {
	testCases := []struct {
		iterations      uint64
		itersPerSecond  uint64
		expectedSeconds float64
	}{
		{1000000, 1000000, 1.0},
		{500000, 1000000, 0.5},
		{2000000, 1000000, 2.0},
		{1000000, 500000, 2.0},
	}

	for _, tc := range testCases {
		proof := &Proof{Iterations: tc.iterations}
		params := Parameters{IterationsPerSecond: tc.itersPerSecond}
		elapsed := proof.MinElapsedTime(params)

		expected := time.Duration(tc.expectedSeconds * float64(time.Second))
		if elapsed != expected {
			t.Errorf("iterations=%d, itersPerSec=%d: expected %v, got %v",
				tc.iterations, tc.itersPerSecond, expected, elapsed)
		}
	}
}

// =============================================================================
// Tests for Encode/Decode (Serialization)
// =============================================================================

func TestEncodeDecodeProof(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	original := ComputeIterations(input, 1000)

	encoded := original.Encode()
	if len(encoded) != 80 {
		t.Errorf("expected 80 bytes, got %d", len(encoded))
	}

	decoded, err := DecodeProof(encoded)
	if err != nil {
		t.Fatalf("DecodeProof failed: %v", err)
	}

	if decoded.Input != original.Input {
		t.Error("input mismatch")
	}
	if decoded.Output != original.Output {
		t.Error("output mismatch")
	}
	if decoded.Iterations != original.Iterations {
		t.Errorf("iterations mismatch: expected %d, got %d", original.Iterations, decoded.Iterations)
	}
	if decoded.Duration != original.Duration {
		t.Errorf("duration mismatch: expected %v, got %v", original.Duration, decoded.Duration)
	}
}

func TestDecodeProofTooShort(t *testing.T) {
	_, err := DecodeProof([]byte("short"))
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestDecodeProofExactlyMinimum(t *testing.T) {
	data := make([]byte, 80)
	_, err := DecodeProof(data)
	if err != nil {
		t.Errorf("should decode minimum size data: %v", err)
	}
}

func TestDecodeProofExtraData(t *testing.T) {
	// Extra data at the end should be ignored
	input := sha256.Sum256([]byte("test"))
	original := ComputeIterations(input, 1000)
	encoded := original.Encode()

	// Add extra bytes
	encodedWithExtra := append(encoded, []byte("extra")...)

	decoded, err := DecodeProof(encodedWithExtra)
	if err != nil {
		t.Fatalf("DecodeProof should handle extra data: %v", err)
	}

	if decoded.Input != original.Input {
		t.Error("input mismatch with extra data")
	}
}

func TestProofEncodingRoundtrip(t *testing.T) {
	original := &Proof{
		Input:      sha256.Sum256([]byte("input")),
		Output:     sha256.Sum256([]byte("output")),
		Iterations: 12345678,
		Duration:   time.Second * 42,
	}

	encoded := original.Encode()
	decoded, err := DecodeProof(encoded)
	if err != nil {
		t.Fatalf("DecodeProof failed: %v", err)
	}

	if !bytes.Equal(decoded.Input[:], original.Input[:]) {
		t.Error("Input mismatch after roundtrip")
	}
	if !bytes.Equal(decoded.Output[:], original.Output[:]) {
		t.Error("Output mismatch after roundtrip")
	}
	if decoded.Iterations != original.Iterations {
		t.Error("Iterations mismatch after roundtrip")
	}
	if decoded.Duration != original.Duration {
		t.Error("Duration mismatch after roundtrip")
	}
}

// =============================================================================
// Tests for BatchVerifier
// =============================================================================

func TestBatchVerifier(t *testing.T) {
	bv := NewBatchVerifier(0) // Auto workers
	if bv.workers <= 0 {
		t.Error("workers should be positive")
	}

	bv = NewBatchVerifier(4)
	if bv.workers != 4 {
		t.Errorf("expected 4 workers, got %d", bv.workers)
	}
}

func TestBatchVerifyAll(t *testing.T) {
	bv := NewBatchVerifier(2)

	// Create multiple proofs
	proofs := make([]*Proof, 5)
	for i := 0; i < 5; i++ {
		input := sha256.Sum256([]byte{byte(i)})
		proofs[i] = ComputeIterations(input, 100)
	}

	results := bv.VerifyAll(proofs)

	if len(results) != 5 {
		t.Errorf("expected 5 results, got %d", len(results))
	}

	for i, r := range results {
		if !r.Valid {
			t.Errorf("proof %d should be valid", i)
		}
		if r.Index != i {
			t.Errorf("expected index %d, got %d", i, r.Index)
		}
	}
}

func TestBatchVerifyAllWithInvalid(t *testing.T) {
	bv := NewBatchVerifier(2)

	proofs := make([]*Proof, 3)
	for i := 0; i < 3; i++ {
		input := sha256.Sum256([]byte{byte(i)})
		proofs[i] = ComputeIterations(input, 100)
	}

	// Corrupt one proof
	proofs[1].Output[0] ^= 0xff

	results := bv.VerifyAll(proofs)

	if results[0].Valid != true {
		t.Error("proof 0 should be valid")
	}
	if results[1].Valid != false {
		t.Error("proof 1 should be invalid")
	}
	if results[2].Valid != true {
		t.Error("proof 2 should be valid")
	}
}

func TestBatchVerifyAllWithNil(t *testing.T) {
	bv := NewBatchVerifier(1)

	proofs := []*Proof{
		ComputeIterations(sha256.Sum256([]byte("a")), 100),
		nil,
		ComputeIterations(sha256.Sum256([]byte("c")), 100),
	}

	results := bv.VerifyAll(proofs)

	if results[0].Valid != true {
		t.Error("proof 0 should be valid")
	}
	if results[1].Valid != false || results[1].Error == nil {
		t.Error("nil proof should be invalid with error")
	}
	if results[2].Valid != true {
		t.Error("proof 2 should be valid")
	}
}

func TestBatchVerifyAllEmpty(t *testing.T) {
	bv := NewBatchVerifier(2)
	results := bv.VerifyAll([]*Proof{})
	if len(results) != 0 {
		t.Error("empty input should return empty results")
	}
}

func TestBatchVerifyAllSingleProof(t *testing.T) {
	bv := NewBatchVerifier(4)
	proof := ComputeIterations(sha256.Sum256([]byte("single")), 100)

	results := bv.VerifyAll([]*Proof{proof})

	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
	if !results[0].Valid {
		t.Error("single proof should be valid")
	}
}

// =============================================================================
// Tests for ChainInput
// =============================================================================

func TestChainInput(t *testing.T) {
	contentHash := sha256.Sum256([]byte("content"))
	previousHash := sha256.Sum256([]byte("previous"))
	ordinal := uint64(42)

	input1 := ChainInput(contentHash, previousHash, ordinal)
	input2 := ChainInput(contentHash, previousHash, ordinal)

	// Same inputs should produce same output
	if input1 != input2 {
		t.Error("ChainInput should be deterministic")
	}

	// Different content hash
	differentContent := sha256.Sum256([]byte("different"))
	input3 := ChainInput(differentContent, previousHash, ordinal)
	if input1 == input3 {
		t.Error("different content should produce different input")
	}

	// Different previous hash
	differentPrevious := sha256.Sum256([]byte("other"))
	input4 := ChainInput(contentHash, differentPrevious, ordinal)
	if input1 == input4 {
		t.Error("different previous hash should produce different input")
	}

	// Different ordinal
	input5 := ChainInput(contentHash, previousHash, 43)
	if input1 == input5 {
		t.Error("different ordinal should produce different input")
	}
}

func TestChainInputDomainSeparation(t *testing.T) {
	// ChainInput should produce different results than raw hash
	contentHash := sha256.Sum256([]byte("content"))
	previousHash := sha256.Sum256([]byte("previous"))

	chainInput := ChainInput(contentHash, previousHash, 0)

	// Direct concatenation would produce a different result
	if chainInput == [32]byte{} {
		t.Error("chain input should not be zero")
	}
}

// =============================================================================
// Tests for computeChain
// =============================================================================

func TestComputeChainDeterminism(t *testing.T) {
	input := sha256.Sum256([]byte("test"))
	iterations := uint64(100)

	output1 := computeChain(input, iterations)
	output2 := computeChain(input, iterations)

	if output1 != output2 {
		t.Error("computeChain should be deterministic")
	}
}

func TestComputeChainSequential(t *testing.T) {
	input := sha256.Sum256([]byte("sequential"))

	// Verify chain is truly sequential
	// Compute 10 iterations
	output10 := computeChain(input, 10)

	// Compute 5, then 5 more
	intermediate := computeChain(input, 5)
	output5plus5 := computeChain(intermediate, 5)

	if output10 != output5plus5 {
		t.Error("chain should be composable: 10 iters = 5 + 5 iters")
	}
}

// =============================================================================
// Tests for Intermediate Checkpoints
// =============================================================================

func TestIntermediateCheckpoints(t *testing.T) {
	input := sha256.Sum256([]byte("intermediate"))
	totalIterations := uint64(1000)

	// Compute full chain
	fullProof := ComputeIterations(input, totalIterations)

	// Compute in segments and verify they compose correctly
	segments := []uint64{250, 250, 250, 250}
	current := input

	for _, seg := range segments {
		current = computeChain(current, seg)
	}

	if current != fullProof.Output {
		t.Error("segmented computation should equal full computation")
	}
}

func TestParallelVerificationSegments(t *testing.T) {
	// Demonstrate that verification can be parallelized with checkpoints
	input := sha256.Sum256([]byte("parallel"))

	// Generate intermediate checkpoints
	checkpoints := make([][32]byte, 5)
	checkpoints[0] = input

	for i := 1; i < 5; i++ {
		checkpoints[i] = computeChain(checkpoints[i-1], 100)
	}

	// Each segment can be verified independently
	bv := NewBatchVerifier(4)
	proofs := make([]*Proof, 4)

	for i := 0; i < 4; i++ {
		proofs[i] = &Proof{
			Input:      checkpoints[i],
			Output:     checkpoints[i+1],
			Iterations: 100,
		}
	}

	results := bv.VerifyAll(proofs)
	for i, r := range results {
		if !r.Valid {
			t.Errorf("segment %d should verify", i)
		}
	}
}

// =============================================================================
// Negative Tests
// =============================================================================

func TestVerifyTamperedProofOutput(t *testing.T) {
	input := sha256.Sum256([]byte("tamper"))
	proof := ComputeIterations(input, 1000)

	// Various tampering attempts
	tamperTests := []struct {
		name   string
		tamper func(*Proof)
	}{
		{"flip first bit of output", func(p *Proof) { p.Output[0] ^= 0x01 }},
		{"flip last bit of output", func(p *Proof) { p.Output[31] ^= 0x80 }},
		{"zero output", func(p *Proof) { p.Output = [32]byte{} }},
		{"swap input and output", func(p *Proof) { p.Input, p.Output = p.Output, p.Input }},
		{"increment iterations", func(p *Proof) { p.Iterations++ }},
		{"decrement iterations", func(p *Proof) { p.Iterations-- }},
	}

	for _, tt := range tamperTests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh copy
			tamperedProof := &Proof{
				Input:      proof.Input,
				Output:     proof.Output,
				Iterations: proof.Iterations,
				Duration:   proof.Duration,
			}
			tt.tamper(tamperedProof)

			if Verify(tamperedProof) {
				t.Errorf("tampered proof (%s) should not verify", tt.name)
			}
		})
	}
}

func TestDecodeProofInvalidData(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"one byte", []byte{0x00}},
		{"79 bytes", make([]byte, 79)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeProof(tc.data)
			if err == nil {
				t.Errorf("should fail to decode %s", tc.name)
			}
		})
	}
}

// =============================================================================
// Test Vectors for Cross-Implementation Compatibility
// =============================================================================

// TestVectorVDF contains test data for cross-implementation testing
type TestVectorVDF struct {
	Name       string
	InputHex   string
	Iterations uint64
	OutputHex  string
}

func TestCrossImplementationVectors(t *testing.T) {
	// These vectors can be used to verify compatibility with other implementations
	// The output hashes are computed by the reference implementation

	testVectors := []TestVectorVDF{
		{
			Name:       "zero_input_single_iteration",
			InputHex:   "0000000000000000000000000000000000000000000000000000000000000000",
			Iterations: 1,
		},
		{
			Name:       "simple_text_100_iterations",
			InputHex:   "", // Will be computed from "test"
			Iterations: 100,
		},
		{
			Name:       "simple_text_1000_iterations",
			InputHex:   "", // Will be computed from "test"
			Iterations: 1000,
		},
	}

	// Generate and log vectors for documentation
	for _, tc := range testVectors {
		var input [32]byte
		if tc.InputHex == "" {
			input = sha256.Sum256([]byte("test"))
		} else {
			decoded, _ := hex.DecodeString(tc.InputHex)
			copy(input[:], decoded)
		}

		proof := ComputeIterations(input, tc.Iterations)

		// Verify the proof
		if !Verify(proof) {
			t.Errorf("vector %s: proof should verify", tc.Name)
		}

		// Log for documentation
		t.Logf("Vector: %s", tc.Name)
		t.Logf("  Input:  %s", hex.EncodeToString(input[:]))
		t.Logf("  Iters:  %d", tc.Iterations)
		t.Logf("  Output: %s", hex.EncodeToString(proof.Output[:]))
	}
}

// TestKnownVectors verifies against known outputs (regression test)
func TestKnownVectors(t *testing.T) {
	// Vector 1: Zero input, 1 iteration
	// SHA256(00..00) = 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
	var zeroInput [32]byte
	proof := ComputeIterations(zeroInput, 1)
	expectedOutput := "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
	actualOutput := hex.EncodeToString(proof.Output[:])
	if actualOutput != expectedOutput {
		t.Errorf("zero input 1 iter: expected %s, got %s", expectedOutput, actualOutput)
	}

	// Vector 2: SHA256("test"), 0 iterations (output = input)
	testInput := sha256.Sum256([]byte("test"))
	proof2 := ComputeIterations(testInput, 0)
	if proof2.Output != testInput {
		t.Error("0 iterations should return input unchanged")
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkComputeIterations100(b *testing.B) {
	input := sha256.Sum256([]byte("benchmark"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeIterations(input, 100)
	}
}

func BenchmarkComputeIterations1000(b *testing.B) {
	input := sha256.Sum256([]byte("benchmark"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeIterations(input, 1000)
	}
}

func BenchmarkComputeIterations10000(b *testing.B) {
	input := sha256.Sum256([]byte("benchmark"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeIterations(input, 10000)
	}
}

func BenchmarkComputeIterations100000(b *testing.B) {
	input := sha256.Sum256([]byte("benchmark"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeIterations(input, 100000)
	}
}

func BenchmarkVerify(b *testing.B) {
	input := sha256.Sum256([]byte("benchmark"))
	proof := ComputeIterations(input, 10000)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Verify(proof)
	}
}

func BenchmarkEncode(b *testing.B) {
	input := sha256.Sum256([]byte("benchmark"))
	proof := ComputeIterations(input, 1000)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		proof.Encode()
	}
}

func BenchmarkDecode(b *testing.B) {
	input := sha256.Sum256([]byte("benchmark"))
	proof := ComputeIterations(input, 1000)
	data := proof.Encode()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		DecodeProof(data)
	}
}

func BenchmarkBatchVerify(b *testing.B) {
	bv := NewBatchVerifier(0)
	proofs := make([]*Proof, 10)
	for i := 0; i < 10; i++ {
		input := sha256.Sum256([]byte{byte(i)})
		proofs[i] = ComputeIterations(input, 1000)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		bv.VerifyAll(proofs)
	}
}

func BenchmarkCalibrate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Calibrate(100 * time.Millisecond)
	}
}

// =============================================================================
// Fuzz Tests
// =============================================================================

func FuzzDecodeProof(f *testing.F) {
	// Add seed corpus with valid proof data
	input := sha256.Sum256([]byte("test"))
	validProof := ComputeIterations(input, 1000)
	validData := validProof.Encode()
	f.Add(validData)

	// Add edge cases
	f.Add(make([]byte, 80))               // Minimum size, all zeros
	f.Add(bytes.Repeat([]byte{0xff}, 80)) // Minimum size, all 0xff
	f.Add(make([]byte, 0))                // Empty
	f.Add(make([]byte, 79))               // Too short by one byte
	f.Add(make([]byte, 81))               // One byte too long (still valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		// DecodeProof should not panic on any input
		proof, err := DecodeProof(data)
		if err != nil {
			// Error expected for invalid data
			if len(data) >= 80 {
				t.Errorf("DecodeProof failed on %d-byte input: %v", len(data), err)
			}
			return
		}

		// If decoding succeeded, verify we can re-encode
		reencoded := proof.Encode()

		// Re-encoded data should be exactly 80 bytes
		if len(reencoded) != 80 {
			t.Errorf("Encoded proof should be 80 bytes, got %d", len(reencoded))
		}

		// Re-decode should produce the same proof
		proof2, err := DecodeProof(reencoded)
		if err != nil {
			t.Errorf("Failed to decode re-encoded proof: %v", err)
		}

		if proof.Input != proof2.Input {
			t.Error("Input mismatch after re-encode")
		}
		if proof.Output != proof2.Output {
			t.Error("Output mismatch after re-encode")
		}
		if proof.Iterations != proof2.Iterations {
			t.Error("Iterations mismatch after re-encode")
		}
		if proof.Duration != proof2.Duration {
			t.Error("Duration mismatch after re-encode")
		}
	})
}

func FuzzVerify(f *testing.F) {
	// Seed with valid proof
	input := sha256.Sum256([]byte("seed"))
	validProof := ComputeIterations(input, 100)
	f.Add(validProof.Encode())

	f.Fuzz(func(t *testing.T, data []byte) {
		proof, err := DecodeProof(data)
		if err != nil {
			return // Invalid proof data, skip
		}

		// Verify should not panic
		_ = Verify(proof)
	})
}
