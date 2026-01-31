// Package jitter verification functions for cryptographic chain validation.
package jitter

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// Verification errors
var (
	ErrEmptyChain          = errors.New("empty sample chain")
	ErrHashMismatch        = errors.New("sample hash mismatch")
	ErrChainLinkBroken     = errors.New("chain link broken")
	ErrTimestampNotMono    = errors.New("timestamp not monotonically increasing")
	ErrCountNotMono        = errors.New("keystroke count not monotonically increasing")
	ErrJitterMismatch      = errors.New("jitter value mismatch")
	ErrInvalidFirstSample  = errors.New("first sample has non-zero previous hash")
	ErrNilSeed             = errors.New("seed is nil or empty")
	ErrDuplicateTimestamp  = errors.New("duplicate timestamp detected")
)

// VerificationResult contains detailed results of chain verification.
type VerificationResult struct {
	Valid           bool     `json:"valid"`
	SamplesVerified int      `json:"samples_verified"`
	Errors          []string `json:"errors,omitempty"`
}

// VerifyChain verifies the entire jitter sample chain.
// It checks:
// - Hash integrity of each sample
// - Chain linkage (each sample's PreviousHash matches previous sample's Hash)
// - Monotonically increasing timestamps
// - Monotonically increasing keystroke counts
// - Jitter values can be recomputed from the seed
func VerifyChain(samples []Sample, seed []byte, params Parameters) error {
	if len(samples) == 0 {
		return ErrEmptyChain
	}

	if len(seed) == 0 {
		return ErrNilSeed
	}

	for i := range samples {
		var prevSample *Sample
		if i > 0 {
			prevSample = &samples[i-1]
		}

		if err := VerifySample(samples[i], prevSample, seed, params); err != nil {
			return fmt.Errorf("sample %d: %w", i, err)
		}
	}

	return nil
}

// VerifySample verifies a single sample in the chain.
// prevSample should be nil for the first sample in the chain.
func VerifySample(sample Sample, prevSample *Sample, seed []byte, params Parameters) error {
	if len(seed) == 0 {
		return ErrNilSeed
	}

	// 1. Verify the sample's hash integrity
	computedHash := sample.computeHash()
	if computedHash != sample.Hash {
		return ErrHashMismatch
	}

	// 2. Verify chain linkage
	if prevSample == nil {
		// First sample must have zero previous hash
		if sample.PreviousHash != ([32]byte{}) {
			return ErrInvalidFirstSample
		}
	} else {
		// Subsequent samples must link to previous
		if sample.PreviousHash != prevSample.Hash {
			return ErrChainLinkBroken
		}

		// 3. Verify timestamps are monotonically increasing (strictly)
		if !sample.Timestamp.After(prevSample.Timestamp) {
			if sample.Timestamp.Equal(prevSample.Timestamp) {
				return ErrDuplicateTimestamp
			}
			return ErrTimestampNotMono
		}

		// 4. Verify keystroke counts are monotonically increasing
		if sample.KeystrokeCount <= prevSample.KeystrokeCount {
			return ErrCountNotMono
		}
	}

	// 5. Verify the jitter value can be recomputed
	var prevJitter [32]byte
	if prevSample != nil {
		prevJitter = prevSample.Hash
	}

	expectedJitter := ComputeJitterValue(seed, sample.DocumentHash, sample.KeystrokeCount, sample.Timestamp, prevJitter, params)
	if expectedJitter != sample.JitterMicros {
		return ErrJitterMismatch
	}

	return nil
}

// VerifyChainDetailed performs verification and returns detailed results.
func VerifyChainDetailed(samples []Sample, seed []byte, params Parameters) VerificationResult {
	result := VerificationResult{
		Valid:  true,
		Errors: make([]string, 0),
	}

	if len(samples) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ErrEmptyChain.Error())
		return result
	}

	if len(seed) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ErrNilSeed.Error())
		return result
	}

	for i := range samples {
		var prevSample *Sample
		if i > 0 {
			prevSample = &samples[i-1]
		}

		if err := VerifySample(samples[i], prevSample, seed, params); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("sample %d: %s", i, err.Error()))
		} else {
			result.SamplesVerified++
		}
	}

	return result
}

// VerifyChainWithSeed is a convenience function that takes a 32-byte seed array.
func VerifyChainWithSeed(samples []Sample, seed [32]byte, params Parameters) error {
	return VerifyChain(samples, seed[:], params)
}

// ChainData represents a serialized chain with all metadata needed for verification.
type ChainData struct {
	Version    int       `json:"version"`
	Params     Parameters `json:"params"`
	Samples    []Sample   `json:"samples"`
	CreatedAt  time.Time  `json:"created_at"`
}

// EncodeChain serializes a sample chain for storage or export.
// Note: This does NOT include the seed - the seed must be stored/transmitted separately.
func EncodeChain(samples []Sample, params Parameters) ([]byte, error) {
	data := ChainData{
		Version:   1,
		Params:    params,
		Samples:   samples,
		CreatedAt: time.Now(),
	}

	return json.Marshal(data)
}

// DecodeChain deserializes a sample chain from storage.
func DecodeChain(data []byte) ([]Sample, Parameters, error) {
	var chainData ChainData
	if err := json.Unmarshal(data, &chainData); err != nil {
		return nil, Parameters{}, fmt.Errorf("failed to decode chain: %w", err)
	}

	if chainData.Version != 1 {
		return nil, Parameters{}, fmt.Errorf("unsupported chain version: %d", chainData.Version)
	}

	return chainData.Samples, chainData.Params, nil
}

// EncodeSampleBinary encodes a single sample in a compact binary format.
// Format: timestamp(8) + count(8) + docHash(32) + jitterMicros(4) + hash(32) + prevHash(32) = 116 bytes
func EncodeSampleBinary(sample Sample) []byte {
	buf := make([]byte, 116)
	offset := 0

	// Timestamp as UnixNano
	binary.BigEndian.PutUint64(buf[offset:], uint64(sample.Timestamp.UnixNano()))
	offset += 8

	// Keystroke count
	binary.BigEndian.PutUint64(buf[offset:], sample.KeystrokeCount)
	offset += 8

	// Document hash
	copy(buf[offset:], sample.DocumentHash[:])
	offset += 32

	// Jitter micros
	binary.BigEndian.PutUint32(buf[offset:], sample.JitterMicros)
	offset += 4

	// Hash
	copy(buf[offset:], sample.Hash[:])
	offset += 32

	// Previous hash
	copy(buf[offset:], sample.PreviousHash[:])

	return buf
}

// DecodeSampleBinary decodes a sample from compact binary format.
func DecodeSampleBinary(data []byte) (Sample, error) {
	if len(data) != 116 {
		return Sample{}, fmt.Errorf("invalid sample data length: expected 116, got %d", len(data))
	}

	var sample Sample
	offset := 0

	// Timestamp
	nanos := binary.BigEndian.Uint64(data[offset:])
	sample.Timestamp = time.Unix(0, int64(nanos))
	offset += 8

	// Keystroke count
	sample.KeystrokeCount = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Document hash
	copy(sample.DocumentHash[:], data[offset:offset+32])
	offset += 32

	// Jitter micros
	sample.JitterMicros = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// Hash
	copy(sample.Hash[:], data[offset:offset+32])
	offset += 32

	// Previous hash
	copy(sample.PreviousHash[:], data[offset:offset+32])

	return sample, nil
}

// EncodeChainBinary encodes a chain in compact binary format.
// Format: version(1) + params(13) + count(4) + samples(116 * n)
func EncodeChainBinary(samples []Sample, params Parameters) ([]byte, error) {
	// Calculate total size
	headerSize := 1 + 13 + 4 // version + params + sample count
	totalSize := headerSize + len(samples)*116

	buf := make([]byte, totalSize)
	offset := 0

	// Version
	buf[offset] = 1
	offset++

	// Parameters
	binary.BigEndian.PutUint32(buf[offset:], params.MinJitterMicros)
	offset += 4
	binary.BigEndian.PutUint32(buf[offset:], params.MaxJitterMicros)
	offset += 4
	binary.BigEndian.PutUint32(buf[offset:], uint32(params.SampleInterval))
	offset += 4
	if params.InjectEnabled {
		buf[offset] = 1
	}
	offset++

	// Sample count
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(samples)))
	offset += 4

	// Samples
	for _, sample := range samples {
		sampleBytes := EncodeSampleBinary(sample)
		copy(buf[offset:], sampleBytes)
		offset += 116
	}

	return buf, nil
}

// DecodeChainBinary decodes a chain from compact binary format.
func DecodeChainBinary(data []byte) ([]Sample, Parameters, error) {
	if len(data) < 18 { // minimum header size
		return nil, Parameters{}, errors.New("data too short for chain header")
	}

	offset := 0

	// Version
	version := data[offset]
	if version != 1 {
		return nil, Parameters{}, fmt.Errorf("unsupported chain version: %d", version)
	}
	offset++

	// Parameters
	var params Parameters
	params.MinJitterMicros = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	params.MaxJitterMicros = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	params.SampleInterval = uint64(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	params.InjectEnabled = data[offset] == 1
	offset++

	// Sample count
	sampleCount := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// Verify data length
	expectedLen := 18 + int(sampleCount)*116
	if len(data) != expectedLen {
		return nil, Parameters{}, fmt.Errorf("invalid data length: expected %d, got %d", expectedLen, len(data))
	}

	// Decode samples
	samples := make([]Sample, sampleCount)
	for i := range samples {
		sample, err := DecodeSampleBinary(data[offset : offset+116])
		if err != nil {
			return nil, Parameters{}, fmt.Errorf("failed to decode sample %d: %w", i, err)
		}
		samples[i] = sample
		offset += 116
	}

	return samples, params, nil
}

// CompareChains checks if two sample chains are identical.
func CompareChains(a, b []Sample) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if !CompareSamples(a[i], b[i]) {
			return false
		}
	}

	return true
}

// CompareSamples checks if two samples are identical.
func CompareSamples(a, b Sample) bool {
	if !a.Timestamp.Equal(b.Timestamp) {
		return false
	}
	if a.KeystrokeCount != b.KeystrokeCount {
		return false
	}
	if a.DocumentHash != b.DocumentHash {
		return false
	}
	if a.JitterMicros != b.JitterMicros {
		return false
	}
	if a.Hash != b.Hash {
		return false
	}
	if a.PreviousHash != b.PreviousHash {
		return false
	}
	return true
}

// FindChainDivergence finds the first index where two chains differ.
// Returns -1 if chains are identical.
func FindChainDivergence(a, b []Sample) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	for i := 0; i < minLen; i++ {
		if !CompareSamples(a[i], b[i]) {
			return i
		}
	}

	// If one chain is longer, that's where they diverge
	if len(a) != len(b) {
		return minLen
	}

	return -1
}

// ExtractChainHashes extracts just the hashes from a chain for quick comparison.
func ExtractChainHashes(samples []Sample) [][32]byte {
	hashes := make([][32]byte, len(samples))
	for i, s := range samples {
		hashes[i] = s.Hash
	}
	return hashes
}

// VerifyChainContinuity checks if newSamples is a valid continuation of existingSamples.
// This is useful for incremental verification during a session.
func VerifyChainContinuity(existingSamples, newSamples []Sample, seed []byte, params Parameters) error {
	if len(newSamples) == 0 {
		return nil // Nothing new to verify
	}

	if len(seed) == 0 {
		return ErrNilSeed
	}

	// If there are existing samples, the first new sample must chain from the last existing
	var lastExisting *Sample
	if len(existingSamples) > 0 {
		lastExisting = &existingSamples[len(existingSamples)-1]
		firstNew := newSamples[0]

		if firstNew.PreviousHash != lastExisting.Hash {
			return fmt.Errorf("new samples don't chain from existing: expected prevHash %x, got %x",
				lastExisting.Hash[:8], firstNew.PreviousHash[:8])
		}

		if !firstNew.Timestamp.After(lastExisting.Timestamp) {
			return ErrTimestampNotMono
		}

		if firstNew.KeystrokeCount <= lastExisting.KeystrokeCount {
			return ErrCountNotMono
		}
	}

	// Verify the new samples internally, using lastExisting as the "previous" for the first new sample
	for i := range newSamples {
		var prevSample *Sample
		if i > 0 {
			prevSample = &newSamples[i-1]
		} else {
			// For the first new sample, use the last existing sample as previous
			prevSample = lastExisting
		}

		if err := VerifySample(newSamples[i], prevSample, seed, params); err != nil {
			return fmt.Errorf("new sample %d: %w", i, err)
		}
	}

	return nil
}

// HashChainRoot computes a single hash representing the entire chain.
// This can be used for efficient chain comparison or anchoring.
func HashChainRoot(samples []Sample) [32]byte {
	if len(samples) == 0 {
		return [32]byte{}
	}

	// The root is simply the last sample's hash, which already incorporates all previous
	return samples[len(samples)-1].Hash
}

// ValidateSampleFormat checks if a sample has valid field values (non-crypto checks).
func ValidateSampleFormat(sample Sample) error {
	// Zero time is invalid
	if sample.Timestamp.IsZero() {
		return errors.New("timestamp is zero")
	}

	// Timestamp shouldn't be in the far future
	if sample.Timestamp.After(time.Now().Add(24 * time.Hour)) {
		return errors.New("timestamp is in the future")
	}

	// Zero hash is only valid for first sample's PreviousHash
	if sample.Hash == ([32]byte{}) {
		return errors.New("sample hash is zero")
	}

	return nil
}

// MarshalSampleForSigning creates the canonical byte representation of a sample for signing.
// This is useful when the jitter evidence needs to be signed by an external key.
func MarshalSampleForSigning(sample Sample) []byte {
	var buf bytes.Buffer

	// Version prefix
	buf.WriteString("witnessd-sample-v1\n")

	// Timestamp
	var timeBuf [8]byte
	binary.BigEndian.PutUint64(timeBuf[:], uint64(sample.Timestamp.UnixNano()))
	buf.Write(timeBuf[:])

	// Count
	var countBuf [8]byte
	binary.BigEndian.PutUint64(countBuf[:], sample.KeystrokeCount)
	buf.Write(countBuf[:])

	// Document hash
	buf.Write(sample.DocumentHash[:])

	// Jitter
	var jitterBuf [4]byte
	binary.BigEndian.PutUint32(jitterBuf[:], sample.JitterMicros)
	buf.Write(jitterBuf[:])

	// Previous hash
	buf.Write(sample.PreviousHash[:])

	// Sample hash
	buf.Write(sample.Hash[:])

	return buf.Bytes()
}

// =============================================================================
// Zone-Committed Verification (Statistical Model)
// =============================================================================

// ContentVerificationResult contains detailed results of zone-committed verification.
type ContentVerificationResult struct {
	Valid                 bool                    `json:"valid"`
	ChainValid            bool                    `json:"chain_valid"`
	ZonesCompatible       bool                    `json:"zones_compatible"`
	ProfilePlausible      bool                    `json:"profile_plausible"`
	ZoneDivergence        float64                 `json:"zone_divergence"`        // Category-level divergence
	TransitionDivergence  float64                 `json:"transition_divergence"`  // Full 64-bin histogram divergence
	ProfileScore          float64                 `json:"profile_score"`          // 0-1 similarity
	RecordedProfile       TypingProfile           `json:"recorded_profile"`       // From evidence
	ExpectedProfile       TypingProfile           `json:"expected_profile"`       // From document
	RecordedTransitions   ZoneTransitionHistogram `json:"recorded_transitions"`   // Full histogram
	ExpectedTransitions   ZoneTransitionHistogram `json:"expected_transitions"`   // Full histogram
	Errors                []string                `json:"errors,omitempty"`
	Warnings              []string                `json:"warnings,omitempty"`
}

// VerifyWithContent performs statistical verification of zone-committed jitter evidence.
//
// This implements Layer 4a (Keystroke Evidence) verification from the evidence packet.
// Internal verification steps:
//  1. Chain integrity: sample hashes link correctly
//  2. Zone compatibility: recorded zone distribution matches document content
//  3. Profile plausibility: typing patterns are human-like
//
// This does NOT require the secret. For cryptographic verification with secret,
// use VerifyWithSecret.
func VerifyWithContent(samples []JitterSample, content []byte) ContentVerificationResult {
	result := ContentVerificationResult{
		Valid:   true,
		Errors:  make([]string, 0),
	}

	if len(samples) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "no samples to verify")
		return result
	}

	// Step 1: Verify chain integrity
	if err := VerifyJitterChain(samples); err != nil {
		result.ChainValid = false
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("chain integrity: %s", err.Error()))
	} else {
		result.ChainValid = true
	}

	// Step 2: Extract and compare zone distributions
	expectedZones := AnalyzeDocumentZones(content)
	recordedZones := ExtractRecordedZones(samples)

	result.ExpectedProfile = expectedZones
	result.RecordedProfile = recordedZones

	// Compute category-level divergence (coarse)
	result.ZoneDivergence = ZoneKLDivergence(expectedZones, recordedZones)

	// Compute full transition histogram divergence (fine-grained)
	result.ExpectedTransitions = ExpectedTransitionHistogram(content)
	result.RecordedTransitions = ExtractTransitionHistogram(samples)
	result.TransitionDivergence = TransitionHistogramDivergence(result.ExpectedTransitions, result.RecordedTransitions)

	// Use transition divergence as primary check (more discriminating)
	// Jensen-Shannon divergence is bounded [0, safeLog(2) ≈ 0.693]
	// Threshold: 0.3 catches fabricated evidence while allowing natural variation
	if result.TransitionDivergence > 0.3 {
		result.ZonesCompatible = false
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("zone transition divergence %.4f exceeds threshold 0.3", result.TransitionDivergence))
	} else {
		result.ZonesCompatible = true
	}

	// Step 3: Profile plausibility
	result.ProfilePlausible = IsHumanPlausible(recordedZones)
	if !result.ProfilePlausible {
		result.Warnings = append(result.Warnings, "typing profile does not appear human-plausible")
	}

	// Compute profile similarity score
	result.ProfileScore = CompareProfiles(expectedZones, recordedZones)

	// Overall validity: chain must be valid, zones should be compatible
	result.Valid = result.ChainValid && result.ZonesCompatible

	return result
}

// VerifyWithSecret performs full cryptographic verification using the session secret.
// This can detect sophisticated attacks that pass statistical verification.
func VerifyWithSecret(samples []JitterSample, secret [32]byte) error {
	if len(samples) == 0 {
		return ErrEmptyChain
	}

	engine := &verificationEngine{
		secret:     secret,
		prevJitter: 0,
	}

	for i, sample := range samples {
		// Recompute expected jitter
		expectedJitter := engine.computeExpectedJitter(
			sample.DocHash,
			sample.ZoneTransition,
			sample.IntervalBucket,
			sample.Timestamp,
		)

		if sample.JitterMicros != expectedJitter {
			return fmt.Errorf("sample %d: jitter mismatch (expected %d, got %d)",
				i, expectedJitter, sample.JitterMicros)
		}

		// Verify sample hash
		expectedHash := computeJitterSampleHash(&sample)
		if sample.SampleHash != expectedHash {
			return fmt.Errorf("sample %d: hash mismatch", i)
		}

		engine.prevJitter = sample.JitterMicros
		engine.ordinal++
	}

	return nil
}

// computeJitterSampleHash computes the hash for a JitterSample (standalone function for verification)
func computeJitterSampleHash(s *JitterSample) [32]byte {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, s.Ordinal)
	binary.Write(h, binary.BigEndian, s.Timestamp.UnixNano())
	h.Write(s.DocHash[:])
	h.Write([]byte{s.ZoneTransition, s.IntervalBucket})
	binary.Write(h, binary.BigEndian, s.JitterMicros)

	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

// verificationEngine mirrors JitterEngine for cryptographic verification
type verificationEngine struct {
	secret     [32]byte
	ordinal    uint64
	prevJitter uint32
}

func (e *verificationEngine) computeExpectedJitter(docHash [32]byte, zoneTransition uint8, intervalBucket uint8, timestamp time.Time) uint32 {
	h := hmac.New(sha256.New, e.secret[:])

	binary.Write(h, binary.BigEndian, e.ordinal)
	h.Write(docHash[:])
	binary.Write(h, binary.BigEndian, timestamp.UnixNano())
	h.Write([]byte{zoneTransition})
	h.Write([]byte{intervalBucket})
	binary.Write(h, binary.BigEndian, e.prevJitter)

	hash := h.Sum(nil)
	raw := binary.BigEndian.Uint32(hash[:4])
	return MinJitter + (raw % JitterRange)
}

// AnalyzeDocumentZones extracts expected zone distribution from document content.
func AnalyzeDocumentZones(content []byte) TypingProfile {
	var profile TypingProfile
	transitions := TextToZoneSequence(string(content))

	for _, trans := range transitions {
		// Use middle bucket (5) as default since we don't have timing
		bucket := uint8(5)

		if trans.IsSameFinger() {
			profile.SameFingerHist[bucket]++
		} else if trans.IsSameHand() {
			profile.SameHandHist[bucket]++
		} else {
			profile.AlternatingHist[bucket]++
			profile.alternatingCount++
		}
		profile.TotalTransitions++
	}

	if profile.TotalTransitions > 0 {
		profile.HandAlternation = float32(profile.alternatingCount) / float32(profile.TotalTransitions)
	}

	return profile
}

// ExtractRecordedZones extracts zone distribution from recorded samples.
func ExtractRecordedZones(samples []JitterSample) TypingProfile {
	var profile TypingProfile

	for _, sample := range samples {
		if sample.ZoneTransition == 0xFF {
			continue // Skip invalid transitions
		}

		from, to := DecodeZoneTransition(sample.ZoneTransition)
		trans := ZoneTransition{From: from, To: to}
		bucket := sample.IntervalBucket
		if bucket >= 10 {
			bucket = 9
		}

		if trans.IsSameFinger() {
			profile.SameFingerHist[bucket]++
		} else if trans.IsSameHand() {
			profile.SameHandHist[bucket]++
		} else {
			profile.AlternatingHist[bucket]++
			profile.alternatingCount++
		}
		profile.TotalTransitions++
	}

	if profile.TotalTransitions > 0 {
		profile.HandAlternation = float32(profile.alternatingCount) / float32(profile.TotalTransitions)
	}

	return profile
}

// ZoneKLDivergence computes KL divergence between expected and recorded zone transitions.
// NOTE: This compares category distributions (same-finger/same-hand/alternating), NOT the
// full 64-bin zone-to-zone histogram. For fine-grained comparison, use TransitionHistogramDivergence.
// Lower values indicate better match.
func ZoneKLDivergence(expected, recorded TypingProfile) float64 {
	// Compute zone type distributions (ignoring timing buckets)
	var expSameFinger, expSameHand, expAlternating uint64
	var recSameFinger, recSameHand, recAlternating uint64

	for i := 0; i < 10; i++ {
		expSameFinger += uint64(expected.SameFingerHist[i])
		expSameHand += uint64(expected.SameHandHist[i])
		expAlternating += uint64(expected.AlternatingHist[i])
		recSameFinger += uint64(recorded.SameFingerHist[i])
		recSameHand += uint64(recorded.SameHandHist[i])
		recAlternating += uint64(recorded.AlternatingHist[i])
	}

	expTotal := float64(expSameFinger + expSameHand + expAlternating)
	recTotal := float64(recSameFinger + recSameHand + recAlternating)

	if expTotal == 0 || recTotal == 0 {
		// Can't compute divergence - return high value to indicate problem
		if expTotal == 0 && recTotal == 0 {
			return 0.0 // Both empty is OK
		}
		return 10.0 // One empty, one not - max divergence
	}

	// Normalize to probabilities with Laplace smoothing
	epsilon := 0.001
	pExp := [3]float64{
		(float64(expSameFinger) + epsilon) / (expTotal + 3*epsilon),
		(float64(expSameHand) + epsilon) / (expTotal + 3*epsilon),
		(float64(expAlternating) + epsilon) / (expTotal + 3*epsilon),
	}
	pRec := [3]float64{
		(float64(recSameFinger) + epsilon) / (recTotal + 3*epsilon),
		(float64(recSameHand) + epsilon) / (recTotal + 3*epsilon),
		(float64(recAlternating) + epsilon) / (recTotal + 3*epsilon),
	}

	// KL divergence: sum(p * log(p/q))
	var kl float64
	for i := 0; i < 3; i++ {
		if pRec[i] > 0 {
			kl += pRec[i] * safeLog(pRec[i]/pExp[i])
		}
	}

	return kl
}

// ZoneTransitionHistogram is a 64-element histogram of zone-to-zone transitions.
// Index = from*8 + to
type ZoneTransitionHistogram [64]uint32

// ExtractTransitionHistogram extracts the full zone transition histogram from samples.
func ExtractTransitionHistogram(samples []JitterSample) ZoneTransitionHistogram {
	var hist ZoneTransitionHistogram
	for _, s := range samples {
		if s.ZoneTransition != 0xFF {
			hist[s.ZoneTransition]++
		}
	}
	return hist
}

// ExpectedTransitionHistogram computes expected zone transitions from document content.
func ExpectedTransitionHistogram(content []byte) ZoneTransitionHistogram {
	var hist ZoneTransitionHistogram
	transitions := TextToZoneSequence(string(content))
	for _, t := range transitions {
		encoded := EncodeZoneTransition(t.From, t.To)
		if encoded != 0xFF {
			hist[encoded]++
		}
	}
	return hist
}

// TransitionHistogramDivergence computes divergence between two transition histograms.
// This is much more discriminating than category-only comparison.
func TransitionHistogramDivergence(expected, recorded ZoneTransitionHistogram) float64 {
	var expTotal, recTotal float64
	for i := 0; i < 64; i++ {
		expTotal += float64(expected[i])
		recTotal += float64(recorded[i])
	}

	if expTotal == 0 || recTotal == 0 {
		return 10.0 // Max divergence for empty histograms
	}

	// Compute Jensen-Shannon divergence (symmetric, bounded 0-1)
	epsilon := 0.001 / 64 // Laplace smoothing per bin

	var js float64
	for i := 0; i < 64; i++ {
		pExp := (float64(expected[i]) + epsilon) / (expTotal + epsilon*64)
		pRec := (float64(recorded[i]) + epsilon) / (recTotal + epsilon*64)
		pMid := (pExp + pRec) / 2

		if pExp > 0 {
			js += 0.5 * pExp * safeLog(pExp/pMid)
		}
		if pRec > 0 {
			js += 0.5 * pRec * safeLog(pRec/pMid)
		}
	}

	return js
}

// safeLog computes natural logarithm with protection against log(0).
func safeLog(x float64) float64 {
	if x <= 0 {
		return -1e10 // Avoid log(0)
	}
	return math.Log(x)
}

// VerifyJitterChain verifies a sequence of JitterSamples (structural checks only).
// This verifies chain integrity without the secret.
func VerifyJitterChain(samples []JitterSample) error {
	if len(samples) == 0 {
		return ErrEmptyChain
	}

	for i, sample := range samples {
		// Verify sample hash matches computed hash
		expectedHash := computeJitterSampleHash(&sample)
		if sample.SampleHash != expectedHash {
			return fmt.Errorf("sample %d: %w", i, ErrHashMismatch)
		}

		if i > 0 {
			// Verify timestamps are monotonic
			if !sample.Timestamp.After(samples[i-1].Timestamp) {
				return fmt.Errorf("sample %d: %w", i, ErrTimestampNotMono)
			}

			// Verify ordinals are monotonic
			if sample.Ordinal <= samples[i-1].Ordinal {
				return fmt.Errorf("sample %d: ordinal not increasing", i)
			}
		}
	}

	return nil
}

// QuickVerifyProfile performs a quick plausibility check on typing profile data.
// This is useful for early rejection of obviously fake evidence.
func QuickVerifyProfile(profile TypingProfile) []string {
	var issues []string

	// Check for obviously robotic patterns
	if !IsHumanPlausible(profile) {
		issues = append(issues, "profile fails human plausibility check")
	}

	// Check hand alternation is in normal range (30-70%)
	if profile.TotalTransitions > 50 {
		if profile.HandAlternation < 0.25 {
			issues = append(issues, "hand alternation too low (< 25%)")
		}
		if profile.HandAlternation > 0.75 {
			issues = append(issues, "hand alternation too high (> 75%)")
		}
	}

	// Check for impossible timing (all transitions instant)
	var bucket0Count uint64
	for i := 0; i < 10; i++ {
		if i == 0 {
			bucket0Count = uint64(profile.SameFingerHist[0]) + uint64(profile.SameHandHist[0]) + uint64(profile.AlternatingHist[0])
		}
	}
	if profile.TotalTransitions > 0 && bucket0Count == profile.TotalTransitions {
		issues = append(issues, "all transitions in fastest bucket (robotic timing)")
	}

	return issues
}
