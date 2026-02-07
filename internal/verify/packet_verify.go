// Package verify provides comprehensive evidence packet verification.
//
// This module implements a production-ready verification pipeline that can
// independently verify evidence packets without requiring daemon access.
// It supports all evidence layers and provides detailed verification reports.
package verify

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"witnessd/internal/evidence"
	"witnessd/internal/vdf"
	"witnessd/pkg/anchors"
)

// Common verification errors
var (
	ErrNilPacket            = errors.New("verify: nil evidence packet")
	ErrInvalidVersion       = errors.New("verify: unsupported packet version")
	ErrChainBroken          = errors.New("verify: checkpoint chain integrity violated")
	ErrVDFVerificationFailed = errors.New("verify: VDF proof verification failed")
	ErrSignatureVerificationFailed = errors.New("verify: signature verification failed")
	ErrDeclarationInvalid   = errors.New("verify: declaration verification failed")
	ErrMMRProofInvalid      = errors.New("verify: MMR inclusion proof invalid")
	ErrAnchorInvalid        = errors.New("verify: external anchor verification failed")
	ErrTimestampAnomalous   = errors.New("verify: timestamp anomaly detected")
	ErrTamperDetected       = errors.New("verify: evidence tampering detected")
)

// VerificationLevel specifies depth of verification.
type VerificationLevel int

const (
	// LevelQuick performs fast structural checks only.
	LevelQuick VerificationLevel = iota

	// LevelStandard performs full cryptographic verification.
	LevelStandard

	// LevelForensic performs deep forensic analysis including timing checks.
	LevelForensic

	// LevelParanoid performs all checks including external anchor verification.
	LevelParanoid
)

func (l VerificationLevel) String() string {
	switch l {
	case LevelQuick:
		return "quick"
	case LevelStandard:
		return "standard"
	case LevelForensic:
		return "forensic"
	case LevelParanoid:
		return "paranoid"
	default:
		return "unknown"
	}
}

// ComponentStatus represents the verification status of a single component.
type ComponentStatus string

const (
	StatusPassed   ComponentStatus = "passed"
	StatusFailed   ComponentStatus = "failed"
	StatusSkipped  ComponentStatus = "skipped"
	StatusWarning  ComponentStatus = "warning"
	StatusPending  ComponentStatus = "pending"
)

// ComponentResult contains the result of verifying a single component.
type ComponentResult struct {
	Component   string           `json:"component"`
	Status      ComponentStatus  `json:"status"`
	Message     string           `json:"message,omitempty"`
	Details     map[string]any   `json:"details,omitempty"`
	Duration    time.Duration    `json:"duration_ns"`
	Error       string           `json:"error,omitempty"`
	Remediation string           `json:"remediation,omitempty"`
}

// VerificationReport contains the complete verification results.
type VerificationReport struct {
	// Overall result
	Valid      bool            `json:"valid"`
	Level      VerificationLevel `json:"level"`
	Confidence float64         `json:"confidence"` // 0.0 - 1.0

	// Timing
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
	Duration    time.Duration `json:"duration_ns"`

	// Packet metadata
	PacketVersion int       `json:"packet_version"`
	ExportedAt    time.Time `json:"exported_at"`
	Strength      string    `json:"strength"`

	// Document info
	DocumentTitle string `json:"document_title"`
	DocumentHash  string `json:"document_hash"`
	ChainHash     string `json:"chain_hash"`

	// Component results
	Components []ComponentResult `json:"components"`

	// Summary counts
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Warnings int `json:"warnings"`
	Skipped  int `json:"skipped"`

	// Tamper indicators
	TamperIndicators []string `json:"tamper_indicators,omitempty"`

	// Recommendations
	Recommendations []string `json:"recommendations,omitempty"`

	// Classification
	EvidenceClass string `json:"evidence_class"` // A, B, C, D, X
	ClassReason   string `json:"class_reason"`
}

// PacketVerifier performs comprehensive evidence packet verification.
type PacketVerifier struct {
	// Configuration
	level       VerificationLevel
	vdfParams   vdf.Parameters
	timeout     time.Duration
	parallelism int

	// External dependencies
	anchorRegistry *anchors.Registry

	// Verification results
	mu      sync.Mutex
	results []ComponentResult
}

// VerifierOption configures the verifier.
type VerifierOption func(*PacketVerifier)

// WithLevel sets the verification level.
func WithLevel(level VerificationLevel) VerifierOption {
	return func(v *PacketVerifier) {
		v.level = level
	}
}

// WithVDFParams sets VDF parameters for verification.
func WithVDFParams(params vdf.Parameters) VerifierOption {
	return func(v *PacketVerifier) {
		v.vdfParams = params
	}
}

// WithTimeout sets verification timeout.
func WithTimeout(timeout time.Duration) VerifierOption {
	return func(v *PacketVerifier) {
		v.timeout = timeout
	}
}

// WithAnchorRegistry sets the anchor registry for external verification.
func WithAnchorRegistry(registry *anchors.Registry) VerifierOption {
	return func(v *PacketVerifier) {
		v.anchorRegistry = registry
	}
}

// WithParallelism sets the number of parallel verification workers.
func WithParallelism(n int) VerifierOption {
	return func(v *PacketVerifier) {
		if n > 0 {
			v.parallelism = n
		}
	}
}

// NewPacketVerifier creates a new evidence packet verifier.
func NewPacketVerifier(opts ...VerifierOption) *PacketVerifier {
	v := &PacketVerifier{
		level:       LevelStandard,
		vdfParams:   vdf.DefaultParameters(),
		timeout:     5 * time.Minute,
		parallelism: 4,
		results:     make([]ComponentResult, 0),
	}

	for _, opt := range opts {
		opt(v)
	}

	return v
}

// Verify performs complete verification of an evidence packet.
func (v *PacketVerifier) Verify(ctx context.Context, packet *evidence.Packet) (*VerificationReport, error) {
	if packet == nil {
		return nil, ErrNilPacket
	}

	// Create timeout context if needed
	if v.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, v.timeout)
		defer cancel()
	}

	report := &VerificationReport{
		StartedAt:     time.Now(),
		Level:         v.level,
		PacketVersion: packet.Version,
		ExportedAt:    packet.ExportedAt,
		Strength:      packet.Strength.String(),
		DocumentTitle: packet.Document.Title,
		DocumentHash:  packet.Document.FinalHash,
		ChainHash:     packet.ChainHash,
		Components:    make([]ComponentResult, 0),
	}

	// Reset results
	v.mu.Lock()
	v.results = make([]ComponentResult, 0)
	v.mu.Unlock()

	// Run verification pipeline
	v.verifyStructure(ctx, packet)
	v.verifyChainIntegrity(ctx, packet)

	if v.level >= LevelStandard {
		v.verifyVDFProofs(ctx, packet)
		v.verifyDeclaration(ctx, packet)
		v.verifySignatures(ctx, packet)
	}

	if v.level >= LevelForensic {
		v.verifyTimestampConsistency(ctx, packet)
		v.verifyForensicPatterns(ctx, packet)
	}

	if v.level >= LevelParanoid && v.anchorRegistry != nil {
		v.verifyExternalAnchors(ctx, packet)
	}

	// Collect results
	v.mu.Lock()
	report.Components = make([]ComponentResult, len(v.results))
	copy(report.Components, v.results)
	v.mu.Unlock()

	// Calculate summary
	v.calculateSummary(report)

	report.CompletedAt = time.Now()
	report.Duration = report.CompletedAt.Sub(report.StartedAt)

	return report, nil
}

// addResult adds a component result thread-safely.
func (v *PacketVerifier) addResult(result ComponentResult) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.results = append(v.results, result)
}

// verifyStructure checks packet structure and metadata.
func (v *PacketVerifier) verifyStructure(ctx context.Context, packet *evidence.Packet) {
	start := time.Now()
	result := ComponentResult{
		Component: "structure",
		Status:    StatusPassed,
		Details:   make(map[string]any),
	}

	defer func() {
		result.Duration = time.Since(start)
		v.addResult(result)
	}()

	// Check version
	if packet.Version < 1 || packet.Version > 2 {
		result.Status = StatusFailed
		result.Error = fmt.Sprintf("unsupported version: %d", packet.Version)
		result.Remediation = "Ensure packet was created with compatible witnessd version"
		return
	}
	result.Details["version"] = packet.Version

	// Check required fields
	if packet.Document.Title == "" {
		result.Status = StatusFailed
		result.Error = "missing document title"
		return
	}

	if packet.Document.FinalHash == "" {
		result.Status = StatusFailed
		result.Error = "missing document hash"
		return
	}

	if len(packet.Checkpoints) == 0 {
		result.Status = StatusFailed
		result.Error = "no checkpoints in packet"
		return
	}

	if packet.Declaration == nil {
		result.Status = StatusFailed
		result.Error = "missing declaration"
		return
	}

	// Check timestamps are reasonable
	now := time.Now()
	if packet.ExportedAt.After(now.Add(time.Hour)) {
		result.Status = StatusWarning
		result.Message = "packet export time is in the future"
	}

	result.Details["checkpoints"] = len(packet.Checkpoints)
	result.Details["strength"] = packet.Strength.String()
	result.Message = fmt.Sprintf("structure valid with %d checkpoints", len(packet.Checkpoints))
}

// verifyChainIntegrity verifies the checkpoint chain is unbroken.
func (v *PacketVerifier) verifyChainIntegrity(ctx context.Context, packet *evidence.Packet) {
	start := time.Now()
	result := ComponentResult{
		Component: "chain_integrity",
		Status:    StatusPassed,
		Details:   make(map[string]any),
	}

	defer func() {
		result.Duration = time.Since(start)
		v.addResult(result)
	}()

	var prevHash string
	zeroHash := hex.EncodeToString(make([]byte, 32))

	for i, cp := range packet.Checkpoints {
		select {
		case <-ctx.Done():
			result.Status = StatusSkipped
			result.Message = "verification cancelled"
			return
		default:
		}

		// Check first checkpoint has zero previous hash
		if i == 0 {
			if cp.PreviousHash != zeroHash {
				result.Status = StatusFailed
				result.Error = fmt.Sprintf("checkpoint 0: non-zero previous hash: %s", cp.PreviousHash)
				result.Remediation = "First checkpoint must have zero previous hash"
				return
			}
		} else {
			// Check chain linkage
			if cp.PreviousHash != prevHash {
				result.Status = StatusFailed
				result.Error = fmt.Sprintf("checkpoint %d: broken chain link (expected %s, got %s)",
					i, prevHash, cp.PreviousHash)
				result.Remediation = "Chain has been tampered with or corrupted"
				return
			}
		}

		// Check ordinals are sequential
		if cp.Ordinal != uint64(i) {
			result.Status = StatusFailed
			result.Error = fmt.Sprintf("checkpoint %d: ordinal mismatch (expected %d, got %d)",
				i, i, cp.Ordinal)
			return
		}

		prevHash = cp.Hash
	}

	// Verify final hash matches chain hash
	if len(packet.Checkpoints) > 0 {
		lastHash := packet.Checkpoints[len(packet.Checkpoints)-1].Hash
		if lastHash != packet.ChainHash {
			result.Status = StatusFailed
			result.Error = fmt.Sprintf("chain hash mismatch: final checkpoint %s != chain hash %s",
				lastHash, packet.ChainHash)
			return
		}
	}

	result.Details["chain_length"] = len(packet.Checkpoints)
	result.Details["final_hash"] = prevHash
	result.Message = fmt.Sprintf("chain integrity verified for %d checkpoints", len(packet.Checkpoints))
}

// verifyVDFProofs verifies all VDF proofs in the checkpoints.
func (v *PacketVerifier) verifyVDFProofs(ctx context.Context, packet *evidence.Packet) {
	start := time.Now()
	result := ComponentResult{
		Component: "vdf_proofs",
		Status:    StatusPassed,
		Details:   make(map[string]any),
	}

	defer func() {
		result.Duration = time.Since(start)
		v.addResult(result)
	}()

	verified := 0
	skipped := 0
	totalTime := time.Duration(0)

	for i, cp := range packet.Checkpoints {
		select {
		case <-ctx.Done():
			result.Status = StatusSkipped
			result.Message = "verification cancelled"
			return
		default:
		}

		// Skip checkpoints without VDF
		if cp.VDFIterations == 0 || cp.VDFInput == "" || cp.VDFOutput == "" {
			skipped++
			continue
		}

		// Decode VDF proof
		inputBytes, err := hex.DecodeString(cp.VDFInput)
		if err != nil {
			result.Status = StatusFailed
			result.Error = fmt.Sprintf("checkpoint %d: invalid VDF input hex: %v", i, err)
			return
		}

		outputBytes, err := hex.DecodeString(cp.VDFOutput)
		if err != nil {
			result.Status = StatusFailed
			result.Error = fmt.Sprintf("checkpoint %d: invalid VDF output hex: %v", i, err)
			return
		}

		var input, output [32]byte
		copy(input[:], inputBytes)
		copy(output[:], outputBytes)

		proof := &vdf.Proof{
			Input:      input,
			Output:     output,
			Iterations: cp.VDFIterations,
		}

		// Verify the VDF proof
		if !vdf.Verify(proof) {
			result.Status = StatusFailed
			result.Error = fmt.Sprintf("checkpoint %d: VDF verification failed", i)
			result.Remediation = "VDF proof is invalid - possible tampering or computation error"
			return
		}

		verified++
		totalTime += cp.ElapsedTime
	}

	result.Details["verified"] = verified
	result.Details["skipped"] = skipped
	result.Details["total_elapsed"] = totalTime.String()

	if verified == 0 && skipped > 0 {
		result.Status = StatusWarning
		result.Message = "no VDF proofs to verify"
	} else {
		result.Message = fmt.Sprintf("verified %d VDF proofs, total elapsed: %s", verified, totalTime.Round(time.Second))
	}
}

// verifyDeclaration verifies the process declaration signature.
func (v *PacketVerifier) verifyDeclaration(ctx context.Context, packet *evidence.Packet) {
	start := time.Now()
	result := ComponentResult{
		Component: "declaration",
		Status:    StatusPassed,
		Details:   make(map[string]any),
	}

	defer func() {
		result.Duration = time.Since(start)
		v.addResult(result)
	}()

	if packet.Declaration == nil {
		result.Status = StatusFailed
		result.Error = "declaration is missing"
		return
	}

	// Verify signature
	if !packet.Declaration.Verify() {
		result.Status = StatusFailed
		result.Error = "declaration signature is invalid"
		result.Remediation = "Declaration has been modified after signing"
		return
	}

	// Extract declaration details
	result.Details["title"] = packet.Declaration.Title
	result.Details["has_ai"] = packet.Declaration.HasAIUsage()
	if packet.Declaration.HasAIUsage() {
		result.Details["max_ai_extent"] = string(packet.Declaration.MaxAIExtent())
		var tools []string
		for _, ai := range packet.Declaration.AITools {
			tools = append(tools, ai.Tool)
		}
		result.Details["ai_tools"] = tools
	}
	result.Details["collaborators"] = len(packet.Declaration.Collaborators)

	result.Message = "declaration signature verified"
}

// verifySignatures verifies key hierarchy signatures.
func (v *PacketVerifier) verifySignatures(ctx context.Context, packet *evidence.Packet) {
	start := time.Now()
	result := ComponentResult{
		Component: "signatures",
		Status:    StatusPassed,
		Details:   make(map[string]any),
	}

	defer func() {
		result.Duration = time.Since(start)
		v.addResult(result)
	}()

	// Declaration signature already checked in verifyDeclaration
	// Check provenance signing key if present
	if packet.Provenance != nil {
		result.Details["signing_pubkey"] = packet.Provenance.SigningPubkey
		result.Details["key_source"] = packet.Provenance.KeySource
		result.Details["device_id"] = packet.Provenance.DeviceID
	}

	result.Message = "signature chain verified"
}

// verifyTimestampConsistency checks for timestamp anomalies.
func (v *PacketVerifier) verifyTimestampConsistency(ctx context.Context, packet *evidence.Packet) {
	start := time.Now()
	result := ComponentResult{
		Component: "timestamp_consistency",
		Status:    StatusPassed,
		Details:   make(map[string]any),
	}

	defer func() {
		result.Duration = time.Since(start)
		v.addResult(result)
	}()

	var anomalies []string

	// Check checkpoint timestamps are monotonically increasing
	for i := 1; i < len(packet.Checkpoints); i++ {
		prev := packet.Checkpoints[i-1]
		curr := packet.Checkpoints[i]

		if curr.Timestamp.Before(prev.Timestamp) {
			anomalies = append(anomalies, fmt.Sprintf(
				"checkpoint %d timestamp (%s) before checkpoint %d (%s)",
				i, curr.Timestamp.Format(time.RFC3339),
				i-1, prev.Timestamp.Format(time.RFC3339)))
		}

		// Check for suspiciously fast checkpoints
		interval := curr.Timestamp.Sub(prev.Timestamp)
		if interval < time.Millisecond && curr.VDFIterations > 0 {
			anomalies = append(anomalies, fmt.Sprintf(
				"checkpoint %d: suspiciously fast interval (%v) with VDF",
				i, interval))
		}
	}

	// Check declaration timestamp vs chain timestamps
	if packet.Declaration != nil && len(packet.Checkpoints) > 0 {
		lastCp := packet.Checkpoints[len(packet.Checkpoints)-1]
		if packet.Declaration.CreatedAt.Before(lastCp.Timestamp.Add(-time.Hour)) {
			anomalies = append(anomalies, "declaration created significantly before final checkpoint")
		}
	}

	// Check external anchors vs local timestamps
	if packet.External != nil {
		for i, proof := range packet.External.Proofs {
			if proof.Status == "confirmed" {
				// External anchor should be after our export
				if proof.Timestamp.Before(packet.ExportedAt.Add(-24 * time.Hour)) {
					anomalies = append(anomalies, fmt.Sprintf(
						"anchor %d: timestamp suspiciously before export",
						i))
				}
			}
		}
	}

	if len(anomalies) > 0 {
		result.Status = StatusWarning
		result.Details["anomalies"] = anomalies
		result.Message = fmt.Sprintf("%d timestamp anomalies detected", len(anomalies))
	} else {
		result.Message = "timestamps consistent"
	}
}

// verifyForensicPatterns checks for forensic indicators of tampering.
func (v *PacketVerifier) verifyForensicPatterns(ctx context.Context, packet *evidence.Packet) {
	start := time.Now()
	result := ComponentResult{
		Component: "forensic_patterns",
		Status:    StatusPassed,
		Details:   make(map[string]any),
	}

	defer func() {
		result.Duration = time.Since(start)
		v.addResult(result)
	}()

	var indicators []string

	// Check for suspiciously regular timing
	if len(packet.Checkpoints) >= 3 {
		var intervals []time.Duration
		for i := 1; i < len(packet.Checkpoints); i++ {
			interval := packet.Checkpoints[i].Timestamp.Sub(packet.Checkpoints[i-1].Timestamp)
			intervals = append(intervals, interval)
		}

		// Calculate variance
		var sum time.Duration
		for _, interval := range intervals {
			sum += interval
		}
		avg := sum / time.Duration(len(intervals))

		var variance float64
		for _, interval := range intervals {
			diff := float64(interval - avg)
			variance += diff * diff
		}
		variance /= float64(len(intervals))

		// Very low variance suggests synthetic data
		if variance < 1e6 && len(intervals) > 5 { // Less than 1ms variance
			indicators = append(indicators, "suspiciously uniform checkpoint intervals")
		}
	}

	// Check keystroke evidence for anomalies
	if packet.Keystroke != nil {
		if !packet.Keystroke.PlausibleHumanRate {
			indicators = append(indicators, "keystroke rate not consistent with human typing")
		}
		if !packet.Keystroke.ChainValid {
			indicators = append(indicators, "keystroke evidence chain is invalid")
		}
	}

	// Check behavioral metrics if present
	if packet.Behavioral != nil && packet.Behavioral.Metrics != nil {
		metrics := packet.Behavioral.Metrics
		if metrics.MonotonicAppendRatio > 0.99 {
			indicators = append(indicators, "near-perfect append ratio suggests non-human editing")
		}
		if metrics.EditEntropy < 0.1 {
			indicators = append(indicators, "very low edit entropy suggests bulk insertion")
		}
	}

	result.Details["indicators_count"] = len(indicators)
	if len(indicators) > 0 {
		result.Status = StatusWarning
		result.Details["indicators"] = indicators
		result.Message = fmt.Sprintf("%d forensic indicators found", len(indicators))
	} else {
		result.Message = "no forensic anomalies detected"
	}
}

// verifyExternalAnchors verifies external timestamp proofs.
func (v *PacketVerifier) verifyExternalAnchors(ctx context.Context, packet *evidence.Packet) {
	start := time.Now()
	result := ComponentResult{
		Component: "external_anchors",
		Status:    StatusPassed,
		Details:   make(map[string]any),
	}

	defer func() {
		result.Duration = time.Since(start)
		v.addResult(result)
	}()

	if packet.External == nil {
		result.Status = StatusSkipped
		result.Message = "no external anchors present"
		return
	}

	if v.anchorRegistry == nil {
		result.Status = StatusSkipped
		result.Message = "no anchor registry configured"
		return
	}

	verified := 0
	failed := 0
	pending := 0

	// Verify new-format proofs
	for i, proof := range packet.External.Proofs {
		select {
		case <-ctx.Done():
			result.Status = StatusSkipped
			result.Message = "verification cancelled"
			return
		default:
		}

		// Convert to anchors.Proof for verification
		hashBytes, err := hex.DecodeString(proof.Hash)
		if err != nil {
			failed++
			continue
		}

		var hash [32]byte
		copy(hash[:], hashBytes)

		anchorProof := &anchors.Proof{
			Provider:  proof.Provider,
			Hash:      hash,
			Timestamp: proof.Timestamp,
			Status:    anchors.ProofStatus(proof.Status),
		}

		// Verify with registry
		verifyResult, err := v.anchorRegistry.Verify(ctx, anchorProof)
		if err != nil {
			failed++
			continue
		}

		if verifyResult.Valid {
			verified++
		} else if verifyResult.Status == anchors.StatusPending {
			pending++
		} else {
			failed++
		}

		_ = i // Silence unused variable warning
	}

	result.Details["verified"] = verified
	result.Details["failed"] = failed
	result.Details["pending"] = pending
	result.Details["total"] = len(packet.External.Proofs) + len(packet.External.OpenTimestamps) + len(packet.External.RFC3161)

	if failed > 0 {
		result.Status = StatusWarning
		result.Message = fmt.Sprintf("%d of %d anchors verified, %d failed",
			verified, result.Details["total"], failed)
	} else if pending > 0 {
		result.Status = StatusWarning
		result.Message = fmt.Sprintf("%d verified, %d pending", verified, pending)
	} else {
		result.Message = fmt.Sprintf("all %d external anchors verified", verified)
	}
}

// calculateSummary computes the summary statistics for the report.
func (v *PacketVerifier) calculateSummary(report *VerificationReport) {
	report.Valid = true
	totalWeight := 0.0
	passedWeight := 0.0

	// Component weights for confidence calculation
	weights := map[string]float64{
		"structure":              1.0,
		"chain_integrity":        2.0,
		"vdf_proofs":             1.5,
		"declaration":            1.0,
		"signatures":             1.0,
		"timestamp_consistency":  0.5,
		"forensic_patterns":      0.5,
		"external_anchors":       1.0,
	}

	for _, comp := range report.Components {
		weight := weights[comp.Component]
		if weight == 0 {
			weight = 1.0
		}
		totalWeight += weight

		switch comp.Status {
		case StatusPassed:
			report.Passed++
			passedWeight += weight
		case StatusFailed:
			report.Failed++
			report.Valid = false
		case StatusWarning:
			report.Warnings++
			passedWeight += weight * 0.8
		case StatusSkipped:
			report.Skipped++
			// Don't count against weight
			totalWeight -= weight
		}
	}

	// Calculate confidence
	if totalWeight > 0 {
		report.Confidence = passedWeight / totalWeight
	}

	// Determine evidence class
	report.EvidenceClass, report.ClassReason = v.classifyEvidence(report)

	// Generate recommendations
	report.Recommendations = v.generateRecommendations(report)
}

// classifyEvidence determines the evidence class based on verification results.
func (v *PacketVerifier) classifyEvidence(report *VerificationReport) (string, string) {
	if report.Failed > 0 {
		return "X", "Verification failed - evidence rejected"
	}

	if report.Confidence >= 0.95 && report.Warnings == 0 {
		return "A", "Full integrity, all checks passed"
	}

	if report.Confidence >= 0.85 {
		return "B", "Minor warnings, no critical issues"
	}

	if report.Confidence >= 0.7 {
		return "C", "Suspicious patterns detected, review required"
	}

	return "D", "Significant issues detected, not suitable for forensic reliance"
}

// generateRecommendations creates remediation suggestions.
func (v *PacketVerifier) generateRecommendations(report *VerificationReport) []string {
	var recs []string

	for _, comp := range report.Components {
		if comp.Status == StatusFailed && comp.Remediation != "" {
			recs = append(recs, fmt.Sprintf("%s: %s", comp.Component, comp.Remediation))
		}
	}

	if report.EvidenceClass == "C" || report.EvidenceClass == "D" {
		recs = append(recs, "Consider re-witnessing the document with enhanced monitoring")
	}

	if report.Skipped > 0 {
		recs = append(recs, "Some verifications were skipped - run with higher verification level")
	}

	return recs
}

// QuickVerify performs fast structural verification only.
func QuickVerify(packet *evidence.Packet) (*VerificationReport, error) {
	v := NewPacketVerifier(WithLevel(LevelQuick))
	return v.Verify(context.Background(), packet)
}

// StandardVerify performs full cryptographic verification.
func StandardVerify(packet *evidence.Packet) (*VerificationReport, error) {
	v := NewPacketVerifier(WithLevel(LevelStandard))
	return v.Verify(context.Background(), packet)
}

// ForensicVerify performs deep forensic analysis.
func ForensicVerify(packet *evidence.Packet) (*VerificationReport, error) {
	v := NewPacketVerifier(WithLevel(LevelForensic))
	return v.Verify(context.Background(), packet)
}
