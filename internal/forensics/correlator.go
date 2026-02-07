// Package forensics provides content-keystroke correlation analysis.
//
// The correlator verifies that document content length matches keystroke count
// without logging actual keystrokes. It flags documents where content length
// significantly exceeds keystroke count minus detected pastes.
package forensics

import (
	"fmt"
	"math"
	"time"
)

// CorrelationResult contains the analysis of content vs keystroke correlation.
type CorrelationResult struct {
	// Input metrics
	DocumentLength     int64 `json:"document_length"`      // Final document size in bytes
	TotalKeystrokes    int64 `json:"total_keystrokes"`     // Total keystroke count
	DetectedPasteChars int64 `json:"detected_paste_chars"` // Characters from detected pastes
	DetectedPasteCount int64 `json:"detected_paste_count"` // Number of paste operations

	// Derived metrics
	EffectiveKeystrokes int64   `json:"effective_keystrokes"` // Keystrokes minus deletions estimate
	ExpectedContent     int64   `json:"expected_content"`     // Expected content from keystrokes + pastes
	Discrepancy         int64   `json:"discrepancy"`          // Actual - Expected
	DiscrepancyRatio    float64 `json:"discrepancy_ratio"`    // Discrepancy / Expected

	// Velocity metrics (if available)
	AutocompleteChars int64 `json:"autocomplete_chars"` // Characters from velocity-detected autocomplete
	SuspiciousBursts  int   `json:"suspicious_bursts"`  // Number of suspicious velocity bursts

	// Assessment
	Status      CorrelationStatus `json:"status"`
	Explanation string            `json:"explanation"`
	Flags       []CorrelationFlag `json:"flags,omitempty"`
}

// CorrelationStatus indicates the overall correlation assessment.
type CorrelationStatus string

const (
	StatusConsistent   CorrelationStatus = "consistent"   // Content matches expected
	StatusSuspicious   CorrelationStatus = "suspicious"   // Minor discrepancy
	StatusInconsistent CorrelationStatus = "inconsistent" // Major discrepancy
	StatusInsufficient CorrelationStatus = "insufficient" // Not enough data
)

// CorrelationFlag identifies specific concerns.
type CorrelationFlag string

const (
	FlagExcessContent     CorrelationFlag = "excess_content"     // More content than keystrokes explain
	FlagUndetectedPaste   CorrelationFlag = "undetected_paste"   // Likely paste without clipboard detection
	FlagAutocomplete      CorrelationFlag = "autocomplete"       // Velocity suggests autocomplete
	FlagNoKeystrokes      CorrelationFlag = "no_keystrokes"      // Content with zero/few keystrokes
	FlagHighEditRatio     CorrelationFlag = "high_edit_ratio"    // Many deletions (unclear final ratio)
	FlagExternalGenerated CorrelationFlag = "external_generated" // Likely externally generated content
)

// CorrelatorConfig configures the content-keystroke correlator.
type CorrelatorConfig struct {
	// Thresholds for flagging
	SuspiciousRatioThreshold   float64 // Discrepancy ratio for "suspicious" (default: 0.3)
	InconsistentRatioThreshold float64 // Discrepancy ratio for "inconsistent" (default: 0.5)

	// Estimated edit ratio: fraction of keystrokes that are deletions
	// This is used to estimate effective keystrokes from total keystrokes
	// Default: 0.15 (15% of keystrokes are backspace/delete)
	EstimatedEditRatio float64

	// Minimum keystrokes for meaningful analysis
	MinKeystrokes int64

	// Minimum document length for meaningful analysis
	MinDocumentLength int64
}

// DefaultCorrelatorConfig returns sensible defaults.
func DefaultCorrelatorConfig() CorrelatorConfig {
	return CorrelatorConfig{
		SuspiciousRatioThreshold:   0.3, // 30% discrepancy
		InconsistentRatioThreshold: 0.5, // 50% discrepancy
		EstimatedEditRatio:         0.15,
		MinKeystrokes:              10,
		MinDocumentLength:          50,
	}
}

// ContentKeystrokeCorrelator analyzes the relationship between document content
// and recorded keystroke counts.
type ContentKeystrokeCorrelator struct {
	config CorrelatorConfig
}

// NewContentKeystrokeCorrelator creates a correlator with default config.
func NewContentKeystrokeCorrelator() *ContentKeystrokeCorrelator {
	return &ContentKeystrokeCorrelator{
		config: DefaultCorrelatorConfig(),
	}
}

// NewContentKeystrokeCorrelatorWithConfig creates a correlator with custom config.
func NewContentKeystrokeCorrelatorWithConfig(config CorrelatorConfig) *ContentKeystrokeCorrelator {
	return &ContentKeystrokeCorrelator{config: config}
}

// CorrelationInput contains the data needed for correlation analysis.
type CorrelationInput struct {
	// Required
	DocumentLength  int64 // Final document size in bytes
	TotalKeystrokes int64 // Total keystroke count

	// Optional: paste detection
	DetectedPasteChars int64 // Characters from detected pastes
	DetectedPasteCount int64 // Number of paste operations

	// Optional: velocity analysis
	AutocompleteChars int64 // Characters from velocity-detected autocomplete
	SuspiciousBursts  int   // Number of suspicious velocity bursts

	// Optional: if actual edit ratio is known
	ActualEditRatio *float64 // Fraction of keystrokes that were deletions

	// Optional: session info
	SessionDuration time.Duration // For rate calculations
}

// Analyze performs correlation analysis.
func (c *ContentKeystrokeCorrelator) Analyze(input CorrelationInput) *CorrelationResult {
	result := &CorrelationResult{
		DocumentLength:     input.DocumentLength,
		TotalKeystrokes:    input.TotalKeystrokes,
		DetectedPasteChars: input.DetectedPasteChars,
		DetectedPasteCount: input.DetectedPasteCount,
		AutocompleteChars:  input.AutocompleteChars,
		SuspiciousBursts:   input.SuspiciousBursts,
	}

	// Insufficient data check
	if input.TotalKeystrokes < c.config.MinKeystrokes &&
		input.DocumentLength < c.config.MinDocumentLength {
		result.Status = StatusInsufficient
		result.Explanation = "insufficient data for meaningful correlation analysis"
		return result
	}

	// Calculate effective keystrokes (content-producing keystrokes)
	editRatio := c.config.EstimatedEditRatio
	if input.ActualEditRatio != nil {
		editRatio = *input.ActualEditRatio
	}

	// Effective keystrokes = total * (1 - editRatio)
	// This accounts for backspaces and deletes
	result.EffectiveKeystrokes = int64(float64(input.TotalKeystrokes) * (1 - editRatio))

	// Expected content = effective keystrokes + paste chars + autocomplete chars
	result.ExpectedContent = result.EffectiveKeystrokes + input.DetectedPasteChars + input.AutocompleteChars

	// Handle edge case: no expected content
	if result.ExpectedContent <= 0 {
		if input.DocumentLength > 0 {
			result.Status = StatusInconsistent
			result.Explanation = "document has content but no keystroke/paste activity detected"
			result.Flags = append(result.Flags, FlagNoKeystrokes, FlagExternalGenerated)
		} else {
			result.Status = StatusConsistent
			result.Explanation = "empty document with no activity"
		}
		return result
	}

	// Calculate discrepancy
	result.Discrepancy = input.DocumentLength - result.ExpectedContent
	result.DiscrepancyRatio = float64(result.Discrepancy) / float64(result.ExpectedContent)

	// Assess the discrepancy
	c.assessDiscrepancy(result, input)

	return result
}

// assessDiscrepancy determines status and flags based on discrepancy.
func (c *ContentKeystrokeCorrelator) assessDiscrepancy(result *CorrelationResult, input CorrelationInput) {
	absRatio := math.Abs(result.DiscrepancyRatio)

	// Check for suspicious velocity patterns
	if input.SuspiciousBursts > 0 {
		result.Flags = append(result.Flags, FlagAutocomplete)
	}

	// Positive discrepancy: more content than explained
	if result.Discrepancy > 0 {
		if absRatio >= c.config.InconsistentRatioThreshold {
			result.Status = StatusInconsistent
			result.Flags = append(result.Flags, FlagExcessContent)

			// Try to diagnose the cause
			unexplained := result.Discrepancy
			if unexplained > 100 && input.DetectedPasteCount == 0 {
				result.Flags = append(result.Flags, FlagUndetectedPaste)
				result.Explanation = fmt.Sprintf(
					"content exceeds expected by %d bytes (%.0f%%); likely undetected paste or external generation",
					result.Discrepancy, absRatio*100,
				)
			} else if input.SuspiciousBursts > 3 {
				result.Flags = append(result.Flags, FlagExternalGenerated)
				result.Explanation = fmt.Sprintf(
					"content exceeds expected by %d bytes (%.0f%%) with %d suspicious velocity bursts",
					result.Discrepancy, absRatio*100, input.SuspiciousBursts,
				)
			} else {
				result.Explanation = fmt.Sprintf(
					"content exceeds expected by %d bytes (%.0f%%)",
					result.Discrepancy, absRatio*100,
				)
			}
		} else if absRatio >= c.config.SuspiciousRatioThreshold {
			result.Status = StatusSuspicious
			result.Explanation = fmt.Sprintf(
				"minor discrepancy: content exceeds expected by %d bytes (%.0f%%)",
				result.Discrepancy, absRatio*100,
			)
		} else {
			result.Status = StatusConsistent
			result.Explanation = "content length is consistent with keystroke activity"
		}
		return
	}

	// Negative discrepancy: less content than expected (heavy editing)
	if result.Discrepancy < 0 {
		if absRatio >= c.config.SuspiciousRatioThreshold {
			result.Status = StatusSuspicious
			result.Flags = append(result.Flags, FlagHighEditRatio)
			result.Explanation = fmt.Sprintf(
				"document is %d bytes shorter than expected; indicates heavy editing (%.0f%% edit ratio)",
				-result.Discrepancy, absRatio*100,
			)
		} else {
			result.Status = StatusConsistent
			result.Explanation = "content length is consistent with keystroke activity (normal editing)"
		}
		return
	}

	// Perfect match (rare)
	result.Status = StatusConsistent
	result.Explanation = "content length exactly matches expected keystroke activity"
}

// QuickCorrelate performs a simple correlation check.
// Returns true if content is suspicious (likely not human-typed).
func QuickCorrelate(documentLength, keystrokes, pasteChars int64) bool {
	if keystrokes == 0 && documentLength > 50 {
		return true // Content without keystrokes
	}

	effectiveKeystrokes := int64(float64(keystrokes) * 0.85) // Assume 15% edit ratio
	expected := effectiveKeystrokes + pasteChars

	if expected <= 0 {
		return documentLength > 50
	}

	discrepancyRatio := float64(documentLength-expected) / float64(expected)
	return discrepancyRatio > 0.5 // More than 50% excess
}

// CorrelationReport generates a human-readable report.
func (r *CorrelationResult) Report() string {
	report := fmt.Sprintf(`Content-Keystroke Correlation Report
=====================================
Document Length:     %d bytes
Total Keystrokes:    %d
Detected Pastes:     %d operations (%d chars)
Autocomplete Chars:  %d
Suspicious Bursts:   %d

Effective Keystrokes: %d (estimated after edit ratio)
Expected Content:     %d bytes
Actual Content:       %d bytes
Discrepancy:          %d bytes (%.1f%%)

Status: %s
%s
`,
		r.DocumentLength,
		r.TotalKeystrokes,
		r.DetectedPasteCount, r.DetectedPasteChars,
		r.AutocompleteChars,
		r.SuspiciousBursts,
		r.EffectiveKeystrokes,
		r.ExpectedContent,
		r.DocumentLength,
		r.Discrepancy, r.DiscrepancyRatio*100,
		r.Status,
		r.Explanation,
	)

	if len(r.Flags) > 0 {
		report += "\nFlags:\n"
		for _, flag := range r.Flags {
			report += fmt.Sprintf("  - %s\n", flag)
		}
	}

	return report
}
