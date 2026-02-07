// Package verify provides forensic consistency verification.
package verify

import (
	"fmt"
	"math"
	"sort"
	"time"

	"witnessd/internal/evidence"
)

// Forensic verification thresholds
const (
	// Minimum interval between checkpoints that's humanly possible
	MinHumanCheckpointInterval = 100 * time.Millisecond

	// Maximum typing speed (keystrokes per minute) considered human
	MaxHumanTypingSpeed = 200.0

	// Minimum typing speed considered plausible
	MinHumanTypingSpeed = 5.0

	// Maximum variance ratio for "too regular" detection
	TooRegularVarianceThreshold = 0.01

	// Minimum number of samples for statistical analysis
	MinStatisticalSamples = 5
)

// ForensicIndicator represents a detected forensic anomaly.
type ForensicIndicator struct {
	Type        ForensicIndicatorType `json:"type"`
	Severity    ForensicSeverity      `json:"severity"`
	Description string                `json:"description"`
	Details     map[string]any        `json:"details,omitempty"`
	Checkpoint  *int                  `json:"checkpoint,omitempty"`
	TimeRange   *TimeRange            `json:"time_range,omitempty"`
}

// ForensicIndicatorType categorizes forensic indicators.
type ForensicIndicatorType string

const (
	IndicatorTimingAnomaly     ForensicIndicatorType = "timing_anomaly"
	IndicatorSyntheticPattern  ForensicIndicatorType = "synthetic_pattern"
	IndicatorBurstPattern      ForensicIndicatorType = "burst_pattern"
	IndicatorGapPattern        ForensicIndicatorType = "gap_pattern"
	IndicatorClockManipulation ForensicIndicatorType = "clock_manipulation"
	IndicatorKeystrokeAnomaly  ForensicIndicatorType = "keystroke_anomaly"
	IndicatorBehavioralAnomaly ForensicIndicatorType = "behavioral_anomaly"
	IndicatorChainAnomaly      ForensicIndicatorType = "chain_anomaly"
)

// ForensicSeverity indicates how serious an indicator is.
type ForensicSeverity string

const (
	SeverityInfo     ForensicSeverity = "info"
	SeverityWarning  ForensicSeverity = "warning"
	SeverityCritical ForensicSeverity = "critical"
)

// TimeRange represents a time period.
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ForensicVerificationResult contains the complete forensic analysis results.
type ForensicVerificationResult struct {
	Clean       bool                 `json:"clean"`
	Indicators  []ForensicIndicator  `json:"indicators"`
	Statistics  *ForensicStatistics  `json:"statistics,omitempty"`
	Score       float64              `json:"score"` // 0.0 (highly suspicious) to 1.0 (clean)
	Assessment  string               `json:"assessment"`
}

// ForensicStatistics contains statistical analysis of the evidence.
type ForensicStatistics struct {
	TotalCheckpoints      int           `json:"total_checkpoints"`
	TotalDuration         time.Duration `json:"total_duration"`
	MeanInterval          time.Duration `json:"mean_interval"`
	MedianInterval        time.Duration `json:"median_interval"`
	StdDevInterval        time.Duration `json:"stddev_interval"`
	CoefficientOfVariation float64      `json:"coefficient_of_variation"`
	MinInterval           time.Duration `json:"min_interval"`
	MaxInterval           time.Duration `json:"max_interval"`
	EditRate              float64       `json:"edit_rate"` // Edits per minute
	BytesPerCheckpoint    float64       `json:"bytes_per_checkpoint"`
	TotalBytes            int64         `json:"total_bytes"`
}

// ForensicVerifier provides forensic consistency analysis.
type ForensicVerifier struct {
	// Thresholds
	minHumanInterval time.Duration
	maxTypingSpeed   float64
	minTypingSpeed   float64
}

// NewForensicVerifier creates a new forensic verifier with default thresholds.
func NewForensicVerifier() *ForensicVerifier {
	return &ForensicVerifier{
		minHumanInterval: MinHumanCheckpointInterval,
		maxTypingSpeed:   MaxHumanTypingSpeed,
		minTypingSpeed:   MinHumanTypingSpeed,
	}
}

// WithMinInterval sets the minimum human checkpoint interval.
func (v *ForensicVerifier) WithMinInterval(d time.Duration) *ForensicVerifier {
	v.minHumanInterval = d
	return v
}

// WithTypingSpeedRange sets the acceptable typing speed range.
func (v *ForensicVerifier) WithTypingSpeedRange(min, max float64) *ForensicVerifier {
	v.minTypingSpeed = min
	v.maxTypingSpeed = max
	return v
}

// AnalyzeEvidence performs comprehensive forensic analysis on an evidence packet.
func (v *ForensicVerifier) AnalyzeEvidence(packet *evidence.Packet) (*ForensicVerificationResult, error) {
	result := &ForensicVerificationResult{
		Clean:      true,
		Indicators: make([]ForensicIndicator, 0),
		Score:      1.0,
	}

	// Analyze checkpoint timing
	v.analyzeCheckpointTiming(packet, result)

	// Analyze keystroke evidence
	if packet.Keystroke != nil {
		v.analyzeKeystrokePatterns(packet, result)
	}

	// Analyze behavioral evidence
	if packet.Behavioral != nil {
		v.analyzeBehavioralPatterns(packet, result)
	}

	// Analyze chain consistency
	v.analyzeChainConsistency(packet, result)

	// Calculate statistics
	result.Statistics = v.calculateStatistics(packet)

	// Calculate overall score
	result.Score = v.calculateScore(result)
	result.Clean = result.Score >= 0.7

	// Generate assessment
	result.Assessment = v.generateAssessment(result)

	return result, nil
}

// analyzeCheckpointTiming checks for timing-related anomalies.
func (v *ForensicVerifier) analyzeCheckpointTiming(packet *evidence.Packet, result *ForensicVerificationResult) {
	if len(packet.Checkpoints) < 2 {
		return
	}

	var intervals []time.Duration
	var lastTimestamp time.Time

	for i, cp := range packet.Checkpoints {
		if i == 0 {
			lastTimestamp = cp.Timestamp
			continue
		}

		interval := cp.Timestamp.Sub(lastTimestamp)
		intervals = append(intervals, interval)

		// Check for time going backwards
		if interval < 0 {
			result.Indicators = append(result.Indicators, ForensicIndicator{
				Type:        IndicatorClockManipulation,
				Severity:    SeverityCritical,
				Description: fmt.Sprintf("checkpoint %d timestamp before previous checkpoint", i),
				Checkpoint:  &i,
				Details: map[string]any{
					"current_timestamp":  cp.Timestamp,
					"previous_timestamp": lastTimestamp,
					"difference":         interval.String(),
				},
			})
		}

		// Check for suspiciously fast checkpoints
		if interval >= 0 && interval < v.minHumanInterval {
			cpIdx := i
			result.Indicators = append(result.Indicators, ForensicIndicator{
				Type:        IndicatorTimingAnomaly,
				Severity:    SeverityWarning,
				Description: fmt.Sprintf("checkpoint %d created only %v after previous", i, interval),
				Checkpoint:  &cpIdx,
				Details: map[string]any{
					"interval":      interval.String(),
					"min_expected":  v.minHumanInterval.String(),
				},
			})
		}

		// Check for very large gaps
		if interval > 24*time.Hour {
			cpIdx := i
			result.Indicators = append(result.Indicators, ForensicIndicator{
				Type:        IndicatorGapPattern,
				Severity:    SeverityInfo,
				Description: fmt.Sprintf("large gap (%v) before checkpoint %d", interval.Round(time.Hour), i),
				Checkpoint:  &cpIdx,
				TimeRange: &TimeRange{
					Start: lastTimestamp,
					End:   cp.Timestamp,
				},
			})
		}

		lastTimestamp = cp.Timestamp
	}

	// Check for synthetic regularity
	if len(intervals) >= MinStatisticalSamples {
		v.checkSyntheticRegularity(intervals, result)
	}

	// Check for burst patterns
	v.checkBurstPatterns(intervals, result)
}

// checkSyntheticRegularity detects suspiciously uniform timing.
func (v *ForensicVerifier) checkSyntheticRegularity(intervals []time.Duration, result *ForensicVerificationResult) {
	if len(intervals) < MinStatisticalSamples {
		return
	}

	// Calculate mean
	var sum int64
	for _, interval := range intervals {
		sum += int64(interval)
	}
	mean := float64(sum) / float64(len(intervals))

	// Calculate variance
	var variance float64
	for _, interval := range intervals {
		diff := float64(interval) - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))

	// Calculate coefficient of variation
	stdDev := math.Sqrt(variance)
	cv := stdDev / mean

	// Very low CV suggests synthetic data
	if cv < TooRegularVarianceThreshold && len(intervals) > 5 {
		result.Indicators = append(result.Indicators, ForensicIndicator{
			Type:        IndicatorSyntheticPattern,
			Severity:    SeverityCritical,
			Description: "checkpoint intervals are suspiciously uniform (possible synthetic data)",
			Details: map[string]any{
				"mean_interval":            time.Duration(mean).String(),
				"stddev":                   time.Duration(stdDev).String(),
				"coefficient_of_variation": cv,
				"sample_size":              len(intervals),
			},
		})
	}
}

// checkBurstPatterns detects rapid bursts of activity.
func (v *ForensicVerifier) checkBurstPatterns(intervals []time.Duration, result *ForensicVerificationResult) {
	if len(intervals) < 3 {
		return
	}

	// Look for sequences of very short intervals
	burstCount := 0
	burstStart := -1

	for i, interval := range intervals {
		if interval < time.Second {
			if burstStart == -1 {
				burstStart = i
			}
			burstCount++
		} else {
			if burstCount >= 3 {
				result.Indicators = append(result.Indicators, ForensicIndicator{
					Type:        IndicatorBurstPattern,
					Severity:    SeverityWarning,
					Description: fmt.Sprintf("burst of %d checkpoints in rapid succession", burstCount),
					Details: map[string]any{
						"start_checkpoint": burstStart,
						"end_checkpoint":   i,
						"checkpoint_count": burstCount,
					},
				})
			}
			burstCount = 0
			burstStart = -1
		}
	}
}

// analyzeKeystrokePatterns checks keystroke evidence for anomalies.
func (v *ForensicVerifier) analyzeKeystrokePatterns(packet *evidence.Packet, result *ForensicVerificationResult) {
	ks := packet.Keystroke

	// Check typing speed
	if ks.KeystrokesPerMin > v.maxTypingSpeed {
		result.Indicators = append(result.Indicators, ForensicIndicator{
			Type:        IndicatorKeystrokeAnomaly,
			Severity:    SeverityCritical,
			Description: "keystroke rate exceeds human capability",
			Details: map[string]any{
				"reported_rate": ks.KeystrokesPerMin,
				"max_expected":  v.maxTypingSpeed,
			},
		})
	}

	if ks.KeystrokesPerMin > 0 && ks.KeystrokesPerMin < v.minTypingSpeed {
		result.Indicators = append(result.Indicators, ForensicIndicator{
			Type:        IndicatorKeystrokeAnomaly,
			Severity:    SeverityInfo,
			Description: "keystroke rate is unusually low",
			Details: map[string]any{
				"reported_rate": ks.KeystrokesPerMin,
				"min_expected":  v.minTypingSpeed,
			},
		})
	}

	// Check chain validity
	if !ks.ChainValid {
		result.Indicators = append(result.Indicators, ForensicIndicator{
			Type:        IndicatorKeystrokeAnomaly,
			Severity:    SeverityCritical,
			Description: "keystroke evidence chain is invalid",
		})
	}

	// Check plausibility flag
	if !ks.PlausibleHumanRate {
		result.Indicators = append(result.Indicators, ForensicIndicator{
			Type:        IndicatorKeystrokeAnomaly,
			Severity:    SeverityWarning,
			Description: "keystroke pattern flagged as non-human",
		})
	}

	// Check sample count vs keystrokes
	if ks.TotalSamples > 0 && ks.TotalKeystrokes > 0 {
		avgPerSample := float64(ks.TotalKeystrokes) / float64(ks.TotalSamples)
		if avgPerSample > 1000 {
			result.Indicators = append(result.Indicators, ForensicIndicator{
				Type:        IndicatorKeystrokeAnomaly,
				Severity:    SeverityWarning,
				Description: "unusually high keystrokes per sample",
				Details: map[string]any{
					"avg_per_sample": avgPerSample,
				},
			})
		}
	}
}

// analyzeBehavioralPatterns checks behavioral evidence for anomalies.
func (v *ForensicVerifier) analyzeBehavioralPatterns(packet *evidence.Packet, result *ForensicVerificationResult) {
	beh := packet.Behavioral
	if beh.Metrics == nil {
		return
	}

	metrics := beh.Metrics

	// Check monotonic append ratio
	if metrics.MonotonicAppendRatio > 0.99 {
		result.Indicators = append(result.Indicators, ForensicIndicator{
			Type:        IndicatorBehavioralAnomaly,
			Severity:    SeverityWarning,
			Description: "near-perfect append-only pattern suggests bulk insertion",
			Details: map[string]any{
				"monotonic_ratio": metrics.MonotonicAppendRatio,
			},
		})
	}

	// Check edit entropy
	if metrics.EditEntropy < 0.1 {
		result.Indicators = append(result.Indicators, ForensicIndicator{
			Type:        IndicatorBehavioralAnomaly,
			Severity:    SeverityWarning,
			Description: "very low edit entropy suggests non-interactive editing",
			Details: map[string]any{
				"edit_entropy": metrics.EditEntropy,
			},
		})
	}

	// Check positive/negative ratio
	if metrics.PositiveNegativeRatio > 100 {
		result.Indicators = append(result.Indicators, ForensicIndicator{
			Type:        IndicatorBehavioralAnomaly,
			Severity:    SeverityInfo,
			Description: "minimal deletions suggests copy-paste",
			Details: map[string]any{
				"positive_negative_ratio": metrics.PositiveNegativeRatio,
			},
		})
	}

	// Check anomaly count
	if metrics.AnomalyCount > 5 {
		result.Indicators = append(result.Indicators, ForensicIndicator{
			Type:        IndicatorBehavioralAnomaly,
			Severity:    SeverityWarning,
			Description: fmt.Sprintf("%d behavioral anomalies detected", metrics.AnomalyCount),
			Details: map[string]any{
				"anomaly_count": metrics.AnomalyCount,
			},
		})
	}
}

// analyzeChainConsistency checks for chain-level anomalies.
func (v *ForensicVerifier) analyzeChainConsistency(packet *evidence.Packet, result *ForensicVerificationResult) {
	if len(packet.Checkpoints) == 0 {
		return
	}

	// Check for size anomalies
	var sizes []int64
	var prevSize int64 = 0

	for i, cp := range packet.Checkpoints {
		sizes = append(sizes, cp.ContentSize)

		// Check for dramatic size decreases
		if i > 0 && prevSize > 0 {
			decrease := float64(prevSize-cp.ContentSize) / float64(prevSize)
			if decrease > 0.5 && prevSize > 1000 {
				cpIdx := i
				result.Indicators = append(result.Indicators, ForensicIndicator{
					Type:        IndicatorChainAnomaly,
					Severity:    SeverityInfo,
					Description: fmt.Sprintf("checkpoint %d: content decreased by %.0f%%", i, decrease*100),
					Checkpoint:  &cpIdx,
					Details: map[string]any{
						"previous_size": prevSize,
						"current_size":  cp.ContentSize,
						"decrease_pct":  decrease * 100,
					},
				})
			}
		}

		prevSize = cp.ContentSize
	}

	// Check for identical consecutive hashes
	for i := 1; i < len(packet.Checkpoints); i++ {
		if packet.Checkpoints[i].ContentHash == packet.Checkpoints[i-1].ContentHash {
			cpIdx := i
			result.Indicators = append(result.Indicators, ForensicIndicator{
				Type:        IndicatorChainAnomaly,
				Severity:    SeverityInfo,
				Description: fmt.Sprintf("checkpoint %d has same content hash as previous", i),
				Checkpoint:  &cpIdx,
			})
		}
	}
}

// calculateStatistics computes statistical summaries.
func (v *ForensicVerifier) calculateStatistics(packet *evidence.Packet) *ForensicStatistics {
	stats := &ForensicStatistics{
		TotalCheckpoints: len(packet.Checkpoints),
	}

	if len(packet.Checkpoints) < 2 {
		return stats
	}

	// Collect intervals
	var intervals []time.Duration
	var totalSize int64

	for i, cp := range packet.Checkpoints {
		totalSize += cp.ContentSize
		if i > 0 {
			interval := cp.Timestamp.Sub(packet.Checkpoints[i-1].Timestamp)
			intervals = append(intervals, interval)
		}
	}

	stats.TotalBytes = totalSize
	stats.BytesPerCheckpoint = float64(totalSize) / float64(len(packet.Checkpoints))

	if len(intervals) > 0 {
		// Sort for median
		sortedIntervals := make([]time.Duration, len(intervals))
		copy(sortedIntervals, intervals)
		sort.Slice(sortedIntervals, func(i, j int) bool {
			return sortedIntervals[i] < sortedIntervals[j]
		})

		stats.MinInterval = sortedIntervals[0]
		stats.MaxInterval = sortedIntervals[len(sortedIntervals)-1]
		stats.MedianInterval = sortedIntervals[len(sortedIntervals)/2]

		// Calculate mean
		var sum int64
		for _, interval := range intervals {
			sum += int64(interval)
		}
		mean := float64(sum) / float64(len(intervals))
		stats.MeanInterval = time.Duration(mean)

		// Calculate stddev
		var variance float64
		for _, interval := range intervals {
			diff := float64(interval) - mean
			variance += diff * diff
		}
		variance /= float64(len(intervals))
		stats.StdDevInterval = time.Duration(math.Sqrt(variance))

		// Coefficient of variation
		if mean > 0 {
			stats.CoefficientOfVariation = math.Sqrt(variance) / mean
		}

		// Total duration
		stats.TotalDuration = packet.Checkpoints[len(packet.Checkpoints)-1].Timestamp.Sub(
			packet.Checkpoints[0].Timestamp)

		// Edit rate
		if stats.TotalDuration > 0 {
			stats.EditRate = float64(len(packet.Checkpoints)) / stats.TotalDuration.Minutes()
		}
	}

	return stats
}

// calculateScore computes an overall forensic score.
func (v *ForensicVerifier) calculateScore(result *ForensicVerificationResult) float64 {
	score := 1.0

	for _, indicator := range result.Indicators {
		switch indicator.Severity {
		case SeverityCritical:
			score -= 0.3
		case SeverityWarning:
			score -= 0.1
		case SeverityInfo:
			score -= 0.02
		}
	}

	if score < 0 {
		score = 0
	}

	return score
}

// generateAssessment creates a human-readable assessment.
func (v *ForensicVerifier) generateAssessment(result *ForensicVerificationResult) string {
	critical := 0
	warnings := 0
	for _, indicator := range result.Indicators {
		switch indicator.Severity {
		case SeverityCritical:
			critical++
		case SeverityWarning:
			warnings++
		}
	}

	if critical > 0 {
		return fmt.Sprintf("SUSPICIOUS: %d critical anomalies detected - manual review required", critical)
	}

	if warnings > 2 {
		return fmt.Sprintf("CAUTION: %d warning indicators - review recommended", warnings)
	}

	if warnings > 0 {
		return "ACCEPTABLE: minor anomalies detected but within normal range"
	}

	return "CLEAN: no forensic anomalies detected"
}
