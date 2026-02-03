// Package forensics provides metrics and analysis for forensic authorship detection.
//
// This file provides adapters to convert checkpoint data to forensics event data.

package forensics

import (
	"time"
)

// CheckpointData represents checkpoint information for forensics analysis.
// This adapter type allows the forensics package to work with checkpoint chains.
type CheckpointData struct {
	Ordinal      uint64
	Timestamp    time.Time
	ContentSize  int64
	SizeDelta    int32 // Computed from size difference
	ContentHash  [32]byte
	PreviousHash [32]byte
	FilePath     string
}

// CheckpointsToEvents converts checkpoint data to forensics event format.
// This allows forensic analysis of checkpoint-based workflows.
func CheckpointsToEvents(checkpoints []CheckpointData) []EventData {
	events := make([]EventData, len(checkpoints))

	for i, cp := range checkpoints {
		events[i] = EventData{
			ID:          int64(cp.Ordinal),
			TimestampNs: cp.Timestamp.UnixNano(),
			FileSize:    cp.ContentSize,
			SizeDelta:   cp.SizeDelta,
			FilePath:    cp.FilePath,
		}
	}

	return events
}

// AnalyzeCheckpoints performs forensic analysis on a checkpoint sequence.
// Returns an AuthorshipProfile with metrics and anomaly detection.
func AnalyzeCheckpoints(checkpoints []CheckpointData) (*AuthorshipProfile, error) {
	if len(checkpoints) < MinEventsForAnalysis {
		return &AuthorshipProfile{
			EventCount: len(checkpoints),
			Assessment: AssessmentInsufficient,
		}, nil
	}

	// Calculate size deltas between consecutive checkpoints
	for i := 1; i < len(checkpoints); i++ {
		delta := checkpoints[i].ContentSize - checkpoints[i-1].ContentSize
		checkpoints[i].SizeDelta = int32(clamp64(delta, -2147483648, 2147483647))
	}

	// Convert to events
	events := CheckpointsToEvents(checkpoints)

	// Create empty regions map (checkpoints don't have region data)
	regions := make(map[int64][]RegionData)

	// Build profile
	return BuildProfile(events, regions)
}

// clamp64 clamps an int64 to a range.
func clamp64(v, min, max int64) int64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// ExportableMetrics returns metrics in a format suitable for evidence export.
// This matches the structure expected by internal/evidence.ForensicMetrics.
type ExportableMetrics struct {
	MonotonicAppendRatio  float64 `json:"monotonic_append_ratio"`
	EditEntropy           float64 `json:"edit_entropy"`
	MedianInterval        float64 `json:"median_interval_seconds"`
	PositiveNegativeRatio float64 `json:"positive_negative_ratio"`
	DeletionClustering    float64 `json:"deletion_clustering"`
	Assessment            string  `json:"assessment"`
	AnomalyCount          int     `json:"anomaly_count"`
}

// ProfileToExportableMetrics converts a profile to exportable metrics format.
func ProfileToExportableMetrics(profile *AuthorshipProfile) *ExportableMetrics {
	if profile == nil {
		return nil
	}

	return &ExportableMetrics{
		MonotonicAppendRatio:  profile.Metrics.MonotonicAppendRatio,
		EditEntropy:           profile.Metrics.EditEntropy,
		MedianInterval:        profile.Metrics.MedianInterval,
		PositiveNegativeRatio: profile.Metrics.PositiveNegativeRatio,
		DeletionClustering:    profile.Metrics.DeletionClustering,
		Assessment:            string(profile.Assessment),
		AnomalyCount:          len(profile.Anomalies),
	}
}
