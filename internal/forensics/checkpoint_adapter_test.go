package forensics

import (
	"testing"
	"time"
)

func TestCheckpointsToEvents(t *testing.T) {
	now := time.Now()
	checkpoints := []CheckpointData{
		{Ordinal: 0, Timestamp: now, ContentSize: 100, FilePath: "/test/doc.md"},
		{Ordinal: 1, Timestamp: now.Add(time.Minute), ContentSize: 250, SizeDelta: 150, FilePath: "/test/doc.md"},
		{Ordinal: 2, Timestamp: now.Add(2 * time.Minute), ContentSize: 500, SizeDelta: 250, FilePath: "/test/doc.md"},
	}

	events := CheckpointsToEvents(checkpoints)

	if len(events) != 3 {
		t.Errorf("Expected 3 events, got %d", len(events))
	}

	if events[0].ID != 0 {
		t.Errorf("Expected ID 0, got %d", events[0].ID)
	}

	if events[1].SizeDelta != 150 {
		t.Errorf("Expected SizeDelta 150, got %d", events[1].SizeDelta)
	}
}

func TestAnalyzeCheckpoints(t *testing.T) {
	now := time.Now()

	// Test with insufficient data
	t.Run("insufficient data", func(t *testing.T) {
		checkpoints := []CheckpointData{
			{Ordinal: 0, Timestamp: now, ContentSize: 100},
		}

		profile, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if profile.Assessment != AssessmentInsufficient {
			t.Errorf("Expected insufficient assessment, got %s", profile.Assessment)
		}
	})

	// Test with typical authoring pattern
	t.Run("typical authoring", func(t *testing.T) {
		var checkpoints []CheckpointData
		for i := 0; i < 20; i++ {
			cp := CheckpointData{
				Ordinal:     uint64(i),
				Timestamp:   now.Add(time.Duration(i) * 10 * time.Minute),
				ContentSize: int64(100 + i*50),
				FilePath:    "/test/doc.md",
			}
			checkpoints = append(checkpoints, cp)
		}

		profile, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if profile.EventCount != 20 {
			t.Errorf("Expected 20 events, got %d", profile.EventCount)
		}
	})
}

func TestProfileToExportableMetrics(t *testing.T) {
	profile := &AuthorshipProfile{
		Metrics: PrimaryMetrics{
			MonotonicAppendRatio:  0.75,
			EditEntropy:           2.5,
			MedianInterval:        300.0,
			PositiveNegativeRatio: 0.85,
			DeletionClustering:    1.2,
		},
		Assessment: AssessmentConsistent,
		Anomalies:  []Anomaly{{Type: AnomalyGap}},
	}

	metrics := ProfileToExportableMetrics(profile)

	if metrics == nil {
		t.Fatal("Expected non-nil metrics")
	}

	if metrics.MonotonicAppendRatio != 0.75 {
		t.Errorf("Expected MonotonicAppendRatio 0.75, got %f", metrics.MonotonicAppendRatio)
	}

	if metrics.AnomalyCount != 1 {
		t.Errorf("Expected 1 anomaly, got %d", metrics.AnomalyCount)
	}

	if metrics.Assessment != "CONSISTENT WITH HUMAN AUTHORSHIP" {
		t.Errorf("Unexpected assessment: %s", metrics.Assessment)
	}
}

func TestProfileToExportableMetricsNil(t *testing.T) {
	metrics := ProfileToExportableMetrics(nil)
	if metrics != nil {
		t.Error("Expected nil metrics for nil profile")
	}
}
