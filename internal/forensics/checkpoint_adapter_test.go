package forensics

import (
	"math"
	"testing"
	"time"
)

// =============================================================================
// CheckpointsToEvents Tests
// =============================================================================

func TestCheckpointsToEventsComprehensive(t *testing.T) {
	t.Run("basic_conversion", func(t *testing.T) {
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
	})

	t.Run("empty_checkpoints", func(t *testing.T) {
		events := CheckpointsToEvents(nil)
		if len(events) != 0 {
			t.Errorf("expected empty events for nil input, got %d", len(events))
		}

		events = CheckpointsToEvents([]CheckpointData{})
		if len(events) != 0 {
			t.Errorf("expected empty events for empty input, got %d", len(events))
		}
	})

	t.Run("single_checkpoint", func(t *testing.T) {
		checkpoints := []CheckpointData{
			{Ordinal: 42, Timestamp: time.Now(), ContentSize: 1000, FilePath: "/doc.txt"},
		}

		events := CheckpointsToEvents(checkpoints)

		if len(events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(events))
		}
		if events[0].ID != 42 {
			t.Errorf("expected ID 42, got %d", events[0].ID)
		}
		if events[0].FileSize != 1000 {
			t.Errorf("expected FileSize 1000, got %d", events[0].FileSize)
		}
	})

	t.Run("preserves_file_path", func(t *testing.T) {
		checkpoints := []CheckpointData{
			{FilePath: "/path/to/my/document.md"},
			{FilePath: "/path/to/my/document.md"},
		}

		events := CheckpointsToEvents(checkpoints)

		for i, e := range events {
			if e.FilePath != "/path/to/my/document.md" {
				t.Errorf("event %d: expected path preserved, got %s", i, e.FilePath)
			}
		}
	})

	t.Run("timestamp_conversion", func(t *testing.T) {
		now := time.Now()
		checkpoints := []CheckpointData{
			{Timestamp: now},
		}

		events := CheckpointsToEvents(checkpoints)

		expectedNs := now.UnixNano()
		if events[0].TimestampNs != expectedNs {
			t.Errorf("expected timestamp %d, got %d", expectedNs, events[0].TimestampNs)
		}
	})

	t.Run("large_ordinals", func(t *testing.T) {
		checkpoints := []CheckpointData{
			{Ordinal: 0},
			{Ordinal: 1000000},
			{Ordinal: math.MaxUint32},
		}

		events := CheckpointsToEvents(checkpoints)

		if events[2].ID != int64(math.MaxUint32) {
			t.Errorf("large ordinal conversion failed: %d", events[2].ID)
		}
	})
}

// =============================================================================
// AnalyzeCheckpoints Tests
// =============================================================================

func TestAnalyzeCheckpointsComprehensive(t *testing.T) {
	now := time.Now()

	t.Run("insufficient_data", func(t *testing.T) {
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
		if profile.EventCount != 1 {
			t.Errorf("Expected EventCount 1, got %d", profile.EventCount)
		}
	})

	t.Run("exactly_minimum_events", func(t *testing.T) {
		var checkpoints []CheckpointData
		for i := 0; i < MinEventsForAnalysis; i++ {
			checkpoints = append(checkpoints, CheckpointData{
				Ordinal:     uint64(i),
				Timestamp:   now.Add(time.Duration(i) * time.Minute),
				ContentSize: int64(100 + i*20),
				FilePath:    "/test.txt",
			})
		}

		profile, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if profile.EventCount != MinEventsForAnalysis {
			t.Errorf("expected %d events, got %d", MinEventsForAnalysis, profile.EventCount)
		}
	})

	t.Run("typical_authoring", func(t *testing.T) {
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

	t.Run("size_delta_calculation", func(t *testing.T) {
		checkpoints := []CheckpointData{
			{Ordinal: 0, Timestamp: now, ContentSize: 100},
			{Ordinal: 1, Timestamp: now.Add(time.Minute), ContentSize: 250},   // +150
			{Ordinal: 2, Timestamp: now.Add(2 * time.Minute), ContentSize: 200}, // -50
			{Ordinal: 3, Timestamp: now.Add(3 * time.Minute), ContentSize: 300}, // +100
			{Ordinal: 4, Timestamp: now.Add(4 * time.Minute), ContentSize: 100}, // -200
		}

		_, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify size deltas were computed
		// First checkpoint has no delta
		if checkpoints[1].SizeDelta != 150 {
			t.Errorf("checkpoint 1: expected delta 150, got %d", checkpoints[1].SizeDelta)
		}
		if checkpoints[2].SizeDelta != -50 {
			t.Errorf("checkpoint 2: expected delta -50, got %d", checkpoints[2].SizeDelta)
		}
	})

	t.Run("large_size_delta_clamping", func(t *testing.T) {
		checkpoints := []CheckpointData{
			{Ordinal: 0, Timestamp: now, ContentSize: 0},
			{Ordinal: 1, Timestamp: now.Add(time.Minute), ContentSize: 5_000_000_000}, // 5GB
			{Ordinal: 2, Timestamp: now.Add(2 * time.Minute), ContentSize: 100},
			{Ordinal: 3, Timestamp: now.Add(3 * time.Minute), ContentSize: 200},
			{Ordinal: 4, Timestamp: now.Add(4 * time.Minute), ContentSize: 300},
		}

		_, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should clamp to MaxInt32
		if checkpoints[1].SizeDelta != 2147483647 {
			t.Errorf("expected clamped delta, got %d", checkpoints[1].SizeDelta)
		}
	})

	t.Run("with_sessions", func(t *testing.T) {
		gen := NewTestDataGenerator(42)
		checkpoints := gen.GenerateCheckpoints(30, now)

		profile, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if profile.SessionCount < 1 {
			t.Error("should detect at least one session")
		}
	})

	t.Run("timeline_span", func(t *testing.T) {
		checkpoints := []CheckpointData{
			{Ordinal: 0, Timestamp: now},
			{Ordinal: 1, Timestamp: now.Add(time.Hour)},
			{Ordinal: 2, Timestamp: now.Add(2 * time.Hour)},
			{Ordinal: 3, Timestamp: now.Add(24 * time.Hour)},
			{Ordinal: 4, Timestamp: now.Add(48 * time.Hour)},
		}

		profile, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedSpan := 48 * time.Hour
		if math.Abs(float64(profile.TimeSpan-expectedSpan)) > float64(time.Second) {
			t.Errorf("expected time span ~48h, got %v", profile.TimeSpan)
		}
	})
}

func TestAnalyzeCheckpointsEdgeCases(t *testing.T) {
	now := time.Now()

	t.Run("empty_checkpoints", func(t *testing.T) {
		profile, err := AnalyzeCheckpoints(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if profile.Assessment != AssessmentInsufficient {
			t.Error("empty checkpoints should give insufficient assessment")
		}
	})

	t.Run("zero_content_size", func(t *testing.T) {
		var checkpoints []CheckpointData
		for i := 0; i < 10; i++ {
			checkpoints = append(checkpoints, CheckpointData{
				Ordinal:     uint64(i),
				Timestamp:   now.Add(time.Duration(i) * time.Minute),
				ContentSize: 0, // All zeros
			})
		}

		profile, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should handle gracefully
		if profile.EventCount != 10 {
			t.Errorf("expected 10 events, got %d", profile.EventCount)
		}
	})

	t.Run("same_timestamps", func(t *testing.T) {
		var checkpoints []CheckpointData
		for i := 0; i < 10; i++ {
			checkpoints = append(checkpoints, CheckpointData{
				Ordinal:     uint64(i),
				Timestamp:   now, // All same timestamp
				ContentSize: int64(i * 100),
			})
		}

		profile, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// MedianInterval should be 0 or very small
		if profile.Metrics.MedianInterval != 0 {
			t.Errorf("expected 0 median interval for same timestamps, got %v",
				profile.Metrics.MedianInterval)
		}
	})

	t.Run("reverse_chronological", func(t *testing.T) {
		// Checkpoints in reverse order
		var checkpoints []CheckpointData
		for i := 9; i >= 0; i-- {
			checkpoints = append(checkpoints, CheckpointData{
				Ordinal:     uint64(9 - i),
				Timestamp:   now.Add(time.Duration(i) * time.Minute),
				ContentSize: int64(100 + i*20),
			})
		}

		profile, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should handle out-of-order timestamps
		if profile.EventCount != 10 {
			t.Errorf("expected 10 events, got %d", profile.EventCount)
		}
	})

	t.Run("negative_content_size", func(t *testing.T) {
		// Invalid negative sizes
		checkpoints := []CheckpointData{
			{Ordinal: 0, Timestamp: now, ContentSize: 100},
			{Ordinal: 1, Timestamp: now.Add(time.Minute), ContentSize: -50},
			{Ordinal: 2, Timestamp: now.Add(2 * time.Minute), ContentSize: 200},
			{Ordinal: 3, Timestamp: now.Add(3 * time.Minute), ContentSize: 300},
			{Ordinal: 4, Timestamp: now.Add(4 * time.Minute), ContentSize: 400},
		}

		// Should not panic
		profile, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should handle gracefully
		if profile.EventCount != 5 {
			t.Errorf("expected 5 events, got %d", profile.EventCount)
		}
	})
}

// =============================================================================
// ProfileToExportableMetrics Tests
// =============================================================================

func TestProfileToExportableMetricsComprehensive(t *testing.T) {
	t.Run("full_profile", func(t *testing.T) {
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

		if metrics.EditEntropy != 2.5 {
			t.Errorf("Expected EditEntropy 2.5, got %f", metrics.EditEntropy)
		}

		if metrics.MedianInterval != 300.0 {
			t.Errorf("Expected MedianInterval 300.0, got %f", metrics.MedianInterval)
		}

		if metrics.PositiveNegativeRatio != 0.85 {
			t.Errorf("Expected PositiveNegativeRatio 0.85, got %f", metrics.PositiveNegativeRatio)
		}

		if metrics.DeletionClustering != 1.2 {
			t.Errorf("Expected DeletionClustering 1.2, got %f", metrics.DeletionClustering)
		}

		if metrics.AnomalyCount != 1 {
			t.Errorf("Expected 1 anomaly, got %d", metrics.AnomalyCount)
		}

		if metrics.Assessment != "CONSISTENT WITH HUMAN AUTHORSHIP" {
			t.Errorf("Unexpected assessment: %s", metrics.Assessment)
		}
	})

	t.Run("nil_profile", func(t *testing.T) {
		metrics := ProfileToExportableMetrics(nil)
		if metrics != nil {
			t.Error("Expected nil metrics for nil profile")
		}
	})

	t.Run("zero_anomalies", func(t *testing.T) {
		profile := &AuthorshipProfile{
			Anomalies: nil,
		}

		metrics := ProfileToExportableMetrics(profile)
		if metrics.AnomalyCount != 0 {
			t.Errorf("expected 0 anomalies, got %d", metrics.AnomalyCount)
		}
	})

	t.Run("many_anomalies", func(t *testing.T) {
		anomalies := make([]Anomaly, 100)
		for i := range anomalies {
			anomalies[i] = Anomaly{Type: AnomalyGap}
		}

		profile := &AuthorshipProfile{
			Anomalies: anomalies,
		}

		metrics := ProfileToExportableMetrics(profile)
		if metrics.AnomalyCount != 100 {
			t.Errorf("expected 100 anomalies, got %d", metrics.AnomalyCount)
		}
	})

	t.Run("all_assessments", func(t *testing.T) {
		assessments := []Assessment{
			AssessmentConsistent,
			AssessmentSuspicious,
			AssessmentInsufficient,
		}

		for _, a := range assessments {
			profile := &AuthorshipProfile{Assessment: a}
			metrics := ProfileToExportableMetrics(profile)

			if metrics.Assessment != string(a) {
				t.Errorf("expected assessment %s, got %s", a, metrics.Assessment)
			}
		}
	})
}

// =============================================================================
// Clamp64 Tests
// =============================================================================

func TestClamp64(t *testing.T) {
	tests := []struct {
		name     string
		value    int64
		min      int64
		max      int64
		expected int64
	}{
		{"in_range", 50, 0, 100, 50},
		{"at_min", 0, 0, 100, 0},
		{"at_max", 100, 0, 100, 100},
		{"below_min", -50, 0, 100, 0},
		{"above_max", 150, 0, 100, 100},
		{"negative_range", -50, -100, -10, -50},
		{"zero_range", 50, 50, 50, 50},
		{"large_values", 1000000000000, 0, 2147483647, 2147483647},
		{"min_int64", math.MinInt64, 0, 100, 0},
		{"max_int64", math.MaxInt64, 0, 2147483647, 2147483647},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := clamp64(tt.value, tt.min, tt.max)
			if result != tt.expected {
				t.Errorf("clamp64(%d, %d, %d) = %d, want %d",
					tt.value, tt.min, tt.max, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Aggregation Across Checkpoints Tests
// =============================================================================

func TestAggregationAcrossCheckpoints(t *testing.T) {
	gen := NewTestDataGenerator(42)

	t.Run("multiple_files", func(t *testing.T) {
		// Generate checkpoints for multiple files
		now := time.Now()
		var allCheckpoints []CheckpointData

		// File 1
		for i := 0; i < 10; i++ {
			allCheckpoints = append(allCheckpoints, CheckpointData{
				Ordinal:     uint64(i),
				Timestamp:   now.Add(time.Duration(i) * time.Minute),
				ContentSize: int64(100 + i*20),
				FilePath:    "/doc1.txt",
			})
		}

		// File 2
		for i := 0; i < 10; i++ {
			allCheckpoints = append(allCheckpoints, CheckpointData{
				Ordinal:     uint64(10 + i),
				Timestamp:   now.Add(time.Duration(5+i) * time.Minute),
				ContentSize: int64(200 + i*30),
				FilePath:    "/doc2.txt",
			})
		}

		// Analyze combined
		profile, err := AnalyzeCheckpoints(allCheckpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if profile.EventCount != 20 {
			t.Errorf("expected 20 events, got %d", profile.EventCount)
		}
	})

	t.Run("aggregation_metrics", func(t *testing.T) {
		checkpoints := gen.GenerateCheckpoints(50, time.Now())

		profile, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Metrics should be computed
		m := profile.Metrics

		// Verify metrics are in valid ranges
		if m.MedianInterval < 0 {
			t.Error("median interval should be non-negative")
		}
		if m.PositiveNegativeRatio < 0 || m.PositiveNegativeRatio > 1 {
			t.Errorf("pos/neg ratio out of range: %v", m.PositiveNegativeRatio)
		}
	})
}

// =============================================================================
// Timeline Reconstruction Tests
// =============================================================================

func TestTimelineReconstruction(t *testing.T) {
	now := time.Now()

	t.Run("out_of_order_reconstruction", func(t *testing.T) {
		// Checkpoints in random order
		checkpoints := []CheckpointData{
			{Ordinal: 3, Timestamp: now.Add(3 * time.Minute), ContentSize: 300},
			{Ordinal: 0, Timestamp: now, ContentSize: 100},
			{Ordinal: 4, Timestamp: now.Add(4 * time.Minute), ContentSize: 400},
			{Ordinal: 1, Timestamp: now.Add(1 * time.Minute), ContentSize: 150},
			{Ordinal: 2, Timestamp: now.Add(2 * time.Minute), ContentSize: 200},
		}

		profile, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Timeline should be correctly reconstructed
		expectedSpan := 4 * time.Minute
		if math.Abs(float64(profile.TimeSpan-expectedSpan)) > float64(time.Second) {
			t.Errorf("expected span ~4min, got %v", profile.TimeSpan)
		}

		// First and last events should be correct
		expectedFirst := now.Truncate(time.Second)
		actualFirst := profile.FirstEvent.Truncate(time.Second)
		if !expectedFirst.Equal(actualFirst) {
			t.Errorf("first event mismatch: expected %v, got %v", expectedFirst, actualFirst)
		}
	})

	t.Run("session_detection", func(t *testing.T) {
		// Checkpoints with clear session gap
		checkpoints := []CheckpointData{
			{Ordinal: 0, Timestamp: now},
			{Ordinal: 1, Timestamp: now.Add(5 * time.Minute)},
			{Ordinal: 2, Timestamp: now.Add(10 * time.Minute)},
			// 2 hour gap
			{Ordinal: 3, Timestamp: now.Add(130 * time.Minute)},
			{Ordinal: 4, Timestamp: now.Add(135 * time.Minute)},
		}

		profile, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if profile.SessionCount != 2 {
			t.Errorf("expected 2 sessions, got %d", profile.SessionCount)
		}
	})
}

// =============================================================================
// CheckpointData Hash Tests
// =============================================================================

func TestCheckpointDataHashes(t *testing.T) {
	t.Run("hash_chain", func(t *testing.T) {
		now := time.Now()
		var prev [32]byte

		checkpoints := make([]CheckpointData, 5)
		for i := 0; i < 5; i++ {
			var content [32]byte
			for j := 0; j < 32; j++ {
				content[j] = byte(i * 32 + j)
			}

			checkpoints[i] = CheckpointData{
				Ordinal:      uint64(i),
				Timestamp:    now.Add(time.Duration(i) * time.Minute),
				ContentSize:  int64(100 * (i + 1)),
				ContentHash:  content,
				PreviousHash: prev,
			}

			prev = content
		}

		// Verify chain integrity
		for i := 1; i < len(checkpoints); i++ {
			if checkpoints[i].PreviousHash != checkpoints[i-1].ContentHash {
				t.Errorf("hash chain broken at index %d", i)
			}
		}

		// Analysis should still work with hashes
		_, err := AnalyzeCheckpoints(checkpoints)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// =============================================================================
// ExportableMetrics JSON Structure Tests
// =============================================================================

func TestExportableMetricsJSONTags(t *testing.T) {
	// Verify JSON field names match expected schema
	metrics := &ExportableMetrics{
		MonotonicAppendRatio:  0.5,
		EditEntropy:           2.0,
		MedianInterval:        100.0,
		PositiveNegativeRatio: 0.7,
		DeletionClustering:    0.8,
		Assessment:            "CONSISTENT",
		AnomalyCount:          3,
	}

	// The struct tags define the JSON field names
	// This test documents the expected schema
	expectedFields := map[string]interface{}{
		"monotonic_append_ratio":   0.5,
		"edit_entropy":             2.0,
		"median_interval_seconds":  100.0,
		"positive_negative_ratio":  0.7,
		"deletion_clustering":      0.8,
		"assessment":               "CONSISTENT",
		"anomaly_count":            3,
	}

	_ = expectedFields
	_ = metrics

	// The actual JSON serialization is tested in report_test.go
}
