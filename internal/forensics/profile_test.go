package forensics

import (
	"math"
	"testing"
	"time"
)

// =============================================================================
// BuildProfile Tests
// =============================================================================

func TestBuildProfileComprehensive(t *testing.T) {
	gen := NewTestDataGenerator(42)

	t.Run("insufficient_events", func(t *testing.T) {
		events := make([]EventData, MinEventsForAnalysis-1)
		for i := range events {
			events[i] = EventData{ID: int64(i + 1), TimestampNs: int64(i) * 1e9}
		}

		profile, err := BuildProfile(events, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if profile.Assessment != AssessmentInsufficient {
			t.Errorf("expected insufficient assessment, got %v", profile.Assessment)
		}
		if profile.EventCount != len(events) {
			t.Errorf("event count mismatch: %d vs %d", profile.EventCount, len(events))
		}
	})

	t.Run("empty_regions", func(t *testing.T) {
		events := gen.GenerateEvents(20, time.Now(), 500, 0.2)

		profile, err := BuildProfile(events, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should handle missing regions gracefully
		if profile.Assessment == "" {
			t.Error("assessment should not be empty")
		}
	})

	t.Run("complete_data", func(t *testing.T) {
		author := PredefinedAuthors()[0] // slow_thoughtful
		events, regions := gen.GenerateAuthorData(author, 50)

		profile, err := BuildProfile(events, regions)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify all fields populated
		if profile.EventCount != 50 {
			t.Errorf("expected 50 events, got %d", profile.EventCount)
		}
		if profile.FilePath == "" {
			t.Error("file path should be set")
		}
		if profile.SessionCount < 1 {
			t.Error("should have at least one session")
		}
		if profile.TimeSpan <= 0 {
			t.Error("time span should be positive")
		}
		if profile.FirstEvent.IsZero() {
			t.Error("first event should be set")
		}
		if profile.LastEvent.IsZero() {
			t.Error("last event should be set")
		}
	})

	t.Run("timeline_reconstruction", func(t *testing.T) {
		// Events intentionally out of order
		base := time.Now()
		events := []EventData{
			{ID: 3, TimestampNs: base.Add(2 * time.Second).UnixNano()},
			{ID: 1, TimestampNs: base.UnixNano()},
			{ID: 5, TimestampNs: base.Add(4 * time.Second).UnixNano()},
			{ID: 2, TimestampNs: base.Add(1 * time.Second).UnixNano()},
			{ID: 4, TimestampNs: base.Add(3 * time.Second).UnixNano()},
		}
		regions := map[int64][]RegionData{
			1: {{DeltaSign: 1}}, 2: {{DeltaSign: 1}}, 3: {{DeltaSign: 1}},
			4: {{DeltaSign: 1}}, 5: {{DeltaSign: 1}},
		}

		profile, err := BuildProfile(events, regions)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check timeline is reconstructed correctly
		expectedSpan := 4 * time.Second
		if math.Abs(float64(profile.TimeSpan-expectedSpan)) > float64(time.Millisecond) {
			t.Errorf("time span should be ~4s, got %v", profile.TimeSpan)
		}
	})
}

func TestBuildProfileMetricsIntegrity(t *testing.T) {
	gen := NewTestDataGenerator(42)
	events, regions := gen.GenerateAuthorData(PredefinedAuthors()[1], 100) // fast_typist

	profile, err := BuildProfile(events, regions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify metrics are in valid ranges
	m := profile.Metrics

	if m.MonotonicAppendRatio < 0 || m.MonotonicAppendRatio > 1 {
		t.Errorf("monotonic append ratio out of range: %v", m.MonotonicAppendRatio)
	}
	if m.EditEntropy < 0 {
		t.Errorf("edit entropy should be non-negative: %v", m.EditEntropy)
	}
	if m.MedianInterval < 0 {
		t.Errorf("median interval should be non-negative: %v", m.MedianInterval)
	}
	if m.PositiveNegativeRatio < 0 || m.PositiveNegativeRatio > 1 {
		t.Errorf("positive/negative ratio out of range: %v", m.PositiveNegativeRatio)
	}
	if m.DeletionClustering < 0 {
		t.Errorf("deletion clustering should be non-negative: %v", m.DeletionClustering)
	}
}

// =============================================================================
// DetectSessions Tests
// =============================================================================

func TestDetectSessionsComprehensive(t *testing.T) {
	tests := []struct {
		name             string
		events           []EventData
		gapThresholdSec  float64
		expectedSessions int
	}{
		{
			name:             "nil events",
			events:           nil,
			gapThresholdSec:  1800,
			expectedSessions: 0,
		},
		{
			name:             "empty events",
			events:           []EventData{},
			gapThresholdSec:  1800,
			expectedSessions: 0,
		},
		{
			name: "single event",
			events: []EventData{
				{TimestampNs: 0},
			},
			gapThresholdSec:  1800,
			expectedSessions: 1,
		},
		{
			name: "continuous session",
			events: []EventData{
				{TimestampNs: 0},
				{TimestampNs: 60_000_000_000},   // 1 min
				{TimestampNs: 120_000_000_000},  // 2 min
				{TimestampNs: 180_000_000_000},  // 3 min
			},
			gapThresholdSec:  1800, // 30 min threshold
			expectedSessions: 1,
		},
		{
			name: "two sessions with gap",
			events: []EventData{
				{TimestampNs: 0},
				{TimestampNs: 60_000_000_000},    // 1 min
				{TimestampNs: 2000_000_000_000},  // 33+ min gap
				{TimestampNs: 2060_000_000_000},  // 1 min later
			},
			gapThresholdSec:  1800,
			expectedSessions: 2,
		},
		{
			name: "custom threshold - short gaps",
			events: []EventData{
				{TimestampNs: 0},
				{TimestampNs: 5_000_000_000},   // 5 sec
				{TimestampNs: 15_000_000_000},  // 10 sec gap (exceeds 5s threshold)
				{TimestampNs: 20_000_000_000},  // 5 sec later
			},
			gapThresholdSec:  5.0, // 5 second threshold
			expectedSessions: 2,
		},
		{
			name: "many sessions",
			events: []EventData{
				{TimestampNs: 0},
				{TimestampNs: 1800_000_000_001},  // Just over 30 min
				{TimestampNs: 3600_000_000_002},  // Another 30+ min
				{TimestampNs: 5400_000_000_003},  // Another 30+ min
			},
			gapThresholdSec:  1800,
			expectedSessions: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions := DetectSessions(tt.events, tt.gapThresholdSec)

			actualCount := 0
			if sessions != nil {
				actualCount = len(sessions)
			}

			if actualCount != tt.expectedSessions {
				t.Errorf("expected %d sessions, got %d", tt.expectedSessions, actualCount)
			}
		})
	}
}

func TestDetectSessionsPreservesOrder(t *testing.T) {
	// Events out of order
	events := []EventData{
		{ID: 3, TimestampNs: 300_000_000_000},
		{ID: 1, TimestampNs: 100_000_000_000},
		{ID: 2, TimestampNs: 200_000_000_000},
	}

	sessions := DetectSessions(events, 1800)

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}

	// Events within session should be sorted by timestamp
	session := sessions[0]
	for i := 1; i < len(session); i++ {
		if session[i].TimestampNs < session[i-1].TimestampNs {
			t.Error("session events should be sorted by timestamp")
		}
	}
}

func TestDetectSessionsEventCounts(t *testing.T) {
	gen := NewTestDataGenerator(42)

	// Generate events with a clear gap
	events := gen.GenerateEventsWithGap(10, 15, time.Now(), 2*time.Hour)

	sessions := DetectSessions(events, DefaultSessionGapSec)

	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	if len(sessions[0]) != 10 {
		t.Errorf("first session should have 10 events, got %d", len(sessions[0]))
	}
	if len(sessions[1]) != 15 {
		t.Errorf("second session should have 15 events, got %d", len(sessions[1]))
	}
}

// =============================================================================
// DetectAnomalies Tests
// =============================================================================

func TestDetectAnomaliesComprehensive(t *testing.T) {
	tests := []struct {
		name          string
		metrics       *PrimaryMetrics
		expectedTypes []AnomalyType
	}{
		{
			name:          "nil metrics",
			metrics:       nil,
			expectedTypes: nil,
		},
		{
			name: "all normal",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio: 0.4,
				EditEntropy:          2.5,
			},
			expectedTypes: nil,
		},
		{
			name: "high monotonic",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio: 0.9,
				EditEntropy:          2.5,
			},
			expectedTypes: []AnomalyType{AnomalyMonotonic},
		},
		{
			name: "low entropy",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio: 0.4,
				EditEntropy:          1.0,
			},
			expectedTypes: []AnomalyType{AnomalyLowEntropy},
		},
		{
			name: "both anomalies",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio: 0.9,
				EditEntropy:          1.0,
			},
			expectedTypes: []AnomalyType{AnomalyMonotonic, AnomalyLowEntropy},
		},
		{
			name: "zero entropy is not flagged",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio: 0.4,
				EditEntropy:          0, // Zero is not low (insufficient data)
			},
			expectedTypes: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := makeEvents(0, 1e9, 2e9)
			anomalies := DetectAnomalies(events, nil, tt.metrics)

			// Verify expected anomaly types
			foundTypes := make(map[AnomalyType]bool)
			for _, a := range anomalies {
				foundTypes[a.Type] = true
			}

			for _, expected := range tt.expectedTypes {
				if !foundTypes[expected] {
					t.Errorf("expected anomaly type %v not found", expected)
				}
			}

			// Verify no unexpected metric-based anomalies
			if tt.expectedTypes == nil && len(anomalies) > 0 {
				// Filter out temporal anomalies which are separate
				metricAnomalies := 0
				for _, a := range anomalies {
					if a.Type == AnomalyMonotonic || a.Type == AnomalyLowEntropy {
						metricAnomalies++
					}
				}
				if metricAnomalies > 0 {
					t.Errorf("expected no metric anomalies, got %d", metricAnomalies)
				}
			}
		})
	}
}

func TestDetectAnomaliesSeverity(t *testing.T) {
	metrics := &PrimaryMetrics{
		MonotonicAppendRatio: 0.95,
		EditEntropy:          0.5,
	}

	anomalies := DetectAnomalies(nil, nil, metrics)

	// All metric-based anomalies should be warnings
	for _, a := range anomalies {
		if a.Type == AnomalyMonotonic || a.Type == AnomalyLowEntropy {
			if a.Severity != SeverityWarning {
				t.Errorf("metric anomaly %v should be warning, got %v", a.Type, a.Severity)
			}
		}
	}
}

// =============================================================================
// DetectTemporalAnomalies Tests
// =============================================================================

func TestDetectTemporalAnomaliesGaps(t *testing.T) {
	tests := []struct {
		name        string
		gapHours    float64
		expectGap   bool
	}{
		{"no gap - 12 hours", 12, false},
		{"borderline - 24 hours", 24, false}, // Equal to threshold, not exceeded
		{"gap detected - 25 hours", 25, true},
		{"large gap - 72 hours", 72, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gapNs := int64(tt.gapHours * 3600 * 1e9)
			events := []EventData{
				{TimestampNs: 0, SizeDelta: 10},
				{TimestampNs: gapNs, SizeDelta: 10},
			}

			anomalies := detectTemporalAnomalies(events, nil)

			foundGap := false
			for _, a := range anomalies {
				if a.Type == AnomalyGap {
					foundGap = true
					break
				}
			}

			if foundGap != tt.expectGap {
				t.Errorf("gap detection: expected %v, got %v", tt.expectGap, foundGap)
			}
		})
	}
}

func TestDetectTemporalAnomaliesHighVelocity(t *testing.T) {
	tests := []struct {
		name           string
		intervalSec    float64
		sizeDelta      int32
		expectVelocity bool
	}{
		{"slow typing", 10.0, 50, false},                // 5 bps
		{"normal typing", 1.0, 50, false},               // 50 bps
		{"fast typing", 1.0, 100, false},                // 100 bps (at threshold)
		{"high velocity", 1.0, 150, true},               // 150 bps
		{"extreme velocity", 0.5, 200, true},            // 400 bps
		{"very long interval", 120.0, 500, false},       // Intervals > 60s excluded
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intervalNs := int64(tt.intervalSec * 1e9)
			events := []EventData{
				{TimestampNs: 0, SizeDelta: 0},
				{TimestampNs: intervalNs, SizeDelta: tt.sizeDelta},
			}

			anomalies := detectTemporalAnomalies(events, nil)

			foundVelocity := false
			for _, a := range anomalies {
				if a.Type == AnomalyHighVelocity {
					foundVelocity = true
					break
				}
			}

			if foundVelocity != tt.expectVelocity {
				bps := float64(tt.sizeDelta) / tt.intervalSec
				t.Errorf("velocity detection at %.0f bps: expected %v, got %v",
					bps, tt.expectVelocity, foundVelocity)
			}
		})
	}
}

func TestDetectTemporalAnomaliesEdgeCases(t *testing.T) {
	t.Run("empty events", func(t *testing.T) {
		anomalies := detectTemporalAnomalies(nil, nil)
		if len(anomalies) != 0 {
			t.Errorf("expected no anomalies, got %d", len(anomalies))
		}
	})

	t.Run("single event", func(t *testing.T) {
		events := []EventData{{TimestampNs: 0}}
		anomalies := detectTemporalAnomalies(events, nil)
		if len(anomalies) != 0 {
			t.Errorf("expected no anomalies with single event, got %d", len(anomalies))
		}
	})

	t.Run("zero interval", func(t *testing.T) {
		events := []EventData{
			{TimestampNs: 0, SizeDelta: 100},
			{TimestampNs: 0, SizeDelta: 100}, // Same timestamp
		}
		anomalies := detectTemporalAnomalies(events, nil)
		// Should not panic, zero interval skipped
		if len(anomalies) > 0 {
			t.Log("zero interval handled gracefully")
		}
	})

	t.Run("negative delta", func(t *testing.T) {
		events := []EventData{
			{TimestampNs: 0, SizeDelta: 0},
			{TimestampNs: 1_000_000_000, SizeDelta: -200}, // Deletion at 200 bps
		}
		anomalies := detectTemporalAnomalies(events, nil)
		// Negative deltas should use absolute value
		foundVelocity := false
		for _, a := range anomalies {
			if a.Type == AnomalyHighVelocity {
				foundVelocity = true
			}
		}
		if !foundVelocity {
			t.Error("high velocity from deletions should be detected")
		}
	})
}

// =============================================================================
// DetermineAssessment Tests
// =============================================================================

func TestDetermineAssessmentComprehensive(t *testing.T) {
	tests := []struct {
		name       string
		metrics    *PrimaryMetrics
		anomalies  []Anomaly
		eventCount int
		expected   Assessment
	}{
		{
			name:       "insufficient events",
			metrics:    &PrimaryMetrics{},
			anomalies:  nil,
			eventCount: MinEventsForAssessment - 1,
			expected:   AssessmentInsufficient,
		},
		{
			name:       "nil metrics",
			metrics:    nil,
			anomalies:  nil,
			eventCount: 50,
			expected:   AssessmentInsufficient,
		},
		{
			name: "consistent - all normal",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio:  0.4,
				EditEntropy:           2.5,
				PositiveNegativeRatio: 0.7,
				DeletionClustering:    0.5,
			},
			anomalies:  nil,
			eventCount: 50,
			expected:   AssessmentConsistent,
		},
		{
			name: "suspicious - high monotonic + low entropy",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio:  0.95,
				EditEntropy:           0.5,
				PositiveNegativeRatio: 0.7,
				DeletionClustering:    0.5,
			},
			anomalies:  nil,
			eventCount: 50,
			expected:   AssessmentSuspicious,
		},
		{
			name: "suspicious - three indicators",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio:  0.92, // > 0.90
				EditEntropy:           0.8,  // < 1.0
				PositiveNegativeRatio: 0.96, // > 0.95
				DeletionClustering:    0.5,
			},
			anomalies:  nil,
			eventCount: 50,
			expected:   AssessmentSuspicious,
		},
		{
			name: "suspicious - many alerts",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio: 0.5,
				EditEntropy:          2.5,
			},
			anomalies: []Anomaly{
				{Severity: SeverityAlert},
				{Severity: SeverityAlert},
			},
			eventCount: 50,
			expected:   AssessmentSuspicious,
		},
		{
			name: "suspicious - many warnings",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio: 0.5,
				EditEntropy:          2.5,
			},
			anomalies: []Anomaly{
				{Severity: SeverityWarning},
				{Severity: SeverityWarning},
				{Severity: SeverityWarning},
			},
			eventCount: 50,
			expected:   AssessmentSuspicious,
		},
		{
			name: "consistent despite one indicator",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio:  0.92, // > 0.90 (one indicator)
				EditEntropy:           2.5,  // Normal
				PositiveNegativeRatio: 0.7,  // Normal
				DeletionClustering:    0.5,  // Normal
			},
			anomalies:  nil,
			eventCount: 50,
			expected:   AssessmentConsistent,
		},
		{
			name: "deletion clustering suspicious range",
			metrics: &PrimaryMetrics{
				MonotonicAppendRatio:  0.92,
				EditEntropy:           0.8,
				PositiveNegativeRatio: 0.7,
				DeletionClustering:    1.0, // In suspicious range (0.9-1.1)
			},
			anomalies:  nil,
			eventCount: 50,
			expected:   AssessmentSuspicious, // 3 indicators
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetermineAssessment(tt.metrics, tt.anomalies, tt.eventCount)
			if result != tt.expected {
				t.Errorf("DetermineAssessment() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetermineAssessmentThresholds(t *testing.T) {
	// Test exact threshold boundaries
	t.Run("event_count_boundary", func(t *testing.T) {
		metrics := &PrimaryMetrics{MonotonicAppendRatio: 0.5, EditEntropy: 2.5}

		// Exactly at threshold
		result := DetermineAssessment(metrics, nil, MinEventsForAssessment)
		if result == AssessmentInsufficient {
			t.Error("exactly at threshold should not be insufficient")
		}

		// One below threshold
		result = DetermineAssessment(metrics, nil, MinEventsForAssessment-1)
		if result != AssessmentInsufficient {
			t.Error("below threshold should be insufficient")
		}
	})

	t.Run("monotonic_boundary", func(t *testing.T) {
		// At 0.90 (not > 0.90)
		metrics := &PrimaryMetrics{
			MonotonicAppendRatio:  0.90,
			EditEntropy:           2.5,
			PositiveNegativeRatio: 0.7,
		}
		result := DetermineAssessment(metrics, nil, 50)
		if result == AssessmentSuspicious {
			t.Error("exactly at 0.90 should not count as suspicious indicator")
		}

		// At 0.901 (> 0.90)
		metrics.MonotonicAppendRatio = 0.901
		// Need more indicators for suspicious
	})
}

// =============================================================================
// Abs32 Tests
// =============================================================================

func TestAbs32Comprehensive(t *testing.T) {
	tests := []struct {
		input    int32
		expected int32
	}{
		{0, 0},
		{1, 1},
		{-1, 1},
		{100, 100},
		{-100, 100},
		{2147483647, 2147483647},     // MaxInt32
		{-2147483647, 2147483647},    // -MaxInt32
		{-2147483648, 2147483647},    // MinInt32 special case
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := abs32(tt.input)
			if result != tt.expected {
				t.Errorf("abs32(%d) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Authorship Profiling Tests
// =============================================================================

func TestAuthorProfileDiscrimination(t *testing.T) {
	gen := NewTestDataGenerator(42)
	authors := PredefinedAuthors()

	// Generate profiles for each author type
	type profileSummary struct {
		name        string
		appendRatio float64
		entropy     float64
		posNegRatio float64
		clustering  float64
	}

	summaries := make([]profileSummary, len(authors))

	for i, author := range authors {
		events, regions := gen.GenerateAuthorData(author, 200)
		profile, err := BuildProfile(events, regions)
		if err != nil {
			t.Fatalf("failed to build profile for %s: %v", author.Name, err)
		}

		summaries[i] = profileSummary{
			name:        author.Name,
			appendRatio: profile.Metrics.MonotonicAppendRatio,
			entropy:     profile.Metrics.EditEntropy,
			posNegRatio: profile.Metrics.PositiveNegativeRatio,
			clustering:  profile.Metrics.DeletionClustering,
		}

		t.Logf("%s: append=%.2f, entropy=%.2f, posNeg=%.2f, cluster=%.2f",
			author.Name, summaries[i].appendRatio, summaries[i].entropy,
			summaries[i].posNegRatio, summaries[i].clustering)
	}

	// Verify AI-like pattern is distinguishable
	aiIdx := -1
	for i, s := range summaries {
		if s.name == "ai_like" {
			aiIdx = i
			break
		}
	}

	if aiIdx >= 0 {
		ai := summaries[aiIdx]
		// AI should have high append ratio
		if ai.appendRatio < 0.7 {
			t.Errorf("AI-like pattern should have high append ratio, got %v", ai.appendRatio)
		}
		// AI should have high positive ratio (few deletions)
		if ai.posNegRatio < 0.9 {
			t.Errorf("AI-like pattern should have high pos/neg ratio, got %v", ai.posNegRatio)
		}
	}

	// Verify meticulous editor is different
	editorIdx := -1
	for i, s := range summaries {
		if s.name == "meticulous_editor" {
			editorIdx = i
			break
		}
	}

	if editorIdx >= 0 && aiIdx >= 0 {
		editor := summaries[editorIdx]
		ai := summaries[aiIdx]

		// Editor should have lower append ratio than AI
		if editor.appendRatio >= ai.appendRatio {
			t.Errorf("editor append ratio (%v) should be lower than AI (%v)",
				editor.appendRatio, ai.appendRatio)
		}
	}
}

func TestAuthorProfileMatching(t *testing.T) {
	gen := NewTestDataGenerator(42)

	// Generate baseline profile
	baseAuthor := AuthorProfile{
		Name:           "baseline",
		MeanIntervalMs: 200,
		IntervalStdDev: 50,
		EditRatio:      0.15,
		AppendRatio:    0.5,
	}

	baseEvents, baseRegions := gen.GenerateAuthorData(baseAuthor, 100)
	baseProfile, _ := BuildProfile(baseEvents, baseRegions)

	// Generate second sample from same author
	sameEvents, sameRegions := gen.GenerateAuthorData(baseAuthor, 100)
	sameProfile, _ := BuildProfile(sameEvents, sameRegions)

	// Generate sample from different author
	diffAuthor := AuthorProfile{
		Name:           "different",
		MeanIntervalMs: 500, // Much slower
		IntervalStdDev: 100,
		EditRatio:      0.05, // Fewer deletions
		AppendRatio:    0.9,  // More sequential
	}
	diffEvents, diffRegions := gen.GenerateAuthorData(diffAuthor, 100)
	diffProfile, _ := BuildProfile(diffEvents, diffRegions)

	// Calculate profile similarity
	sameSimilarity := calculateProfileSimilarity(baseProfile, sameProfile)
	diffSimilarity := calculateProfileSimilarity(baseProfile, diffProfile)

	// Same author should be more similar
	if sameSimilarity < diffSimilarity {
		t.Errorf("same author similarity (%v) should exceed different author (%v)",
			sameSimilarity, diffSimilarity)
	}
}

// calculateProfileSimilarity computes similarity between two profiles (0-1).
func calculateProfileSimilarity(p1, p2 *AuthorshipProfile) float64 {
	if p1 == nil || p2 == nil {
		return 0
	}

	// Compare each metric, weighted
	m1, m2 := p1.Metrics, p2.Metrics

	diffs := []float64{
		math.Abs(m1.MonotonicAppendRatio - m2.MonotonicAppendRatio),
		math.Abs(m1.EditEntropy-m2.EditEntropy) / 4.0, // Normalize (max ~4)
		math.Abs(m1.PositiveNegativeRatio - m2.PositiveNegativeRatio),
		math.Abs(m1.DeletionClustering-m2.DeletionClustering) / 2.0, // Normalize
	}

	totalDiff := 0.0
	for _, d := range diffs {
		totalDiff += d
	}

	// Convert to similarity (0-1)
	avgDiff := totalDiff / float64(len(diffs))
	return 1.0 - math.Min(avgDiff, 1.0)
}

// =============================================================================
// Threshold Calibration Tests
// =============================================================================

func TestThresholdCalibration(t *testing.T) {
	// Verify default thresholds are reasonable
	t.Run("monotonic_threshold", func(t *testing.T) {
		if ThresholdMonotonicAppend < 0.7 || ThresholdMonotonicAppend > 0.95 {
			t.Errorf("monotonic threshold %v seems unreasonable", ThresholdMonotonicAppend)
		}
	})

	t.Run("entropy_threshold", func(t *testing.T) {
		if ThresholdLowEntropy < 1.0 || ThresholdLowEntropy > 2.0 {
			t.Errorf("entropy threshold %v seems unreasonable", ThresholdLowEntropy)
		}
	})

	t.Run("velocity_threshold", func(t *testing.T) {
		// 100 bytes/sec is about 20 words per minute
		if ThresholdHighVelocityBps < 80 || ThresholdHighVelocityBps > 200 {
			t.Errorf("velocity threshold %v bps seems unreasonable", ThresholdHighVelocityBps)
		}
	})

	t.Run("gap_threshold", func(t *testing.T) {
		if ThresholdGapHours < 12 || ThresholdGapHours > 48 {
			t.Errorf("gap threshold %v hours seems unreasonable", ThresholdGapHours)
		}
	})
}

// =============================================================================
// Real-World-Like Data Tests
// =============================================================================

func TestRealWorldDataPatterns(t *testing.T) {
	gen := NewTestDataGenerator(42)

	t.Run("writing_session", func(t *testing.T) {
		// Simulate a writing session: start slow, speed up, then slow for review
		events := []EventData{}
		base := time.Now()
		current := base

		// Warm-up phase (slow)
		for i := 0; i < 10; i++ {
			events = append(events, EventData{
				ID:          int64(len(events) + 1),
				TimestampNs: current.UnixNano(),
				SizeDelta:   30,
				FilePath:    "/doc.txt",
			})
			current = current.Add(time.Duration(300+gen.rng.Intn(200)) * time.Millisecond)
		}

		// Flow state (fast)
		for i := 0; i < 50; i++ {
			events = append(events, EventData{
				ID:          int64(len(events) + 1),
				TimestampNs: current.UnixNano(),
				SizeDelta:   int32(20 + gen.rng.Intn(30)),
				FilePath:    "/doc.txt",
			})
			current = current.Add(time.Duration(80+gen.rng.Intn(60)) * time.Millisecond)
		}

		// Review phase (mixed, with deletions)
		for i := 0; i < 20; i++ {
			delta := int32(gen.rng.Intn(40) - 20) // -20 to +20
			events = append(events, EventData{
				ID:          int64(len(events) + 1),
				TimestampNs: current.UnixNano(),
				SizeDelta:   delta,
				FilePath:    "/doc.txt",
			})
			current = current.Add(time.Duration(200+gen.rng.Intn(300)) * time.Millisecond)
		}

		// Generate regions
		regions := make(map[int64][]RegionData)
		for _, e := range events {
			deltaSign := int8(1)
			if e.SizeDelta < 0 {
				deltaSign = -1
			}
			pos := gen.rng.Float32()
			regions[e.ID] = []RegionData{{
				StartPct:  pos,
				DeltaSign: deltaSign,
				ByteCount: abs32(e.SizeDelta),
			}}
		}

		profile, err := BuildProfile(events, regions)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should be consistent with human authorship
		if profile.Assessment != AssessmentConsistent {
			t.Errorf("writing session should be consistent, got %v", profile.Assessment)
		}
	})

	t.Run("paste_heavy_document", func(t *testing.T) {
		// Simulate document built with lots of pasting
		events := []EventData{}
		base := time.Now()
		current := base

		for i := 0; i < 30; i++ {
			// Occasional very large "paste"
			delta := int32(20 + gen.rng.Intn(30))
			if i%5 == 0 {
				delta = int32(500 + gen.rng.Intn(500)) // Large paste
			}

			events = append(events, EventData{
				ID:          int64(len(events) + 1),
				TimestampNs: current.UnixNano(),
				SizeDelta:   delta,
				FilePath:    "/doc.txt",
			})
			current = current.Add(time.Duration(1+gen.rng.Intn(5)) * time.Second)
		}

		regions := make(map[int64][]RegionData)
		for _, e := range events {
			// Pastes tend to be at end of document
			pos := float32(0.9 + gen.rng.Float32()*0.1)
			regions[e.ID] = []RegionData{{
				StartPct:  pos,
				DeltaSign: 1,
				ByteCount: e.SizeDelta,
			}}
		}

		profile, err := BuildProfile(events, regions)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// May show some suspicious patterns
		t.Logf("paste-heavy: assessment=%v, append=%.2f, entropy=%.2f",
			profile.Assessment, profile.Metrics.MonotonicAppendRatio, profile.Metrics.EditEntropy)
	})
}
