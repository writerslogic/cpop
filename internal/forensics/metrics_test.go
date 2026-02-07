package forensics

import (
	"math"
	"sort"
	"testing"
	"time"
)

// =============================================================================
// Statistical Calculation Tests
// =============================================================================

func TestMedian(t *testing.T) {
	tests := []struct {
		name     string
		values   []float64
		expected float64
	}{
		{
			name:     "empty slice",
			values:   []float64{},
			expected: 0,
		},
		{
			name:     "single value",
			values:   []float64{5.0},
			expected: 5.0,
		},
		{
			name:     "two values",
			values:   []float64{1.0, 3.0},
			expected: 2.0, // Average of 1 and 3
		},
		{
			name:     "odd count",
			values:   []float64{1.0, 2.0, 3.0},
			expected: 2.0,
		},
		{
			name:     "even count",
			values:   []float64{1.0, 2.0, 3.0, 4.0},
			expected: 2.5, // Average of 2 and 3
		},
		{
			name:     "unsorted input",
			values:   []float64{5.0, 1.0, 3.0, 2.0, 4.0},
			expected: 3.0,
		},
		{
			name:     "negative values",
			values:   []float64{-5.0, -1.0, 0.0, 1.0, 5.0},
			expected: 0.0,
		},
		{
			name:     "all same values",
			values:   []float64{7.0, 7.0, 7.0, 7.0},
			expected: 7.0,
		},
		{
			name:     "large range",
			values:   []float64{0.001, 1000000.0},
			expected: 500000.0005,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := median(tt.values)
			if !IsApproximatelyEqual(result, tt.expected, 0.0001) {
				t.Errorf("median(%v) = %v, want %v", tt.values, result, tt.expected)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name        string
		histogram   []int
		expectedMin float64
		expectedMax float64
	}{
		{
			name:        "empty histogram",
			histogram:   []int{},
			expectedMin: 0,
			expectedMax: 0,
		},
		{
			name:        "all zeros",
			histogram:   []int{0, 0, 0, 0},
			expectedMin: 0,
			expectedMax: 0,
		},
		{
			name:        "single bin with count",
			histogram:   []int{10, 0, 0, 0},
			expectedMin: 0,
			expectedMax: 0,
		},
		{
			name:        "uniform distribution - 2 bins",
			histogram:   []int{50, 50},
			expectedMin: 0.99,
			expectedMax: 1.01, // log2(2) = 1
		},
		{
			name:        "uniform distribution - 4 bins",
			histogram:   []int{25, 25, 25, 25},
			expectedMin: 1.99,
			expectedMax: 2.01, // log2(4) = 2
		},
		{
			name:        "uniform distribution - 8 bins",
			histogram:   []int{10, 10, 10, 10, 10, 10, 10, 10},
			expectedMin: 2.99,
			expectedMax: 3.01, // log2(8) = 3
		},
		{
			name:        "skewed distribution",
			histogram:   []int{90, 5, 3, 2},
			expectedMin: 0,
			expectedMax: 1.5, // Low entropy
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shannonEntropy(tt.histogram)
			if result < tt.expectedMin || result > tt.expectedMax {
				t.Errorf("shannonEntropy(%v) = %v, want between %v and %v",
					tt.histogram, result, tt.expectedMin, tt.expectedMax)
			}
		})
	}
}

func TestShannonEntropyProperties(t *testing.T) {
	// Property: Entropy is non-negative
	t.Run("non-negative", func(t *testing.T) {
		gen := NewTestDataGenerator(42)
		for i := 0; i < 100; i++ {
			size := gen.rng.Intn(50) + 1
			histogram := make([]int, size)
			for j := 0; j < size; j++ {
				histogram[j] = gen.rng.Intn(100)
			}
			result := shannonEntropy(histogram)
			if result < 0 {
				t.Errorf("entropy should be non-negative, got %v for %v", result, histogram)
			}
		}
	})

	// Property: Maximum entropy is log2(n) for n bins
	t.Run("max_entropy_bound", func(t *testing.T) {
		for n := 2; n <= 32; n++ {
			histogram := make([]int, n)
			for j := 0; j < n; j++ {
				histogram[j] = 100 // Uniform
			}
			result := shannonEntropy(histogram)
			maxEntropy := math.Log2(float64(n))
			if !IsApproximatelyEqual(result, maxEntropy, 0.001) {
				t.Errorf("uniform distribution with %d bins: entropy = %v, expected %v",
					n, result, maxEntropy)
			}
		}
	})

	// Property: Adding to a single bin doesn't increase entropy
	t.Run("single_bin_dominance", func(t *testing.T) {
		histogram := []int{1, 1, 1, 1}
		baseEntropy := shannonEntropy(histogram)

		histogram[0] = 1000 // Dominate first bin
		newEntropy := shannonEntropy(histogram)

		if newEntropy >= baseEntropy {
			t.Errorf("concentrating in one bin should reduce entropy: %v -> %v",
				baseEntropy, newEntropy)
		}
	})
}

// =============================================================================
// MonotonicAppendRatio Tests
// =============================================================================

func TestMonotonicAppendRatioComprehensive(t *testing.T) {
	tests := []struct {
		name      string
		regions   []RegionData
		threshold float32
		expected  float64
	}{
		{
			name:      "nil regions",
			regions:   nil,
			threshold: 0.95,
			expected:  0,
		},
		{
			name:      "empty regions",
			regions:   []RegionData{},
			threshold: 0.95,
			expected:  0,
		},
		{
			name: "exactly at threshold",
			regions: []RegionData{
				{StartPct: 0.95},
			},
			threshold: 0.95,
			expected:  1.0,
		},
		{
			name: "just below threshold",
			regions: []RegionData{
				{StartPct: 0.9499},
			},
			threshold: 0.95,
			expected:  0,
		},
		{
			name: "boundary values",
			regions: []RegionData{
				{StartPct: 0.0},
				{StartPct: 0.5},
				{StartPct: 0.95},
				{StartPct: 0.99},
				{StartPct: 1.0}, // Should count as append
			},
			threshold: 0.95,
			expected:  0.6, // 3 out of 5
		},
		{
			name:      "custom threshold 0.5",
			regions:   []RegionData{{StartPct: 0.4}, {StartPct: 0.6}},
			threshold: 0.5,
			expected:  0.5, // 1 out of 2
		},
		{
			name:      "custom threshold 0.0",
			regions:   []RegionData{{StartPct: 0.0}, {StartPct: 0.5}},
			threshold: 0.0,
			expected:  1.0, // All positions >= 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MonotonicAppendRatio(tt.regions, tt.threshold)
			if !IsApproximatelyEqual(result, tt.expected, 0.0001) {
				t.Errorf("MonotonicAppendRatio() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMonotonicAppendRatioAIPattern(t *testing.T) {
	gen := NewTestDataGenerator(42)
	regions := gen.GenerateAppendOnlyRegions(100, 0.95)

	ratio := MonotonicAppendRatio(regions, 0.95)

	// AI-like pattern should have very high append ratio
	if ratio < 0.9 {
		t.Errorf("append-only pattern should have ratio > 0.9, got %v", ratio)
	}
}

func TestMonotonicAppendRatioHumanPattern(t *testing.T) {
	gen := NewTestDataGenerator(42)
	regions := gen.GenerateUniformRegions(100, 0.7) // Mix of insertions/deletions

	ratio := MonotonicAppendRatio(regions, 0.95)

	// Human editing should have moderate append ratio
	if ratio > 0.2 {
		t.Errorf("uniform distribution should have low append ratio (< 0.2), got %v", ratio)
	}
}

// =============================================================================
// EditEntropy Tests
// =============================================================================

func TestEditEntropyComprehensive(t *testing.T) {
	tests := []struct {
		name        string
		regions     []RegionData
		bins        int
		expectedMin float64
		expectedMax float64
	}{
		{
			name:        "nil regions",
			regions:     nil,
			bins:        20,
			expectedMin: 0,
			expectedMax: 0,
		},
		{
			name:        "negative bins",
			regions:     []RegionData{{StartPct: 0.5}},
			bins:        -1,
			expectedMin: 0,
			expectedMax: 0,
		},
		{
			name:        "single region",
			regions:     []RegionData{{StartPct: 0.5}},
			bins:        20,
			expectedMin: 0,
			expectedMax: 0, // Single region = zero entropy
		},
		{
			name: "all in same bin",
			regions: []RegionData{
				{StartPct: 0.51}, {StartPct: 0.52}, {StartPct: 0.53},
			},
			bins:        10,
			expectedMin: 0,
			expectedMax: 0.1,
		},
		{
			name:        "clamped negative position",
			regions:     []RegionData{{StartPct: -0.5}},
			bins:        10,
			expectedMin: 0,
			expectedMax: 0,
		},
		{
			name:        "clamped position >= 1",
			regions:     []RegionData{{StartPct: 1.5}},
			bins:        10,
			expectedMin: 0,
			expectedMax: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EditEntropy(tt.regions, tt.bins)
			if result < tt.expectedMin || result > tt.expectedMax {
				t.Errorf("EditEntropy() = %v, want between %v and %v",
					result, tt.expectedMin, tt.expectedMax)
			}
		})
	}
}

func TestEditEntropyDistributions(t *testing.T) {
	// Compare entropy of different distributions
	gen := NewTestDataGenerator(42)

	// Concentrated in one position
	concentrated := []RegionData{}
	for i := 0; i < 100; i++ {
		concentrated = append(concentrated, RegionData{StartPct: 0.5})
	}

	// Uniform distribution
	uniform := gen.GenerateUniformRegions(100, 0.5)

	// Bimodal distribution (beginning and end)
	bimodal := []RegionData{}
	for i := 0; i < 50; i++ {
		bimodal = append(bimodal, RegionData{StartPct: 0.1})
		bimodal = append(bimodal, RegionData{StartPct: 0.9})
	}

	entropyConcentrated := EditEntropy(concentrated, 20)
	entropyUniform := EditEntropy(uniform, 20)
	entropyBimodal := EditEntropy(bimodal, 20)

	// Verify ordering: concentrated < bimodal < uniform
	if entropyConcentrated >= entropyBimodal {
		t.Errorf("concentrated entropy (%v) should be less than bimodal (%v)",
			entropyConcentrated, entropyBimodal)
	}
	if entropyBimodal >= entropyUniform {
		t.Errorf("bimodal entropy (%v) should be less than uniform (%v)",
			entropyBimodal, entropyUniform)
	}
}

func TestEditEntropyBinBoundaries(t *testing.T) {
	// Test that bin assignment is correct at boundaries
	bins := 10

	// Each region at different bin boundaries
	regions := []RegionData{
		{StartPct: 0.0},   // Bin 0
		{StartPct: 0.099}, // Bin 0
		{StartPct: 0.1},   // Bin 1
		{StartPct: 0.199}, // Bin 1
		{StartPct: 0.5},   // Bin 5
		{StartPct: 0.999}, // Bin 9
	}

	entropy := EditEntropy(regions, bins)

	// Should have some entropy since regions span multiple bins
	if entropy <= 0 {
		t.Errorf("regions spanning multiple bins should have positive entropy, got %v", entropy)
	}
}

// =============================================================================
// MedianInterval Tests
// =============================================================================

func TestMedianIntervalComprehensive(t *testing.T) {
	tests := []struct {
		name      string
		events    []EventData
		expected  float64
		tolerance float64
	}{
		{
			name:      "nil events",
			events:    nil,
			expected:  0,
			tolerance: 0,
		},
		{
			name:      "empty events",
			events:    []EventData{},
			expected:  0,
			tolerance: 0,
		},
		{
			name: "millisecond precision",
			events: []EventData{
				{TimestampNs: 0},
				{TimestampNs: 500_000_000}, // 500ms
			},
			expected:  0.5,
			tolerance: 0.001,
		},
		{
			name: "microsecond precision",
			events: []EventData{
				{TimestampNs: 0},
				{TimestampNs: 500_000}, // 500us
			},
			expected:  0.0005,
			tolerance: 0.00001,
		},
		{
			name: "large intervals",
			events: []EventData{
				{TimestampNs: 0},
				{TimestampNs: 3600_000_000_000}, // 1 hour
			},
			expected:  3600.0,
			tolerance: 0.001,
		},
		{
			name: "varying intervals",
			events: []EventData{
				{TimestampNs: 0},
				{TimestampNs: 1_000_000_000},  // 1s interval
				{TimestampNs: 11_000_000_000}, // 10s interval
				{TimestampNs: 12_000_000_000}, // 1s interval
			},
			expected:  1.0, // Median of [1, 10, 1] sorted = [1, 1, 10] -> 1
			tolerance: 0.001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MedianInterval(tt.events)
			if !IsApproximatelyEqual(result, tt.expected, tt.tolerance) {
				t.Errorf("MedianInterval() = %v, want %v (tolerance %v)",
					result, tt.expected, tt.tolerance)
			}
		})
	}
}

func TestMedianIntervalPreservesOriginalOrder(t *testing.T) {
	// Ensure original slice is not modified
	events := []EventData{
		{TimestampNs: 3_000_000_000},
		{TimestampNs: 1_000_000_000},
		{TimestampNs: 2_000_000_000},
	}
	originalFirst := events[0].TimestampNs

	MedianInterval(events)

	if events[0].TimestampNs != originalFirst {
		t.Error("MedianInterval should not modify original slice order")
	}
}

func TestMedianIntervalWithRealisticData(t *testing.T) {
	gen := NewTestDataGenerator(42)

	// Generate events with known mean interval
	meanIntervalMs := 200.0 // 200ms average
	events := gen.GenerateEvents(100, time.Now(), meanIntervalMs, 0.2)

	result := MedianInterval(events)
	resultMs := result * 1000 // Convert to ms

	// Result should be close to mean (within 50% for test stability)
	if resultMs < meanIntervalMs*0.5 || resultMs > meanIntervalMs*1.5 {
		t.Errorf("median interval %vms should be near mean %vms", resultMs, meanIntervalMs)
	}
}

// =============================================================================
// PositiveNegativeRatio Tests
// =============================================================================

func TestPositiveNegativeRatioComprehensive(t *testing.T) {
	tests := []struct {
		name     string
		regions  []RegionData
		expected float64
	}{
		{
			name:     "nil regions",
			regions:  nil,
			expected: 0.5, // Neutral
		},
		{
			name:     "empty regions",
			regions:  []RegionData{},
			expected: 0.5,
		},
		{
			name: "75% insertions",
			regions: []RegionData{
				{DeltaSign: 1}, {DeltaSign: 1}, {DeltaSign: 1},
				{DeltaSign: -1},
			},
			expected: 0.75,
		},
		{
			name: "25% insertions",
			regions: []RegionData{
				{DeltaSign: 1},
				{DeltaSign: -1}, {DeltaSign: -1}, {DeltaSign: -1},
			},
			expected: 0.25,
		},
		{
			name: "only replacements",
			regions: []RegionData{
				{DeltaSign: 0}, {DeltaSign: 0}, {DeltaSign: 0},
			},
			expected: 0.5, // Neutral when no insertions/deletions
		},
		{
			name: "mixed with many replacements",
			regions: []RegionData{
				{DeltaSign: 1},
				{DeltaSign: 0}, {DeltaSign: 0}, {DeltaSign: 0},
				{DeltaSign: -1},
			},
			expected: 0.5, // 1 insert, 1 delete (replacements ignored)
		},
		{
			name: "single insertion",
			regions: []RegionData{
				{DeltaSign: 1},
			},
			expected: 1.0,
		},
		{
			name: "single deletion",
			regions: []RegionData{
				{DeltaSign: -1},
			},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PositiveNegativeRatio(tt.regions)
			if !IsApproximatelyEqual(result, tt.expected, 0.0001) {
				t.Errorf("PositiveNegativeRatio() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPositiveNegativeRatioAuthors(t *testing.T) {
	gen := NewTestDataGenerator(42)
	authors := PredefinedAuthors()

	for _, author := range authors {
		t.Run(author.Name, func(t *testing.T) {
			events, regions := gen.GenerateAuthorData(author, 100)
			_ = events // Not used directly

			// Flatten regions
			var allRegions []RegionData
			for _, rs := range regions {
				allRegions = append(allRegions, rs...)
			}

			ratio := PositiveNegativeRatio(allRegions)

			// Verify ratio is in valid range
			if ratio < 0 || ratio > 1 {
				t.Errorf("ratio for %s should be in [0,1], got %v", author.Name, ratio)
			}

			// High edit ratio authors should have lower positive ratio
			if author.EditRatio > 0.3 && ratio > 0.8 {
				t.Errorf("high edit ratio author %s should have lower positive ratio, got %v",
					author.Name, ratio)
			}
		})
	}
}

// =============================================================================
// DeletionClusteringCoef Tests
// =============================================================================

func TestDeletionClusteringCoefComprehensive(t *testing.T) {
	tests := []struct {
		name     string
		regions  []RegionData
		expected float64
	}{
		{
			name:     "nil regions",
			regions:  nil,
			expected: 0,
		},
		{
			name:     "no deletions",
			regions:  []RegionData{{DeltaSign: 1}, {DeltaSign: 1}},
			expected: 0,
		},
		{
			name: "single deletion",
			regions: []RegionData{
				{StartPct: 0.5, DeltaSign: -1},
			},
			expected: 0,
		},
		{
			name: "two deletions same position",
			regions: []RegionData{
				{StartPct: 0.5, DeltaSign: -1},
				{StartPct: 0.5, DeltaSign: -1},
			},
			expected: 0, // Zero distance means zero coef after normalization
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DeletionClusteringCoef(tt.regions)
			if !IsApproximatelyEqual(result, tt.expected, 0.0001) {
				t.Errorf("DeletionClusteringCoef() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDeletionClusteringCoefComparison(t *testing.T) {
	gen := NewTestDataGenerator(42)

	// Highly clustered deletions
	clustered := gen.GenerateClusteredDeletions(50, []float32{0.3, 0.7}, 0.02)

	// Scattered deletions
	scattered := gen.GenerateScatteredDeletions(50)

	clusteredCoef := DeletionClusteringCoef(clustered)
	scatteredCoef := DeletionClusteringCoef(scattered)

	// Scattered deletions should have higher coefficient
	if scatteredCoef <= clusteredCoef {
		t.Errorf("scattered coef (%v) should be > clustered coef (%v)",
			scatteredCoef, clusteredCoef)
	}
}

func TestDeletionClusteringCoefUniform(t *testing.T) {
	// Perfectly uniform deletions should have coefficient around 1
	n := 100
	regions := make([]RegionData, n)
	for i := 0; i < n; i++ {
		regions[i] = RegionData{
			StartPct:  float32(i) / float32(n),
			DeltaSign: -1,
		}
	}

	coef := DeletionClusteringCoef(regions)

	// For uniform distribution, coefficient should be close to 1
	// (actual expected distance equals observed distance)
	if coef < 0.5 || coef > 2.0 {
		t.Errorf("uniform distribution should have coef near 1, got %v", coef)
	}
}

// =============================================================================
// ComputePrimaryMetrics Integration Tests
// =============================================================================

func TestComputePrimaryMetricsIntegration(t *testing.T) {
	gen := NewTestDataGenerator(42)

	t.Run("human_like_author", func(t *testing.T) {
		author := AuthorProfile{
			Name:            "typical_human",
			MeanIntervalMs:  200,
			IntervalStdDev:  80,
			EditRatio:       0.2,
			AppendRatio:     0.4,
			RevisionPattern: "clustered",
		}

		events, regions := gen.GenerateAuthorData(author, 100)
		metrics, err := ComputePrimaryMetrics(events, regions)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Human-like characteristics
		if metrics.MonotonicAppendRatio > 0.8 {
			t.Errorf("human pattern should have moderate append ratio, got %v",
				metrics.MonotonicAppendRatio)
		}
		if metrics.PositiveNegativeRatio > 0.95 {
			t.Errorf("human pattern should have some deletions, got ratio %v",
				metrics.PositiveNegativeRatio)
		}
	})

	t.Run("ai_like_author", func(t *testing.T) {
		author := AuthorProfile{
			Name:            "ai_like",
			MeanIntervalMs:  50,
			IntervalStdDev:  10,
			EditRatio:       0.01,
			AppendRatio:     0.98,
			RevisionPattern: "none",
		}

		events, regions := gen.GenerateAuthorData(author, 100)
		metrics, err := ComputePrimaryMetrics(events, regions)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// AI-like characteristics
		if metrics.MonotonicAppendRatio < 0.7 {
			t.Errorf("AI pattern should have high append ratio, got %v",
				metrics.MonotonicAppendRatio)
		}
		if metrics.PositiveNegativeRatio < 0.9 {
			t.Errorf("AI pattern should have very few deletions, got ratio %v",
				metrics.PositiveNegativeRatio)
		}
	})
}

func TestComputePrimaryMetricsEdgeCases(t *testing.T) {
	t.Run("exactly_minimum_events", func(t *testing.T) {
		events := make([]EventData, MinEventsForAnalysis)
		regions := make(map[int64][]RegionData)
		for i := 0; i < MinEventsForAnalysis; i++ {
			events[i] = EventData{
				ID:          int64(i + 1),
				TimestampNs: int64(i) * 1_000_000_000,
				FilePath:    "/test.txt",
			}
			regions[int64(i+1)] = []RegionData{{StartPct: float32(i) * 0.1, DeltaSign: 1}}
		}

		metrics, err := ComputePrimaryMetrics(events, regions)
		if err != nil {
			t.Fatalf("should succeed with exactly minimum events: %v", err)
		}
		if metrics == nil {
			t.Fatal("metrics should not be nil")
		}
	})

	t.Run("one_below_minimum", func(t *testing.T) {
		events := make([]EventData, MinEventsForAnalysis-1)
		regions := make(map[int64][]RegionData)
		for i := 0; i < len(events); i++ {
			events[i] = EventData{ID: int64(i + 1)}
			regions[int64(i+1)] = []RegionData{{DeltaSign: 1}}
		}

		_, err := ComputePrimaryMetrics(events, regions)
		if err != ErrInsufficientData {
			t.Errorf("expected ErrInsufficientData, got %v", err)
		}
	})

	t.Run("extreme_timestamps", func(t *testing.T) {
		events := []EventData{
			{ID: 1, TimestampNs: 0},
			{ID: 2, TimestampNs: 1},
			{ID: 3, TimestampNs: 2},
			{ID: 4, TimestampNs: 3},
			{ID: 5, TimestampNs: math.MaxInt64 / 2}, // Very large gap
		}
		regions := map[int64][]RegionData{
			1: {{DeltaSign: 1}}, 2: {{DeltaSign: 1}}, 3: {{DeltaSign: 1}},
			4: {{DeltaSign: 1}}, 5: {{DeltaSign: 1}},
		}

		metrics, err := ComputePrimaryMetrics(events, regions)
		if err != nil {
			t.Fatalf("should handle extreme timestamps: %v", err)
		}
		if metrics.MedianInterval <= 0 {
			t.Error("median interval should be positive")
		}
	})
}

// =============================================================================
// FlattenRegions Tests
// =============================================================================

func TestFlattenRegionsComprehensive(t *testing.T) {
	tests := []struct {
		name     string
		regions  map[int64][]RegionData
		expected int
	}{
		{
			name:     "nil map",
			regions:  nil,
			expected: 0,
		},
		{
			name:     "empty map",
			regions:  map[int64][]RegionData{},
			expected: 0,
		},
		{
			name: "single event with regions",
			regions: map[int64][]RegionData{
				1: {{StartPct: 0.1}, {StartPct: 0.2}},
			},
			expected: 2,
		},
		{
			name: "multiple events mixed",
			regions: map[int64][]RegionData{
				1: {{StartPct: 0.1}},
				2: {},
				3: {{StartPct: 0.3}, {StartPct: 0.4}, {StartPct: 0.5}},
			},
			expected: 4,
		},
		{
			name: "all empty slices",
			regions: map[int64][]RegionData{
				1: {},
				2: {},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := flattenRegions(tt.regions)
			if len(result) != tt.expected {
				t.Errorf("flattenRegions() returned %d regions, want %d",
					len(result), tt.expected)
			}
		})
	}
}

// =============================================================================
// Inter-Key Timing Analysis Tests
// =============================================================================

func TestInterKeyTimingAnalysis(t *testing.T) {
	gen := NewTestDataGenerator(42)

	t.Run("burst_detection", func(t *testing.T) {
		// Create events with a burst in the middle
		events := gen.GenerateEvents(50, time.Now(), 500, 0.1)

		// Insert burst: 10 events in 100ms each
		burstStart := time.Now()
		for i := 0; i < 10; i++ {
			events = append(events, EventData{
				ID:          int64(100 + i),
				TimestampNs: burstStart.Add(time.Duration(i*100) * time.Millisecond).UnixNano(),
				SizeDelta:   50,
			})
		}

		// Sort by timestamp
		sort.Slice(events, func(i, j int) bool {
			return events[i].TimestampNs < events[j].TimestampNs
		})

		// Calculate intervals
		var intervals []float64
		for i := 1; i < len(events); i++ {
			deltaNs := events[i].TimestampNs - events[i-1].TimestampNs
			intervals = append(intervals, float64(deltaNs)/1e9)
		}

		// Find minimum interval
		minInterval := intervals[0]
		for _, v := range intervals {
			if v < minInterval {
				minInterval = v
			}
		}

		// Should detect sub-second intervals from burst
		if minInterval > 0.2 {
			t.Errorf("should detect burst intervals, min was %v", minInterval)
		}
	})

	t.Run("zone_classification", func(t *testing.T) {
		// Test interval classification into zones
		intervals := []float64{0.05, 0.1, 0.5, 1.0, 5.0, 30.0, 300.0}

		classifications := make(map[string]int)
		for _, interval := range intervals {
			zone := classifyIntervalZone(interval)
			classifications[zone]++
		}

		// Should have multiple zones
		if len(classifications) < 3 {
			t.Errorf("should classify intervals into multiple zones, got %v", classifications)
		}
	})
}

// classifyIntervalZone categorizes an interval into typing zones.
func classifyIntervalZone(seconds float64) string {
	switch {
	case seconds < 0.1:
		return "burst"
	case seconds < 1.0:
		return "fast"
	case seconds < 5.0:
		return "normal"
	case seconds < 60.0:
		return "pause"
	default:
		return "gap"
	}
}

// =============================================================================
// Histogram Generation Tests
// =============================================================================

func TestHistogramGeneration(t *testing.T) {
	t.Run("position_histogram", func(t *testing.T) {
		regions := []RegionData{
			{StartPct: 0.05},  // Bin 0
			{StartPct: 0.15},  // Bin 1
			{StartPct: 0.15},  // Bin 1
			{StartPct: 0.95},  // Bin 9
		}

		histogram := buildPositionHistogram(regions, 10)

		if histogram[0] != 1 {
			t.Errorf("bin 0 should have 1, got %d", histogram[0])
		}
		if histogram[1] != 2 {
			t.Errorf("bin 1 should have 2, got %d", histogram[1])
		}
		if histogram[9] != 1 {
			t.Errorf("bin 9 should have 1, got %d", histogram[9])
		}
	})

	t.Run("velocity_histogram", func(t *testing.T) {
		events := []EventData{
			{TimestampNs: 0, SizeDelta: 0},
			{TimestampNs: 1_000_000_000, SizeDelta: 10},  // 10 bps
			{TimestampNs: 2_000_000_000, SizeDelta: 100}, // 100 bps
			{TimestampNs: 3_000_000_000, SizeDelta: 50},  // 50 bps
		}

		velocities := calculateVelocities(events)

		if len(velocities) != 3 {
			t.Errorf("should have 3 velocities, got %d", len(velocities))
		}

		// First velocity should be 10 bps
		if !IsApproximatelyEqual(velocities[0], 10, 0.1) {
			t.Errorf("first velocity should be ~10, got %v", velocities[0])
		}
	})
}

// buildPositionHistogram creates histogram of edit positions.
func buildPositionHistogram(regions []RegionData, bins int) []int {
	histogram := make([]int, bins)
	for _, r := range regions {
		pos := r.StartPct
		if pos < 0 {
			pos = 0
		}
		if pos >= 1 {
			pos = 0.9999
		}
		binIdx := int(pos * float32(bins))
		if binIdx >= bins {
			binIdx = bins - 1
		}
		histogram[binIdx]++
	}
	return histogram
}

// calculateVelocities computes bytes per second between consecutive events.
func calculateVelocities(events []EventData) []float64 {
	if len(events) < 2 {
		return nil
	}

	velocities := make([]float64, len(events)-1)
	for i := 1; i < len(events); i++ {
		deltaNs := events[i].TimestampNs - events[i-1].TimestampNs
		if deltaNs <= 0 {
			velocities[i-1] = 0
			continue
		}
		deltaSec := float64(deltaNs) / 1e9
		bytesDelta := float64(abs32(events[i].SizeDelta))
		velocities[i-1] = bytesDelta / deltaSec
	}
	return velocities
}

// =============================================================================
// Outlier Detection Tests
// =============================================================================

func TestOutlierDetection(t *testing.T) {
	t.Run("iqr_method", func(t *testing.T) {
		// Normal data with outliers
		values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100, 200}

		outliers := detectOutliersIQR(values, 1.5)

		if len(outliers) != 2 {
			t.Errorf("should detect 2 outliers, got %d: %v", len(outliers), outliers)
		}
	})

	t.Run("zscore_method", func(t *testing.T) {
		// Normal distribution with one extreme outlier
		values := make([]float64, 100)
		for i := 0; i < 99; i++ {
			values[i] = float64(50 + i%10) // 50-59 range
		}
		values[99] = 500 // Extreme outlier

		outliers := detectOutliersZScore(values, 3.0)

		if len(outliers) == 0 {
			t.Error("should detect at least one outlier")
		}
	})
}

// detectOutliersIQR finds outliers using the IQR method.
func detectOutliersIQR(values []float64, k float64) []float64 {
	if len(values) < 4 {
		return nil
	}

	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	q1 := CalculatePercentile(sorted, 25)
	q3 := CalculatePercentile(sorted, 75)
	iqr := q3 - q1

	lowerBound := q1 - k*iqr
	upperBound := q3 + k*iqr

	var outliers []float64
	for _, v := range values {
		if v < lowerBound || v > upperBound {
			outliers = append(outliers, v)
		}
	}
	return outliers
}

// detectOutliersZScore finds outliers using Z-score method.
func detectOutliersZScore(values []float64, threshold float64) []float64 {
	if len(values) < 3 {
		return nil
	}

	mean := CalculateMean(values)
	stdDev := CalculateStdDev(values)
	if stdDev == 0 {
		return nil
	}

	var outliers []float64
	for _, v := range values {
		zScore := math.Abs(v-mean) / stdDev
		if zScore > threshold {
			outliers = append(outliers, v)
		}
	}
	return outliers
}
