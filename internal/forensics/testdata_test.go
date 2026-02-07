package forensics

import (
	"math"
	"math/rand"
	"time"
)

// =============================================================================
// Test Data Generators for Forensics Package
// =============================================================================

// TestDataGenerator provides methods for generating realistic test data.
type TestDataGenerator struct {
	rng *rand.Rand
}

// NewTestDataGenerator creates a generator with a seed.
func NewTestDataGenerator(seed int64) *TestDataGenerator {
	return &TestDataGenerator{
		rng: rand.New(rand.NewSource(seed)),
	}
}

// =============================================================================
// Event Generators
// =============================================================================

// GenerateEvents creates n events with timestamps starting from base.
// meanIntervalMs: average milliseconds between events
// jitterFraction: random variation (0.0 to 1.0)
func (g *TestDataGenerator) GenerateEvents(n int, base time.Time, meanIntervalMs float64, jitterFraction float64) []EventData {
	events := make([]EventData, n)
	currentTime := base

	for i := 0; i < n; i++ {
		jitter := 1.0 + (g.rng.Float64()*2-1)*jitterFraction
		intervalMs := meanIntervalMs * jitter
		if intervalMs < 1 {
			intervalMs = 1
		}

		events[i] = EventData{
			ID:          int64(i + 1),
			TimestampNs: currentTime.UnixNano(),
			FileSize:    int64(100 + i*50),
			SizeDelta:   int32(g.rng.Intn(100) - 20), // -20 to +80
			FilePath:    "/test/document.txt",
		}

		currentTime = currentTime.Add(time.Duration(intervalMs) * time.Millisecond)
	}

	return events
}

// GenerateEventsWithGap creates events with a configurable gap.
func (g *TestDataGenerator) GenerateEventsWithGap(beforeGap, afterGap int, base time.Time, gapDuration time.Duration) []EventData {
	events := make([]EventData, beforeGap+afterGap)
	currentTime := base

	// Events before gap
	for i := 0; i < beforeGap; i++ {
		events[i] = EventData{
			ID:          int64(i + 1),
			TimestampNs: currentTime.UnixNano(),
			FileSize:    int64(100 + i*50),
			SizeDelta:   50,
			FilePath:    "/test/document.txt",
		}
		currentTime = currentTime.Add(time.Second)
	}

	// Apply gap
	currentTime = currentTime.Add(gapDuration)

	// Events after gap
	for i := beforeGap; i < beforeGap+afterGap; i++ {
		events[i] = EventData{
			ID:          int64(i + 1),
			TimestampNs: currentTime.UnixNano(),
			FileSize:    int64(100 + i*50),
			SizeDelta:   50,
			FilePath:    "/test/document.txt",
		}
		currentTime = currentTime.Add(time.Second)
	}

	return events
}

// GenerateHighVelocityEvents creates events with abnormally high content velocity.
func (g *TestDataGenerator) GenerateHighVelocityEvents(n int, base time.Time, bytesPerSecond float64) []EventData {
	events := make([]EventData, n)
	currentTime := base
	intervalMs := 1000.0 // 1 second intervals
	bytesPerInterval := int32(bytesPerSecond)

	for i := 0; i < n; i++ {
		events[i] = EventData{
			ID:          int64(i + 1),
			TimestampNs: currentTime.UnixNano(),
			FileSize:    int64(100 + i*int(bytesPerInterval)),
			SizeDelta:   bytesPerInterval,
			FilePath:    "/test/document.txt",
		}
		currentTime = currentTime.Add(time.Duration(intervalMs) * time.Millisecond)
	}

	return events
}

// =============================================================================
// Region Generators
// =============================================================================

// GenerateUniformRegions creates regions uniformly distributed across the document.
func (g *TestDataGenerator) GenerateUniformRegions(n int, insertionRatio float64) []RegionData {
	regions := make([]RegionData, n)

	for i := 0; i < n; i++ {
		pos := float32(i) / float32(n)
		deltaSign := int8(1)
		if g.rng.Float64() > insertionRatio {
			deltaSign = -1
		}

		regions[i] = RegionData{
			StartPct:  pos,
			EndPct:    pos + 0.01,
			DeltaSign: deltaSign,
			ByteCount: int32(g.rng.Intn(100) + 1),
		}
	}

	return regions
}

// GenerateAppendOnlyRegions creates regions that simulate append-only editing.
func (g *TestDataGenerator) GenerateAppendOnlyRegions(n int, appendThreshold float32) []RegionData {
	regions := make([]RegionData, n)

	for i := 0; i < n; i++ {
		// Most edits at end of document
		pos := appendThreshold + g.rng.Float32()*(1.0-appendThreshold)
		if pos >= 1.0 {
			pos = 0.9999
		}

		regions[i] = RegionData{
			StartPct:  pos,
			EndPct:    pos + 0.01,
			DeltaSign: 1, // All insertions
			ByteCount: int32(g.rng.Intn(100) + 1),
		}
	}

	return regions
}

// GenerateClusteredDeletions creates deletions clustered in specific areas.
func (g *TestDataGenerator) GenerateClusteredDeletions(n int, clusterCenters []float32, clusterSpread float32) []RegionData {
	regions := make([]RegionData, n)

	for i := 0; i < n; i++ {
		// Pick a random cluster center
		center := clusterCenters[g.rng.Intn(len(clusterCenters))]
		offset := (g.rng.Float32()*2 - 1) * clusterSpread
		pos := center + offset

		// Clamp to valid range
		if pos < 0 {
			pos = 0
		}
		if pos >= 1 {
			pos = 0.9999
		}

		regions[i] = RegionData{
			StartPct:  pos,
			EndPct:    pos + 0.01,
			DeltaSign: -1, // All deletions
			ByteCount: int32(g.rng.Intn(50) + 1),
		}
	}

	return regions
}

// GenerateScatteredDeletions creates deletions uniformly scattered.
func (g *TestDataGenerator) GenerateScatteredDeletions(n int) []RegionData {
	regions := make([]RegionData, n)

	for i := 0; i < n; i++ {
		pos := g.rng.Float32()
		if pos >= 1 {
			pos = 0.9999
		}

		regions[i] = RegionData{
			StartPct:  pos,
			EndPct:    pos + 0.01,
			DeltaSign: -1,
			ByteCount: int32(g.rng.Intn(50) + 1),
		}
	}

	return regions
}

// =============================================================================
// Author Profile Generators
// =============================================================================

// AuthorProfile represents a simulated author's typing characteristics.
type AuthorProfile struct {
	Name            string
	MeanIntervalMs  float64 // Average keystroke interval
	IntervalStdDev  float64 // Variance in interval
	EditRatio       float64 // Fraction of edits that are deletions
	AppendRatio     float64 // Fraction of edits at document end
	RevisionPattern string  // "clustered", "scattered", "none"
}

// PredefinedAuthors returns common author typing profiles.
func PredefinedAuthors() []AuthorProfile {
	return []AuthorProfile{
		{
			Name:            "slow_thoughtful",
			MeanIntervalMs:  500,
			IntervalStdDev:  200,
			EditRatio:       0.15,
			AppendRatio:     0.4,
			RevisionPattern: "clustered",
		},
		{
			Name:            "fast_typist",
			MeanIntervalMs:  80,
			IntervalStdDev:  30,
			EditRatio:       0.1,
			AppendRatio:     0.6,
			RevisionPattern: "scattered",
		},
		{
			Name:            "meticulous_editor",
			MeanIntervalMs:  200,
			IntervalStdDev:  100,
			EditRatio:       0.35,
			AppendRatio:     0.3,
			RevisionPattern: "clustered",
		},
		{
			Name:            "ai_like",
			MeanIntervalMs:  50,
			IntervalStdDev:  10,
			EditRatio:       0.02,
			AppendRatio:     0.95,
			RevisionPattern: "none",
		},
		{
			Name:            "copy_paster",
			MeanIntervalMs:  2000,
			IntervalStdDev:  500,
			EditRatio:       0.05,
			AppendRatio:     0.85,
			RevisionPattern: "none",
		},
	}
}

// GenerateAuthorData creates synthetic data matching an author profile.
func (g *TestDataGenerator) GenerateAuthorData(profile AuthorProfile, eventCount int) ([]EventData, map[int64][]RegionData) {
	base := time.Now().Add(-time.Hour * 24) // Start 24 hours ago
	events := make([]EventData, eventCount)
	regions := make(map[int64][]RegionData)

	currentTime := base
	currentSize := int64(0)

	for i := 0; i < eventCount; i++ {
		// Generate interval with normal distribution
		interval := profile.MeanIntervalMs + g.rng.NormFloat64()*profile.IntervalStdDev
		if interval < 10 {
			interval = 10 // Minimum 10ms
		}

		// Determine if this is an insertion or deletion
		isInsertion := g.rng.Float64() >= profile.EditRatio
		var delta int32
		if isInsertion {
			delta = int32(g.rng.Intn(50) + 1)
		} else {
			maxDelete := int32(50)
			if currentSize < 50 {
				maxDelete = int32(currentSize)
			}
			if maxDelete <= 0 {
				delta = 0
			} else {
				delta = -int32(g.rng.Intn(int(maxDelete)))
			}
		}

		currentSize += int64(delta)
		if currentSize < 0 {
			currentSize = 0
		}

		events[i] = EventData{
			ID:          int64(i + 1),
			TimestampNs: currentTime.UnixNano(),
			FileSize:    currentSize,
			SizeDelta:   delta,
			FilePath:    "/test/document.txt",
		}

		// Generate region for this event
		var pos float32
		if g.rng.Float64() < profile.AppendRatio {
			// Edit at end
			pos = 0.95 + g.rng.Float32()*0.05
		} else {
			// Edit elsewhere
			pos = g.rng.Float32() * 0.95
		}

		if pos >= 1 {
			pos = 0.9999
		}

		deltaSign := int8(1)
		if delta < 0 {
			deltaSign = -1
		} else if delta == 0 {
			deltaSign = 0
		}

		regions[int64(i+1)] = []RegionData{{
			StartPct:  pos,
			EndPct:    pos + 0.01,
			DeltaSign: deltaSign,
			ByteCount: abs32(delta),
		}}

		currentTime = currentTime.Add(time.Duration(interval) * time.Millisecond)
	}

	return events, regions
}

// =============================================================================
// Checkpoint Generators
// =============================================================================

// GenerateCheckpoints creates checkpoint data with realistic patterns.
func (g *TestDataGenerator) GenerateCheckpoints(n int, base time.Time) []CheckpointData {
	checkpoints := make([]CheckpointData, n)
	currentTime := base
	currentSize := int64(100)

	var prevHash [32]byte

	for i := 0; i < n; i++ {
		// Random interval: 1-30 minutes
		intervalMinutes := g.rng.Intn(30) + 1
		currentTime = currentTime.Add(time.Duration(intervalMinutes) * time.Minute)

		// Random size change: -100 to +500 bytes
		delta := int32(g.rng.Intn(600) - 100)
		newSize := currentSize + int64(delta)
		if newSize < 0 {
			newSize = 0
			delta = -int32(currentSize)
		}

		// Generate pseudo-random hash
		var contentHash [32]byte
		for j := 0; j < 32; j++ {
			contentHash[j] = byte(g.rng.Intn(256))
		}

		checkpoints[i] = CheckpointData{
			Ordinal:      uint64(i),
			Timestamp:    currentTime,
			ContentSize:  newSize,
			SizeDelta:    delta,
			ContentHash:  contentHash,
			PreviousHash: prevHash,
			FilePath:     "/test/document.txt",
		}

		prevHash = contentHash
		currentSize = newSize
	}

	return checkpoints
}

// GenerateLargeDataset creates a large dataset for performance testing.
func (g *TestDataGenerator) GenerateLargeDataset(eventCount int) ([]EventData, map[int64][]RegionData) {
	base := time.Now().Add(-time.Hour * 720) // 30 days ago
	events := make([]EventData, eventCount)
	regions := make(map[int64][]RegionData)

	currentTime := base
	currentSize := int64(0)

	for i := 0; i < eventCount; i++ {
		// Random interval: 100ms to 5s
		intervalMs := g.rng.Intn(4900) + 100
		currentTime = currentTime.Add(time.Duration(intervalMs) * time.Millisecond)

		// Random delta
		delta := int32(g.rng.Intn(200) - 40) // -40 to +160
		newSize := currentSize + int64(delta)
		if newSize < 0 {
			newSize = 0
			delta = -int32(currentSize)
		}

		events[i] = EventData{
			ID:          int64(i + 1),
			TimestampNs: currentTime.UnixNano(),
			FileSize:    newSize,
			SizeDelta:   delta,
			FilePath:    "/test/document.txt",
		}

		// Generate region
		pos := g.rng.Float32()
		if pos >= 1 {
			pos = 0.9999
		}

		deltaSign := int8(1)
		if delta < 0 {
			deltaSign = -1
		} else if delta == 0 {
			deltaSign = 0
		}

		regions[int64(i+1)] = []RegionData{{
			StartPct:  pos,
			EndPct:    pos + 0.01,
			DeltaSign: deltaSign,
			ByteCount: abs32(delta),
		}}

		currentSize = newSize
	}

	return events, regions
}

// =============================================================================
// Statistical Helpers
// =============================================================================

// CalculateMean computes the mean of a float64 slice.
func CalculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// CalculateStdDev computes the standard deviation of a float64 slice.
func CalculateStdDev(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mean := CalculateMean(values)
	sumSq := 0.0
	for _, v := range values {
		diff := v - mean
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq / float64(len(values)))
}

// CalculatePercentile computes the p-th percentile (p in 0-100).
func CalculatePercentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	if p <= 0 {
		return values[0]
	}
	if p >= 100 {
		return values[len(values)-1]
	}

	// Sort a copy
	sorted := make([]float64, len(values))
	copy(sorted, values)
	floatSort(sorted)

	// Calculate index
	index := (p / 100.0) * float64(len(sorted)-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))

	if lower == upper {
		return sorted[lower]
	}

	// Linear interpolation
	fraction := index - float64(lower)
	return sorted[lower]*(1-fraction) + sorted[upper]*fraction
}

// floatSort sorts float64 slice in place (simple implementation for tests).
func floatSort(values []float64) {
	for i := 0; i < len(values)-1; i++ {
		for j := i + 1; j < len(values); j++ {
			if values[j] < values[i] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
}

// IsApproximatelyEqual checks if two floats are within tolerance.
func IsApproximatelyEqual(a, b, tolerance float64) bool {
	return math.Abs(a-b) <= tolerance
}

// =============================================================================
// Correlation Test Data
// =============================================================================

// CorrelationTestCase represents a test case for correlation analysis.
type CorrelationTestCase struct {
	Name           string
	Input          CorrelationInput
	ExpectedStatus CorrelationStatus
	ExpectedFlags  []CorrelationFlag
}

// GenerateCorrelationTestCases returns standard test cases.
func GenerateCorrelationTestCases() []CorrelationTestCase {
	return []CorrelationTestCase{
		{
			Name: "perfectly_consistent",
			Input: CorrelationInput{
				DocumentLength:  1000,
				TotalKeystrokes: 1176, // ~85% effective = 1000
			},
			ExpectedStatus: StatusConsistent,
			ExpectedFlags:  nil,
		},
		{
			Name: "consistent_with_paste",
			Input: CorrelationInput{
				DocumentLength:     2000,
				TotalKeystrokes:    1176,
				DetectedPasteChars: 1000,
				DetectedPasteCount: 2,
			},
			ExpectedStatus: StatusConsistent,
			ExpectedFlags:  nil,
		},
		{
			Name: "suspicious_excess",
			Input: CorrelationInput{
				DocumentLength:  1500,
				TotalKeystrokes: 1000, // Expects ~850 chars
			},
			ExpectedStatus: StatusSuspicious,
			ExpectedFlags:  nil,
		},
		{
			Name: "inconsistent_no_keystrokes",
			Input: CorrelationInput{
				DocumentLength:  5000,
				TotalKeystrokes: 0,
			},
			ExpectedStatus: StatusInconsistent,
			ExpectedFlags:  []CorrelationFlag{FlagNoKeystrokes, FlagExternalGenerated},
		},
		{
			Name: "insufficient_data",
			Input: CorrelationInput{
				DocumentLength:  10,
				TotalKeystrokes: 5,
			},
			ExpectedStatus: StatusInsufficient,
			ExpectedFlags:  nil,
		},
		{
			Name: "heavy_editing",
			Input: CorrelationInput{
				DocumentLength:  500,
				TotalKeystrokes: 2000, // Expects ~1700 chars
			},
			ExpectedStatus: StatusSuspicious,
			ExpectedFlags:  []CorrelationFlag{FlagHighEditRatio},
		},
		{
			Name: "autocomplete_detected",
			Input: CorrelationInput{
				DocumentLength:     3000,
				TotalKeystrokes:    1176,
				AutocompleteChars:  500,
				SuspiciousBursts:   3,
			},
			ExpectedStatus: StatusSuspicious,
			ExpectedFlags:  []CorrelationFlag{FlagAutocomplete},
		},
	}
}
