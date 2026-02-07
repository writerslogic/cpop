package forensics

import (
	"math"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// ContentKeystrokeCorrelator Tests
// =============================================================================

func TestNewContentKeystrokeCorrelator(t *testing.T) {
	correlator := NewContentKeystrokeCorrelator()
	if correlator == nil {
		t.Fatal("NewContentKeystrokeCorrelator returned nil")
	}

	// Verify default config
	cfg := correlator.config
	if cfg.SuspiciousRatioThreshold <= 0 {
		t.Error("suspicious ratio threshold should be positive")
	}
	if cfg.InconsistentRatioThreshold <= cfg.SuspiciousRatioThreshold {
		t.Error("inconsistent threshold should be > suspicious threshold")
	}
	if cfg.EstimatedEditRatio < 0 || cfg.EstimatedEditRatio > 1 {
		t.Error("estimated edit ratio should be in [0,1]")
	}
	if cfg.MinKeystrokes <= 0 {
		t.Error("min keystrokes should be positive")
	}
	if cfg.MinDocumentLength <= 0 {
		t.Error("min document length should be positive")
	}
}

func TestNewContentKeystrokeCorrelatorWithConfig(t *testing.T) {
	customCfg := CorrelatorConfig{
		SuspiciousRatioThreshold:   0.2,
		InconsistentRatioThreshold: 0.4,
		EstimatedEditRatio:         0.2,
		MinKeystrokes:              5,
		MinDocumentLength:          20,
	}

	correlator := NewContentKeystrokeCorrelatorWithConfig(customCfg)
	if correlator.config != customCfg {
		t.Error("custom config not applied")
	}
}

func TestDefaultCorrelatorConfig(t *testing.T) {
	cfg := DefaultCorrelatorConfig()

	// Verify sensible defaults
	if cfg.SuspiciousRatioThreshold != 0.3 {
		t.Errorf("expected suspicious threshold 0.3, got %v", cfg.SuspiciousRatioThreshold)
	}
	if cfg.InconsistentRatioThreshold != 0.5 {
		t.Errorf("expected inconsistent threshold 0.5, got %v", cfg.InconsistentRatioThreshold)
	}
	if cfg.EstimatedEditRatio != 0.15 {
		t.Errorf("expected edit ratio 0.15, got %v", cfg.EstimatedEditRatio)
	}
	if cfg.MinKeystrokes != 10 {
		t.Errorf("expected min keystrokes 10, got %d", cfg.MinKeystrokes)
	}
	if cfg.MinDocumentLength != 50 {
		t.Errorf("expected min document length 50, got %d", cfg.MinDocumentLength)
	}
}

// =============================================================================
// Correlation Analysis Tests
// =============================================================================

func TestAnalyzeConsistent(t *testing.T) {
	correlator := NewContentKeystrokeCorrelator()

	// Document length = effective keystrokes
	// 1000 keystrokes * 0.85 = 850 effective
	input := CorrelationInput{
		DocumentLength:  850,
		TotalKeystrokes: 1000,
	}

	result := correlator.Analyze(input)

	if result.Status != StatusConsistent {
		t.Errorf("expected consistent status, got %v: %s", result.Status, result.Explanation)
	}
	if result.EffectiveKeystrokes != 850 {
		t.Errorf("expected 850 effective keystrokes, got %d", result.EffectiveKeystrokes)
	}
}

func TestAnalyzeConsistentWithPaste(t *testing.T) {
	correlator := NewContentKeystrokeCorrelator()

	// 500 keystrokes * 0.85 = 425 effective
	// 425 + 500 paste = 925 expected
	// Document = 925 (exact match)
	input := CorrelationInput{
		DocumentLength:     925,
		TotalKeystrokes:    500,
		DetectedPasteChars: 500,
		DetectedPasteCount: 2,
	}

	result := correlator.Analyze(input)

	if result.Status != StatusConsistent {
		t.Errorf("expected consistent status, got %v", result.Status)
	}
	if result.ExpectedContent != 925 {
		t.Errorf("expected content 925, got %d", result.ExpectedContent)
	}
}

func TestAnalyzeSuspiciousExcess(t *testing.T) {
	correlator := NewContentKeystrokeCorrelator()

	// 1000 keystrokes * 0.85 = 850 effective
	// Document = 1200 (41% excess > 30% threshold)
	input := CorrelationInput{
		DocumentLength:  1200,
		TotalKeystrokes: 1000,
	}

	result := correlator.Analyze(input)

	if result.Status != StatusSuspicious && result.Status != StatusInconsistent {
		t.Errorf("expected suspicious or inconsistent status, got %v", result.Status)
	}
}

func TestAnalyzeInconsistentNoKeystrokes(t *testing.T) {
	correlator := NewContentKeystrokeCorrelator()

	input := CorrelationInput{
		DocumentLength:  5000,
		TotalKeystrokes: 0,
	}

	result := correlator.Analyze(input)

	if result.Status != StatusInconsistent {
		t.Errorf("expected inconsistent status, got %v", result.Status)
	}

	// Should have appropriate flags
	hasNoKeystrokes := false
	hasExternalGenerated := false
	for _, flag := range result.Flags {
		if flag == FlagNoKeystrokes {
			hasNoKeystrokes = true
		}
		if flag == FlagExternalGenerated {
			hasExternalGenerated = true
		}
	}

	if !hasNoKeystrokes {
		t.Error("expected FlagNoKeystrokes")
	}
	if !hasExternalGenerated {
		t.Error("expected FlagExternalGenerated")
	}
}

func TestAnalyzeInsufficientData(t *testing.T) {
	correlator := NewContentKeystrokeCorrelator()

	input := CorrelationInput{
		DocumentLength:  10,
		TotalKeystrokes: 5,
	}

	result := correlator.Analyze(input)

	if result.Status != StatusInsufficient {
		t.Errorf("expected insufficient status, got %v", result.Status)
	}
}

func TestAnalyzeHeavyEditing(t *testing.T) {
	correlator := NewContentKeystrokeCorrelator()

	// Heavy editing: many keystrokes, small document
	// 2000 keystrokes * 0.85 = 1700 effective
	// Document = 500 (70% deficit)
	input := CorrelationInput{
		DocumentLength:  500,
		TotalKeystrokes: 2000,
	}

	result := correlator.Analyze(input)

	// Should flag high edit ratio
	hasHighEditRatio := false
	for _, flag := range result.Flags {
		if flag == FlagHighEditRatio {
			hasHighEditRatio = true
		}
	}

	if !hasHighEditRatio {
		t.Error("expected FlagHighEditRatio for heavy editing")
	}
}

func TestAnalyzeWithAutocomplete(t *testing.T) {
	correlator := NewContentKeystrokeCorrelator()

	// 500 keystrokes * 0.85 = 425 effective
	// 425 + 300 autocomplete = 725 expected
	input := CorrelationInput{
		DocumentLength:    750,
		TotalKeystrokes:   500,
		AutocompleteChars: 300,
		SuspiciousBursts:  5,
	}

	result := correlator.Analyze(input)

	// Should flag autocomplete
	hasAutocomplete := false
	for _, flag := range result.Flags {
		if flag == FlagAutocomplete {
			hasAutocomplete = true
		}
	}

	if !hasAutocomplete {
		t.Error("expected FlagAutocomplete when suspicious bursts > 0")
	}
}

func TestAnalyzeWithActualEditRatio(t *testing.T) {
	correlator := NewContentKeystrokeCorrelator()

	actualRatio := 0.3 // 30% deletions
	input := CorrelationInput{
		DocumentLength:  700,
		TotalKeystrokes: 1000,
		ActualEditRatio: &actualRatio,
	}

	result := correlator.Analyze(input)

	// 1000 * (1 - 0.3) = 700 effective
	if result.EffectiveKeystrokes != 700 {
		t.Errorf("expected 700 effective keystrokes with 30%% edit ratio, got %d",
			result.EffectiveKeystrokes)
	}
}

func TestAnalyzeEmptyDocument(t *testing.T) {
	correlator := NewContentKeystrokeCorrelator()

	input := CorrelationInput{
		DocumentLength:  0,
		TotalKeystrokes: 0,
	}

	result := correlator.Analyze(input)

	// Empty with no activity should be consistent
	if result.Status != StatusInsufficient {
		// Could also be consistent for empty document
		if result.Status != StatusConsistent {
			t.Errorf("unexpected status for empty: %v", result.Status)
		}
	}
}

func TestAnalyzePerfectMatch(t *testing.T) {
	correlator := NewContentKeystrokeCorrelator()

	// Exact match is rare but possible
	input := CorrelationInput{
		DocumentLength:  850,
		TotalKeystrokes: 1000,
	}

	result := correlator.Analyze(input)

	if result.Discrepancy != 0 {
		t.Errorf("expected 0 discrepancy, got %d", result.Discrepancy)
	}
}

// =============================================================================
// Discrepancy Calculation Tests
// =============================================================================

func TestDiscrepancyRatioCalculation(t *testing.T) {
	correlator := NewContentKeystrokeCorrelator()

	tests := []struct {
		name           string
		docLength      int64
		keystrokes     int64
		paste          int64
		autocomplete   int64
		expectedRatio  float64
		tolerance      float64
	}{
		{
			name:          "no discrepancy",
			docLength:     850,
			keystrokes:    1000,
			expectedRatio: 0,
			tolerance:     0.01,
		},
		{
			name:          "positive discrepancy",
			docLength:     1000,
			keystrokes:    1000, // 850 effective
			expectedRatio: (1000 - 850) / 850.0,
			tolerance:     0.01,
		},
		{
			name:          "negative discrepancy",
			docLength:     700,
			keystrokes:    1000, // 850 effective
			expectedRatio: (700 - 850) / 850.0,
			tolerance:     0.01,
		},
		{
			name:          "with paste",
			docLength:     1350,
			keystrokes:    1000,
			paste:         500, // 850 + 500 = 1350
			expectedRatio: 0,
			tolerance:     0.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := CorrelationInput{
				DocumentLength:     tt.docLength,
				TotalKeystrokes:    tt.keystrokes,
				DetectedPasteChars: tt.paste,
				AutocompleteChars:  tt.autocomplete,
			}

			result := correlator.Analyze(input)

			if math.Abs(result.DiscrepancyRatio-tt.expectedRatio) > tt.tolerance {
				t.Errorf("discrepancy ratio = %v, expected ~%v", result.DiscrepancyRatio, tt.expectedRatio)
			}
		})
	}
}

// =============================================================================
// QuickCorrelate Tests
// =============================================================================

func TestQuickCorrelate(t *testing.T) {
	tests := []struct {
		name       string
		docLength  int64
		keystrokes int64
		paste      int64
		suspicious bool
	}{
		{
			name:       "consistent",
			docLength:  850,
			keystrokes: 1000,
			paste:      0,
			suspicious: false,
		},
		{
			name:       "with paste consistent",
			docLength:  1850,
			keystrokes: 1000,
			paste:      1000,
			suspicious: false,
		},
		{
			name:       "no keystrokes suspicious",
			docLength:  500,
			keystrokes: 0,
			paste:      0,
			suspicious: true,
		},
		{
			name:       "excessive content",
			docLength:  2000,
			keystrokes: 1000, // Expects ~850
			paste:      0,
			suspicious: true, // 135% excess > 50%
		},
		{
			name:       "small document no keystrokes",
			docLength:  30, // Below 50 threshold
			keystrokes: 0,
			paste:      0,
			suspicious: false,
		},
		{
			name:       "borderline excess",
			docLength:  1275, // 50% above 850
			keystrokes: 1000,
			paste:      0,
			suspicious: false, // At exactly 50%, not suspicious
		},
		{
			name:       "just over threshold",
			docLength:  1280, // Just over 50%
			keystrokes: 1000,
			paste:      0,
			suspicious: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := QuickCorrelate(tt.docLength, tt.keystrokes, tt.paste)
			if result != tt.suspicious {
				t.Errorf("QuickCorrelate() = %v, want %v", result, tt.suspicious)
			}
		})
	}
}

// =============================================================================
// Correlation Report Tests
// =============================================================================

func TestCorrelationReport(t *testing.T) {
	result := &CorrelationResult{
		DocumentLength:      1500,
		TotalKeystrokes:     1000,
		DetectedPasteChars:  200,
		DetectedPasteCount:  2,
		AutocompleteChars:   100,
		SuspiciousBursts:    3,
		EffectiveKeystrokes: 850,
		ExpectedContent:     1150,
		Discrepancy:         350,
		DiscrepancyRatio:    0.304,
		Status:              StatusSuspicious,
		Explanation:         "minor discrepancy detected",
		Flags:               []CorrelationFlag{FlagAutocomplete},
	}

	report := result.Report()

	// Verify report contains key information
	checks := []string{
		"Content-Keystroke Correlation Report",
		"Document Length:     1500",
		"Total Keystrokes:    1000",
		"Detected Pastes:     2",
		"Effective Keystrokes: 850",
		"Expected Content:     1150",
		"Discrepancy:          350",
		"Status: suspicious",
		"Flags:",
		"autocomplete",
	}

	for _, check := range checks {
		if !strings.Contains(report, check) {
			t.Errorf("report should contain %q", check)
		}
	}
}

func TestCorrelationReportNoFlags(t *testing.T) {
	result := &CorrelationResult{
		DocumentLength:  850,
		TotalKeystrokes: 1000,
		Status:          StatusConsistent,
		Flags:           nil,
	}

	report := result.Report()

	if strings.Contains(report, "Flags:\n  -") {
		t.Error("report should not show flags section when empty")
	}
}

// =============================================================================
// Burst Detection Tests
// =============================================================================

func TestBurstDetection(t *testing.T) {
	gen := NewTestDataGenerator(42)

	t.Run("detect_typing_bursts", func(t *testing.T) {
		// Normal typing followed by burst
		events := []EventData{}
		base := time.Now()
		current := base

		// Normal typing (200ms intervals)
		for i := 0; i < 20; i++ {
			events = append(events, EventData{
				TimestampNs: current.UnixNano(),
				SizeDelta:   int32(5 + gen.rng.Intn(10)),
			})
			current = current.Add(200 * time.Millisecond)
		}

		// Burst (20ms intervals, 250+ bytes/sec)
		for i := 0; i < 10; i++ {
			events = append(events, EventData{
				TimestampNs: current.UnixNano(),
				SizeDelta:   10, // 500 bps at 20ms intervals
			})
			current = current.Add(20 * time.Millisecond)
		}

		bursts := detectBursts(events, 100.0) // 100 bps threshold

		if len(bursts) < 5 {
			t.Errorf("expected at least 5 burst events, detected %d", len(bursts))
		}
	})

	t.Run("no_bursts_normal_typing", func(t *testing.T) {
		events := gen.GenerateEvents(50, time.Now(), 200, 0.2)

		bursts := detectBursts(events, 100.0)

		// Normal typing at 200ms with small deltas shouldn't trigger bursts
		if len(bursts) > 5 { // Allow some variability
			t.Errorf("normal typing detected %d bursts (should be minimal)", len(bursts))
		}
	})
}

// detectBursts finds high-velocity editing events.
func detectBursts(events []EventData, thresholdBps float64) []EventData {
	var bursts []EventData

	for i := 1; i < len(events); i++ {
		deltaNs := events[i].TimestampNs - events[i-1].TimestampNs
		if deltaNs <= 0 {
			continue
		}

		deltaSec := float64(deltaNs) / 1e9
		if deltaSec > 60 { // Skip long gaps
			continue
		}

		bytesDelta := math.Abs(float64(events[i].SizeDelta))
		bps := bytesDelta / deltaSec

		if bps > thresholdBps {
			bursts = append(bursts, events[i])
		}
	}

	return bursts
}

// =============================================================================
// Copy-Paste Detection Tests
// =============================================================================

func TestCopyPasteDetection(t *testing.T) {
	t.Run("large_instant_additions", func(t *testing.T) {
		events := []EventData{
			{TimestampNs: 0, SizeDelta: 10},
			{TimestampNs: 1_000_000_000, SizeDelta: 500}, // 500 bytes in 1 second
			{TimestampNs: 2_000_000_000, SizeDelta: 15},
		}

		pastes := detectPotentialPastes(events, 200, 1.0)

		if len(pastes) != 1 {
			t.Errorf("expected 1 potential paste, got %d", len(pastes))
		}
	})

	t.Run("normal_typing_no_paste", func(t *testing.T) {
		events := []EventData{}
		for i := 0; i < 50; i++ {
			events = append(events, EventData{
				TimestampNs: int64(i) * 200_000_000, // 200ms
				SizeDelta:   int32(5 + i%10),        // 5-14 bytes
			})
		}

		pastes := detectPotentialPastes(events, 200, 1.0)

		if len(pastes) > 0 {
			t.Errorf("normal typing should not trigger paste detection, got %d", len(pastes))
		}
	})
}

// detectPotentialPastes finds events that look like paste operations.
func detectPotentialPastes(events []EventData, minBytes int32, maxSeconds float64) []EventData {
	var pastes []EventData

	for i := 1; i < len(events); i++ {
		deltaNs := events[i].TimestampNs - events[i-1].TimestampNs
		deltaSec := float64(deltaNs) / 1e9

		// Large addition in short time
		if events[i].SizeDelta >= minBytes && deltaSec <= maxSeconds {
			pastes = append(pastes, events[i])
		}
	}

	return pastes
}

// =============================================================================
// AI-Generated Content Indicator Tests
// =============================================================================

func TestAIGeneratedContentIndicators(t *testing.T) {
	gen := NewTestDataGenerator(42)

	t.Run("ai_like_pattern", func(t *testing.T) {
		aiAuthor := PredefinedAuthors()[3] // ai_like
		events, regions := gen.GenerateAuthorData(aiAuthor, 100)

		indicators := countAIIndicators(events, regions)

		// AI patterns should have multiple indicators
		if indicators < 2 {
			t.Errorf("AI-like pattern should have >= 2 indicators, got %d", indicators)
		}
	})

	t.Run("human_pattern", func(t *testing.T) {
		humanAuthor := PredefinedAuthors()[0] // slow_thoughtful
		events, regions := gen.GenerateAuthorData(humanAuthor, 100)

		indicators := countAIIndicators(events, regions)

		// Human patterns should have few indicators
		if indicators >= 3 {
			t.Errorf("human pattern should have < 3 indicators, got %d", indicators)
		}
	})
}

// countAIIndicators counts suspicious patterns suggesting AI generation.
func countAIIndicators(events []EventData, regions map[int64][]RegionData) int {
	indicators := 0

	// Flatten regions
	var allRegions []RegionData
	for _, rs := range regions {
		allRegions = append(allRegions, rs...)
	}

	// Check monotonic append ratio
	appendRatio := MonotonicAppendRatio(allRegions, DefaultAppendThreshold)
	if appendRatio > 0.85 {
		indicators++
	}

	// Check edit entropy
	entropy := EditEntropy(allRegions, DefaultHistogramBins)
	if entropy < 1.5 && entropy > 0 {
		indicators++
	}

	// Check positive/negative ratio
	posNegRatio := PositiveNegativeRatio(allRegions)
	if posNegRatio > 0.95 {
		indicators++
	}

	// Check for consistent timing (low variance)
	if len(events) >= 2 {
		var intervals []float64
		for i := 1; i < len(events); i++ {
			deltaNs := events[i].TimestampNs - events[i-1].TimestampNs
			intervals = append(intervals, float64(deltaNs)/1e9)
		}
		if len(intervals) > 5 {
			stdDev := CalculateStdDev(intervals)
			mean := CalculateMean(intervals)
			if mean > 0 {
				cv := stdDev / mean // Coefficient of variation
				if cv < 0.3 {       // Very consistent timing
					indicators++
				}
			}
		}
	}

	return indicators
}

// =============================================================================
// False Positive/Negative Characterization Tests
// =============================================================================

func TestFalsePositiveRateCharacterization(t *testing.T) {
	gen := NewTestDataGenerator(42)

	// Generate many "human" profiles and check false positive rate
	falsePositives := 0
	totalTests := 100

	humanAuthors := []AuthorProfile{
		PredefinedAuthors()[0], // slow_thoughtful
		PredefinedAuthors()[1], // fast_typist
		PredefinedAuthors()[2], // meticulous_editor
	}

	for i := 0; i < totalTests; i++ {
		author := humanAuthors[i%len(humanAuthors)]
		events, regions := gen.GenerateAuthorData(author, 50+gen.rng.Intn(50))

		profile, err := BuildProfile(events, regions)
		if err != nil {
			continue
		}

		if profile.Assessment == AssessmentSuspicious {
			falsePositives++
		}
	}

	fpRate := float64(falsePositives) / float64(totalTests)

	// Log the false positive rate
	t.Logf("False positive rate for human patterns: %.2f%% (%d/%d)",
		fpRate*100, falsePositives, totalTests)

	// Should be reasonably low
	if fpRate > 0.20 { // 20% threshold
		t.Errorf("false positive rate too high: %.2f%%", fpRate*100)
	}
}

func TestFalseNegativeRateCharacterization(t *testing.T) {
	gen := NewTestDataGenerator(42)

	// Generate many "AI-like" profiles and check false negative rate
	falseNegatives := 0
	totalTests := 100

	for i := 0; i < totalTests; i++ {
		aiAuthor := AuthorProfile{
			Name:            "ai_test",
			MeanIntervalMs:  30 + float64(gen.rng.Intn(30)),
			IntervalStdDev:  5,
			EditRatio:       0.01,
			AppendRatio:     0.95 + gen.rng.Float64()*0.05,
			RevisionPattern: "none",
		}

		events, regions := gen.GenerateAuthorData(aiAuthor, 50+gen.rng.Intn(50))

		profile, err := BuildProfile(events, regions)
		if err != nil {
			continue
		}

		if profile.Assessment == AssessmentConsistent {
			falseNegatives++
		}
	}

	fnRate := float64(falseNegatives) / float64(totalTests)

	// Log the false negative rate
	t.Logf("False negative rate for AI patterns: %.2f%% (%d/%d)",
		fnRate*100, falseNegatives, totalTests)

	// Note: Some false negatives are expected since patterns overlap
	// This is informational for threshold tuning
}

// =============================================================================
// Unusual Timing Pattern Tests
// =============================================================================

func TestUnusualTimingPatterns(t *testing.T) {
	t.Run("perfectly_regular_intervals", func(t *testing.T) {
		// Machine-like perfect regularity
		events := make([]EventData, 50)
		for i := 0; i < 50; i++ {
			events[i] = EventData{
				TimestampNs: int64(i) * 100_000_000, // Exactly 100ms
				SizeDelta:   10,
			}
		}

		var intervals []float64
		for i := 1; i < len(events); i++ {
			deltaNs := events[i].TimestampNs - events[i-1].TimestampNs
			intervals = append(intervals, float64(deltaNs)/1e9)
		}

		stdDev := CalculateStdDev(intervals)

		// Perfect regularity should have zero std dev
		if stdDev > 0.001 {
			t.Errorf("perfectly regular intervals should have ~0 std dev, got %v", stdDev)
		}
	})

	t.Run("bimodal_intervals", func(t *testing.T) {
		// Two distinct typing speeds (e.g., typing vs thinking)
		events := []EventData{}
		current := int64(0)

		for i := 0; i < 25; i++ {
			events = append(events, EventData{TimestampNs: current, SizeDelta: 10})
			current += 100_000_000 // 100ms (typing)
		}
		for i := 0; i < 25; i++ {
			events = append(events, EventData{TimestampNs: current, SizeDelta: 10})
			current += 2_000_000_000 // 2s (thinking)
		}

		var intervals []float64
		for i := 1; i < len(events); i++ {
			deltaNs := events[i].TimestampNs - events[i-1].TimestampNs
			intervals = append(intervals, float64(deltaNs)/1e9)
		}

		// Should detect bimodal distribution (high variance)
		stdDev := CalculateStdDev(intervals)
		mean := CalculateMean(intervals)

		if stdDev < mean*0.5 {
			t.Errorf("bimodal intervals should have high variance, got stdDev=%v, mean=%v",
				stdDev, mean)
		}
	})
}

// =============================================================================
// Correlation Status and Flag Constants Tests
// =============================================================================

func TestCorrelationStatusValues(t *testing.T) {
	statuses := []CorrelationStatus{
		StatusConsistent,
		StatusSuspicious,
		StatusInconsistent,
		StatusInsufficient,
	}

	for _, s := range statuses {
		if s == "" {
			t.Error("status should not be empty")
		}
	}

	// Verify uniqueness
	seen := make(map[CorrelationStatus]bool)
	for _, s := range statuses {
		if seen[s] {
			t.Errorf("duplicate status: %v", s)
		}
		seen[s] = true
	}
}

func TestCorrelationFlagValues(t *testing.T) {
	flags := []CorrelationFlag{
		FlagExcessContent,
		FlagUndetectedPaste,
		FlagAutocomplete,
		FlagNoKeystrokes,
		FlagHighEditRatio,
		FlagExternalGenerated,
	}

	for _, f := range flags {
		if f == "" {
			t.Error("flag should not be empty")
		}
	}

	// Verify uniqueness
	seen := make(map[CorrelationFlag]bool)
	for _, f := range flags {
		if seen[f] {
			t.Errorf("duplicate flag: %v", f)
		}
		seen[f] = true
	}
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestCorrelatorEdgeCases(t *testing.T) {
	correlator := NewContentKeystrokeCorrelator()

	t.Run("zero_expected_content", func(t *testing.T) {
		input := CorrelationInput{
			DocumentLength:  0,
			TotalKeystrokes: 0,
		}
		result := correlator.Analyze(input)
		// Should not panic
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("very_large_values", func(t *testing.T) {
		input := CorrelationInput{
			DocumentLength:  1_000_000_000, // 1GB
			TotalKeystrokes: 100_000_000,   // 100M keystrokes
		}
		result := correlator.Analyze(input)
		// Should not overflow
		if result.EffectiveKeystrokes < 0 {
			t.Error("effective keystrokes overflowed")
		}
	})

	t.Run("negative_size_delta", func(t *testing.T) {
		// Edge case: document shrunk
		input := CorrelationInput{
			DocumentLength:  100,
			TotalKeystrokes: 1000,
		}
		result := correlator.Analyze(input)
		// Negative discrepancy should be handled
		if result.Discrepancy >= 0 && result.DocumentLength < result.ExpectedContent {
			t.Error("discrepancy sign mismatch")
		}
	})
}
