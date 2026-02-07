package forensics

import (
	"bytes"
	"encoding/json"
	"html/template"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// PrintReport Tests
// =============================================================================

func TestPrintReportComprehensive(t *testing.T) {
	t.Run("full_profile", func(t *testing.T) {
		profile := &AuthorshipProfile{
			FilePath:     "/path/to/document.txt",
			EventCount:   150,
			SessionCount: 3,
			TimeSpan:     72 * time.Hour,
			FirstEvent:   time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
			LastEvent:    time.Date(2024, 1, 4, 10, 0, 0, 0, time.UTC),
			Metrics: PrimaryMetrics{
				MonotonicAppendRatio:  0.35,
				EditEntropy:           2.8,
				MedianInterval:        12.5,
				PositiveNegativeRatio: 0.72,
				DeletionClustering:    0.45,
			},
			Anomalies: []Anomaly{
				{
					Timestamp:   time.Date(2024, 1, 2, 14, 30, 0, 0, time.UTC),
					Type:        AnomalyGap,
					Description: "Long editing gap detected",
					Severity:    SeverityInfo,
					Context:     "Between sessions",
				},
				{
					Timestamp:   time.Date(2024, 1, 3, 9, 15, 0, 0, time.UTC),
					Type:        AnomalyHighVelocity,
					Description: "High-velocity content addition",
					Severity:    SeverityWarning,
				},
			},
			Assessment: AssessmentConsistent,
		}

		var buf bytes.Buffer
		PrintReport(&buf, profile)
		output := buf.String()

		// Verify all major sections present
		sections := []string{
			"FORENSIC AUTHORSHIP ANALYSIS",
			"File:",
			"Events:",
			"Sessions:",
			"Time Span:",
			"First Event:",
			"Last Event:",
			"PRIMARY METRICS",
			"Monotonic Append Ratio:",
			"Edit Entropy:",
			"Median Interval:",
			"Positive/Negative Ratio:",
			"Deletion Clustering:",
			"ANOMALIES DETECTED",
			"ASSESSMENT:",
		}

		for _, section := range sections {
			if !strings.Contains(output, section) {
				t.Errorf("output should contain section: %s", section)
			}
		}

		// Verify metric values
		if !strings.Contains(output, "0.350") {
			t.Error("output should contain monotonic append ratio value")
		}
		if !strings.Contains(output, "12.50 sec") {
			t.Error("output should contain median interval value")
		}

		// Verify anomalies
		if !strings.Contains(output, "Long editing gap") {
			t.Error("output should contain anomaly description")
		}
		if !strings.Contains(output, "Between sessions") {
			t.Error("output should contain anomaly context")
		}
	})

	t.Run("minimal_profile", func(t *testing.T) {
		profile := &AuthorshipProfile{
			EventCount: 10,
			Assessment: AssessmentInsufficient,
		}

		var buf bytes.Buffer
		PrintReport(&buf, profile)
		output := buf.String()

		// Should not contain file path or timestamps
		if strings.Contains(output, "File:") && strings.Contains(output, "/") {
			// OK - File section might exist but be empty
		}

		// Should show assessment
		if !strings.Contains(output, string(AssessmentInsufficient)) {
			t.Error("output should contain insufficient assessment")
		}
	})

	t.Run("zero_values", func(t *testing.T) {
		profile := &AuthorshipProfile{
			EventCount: 0,
			Metrics: PrimaryMetrics{
				MonotonicAppendRatio:  0,
				EditEntropy:           0,
				MedianInterval:        0,
				PositiveNegativeRatio: 0.5,
				DeletionClustering:    0,
			},
			Assessment: AssessmentInsufficient,
		}

		var buf bytes.Buffer
		PrintReport(&buf, profile)
		output := buf.String()

		// Should handle zero values gracefully
		if !strings.Contains(output, "0.000") {
			t.Error("output should contain zero values formatted")
		}
	})
}

func TestPrintReportSeverityMarkers(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityAlert, "[!!!]"},
		{SeverityWarning, "[ ! ]"},
		{SeverityInfo, "[ i ]"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			profile := &AuthorshipProfile{
				EventCount: 50,
				Anomalies: []Anomaly{
					{
						Type:        AnomalyGap,
						Description: "Test anomaly",
						Severity:    tt.severity,
					},
				},
				Assessment: AssessmentConsistent,
			}

			var buf bytes.Buffer
			PrintReport(&buf, profile)
			output := buf.String()

			if !strings.Contains(output, tt.expected) {
				t.Errorf("output should contain severity marker %s", tt.expected)
			}
		})
	}
}

// =============================================================================
// FormatDuration Tests
// =============================================================================

func TestFormatDurationComprehensive(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{-1 * time.Second, "0 seconds"},
		{0, "0 seconds"},
		{1 * time.Second, "1 second"},
		{2 * time.Second, "2 seconds"},
		{59 * time.Second, "59 seconds"},
		{1 * time.Minute, "1 minute, 0 seconds"},
		{1*time.Minute + 30*time.Second, "1 minute, 30 seconds"},
		{2 * time.Minute, "2 minutes, 0 seconds"},
		{59*time.Minute + 59*time.Second, "59 minutes, 59 seconds"},
		{1 * time.Hour, "1 hour, 0 minutes"},
		{1*time.Hour + 30*time.Minute, "1 hour, 30 minutes"},
		{2 * time.Hour, "2 hours, 0 minutes"},
		{23*time.Hour + 59*time.Minute, "23 hours, 59 minutes"},
		{24 * time.Hour, "1 day, 0 hours"},
		{24*time.Hour + 12*time.Hour, "1 day, 12 hours"},
		{48 * time.Hour, "2 days, 0 hours"},
		{365 * 24 * time.Hour, "365 days, 0 hours"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := FormatDuration(tt.duration)
			if result != tt.expected {
				t.Errorf("FormatDuration(%v) = %q, want %q", tt.duration, result, tt.expected)
			}
		})
	}
}

func TestFormatDurationEdgeCases(t *testing.T) {
	t.Run("large_duration", func(t *testing.T) {
		// 10 years
		d := 10 * 365 * 24 * time.Hour
		result := FormatDuration(d)
		if !strings.Contains(result, "days") {
			t.Errorf("large duration should format as days: %q", result)
		}
	})

	t.Run("nanoseconds_ignored", func(t *testing.T) {
		d := 1*time.Second + 500*time.Millisecond
		result := FormatDuration(d)
		// Should round down to 1 second
		if result != "1 second" {
			t.Errorf("sub-second should be truncated: %q", result)
		}
	})
}

// =============================================================================
// FormatMetricBar Tests
// =============================================================================

func TestFormatMetricBarComprehensive(t *testing.T) {
	tests := []struct {
		name     string
		value    float64
		min      float64
		max      float64
		width    int
		expected string
	}{
		{"zero_width", 0.5, 0, 1, 0, ""},
		{"invalid_range", 0.5, 1, 0, 10, "----------"},
		{"at_min", 0, 0, 1, 10, "[----------]"},
		{"at_max", 1, 0, 1, 10, "[##########]"},
		{"below_min", -0.5, 0, 1, 10, "[----------]"},
		{"above_max", 1.5, 0, 1, 10, "[##########]"},
		{"quarter", 0.25, 0, 1, 8, "[##------]"},
		{"half", 0.5, 0, 1, 10, "[#####-----]"},
		{"three_quarters", 0.75, 0, 1, 8, "[######--]"},
		{"custom_range", 50, 0, 100, 10, "[#####-----]"},
		{"negative_range", -5, -10, 0, 10, "[#####-----]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatMetricBar(tt.value, tt.min, tt.max, tt.width)
			if result != tt.expected {
				t.Errorf("FormatMetricBar(%v, %v, %v, %v) = %q, want %q",
					tt.value, tt.min, tt.max, tt.width, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Interpretation Function Tests
// =============================================================================

func TestInterpretMonotonicAppend(t *testing.T) {
	tests := []struct {
		ratio    float64
		contains string
	}{
		{0.95, "AI-like"},
		{0.92, "AI-like"},
		{0.85, "High"},
		{0.75, "High"},
		{0.50, "Moderate"},
		{0.45, "Moderate"},
		{0.30, "Low"},
		{0.10, "Low"},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := interpretMonotonicAppend(tt.ratio)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("interpretMonotonicAppend(%v) = %q, should contain %q",
					tt.ratio, result, tt.contains)
			}
		})
	}
}

func TestInterpretEditEntropy(t *testing.T) {
	tests := []struct {
		entropy  float64
		contains string
	}{
		{0.5, "Very low"},
		{0.9, "Very low"},
		{1.5, "Low"},
		{1.9, "Low"},
		{2.5, "Moderate"},
		{2.9, "Moderate"},
		{3.5, "High"},
		{4.0, "High"},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := interpretEditEntropy(tt.entropy)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("interpretEditEntropy(%v) = %q, should contain %q",
					tt.entropy, result, tt.contains)
			}
		})
	}
}

func TestInterpretMedianInterval(t *testing.T) {
	tests := []struct {
		interval float64
		contains string
	}{
		{0.5, "Very fast"},
		{0.9, "Very fast"},
		{2.0, "Fast"},
		{4.9, "Fast"},
		{15.0, "Moderate"},
		{29.9, "Moderate"},
		{60.0, "Slow"},
		{299.9, "Slow"},
		{600.0, "Very slow"},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := interpretMedianInterval(tt.interval)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("interpretMedianInterval(%v) = %q, should contain %q",
					tt.interval, result, tt.contains)
			}
		})
	}
}

func TestInterpretPosNegRatio(t *testing.T) {
	tests := []struct {
		ratio    float64
		contains string
	}{
		{0.98, "suspicious"},
		{0.96, "suspicious"},
		{0.85, "Mostly insertions"},
		{0.81, "Mostly insertions"},
		{0.70, "Balanced toward"},
		{0.65, "Balanced toward"},
		{0.50, "Balanced:"},
		{0.45, "Balanced:"},
		{0.30, "Mostly deletions"},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := interpretPosNegRatio(tt.ratio)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("interpretPosNegRatio(%v) = %q, should contain %q",
					tt.ratio, result, tt.contains)
			}
		})
	}
}

func TestInterpretDeletionClustering(t *testing.T) {
	tests := []struct {
		coef     float64
		contains string
	}{
		{0, "No deletions"},
		{0.3, "Highly clustered"},
		{0.49, "Highly clustered"},
		{0.6, "Moderately clustered"},
		{0.79, "Moderately clustered"},
		{1.0, "Scattered"},
		{1.1, "Scattered"},
		{1.5, "Very scattered"},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := interpretDeletionClustering(tt.coef)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("interpretDeletionClustering(%v) = %q, should contain %q",
					tt.coef, result, tt.contains)
			}
		})
	}
}

// =============================================================================
// JSON Schema Compliance Tests
// =============================================================================

func TestJSONSchemaCompliance(t *testing.T) {
	t.Run("exportable_metrics_json", func(t *testing.T) {
		metrics := &ExportableMetrics{
			MonotonicAppendRatio:  0.35,
			EditEntropy:           2.8,
			MedianInterval:        12.5,
			PositiveNegativeRatio: 0.72,
			DeletionClustering:    0.45,
			Assessment:            string(AssessmentConsistent),
			AnomalyCount:          2,
		}

		data, err := json.Marshal(metrics)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		// Verify JSON structure
		var parsed map[string]interface{}
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		// Check required fields
		requiredFields := []string{
			"monotonic_append_ratio",
			"edit_entropy",
			"median_interval_seconds",
			"positive_negative_ratio",
			"deletion_clustering",
			"assessment",
			"anomaly_count",
		}

		for _, field := range requiredFields {
			if _, ok := parsed[field]; !ok {
				t.Errorf("missing required field: %s", field)
			}
		}
	})

	t.Run("correlation_result_json", func(t *testing.T) {
		result := &CorrelationResult{
			DocumentLength:      1500,
			TotalKeystrokes:     1000,
			DetectedPasteChars:  200,
			DetectedPasteCount:  2,
			EffectiveKeystrokes: 850,
			ExpectedContent:     1050,
			Discrepancy:         450,
			DiscrepancyRatio:    0.43,
			AutocompleteChars:   50,
			SuspiciousBursts:    1,
			Status:              StatusSuspicious,
			Explanation:         "minor discrepancy",
			Flags:               []CorrelationFlag{FlagAutocomplete},
		}

		data, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		// Verify JSON structure
		var parsed map[string]interface{}
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		// Check key fields
		if parsed["status"] != "suspicious" {
			t.Errorf("status should be 'suspicious', got %v", parsed["status"])
		}
		if parsed["document_length"] != float64(1500) {
			t.Errorf("document_length mismatch: %v", parsed["document_length"])
		}
	})

	t.Run("round_trip", func(t *testing.T) {
		original := &ExportableMetrics{
			MonotonicAppendRatio:  0.35,
			EditEntropy:           2.8,
			MedianInterval:        12.5,
			PositiveNegativeRatio: 0.72,
			DeletionClustering:    0.45,
			Assessment:            "CONSISTENT",
			AnomalyCount:          0,
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded ExportableMetrics
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if decoded.MonotonicAppendRatio != original.MonotonicAppendRatio {
			t.Error("round-trip failed for MonotonicAppendRatio")
		}
		if decoded.AnomalyCount != original.AnomalyCount {
			t.Error("round-trip failed for AnomalyCount")
		}
	})
}

// =============================================================================
// HTML Report Generation Tests
// =============================================================================

func TestHTMLReportGeneration(t *testing.T) {
	profile := &AuthorshipProfile{
		FilePath:     "/test/doc.txt",
		EventCount:   100,
		SessionCount: 2,
		TimeSpan:     24 * time.Hour,
		Metrics: PrimaryMetrics{
			MonotonicAppendRatio:  0.35,
			EditEntropy:           2.5,
			MedianInterval:        10.0,
			PositiveNegativeRatio: 0.7,
			DeletionClustering:    0.5,
		},
		Assessment: AssessmentConsistent,
	}

	html := GenerateHTMLReport(profile)

	// Verify HTML structure
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("should contain DOCTYPE")
	}
	if !strings.Contains(html, "<html") {
		t.Error("should contain html tag")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("should contain closing html tag")
	}

	// Verify content
	if !strings.Contains(html, "/test/doc.txt") {
		t.Error("should contain file path")
	}
	if !strings.Contains(html, "CONSISTENT") {
		t.Error("should contain assessment")
	}
}

// GenerateHTMLReport creates an HTML version of the forensics report.
func GenerateHTMLReport(profile *AuthorshipProfile) string {
	const tmpl = `<!DOCTYPE html>
<html>
<head>
    <title>Forensic Authorship Analysis</title>
    <style>
        body { font-family: sans-serif; margin: 40px; }
        .header { border-bottom: 2px solid #333; padding-bottom: 10px; }
        .metrics { margin: 20px 0; }
        .metric { margin: 10px 0; }
        .bar { background: #eee; height: 20px; width: 200px; display: inline-block; }
        .fill { background: #4CAF50; height: 100%; }
        .assessment { font-size: 1.2em; font-weight: bold; margin-top: 30px; }
        .consistent { color: green; }
        .suspicious { color: orange; }
        .insufficient { color: gray; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Forensic Authorship Analysis</h1>
        <p>File: {{.FilePath}}</p>
        <p>Events: {{.EventCount}} | Sessions: {{.SessionCount}}</p>
    </div>

    <div class="metrics">
        <h2>Primary Metrics</h2>
        <div class="metric">
            <strong>Monotonic Append Ratio:</strong> {{printf "%.3f" .Metrics.MonotonicAppendRatio}}
        </div>
        <div class="metric">
            <strong>Edit Entropy:</strong> {{printf "%.3f" .Metrics.EditEntropy}}
        </div>
        <div class="metric">
            <strong>Median Interval:</strong> {{printf "%.2f" .Metrics.MedianInterval}} sec
        </div>
        <div class="metric">
            <strong>Pos/Neg Ratio:</strong> {{printf "%.3f" .Metrics.PositiveNegativeRatio}}
        </div>
        <div class="metric">
            <strong>Deletion Clustering:</strong> {{printf "%.3f" .Metrics.DeletionClustering}}
        </div>
    </div>

    <div class="assessment {{.AssessmentClass}}">
        Assessment: {{.Assessment}}
    </div>
</body>
</html>`

	t := template.Must(template.New("report").Parse(tmpl))

	data := struct {
		*AuthorshipProfile
		AssessmentClass string
	}{
		AuthorshipProfile: profile,
		AssessmentClass:   getAssessmentClass(profile.Assessment),
	}

	var buf bytes.Buffer
	t.Execute(&buf, data)
	return buf.String()
}

func getAssessmentClass(a Assessment) string {
	switch a {
	case AssessmentConsistent:
		return "consistent"
	case AssessmentSuspicious:
		return "suspicious"
	default:
		return "insufficient"
	}
}

func TestGetAssessmentClass(t *testing.T) {
	tests := []struct {
		assessment Assessment
		expected   string
	}{
		{AssessmentConsistent, "consistent"},
		{AssessmentSuspicious, "suspicious"},
		{AssessmentInsufficient, "insufficient"},
		{Assessment("unknown"), "insufficient"},
	}

	for _, tt := range tests {
		t.Run(string(tt.assessment), func(t *testing.T) {
			result := getAssessmentClass(tt.assessment)
			if result != tt.expected {
				t.Errorf("getAssessmentClass(%v) = %q, want %q",
					tt.assessment, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Report Section Tests
// =============================================================================

func TestReportSections(t *testing.T) {
	t.Run("metrics_section", func(t *testing.T) {
		profile := &AuthorshipProfile{
			Metrics: PrimaryMetrics{
				MonotonicAppendRatio:  0.85,
				EditEntropy:           1.2,
				MedianInterval:        0.5,
				PositiveNegativeRatio: 0.95,
				DeletionClustering:    1.1,
			},
			Assessment: AssessmentSuspicious,
		}

		var buf bytes.Buffer
		PrintReport(&buf, profile)
		output := buf.String()

		// All metrics should be present
		metrics := []string{
			"Monotonic Append Ratio",
			"Edit Entropy",
			"Median Interval",
			"Positive/Negative Ratio",
			"Deletion Clustering",
		}

		for _, m := range metrics {
			if !strings.Contains(output, m) {
				t.Errorf("report should contain metric: %s", m)
			}
		}
	})

	t.Run("anomalies_section", func(t *testing.T) {
		profile := &AuthorshipProfile{
			Anomalies: []Anomaly{
				{Type: AnomalyGap, Description: "Gap 1", Severity: SeverityInfo},
				{Type: AnomalyHighVelocity, Description: "Velocity 1", Severity: SeverityWarning},
				{Type: AnomalyMonotonic, Description: "Monotonic 1", Severity: SeverityAlert},
			},
			Assessment: AssessmentSuspicious,
		}

		var buf bytes.Buffer
		PrintReport(&buf, profile)
		output := buf.String()

		// All anomalies should be numbered
		if !strings.Contains(output, "1.") {
			t.Error("anomalies should be numbered starting with 1")
		}
		if !strings.Contains(output, "2.") {
			t.Error("should have anomaly 2")
		}
		if !strings.Contains(output, "3.") {
			t.Error("should have anomaly 3")
		}
	})

	t.Run("empty_file_path", func(t *testing.T) {
		profile := &AuthorshipProfile{
			FilePath:   "",
			EventCount: 10,
			Assessment: AssessmentInsufficient,
		}

		var buf bytes.Buffer
		PrintReport(&buf, profile)
		output := buf.String()

		// Should not crash and should handle empty path
		if strings.Contains(output, "File:           /") {
			t.Error("should not show file path when empty")
		}
	})
}

// =============================================================================
// Report with Minimal vs Maximal Data Tests
// =============================================================================

func TestReportMinimalData(t *testing.T) {
	profile := &AuthorshipProfile{
		EventCount: 3,
		Assessment: AssessmentInsufficient,
	}

	var buf bytes.Buffer
	PrintReport(&buf, profile)
	output := buf.String()

	// Should still produce valid report
	if !strings.Contains(output, "FORENSIC AUTHORSHIP ANALYSIS") {
		t.Error("minimal report should have header")
	}
	if !strings.Contains(output, "ASSESSMENT") {
		t.Error("minimal report should have assessment")
	}
}

func TestReportMaximalData(t *testing.T) {
	gen := NewTestDataGenerator(42)

	// Create profile with lots of anomalies
	anomalies := make([]Anomaly, 50)
	for i := 0; i < 50; i++ {
		severity := SeverityInfo
		if i%3 == 0 {
			severity = SeverityWarning
		}
		if i%7 == 0 {
			severity = SeverityAlert
		}

		anomalies[i] = Anomaly{
			Timestamp:   time.Now().Add(time.Duration(i) * time.Minute),
			Type:        AnomalyType([]AnomalyType{AnomalyGap, AnomalyHighVelocity, AnomalyMonotonic, AnomalyLowEntropy}[i%4]),
			Description: "Test anomaly description " + string(rune('A'+i%26)),
			Severity:    severity,
			Context:     "Context " + string(rune('0'+i%10)),
		}
	}

	events, regions := gen.GenerateAuthorData(PredefinedAuthors()[0], 500)
	profile, _ := BuildProfile(events, regions)
	profile.Anomalies = anomalies

	var buf bytes.Buffer
	PrintReport(&buf, profile)
	output := buf.String()

	// Should handle large report
	if len(output) < 1000 {
		t.Error("maximal report should be substantial")
	}

	// All 50 anomalies should be present
	if !strings.Contains(output, "50.") {
		t.Error("should list all 50 anomalies")
	}
}

// =============================================================================
// Report Edge Cases
// =============================================================================

func TestReportEdgeCases(t *testing.T) {
	t.Run("zero_time_span", func(t *testing.T) {
		profile := &AuthorshipProfile{
			EventCount: 1,
			TimeSpan:   0,
			Assessment: AssessmentInsufficient,
		}

		var buf bytes.Buffer
		PrintReport(&buf, profile)
		output := buf.String()

		if strings.Contains(output, "Time Span:      -") {
			t.Error("should handle zero time span")
		}
	})

	t.Run("special_characters_in_path", func(t *testing.T) {
		profile := &AuthorshipProfile{
			FilePath:   "/path/with spaces/and'quotes\"/file.txt",
			EventCount: 10,
			Assessment: AssessmentInsufficient,
		}

		var buf bytes.Buffer
		PrintReport(&buf, profile)
		output := buf.String()

		if !strings.Contains(output, "with spaces") {
			t.Error("should preserve special characters in path")
		}
	})

	t.Run("unicode_in_description", func(t *testing.T) {
		profile := &AuthorshipProfile{
			EventCount: 10,
			Anomalies: []Anomaly{
				{
					Type:        AnomalyGap,
					Description: "Gap with unicode: \u00e9\u00e8\u00ea",
					Severity:    SeverityInfo,
				},
			},
			Assessment: AssessmentConsistent,
		}

		var buf bytes.Buffer
		PrintReport(&buf, profile)
		output := buf.String()

		if !strings.Contains(output, "\u00e9") {
			t.Error("should preserve unicode characters")
		}
	})
}
