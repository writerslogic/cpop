// keystroke-gen generates synthetic human-like keystroke events for testing
// the debouncing and kinetic gap detection algorithms without needing manual typing.
//
// Usage:
//
//	go run tools/keystroke-gen.go -output events.json -count 100
//	go run tools/keystroke-gen.go -output events.json -profile fast-typist
//	go run tools/keystroke-gen.go -output events.json -profile ai-generated
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"
)

// Event represents a synthetic file modification event.
type Event struct {
	ID          int64   `json:"id"`
	TimestampNs int64   `json:"timestamp_ns"`
	FileSize    int64   `json:"file_size"`
	SizeDelta   int32   `json:"size_delta"`
	FilePath    string  `json:"file_path"`
	Regions     []Region `json:"regions,omitempty"`
}

// Region represents an edit region within a file.
type Region struct {
	StartPct  float32 `json:"start_pct"`
	EndPct    float32 `json:"end_pct"`
	DeltaSign int8    `json:"delta_sign"` // 0=unchanged, 1=increase, 2=decrease
	ByteCount int32   `json:"byte_count"`
}

// TypingProfile defines parameters for simulating different typing behaviors.
type TypingProfile struct {
	Name                 string
	Description          string
	MedianIntervalMs     float64 // Median time between events
	IntervalStdDevMs     float64 // Standard deviation
	SessionGapMinutes    float64 // Gap between sessions
	SessionEventCount    int     // Events per session
	AppendProbability    float64 // Probability of appending vs editing
	DeletionProbability  float64 // Probability of deletion
	BurstProbability     float64 // Probability of fast burst
	BurstIntervalMs      float64 // Interval during bursts
	PauseProbability     float64 // Probability of thinking pause
	PauseMaxMs           float64 // Maximum pause duration
}

var profiles = map[string]TypingProfile{
	"normal": {
		Name:                "Normal Human Typist",
		Description:         "Typical human typing with natural variation",
		MedianIntervalMs:    2000,
		IntervalStdDevMs:    1500,
		SessionGapMinutes:   45,
		SessionEventCount:   50,
		AppendProbability:   0.6,
		DeletionProbability: 0.15,
		BurstProbability:    0.1,
		BurstIntervalMs:     200,
		PauseProbability:    0.05,
		PauseMaxMs:          30000,
	},
	"fast-typist": {
		Name:                "Fast Typist",
		Description:         "Experienced typist with quick, consistent pace",
		MedianIntervalMs:    800,
		IntervalStdDevMs:    400,
		SessionGapMinutes:   30,
		SessionEventCount:   80,
		AppendProbability:   0.5,
		DeletionProbability: 0.2,
		BurstProbability:    0.15,
		BurstIntervalMs:     150,
		PauseProbability:    0.03,
		PauseMaxMs:          15000,
	},
	"slow-thoughtful": {
		Name:                "Slow Thoughtful Writer",
		Description:         "Careful, deliberate writing with many pauses",
		MedianIntervalMs:    5000,
		IntervalStdDevMs:    3000,
		SessionGapMinutes:   60,
		SessionEventCount:   30,
		AppendProbability:   0.4,
		DeletionProbability: 0.25,
		BurstProbability:    0.02,
		BurstIntervalMs:     500,
		PauseProbability:    0.15,
		PauseMaxMs:          120000,
	},
	"ai-generated": {
		Name:                "AI-Generated Content",
		Description:         "Simulates AI-assisted or pasted content",
		MedianIntervalMs:    50,
		IntervalStdDevMs:    20,
		SessionGapMinutes:   5,
		SessionEventCount:   200,
		AppendProbability:   0.98,
		DeletionProbability: 0.01,
		BurstProbability:    0.8,
		BurstIntervalMs:     30,
		PauseProbability:    0.01,
		PauseMaxMs:          5000,
	},
	"paste-heavy": {
		Name:                "Paste-Heavy Workflow",
		Description:         "Mix of typing and large pastes",
		MedianIntervalMs:    3000,
		IntervalStdDevMs:    2000,
		SessionGapMinutes:   30,
		SessionEventCount:   40,
		AppendProbability:   0.85,
		DeletionProbability: 0.05,
		BurstProbability:    0.3,
		BurstIntervalMs:     50,
		PauseProbability:    0.1,
		PauseMaxMs:          60000,
	},
	"revision-pass": {
		Name:                "Revision Pass",
		Description:         "Editing existing content with many deletions",
		MedianIntervalMs:    1500,
		IntervalStdDevMs:    1000,
		SessionGapMinutes:   20,
		SessionEventCount:   60,
		AppendProbability:   0.3,
		DeletionProbability: 0.4,
		BurstProbability:    0.05,
		BurstIntervalMs:     300,
		PauseProbability:    0.08,
		PauseMaxMs:          20000,
	},
}

func main() {
	var (
		outputPath  = flag.String("output", "events.json", "Output file path")
		eventCount  = flag.Int("count", 100, "Number of events to generate")
		profileName = flag.String("profile", "normal", "Typing profile to use")
		filePath    = flag.String("file", "test-document.txt", "Simulated file path")
		startTime   = flag.Int64("start", 0, "Start timestamp (ns); 0 = now")
		seed        = flag.Int64("seed", 0, "Random seed; 0 = use current time")
		listProfiles = flag.Bool("list", false, "List available profiles")
	)
	flag.Parse()

	if *listProfiles {
		fmt.Println("Available profiles:")
		for name, p := range profiles {
			fmt.Printf("  %-20s %s\n", name, p.Description)
		}
		os.Exit(0)
	}

	profile, ok := profiles[*profileName]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown profile: %s\n", *profileName)
		fmt.Fprintf(os.Stderr, "Use -list to see available profiles\n")
		os.Exit(1)
	}

	// Initialize random source
	if *seed == 0 {
		*seed = time.Now().UnixNano()
	}
	rng := rand.New(rand.NewSource(*seed))

	// Initialize start time
	if *startTime == 0 {
		*startTime = time.Now().UnixNano()
	}

	fmt.Printf("Generating %d events with profile: %s\n", *eventCount, profile.Name)
	fmt.Printf("Random seed: %d\n", *seed)

	events := generateEvents(rng, profile, *eventCount, *filePath, *startTime)

	// Write output
	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling events: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outputPath, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %d events to %s\n", len(events), *outputPath)

	// Print summary statistics
	printStats(events)
}

func generateEvents(rng *rand.Rand, profile TypingProfile, count int, filePath string, startTime int64) []Event {
	events := make([]Event, 0, count)

	currentTime := startTime
	fileSize := int64(0)
	eventID := int64(1)
	eventsInSession := 0
	inBurst := false
	burstRemaining := 0

	for i := 0; i < count; i++ {
		// Determine interval to next event
		var intervalMs float64

		if inBurst && burstRemaining > 0 {
			// Continue burst
			intervalMs = profile.BurstIntervalMs * (0.5 + rng.Float64())
			burstRemaining--
			if burstRemaining == 0 {
				inBurst = false
			}
		} else if rng.Float64() < profile.PauseProbability {
			// Thinking pause
			intervalMs = profile.MedianIntervalMs + rng.Float64()*profile.PauseMaxMs
		} else if rng.Float64() < profile.BurstProbability {
			// Start burst
			inBurst = true
			burstRemaining = 3 + rng.Intn(10)
			intervalMs = profile.BurstIntervalMs * (0.5 + rng.Float64())
		} else {
			// Normal interval with log-normal distribution
			intervalMs = logNormalSample(rng, profile.MedianIntervalMs, profile.IntervalStdDevMs)
		}

		// Check for session gap
		eventsInSession++
		if eventsInSession >= profile.SessionEventCount {
			intervalMs += profile.SessionGapMinutes * 60 * 1000 * (0.5 + rng.Float64())
			eventsInSession = 0
		}

		currentTime += int64(intervalMs * 1e6) // Convert ms to ns

		// Generate edit region
		var region Region
		var sizeDelta int32

		if rng.Float64() < profile.AppendProbability {
			// Append at end
			region = Region{
				StartPct:  0.95 + rng.Float32()*0.05,
				EndPct:    1.0,
				DeltaSign: 1, // Increase
				ByteCount: int32(10 + rng.Intn(200)),
			}
			sizeDelta = region.ByteCount
		} else if rng.Float64() < profile.DeletionProbability/(1-profile.AppendProbability) {
			// Deletion
			startPct := rng.Float32() * 0.9
			region = Region{
				StartPct:  startPct,
				EndPct:    startPct + rng.Float32()*0.1,
				DeltaSign: 2, // Decrease
				ByteCount: int32(5 + rng.Intn(50)),
			}
			sizeDelta = -region.ByteCount
		} else {
			// Edit in middle
			startPct := rng.Float32() * 0.8
			region = Region{
				StartPct:  startPct,
				EndPct:    startPct + rng.Float32()*0.1,
				DeltaSign: 1,
				ByteCount: int32(5 + rng.Intn(100)),
			}
			sizeDelta = region.ByteCount
		}

		fileSize += int64(sizeDelta)
		if fileSize < 0 {
			fileSize = 0
		}

		event := Event{
			ID:          eventID,
			TimestampNs: currentTime,
			FileSize:    fileSize,
			SizeDelta:   sizeDelta,
			FilePath:    filePath,
			Regions:     []Region{region},
		}
		events = append(events, event)
		eventID++
	}

	return events
}

// logNormalSample generates a sample from a log-normal distribution.
func logNormalSample(rng *rand.Rand, median, stdDev float64) float64 {
	// Convert median to mean of underlying normal
	mu := math.Log(median)
	// Approximate sigma from desired stdDev
	sigma := math.Log(1 + stdDev/median)
	if sigma < 0.1 {
		sigma = 0.1
	}

	// Box-Muller transform
	u1 := rng.Float64()
	u2 := rng.Float64()
	z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)

	return math.Exp(mu + sigma*z)
}

func printStats(events []Event) {
	if len(events) < 2 {
		return
	}

	// Calculate intervals
	var intervals []float64
	for i := 1; i < len(events); i++ {
		intervalNs := events[i].TimestampNs - events[i-1].TimestampNs
		intervals = append(intervals, float64(intervalNs)/1e9)
	}

	// Calculate statistics
	var sum, sumSq float64
	min, max := intervals[0], intervals[0]
	for _, v := range intervals {
		sum += v
		sumSq += v * v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	mean := sum / float64(len(intervals))
	variance := sumSq/float64(len(intervals)) - mean*mean
	stdDev := math.Sqrt(variance)

	// Count appends vs edits
	appendCount := 0
	deleteCount := 0
	for _, e := range events {
		for _, r := range e.Regions {
			if r.StartPct >= 0.95 {
				appendCount++
			}
			if r.DeltaSign == 2 {
				deleteCount++
			}
		}
	}

	fmt.Println("\nStatistics:")
	fmt.Printf("  Total events:     %d\n", len(events))
	fmt.Printf("  Time span:        %.1f seconds\n", float64(events[len(events)-1].TimestampNs-events[0].TimestampNs)/1e9)
	fmt.Printf("  Interval mean:    %.2f seconds\n", mean)
	fmt.Printf("  Interval stddev:  %.2f seconds\n", stdDev)
	fmt.Printf("  Interval min:     %.3f seconds\n", min)
	fmt.Printf("  Interval max:     %.1f seconds\n", max)
	fmt.Printf("  Append ratio:     %.2f\n", float64(appendCount)/float64(len(events)))
	fmt.Printf("  Deletion ratio:   %.2f\n", float64(deleteCount)/float64(len(events)))
}
