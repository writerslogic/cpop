package keystroke

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// BenchmarkKeystrokeCapture benchmarks keystroke capture simulation.
func BenchmarkKeystrokeCapture(b *testing.B) {
	counter := NewSimulated()
	ctx := context.Background()

	if err := counter.Start(ctx); err != nil {
		b.Fatalf("failed to start counter: %v", err)
	}
	defer counter.Stop()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		counter.SimulateKeystroke()
	}

	b.ReportMetric(float64(counter.Count()), "total_keystrokes")
}

// BenchmarkSimulatedCounterBatch benchmarks batch keystroke simulation.
func BenchmarkSimulatedCounterBatch(b *testing.B) {
	batchSizes := []int{100, 500, 1000, 5000}

	for _, batchSize := range batchSizes {
		b.Run(fmt.Sprintf("batch_%d", batchSize), func(b *testing.B) {
			counter := NewSimulated()
			ctx := context.Background()
			counter.Start(ctx)
			defer counter.Stop()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				counter.SimulateKeystrokes(batchSize)
			}

			b.ReportMetric(float64(batchSize), "keystrokes/batch")
		})
	}
}

// BenchmarkBaseCounterIncrement benchmarks the base counter increment operation.
func BenchmarkBaseCounterIncrement(b *testing.B) {
	base := &BaseCounter{}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		base.Increment()
	}
}

// BenchmarkSubscription benchmarks keystroke subscription/notification.
func BenchmarkSubscription(b *testing.B) {
	intervals := []uint64{10, 50, 100}

	for _, interval := range intervals {
		b.Run(fmt.Sprintf("interval_%d", interval), func(b *testing.B) {
			counter := NewSimulated()
			ctx := context.Background()
			counter.Start(ctx)

			ch := counter.Subscribe(interval)

			// Drain events in background
			go func() {
				for range ch {
				}
			}()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				counter.SimulateKeystroke()
			}

			counter.Stop()

			b.ReportMetric(float64(interval), "subscription_interval")
		})
	}
}

// BenchmarkMultipleSubscribers benchmarks multiple concurrent subscribers.
func BenchmarkMultipleSubscribers(b *testing.B) {
	subscriberCounts := []int{1, 5, 10}

	for _, numSubscribers := range subscriberCounts {
		b.Run(fmt.Sprintf("subscribers_%d", numSubscribers), func(b *testing.B) {
			counter := NewSimulated()
			ctx := context.Background()
			counter.Start(ctx)

			// Create subscribers
			channels := make([]<-chan Event, numSubscribers)
			for i := 0; i < numSubscribers; i++ {
				channels[i] = counter.Subscribe(uint64(50 + i*10))

				// Drain events
				go func(ch <-chan Event) {
					for range ch {
					}
				}(channels[i])
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				counter.SimulateKeystroke()
			}

			counter.Stop()

			b.ReportMetric(float64(numSubscribers), "num_subscribers")
		})
	}
}

// BenchmarkCrossValidation benchmarks cross-validation logic.
func BenchmarkCrossValidation(b *testing.B) {
	appLayerCounts := []int64{1000, 10000, 100000}

	for _, count := range appLayerCounts {
		b.Run(fmt.Sprintf("count_%d", count), func(b *testing.B) {
			hidCount := count - int64(float64(count)*0.05) // 5% discrepancy

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				result := CrossValidate(count, hidCount)
				_ = result
			}
		})
	}
}

// BenchmarkVelocityAnalyzer benchmarks the velocity analyzer.
func BenchmarkVelocityAnalyzer(b *testing.B) {
	analyzer := NewVelocityAnalyzer()

	b.Run("OnCharacter", func(b *testing.B) {
		now := time.Now()

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			// Simulate typing at ~100ms intervals
			now = now.Add(100 * time.Millisecond)
			burst := analyzer.OnCharacter(now)
			_ = burst
		}
	})

	b.Run("Stats", func(b *testing.B) {
		// Pre-populate with some data
		analyzer := NewVelocityAnalyzer()
		now := time.Now()
		for i := 0; i < 1000; i++ {
			now = now.Add(80 * time.Millisecond)
			analyzer.OnCharacter(now)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			stats := analyzer.Stats()
			_ = stats
		}
	})
}

// BenchmarkVelocityClassification benchmarks velocity classification.
func BenchmarkVelocityClassification(b *testing.B) {
	velocities := []float64{5.0, 15.0, 35.0, 100.0, 500.0}

	for _, v := range velocities {
		b.Run(fmt.Sprintf("velocity_%.0f", v), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				class := ClassifyVelocity(v)
				_ = class
			}
		})
	}
}

// BenchmarkIsSuspiciousBurst benchmarks suspicious burst detection.
func BenchmarkIsSuspiciousBurst(b *testing.B) {
	testCases := []struct {
		chars    int
		duration time.Duration
	}{
		{10, 1 * time.Second},       // Normal
		{100, 500 * time.Millisecond}, // Fast
		{500, 100 * time.Millisecond}, // Suspicious
	}

	for _, tc := range testCases {
		b.Run(fmt.Sprintf("chars_%d_dur_%s", tc.chars, tc.duration), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				suspicious := IsSuspiciousBurst(tc.chars, tc.duration)
				_ = suspicious
			}
		})
	}
}

// BenchmarkVelocityBurstAnalysis benchmarks burst detection over time.
func BenchmarkVelocityBurstAnalysis(b *testing.B) {
	patterns := []struct {
		name        string
		baseInterval time.Duration
		burstSize   int
	}{
		{"normal_typing", 100 * time.Millisecond, 50},
		{"fast_typing", 50 * time.Millisecond, 100},
		{"mixed_bursts", 80 * time.Millisecond, 200},
	}

	for _, p := range patterns {
		b.Run(p.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				analyzer := NewVelocityAnalyzer()
				now := time.Now()

				for j := 0; j < p.burstSize; j++ {
					// Vary interval slightly
					interval := p.baseInterval
					if j%10 == 0 {
						interval = interval / 2 // Occasional faster burst
					}
					now = now.Add(interval)
					analyzer.OnCharacter(now)
				}

				analyzer.FlushBurst()
			}
		})
	}
}

// BenchmarkRecentBursts benchmarks retrieving recent bursts.
func BenchmarkRecentBursts(b *testing.B) {
	analyzer := NewVelocityAnalyzer()
	now := time.Now()

	// Generate many bursts
	for i := 0; i < 500; i++ {
		// Simulate a burst
		for j := 0; j < 20; j++ {
			now = now.Add(50 * time.Millisecond)
			analyzer.OnCharacter(now)
		}
		// Gap between bursts
		now = now.Add(500 * time.Millisecond)
	}

	counts := []int{10, 50, 100}

	for _, count := range counts {
		b.Run(fmt.Sprintf("recent_%d", count), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				bursts := analyzer.RecentBursts(count)
				_ = bursts
			}
		})
	}
}

// BenchmarkSuspiciousBurstsList benchmarks suspicious burst filtering.
func BenchmarkSuspiciousBurstsList(b *testing.B) {
	analyzer := NewVelocityAnalyzer()
	analyzer.SetSuspiciousLevel(VelocityAutocomplete)
	now := time.Now()

	// Generate mixed bursts
	for i := 0; i < 200; i++ {
		burstInterval := 80 * time.Millisecond
		if i%5 == 0 {
			burstInterval = 5 * time.Millisecond // Suspicious burst
		}

		for j := 0; j < 30; j++ {
			now = now.Add(burstInterval)
			analyzer.OnCharacter(now)
		}
		now = now.Add(300 * time.Millisecond)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		suspicious := analyzer.SuspiciousBurstsList()
		_ = suspicious
	}
}

// BenchmarkVelocityAnalyzerReset benchmarks analyzer reset.
func BenchmarkVelocityAnalyzerReset(b *testing.B) {
	analyzer := NewVelocityAnalyzer()
	now := time.Now()

	// Pre-populate
	for i := 0; i < 1000; i++ {
		now = now.Add(80 * time.Millisecond)
		analyzer.OnCharacter(now)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		analyzer.Reset()

		// Re-populate for next iteration
		b.StopTimer()
		now = time.Now()
		for j := 0; j < 100; j++ {
			now = now.Add(80 * time.Millisecond)
			analyzer.OnCharacter(now)
		}
		b.StartTimer()
	}
}

// BenchmarkCounterConcurrency benchmarks concurrent counter access.
func BenchmarkCounterConcurrency(b *testing.B) {
	counter := NewSimulated()
	ctx := context.Background()
	counter.Start(ctx)
	defer counter.Stop()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			counter.SimulateKeystroke()
			_ = counter.Count()
		}
	})
}

// BenchmarkEventCreation benchmarks Event struct creation.
func BenchmarkEventCreation(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		event := Event{
			Count:     uint64(i),
			Timestamp: time.Now(),
		}
		_ = event
	}
}

// BenchmarkVelocityThresholds benchmarks threshold operations.
func BenchmarkVelocityThresholds(b *testing.B) {
	b.Run("DefaultThresholds", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			thresholds := DefaultVelocityThresholds()
			_ = thresholds
		}
	})

	b.Run("CustomThresholds", func(b *testing.B) {
		thresholds := VelocityThresholds{
			HumanMax:        15.0,
			FastTypistMax:   30.0,
			DictationMax:    60.0,
			AutocompleteMax: 250.0,
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			analyzer := NewVelocityAnalyzerWithThresholds(thresholds)
			_ = analyzer
		}
	})
}

// BenchmarkVelocityClassString benchmarks velocity class string conversion.
func BenchmarkVelocityClassString(b *testing.B) {
	classes := []VelocityClass{VelocityHuman, VelocityFastTypist, VelocityDictation, VelocityAutocomplete, VelocityPaste}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		class := classes[i%len(classes)]
		s := class.String()
		_ = s
	}
}

// BenchmarkValidationStats benchmarks validation stats collection.
func BenchmarkValidationStats(b *testing.B) {
	stats := ValidationStats{
		CGEventTapCount:        10000,
		HIDCount:               9800,
		ValidatedCount:         9800,
		TotalSyntheticDetected: 200,
		Discrepancy:            200,
		HIDMonitorActive:       true,
		StrictMode:             true,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate accessing stats (would normally go through a method)
		total := stats.CGEventTapCount
		synthetic := stats.TotalSyntheticDetected
		_ = total
		_ = synthetic
	}
}

// BenchmarkSyntheticEventStats benchmarks synthetic event stats.
func BenchmarkSyntheticEventStats(b *testing.B) {
	stats := SyntheticEventStats{
		TotalRejected:           500,
		Suspicious:              150,
		RejectedBadSourceState:  100,
		RejectedBadKeyboardType: 50,
		RejectedNonKernelPID:    200,
		RejectedZeroTimestamp:   50,
		TotalEventsSeen:         50000,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate computing ratios
		rejectionRate := float64(stats.TotalRejected) / float64(stats.TotalEventsSeen)
		_ = rejectionRate
	}
}
