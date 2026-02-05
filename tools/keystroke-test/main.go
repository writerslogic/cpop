//go:build darwin

// Command keystroke-test is a manual testing tool for the CGEventTap keystroke counter.
//
// It checks accessibility permissions, starts the keystroke counter, and prints
// statistics every second until interrupted with Ctrl+C.
//
// Usage:
//
//	go build -o keystroke-test ./tools/keystroke-test
//	./keystroke-test
//
// Requirements:
//   - macOS
//   - Accessibility permissions must be granted to Terminal (or this binary)
//   - Go to System Preferences > Security & Privacy > Privacy > Accessibility
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"witnessd/internal/keystroke"
)

func main() {
	fmt.Println("Keystroke Counter Test")
	fmt.Println("======================")
	fmt.Println()

	// Check accessibility permissions
	fmt.Print("Checking accessibility permissions... ")
	if keystroke.CheckAccessibility() {
		fmt.Println("OK")
	} else {
		fmt.Println("DENIED")
		fmt.Println()
		fmt.Println("Accessibility permission is required for keystroke counting.")
		fmt.Println("Please grant access in System Preferences:")
		fmt.Println("  1. Open System Preferences")
		fmt.Println("  2. Go to Security & Privacy > Privacy > Accessibility")
		fmt.Println("  3. Add Terminal.app (or this binary)")
		fmt.Println()
		fmt.Print("Would you like to open the prompt now? (y/n): ")

		var response string
		fmt.Scanln(&response)
		if response == "y" || response == "Y" {
			fmt.Println("Opening accessibility prompt...")
			keystroke.PromptAccessibility()
			fmt.Println()
			fmt.Println("After granting permission, please restart this program.")
		}
		os.Exit(1)
	}

	// Create counter
	counter := keystroke.New()

	// Verify availability
	available, msg := counter.Available()
	fmt.Printf("Counter availability: %s\n", msg)
	if !available {
		fmt.Println("ERROR: Counter not available")
		os.Exit(1)
	}

	// Set up signal handling for clean shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the counter
	fmt.Print("Starting keystroke counter... ")
	if err := counter.Start(ctx); err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
	fmt.Println()
	fmt.Println("Counting keystrokes. Press Ctrl+C to stop.")
	fmt.Println()
	fmt.Println("Time        | Total | Delta | Rate (keys/sec)")
	fmt.Println("------------|-------|-------|----------------")

	// Subscribe to events (every 10 keystrokes)
	events := counter.Subscribe(10)

	// Reporting ticker
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	var lastCount uint64
	var lastTime = startTime

	// Main loop
	for {
		select {
		case <-sigChan:
			fmt.Println()
			fmt.Println("Received interrupt signal, stopping...")
			goto shutdown

		case <-events:
			// Just consume events - they're counted in the ticker report

		case now := <-ticker.C:
			count := counter.Count()
			delta := count - lastCount
			elapsed := now.Sub(lastTime).Seconds()

			var rate float64
			if elapsed > 0 {
				rate = float64(delta) / elapsed
			}

			runDuration := now.Sub(startTime).Truncate(time.Second)
			fmt.Printf("%11s | %5d | %5d | %.1f\n",
				runDuration.String(),
				count,
				delta,
				rate)

			lastCount = count
			lastTime = now

			// Check for DarwinCounter-specific diagnostics
			if dc, ok := counter.(*keystroke.DarwinCounter); ok {
				if tapDisables := dc.TapDisableCount(); tapDisables > 0 {
					fmt.Printf("  [Warning: tap was disabled by system %d time(s)]\n", tapDisables)
				}
			}
		}
	}

shutdown:
	// Stop the counter
	fmt.Print("Stopping counter... ")
	if err := counter.Stop(); err != nil {
		fmt.Printf("FAILED: %v\n", err)
	} else {
		fmt.Println("OK")
	}

	// Print final statistics
	totalDuration := time.Since(startTime)
	totalCount := counter.Count()

	fmt.Println()
	fmt.Println("Final Statistics")
	fmt.Println("----------------")
	fmt.Printf("Total keystrokes: %d\n", totalCount)
	fmt.Printf("Total duration:   %s\n", totalDuration.Truncate(time.Millisecond))
	if totalDuration.Seconds() > 0 {
		avgRate := float64(totalCount) / totalDuration.Seconds()
		fmt.Printf("Average rate:     %.2f keys/sec\n", avgRate)
	}

	fmt.Println()
	fmt.Println("Test completed successfully.")
}
