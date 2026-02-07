//go:build darwin || linux || windows

// Package keystroke provides velocity analysis for detecting autocomplete and predictive input.

package keystroke

import (
	"sync"
	"time"
)

// VelocityClass categorizes input based on character rate.
type VelocityClass int

const (
	VelocityHuman      VelocityClass = iota // Normal human typing (< 12 chars/sec)
	VelocityFastTypist                      // Fast typist (12-25 chars/sec)
	VelocityDictation                       // Voice dictation (25-50 chars/sec)
	VelocityAutocomplete                    // IDE autocomplete (50-200 chars/sec)
	VelocityPaste                           // Paste or synthetic (> 200 chars/sec)
)

func (v VelocityClass) String() string {
	switch v {
	case VelocityHuman:
		return "human"
	case VelocityFastTypist:
		return "fast_typist"
	case VelocityDictation:
		return "dictation"
	case VelocityAutocomplete:
		return "autocomplete"
	case VelocityPaste:
		return "paste"
	default:
		return "unknown"
	}
}

// VelocityThresholds defines the character-per-second thresholds for each class.
type VelocityThresholds struct {
	// Human: < HumanMax chars/sec (typical: 5-8, skilled: 10-12)
	HumanMax float64

	// FastTypist: HumanMax to FastTypistMax chars/sec (competitive typists)
	FastTypistMax float64

	// Dictation: FastTypistMax to DictationMax chars/sec (voice to text)
	DictationMax float64

	// Autocomplete: DictationMax to AutocompleteMax chars/sec (IDE completion)
	AutocompleteMax float64

	// Paste: > AutocompleteMax chars/sec (instant insertion)
}

// DefaultVelocityThresholds returns empirically-derived thresholds.
func DefaultVelocityThresholds() VelocityThresholds {
	return VelocityThresholds{
		HumanMax:        12.0,  // 12 chars/sec = ~70 WPM sustained
		FastTypistMax:   25.0,  // 25 chars/sec = ~150 WPM (competitive)
		DictationMax:    50.0,  // 50 chars/sec = voice-to-text typical
		AutocompleteMax: 200.0, // 200 chars/sec = IDE completion
		// > 200 chars/sec = paste or synthetic
	}
}

// VelocityBurst represents a detected burst of rapid input.
type VelocityBurst struct {
	StartTime  time.Time     // When the burst started
	EndTime    time.Time     // When the burst ended
	Duration   time.Duration // Duration of the burst
	CharCount  int           // Number of characters in the burst
	Velocity   float64       // Characters per second
	Class      VelocityClass // Classification of this burst
	Suspicious bool          // Whether this burst is suspicious for human input
}

// VelocityAnalyzer detects and classifies input velocity patterns.
type VelocityAnalyzer struct {
	mu sync.RWMutex

	thresholds VelocityThresholds

	// Configuration
	burstWindow     time.Duration // Max gap between chars to be considered same burst
	minBurstSize    int           // Minimum chars to analyze as a burst
	suspiciousLevel VelocityClass // Threshold for flagging as suspicious

	// State
	lastCharTime    time.Time
	burstStartTime  time.Time
	burstCharCount  int
	inBurst         bool

	// Statistics
	bursts         []VelocityBurst
	maxBursts      int // Maximum bursts to retain
	totalChars     int
	suspiciousBursts int
	classCounts    map[VelocityClass]int
}

// NewVelocityAnalyzer creates a velocity analyzer with default settings.
func NewVelocityAnalyzer() *VelocityAnalyzer {
	return &VelocityAnalyzer{
		thresholds:      DefaultVelocityThresholds(),
		burstWindow:     150 * time.Millisecond, // 150ms gap = same burst
		minBurstSize:    5,                       // Need at least 5 chars
		suspiciousLevel: VelocityAutocomplete,    // Flag autocomplete+ as suspicious
		maxBursts:       1000,
		classCounts:     make(map[VelocityClass]int),
	}
}

// NewVelocityAnalyzerWithThresholds creates an analyzer with custom thresholds.
func NewVelocityAnalyzerWithThresholds(t VelocityThresholds) *VelocityAnalyzer {
	va := NewVelocityAnalyzer()
	va.thresholds = t
	return va
}

// SetSuspiciousLevel sets which velocity class triggers suspicious flagging.
func (va *VelocityAnalyzer) SetSuspiciousLevel(level VelocityClass) {
	va.mu.Lock()
	defer va.mu.Unlock()
	va.suspiciousLevel = level
}

// OnCharacter processes a character input event.
// Returns the burst info if a burst just ended, nil otherwise.
func (va *VelocityAnalyzer) OnCharacter(now time.Time) *VelocityBurst {
	va.mu.Lock()
	defer va.mu.Unlock()

	va.totalChars++

	// First character
	if va.lastCharTime.IsZero() {
		va.lastCharTime = now
		va.burstStartTime = now
		va.burstCharCount = 1
		va.inBurst = true
		return nil
	}

	interval := now.Sub(va.lastCharTime)
	va.lastCharTime = now

	// Within burst window?
	if interval <= va.burstWindow {
		// Continue or start burst
		if !va.inBurst {
			va.burstStartTime = now.Add(-interval)
			va.burstCharCount = 1
		}
		va.inBurst = true
		va.burstCharCount++
		return nil
	}

	// Burst ended - analyze it
	var result *VelocityBurst
	if va.inBurst && va.burstCharCount >= va.minBurstSize {
		result = va.analyzeBurst(va.burstStartTime, va.lastCharTime.Add(-interval), va.burstCharCount)
	}

	// Start new potential burst
	va.inBurst = true
	va.burstStartTime = now
	va.burstCharCount = 1

	return result
}

// FlushBurst forces analysis of the current burst (call at end of input session).
func (va *VelocityAnalyzer) FlushBurst() *VelocityBurst {
	va.mu.Lock()
	defer va.mu.Unlock()

	if va.inBurst && va.burstCharCount >= va.minBurstSize {
		result := va.analyzeBurst(va.burstStartTime, va.lastCharTime, va.burstCharCount)
		va.inBurst = false
		va.burstCharCount = 0
		return result
	}
	return nil
}

// analyzeBurst classifies and records a completed burst.
func (va *VelocityAnalyzer) analyzeBurst(start, end time.Time, chars int) *VelocityBurst {
	duration := end.Sub(start)
	if duration <= 0 {
		duration = time.Millisecond // Minimum 1ms
	}

	velocity := float64(chars) / duration.Seconds()
	class := va.classifyVelocity(velocity)

	burst := &VelocityBurst{
		StartTime:  start,
		EndTime:    end,
		Duration:   duration,
		CharCount:  chars,
		Velocity:   velocity,
		Class:      class,
		Suspicious: class >= va.suspiciousLevel,
	}

	// Record statistics
	va.classCounts[class]++
	if burst.Suspicious {
		va.suspiciousBursts++
	}

	// Store burst (with size limit)
	if len(va.bursts) >= va.maxBursts {
		va.bursts = va.bursts[len(va.bursts)/2:]
	}
	va.bursts = append(va.bursts, *burst)

	return burst
}

// classifyVelocity determines the class for a given velocity.
func (va *VelocityAnalyzer) classifyVelocity(charsPerSec float64) VelocityClass {
	switch {
	case charsPerSec <= va.thresholds.HumanMax:
		return VelocityHuman
	case charsPerSec <= va.thresholds.FastTypistMax:
		return VelocityFastTypist
	case charsPerSec <= va.thresholds.DictationMax:
		return VelocityDictation
	case charsPerSec <= va.thresholds.AutocompleteMax:
		return VelocityAutocomplete
	default:
		return VelocityPaste
	}
}

// VelocityStats contains aggregate velocity statistics.
type VelocityStats struct {
	TotalCharacters     int                    `json:"total_characters"`
	TotalBursts         int                    `json:"total_bursts"`
	SuspiciousBursts    int                    `json:"suspicious_bursts"`
	BurstsByClass       map[string]int         `json:"bursts_by_class"`
	SuspiciousRatio     float64                `json:"suspicious_ratio"`
	MaxVelocity         float64                `json:"max_velocity"`
	AvgBurstVelocity    float64                `json:"avg_burst_velocity"`
	AutocompleteChars   int                    `json:"autocomplete_chars"`
	PasteChars          int                    `json:"paste_chars"`
}

// Stats returns aggregate velocity statistics.
func (va *VelocityAnalyzer) Stats() VelocityStats {
	va.mu.RLock()
	defer va.mu.RUnlock()

	stats := VelocityStats{
		TotalCharacters:  va.totalChars,
		TotalBursts:      len(va.bursts),
		SuspiciousBursts: va.suspiciousBursts,
		BurstsByClass:    make(map[string]int),
	}

	// Convert class counts to string keys
	for class, count := range va.classCounts {
		stats.BurstsByClass[class.String()] = count
	}

	if len(va.bursts) > 0 {
		var totalVelocity float64
		for _, b := range va.bursts {
			totalVelocity += b.Velocity
			if b.Velocity > stats.MaxVelocity {
				stats.MaxVelocity = b.Velocity
			}
			if b.Class == VelocityAutocomplete {
				stats.AutocompleteChars += b.CharCount
			} else if b.Class == VelocityPaste {
				stats.PasteChars += b.CharCount
			}
		}
		stats.AvgBurstVelocity = totalVelocity / float64(len(va.bursts))
		stats.SuspiciousRatio = float64(va.suspiciousBursts) / float64(len(va.bursts))
	}

	return stats
}

// RecentBursts returns the N most recent bursts.
func (va *VelocityAnalyzer) RecentBursts(n int) []VelocityBurst {
	va.mu.RLock()
	defer va.mu.RUnlock()

	if n > len(va.bursts) {
		n = len(va.bursts)
	}
	if n <= 0 {
		return nil
	}

	result := make([]VelocityBurst, n)
	copy(result, va.bursts[len(va.bursts)-n:])
	return result
}

// SuspiciousBurstsList returns all suspicious bursts.
func (va *VelocityAnalyzer) SuspiciousBurstsList() []VelocityBurst {
	va.mu.RLock()
	defer va.mu.RUnlock()

	var result []VelocityBurst
	for _, b := range va.bursts {
		if b.Suspicious {
			result = append(result, b)
		}
	}
	return result
}

// Reset clears all state and statistics.
func (va *VelocityAnalyzer) Reset() {
	va.mu.Lock()
	defer va.mu.Unlock()

	va.lastCharTime = time.Time{}
	va.burstStartTime = time.Time{}
	va.burstCharCount = 0
	va.inBurst = false
	va.bursts = nil
	va.totalChars = 0
	va.suspiciousBursts = 0
	va.classCounts = make(map[VelocityClass]int)
}

// IsSuspiciousBurst is a convenience function for simple burst detection.
// Returns true if the given character count in the given duration suggests
// non-human input (autocomplete or paste).
func IsSuspiciousBurst(chars int, duration time.Duration) bool {
	if duration <= 0 {
		return chars > 1 // Multiple chars in zero time is suspicious
	}
	velocity := float64(chars) / duration.Seconds()
	thresholds := DefaultVelocityThresholds()
	return velocity > thresholds.DictationMax // > 50 chars/sec
}

// ClassifyVelocity returns the class for a given velocity (standalone function).
func ClassifyVelocity(charsPerSec float64) VelocityClass {
	thresholds := DefaultVelocityThresholds()
	switch {
	case charsPerSec <= thresholds.HumanMax:
		return VelocityHuman
	case charsPerSec <= thresholds.FastTypistMax:
		return VelocityFastTypist
	case charsPerSec <= thresholds.DictationMax:
		return VelocityDictation
	case charsPerSec <= thresholds.AutocompleteMax:
		return VelocityAutocomplete
	default:
		return VelocityPaste
	}
}
