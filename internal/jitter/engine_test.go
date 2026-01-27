package jitter

import (
	"crypto/sha256"
	"testing"
	"time"
)

func TestJitterEngineBasic(t *testing.T) {
	secret := sha256.Sum256([]byte("test-secret"))
	engine := NewJitterEngine(secret)

	docHash := sha256.Sum256([]byte("test document"))

	// Simulate typing "the"
	// t = keycode 0x11 (zone 3)
	// h = keycode 0x04 (zone 4)
	// e = keycode 0x0E (zone 2)

	jitter1, sample1 := engine.OnKeystroke(0x11, docHash) // t
	if sample1 == nil {
		t.Log("First keystroke has no previous zone, sample may be nil or special")
	}
	_ = jitter1

	time.Sleep(50 * time.Millisecond)

	jitter2, sample2 := engine.OnKeystroke(0x04, docHash) // h
	if jitter2 < MinJitter || jitter2 > MaxJitter {
		t.Errorf("Jitter out of range: %d", jitter2)
	}
	if sample2 == nil {
		t.Error("Expected sample after second keystroke")
	}

	time.Sleep(50 * time.Millisecond)

	jitter3, sample3 := engine.OnKeystroke(0x0E, docHash) // e
	if jitter3 < MinJitter || jitter3 > MaxJitter {
		t.Errorf("Jitter out of range: %d", jitter3)
	}

	// Verify samples are chained (different jitter values due to different inputs)
	if sample2 != nil && sample3 != nil {
		if sample2.JitterMicros == sample3.JitterMicros {
			t.Log("Warning: same jitter values (possible but unlikely)")
		}
	}
}

func TestJitterDeterminism(t *testing.T) {
	secret := sha256.Sum256([]byte("determinism-test"))
	docHash := sha256.Sum256([]byte("document"))

	// Create two engines with same secret
	engine1 := NewJitterEngine(secret)
	engine2 := NewJitterEngine(secret)

	// Same inputs should produce same jitter
	fixedTime := time.Date(2026, 1, 25, 12, 0, 0, 0, time.UTC)

	// We need to test the internal computeJitter directly for determinism
	// since OnKeystroke uses time.Now()

	j1 := engine1.computeJitter(docHash, EncodeZoneTransition(3, 4), 1, fixedTime)
	j2 := engine2.computeJitter(docHash, EncodeZoneTransition(3, 4), 1, fixedTime)

	if j1 != j2 {
		t.Errorf("Same inputs should produce same jitter: %d != %d", j1, j2)
	}
}

func TestJitterZoneCommitment(t *testing.T) {
	secret := sha256.Sum256([]byte("zone-commitment-test"))
	docHash := sha256.Sum256([]byte("document"))
	fixedTime := time.Date(2026, 1, 25, 12, 0, 0, 0, time.UTC)

	engine := NewJitterEngine(secret)

	// Different zone transitions should produce different jitter
	j1 := engine.computeJitter(docHash, EncodeZoneTransition(0, 4), 1, fixedTime)

	engine2 := NewJitterEngine(secret)
	j2 := engine2.computeJitter(docHash, EncodeZoneTransition(3, 7), 1, fixedTime)

	if j1 == j2 {
		t.Error("Different zone transitions should produce different jitter")
	}
}

func TestTypingProfile(t *testing.T) {
	secret := sha256.Sum256([]byte("profile-test"))
	engine := NewJitterEngine(secret)
	docHash := sha256.Sum256([]byte("document"))

	// Simulate alternating hand typing
	// Left hand keys: q(0x0C), w(0x0D), e(0x0E)
	// Right hand keys: i(0x22), o(0x1F), p(0x23)

	keys := []uint16{0x0C, 0x22, 0x0D, 0x1F, 0x0E, 0x23} // q, i, w, o, e, p

	for _, k := range keys {
		engine.OnKeystroke(k, docHash)
		time.Sleep(50 * time.Millisecond)
	}

	profile := engine.Profile()

	if profile.TotalTransitions != 5 {
		t.Errorf("Expected 5 transitions, got %d", profile.TotalTransitions)
	}

	// All transitions should be alternating (left->right or right->left)
	if profile.HandAlternation < 0.9 {
		t.Errorf("Expected high hand alternation ratio, got %.2f", profile.HandAlternation)
	}
}

func TestCompareProfiles(t *testing.T) {
	// Two identical profiles should have similarity 1.0
	profileA := TypingProfile{
		SameFingerHist:   [10]uint32{5, 10, 15, 20, 10, 5, 0, 0, 0, 0},
		SameHandHist:     [10]uint32{10, 20, 30, 25, 15, 5, 0, 0, 0, 0},
		AlternatingHist:  [10]uint32{20, 40, 50, 30, 15, 5, 0, 0, 0, 0},
		HandAlternation:  0.55,
		TotalTransitions: 100,
	}

	similarity := CompareProfiles(profileA, profileA)
	if similarity < 0.99 {
		t.Errorf("Identical profiles should have similarity ~1.0, got %.4f", similarity)
	}

	// Two very different profiles should have low similarity
	profileB := TypingProfile{
		SameFingerHist:   [10]uint32{0, 0, 0, 0, 0, 5, 10, 20, 30, 40},
		SameHandHist:     [10]uint32{0, 0, 0, 0, 5, 10, 20, 30, 25, 15},
		AlternatingHist:  [10]uint32{0, 0, 0, 5, 10, 20, 30, 40, 35, 20},
		HandAlternation:  0.25,
		TotalTransitions: 100,
	}

	similarity2 := CompareProfiles(profileA, profileB)
	if similarity2 > 0.5 {
		t.Errorf("Very different profiles should have low similarity, got %.4f", similarity2)
	}

	// Empty profile comparison
	emptyProfile := TypingProfile{}
	similarity3 := CompareProfiles(emptyProfile, profileA)
	if similarity3 != 0.0 {
		t.Errorf("Empty profile comparison should return 0.0, got %.4f", similarity3)
	}
}

func TestIsHumanPlausible(t *testing.T) {
	// Plausible human profile
	humanProfile := TypingProfile{
		SameFingerHist:   [10]uint32{2, 5, 8, 10, 8, 5, 2, 0, 0, 0},
		SameHandHist:     [10]uint32{10, 20, 25, 30, 25, 15, 5, 0, 0, 0},
		AlternatingHist:  [10]uint32{20, 40, 50, 45, 30, 15, 5, 0, 0, 0},
		HandAlternation:  0.50,
		TotalTransitions: 200,
	}

	if !IsHumanPlausible(humanProfile) {
		t.Error("Human-like profile should be plausible")
	}

	// Robotic profile (all same timing)
	roboticProfile := TypingProfile{
		SameFingerHist:   [10]uint32{100, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		SameHandHist:     [10]uint32{200, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		AlternatingHist:  [10]uint32{300, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		HandAlternation:  0.50,
		TotalTransitions: 600,
	}

	if IsHumanPlausible(roboticProfile) {
		t.Error("Robotic profile (all same timing) should not be plausible")
	}

	// Profile with extreme hand alternation
	extremeProfile := TypingProfile{
		SameFingerHist:   [10]uint32{5, 10, 15, 10, 5, 0, 0, 0, 0, 0},
		SameHandHist:     [10]uint32{10, 20, 30, 20, 10, 0, 0, 0, 0, 0},
		AlternatingHist:  [10]uint32{5, 5, 5, 5, 5, 0, 0, 0, 0, 0},
		HandAlternation:  0.10, // Very low - mostly one-handed
		TotalTransitions: 150,
	}

	if IsHumanPlausible(extremeProfile) {
		t.Error("Extreme one-handed profile should not be plausible")
	}
}

func TestProfileDistance(t *testing.T) {
	profileA := TypingProfile{
		SameFingerHist:   [10]uint32{5, 10, 15, 20, 10, 5, 0, 0, 0, 0},
		SameHandHist:     [10]uint32{10, 20, 30, 25, 15, 5, 0, 0, 0, 0},
		AlternatingHist:  [10]uint32{20, 40, 50, 30, 15, 5, 0, 0, 0, 0},
		HandAlternation:  0.55,
		TotalTransitions: 100,
	}

	// Distance to self should be ~0
	distSelf := ProfileDistance(profileA, profileA)
	if distSelf > 0.001 {
		t.Errorf("Distance to self should be ~0, got %.6f", distSelf)
	}

	// Distance to different profile should be >0
	profileB := TypingProfile{
		SameFingerHist:   [10]uint32{0, 0, 0, 0, 0, 5, 10, 20, 30, 40},
		SameHandHist:     [10]uint32{0, 0, 0, 0, 5, 10, 20, 30, 25, 15},
		AlternatingHist:  [10]uint32{0, 0, 0, 5, 10, 20, 30, 40, 35, 20},
		HandAlternation:  0.25,
		TotalTransitions: 100,
	}

	distDiff := ProfileDistance(profileA, profileB)
	if distDiff < 0.1 {
		t.Errorf("Distance to different profile should be significant, got %.6f", distDiff)
	}
}

func TestVerifyWithContentBasic(t *testing.T) {
	secret := sha256.Sum256([]byte("content-verify-test"))
	engine := NewJitterEngine(secret)

	// Simulate typing "the" and collect samples
	content := "the"
	docHash := sha256.Sum256([]byte(content))

	var samples []JitterSample

	// t = keycode 0x11 (zone 3)
	_, sample1 := engine.OnKeystroke(0x11, docHash)
	if sample1 != nil {
		samples = append(samples, *sample1)
	}

	time.Sleep(50 * time.Millisecond)

	// h = keycode 0x04 (zone 4)
	_, sample2 := engine.OnKeystroke(0x04, docHash)
	if sample2 != nil {
		samples = append(samples, *sample2)
	}

	time.Sleep(50 * time.Millisecond)

	// e = keycode 0x0E (zone 2)
	_, sample3 := engine.OnKeystroke(0x0E, docHash)
	if sample3 != nil {
		samples = append(samples, *sample3)
	}

	// Statistical verification (no secret needed)
	result := VerifyWithContent(samples, []byte(content))

	// Chain should be valid
	if !result.ChainValid {
		t.Errorf("Chain should be valid: %v", result.Errors)
	}

	// Zone divergence should be reasonable for typed content
	t.Logf("Zone divergence: %.4f", result.ZoneDivergence)
	t.Logf("Profile score: %.4f", result.ProfileScore)
	t.Logf("Recorded transitions: %d", result.RecordedProfile.TotalTransitions)
	t.Logf("Expected transitions: %d", result.ExpectedProfile.TotalTransitions)

	// Cryptographic verification with secret
	if err := VerifyWithSecret(samples, secret); err != nil {
		t.Errorf("Cryptographic verification should pass: %v", err)
	}

	// Verification with wrong secret should fail
	wrongSecret := sha256.Sum256([]byte("wrong-secret"))
	if err := VerifyWithSecret(samples, wrongSecret); err == nil {
		t.Error("Verification with wrong secret should fail")
	}
}

func TestVerifyJitterChain(t *testing.T) {
	secret := sha256.Sum256([]byte("chain-test"))
	engine := NewJitterEngine(secret)
	docHash := sha256.Sum256([]byte("test"))

	var samples []JitterSample

	// Generate a chain of samples
	keys := []uint16{0x0C, 0x22, 0x0D, 0x1F, 0x0E} // q, i, w, o, e
	for _, k := range keys {
		_, sample := engine.OnKeystroke(k, docHash)
		if sample != nil {
			samples = append(samples, *sample)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Verify the chain
	err := VerifyJitterChain(samples)
	if err != nil {
		t.Errorf("Valid chain should verify: %v", err)
	}

	// Test with empty chain
	err = VerifyJitterChain([]JitterSample{})
	if err != ErrEmptyChain {
		t.Errorf("Empty chain should return ErrEmptyChain, got %v", err)
	}
}

func TestQuickVerifyProfile(t *testing.T) {
	// Human-like profile should have no issues
	humanProfile := TypingProfile{
		SameFingerHist:   [10]uint32{2, 5, 8, 10, 8, 5, 2, 0, 0, 0},
		SameHandHist:     [10]uint32{10, 20, 25, 30, 25, 15, 5, 0, 0, 0},
		AlternatingHist:  [10]uint32{20, 40, 50, 45, 30, 15, 5, 0, 0, 0},
		HandAlternation:  0.50,
		TotalTransitions: 200,
	}

	issues := QuickVerifyProfile(humanProfile)
	if len(issues) > 0 {
		t.Errorf("Human profile should have no issues, got: %v", issues)
	}

	// Robotic profile should have issues
	roboticProfile := TypingProfile{
		SameFingerHist:   [10]uint32{100, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		SameHandHist:     [10]uint32{200, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		AlternatingHist:  [10]uint32{300, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		HandAlternation:  0.50,
		TotalTransitions: 600,
	}

	issues = QuickVerifyProfile(roboticProfile)
	if len(issues) == 0 {
		t.Error("Robotic profile should have issues")
	}
}

func TestStatisticalVerificationCatchesFabrication(t *testing.T) {
	// Scenario: Attacker claims to have typed "hello world"
	// but provides zone transitions for completely different content

	claimedContent := []byte("hello world")

	// Create fabricated samples with wrong zone transitions
	// Real "hello world" would have zones: 4-2-6-6-6 (space) 1-6-3-6-2
	// Fabricator uses only left-hand zones (0-3)
	fabricatedSamples := []JitterSample{
		{Ordinal: 1, Timestamp: time.Now(), ZoneTransition: EncodeZoneTransition(0, 1), IntervalBucket: 2, JitterMicros: 1500},
		{Ordinal: 2, Timestamp: time.Now().Add(50 * time.Millisecond), ZoneTransition: EncodeZoneTransition(1, 2), IntervalBucket: 2, JitterMicros: 1600},
		{Ordinal: 3, Timestamp: time.Now().Add(100 * time.Millisecond), ZoneTransition: EncodeZoneTransition(2, 3), IntervalBucket: 2, JitterMicros: 1700},
		{Ordinal: 4, Timestamp: time.Now().Add(150 * time.Millisecond), ZoneTransition: EncodeZoneTransition(3, 0), IntervalBucket: 2, JitterMicros: 1800},
		{Ordinal: 5, Timestamp: time.Now().Add(200 * time.Millisecond), ZoneTransition: EncodeZoneTransition(0, 1), IntervalBucket: 2, JitterMicros: 1900},
	}

	// Compute proper hashes for the fabricated samples
	for i := range fabricatedSamples {
		fabricatedSamples[i].SampleHash = computeJitterSampleHash(&fabricatedSamples[i])
	}

	result := VerifyWithContent(fabricatedSamples, claimedContent)

	// Chain should be structurally valid (attacker can make valid hashes)
	if !result.ChainValid {
		t.Log("Chain validity:", result.ChainValid)
	}

	// But zone divergence should be high
	t.Logf("Fabricated zone divergence: %.4f", result.ZoneDivergence)
	t.Logf("Fabricated hand alternation (recorded): %.2f", result.RecordedProfile.HandAlternation)
	t.Logf("Expected hand alternation: %.2f", result.ExpectedProfile.HandAlternation)

	// The fabricated samples are all left-hand (zones 0-3), so hand alternation = 0
	// Real "hello world" has significant hand alternation
	if result.RecordedProfile.HandAlternation > 0.1 {
		t.Error("Fabricated evidence has too much alternation")
	}

	// Zone distribution should differ significantly
	if result.ZoneDivergence < 0.5 {
		t.Errorf("Expected high divergence for fabricated zones, got %.4f", result.ZoneDivergence)
	}
}

func TestStatisticalVerificationPassesLegitimate(t *testing.T) {
	// Scenario: User legitimately types "the quick brown fox"
	secret := sha256.Sum256([]byte("legitimate-typing"))
	engine := NewJitterEngine(secret)

	content := "the quick brown fox"
	docHash := sha256.Sum256([]byte(content))

	// Simulate typing with correct keycodes
	keycodes := []uint16{
		0x11, 0x04, 0x0E, // the
		0x0C, 0x1F, 0x22, 0x02, 0x28, // quick (q, u, i, c, k)
		0x0B, 0x03, 0x1F, 0x1E, 0x2E, // brown (b, r, o, w, n)
		0x03, 0x1F, 0x07, // fox (f, o, x)
	}

	var samples []JitterSample
	for _, kc := range keycodes {
		_, sample := engine.OnKeystroke(kc, docHash)
		if sample != nil {
			samples = append(samples, *sample)
		}
		time.Sleep(30 * time.Millisecond)
	}

	result := VerifyWithContent(samples, []byte(content))

	t.Logf("Legitimate zone divergence: %.4f", result.ZoneDivergence)
	t.Logf("Legitimate profile score: %.4f", result.ProfileScore)
	t.Logf("Legitimate hand alternation (recorded): %.2f", result.RecordedProfile.HandAlternation)
	t.Logf("Legitimate hand alternation (expected): %.2f", result.ExpectedProfile.HandAlternation)

	// Chain should be valid
	if !result.ChainValid {
		t.Errorf("Legitimate chain should be valid: %v", result.Errors)
	}

	// Zones should be compatible (low divergence)
	if result.ZoneDivergence > 1.0 {
		t.Errorf("Legitimate evidence should have low zone divergence, got %.4f", result.ZoneDivergence)
	}

	// Cryptographic verification should pass
	if err := VerifyWithSecret(samples, secret); err != nil {
		t.Errorf("Cryptographic verification should pass: %v", err)
	}
}

// TestRealisticAuthorshipSession simulates a realistic writing session:
// - Multi-paragraph document
// - Variable typing speeds (thinking pauses, bursts)
// - Document evolves through multiple states
// - Includes common typing patterns
func TestRealisticAuthorshipSession(t *testing.T) {
	secret := sha256.Sum256([]byte("realistic-authorship-test"))
	engine := NewJitterEngine(secret)

	// Realistic document: opening paragraph of an essay
	finalContent := `The concept of digital authorship has evolved significantly
in the age of artificial intelligence. Writers now face unprecedented questions
about creativity, originality, and the nature of human expression. This essay
explores how cryptographic witnessing can provide verifiable proof of the
creative process, distinguishing human-authored content from machine-generated text.`

	// Simulate typing in stages with evolving document states
	var samples []JitterSample
	var currentDoc string

	// Stage 1: First sentence (fast typing, familiar words)
	stage1 := "The concept of digital authorship has evolved significantly"
	samples = append(samples, simulateTypingStage(t, engine, stage1, &currentDoc, 40, 80)...)

	// Stage 2: Pause to think, then continue (slower, more deliberate)
	stage2 := " in the age of artificial intelligence."
	samples = append(samples, simulateTypingStage(t, engine, stage2, &currentDoc, 80, 150)...)

	// Stage 3: New sentence (medium pace)
	stage3 := " Writers now face unprecedented questions about creativity, originality, and the nature of human expression."
	samples = append(samples, simulateTypingStage(t, engine, stage3, &currentDoc, 50, 100)...)

	// Stage 4: Thesis statement (slow, careful typing)
	stage4 := " This essay explores how cryptographic witnessing can provide verifiable proof of the creative process,"
	samples = append(samples, simulateTypingStage(t, engine, stage4, &currentDoc, 70, 120)...)

	// Stage 5: Conclusion of intro (faster, momentum)
	stage5 := " distinguishing human-authored content from machine-generated text."
	samples = append(samples, simulateTypingStage(t, engine, stage5, &currentDoc, 35, 70)...)

	t.Logf("=== Realistic Authorship Session ===")
	t.Logf("Final document length: %d characters", len(finalContent))
	t.Logf("Total samples collected: %d", len(samples))
	t.Logf("Unique document states: %d", countUniqueDocHashes(samples))

	// Calculate session duration
	if len(samples) > 1 {
		duration := samples[len(samples)-1].Timestamp.Sub(samples[0].Timestamp)
		keystrokesPerMin := float64(len(samples)) / duration.Minutes()
		t.Logf("Session duration: %s", duration.Round(time.Millisecond))
		t.Logf("Effective typing rate: %.0f keystrokes/min", keystrokesPerMin)
	}

	// Verify with statistical model
	result := VerifyWithContent(samples, []byte(currentDoc))

	t.Logf("\n=== Statistical Verification ===")
	t.Logf("Chain valid: %v", result.ChainValid)
	t.Logf("Zones compatible: %v", result.ZonesCompatible)
	t.Logf("Profile plausible: %v", result.ProfilePlausible)
	t.Logf("Zone divergence: %.4f (threshold: 2.0)", result.ZoneDivergence)
	t.Logf("Profile score: %.4f", result.ProfileScore)

	t.Logf("\n=== Zone Distribution ===")
	t.Logf("Recorded - Same finger: %d, Same hand: %d, Alternating: %d",
		sumHist(result.RecordedProfile.SameFingerHist[:]),
		sumHist(result.RecordedProfile.SameHandHist[:]),
		sumHist(result.RecordedProfile.AlternatingHist[:]))
	t.Logf("Expected - Same finger: %d, Same hand: %d, Alternating: %d",
		sumHist(result.ExpectedProfile.SameFingerHist[:]),
		sumHist(result.ExpectedProfile.SameHandHist[:]),
		sumHist(result.ExpectedProfile.AlternatingHist[:]))
	t.Logf("Hand alternation: recorded=%.2f, expected=%.2f",
		result.RecordedProfile.HandAlternation, result.ExpectedProfile.HandAlternation)

	// Assertions
	if !result.ChainValid {
		t.Errorf("Chain should be valid: %v", result.Errors)
	}

	if !result.ZonesCompatible {
		t.Errorf("Zones should be compatible for legitimate typing")
	}

	if !result.ProfilePlausible {
		t.Errorf("Profile should be human-plausible")
	}

	if result.ZoneDivergence > 1.0 {
		t.Errorf("Zone divergence too high for legitimate typing: %.4f", result.ZoneDivergence)
	}

	// Verify cryptographically
	if err := VerifyWithSecret(samples, secret); err != nil {
		t.Errorf("Cryptographic verification failed: %v", err)
	}

	// Verify wrong secret fails
	wrongSecret := sha256.Sum256([]byte("attacker-secret"))
	if err := VerifyWithSecret(samples, wrongSecret); err == nil {
		t.Error("Wrong secret should fail cryptographic verification")
	}
}

// simulateTypingStage simulates typing a chunk of text with variable timing
func simulateTypingStage(t *testing.T, engine *JitterEngine, text string, currentDoc *string, minDelayMs, maxDelayMs int) []JitterSample {
	var samples []JitterSample

	for _, char := range text {
		*currentDoc += string(char)
		docHash := sha256.Sum256([]byte(*currentDoc))

		keyCode := charToKeyCode(char)
		if keyCode == 0xFFFF {
			continue // Skip unmapped characters
		}

		_, sample := engine.OnKeystroke(keyCode, docHash)
		if sample != nil {
			samples = append(samples, *sample)
		}

		// Variable delay: faster for common patterns, slower for uncommon
		delay := minDelayMs + int(pseudoRandom(uint64(char))%uint64(maxDelayMs-minDelayMs))
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	return samples
}

// charToKeyCode maps characters to macOS virtual key codes
func charToKeyCode(c rune) uint16 {
	switch c {
	// Letters (lowercase and uppercase map to same keycode)
	case 'a', 'A':
		return 0x00
	case 's', 'S':
		return 0x01
	case 'd', 'D':
		return 0x02
	case 'f', 'F':
		return 0x03
	case 'h', 'H':
		return 0x04
	case 'g', 'G':
		return 0x05
	case 'z', 'Z':
		return 0x06
	case 'x', 'X':
		return 0x07
	case 'c', 'C':
		return 0x08
	case 'v', 'V':
		return 0x09
	case 'b', 'B':
		return 0x0B
	case 'q', 'Q':
		return 0x0C
	case 'w', 'W':
		return 0x0D
	case 'e', 'E':
		return 0x0E
	case 'r', 'R':
		return 0x0F
	case 'y', 'Y':
		return 0x10
	case 't', 'T':
		return 0x11
	case 'o', 'O':
		return 0x1F
	case 'u', 'U':
		return 0x20
	case 'i', 'I':
		return 0x22
	case 'p', 'P':
		return 0x23
	case 'l', 'L':
		return 0x25
	case 'j', 'J':
		return 0x26
	case 'k', 'K':
		return 0x28
	case 'n', 'N':
		return 0x2D
	case 'm', 'M':
		return 0x2E
	case ',':
		return 0x2B
	case '.':
		return 0x2F
	case ';', ':':
		return 0x29
	case '/', '?':
		return 0x2C
	// Non-zone keys return special marker
	case ' ', '\n', '\t', '-', '\'', '"':
		return 0xFFFF
	default:
		return 0xFFFF
	}
}

// pseudoRandom generates a deterministic "random" number from a seed
func pseudoRandom(seed uint64) uint64 {
	seed = seed*6364136223846793005 + 1442695040888963407
	return seed
}

// countUniqueDocHashes counts unique document states in samples
func countUniqueDocHashes(samples []JitterSample) int {
	seen := make(map[[32]byte]bool)
	for _, s := range samples {
		seen[s.DocHash] = true
	}
	return len(seen)
}

// sumHist sums all values in a histogram
func sumHist(hist []uint32) uint64 {
	var sum uint64
	for _, v := range hist {
		sum += uint64(v)
	}
	return sum
}

// TestRealisticFabricationAttempt simulates an attacker trying to fabricate
// evidence for a document they didn't type
func TestRealisticFabricationAttempt(t *testing.T) {
	// The attacker has the final document but didn't type it
	stolenDocument := `The concept of digital authorship has evolved significantly
in the age of artificial intelligence. Writers now face unprecedented questions
about creativity, originality, and the nature of human expression.`

	// Attacker creates fake evidence
	// Strategy 1: Random zone transitions (naive attack)
	t.Run("NaiveRandomZones", func(t *testing.T) {
		samples := fabricateNaiveEvidence(stolenDocument, 200)
		result := VerifyWithContent(samples, []byte(stolenDocument))

		t.Logf("Naive attack - Transition divergence: %.4f (threshold: 0.3)", result.TransitionDivergence)
		t.Logf("Naive attack - Zones compatible: %v", result.ZonesCompatible)

		// Random zones should have high transition divergence
		// Real text has specific transitions (e.g., "th" always = 3→4)
		// Random zones spread across all 64 possible transitions
		if result.ZonesCompatible {
			t.Errorf("Random zone fabrication should be detected, divergence: %.4f", result.TransitionDivergence)
		}
	})

	// Strategy 2: All same-hand transitions (one-handed typing claim)
	t.Run("OneHandedFabrication", func(t *testing.T) {
		samples := fabricateOneHandedEvidence(stolenDocument, 200)
		result := VerifyWithContent(samples, []byte(stolenDocument))

		t.Logf("One-handed attack - Zone divergence: %.4f", result.ZoneDivergence)
		t.Logf("One-handed attack - Hand alternation: recorded=%.2f, expected=%.2f",
			result.RecordedProfile.HandAlternation, result.ExpectedProfile.HandAlternation)

		// Should fail plausibility check (extreme hand alternation)
		if result.ProfilePlausible {
			t.Error("One-handed fabrication should fail plausibility")
		}
	})

	// Strategy 3: Robotic timing (all same interval bucket)
	t.Run("RoboticTiming", func(t *testing.T) {
		samples := fabricateRoboticEvidence(stolenDocument, 200)
		result := VerifyWithContent(samples, []byte(stolenDocument))

		t.Logf("Robotic attack - Profile plausible: %v", result.ProfilePlausible)

		// Check timing distribution
		var bucket0Count uint64
		for i := 0; i < 10; i++ {
			if i == 2 { // All samples in bucket 2
				bucket0Count += uint64(result.RecordedProfile.SameFingerHist[i])
				bucket0Count += uint64(result.RecordedProfile.SameHandHist[i])
				bucket0Count += uint64(result.RecordedProfile.AlternatingHist[i])
			}
		}

		t.Logf("Robotic attack - Samples in single bucket: %d/%d",
			bucket0Count, result.RecordedProfile.TotalTransitions)
	})

	// Strategy 4: Sophisticated attack - tries to match expected zone distribution
	t.Run("SophisticatedZoneMatching", func(t *testing.T) {
		// Attacker analyzes the document and creates matching zone distribution
		expectedProfile := AnalyzeDocumentZones([]byte(stolenDocument))

		samples := fabricateSophisticatedEvidence(stolenDocument, expectedProfile, 200)
		result := VerifyWithContent(samples, []byte(stolenDocument))

		t.Logf("Sophisticated attack - Zone divergence: %.4f", result.ZoneDivergence)
		t.Logf("Sophisticated attack - Profile score: %.4f", result.ProfileScore)

		// This attack might pass statistical verification!
		// That's why we have cryptographic verification with secret for dispute resolution
		if result.ZoneDivergence < 0.5 {
			t.Logf("WARNING: Sophisticated attack passes statistical verification")
			t.Logf("This is expected - cryptographic verification with secret is needed")
		}

		// But they can't pass cryptographic verification without the secret
		randomSecret := sha256.Sum256([]byte("attacker-doesnt-know-this"))
		if err := VerifyWithSecret(samples, randomSecret); err == nil {
			t.Error("Sophisticated attack should fail cryptographic verification")
		}
	})
}

// fabricateNaiveEvidence creates evidence with random zone transitions
func fabricateNaiveEvidence(doc string, numSamples int) []JitterSample {
	samples := make([]JitterSample, numSamples)
	baseTime := time.Now()

	for i := 0; i < numSamples; i++ {
		fromZone := int(pseudoRandom(uint64(i*2)) % 8)
		toZone := int(pseudoRandom(uint64(i*2+1)) % 8)

		samples[i] = JitterSample{
			Ordinal:        uint64(i + 1),
			Timestamp:      baseTime.Add(time.Duration(i*50) * time.Millisecond),
			DocHash:        sha256.Sum256([]byte(doc)),
			ZoneTransition: EncodeZoneTransition(fromZone, toZone),
			IntervalBucket: uint8(pseudoRandom(uint64(i*3)) % 10),
			JitterMicros:   uint32(MinJitter + pseudoRandom(uint64(i*4))%uint64(JitterRange)),
		}
		samples[i].SampleHash = computeJitterSampleHash(&samples[i])
	}

	return samples
}

// fabricateOneHandedEvidence creates evidence with only left-hand zones
func fabricateOneHandedEvidence(doc string, numSamples int) []JitterSample {
	samples := make([]JitterSample, numSamples)
	baseTime := time.Now()

	for i := 0; i < numSamples; i++ {
		fromZone := int(pseudoRandom(uint64(i*2)) % 4) // Only zones 0-3 (left hand)
		toZone := int(pseudoRandom(uint64(i*2+1)) % 4)

		samples[i] = JitterSample{
			Ordinal:        uint64(i + 1),
			Timestamp:      baseTime.Add(time.Duration(i*50) * time.Millisecond),
			DocHash:        sha256.Sum256([]byte(doc)),
			ZoneTransition: EncodeZoneTransition(fromZone, toZone),
			IntervalBucket: uint8(2 + pseudoRandom(uint64(i*3))%3), // Buckets 2-4
			JitterMicros:   uint32(MinJitter + pseudoRandom(uint64(i*4))%uint64(JitterRange)),
		}
		samples[i].SampleHash = computeJitterSampleHash(&samples[i])
	}

	return samples
}

// fabricateRoboticEvidence creates evidence with identical timing
func fabricateRoboticEvidence(doc string, numSamples int) []JitterSample {
	samples := make([]JitterSample, numSamples)
	baseTime := time.Now()

	for i := 0; i < numSamples; i++ {
		fromZone := int(pseudoRandom(uint64(i*2)) % 8)
		toZone := int(pseudoRandom(uint64(i*2+1)) % 8)

		samples[i] = JitterSample{
			Ordinal:        uint64(i + 1),
			Timestamp:      baseTime.Add(time.Duration(i*50) * time.Millisecond), // Exactly 50ms apart
			DocHash:        sha256.Sum256([]byte(doc)),
			ZoneTransition: EncodeZoneTransition(fromZone, toZone),
			IntervalBucket: 2, // Always bucket 2 (robotic)
			JitterMicros:   uint32(MinJitter + pseudoRandom(uint64(i*4))%uint64(JitterRange)),
		}
		samples[i].SampleHash = computeJitterSampleHash(&samples[i])
	}

	return samples
}

// fabricateSophisticatedEvidence tries to match the expected zone distribution
func fabricateSophisticatedEvidence(doc string, expectedProfile TypingProfile, numSamples int) []JitterSample {
	samples := make([]JitterSample, numSamples)
	baseTime := time.Now()

	// Calculate target ratios from expected profile
	totalExpected := float64(expectedProfile.TotalTransitions)
	if totalExpected == 0 {
		totalExpected = 1
	}

	// Count expected alternating vs same-hand ratio
	var altCount, sameCount uint64
	for i := 0; i < 10; i++ {
		altCount += uint64(expectedProfile.AlternatingHist[i])
		sameCount += uint64(expectedProfile.SameFingerHist[i]) + uint64(expectedProfile.SameHandHist[i])
	}

	altRatio := float64(altCount) / totalExpected

	for i := 0; i < numSamples; i++ {
		var fromZone, toZone int

		// Try to match alternation ratio
		if float64(pseudoRandom(uint64(i*5))%100)/100.0 < altRatio {
			// Alternating: different hands
			fromZone = int(pseudoRandom(uint64(i*2)) % 4)       // Left hand
			toZone = 4 + int(pseudoRandom(uint64(i*2+1))%4)     // Right hand
		} else {
			// Same hand
			hand := int(pseudoRandom(uint64(i*6)) % 2)
			if hand == 0 {
				fromZone = int(pseudoRandom(uint64(i*2)) % 4)
				toZone = int(pseudoRandom(uint64(i*2+1)) % 4)
			} else {
				fromZone = 4 + int(pseudoRandom(uint64(i*2))%4)
				toZone = 4 + int(pseudoRandom(uint64(i*2+1))%4)
			}
		}

		// Vary timing buckets somewhat naturally
		bucket := uint8(1 + pseudoRandom(uint64(i*7))%6) // Buckets 1-6

		samples[i] = JitterSample{
			Ordinal:        uint64(i + 1),
			Timestamp:      baseTime.Add(time.Duration(i*50+int(pseudoRandom(uint64(i*8))%30)) * time.Millisecond),
			DocHash:        sha256.Sum256([]byte(doc)),
			ZoneTransition: EncodeZoneTransition(fromZone, toZone),
			IntervalBucket: bucket,
			JitterMicros:   uint32(MinJitter + pseudoRandom(uint64(i*4))%uint64(JitterRange)),
		}
		samples[i].SampleHash = computeJitterSampleHash(&samples[i])
	}

	return samples
}
