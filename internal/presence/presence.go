// Package presence implements Layer 2 Presence Verification.
//
// Presence verification proves that a human was physically present at the
// keyboard during claimed writing sessions. It uses random challenges that
// require immediate human response.
//
// Unlike continuous behavioral monitoring, presence verification is:
// - Explicit: The author opts into verification sessions
// - Minimal: Only proves presence, not content or behavior
// - Private: No keystroke timing, no content capture
//
// Automated drip attacks cannot respond to unanticipated random challenges.
package presence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand"
	"strings"
	"time"
)

// Session represents a verified presence session.
type Session struct {
	ID        string    `json:"id"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Active    bool      `json:"active"`

	// Challenges issued during this session
	Challenges []Challenge `json:"challenges"`

	// Checkpoints committed during this session
	CheckpointOrdinals []uint64 `json:"checkpoint_ordinals,omitempty"`

	// Statistics
	ChallengesIssued   int     `json:"challenges_issued"`
	ChallengesPassed   int     `json:"challenges_passed"`
	ChallengesFailed   int     `json:"challenges_failed"`
	ChallengesMissed   int     `json:"challenges_missed"`
	VerificationRate   float64 `json:"verification_rate"`
}

// Challenge represents a single presence verification challenge.
type Challenge struct {
	ID            string        `json:"id"`
	Type          ChallengeType `json:"type"`
	IssuedAt      time.Time     `json:"issued_at"`
	ExpiresAt     time.Time     `json:"expires_at"`
	Window        time.Duration `json:"window"`

	// The challenge content
	Prompt        string `json:"prompt"`
	ExpectedHash  string `json:"expected_hash"` // Hash of correct response

	// Response (if received)
	RespondedAt   *time.Time `json:"responded_at,omitempty"`
	ResponseHash  string     `json:"response_hash,omitempty"`
	Status        ChallengeStatus `json:"status"`
}

// ChallengeType enumerates challenge types.
type ChallengeType string

const (
	ChallengeTypePhrase ChallengeType = "type_phrase"
	ChallengeTypeMath   ChallengeType = "simple_math"
	ChallengeTypeWord   ChallengeType = "type_word"
)

// ChallengeStatus indicates challenge outcome.
type ChallengeStatus string

const (
	StatusPending  ChallengeStatus = "pending"
	StatusPassed   ChallengeStatus = "passed"
	StatusFailed   ChallengeStatus = "failed"
	StatusExpired  ChallengeStatus = "expired"
)

// Config controls presence verification behavior.
type Config struct {
	// How often to issue challenges (average interval)
	ChallengeInterval time.Duration `json:"challenge_interval"`

	// Random variance on challenge timing (0.0 - 1.0)
	IntervalVariance float64 `json:"interval_variance"`

	// Time allowed to respond to a challenge
	ResponseWindow time.Duration `json:"response_window"`

	// Challenge types to use
	EnabledChallenges []ChallengeType `json:"enabled_challenges"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		ChallengeInterval: 10 * time.Minute,
		IntervalVariance:  0.5, // ±50% variance
		ResponseWindow:    60 * time.Second,
		EnabledChallenges: []ChallengeType{
			ChallengeTypePhrase,
			ChallengeTypeMath,
			ChallengeTypeWord,
		},
	}
}

// Verifier manages presence verification sessions.
type Verifier struct {
	config  Config
	session *Session
	rng     *mathrand.Rand
}

// NewVerifier creates a new presence verifier.
func NewVerifier(config Config) *Verifier {
	return &Verifier{
		config: config,
		rng:    mathrand.New(mathrand.NewSource(time.Now().UnixNano())),
	}
}

// StartSession begins a new presence verification session.
func (v *Verifier) StartSession() (*Session, error) {
	if v.session != nil && v.session.Active {
		return nil, errors.New("session already active")
	}

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}

	v.session = &Session{
		ID:        hex.EncodeToString(id),
		StartTime: time.Now(),
		Active:    true,
	}

	return v.session, nil
}

// EndSession ends the current session and computes statistics.
func (v *Verifier) EndSession() (*Session, error) {
	if v.session == nil || !v.session.Active {
		return nil, errors.New("no active session")
	}

	v.session.EndTime = time.Now()
	v.session.Active = false

	// Compute statistics
	v.session.ChallengesIssued = len(v.session.Challenges)
	for _, c := range v.session.Challenges {
		switch c.Status {
		case StatusPassed:
			v.session.ChallengesPassed++
		case StatusFailed:
			v.session.ChallengesFailed++
		case StatusExpired, StatusPending:
			v.session.ChallengesMissed++
		}
	}

	if v.session.ChallengesIssued > 0 {
		v.session.VerificationRate = float64(v.session.ChallengesPassed) / float64(v.session.ChallengesIssued)
	}

	session := v.session
	v.session = nil
	return session, nil
}

// IssueChallenge generates a new random challenge.
func (v *Verifier) IssueChallenge() (*Challenge, error) {
	if v.session == nil || !v.session.Active {
		return nil, errors.New("no active session")
	}

	// Expire any pending challenges
	v.expirePending()

	// Pick random challenge type
	challengeType := v.config.EnabledChallenges[v.rng.Intn(len(v.config.EnabledChallenges))]

	// Generate challenge
	var prompt, expectedResponse string
	switch challengeType {
	case ChallengeTypePhrase:
		prompt, expectedResponse = v.generatePhrase()
	case ChallengeTypeMath:
		prompt, expectedResponse = v.generateMath()
	case ChallengeTypeWord:
		prompt, expectedResponse = v.generateWord()
	default:
		prompt, expectedResponse = v.generatePhrase()
	}

	id := make([]byte, 8)
	rand.Read(id)

	now := time.Now()
	challenge := Challenge{
		ID:           hex.EncodeToString(id),
		Type:         challengeType,
		IssuedAt:     now,
		ExpiresAt:    now.Add(v.config.ResponseWindow),
		Window:       v.config.ResponseWindow,
		Prompt:       prompt,
		ExpectedHash: hashResponse(expectedResponse),
		Status:       StatusPending,
	}

	v.session.Challenges = append(v.session.Challenges, challenge)
	return &challenge, nil
}

// RespondToChallenge checks a response against the pending challenge.
func (v *Verifier) RespondToChallenge(challengeID, response string) (bool, error) {
	if v.session == nil || !v.session.Active {
		return false, errors.New("no active session")
	}

	// Find the challenge
	var challenge *Challenge
	for i := range v.session.Challenges {
		if v.session.Challenges[i].ID == challengeID {
			challenge = &v.session.Challenges[i]
			break
		}
	}

	if challenge == nil {
		return false, errors.New("challenge not found")
	}

	if challenge.Status != StatusPending {
		return false, fmt.Errorf("challenge already resolved: %s", challenge.Status)
	}

	now := time.Now()
	challenge.RespondedAt = &now
	challenge.ResponseHash = hashResponse(response)

	// Check if expired
	if now.After(challenge.ExpiresAt) {
		challenge.Status = StatusExpired
		return false, nil
	}

	// Check response
	if challenge.ResponseHash == challenge.ExpectedHash {
		challenge.Status = StatusPassed
		return true, nil
	}

	challenge.Status = StatusFailed
	return false, nil
}

// NextChallengeTime returns when the next challenge should be issued.
func (v *Verifier) NextChallengeTime() time.Time {
	if v.session == nil || !v.session.Active {
		return time.Time{}
	}

	// Find the last challenge
	var lastTime time.Time
	if len(v.session.Challenges) > 0 {
		lastTime = v.session.Challenges[len(v.session.Challenges)-1].IssuedAt
	} else {
		lastTime = v.session.StartTime
	}

	// Add interval with variance
	interval := v.config.ChallengeInterval
	variance := time.Duration(float64(interval) * v.config.IntervalVariance * (v.rng.Float64()*2 - 1))
	return lastTime.Add(interval + variance)
}

// ShouldIssueChallenge returns true if it's time for a new challenge.
func (v *Verifier) ShouldIssueChallenge() bool {
	return time.Now().After(v.NextChallengeTime())
}

// ActiveSession returns the current session, if any.
func (v *Verifier) ActiveSession() *Session {
	return v.session
}

func (v *Verifier) expirePending() {
	now := time.Now()
	for i := range v.session.Challenges {
		if v.session.Challenges[i].Status == StatusPending && now.After(v.session.Challenges[i].ExpiresAt) {
			v.session.Challenges[i].Status = StatusExpired
		}
	}
}

// Challenge generators

func (v *Verifier) generatePhrase() (prompt, expected string) {
	phrases := []string{
		"the quick brown fox",
		"hello world today",
		"verify my presence",
		"cryptographic proof",
		"authentic authorship",
		"digital signature",
		"hash chain valid",
		"timestamp verified",
		"witness protocol",
		"merkle mountain",
	}
	phrase := phrases[v.rng.Intn(len(phrases))]
	return fmt.Sprintf("Type the phrase: %s", phrase), strings.ToLower(phrase)
}

func (v *Verifier) generateMath() (prompt, expected string) {
	a := v.rng.Intn(20) + 1
	b := v.rng.Intn(20) + 1

	ops := []struct {
		symbol string
		fn     func(int, int) int
	}{
		{"+", func(x, y int) int { return x + y }},
		{"-", func(x, y int) int { return x - y }},
		{"*", func(x, y int) int { return x * y }},
	}

	op := ops[v.rng.Intn(len(ops))]
	result := op.fn(a, b)

	return fmt.Sprintf("Solve: %d %s %d = ?", a, op.symbol, b), fmt.Sprintf("%d", result)
}

func (v *Verifier) generateWord() (prompt, expected string) {
	words := []string{
		"cryptography", "authentication", "verification",
		"signature", "timestamp", "blockchain",
		"integrity", "provenance", "authorship",
		"attestation", "declaration", "witness",
	}
	word := words[v.rng.Intn(len(words))]
	return fmt.Sprintf("Type the word: %s", word), strings.ToLower(word)
}

func hashResponse(response string) string {
	// Normalize: lowercase, trim whitespace
	normalized := strings.ToLower(strings.TrimSpace(response))
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// Evidence contains presence verification evidence for export.
type Evidence struct {
	Sessions      []Session `json:"sessions"`
	TotalDuration time.Duration `json:"total_duration"`
	TotalChallenges int `json:"total_challenges"`
	TotalPassed   int `json:"total_passed"`
	OverallRate   float64 `json:"overall_rate"`
}

// CompileEvidence aggregates multiple sessions into evidence.
func CompileEvidence(sessions []Session) Evidence {
	ev := Evidence{
		Sessions: sessions,
	}

	for _, s := range sessions {
		if !s.EndTime.IsZero() {
			ev.TotalDuration += s.EndTime.Sub(s.StartTime)
		}
		ev.TotalChallenges += s.ChallengesIssued
		ev.TotalPassed += s.ChallengesPassed
	}

	if ev.TotalChallenges > 0 {
		ev.OverallRate = float64(ev.TotalPassed) / float64(ev.TotalChallenges)
	}

	return ev
}

// Encode serializes a session to JSON.
func (s *Session) Encode() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// DecodeSession deserializes a session from JSON.
func DecodeSession(data []byte) (*Session, error) {
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
