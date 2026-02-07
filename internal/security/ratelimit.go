package security

import (
	"errors"
	"sync"
	"time"
)

// Rate limiting errors
var (
	ErrRateLimited = errors.New("security: rate limit exceeded")
)

// RateLimiter implements a token bucket rate limiter.
type RateLimiter struct {
	mu           sync.Mutex
	rate         float64 // tokens per second
	burst        int     // maximum burst size
	tokens       float64
	lastRefill   time.Time
	blockedUntil time.Time
}

// NewRateLimiter creates a new rate limiter.
// rate is the sustained rate (operations per second)
// burst is the maximum allowed burst (operations)
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst), // Start full
		lastRefill: time.Now(),
	}
}

// Allow checks if an operation is allowed under the rate limit.
// It returns true if allowed, false if rate limited.
func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if we're in a blocked period
	now := time.Now()
	if now.Before(r.blockedUntil) {
		return false
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.tokens += elapsed * r.rate
	if r.tokens > float64(r.burst) {
		r.tokens = float64(r.burst)
	}
	r.lastRefill = now

	// Check if we have enough tokens
	if r.tokens >= 1.0 {
		r.tokens--
		return true
	}

	return false
}

// Wait blocks until the operation is allowed or the context expires.
// Returns nil if allowed, ErrRateLimited if timeout.
func (r *RateLimiter) Wait(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for {
		if r.Allow() {
			return nil
		}

		// Check timeout
		if time.Now().After(deadline) {
			return ErrRateLimited
		}

		// Wait a bit before retrying
		// Calculate optimal wait time based on rate
		waitTime := time.Duration(float64(time.Second) / r.rate)
		if waitTime < time.Millisecond {
			waitTime = time.Millisecond
		}
		if waitTime > 100*time.Millisecond {
			waitTime = 100 * time.Millisecond
		}

		time.Sleep(waitTime)
	}
}

// Block temporarily blocks all operations for the specified duration.
// This is useful for implementing exponential backoff after detected attacks.
func (r *RateLimiter) Block(duration time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.blockedUntil = time.Now().Add(duration)
}

// Reset resets the rate limiter to full capacity.
func (r *RateLimiter) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.tokens = float64(r.burst)
	r.lastRefill = time.Now()
	r.blockedUntil = time.Time{}
}

// IPRateLimiter implements per-IP rate limiting.
type IPRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*RateLimiter
	rate     float64
	burst    int
	cleanup  time.Duration // How long to keep inactive limiters
}

// NewIPRateLimiter creates a new per-IP rate limiter.
func NewIPRateLimiter(rate float64, burst int, cleanup time.Duration) *IPRateLimiter {
	ipl := &IPRateLimiter{
		limiters: make(map[string]*RateLimiter),
		rate:     rate,
		burst:    burst,
		cleanup:  cleanup,
	}

	// Start cleanup goroutine
	go ipl.cleanupLoop()

	return ipl
}

// Allow checks if an operation from the given IP is allowed.
func (ipl *IPRateLimiter) Allow(ip string) bool {
	ipl.mu.Lock()
	limiter, ok := ipl.limiters[ip]
	if !ok {
		limiter = NewRateLimiter(ipl.rate, ipl.burst)
		ipl.limiters[ip] = limiter
	}
	ipl.mu.Unlock()

	return limiter.Allow()
}

// Block temporarily blocks an IP.
func (ipl *IPRateLimiter) Block(ip string, duration time.Duration) {
	ipl.mu.Lock()
	limiter, ok := ipl.limiters[ip]
	if !ok {
		limiter = NewRateLimiter(ipl.rate, ipl.burst)
		ipl.limiters[ip] = limiter
	}
	ipl.mu.Unlock()

	limiter.Block(duration)
}

func (ipl *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(ipl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		ipl.cleanup_()
	}
}

func (ipl *IPRateLimiter) cleanup_() {
	ipl.mu.Lock()
	defer ipl.mu.Unlock()

	now := time.Now()
	for ip, limiter := range ipl.limiters {
		limiter.mu.Lock()
		// Remove if inactive for cleanup duration
		if now.Sub(limiter.lastRefill) > ipl.cleanup {
			delete(ipl.limiters, ip)
		}
		limiter.mu.Unlock()
	}
}

// ConnectionLimiter limits the number of concurrent connections.
type ConnectionLimiter struct {
	mu       sync.Mutex
	current  int
	max      int
	perIP    map[string]int
	maxPerIP int
}

// NewConnectionLimiter creates a new connection limiter.
func NewConnectionLimiter(max, maxPerIP int) *ConnectionLimiter {
	return &ConnectionLimiter{
		max:      max,
		maxPerIP: maxPerIP,
		perIP:    make(map[string]int),
	}
}

// Acquire attempts to acquire a connection slot.
// Returns true if successful, false if limit reached.
func (cl *ConnectionLimiter) Acquire(ip string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	// Check global limit
	if cl.current >= cl.max {
		return false
	}

	// Check per-IP limit
	if cl.perIP[ip] >= cl.maxPerIP {
		return false
	}

	cl.current++
	cl.perIP[ip]++
	return true
}

// Release releases a connection slot.
func (cl *ConnectionLimiter) Release(ip string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.current > 0 {
		cl.current--
	}
	if cl.perIP[ip] > 0 {
		cl.perIP[ip]--
		if cl.perIP[ip] == 0 {
			delete(cl.perIP, ip)
		}
	}
}

// Current returns the current number of connections.
func (cl *ConnectionLimiter) Current() int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.current
}

// FailureLimiter implements progressive delays after failures.
// This helps prevent brute-force attacks.
type FailureLimiter struct {
	mu           sync.Mutex
	failures     map[string]*failureRecord
	baseDelay    time.Duration
	maxDelay     time.Duration
	resetAfter   time.Duration
	maxFailures  int
	lockDuration time.Duration
}

type failureRecord struct {
	count      int
	lastFailed time.Time
	lockedUntil time.Time
}

// NewFailureLimiter creates a new failure limiter.
func NewFailureLimiter(baseDelay, maxDelay, resetAfter time.Duration, maxFailures int, lockDuration time.Duration) *FailureLimiter {
	return &FailureLimiter{
		failures:     make(map[string]*failureRecord),
		baseDelay:    baseDelay,
		maxDelay:     maxDelay,
		resetAfter:   resetAfter,
		maxFailures:  maxFailures,
		lockDuration: lockDuration,
	}
}

// RecordFailure records a failure for the given key.
// Returns the required delay before the next attempt.
func (fl *FailureLimiter) RecordFailure(key string) time.Duration {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	now := time.Now()
	record, ok := fl.failures[key]
	if !ok {
		record = &failureRecord{}
		fl.failures[key] = record
	}

	// Reset if enough time has passed
	if now.Sub(record.lastFailed) > fl.resetAfter {
		record.count = 0
	}

	record.count++
	record.lastFailed = now

	// Calculate delay with exponential backoff
	delay := fl.baseDelay * time.Duration(1<<uint(record.count-1))
	if delay > fl.maxDelay {
		delay = fl.maxDelay
	}

	// Lock if max failures exceeded
	if record.count >= fl.maxFailures {
		record.lockedUntil = now.Add(fl.lockDuration)
	}

	return delay
}

// IsLocked checks if the key is currently locked.
func (fl *FailureLimiter) IsLocked(key string) bool {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	record, ok := fl.failures[key]
	if !ok {
		return false
	}

	return time.Now().Before(record.lockedUntil)
}

// RecordSuccess resets the failure count for the given key.
func (fl *FailureLimiter) RecordSuccess(key string) {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	delete(fl.failures, key)
}

// GetDelay returns the current required delay for the given key.
func (fl *FailureLimiter) GetDelay(key string) time.Duration {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	record, ok := fl.failures[key]
	if !ok {
		return 0
	}

	// Calculate remaining delay
	elapsed := time.Since(record.lastFailed)
	delay := fl.baseDelay * time.Duration(1<<uint(record.count-1))
	if delay > fl.maxDelay {
		delay = fl.maxDelay
	}

	if elapsed >= delay {
		return 0
	}

	return delay - elapsed
}
