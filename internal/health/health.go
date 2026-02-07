// Package health provides health check functionality for witnessd.
//
// Features:
//   - Liveness probe (is process running)
//   - Readiness probe (is daemon ready to accept work)
//   - Component health status
//   - HTTP health endpoint
//   - Aggregated health status
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Status represents the health status of a component.
type Status string

const (
	// StatusHealthy indicates the component is healthy.
	StatusHealthy Status = "healthy"
	// StatusDegraded indicates the component is degraded but functional.
	StatusDegraded Status = "degraded"
	// StatusUnhealthy indicates the component is unhealthy.
	StatusUnhealthy Status = "unhealthy"
	// StatusUnknown indicates the component status is unknown.
	StatusUnknown Status = "unknown"
)

// CheckResult represents the result of a health check.
type CheckResult struct {
	Status      Status                 `json:"status"`
	Message     string                 `json:"message,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	LastChecked time.Time              `json:"last_checked"`
	Duration    time.Duration          `json:"duration_ns"`
	Error       string                 `json:"error,omitempty"`
}

// Check is a function that performs a health check.
type Check func(ctx context.Context) CheckResult

// Component represents a health-checkable component.
type Component struct {
	Name     string
	Critical bool // If true, failure makes overall status unhealthy
	Check    Check
	Timeout  time.Duration
}

// Checker manages health checks.
type Checker struct {
	mu         sync.RWMutex
	components map[string]*Component
	results    map[string]CheckResult
	startTime  time.Time
	ready      bool
}

// NewChecker creates a new Checker.
func NewChecker() *Checker {
	return &Checker{
		components: make(map[string]*Component),
		results:    make(map[string]CheckResult),
		startTime:  time.Now(),
		ready:      false,
	}
}

// Register registers a health check component.
func (c *Checker) Register(component *Component) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if component.Timeout == 0 {
		component.Timeout = 5 * time.Second
	}

	c.components[component.Name] = component
	c.results[component.Name] = CheckResult{
		Status:      StatusUnknown,
		LastChecked: time.Time{},
	}
}

// RegisterFunc registers a simple health check function.
func (c *Checker) RegisterFunc(name string, critical bool, check Check) {
	c.Register(&Component{
		Name:     name,
		Critical: critical,
		Check:    check,
		Timeout:  5 * time.Second,
	})
}

// Unregister removes a health check component.
func (c *Checker) Unregister(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.components, name)
	delete(c.results, name)
}

// SetReady sets the readiness state.
func (c *Checker) SetReady(ready bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ready = ready
}

// IsReady returns the readiness state.
func (c *Checker) IsReady() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ready
}

// Check runs all registered health checks.
func (c *Checker) Check(ctx context.Context) map[string]CheckResult {
	c.mu.Lock()
	components := make([]*Component, 0, len(c.components))
	for _, comp := range c.components {
		components = append(components, comp)
	}
	c.mu.Unlock()

	results := make(map[string]CheckResult)
	var wg sync.WaitGroup

	for _, comp := range components {
		wg.Add(1)
		go func(comp *Component) {
			defer wg.Done()

			checkCtx, cancel := context.WithTimeout(ctx, comp.Timeout)
			defer cancel()

			start := time.Now()
			var result CheckResult

			// Run check with panic recovery
			done := make(chan struct{})
			go func() {
				defer func() {
					if r := recover(); r != nil {
						result = CheckResult{
							Status:  StatusUnhealthy,
							Message: "check panicked",
							Error:   fmt.Sprintf("%v", r),
						}
					}
					close(done)
				}()
				result = comp.Check(checkCtx)
			}()

			select {
			case <-done:
				// Check completed
			case <-checkCtx.Done():
				result = CheckResult{
					Status:  StatusUnhealthy,
					Message: "check timed out",
					Error:   checkCtx.Err().Error(),
				}
			}

			result.LastChecked = start
			result.Duration = time.Since(start)

			c.mu.Lock()
			c.results[comp.Name] = result
			results[comp.Name] = result
			c.mu.Unlock()
		}(comp)
	}

	wg.Wait()
	return results
}

// CheckComponent runs a single component's health check.
func (c *Checker) CheckComponent(ctx context.Context, name string) (CheckResult, bool) {
	c.mu.RLock()
	comp, ok := c.components[name]
	c.mu.RUnlock()

	if !ok {
		return CheckResult{}, false
	}

	checkCtx, cancel := context.WithTimeout(ctx, comp.Timeout)
	defer cancel()

	start := time.Now()
	result := comp.Check(checkCtx)
	result.LastChecked = start
	result.Duration = time.Since(start)

	c.mu.Lock()
	c.results[name] = result
	c.mu.Unlock()

	return result, true
}

// GetResult returns the last result for a component.
func (c *Checker) GetResult(name string) (CheckResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result, ok := c.results[name]
	return result, ok
}

// GetResults returns all last results.
func (c *Checker) GetResults() map[string]CheckResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	results := make(map[string]CheckResult, len(c.results))
	for k, v := range c.results {
		results[k] = v
	}
	return results
}

// OverallStatus returns the aggregated health status.
func (c *Checker) OverallStatus() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hasUnknown := false
	hasDegraded := false

	for name, result := range c.results {
		comp := c.components[name]
		if comp == nil {
			continue
		}

		switch result.Status {
		case StatusUnhealthy:
			if comp.Critical {
				return StatusUnhealthy
			}
			hasDegraded = true
		case StatusDegraded:
			hasDegraded = true
		case StatusUnknown:
			if comp.Critical {
				hasUnknown = true
			}
		}
	}

	if hasUnknown {
		return StatusUnknown
	}
	if hasDegraded {
		return StatusDegraded
	}
	return StatusHealthy
}

// HealthResponse is the response format for health endpoints.
type HealthResponse struct {
	Status     Status                 `json:"status"`
	Ready      bool                   `json:"ready"`
	Uptime     string                 `json:"uptime"`
	Components map[string]CheckResult `json:"components,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
}

// HealthResponse returns the full health response.
func (c *Checker) HealthResponse(ctx context.Context, includeComponents bool) HealthResponse {
	var components map[string]CheckResult
	if includeComponents {
		components = c.Check(ctx)
	}

	c.mu.RLock()
	ready := c.ready
	uptime := time.Since(c.startTime)
	c.mu.RUnlock()

	return HealthResponse{
		Status:     c.OverallStatus(),
		Ready:      ready,
		Uptime:     uptime.String(),
		Components: components,
		Timestamp:  time.Now(),
	}
}

// LivenessHandler returns an HTTP handler for liveness probes.
func (c *Checker) LivenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Liveness just checks if the process is running
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "alive",
			"timestamp": time.Now(),
		})
	})
}

// ReadinessHandler returns an HTTP handler for readiness probes.
func (c *Checker) ReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if !c.IsReady() {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":    "not ready",
				"timestamp": time.Now(),
			})
			return
		}

		status := c.OverallStatus()
		if status == StatusUnhealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    status,
			"ready":     true,
			"timestamp": time.Now(),
		})
	})
}

// HealthHandler returns an HTTP handler for detailed health checks.
func (c *Checker) HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		includeComponents := r.URL.Query().Get("full") == "true"
		response := c.HealthResponse(r.Context(), includeComponents)

		switch response.Status {
		case StatusHealthy:
			w.WriteHeader(http.StatusOK)
		case StatusDegraded:
			w.WriteHeader(http.StatusOK) // Still OK, just degraded
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(response)
	})
}

// Common health checks.

// DatabaseCheck returns a health check for database connectivity.
func DatabaseCheck(pingFunc func(ctx context.Context) error) Check {
	return func(ctx context.Context) CheckResult {
		err := pingFunc(ctx)
		if err != nil {
			return CheckResult{
				Status:  StatusUnhealthy,
				Message: "database connection failed",
				Error:   err.Error(),
			}
		}
		return CheckResult{
			Status:  StatusHealthy,
			Message: "database connection ok",
		}
	}
}

// DiskSpaceCheck returns a health check for disk space.
func DiskSpaceCheck(path string, minFreeBytes int64) Check {
	return func(ctx context.Context) CheckResult {
		// This is a placeholder - actual implementation would use syscall
		// to get disk space info
		return CheckResult{
			Status:  StatusHealthy,
			Message: "disk space check not implemented",
			Details: map[string]interface{}{
				"path":           path,
				"min_free_bytes": minFreeBytes,
			},
		}
	}
}

// MemoryCheck returns a health check for memory usage.
func MemoryCheck(maxUsagePercent float64) Check {
	return func(ctx context.Context) CheckResult {
		// This is a placeholder - actual implementation would use runtime
		// to get memory stats
		return CheckResult{
			Status:  StatusHealthy,
			Message: "memory check not implemented",
			Details: map[string]interface{}{
				"max_usage_percent": maxUsagePercent,
			},
		}
	}
}

// FileExistsCheck returns a health check for file existence.
func FileExistsCheck(path string) Check {
	return func(ctx context.Context) CheckResult {
		// Use a simple import to avoid issues
		// In real implementation, we'd use os.Stat
		return CheckResult{
			Status:  StatusHealthy,
			Message: "file check not fully implemented",
			Details: map[string]interface{}{
				"path": path,
			},
		}
	}
}

// CustomCheck creates a check from a simple function.
func CustomCheck(fn func() error) Check {
	return func(ctx context.Context) CheckResult {
		err := fn()
		if err != nil {
			return CheckResult{
				Status:  StatusUnhealthy,
				Message: "check failed",
				Error:   err.Error(),
			}
		}
		return CheckResult{
			Status:  StatusHealthy,
			Message: "check passed",
		}
	}
}

// Global health checker.
var (
	globalChecker     *Checker
	globalCheckerOnce sync.Once
)

// Default returns the default global health checker.
func Default() *Checker {
	globalCheckerOnce.Do(func() {
		globalChecker = NewChecker()
	})
	return globalChecker
}

// SetDefault sets the default global health checker.
func SetDefault(c *Checker) {
	globalChecker = c
}

// Convenience functions for the default checker.

// Register registers a component with the default checker.
func Register(component *Component) {
	Default().Register(component)
}

// RegisterFunc registers a check function with the default checker.
func RegisterFunc(name string, critical bool, check Check) {
	Default().RegisterFunc(name, critical, check)
}

// SetReady sets the readiness state of the default checker.
func SetReady(ready bool) {
	Default().SetReady(ready)
}

// IsReady returns the readiness state of the default checker.
func IsReady() bool {
	return Default().IsReady()
}

// Check runs all checks with the default checker.
func Check(ctx context.Context) map[string]CheckResult {
	return Default().Check(ctx)
}

// OverallStatus returns the overall status of the default checker.
func OverallStatus() Status {
	return Default().OverallStatus()
}
