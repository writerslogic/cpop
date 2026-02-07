// Package metrics provides Prometheus-compatible metrics for witnessd.
//
// Features:
//   - Counters for keystrokes, checkpoints, sessions
//   - Gauges for active sessions, WAL size, MMR size
//   - Histograms for checkpoint duration, VDF computation time
//   - Optional HTTP endpoint for scraping
//   - Thread-safe operations
package metrics

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MetricType represents the type of metric.
type MetricType int

const (
	// TypeCounter is a monotonically increasing counter.
	TypeCounter MetricType = iota
	// TypeGauge is a value that can go up and down.
	TypeGauge
	// TypeHistogram is a distribution of values.
	TypeHistogram
	// TypeSummary is a summary of values with quantiles.
	TypeSummary
)

// String returns the string representation of the metric type.
func (t MetricType) String() string {
	switch t {
	case TypeCounter:
		return "counter"
	case TypeGauge:
		return "gauge"
	case TypeHistogram:
		return "histogram"
	case TypeSummary:
		return "summary"
	default:
		return "unknown"
	}
}

// Labels represents metric labels.
type Labels map[string]string

// String returns a string representation of labels.
func (l Labels) String() string {
	if len(l) == 0 {
		return ""
	}

	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(l))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, l[k]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Counter is a monotonically increasing counter.
type Counter struct {
	name   string
	help   string
	labels Labels
	value  atomic.Uint64
}

// NewCounter creates a new Counter.
func NewCounter(name, help string, labels Labels) *Counter {
	return &Counter{
		name:   name,
		help:   help,
		labels: labels,
	}
}

// Inc increments the counter by 1.
func (c *Counter) Inc() {
	c.value.Add(1)
}

// Add adds the given value to the counter.
func (c *Counter) Add(v uint64) {
	c.value.Add(v)
}

// Value returns the current value.
func (c *Counter) Value() uint64 {
	return c.value.Load()
}

// Name returns the metric name.
func (c *Counter) Name() string {
	return c.name
}

// Help returns the help text.
func (c *Counter) Help() string {
	return c.help
}

// Type returns the metric type.
func (c *Counter) Type() MetricType {
	return TypeCounter
}

// Gauge is a value that can go up and down.
type Gauge struct {
	name   string
	help   string
	labels Labels
	value  atomic.Int64
}

// NewGauge creates a new Gauge.
func NewGauge(name, help string, labels Labels) *Gauge {
	return &Gauge{
		name:   name,
		help:   help,
		labels: labels,
	}
}

// Set sets the gauge to the given value.
func (g *Gauge) Set(v int64) {
	g.value.Store(v)
}

// Inc increments the gauge by 1.
func (g *Gauge) Inc() {
	g.value.Add(1)
}

// Dec decrements the gauge by 1.
func (g *Gauge) Dec() {
	g.value.Add(-1)
}

// Add adds the given value to the gauge.
func (g *Gauge) Add(v int64) {
	g.value.Add(v)
}

// Value returns the current value.
func (g *Gauge) Value() int64 {
	return g.value.Load()
}

// Name returns the metric name.
func (g *Gauge) Name() string {
	return g.name
}

// Help returns the help text.
func (g *Gauge) Help() string {
	return g.help
}

// Type returns the metric type.
func (g *Gauge) Type() MetricType {
	return TypeGauge
}

// Histogram tracks the distribution of values.
type Histogram struct {
	name    string
	help    string
	labels  Labels
	buckets []float64

	mu     sync.Mutex
	counts []uint64
	sum    float64
	count  uint64
}

// DefaultBuckets are default histogram buckets.
var DefaultBuckets = []float64{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

// DurationBuckets are buckets for duration histograms (in seconds).
var DurationBuckets = []float64{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60,
}

// SizeBuckets are buckets for size histograms (in bytes).
var SizeBuckets = []float64{
	100, 1000, 10000, 100000, 1000000, 10000000, 100000000,
}

// NewHistogram creates a new Histogram.
func NewHistogram(name, help string, labels Labels, buckets []float64) *Histogram {
	if buckets == nil {
		buckets = DefaultBuckets
	}

	// Ensure buckets are sorted
	sortedBuckets := make([]float64, len(buckets))
	copy(sortedBuckets, buckets)
	sort.Float64s(sortedBuckets)

	return &Histogram{
		name:    name,
		help:    help,
		labels:  labels,
		buckets: sortedBuckets,
		counts:  make([]uint64, len(sortedBuckets)+1), // +1 for +Inf
	}
}

// Observe records a value.
func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.sum += v
	h.count++

	// Find bucket and increment
	idx := sort.SearchFloat64s(h.buckets, v)
	if idx < len(h.buckets) && h.buckets[idx] == v {
		idx++
	}
	for i := idx; i < len(h.counts); i++ {
		h.counts[i]++
	}
}

// ObserveDuration records a duration in seconds.
func (h *Histogram) ObserveDuration(d time.Duration) {
	h.Observe(d.Seconds())
}

// Timer returns a timer that records duration when stopped.
func (h *Histogram) Timer() *HistogramTimer {
	return &HistogramTimer{
		histogram: h,
		start:     time.Now(),
	}
}

// Name returns the metric name.
func (h *Histogram) Name() string {
	return h.name
}

// Help returns the help text.
func (h *Histogram) Help() string {
	return h.help
}

// Type returns the metric type.
func (h *Histogram) Type() MetricType {
	return TypeHistogram
}

// Sum returns the sum of observed values.
func (h *Histogram) Sum() float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sum
}

// Count returns the count of observations.
func (h *Histogram) Count() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

// Mean returns the mean of observed values.
func (h *Histogram) Mean() float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.count == 0 {
		return 0
	}
	return h.sum / float64(h.count)
}

// HistogramTimer is a timer for histogram observations.
type HistogramTimer struct {
	histogram *Histogram
	start     time.Time
}

// Stop stops the timer and records the duration.
func (t *HistogramTimer) Stop() time.Duration {
	d := time.Since(t.start)
	t.histogram.ObserveDuration(d)
	return d
}

// Registry holds all registered metrics.
type Registry struct {
	mu       sync.RWMutex
	counters map[string]*Counter
	gauges   map[string]*Gauge
	histograms map[string]*Histogram

	namespace string
	subsystem string
}

// NewRegistry creates a new Registry.
func NewRegistry(namespace, subsystem string) *Registry {
	return &Registry{
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
		namespace:  namespace,
		subsystem:  subsystem,
	}
}

// fullName returns the full metric name with namespace and subsystem.
func (r *Registry) fullName(name string) string {
	parts := []string{}
	if r.namespace != "" {
		parts = append(parts, r.namespace)
	}
	if r.subsystem != "" {
		parts = append(parts, r.subsystem)
	}
	parts = append(parts, name)
	return strings.Join(parts, "_")
}

// RegisterCounter registers a new counter.
func (r *Registry) RegisterCounter(name, help string, labels Labels) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()

	fullName := r.fullName(name)
	if c, ok := r.counters[fullName]; ok {
		return c
	}

	c := NewCounter(fullName, help, labels)
	r.counters[fullName] = c
	return c
}

// RegisterGauge registers a new gauge.
func (r *Registry) RegisterGauge(name, help string, labels Labels) *Gauge {
	r.mu.Lock()
	defer r.mu.Unlock()

	fullName := r.fullName(name)
	if g, ok := r.gauges[fullName]; ok {
		return g
	}

	g := NewGauge(fullName, help, labels)
	r.gauges[fullName] = g
	return g
}

// RegisterHistogram registers a new histogram.
func (r *Registry) RegisterHistogram(name, help string, labels Labels, buckets []float64) *Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()

	fullName := r.fullName(name)
	if h, ok := r.histograms[fullName]; ok {
		return h
	}

	h := NewHistogram(fullName, help, labels, buckets)
	r.histograms[fullName] = h
	return h
}

// GetCounter returns a counter by name.
func (r *Registry) GetCounter(name string) *Counter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.counters[r.fullName(name)]
}

// GetGauge returns a gauge by name.
func (r *Registry) GetGauge(name string) *Gauge {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.gauges[r.fullName(name)]
}

// GetHistogram returns a histogram by name.
func (r *Registry) GetHistogram(name string) *Histogram {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.histograms[r.fullName(name)]
}

// WritePrometheus writes metrics in Prometheus text format.
func (r *Registry) WritePrometheus(w io.Writer) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Write counters
	for _, c := range r.counters {
		fmt.Fprintf(w, "# HELP %s %s\n", c.name, c.help)
		fmt.Fprintf(w, "# TYPE %s counter\n", c.name)
		fmt.Fprintf(w, "%s%s %d\n", c.name, c.labels.String(), c.Value())
	}

	// Write gauges
	for _, g := range r.gauges {
		fmt.Fprintf(w, "# HELP %s %s\n", g.name, g.help)
		fmt.Fprintf(w, "# TYPE %s gauge\n", g.name)
		fmt.Fprintf(w, "%s%s %d\n", g.name, g.labels.String(), g.Value())
	}

	// Write histograms
	for _, h := range r.histograms {
		h.mu.Lock()
		fmt.Fprintf(w, "# HELP %s %s\n", h.name, h.help)
		fmt.Fprintf(w, "# TYPE %s histogram\n", h.name)

		labelStr := h.labels.String()
		if labelStr == "" {
			labelStr = "{"
		} else {
			labelStr = labelStr[:len(labelStr)-1] + ","
		}

		cumulative := uint64(0)
		for i, bucket := range h.buckets {
			cumulative += h.counts[i]
			fmt.Fprintf(w, "%s_bucket%sle=\"%.6f\"} %d\n", h.name, labelStr, bucket, cumulative)
		}
		cumulative += h.counts[len(h.buckets)]
		fmt.Fprintf(w, "%s_bucket%sle=\"+Inf\"} %d\n", h.name, labelStr, cumulative)
		fmt.Fprintf(w, "%s_sum%s %f\n", h.name, h.labels.String(), h.sum)
		fmt.Fprintf(w, "%s_count%s %d\n", h.name, h.labels.String(), h.count)
		h.mu.Unlock()
	}

	return nil
}

// WriteJSON writes metrics in JSON format.
func (r *Registry) WriteJSON(w io.Writer) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	metrics := make(map[string]interface{})

	// Add counters
	for _, c := range r.counters {
		metrics[c.name] = map[string]interface{}{
			"type":   "counter",
			"help":   c.help,
			"labels": c.labels,
			"value":  c.Value(),
		}
	}

	// Add gauges
	for _, g := range r.gauges {
		metrics[g.name] = map[string]interface{}{
			"type":   "gauge",
			"help":   g.help,
			"labels": g.labels,
			"value":  g.Value(),
		}
	}

	// Add histograms
	for _, h := range r.histograms {
		h.mu.Lock()
		bucketCounts := make(map[string]uint64)
		cumulative := uint64(0)
		for i, bucket := range h.buckets {
			cumulative += h.counts[i]
			bucketCounts[fmt.Sprintf("%.6f", bucket)] = cumulative
		}
		cumulative += h.counts[len(h.buckets)]
		bucketCounts["+Inf"] = cumulative

		metrics[h.name] = map[string]interface{}{
			"type":    "histogram",
			"help":    h.help,
			"labels":  h.labels,
			"buckets": bucketCounts,
			"sum":     h.sum,
			"count":   h.count,
			"mean":    func() float64 {
				if h.count == 0 {
					return 0
				}
				return h.sum / float64(h.count)
			}(),
		}
		h.mu.Unlock()
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(metrics)
}

// Snapshot returns a snapshot of all metrics.
func (r *Registry) Snapshot() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snapshot := make(map[string]interface{})

	for _, c := range r.counters {
		snapshot[c.name] = c.Value()
	}

	for _, g := range r.gauges {
		snapshot[g.name] = g.Value()
	}

	for _, h := range r.histograms {
		snapshot[h.name+"_sum"] = h.Sum()
		snapshot[h.name+"_count"] = h.Count()
		snapshot[h.name+"_mean"] = h.Mean()
	}

	return snapshot
}

// Reset resets all metrics.
func (r *Registry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, c := range r.counters {
		c.value.Store(0)
	}

	for _, g := range r.gauges {
		g.value.Store(0)
	}

	for _, h := range r.histograms {
		h.mu.Lock()
		h.sum = 0
		h.count = 0
		for i := range h.counts {
			h.counts[i] = 0
		}
		h.mu.Unlock()
	}
}

// HTTPHandler returns an HTTP handler for metrics.
func (r *Registry) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		accept := req.Header.Get("Accept")
		if strings.Contains(accept, "application/json") {
			w.Header().Set("Content-Type", "application/json")
			r.WriteJSON(w)
		} else {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			r.WritePrometheus(w)
		}
	})
}

// Global default registry.
var defaultRegistry = NewRegistry("witnessd", "")

// Default returns the default global registry.
func Default() *Registry {
	return defaultRegistry
}

// SetDefault sets the default global registry.
func SetDefault(r *Registry) {
	defaultRegistry = r
}

// Percentile calculates the p-th percentile from histogram buckets.
func Percentile(buckets []float64, counts []uint64, p float64) float64 {
	if len(counts) == 0 || counts[len(counts)-1] == 0 {
		return 0
	}

	total := counts[len(counts)-1]
	target := uint64(math.Ceil(float64(total) * p / 100))

	for i, count := range counts {
		if count >= target {
			if i == 0 {
				return buckets[0] / 2
			}
			// Linear interpolation
			lower := buckets[i-1]
			upper := buckets[i]
			if i == len(buckets) {
				upper = lower * 2
			}
			prevCount := uint64(0)
			if i > 0 {
				prevCount = counts[i-1]
			}
			ratio := float64(target-prevCount) / float64(count-prevCount)
			return lower + (upper-lower)*ratio
		}
	}

	return buckets[len(buckets)-1]
}
