// Package tracing provides distributed tracing support for witnessd.
//
// This package provides a lightweight tracing implementation that is compatible
// with OpenTelemetry concepts but does not require the full OpenTelemetry SDK.
// It can be used standalone or integrated with OpenTelemetry exporters.
//
// Features:
//   - Span creation and context propagation
//   - Trace context propagation (W3C Trace Context)
//   - Configurable sampling
//   - Multiple exporters (stdout, file, OTLP)
//   - Attributes and events on spans
package tracing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// TraceID is a unique identifier for a trace.
type TraceID [16]byte

// String returns the hex representation of the TraceID.
func (t TraceID) String() string {
	return hex.EncodeToString(t[:])
}

// IsValid returns true if the TraceID is non-zero.
func (t TraceID) IsValid() bool {
	for _, b := range t {
		if b != 0 {
			return true
		}
	}
	return false
}

// SpanID is a unique identifier for a span.
type SpanID [8]byte

// String returns the hex representation of the SpanID.
func (s SpanID) String() string {
	return hex.EncodeToString(s[:])
}

// IsValid returns true if the SpanID is non-zero.
func (s SpanID) IsValid() bool {
	for _, b := range s {
		if b != 0 {
			return true
		}
	}
	return false
}

// SpanKind represents the kind of span.
type SpanKind int

const (
	// SpanKindInternal is the default span kind.
	SpanKindInternal SpanKind = iota
	// SpanKindServer represents a server-side span.
	SpanKindServer
	// SpanKindClient represents a client-side span.
	SpanKindClient
	// SpanKindProducer represents a producer span.
	SpanKindProducer
	// SpanKindConsumer represents a consumer span.
	SpanKindConsumer
)

// String returns the string representation of SpanKind.
func (k SpanKind) String() string {
	switch k {
	case SpanKindServer:
		return "server"
	case SpanKindClient:
		return "client"
	case SpanKindProducer:
		return "producer"
	case SpanKindConsumer:
		return "consumer"
	default:
		return "internal"
	}
}

// StatusCode represents the status of a span.
type StatusCode int

const (
	// StatusUnset is the default status.
	StatusUnset StatusCode = iota
	// StatusOK indicates success.
	StatusOK
	// StatusError indicates an error occurred.
	StatusError
)

// String returns the string representation of StatusCode.
func (s StatusCode) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusError:
		return "error"
	default:
		return "unset"
	}
}

// Attribute represents a key-value pair attached to a span.
type Attribute struct {
	Key   string
	Value interface{}
}

// Event represents an event that occurred during a span.
type Event struct {
	Name       string
	Timestamp  time.Time
	Attributes []Attribute
}

// SpanContext contains the trace context information.
type SpanContext struct {
	TraceID    TraceID
	SpanID     SpanID
	TraceFlags byte
	TraceState string
	Remote     bool
}

// IsValid returns true if the SpanContext is valid.
func (sc SpanContext) IsValid() bool {
	return sc.TraceID.IsValid() && sc.SpanID.IsValid()
}

// IsSampled returns true if the span should be sampled.
func (sc SpanContext) IsSampled() bool {
	return sc.TraceFlags&0x01 != 0
}

// Span represents a unit of work or operation.
type Span struct {
	mu         sync.RWMutex
	tracer     *Tracer
	name       string
	context    SpanContext
	parent     SpanContext
	kind       SpanKind
	startTime  time.Time
	endTime    time.Time
	attributes []Attribute
	events     []Event
	status     StatusCode
	statusMsg  string
	ended      atomic.Bool
}

// Context returns the span's context.
func (s *Span) Context() SpanContext {
	return s.context
}

// SetName sets the span name.
func (s *Span) SetName(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.name = name
}

// SetAttribute sets an attribute on the span.
func (s *Span) SetAttribute(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attributes = append(s.attributes, Attribute{Key: key, Value: value})
}

// SetAttributes sets multiple attributes on the span.
func (s *Span) SetAttributes(attrs ...Attribute) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attributes = append(s.attributes, attrs...)
}

// AddEvent adds an event to the span.
func (s *Span) AddEvent(name string, attrs ...Attribute) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, Event{
		Name:       name,
		Timestamp:  time.Now(),
		Attributes: attrs,
	})
}

// SetStatus sets the span status.
func (s *Span) SetStatus(code StatusCode, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = code
	s.statusMsg = message
}

// RecordError records an error on the span.
func (s *Span) RecordError(err error) {
	if err == nil {
		return
	}
	s.AddEvent("exception",
		Attribute{Key: "exception.type", Value: fmt.Sprintf("%T", err)},
		Attribute{Key: "exception.message", Value: err.Error()},
	)
	s.SetStatus(StatusError, err.Error())
}

// End ends the span.
func (s *Span) End() {
	if s.ended.Swap(true) {
		return // Already ended
	}

	s.mu.Lock()
	s.endTime = time.Now()
	s.mu.Unlock()

	// Export the span
	if s.tracer != nil && s.tracer.exporter != nil {
		s.tracer.exporter.ExportSpan(s)
	}
}

// Duration returns the span duration.
func (s *Span) Duration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.endTime.IsZero() {
		return time.Since(s.startTime)
	}
	return s.endTime.Sub(s.startTime)
}

// SpanData returns a snapshot of the span data.
type SpanData struct {
	Name       string                 `json:"name"`
	TraceID    string                 `json:"trace_id"`
	SpanID     string                 `json:"span_id"`
	ParentID   string                 `json:"parent_id,omitempty"`
	Kind       string                 `json:"kind"`
	StartTime  time.Time              `json:"start_time"`
	EndTime    time.Time              `json:"end_time"`
	Duration   time.Duration          `json:"duration_ns"`
	Status     string                 `json:"status"`
	StatusMsg  string                 `json:"status_message,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Events     []EventData            `json:"events,omitempty"`
}

// EventData is a serializable event.
type EventData struct {
	Name       string                 `json:"name"`
	Timestamp  time.Time              `json:"timestamp"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// Data returns the span data as a SpanData struct.
func (s *Span) Data() SpanData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	attrs := make(map[string]interface{})
	for _, a := range s.attributes {
		attrs[a.Key] = a.Value
	}

	events := make([]EventData, len(s.events))
	for i, e := range s.events {
		eventAttrs := make(map[string]interface{})
		for _, a := range e.Attributes {
			eventAttrs[a.Key] = a.Value
		}
		events[i] = EventData{
			Name:       e.Name,
			Timestamp:  e.Timestamp,
			Attributes: eventAttrs,
		}
	}

	parentID := ""
	if s.parent.SpanID.IsValid() {
		parentID = s.parent.SpanID.String()
	}

	return SpanData{
		Name:       s.name,
		TraceID:    s.context.TraceID.String(),
		SpanID:     s.context.SpanID.String(),
		ParentID:   parentID,
		Kind:       s.kind.String(),
		StartTime:  s.startTime,
		EndTime:    s.endTime,
		Duration:   s.endTime.Sub(s.startTime),
		Status:     s.status.String(),
		StatusMsg:  s.statusMsg,
		Attributes: attrs,
		Events:     events,
	}
}

// Exporter exports spans.
type Exporter interface {
	ExportSpan(span *Span)
	Shutdown() error
}

// StdoutExporter exports spans to stdout.
type StdoutExporter struct {
	mu      sync.Mutex
	encoder *json.Encoder
	pretty  bool
}

// NewStdoutExporter creates a new StdoutExporter.
func NewStdoutExporter(pretty bool) *StdoutExporter {
	enc := json.NewEncoder(os.Stdout)
	if pretty {
		enc.SetIndent("", "  ")
	}
	return &StdoutExporter{
		encoder: enc,
		pretty:  pretty,
	}
}

// ExportSpan exports a span to stdout.
func (e *StdoutExporter) ExportSpan(span *Span) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.encoder.Encode(span.Data())
}

// Shutdown shuts down the exporter.
func (e *StdoutExporter) Shutdown() error {
	return nil
}

// FileExporter exports spans to a file.
type FileExporter struct {
	mu      sync.Mutex
	file    *os.File
	encoder *json.Encoder
}

// NewFileExporter creates a new FileExporter.
func NewFileExporter(path string) (*FileExporter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	return &FileExporter{
		file:    f,
		encoder: json.NewEncoder(f),
	}, nil
}

// ExportSpan exports a span to the file.
func (e *FileExporter) ExportSpan(span *Span) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.encoder.Encode(span.Data())
}

// Shutdown closes the file.
func (e *FileExporter) Shutdown() error {
	return e.file.Close()
}

// NoopExporter is an exporter that does nothing.
type NoopExporter struct{}

// ExportSpan does nothing.
func (e *NoopExporter) ExportSpan(span *Span) {}

// Shutdown does nothing.
func (e *NoopExporter) Shutdown() error { return nil }

// MultiExporter exports to multiple exporters.
type MultiExporter struct {
	exporters []Exporter
}

// NewMultiExporter creates a new MultiExporter.
func NewMultiExporter(exporters ...Exporter) *MultiExporter {
	return &MultiExporter{exporters: exporters}
}

// ExportSpan exports a span to all exporters.
func (e *MultiExporter) ExportSpan(span *Span) {
	for _, exp := range e.exporters {
		exp.ExportSpan(span)
	}
}

// Shutdown shuts down all exporters.
func (e *MultiExporter) Shutdown() error {
	var lastErr error
	for _, exp := range e.exporters {
		if err := exp.Shutdown(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Sampler decides whether a span should be sampled.
type Sampler interface {
	ShouldSample(traceID TraceID, name string) bool
}

// AlwaysSample samples all spans.
type AlwaysSample struct{}

// ShouldSample always returns true.
func (s AlwaysSample) ShouldSample(traceID TraceID, name string) bool {
	return true
}

// NeverSample never samples spans.
type NeverSample struct{}

// ShouldSample always returns false.
func (s NeverSample) ShouldSample(traceID TraceID, name string) bool {
	return false
}

// RatioSampler samples a fraction of spans.
type RatioSampler struct {
	ratio float64
}

// NewRatioSampler creates a new RatioSampler.
func NewRatioSampler(ratio float64) *RatioSampler {
	if ratio < 0 {
		ratio = 0
	} else if ratio > 1 {
		ratio = 1
	}
	return &RatioSampler{ratio: ratio}
}

// ShouldSample returns true based on the sampling ratio.
func (s *RatioSampler) ShouldSample(traceID TraceID, name string) bool {
	// Use first 8 bytes of trace ID as a uint64
	h := uint64(0)
	for i := 0; i < 8; i++ {
		h = h<<8 | uint64(traceID[i])
	}
	// Compare with threshold
	threshold := uint64(s.ratio * float64(^uint64(0)))
	return h < threshold
}

// TracerConfig configures a tracer.
type TracerConfig struct {
	ServiceName string
	Exporter    Exporter
	Sampler     Sampler
	Enabled     bool
}

// Tracer creates spans.
type Tracer struct {
	serviceName string
	exporter    Exporter
	sampler     Sampler
	enabled     bool
}

// NewTracer creates a new Tracer.
func NewTracer(cfg *TracerConfig) *Tracer {
	if cfg == nil {
		cfg = &TracerConfig{}
	}

	exporter := cfg.Exporter
	if exporter == nil {
		exporter = &NoopExporter{}
	}

	sampler := cfg.Sampler
	if sampler == nil {
		sampler = AlwaysSample{}
	}

	return &Tracer{
		serviceName: cfg.ServiceName,
		exporter:    exporter,
		sampler:     sampler,
		enabled:     cfg.Enabled,
	}
}

// Start starts a new span.
func (t *Tracer) Start(ctx context.Context, name string, opts ...SpanOption) (context.Context, *Span) {
	if !t.enabled {
		return ctx, &Span{name: name}
	}

	// Get parent span context from context
	parent := SpanFromContext(ctx)
	var parentContext SpanContext
	if parent != nil {
		parentContext = parent.Context()
	}

	// Generate trace ID and span ID
	var traceID TraceID
	if parentContext.TraceID.IsValid() {
		traceID = parentContext.TraceID
	} else {
		rand.Read(traceID[:])
	}

	var spanID SpanID
	rand.Read(spanID[:])

	// Check sampling
	sampled := t.sampler.ShouldSample(traceID, name)
	var traceFlags byte
	if sampled {
		traceFlags = 0x01
	}

	span := &Span{
		tracer: t,
		name:   name,
		context: SpanContext{
			TraceID:    traceID,
			SpanID:     spanID,
			TraceFlags: traceFlags,
		},
		parent:     parentContext,
		kind:       SpanKindInternal,
		startTime:  time.Now(),
		attributes: make([]Attribute, 0),
		events:     make([]Event, 0),
	}

	// Apply options
	for _, opt := range opts {
		opt(span)
	}

	// Add service name attribute
	if t.serviceName != "" {
		span.SetAttribute("service.name", t.serviceName)
	}

	return ContextWithSpan(ctx, span), span
}

// SpanOption configures a span.
type SpanOption func(*Span)

// WithSpanKind sets the span kind.
func WithSpanKind(kind SpanKind) SpanOption {
	return func(s *Span) {
		s.kind = kind
	}
}

// WithAttributes sets initial attributes.
func WithAttributes(attrs ...Attribute) SpanOption {
	return func(s *Span) {
		s.attributes = append(s.attributes, attrs...)
	}
}

// Context key for spans.
type spanContextKey struct{}

// ContextWithSpan returns a new context with the span.
func ContextWithSpan(ctx context.Context, span *Span) context.Context {
	return context.WithValue(ctx, spanContextKey{}, span)
}

// SpanFromContext returns the span from the context.
func SpanFromContext(ctx context.Context) *Span {
	if ctx == nil {
		return nil
	}
	if span, ok := ctx.Value(spanContextKey{}).(*Span); ok {
		return span
	}
	return nil
}

// Global tracer.
var (
	globalTracer     *Tracer
	globalTracerOnce sync.Once
)

// GetTracer returns the global tracer.
func GetTracer() *Tracer {
	globalTracerOnce.Do(func() {
		globalTracer = NewTracer(&TracerConfig{
			ServiceName: "witnessd",
			Enabled:     false, // Disabled by default
		})
	})
	return globalTracer
}

// SetTracer sets the global tracer.
func SetTracer(t *Tracer) {
	globalTracer = t
}

// InitTracer initializes the global tracer with the given config.
func InitTracer(cfg *TracerConfig) *Tracer {
	globalTracer = NewTracer(cfg)
	return globalTracer
}

// Shutdown shuts down the global tracer.
func Shutdown() error {
	if globalTracer != nil && globalTracer.exporter != nil {
		return globalTracer.exporter.Shutdown()
	}
	return nil
}

// Convenience functions.

// StartSpan starts a span using the global tracer.
func StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, *Span) {
	return GetTracer().Start(ctx, name, opts...)
}

// Trace is a convenience function for tracing a function.
func Trace(ctx context.Context, name string, fn func(ctx context.Context) error) error {
	ctx, span := StartSpan(ctx, name)
	defer span.End()

	err := fn(ctx)
	if err != nil {
		span.RecordError(err)
	} else {
		span.SetStatus(StatusOK, "")
	}
	return err
}

// W3C Trace Context parsing and formatting.

// ParseTraceParent parses a W3C traceparent header.
func ParseTraceParent(header string) (SpanContext, error) {
	// Format: version-traceId-parentId-flags
	// Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01

	if len(header) != 55 {
		return SpanContext{}, fmt.Errorf("invalid traceparent length")
	}

	if header[2] != '-' || header[35] != '-' || header[52] != '-' {
		return SpanContext{}, fmt.Errorf("invalid traceparent format")
	}

	version := header[0:2]
	if version != "00" {
		return SpanContext{}, fmt.Errorf("unsupported traceparent version: %s", version)
	}

	traceIDHex := header[3:35]
	spanIDHex := header[36:52]
	flagsHex := header[53:55]

	var traceID TraceID
	traceIDBytes, err := hex.DecodeString(traceIDHex)
	if err != nil {
		return SpanContext{}, fmt.Errorf("invalid trace ID: %w", err)
	}
	copy(traceID[:], traceIDBytes)

	var spanID SpanID
	spanIDBytes, err := hex.DecodeString(spanIDHex)
	if err != nil {
		return SpanContext{}, fmt.Errorf("invalid span ID: %w", err)
	}
	copy(spanID[:], spanIDBytes)

	flags := byte(0)
	if flagsHex == "01" {
		flags = 0x01
	}

	return SpanContext{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: flags,
		Remote:     true,
	}, nil
}

// FormatTraceParent formats a SpanContext as a W3C traceparent header.
func FormatTraceParent(sc SpanContext) string {
	flags := "00"
	if sc.IsSampled() {
		flags = "01"
	}
	return fmt.Sprintf("00-%s-%s-%s", sc.TraceID.String(), sc.SpanID.String(), flags)
}

// InjectTraceContext injects trace context into HTTP headers.
func InjectTraceContext(ctx context.Context, setter func(key, value string)) {
	span := SpanFromContext(ctx)
	if span == nil || !span.Context().IsValid() {
		return
	}
	setter("traceparent", FormatTraceParent(span.Context()))
	if span.Context().TraceState != "" {
		setter("tracestate", span.Context().TraceState)
	}
}

// ExtractTraceContext extracts trace context from HTTP headers.
func ExtractTraceContext(getter func(key string) string) SpanContext {
	traceparent := getter("traceparent")
	if traceparent == "" {
		return SpanContext{}
	}

	sc, err := ParseTraceParent(traceparent)
	if err != nil {
		return SpanContext{}
	}

	sc.TraceState = getter("tracestate")
	return sc
}

// BufferedExporter buffers spans and exports them in batches.
type BufferedExporter struct {
	mu       sync.Mutex
	spans    []SpanData
	maxBatch int
	exporter Exporter
	writer   io.Writer
}

// NewBufferedExporter creates a new BufferedExporter.
func NewBufferedExporter(w io.Writer, maxBatch int) *BufferedExporter {
	if maxBatch <= 0 {
		maxBatch = 100
	}
	return &BufferedExporter{
		spans:    make([]SpanData, 0, maxBatch),
		maxBatch: maxBatch,
		writer:   w,
	}
}

// ExportSpan adds a span to the buffer.
func (e *BufferedExporter) ExportSpan(span *Span) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.spans = append(e.spans, span.Data())
	if len(e.spans) >= e.maxBatch {
		e.flush()
	}
}

// flush writes buffered spans.
func (e *BufferedExporter) flush() {
	if len(e.spans) == 0 {
		return
	}

	enc := json.NewEncoder(e.writer)
	for _, s := range e.spans {
		enc.Encode(s)
	}
	e.spans = e.spans[:0]
}

// Shutdown flushes remaining spans and closes.
func (e *BufferedExporter) Shutdown() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.flush()
	return nil
}
