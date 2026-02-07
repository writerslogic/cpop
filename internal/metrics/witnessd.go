// Package metrics provides Prometheus-compatible metrics for witnessd.
package metrics

import (
	"time"
)

// WitnessdMetrics holds all witnessd-specific metrics.
type WitnessdMetrics struct {
	registry *Registry

	// Counters
	KeystrokesTotal   *Counter
	CheckpointsTotal  *Counter
	SessionsTotal     *Counter
	VerificationsTotal *Counter
	ExportsTotal      *Counter
	AnchorsTotal      *Counter
	ErrorsTotal       *Counter

	// Gauges
	ActiveSessions    *Gauge
	WALSizeBytes      *Gauge
	MMRSize           *Gauge
	DatabaseSizeBytes *Gauge
	UptimeSeconds     *Gauge
	LastCheckpointTs  *Gauge
	PendingAnchors    *Gauge

	// Histograms
	CheckpointDuration    *Histogram
	VDFComputationTime    *Histogram
	VerificationDuration  *Histogram
	AnchorDuration        *Histogram
	DatabaseQueryDuration *Histogram
	KeystrokeInterval     *Histogram
}

// startTime records when metrics were initialized.
var startTime = time.Now()

// NewWitnessdMetrics creates and registers all witnessd metrics.
func NewWitnessdMetrics(registry *Registry) *WitnessdMetrics {
	if registry == nil {
		registry = Default()
	}

	m := &WitnessdMetrics{
		registry: registry,

		// Counters
		KeystrokesTotal: registry.RegisterCounter(
			"keystrokes_total",
			"Total number of keystrokes recorded",
			nil,
		),
		CheckpointsTotal: registry.RegisterCounter(
			"checkpoints_total",
			"Total number of checkpoints created",
			nil,
		),
		SessionsTotal: registry.RegisterCounter(
			"sessions_total",
			"Total number of sessions started",
			nil,
		),
		VerificationsTotal: registry.RegisterCounter(
			"verifications_total",
			"Total number of verifications performed",
			nil,
		),
		ExportsTotal: registry.RegisterCounter(
			"exports_total",
			"Total number of evidence exports",
			nil,
		),
		AnchorsTotal: registry.RegisterCounter(
			"anchors_total",
			"Total number of anchoring operations",
			nil,
		),
		ErrorsTotal: registry.RegisterCounter(
			"errors_total",
			"Total number of errors",
			nil,
		),

		// Gauges
		ActiveSessions: registry.RegisterGauge(
			"active_sessions",
			"Number of currently active sessions",
			nil,
		),
		WALSizeBytes: registry.RegisterGauge(
			"wal_size_bytes",
			"Size of the write-ahead log in bytes",
			nil,
		),
		MMRSize: registry.RegisterGauge(
			"mmr_size",
			"Number of nodes in the MMR",
			nil,
		),
		DatabaseSizeBytes: registry.RegisterGauge(
			"database_size_bytes",
			"Size of the database in bytes",
			nil,
		),
		UptimeSeconds: registry.RegisterGauge(
			"uptime_seconds",
			"Number of seconds the daemon has been running",
			nil,
		),
		LastCheckpointTs: registry.RegisterGauge(
			"last_checkpoint_timestamp",
			"Unix timestamp of the last checkpoint",
			nil,
		),
		PendingAnchors: registry.RegisterGauge(
			"pending_anchors",
			"Number of pending anchor operations",
			nil,
		),

		// Histograms
		CheckpointDuration: registry.RegisterHistogram(
			"checkpoint_duration_seconds",
			"Duration of checkpoint operations in seconds",
			nil,
			DurationBuckets,
		),
		VDFComputationTime: registry.RegisterHistogram(
			"vdf_computation_seconds",
			"Duration of VDF computation in seconds",
			nil,
			[]float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600},
		),
		VerificationDuration: registry.RegisterHistogram(
			"verification_duration_seconds",
			"Duration of verification operations in seconds",
			nil,
			DurationBuckets,
		),
		AnchorDuration: registry.RegisterHistogram(
			"anchor_duration_seconds",
			"Duration of anchoring operations in seconds",
			nil,
			[]float64{1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
		),
		DatabaseQueryDuration: registry.RegisterHistogram(
			"database_query_duration_seconds",
			"Duration of database queries in seconds",
			nil,
			DurationBuckets,
		),
		KeystrokeInterval: registry.RegisterHistogram(
			"keystroke_interval_seconds",
			"Time between keystrokes in seconds",
			nil,
			[]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10},
		),
	}

	return m
}

// RecordKeystroke records a keystroke.
func (m *WitnessdMetrics) RecordKeystroke() {
	m.KeystrokesTotal.Inc()
}

// RecordKeystrokeInterval records the interval between keystrokes.
func (m *WitnessdMetrics) RecordKeystrokeInterval(d time.Duration) {
	m.KeystrokeInterval.ObserveDuration(d)
}

// RecordCheckpoint records a checkpoint creation.
func (m *WitnessdMetrics) RecordCheckpoint(duration time.Duration) {
	m.CheckpointsTotal.Inc()
	m.CheckpointDuration.ObserveDuration(duration)
	m.LastCheckpointTs.Set(time.Now().Unix())
}

// StartCheckpointTimer returns a timer for checkpoint operations.
func (m *WitnessdMetrics) StartCheckpointTimer() *HistogramTimer {
	return m.CheckpointDuration.Timer()
}

// RecordVDFComputation records a VDF computation.
func (m *WitnessdMetrics) RecordVDFComputation(duration time.Duration) {
	m.VDFComputationTime.ObserveDuration(duration)
}

// StartVDFTimer returns a timer for VDF computation.
func (m *WitnessdMetrics) StartVDFTimer() *HistogramTimer {
	return m.VDFComputationTime.Timer()
}

// RecordVerification records a verification operation.
func (m *WitnessdMetrics) RecordVerification(duration time.Duration, success bool) {
	m.VerificationsTotal.Inc()
	m.VerificationDuration.ObserveDuration(duration)
	if !success {
		m.ErrorsTotal.Inc()
	}
}

// StartVerificationTimer returns a timer for verification operations.
func (m *WitnessdMetrics) StartVerificationTimer() *HistogramTimer {
	return m.VerificationDuration.Timer()
}

// RecordExport records an evidence export.
func (m *WitnessdMetrics) RecordExport() {
	m.ExportsTotal.Inc()
}

// RecordAnchor records an anchoring operation.
func (m *WitnessdMetrics) RecordAnchor(duration time.Duration, success bool) {
	m.AnchorsTotal.Inc()
	m.AnchorDuration.ObserveDuration(duration)
	if !success {
		m.ErrorsTotal.Inc()
	}
}

// StartAnchorTimer returns a timer for anchoring operations.
func (m *WitnessdMetrics) StartAnchorTimer() *HistogramTimer {
	return m.AnchorDuration.Timer()
}

// RecordDatabaseQuery records a database query.
func (m *WitnessdMetrics) RecordDatabaseQuery(duration time.Duration) {
	m.DatabaseQueryDuration.ObserveDuration(duration)
}

// StartDatabaseQueryTimer returns a timer for database queries.
func (m *WitnessdMetrics) StartDatabaseQueryTimer() *HistogramTimer {
	return m.DatabaseQueryDuration.Timer()
}

// RecordError records an error.
func (m *WitnessdMetrics) RecordError() {
	m.ErrorsTotal.Inc()
}

// SessionStarted records a session start.
func (m *WitnessdMetrics) SessionStarted() {
	m.SessionsTotal.Inc()
	m.ActiveSessions.Inc()
}

// SessionEnded records a session end.
func (m *WitnessdMetrics) SessionEnded() {
	m.ActiveSessions.Dec()
}

// SetWALSize sets the WAL size.
func (m *WitnessdMetrics) SetWALSize(bytes int64) {
	m.WALSizeBytes.Set(bytes)
}

// SetMMRSize sets the MMR size.
func (m *WitnessdMetrics) SetMMRSize(nodes int64) {
	m.MMRSize.Set(nodes)
}

// SetDatabaseSize sets the database size.
func (m *WitnessdMetrics) SetDatabaseSize(bytes int64) {
	m.DatabaseSizeBytes.Set(bytes)
}

// SetPendingAnchors sets the number of pending anchors.
func (m *WitnessdMetrics) SetPendingAnchors(count int64) {
	m.PendingAnchors.Set(count)
}

// UpdateUptime updates the uptime metric.
func (m *WitnessdMetrics) UpdateUptime() {
	m.UptimeSeconds.Set(int64(time.Since(startTime).Seconds()))
}

// Snapshot returns a snapshot of key metrics.
func (m *WitnessdMetrics) Snapshot() map[string]interface{} {
	m.UpdateUptime()
	return map[string]interface{}{
		"keystrokes_total":       m.KeystrokesTotal.Value(),
		"checkpoints_total":      m.CheckpointsTotal.Value(),
		"sessions_total":         m.SessionsTotal.Value(),
		"verifications_total":    m.VerificationsTotal.Value(),
		"exports_total":          m.ExportsTotal.Value(),
		"anchors_total":          m.AnchorsTotal.Value(),
		"errors_total":           m.ErrorsTotal.Value(),
		"active_sessions":        m.ActiveSessions.Value(),
		"wal_size_bytes":         m.WALSizeBytes.Value(),
		"mmr_size":               m.MMRSize.Value(),
		"database_size_bytes":    m.DatabaseSizeBytes.Value(),
		"uptime_seconds":         m.UptimeSeconds.Value(),
		"checkpoint_avg_seconds": m.CheckpointDuration.Mean(),
		"vdf_avg_seconds":        m.VDFComputationTime.Mean(),
	}
}

// Global witnessd metrics instance.
var defaultWitnessdMetrics *WitnessdMetrics

// GetMetrics returns the global witnessd metrics instance.
func GetMetrics() *WitnessdMetrics {
	if defaultWitnessdMetrics == nil {
		defaultWitnessdMetrics = NewWitnessdMetrics(Default())
	}
	return defaultWitnessdMetrics
}

// InitMetrics initializes the global witnessd metrics with a custom registry.
func InitMetrics(registry *Registry) *WitnessdMetrics {
	defaultWitnessdMetrics = NewWitnessdMetrics(registry)
	return defaultWitnessdMetrics
}
