// Package store provides SQLite-based event storage for witnessd.
package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Migration represents a database schema migration.
type Migration struct {
	Version     int
	Description string
	Up          string
	Down        string
}

// migrations contains all database migrations in order.
var migrations = []Migration{
	{
		Version:     1,
		Description: "Initial schema with events, devices, contexts, and weaves",
		Up:          migrationV1Up,
		Down:        migrationV1Down,
	},
	{
		Version:     2,
		Description: "Add sessions table for tracking sessions",
		Up:          migrationV2Up,
		Down:        migrationV2Down,
	},
	{
		Version:     3,
		Description: "Add checkpoints table for explicit commit tracking",
		Up:          migrationV3Up,
		Down:        migrationV3Down,
	},
	{
		Version:     4,
		Description: "Add anchor_proofs table for external timestamp anchors",
		Up:          migrationV4Up,
		Down:        migrationV4Down,
	},
	{
		Version:     5,
		Description: "Add forensic_profiles table for authorship analysis",
		Up:          migrationV5Up,
		Down:        migrationV5Down,
	},
	{
		Version:     6,
		Description: "Add presence_sessions table for human verification",
		Up:          migrationV6Up,
		Down:        migrationV6Down,
	},
	{
		Version:     7,
		Description: "Add keystroke_sessions table for jitter evidence",
		Up:          migrationV7Up,
		Down:        migrationV7Down,
	},
	{
		Version:     8,
		Description: "Add config_snapshots table for configuration history",
		Up:          migrationV8Up,
		Down:        migrationV8Down,
	},
}

// Migration SQL statements

const migrationV1Up = `
-- Devices table
CREATE TABLE IF NOT EXISTS devices (
    device_id       BLOB PRIMARY KEY,
    created_at      INTEGER NOT NULL,
    signing_pubkey  BLOB NOT NULL,
    hostname        TEXT
);

-- Contexts table for editing context markers
CREATE TABLE IF NOT EXISTS contexts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT NOT NULL,
    note        TEXT,
    start_ns    INTEGER NOT NULL,
    end_ns      INTEGER
);

-- Events table (main event log)
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       BLOB NOT NULL REFERENCES devices(device_id),
    mmr_index       INTEGER NOT NULL UNIQUE,
    mmr_leaf_hash   BLOB NOT NULL,
    timestamp_ns    INTEGER NOT NULL,
    file_path       TEXT NOT NULL,
    content_hash    BLOB NOT NULL,
    file_size       INTEGER NOT NULL,
    size_delta      INTEGER NOT NULL,
    context_id      INTEGER REFERENCES contexts(id)
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_events_file ON events(file_path, timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_events_content ON events(content_hash);

-- Edit regions table for forensic analysis
CREATE TABLE IF NOT EXISTS edit_regions (
    event_id    INTEGER NOT NULL REFERENCES events(id),
    ordinal     INTEGER NOT NULL,
    start_pct   REAL NOT NULL,
    end_pct     REAL NOT NULL,
    delta_sign  INTEGER NOT NULL,
    byte_count  INTEGER NOT NULL,
    PRIMARY KEY (event_id, ordinal)
);

-- Verification index for MMR verification
CREATE TABLE IF NOT EXISTS verification_index (
    mmr_index       INTEGER PRIMARY KEY,
    leaf_hash       BLOB NOT NULL,
    metadata_hash   BLOB NOT NULL,
    regions_root    BLOB,
    verified_at     INTEGER
);

-- Weaves table for cross-device state sync
CREATE TABLE IF NOT EXISTS weaves (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns    INTEGER NOT NULL,
    device_roots    TEXT NOT NULL,
    weave_hash      BLOB NOT NULL,
    signature       BLOB NOT NULL
);
`

const migrationV1Down = `
DROP TABLE IF EXISTS weaves;
DROP TABLE IF EXISTS verification_index;
DROP TABLE IF EXISTS edit_regions;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS contexts;
DROP TABLE IF EXISTS devices;
`

const migrationV2Up = `
-- Sessions table for tracking editing sessions
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    device_id       BLOB NOT NULL REFERENCES devices(device_id),
    started_at      INTEGER NOT NULL,
    ended_at        INTEGER,
    document_path   TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    keystroke_count INTEGER DEFAULT 0,
    sample_count    INTEGER DEFAULT 0,
    metadata        TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_sessions_document ON sessions(document_path);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
`

const migrationV2Down = `
DROP INDEX IF EXISTS idx_sessions_status;
DROP INDEX IF EXISTS idx_sessions_document;
DROP INDEX IF EXISTS idx_sessions_device;
DROP TABLE IF EXISTS sessions;
`

const migrationV3Up = `
-- Checkpoints table for explicit commits
CREATE TABLE IF NOT EXISTS checkpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       BLOB NOT NULL REFERENCES devices(device_id),
    session_id      TEXT REFERENCES sessions(id),
    document_path   TEXT NOT NULL,
    sequence_num    INTEGER NOT NULL,
    timestamp_ns    INTEGER NOT NULL,
    content_hash    BLOB NOT NULL,
    event_hash      BLOB NOT NULL,
    file_size       INTEGER NOT NULL,
    size_delta      INTEGER NOT NULL,
    vdf_input       BLOB,
    vdf_output      BLOB,
    vdf_iterations  INTEGER DEFAULT 0,
    message         TEXT,
    signature       BLOB,
    UNIQUE(document_path, sequence_num)
);

CREATE INDEX IF NOT EXISTS idx_checkpoints_document ON checkpoints(document_path, sequence_num);
CREATE INDEX IF NOT EXISTS idx_checkpoints_timestamp ON checkpoints(timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_checkpoints_session ON checkpoints(session_id);
`

const migrationV3Down = `
DROP INDEX IF EXISTS idx_checkpoints_session;
DROP INDEX IF EXISTS idx_checkpoints_timestamp;
DROP INDEX IF EXISTS idx_checkpoints_document;
DROP TABLE IF EXISTS checkpoints;
`

const migrationV4Up = `
-- Anchor proofs table for external timestamp anchors
CREATE TABLE IF NOT EXISTS anchor_proofs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    checkpoint_id   INTEGER REFERENCES checkpoints(id),
    event_id        INTEGER REFERENCES events(id),
    provider        TEXT NOT NULL,
    provider_type   TEXT NOT NULL,
    hash            BLOB NOT NULL,
    timestamp       INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    raw_proof       BLOB,
    verify_url      TEXT,
    block_height    INTEGER,
    block_hash      TEXT,
    block_time      INTEGER,
    transaction_id  TEXT,
    certificate     BLOB,
    metadata        TEXT,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_anchors_checkpoint ON anchor_proofs(checkpoint_id);
CREATE INDEX IF NOT EXISTS idx_anchors_event ON anchor_proofs(event_id);
CREATE INDEX IF NOT EXISTS idx_anchors_provider ON anchor_proofs(provider);
CREATE INDEX IF NOT EXISTS idx_anchors_status ON anchor_proofs(status);
CREATE INDEX IF NOT EXISTS idx_anchors_hash ON anchor_proofs(hash);

-- Anchor batches for batching multiple hashes
CREATE TABLE IF NOT EXISTS anchor_batches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    provider        TEXT NOT NULL,
    merkle_root     BLOB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    created_at      INTEGER NOT NULL,
    submitted_at    INTEGER,
    confirmed_at    INTEGER
);

-- Batch items linking checkpoints/events to batches
CREATE TABLE IF NOT EXISTS anchor_batch_items (
    batch_id        INTEGER NOT NULL REFERENCES anchor_batches(id),
    checkpoint_id   INTEGER REFERENCES checkpoints(id),
    event_id        INTEGER REFERENCES events(id),
    hash            BLOB NOT NULL,
    merkle_proof    BLOB,
    PRIMARY KEY (batch_id, hash)
);
`

const migrationV4Down = `
DROP TABLE IF EXISTS anchor_batch_items;
DROP TABLE IF EXISTS anchor_batches;
DROP INDEX IF EXISTS idx_anchors_hash;
DROP INDEX IF EXISTS idx_anchors_status;
DROP INDEX IF EXISTS idx_anchors_provider;
DROP INDEX IF EXISTS idx_anchors_event;
DROP INDEX IF EXISTS idx_anchors_checkpoint;
DROP TABLE IF EXISTS anchor_proofs;
`

const migrationV5Up = `
-- Forensic profiles for authorship analysis
CREATE TABLE IF NOT EXISTS forensic_profiles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    document_path   TEXT NOT NULL,
    session_id      TEXT REFERENCES sessions(id),
    analysis_type   TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    event_count     INTEGER NOT NULL,
    time_span_ns    INTEGER NOT NULL,
    session_count   INTEGER NOT NULL,
    first_event_ns  INTEGER NOT NULL,
    last_event_ns   INTEGER NOT NULL,
    -- Primary metrics
    monotonic_append_ratio  REAL,
    edit_entropy            REAL,
    median_interval_ns      INTEGER,
    positive_negative_ratio REAL,
    deletion_clustering     REAL,
    -- Assessment
    assessment      TEXT,
    confidence      REAL,
    anomalies       TEXT,
    metadata        TEXT
);

CREATE INDEX IF NOT EXISTS idx_profiles_document ON forensic_profiles(document_path);
CREATE INDEX IF NOT EXISTS idx_profiles_session ON forensic_profiles(session_id);
CREATE INDEX IF NOT EXISTS idx_profiles_created ON forensic_profiles(created_at);

-- Anomaly log for detected patterns
CREATE TABLE IF NOT EXISTS forensic_anomalies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      INTEGER NOT NULL REFERENCES forensic_profiles(id),
    event_id        INTEGER REFERENCES events(id),
    timestamp_ns    INTEGER NOT NULL,
    anomaly_type    TEXT NOT NULL,
    severity        TEXT NOT NULL,
    description     TEXT,
    context         TEXT,
    metrics         TEXT
);

CREATE INDEX IF NOT EXISTS idx_anomalies_profile ON forensic_anomalies(profile_id);
CREATE INDEX IF NOT EXISTS idx_anomalies_type ON forensic_anomalies(anomaly_type);
CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON forensic_anomalies(severity);
`

const migrationV5Down = `
DROP INDEX IF EXISTS idx_anomalies_severity;
DROP INDEX IF EXISTS idx_anomalies_type;
DROP INDEX IF EXISTS idx_anomalies_profile;
DROP TABLE IF EXISTS forensic_anomalies;
DROP INDEX IF EXISTS idx_profiles_created;
DROP INDEX IF EXISTS idx_profiles_session;
DROP INDEX IF EXISTS idx_profiles_document;
DROP TABLE IF EXISTS forensic_profiles;
`

const migrationV6Up = `
-- Presence sessions for human verification
CREATE TABLE IF NOT EXISTS presence_sessions (
    id              TEXT PRIMARY KEY,
    device_id       BLOB NOT NULL REFERENCES devices(device_id),
    started_at      INTEGER NOT NULL,
    ended_at        INTEGER,
    active          INTEGER NOT NULL DEFAULT 1,
    challenges_issued   INTEGER DEFAULT 0,
    challenges_passed   INTEGER DEFAULT 0,
    challenges_failed   INTEGER DEFAULT 0,
    challenges_missed   INTEGER DEFAULT 0,
    verification_rate   REAL DEFAULT 0,
    metadata        TEXT
);

CREATE INDEX IF NOT EXISTS idx_presence_device ON presence_sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_presence_active ON presence_sessions(active);

-- Presence challenges
CREATE TABLE IF NOT EXISTS presence_challenges (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES presence_sessions(id),
    issued_at       INTEGER NOT NULL,
    responded_at    INTEGER,
    challenge_type  TEXT NOT NULL,
    prompt          TEXT NOT NULL,
    expected        TEXT NOT NULL,
    response        TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    time_taken_ms   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_challenges_session ON presence_challenges(session_id);
CREATE INDEX IF NOT EXISTS idx_challenges_status ON presence_challenges(status);
`

const migrationV6Down = `
DROP INDEX IF EXISTS idx_challenges_status;
DROP INDEX IF EXISTS idx_challenges_session;
DROP TABLE IF EXISTS presence_challenges;
DROP INDEX IF EXISTS idx_presence_active;
DROP INDEX IF EXISTS idx_presence_device;
DROP TABLE IF EXISTS presence_sessions;
`

const migrationV7Up = `
-- Keystroke sessions for jitter evidence
CREATE TABLE IF NOT EXISTS keystroke_sessions (
    id              TEXT PRIMARY KEY,
    session_id      TEXT REFERENCES sessions(id),
    device_id       BLOB NOT NULL REFERENCES devices(device_id),
    document_path   TEXT NOT NULL,
    started_at      INTEGER NOT NULL,
    ended_at        INTEGER,
    total_keystrokes    INTEGER DEFAULT 0,
    total_samples       INTEGER DEFAULT 0,
    duration_ns         INTEGER DEFAULT 0,
    keystrokes_per_min  REAL DEFAULT 0,
    unique_doc_hashes   INTEGER DEFAULT 0,
    chain_valid         INTEGER DEFAULT 1,
    tpm_bound           INTEGER DEFAULT 0,
    compromised         INTEGER DEFAULT 0,
    compromise_reason   TEXT,
    metadata            TEXT
);

CREATE INDEX IF NOT EXISTS idx_keystroke_document ON keystroke_sessions(document_path);
CREATE INDEX IF NOT EXISTS idx_keystroke_session ON keystroke_sessions(session_id);

-- Jitter samples
CREATE TABLE IF NOT EXISTS jitter_samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    keystroke_session_id TEXT NOT NULL REFERENCES keystroke_sessions(id),
    sequence_num    INTEGER NOT NULL,
    timestamp_ns    INTEGER NOT NULL,
    keystroke_count INTEGER NOT NULL,
    document_hash   BLOB,
    jitter_hash     BLOB NOT NULL,
    prev_hash       BLOB,
    interval_ns     INTEGER,
    UNIQUE(keystroke_session_id, sequence_num)
);

CREATE INDEX IF NOT EXISTS idx_jitter_session ON jitter_samples(keystroke_session_id);
CREATE INDEX IF NOT EXISTS idx_jitter_timestamp ON jitter_samples(timestamp_ns);
`

const migrationV7Down = `
DROP INDEX IF EXISTS idx_jitter_timestamp;
DROP INDEX IF EXISTS idx_jitter_session;
DROP TABLE IF EXISTS jitter_samples;
DROP INDEX IF EXISTS idx_keystroke_session;
DROP INDEX IF EXISTS idx_keystroke_document;
DROP TABLE IF EXISTS keystroke_sessions;
`

const migrationV8Up = `
-- Config snapshots for configuration history
CREATE TABLE IF NOT EXISTS config_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    version         INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    config_hash     BLOB NOT NULL,
    config_data     TEXT NOT NULL,
    reason          TEXT,
    migrated_from   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_config_version ON config_snapshots(version);
CREATE INDEX IF NOT EXISTS idx_config_created ON config_snapshots(created_at);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
    version         INTEGER PRIMARY KEY,
    applied_at      INTEGER NOT NULL,
    description     TEXT
);
`

const migrationV8Down = `
DROP INDEX IF EXISTS idx_config_created;
DROP INDEX IF EXISTS idx_config_version;
DROP TABLE IF EXISTS config_snapshots;
DROP TABLE IF EXISTS schema_migrations;
`

// MigrateDB applies all pending migrations to the database.
func MigrateDB(db *sql.DB) error {
	// Ensure migrations table exists
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     INTEGER PRIMARY KEY,
			applied_at  INTEGER NOT NULL,
			description TEXT
		)
	`)
	if err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	// Get current version
	var currentVersion int
	err = db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("get current version: %w", err)
	}

	// Apply pending migrations
	for _, m := range migrations {
		if m.Version <= currentVersion {
			continue
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin transaction for migration %d: %w", m.Version, err)
		}

		// Apply migration
		if _, err := tx.Exec(m.Up); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %d (%s): %w", m.Version, m.Description, err)
		}

		// Record migration
		if _, err := tx.Exec(
			"INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
			m.Version, time.Now().UnixNano(), m.Description,
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %d: %w", m.Version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", m.Version, err)
		}
	}

	return nil
}

// RollbackMigration rolls back the last applied migration.
func RollbackMigration(db *sql.DB) error {
	// Get current version
	var currentVersion int
	err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("get current version: %w", err)
	}

	if currentVersion == 0 {
		return fmt.Errorf("no migrations to rollback")
	}

	// Find the migration
	var migration *Migration
	for i := range migrations {
		if migrations[i].Version == currentVersion {
			migration = &migrations[i]
			break
		}
	}

	if migration == nil {
		return fmt.Errorf("migration %d not found", currentVersion)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	// Apply rollback
	if _, err := tx.Exec(migration.Down); err != nil {
		tx.Rollback()
		return fmt.Errorf("rollback migration %d: %w", currentVersion, err)
	}

	// Remove migration record
	if _, err := tx.Exec("DELETE FROM schema_migrations WHERE version = ?", currentVersion); err != nil {
		tx.Rollback()
		return fmt.Errorf("remove migration record: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit rollback: %w", err)
	}

	return nil
}

// GetMigrationStatus returns the current migration status.
type MigrationStatus struct {
	CurrentVersion int
	LatestVersion  int
	Pending        []Migration
	Applied        []AppliedMigration
}

type AppliedMigration struct {
	Version     int
	AppliedAt   time.Time
	Description string
}

func GetMigrationStatus(db *sql.DB) (*MigrationStatus, error) {
	status := &MigrationStatus{
		LatestVersion: len(migrations),
	}

	// Get applied migrations
	rows, err := db.Query("SELECT version, applied_at, description FROM schema_migrations ORDER BY version")
	if err != nil {
		// Table might not exist yet
		status.CurrentVersion = 0
		status.Pending = migrations
		return status, nil
	}
	defer rows.Close()

	appliedVersions := make(map[int]bool)
	for rows.Next() {
		var am AppliedMigration
		var appliedAt int64
		if err := rows.Scan(&am.Version, &appliedAt, &am.Description); err != nil {
			return nil, fmt.Errorf("scan migration: %w", err)
		}
		am.AppliedAt = time.Unix(0, appliedAt)
		status.Applied = append(status.Applied, am)
		appliedVersions[am.Version] = true

		if am.Version > status.CurrentVersion {
			status.CurrentVersion = am.Version
		}
	}

	// Determine pending migrations
	for _, m := range migrations {
		if !appliedVersions[m.Version] {
			status.Pending = append(status.Pending, m)
		}
	}

	return status, nil
}

// ValidateSchema checks that all expected tables exist.
func ValidateSchema(db *sql.DB) error {
	requiredTables := []string{
		"devices",
		"contexts",
		"events",
		"edit_regions",
		"verification_index",
		"weaves",
		"schema_migrations",
	}

	for _, table := range requiredTables {
		var count int
		err := db.QueryRow(
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
			table,
		).Scan(&count)
		if err != nil {
			return fmt.Errorf("check table %s: %w", table, err)
		}
		if count == 0 {
			return fmt.Errorf("missing required table: %s", table)
		}
	}

	return nil
}
