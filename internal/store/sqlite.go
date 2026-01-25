package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// Schema for the witnessd event store.
const schema = `
CREATE TABLE IF NOT EXISTS devices (
    device_id       BLOB PRIMARY KEY,
    created_at      INTEGER NOT NULL,
    signing_pubkey  BLOB NOT NULL,
    hostname        TEXT
);

CREATE TABLE IF NOT EXISTS contexts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT NOT NULL,
    note        TEXT,
    start_ns    INTEGER NOT NULL,
    end_ns      INTEGER
);

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

CREATE TABLE IF NOT EXISTS edit_regions (
    event_id    INTEGER NOT NULL REFERENCES events(id),
    ordinal     INTEGER NOT NULL,
    start_pct   REAL NOT NULL,
    end_pct     REAL NOT NULL,
    delta_sign  INTEGER NOT NULL,
    byte_count  INTEGER NOT NULL,
    PRIMARY KEY (event_id, ordinal)
);

CREATE TABLE IF NOT EXISTS verification_index (
    mmr_index       INTEGER PRIMARY KEY,
    leaf_hash       BLOB NOT NULL,
    metadata_hash   BLOB NOT NULL,
    regions_root    BLOB,
    verified_at     INTEGER
);

CREATE TABLE IF NOT EXISTS weaves (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns    INTEGER NOT NULL,
    device_roots    TEXT NOT NULL,
    weave_hash      BLOB NOT NULL,
    signature       BLOB NOT NULL
);
`

// Store represents the SQLite event store.
type Store struct {
	db *sql.DB
}

// Open opens or creates the SQLite database at the given path and runs migrations.
func Open(path string) (*Store, error) {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Run schema migration
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	return &Store{db: db}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// InsertEvent inserts a new event and returns its ID.
func (s *Store) InsertEvent(e *Event) (int64, error) {
	result, err := s.db.Exec(`
		INSERT INTO events (device_id, mmr_index, mmr_leaf_hash, timestamp_ns, file_path, content_hash, file_size, size_delta, context_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.DeviceID[:], e.MMRIndex, e.MMRLeafHash[:], e.TimestampNs, e.FilePath, e.ContentHash[:], e.FileSize, e.SizeDelta, e.ContextID,
	)
	if err != nil {
		return 0, fmt.Errorf("insert event: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}

	return id, nil
}

// InsertEditRegions inserts edit regions for an event.
func (s *Store) InsertEditRegions(eventID int64, regions []EditRegion) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO edit_regions (event_id, ordinal, start_pct, end_pct, delta_sign, byte_count)
		VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, r := range regions {
		if _, err := stmt.Exec(eventID, r.Ordinal, r.StartPct, r.EndPct, r.DeltaSign, r.ByteCount); err != nil {
			return fmt.Errorf("insert edit region: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// GetEvent retrieves an event by ID.
func (s *Store) GetEvent(id int64) (*Event, error) {
	var e Event
	var deviceID, leafHash, contentHash []byte

	err := s.db.QueryRow(`
		SELECT id, device_id, mmr_index, mmr_leaf_hash, timestamp_ns, file_path, content_hash, file_size, size_delta, context_id
		FROM events WHERE id = ?`, id,
	).Scan(&e.ID, &deviceID, &e.MMRIndex, &leafHash, &e.TimestampNs, &e.FilePath, &contentHash, &e.FileSize, &e.SizeDelta, &e.ContextID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get event: %w", err)
	}

	copy(e.DeviceID[:], deviceID)
	copy(e.MMRLeafHash[:], leafHash)
	copy(e.ContentHash[:], contentHash)

	return &e, nil
}

// GetEventByMMRIndex retrieves an event by its MMR index.
func (s *Store) GetEventByMMRIndex(idx uint64) (*Event, error) {
	var e Event
	var deviceID, leafHash, contentHash []byte

	err := s.db.QueryRow(`
		SELECT id, device_id, mmr_index, mmr_leaf_hash, timestamp_ns, file_path, content_hash, file_size, size_delta, context_id
		FROM events WHERE mmr_index = ?`, idx,
	).Scan(&e.ID, &deviceID, &e.MMRIndex, &leafHash, &e.TimestampNs, &e.FilePath, &contentHash, &e.FileSize, &e.SizeDelta, &e.ContextID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get event by mmr index: %w", err)
	}

	copy(e.DeviceID[:], deviceID)
	copy(e.MMRLeafHash[:], leafHash)
	copy(e.ContentHash[:], contentHash)

	return &e, nil
}

// GetEventsByFile retrieves events for a file within a time range.
func (s *Store) GetEventsByFile(path string, startNs, endNs int64) ([]Event, error) {
	rows, err := s.db.Query(`
		SELECT id, device_id, mmr_index, mmr_leaf_hash, timestamp_ns, file_path, content_hash, file_size, size_delta, context_id
		FROM events
		WHERE file_path = ? AND timestamp_ns >= ? AND timestamp_ns <= ?
		ORDER BY timestamp_ns ASC`, path, startNs, endNs,
	)
	if err != nil {
		return nil, fmt.Errorf("query events by file: %w", err)
	}
	defer rows.Close()

	return scanEvents(rows)
}

// GetEditRegions retrieves edit regions for an event.
func (s *Store) GetEditRegions(eventID int64) ([]EditRegion, error) {
	rows, err := s.db.Query(`
		SELECT event_id, ordinal, start_pct, end_pct, delta_sign, byte_count
		FROM edit_regions
		WHERE event_id = ?
		ORDER BY ordinal ASC`, eventID,
	)
	if err != nil {
		return nil, fmt.Errorf("query edit regions: %w", err)
	}
	defer rows.Close()

	var regions []EditRegion
	for rows.Next() {
		var r EditRegion
		if err := rows.Scan(&r.EventID, &r.Ordinal, &r.StartPct, &r.EndPct, &r.DeltaSign, &r.ByteCount); err != nil {
			return nil, fmt.Errorf("scan edit region: %w", err)
		}
		regions = append(regions, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate edit regions: %w", err)
	}

	return regions, nil
}

// GetEventRange retrieves events within a time range.
func (s *Store) GetEventRange(startNs, endNs int64) ([]Event, error) {
	rows, err := s.db.Query(`
		SELECT id, device_id, mmr_index, mmr_leaf_hash, timestamp_ns, file_path, content_hash, file_size, size_delta, context_id
		FROM events
		WHERE timestamp_ns >= ? AND timestamp_ns <= ?
		ORDER BY timestamp_ns ASC`, startNs, endNs,
	)
	if err != nil {
		return nil, fmt.Errorf("query events by range: %w", err)
	}
	defer rows.Close()

	return scanEvents(rows)
}

// InsertContext inserts a new context and returns its ID.
func (s *Store) InsertContext(c *Context) (int64, error) {
	result, err := s.db.Exec(`
		INSERT INTO contexts (type, note, start_ns, end_ns)
		VALUES (?, ?, ?, ?)`,
		string(c.Type), c.Note, c.StartNs, c.EndNs,
	)
	if err != nil {
		return 0, fmt.Errorf("insert context: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}

	return id, nil
}

// GetActiveContext returns the currently open context (EndNs is NULL).
func (s *Store) GetActiveContext() (*Context, error) {
	var c Context
	var contextType string

	err := s.db.QueryRow(`
		SELECT id, type, note, start_ns, end_ns
		FROM contexts
		WHERE end_ns IS NULL
		ORDER BY start_ns DESC
		LIMIT 1`,
	).Scan(&c.ID, &contextType, &c.Note, &c.StartNs, &c.EndNs)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get active context: %w", err)
	}

	c.Type = ContextType(contextType)
	return &c, nil
}

// CloseContext closes an open context by setting its end timestamp.
func (s *Store) CloseContext(id int64, endNs int64) error {
	result, err := s.db.Exec(`UPDATE contexts SET end_ns = ? WHERE id = ?`, endNs, id)
	if err != nil {
		return fmt.Errorf("close context: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("context not found: %d", id)
	}

	return nil
}

// InsertDevice inserts a new device.
func (s *Store) InsertDevice(d *Device) error {
	_, err := s.db.Exec(`
		INSERT INTO devices (device_id, created_at, signing_pubkey, hostname)
		VALUES (?, ?, ?, ?)`,
		d.DeviceID[:], d.CreatedAt, d.SigningPubkey[:], d.Hostname,
	)
	if err != nil {
		return fmt.Errorf("insert device: %w", err)
	}

	return nil
}

// GetDevice retrieves a device by ID.
func (s *Store) GetDevice(id [16]byte) (*Device, error) {
	var d Device
	var deviceID, pubkey []byte

	err := s.db.QueryRow(`
		SELECT device_id, created_at, signing_pubkey, hostname
		FROM devices WHERE device_id = ?`, id[:],
	).Scan(&deviceID, &d.CreatedAt, &pubkey, &d.Hostname)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get device: %w", err)
	}

	copy(d.DeviceID[:], deviceID)
	copy(d.SigningPubkey[:], pubkey)

	return &d, nil
}

// InsertVerificationEntry inserts a verification index entry.
func (s *Store) InsertVerificationEntry(v *VerificationEntry) error {
	var regionsRoot []byte
	if v.RegionsRoot != nil {
		regionsRoot = v.RegionsRoot[:]
	}

	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO verification_index (mmr_index, leaf_hash, metadata_hash, regions_root, verified_at)
		VALUES (?, ?, ?, ?, ?)`,
		v.MMRIndex, v.LeafHash[:], v.MetadataHash[:], regionsRoot, v.VerifiedAt,
	)
	if err != nil {
		return fmt.Errorf("insert verification entry: %w", err)
	}

	return nil
}

// GetVerificationEntry retrieves a verification entry by MMR index.
func (s *Store) GetVerificationEntry(mmrIndex uint64) (*VerificationEntry, error) {
	var v VerificationEntry
	var leafHash, metadataHash, regionsRoot []byte

	err := s.db.QueryRow(`
		SELECT mmr_index, leaf_hash, metadata_hash, regions_root, verified_at
		FROM verification_index WHERE mmr_index = ?`, mmrIndex,
	).Scan(&v.MMRIndex, &leafHash, &metadataHash, &regionsRoot, &v.VerifiedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get verification entry: %w", err)
	}

	copy(v.LeafHash[:], leafHash)
	copy(v.MetadataHash[:], metadataHash)
	if regionsRoot != nil {
		v.RegionsRoot = new([32]byte)
		copy(v.RegionsRoot[:], regionsRoot)
	}

	return &v, nil
}

// GetLastEventForFile retrieves the most recent event for a file path.
func (s *Store) GetLastEventForFile(path string) (*Event, error) {
	var e Event
	var deviceID, leafHash, contentHash []byte

	err := s.db.QueryRow(`
		SELECT id, device_id, mmr_index, mmr_leaf_hash, timestamp_ns, file_path, content_hash, file_size, size_delta, context_id
		FROM events
		WHERE file_path = ?
		ORDER BY timestamp_ns DESC
		LIMIT 1`, path,
	).Scan(&e.ID, &deviceID, &e.MMRIndex, &leafHash, &e.TimestampNs, &e.FilePath, &contentHash, &e.FileSize, &e.SizeDelta, &e.ContextID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get last event for file: %w", err)
	}

	copy(e.DeviceID[:], deviceID)
	copy(e.MMRLeafHash[:], leafHash)
	copy(e.ContentHash[:], contentHash)

	return &e, nil
}

// InsertWeave inserts a new weave record.
func (s *Store) InsertWeave(w *Weave) (int64, error) {
	deviceRootsJSON, err := json.Marshal(w.DeviceRoots)
	if err != nil {
		return 0, fmt.Errorf("marshal device roots: %w", err)
	}

	result, err := s.db.Exec(`
		INSERT INTO weaves (timestamp_ns, device_roots, weave_hash, signature)
		VALUES (?, ?, ?, ?)`,
		w.TimestampNs, string(deviceRootsJSON), w.WeaveHash[:], w.Signature,
	)
	if err != nil {
		return 0, fmt.Errorf("insert weave: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}

	return id, nil
}

// GetWeave retrieves a weave by ID.
func (s *Store) GetWeave(id int64) (*Weave, error) {
	var w Weave
	var deviceRootsJSON string
	var weaveHash []byte

	err := s.db.QueryRow(`
		SELECT id, timestamp_ns, device_roots, weave_hash, signature
		FROM weaves WHERE id = ?`, id,
	).Scan(&w.ID, &w.TimestampNs, &deviceRootsJSON, &weaveHash, &w.Signature)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get weave: %w", err)
	}

	copy(w.WeaveHash[:], weaveHash)

	if err := json.Unmarshal([]byte(deviceRootsJSON), &w.DeviceRoots); err != nil {
		return nil, fmt.Errorf("unmarshal device roots: %w", err)
	}

	return &w, nil
}

// scanEvents is a helper to scan event rows into a slice.
func scanEvents(rows *sql.Rows) ([]Event, error) {
	var events []Event

	for rows.Next() {
		var e Event
		var deviceID, leafHash, contentHash []byte

		if err := rows.Scan(&e.ID, &deviceID, &e.MMRIndex, &leafHash, &e.TimestampNs, &e.FilePath, &contentHash, &e.FileSize, &e.SizeDelta, &e.ContextID); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}

		copy(e.DeviceID[:], deviceID)
		copy(e.MMRLeafHash[:], leafHash)
		copy(e.ContentHash[:], contentHash)

		events = append(events, e)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}

	return events, nil
}
