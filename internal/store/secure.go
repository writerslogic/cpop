// Package store provides secure SQLite-based event storage for witnessd.
//
// Security Model:
// 1. File permissions: 0600 (owner read/write only)
// 2. Integrity: Each record has HMAC verification
// 3. Append-only: Events cannot be modified after insertion
// 4. Chain linking: Each event references previous event hash
package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"witnessd/internal/witness"

	_ "github.com/mattn/go-sqlite3"
)

// SecureStore wraps Store with integrity verification.
type SecureStore struct {
	*Store
	hmacKey    []byte
	lastHash   [32]byte
	mu         sync.RWMutex
	integrityOK bool
}

// secureSchema extends the base schema with integrity fields.
const secureSchema = `
CREATE TABLE IF NOT EXISTS integrity (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    chain_hash      BLOB NOT NULL,
    event_count     INTEGER NOT NULL DEFAULT 0,
    last_verified   INTEGER,
    hmac            BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS secure_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       BLOB NOT NULL,
    timestamp_ns    INTEGER NOT NULL,
    file_path       TEXT NOT NULL,
    content_hash    BLOB NOT NULL,
    file_size       INTEGER NOT NULL,
    size_delta      INTEGER NOT NULL,
    previous_hash   BLOB NOT NULL,
    event_hash      BLOB NOT NULL UNIQUE,
    hmac            BLOB NOT NULL,
    context_type    TEXT,
    context_note    TEXT,
    vdf_input       BLOB,
    vdf_output      BLOB,
    vdf_iterations  INTEGER DEFAULT 0,
    regions_root    BLOB
);

CREATE TABLE IF NOT EXISTS secure_edit_regions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        INTEGER NOT NULL,
    ordinal         INTEGER NOT NULL,
    start_pct       REAL NOT NULL,
    end_pct         REAL NOT NULL,
    delta_sign      INTEGER NOT NULL,
    byte_count      INTEGER NOT NULL,
    FOREIGN KEY(event_id) REFERENCES secure_events(id)
);

CREATE INDEX IF NOT EXISTS idx_secure_events_timestamp ON secure_events(timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_secure_events_file ON secure_events(file_path, timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_secure_events_hash ON secure_events(event_hash);
CREATE INDEX IF NOT EXISTS idx_secure_edit_regions_event ON secure_edit_regions(event_id);
`

// OpenSecure opens or creates a secure SQLite database.
// The hmacKey should be derived from the signing key for tamper detection.
func OpenSecure(path string, hmacKey []byte) (*SecureStore, error) {
	if len(hmacKey) < 32 {
		return nil, errors.New("HMAC key must be at least 32 bytes")
	}

	// Ensure parent directory exists with secure permissions
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	// Check if database exists
	isNew := false
	if _, err := os.Stat(path); os.IsNotExist(err) {
		isNew = true
	}

	// Open database with security settings
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Force connection establishment to create the file
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("establish database connection: %w", err)
	}

	// Apply base schema
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply base schema: %w", err)
	}

	// Apply secure schema
	if _, err := db.Exec(secureSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply secure schema: %w", err)
	}

	// Set secure file permissions (after file is created)
	if err := os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, fmt.Errorf("set database permissions: %w", err)
	}

	store := &SecureStore{
		Store:   &Store{db: db},
		hmacKey: hmacKey,
	}

	// Initialize or verify integrity
	if isNew {
		if err := store.initializeIntegrity(); err != nil {
			db.Close()
			return nil, fmt.Errorf("initialize integrity: %w", err)
		}
		store.integrityOK = true
	} else {
		if err := store.verifyIntegrity(); err != nil {
			// Don't close - allow read-only access to corrupted database
			store.integrityOK = false
			return store, fmt.Errorf("integrity verification failed: %w", err)
		}
		store.integrityOK = true
	}

	return store, nil
}

// IntegrityOK returns true if the database passed integrity verification.
func (s *SecureStore) IntegrityOK() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.integrityOK
}

// initializeIntegrity sets up the integrity chain for a new database.
func (s *SecureStore) initializeIntegrity() error {
	// Initial chain hash is zero
	var zeroHash [32]byte
	s.lastHash = zeroHash

	// Compute HMAC of initial state
	mac := s.computeIntegrityHMAC(zeroHash, 0)

	_, err := s.db.Exec(`
		INSERT INTO integrity (id, chain_hash, event_count, last_verified, hmac)
		VALUES (1, ?, 0, ?, ?)`,
		zeroHash[:], time.Now().UnixNano(), mac,
	)
	return err
}

// verifyIntegrity checks the entire event chain for tampering.
func (s *SecureStore) verifyIntegrity() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load integrity record
	var chainHash, storedMAC []byte
	var eventCount int64

	err := s.db.QueryRow(`SELECT chain_hash, event_count, hmac FROM integrity WHERE id = 1`).
		Scan(&chainHash, &eventCount, &storedMAC)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("integrity record missing")
		}
		return fmt.Errorf("read integrity record: %w", err)
	}

	// Verify integrity HMAC
	var expectedHash [32]byte
	copy(expectedHash[:], chainHash)
	expectedMAC := s.computeIntegrityHMAC(expectedHash, eventCount)
	if !hmac.Equal(storedMAC, expectedMAC) {
		return errors.New("integrity record HMAC mismatch - database may be tampered")
	}

	// Verify event chain
	rows, err := s.db.Query(`
		SELECT id, event_hash, previous_hash, hmac,
		       device_id, timestamp_ns, file_path, content_hash, file_size, size_delta, regions_root
		FROM secure_events ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var lastHash [32]byte
	var count int64

	for rows.Next() {
		var id int64
		var eventHash, previousHash, storedEventMAC []byte
		var deviceID, contentHash, regionsRoot []byte
		var timestampNs, fileSize int64
		var sizeDelta int32
		var filePath string

		if err := rows.Scan(&id, &eventHash, &previousHash, &storedEventMAC,
			&deviceID, &timestampNs, &filePath, &contentHash, &fileSize, &sizeDelta, &regionsRoot); err != nil {
			return fmt.Errorf("scan event %d: %w", id, err)
		}

		// Verify chain linkage
		if count > 0 {
			if !bytesEqual(previousHash, lastHash[:]) {
				return fmt.Errorf("chain break at event %d: previous hash mismatch", id)
			}
		}

		// Verify event HMAC
		expectedEventMAC := s.computeEventHMAC(deviceID, timestampNs, filePath, contentHash, fileSize, sizeDelta, previousHash, regionsRoot)
		if !hmac.Equal(storedEventMAC, expectedEventMAC) {
			return fmt.Errorf("event %d HMAC mismatch - event may be tampered", id)
		}

		// Verify event hash
		computedHash := computeEventHash(deviceID, timestampNs, filePath, contentHash, fileSize, sizeDelta, previousHash, regionsRoot)
		if !bytesEqual(eventHash, computedHash[:]) {
			return fmt.Errorf("event %d hash mismatch", id)
		}

		copy(lastHash[:], eventHash)
		count++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate events: %w", err)
	}

	// Verify count matches
	if count != eventCount {
		return fmt.Errorf("event count mismatch: expected %d, found %d", eventCount, count)
	}

	// Verify final hash matches
	if !bytesEqual(chainHash, lastHash[:]) {
		return fmt.Errorf("chain hash mismatch")
	}

	s.lastHash = lastHash
	return nil
}

// SecureEvent represents a tamper-evident event record.
type SecureEvent struct {
	ID           int64
	DeviceID     [16]byte
	TimestampNs  int64
	FilePath     string
	ContentHash  [32]byte
	FileSize     int64
	SizeDelta    int32
	PreviousHash [32]byte
	EventHash    [32]byte
	ContextType  string
	ContextNote  string

	// VDF proof (proves minimum elapsed time since previous event)
	VDFInput      [32]byte // Input to VDF (previous event hash or genesis)
	VDFOutput     [32]byte // VDF result
	VDFIterations uint64   // Number of iterations performed

	// Edit Topology (forensic structure)
	RegionsRoot   [32]byte             // Merkle root of edit regions
	EditRegions   []witness.EditRegion // Granular edits (in-memory only, stored in separate table)
}

// InsertSecureEvent inserts a new event with integrity verification.
func (s *SecureStore) InsertSecureEvent(e *SecureEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check integrity status while holding the lock to prevent race condition
	if !s.integrityOK {
		return errors.New("database integrity compromised - refusing to write")
	}

	// Set previous hash from chain
	e.PreviousHash = s.lastHash

	// Compute event hash
	e.EventHash = computeEventHash(e.DeviceID[:], e.TimestampNs, e.FilePath, e.ContentHash[:], e.FileSize, e.SizeDelta, e.PreviousHash[:], e.RegionsRoot[:])

	// Compute HMAC
	eventMAC := s.computeEventHMAC(e.DeviceID[:], e.TimestampNs, e.FilePath, e.ContentHash[:], e.FileSize, e.SizeDelta, e.PreviousHash[:], e.RegionsRoot[:])

	// Begin transaction
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert event
	result, err := tx.Exec(`
		INSERT INTO secure_events (device_id, timestamp_ns, file_path, content_hash, file_size, size_delta, previous_hash, event_hash, hmac, context_type, context_note, vdf_input, vdf_output, vdf_iterations, regions_root)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.DeviceID[:], e.TimestampNs, e.FilePath, e.ContentHash[:], e.FileSize, e.SizeDelta, e.PreviousHash[:], e.EventHash[:], eventMAC, e.ContextType, e.ContextNote, e.VDFInput[:], e.VDFOutput[:], e.VDFIterations, e.RegionsRoot[:],
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}

	id, _ := result.LastInsertId()
	e.ID = id

	// Insert edit regions
	if len(e.EditRegions) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO secure_edit_regions (event_id, ordinal, start_pct, end_pct, delta_sign, byte_count) VALUES (?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("prepare regions stmt: %w", err)
		}
		defer stmt.Close()

		for i, r := range e.EditRegions {
			if _, err := stmt.Exec(id, i, r.StartPct, r.EndPct, r.DeltaSign, r.ByteCount); err != nil {
				return fmt.Errorf("insert region %d: %w", i, err)
			}
		}
	}

	// Update integrity record
	newMAC := s.computeIntegrityHMAC(e.EventHash, id)
	_, err = tx.Exec(`UPDATE integrity SET chain_hash = ?, event_count = ?, last_verified = ?, hmac = ? WHERE id = 1`,
		e.EventHash[:], id, time.Now().UnixNano(), newMAC)
	if err != nil {
		return fmt.Errorf("update integrity: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	s.lastHash = e.EventHash
	return nil
}

// GetSecureEvents retrieves events for a file within a time range.
func (s *SecureStore) GetSecureEvents(filePath string, startNs, endNs int64) ([]SecureEvent, error) {
	rows, err := s.db.Query(`
		SELECT id, device_id, timestamp_ns, file_path, content_hash, file_size, size_delta, previous_hash, event_hash, context_type, context_note, vdf_input, vdf_output, vdf_iterations
		FROM secure_events
		WHERE file_path = ? AND timestamp_ns >= ? AND timestamp_ns <= ?
		ORDER BY timestamp_ns ASC`, filePath, startNs, endNs)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	return scanSecureEvents(rows)
}

// GetAllSecureEvents retrieves all events in chronological order.
func (s *SecureStore) GetAllSecureEvents() ([]SecureEvent, error) {
	rows, err := s.db.Query(`
		SELECT id, device_id, timestamp_ns, file_path, content_hash, file_size, size_delta, previous_hash, event_hash, context_type, context_note, vdf_input, vdf_output, vdf_iterations
		FROM secure_events
		ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	return scanSecureEvents(rows)
}

// GetLastSecureEventForFile retrieves the most recent event for a file.
func (s *SecureStore) GetLastSecureEventForFile(filePath string) (*SecureEvent, error) {
	var e SecureEvent
	var deviceID, contentHash, previousHash, eventHash []byte
	var vdfInput, vdfOutput []byte
	var contextType, contextNote sql.NullString
	var vdfIterations sql.NullInt64

	err := s.db.QueryRow(`
		SELECT id, device_id, timestamp_ns, file_path, content_hash, file_size, size_delta, previous_hash, event_hash, context_type, context_note, vdf_input, vdf_output, vdf_iterations
		FROM secure_events
		WHERE file_path = ?
		ORDER BY timestamp_ns DESC
		LIMIT 1`, filePath,
	).Scan(&e.ID, &deviceID, &e.TimestampNs, &e.FilePath, &contentHash, &e.FileSize, &e.SizeDelta, &previousHash, &eventHash, &contextType, &contextNote, &vdfInput, &vdfOutput, &vdfIterations)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get last event: %w", err)
	}

	copy(e.DeviceID[:], deviceID)
	copy(e.ContentHash[:], contentHash)
	copy(e.PreviousHash[:], previousHash)
	copy(e.EventHash[:], eventHash)
	e.ContextType = contextType.String
	e.ContextNote = contextNote.String
	if len(vdfInput) == 32 {
		copy(e.VDFInput[:], vdfInput)
	}
	if len(vdfOutput) == 32 {
		copy(e.VDFOutput[:], vdfOutput)
	}
	e.VDFIterations = uint64(vdfIterations.Int64)

	return &e, nil
}

// Stats returns database statistics.
type Stats struct {
	EventCount    int64
	FileCount     int64
	OldestEvent   time.Time
	NewestEvent   time.Time
	DatabaseSize  int64
	IntegrityOK   bool
	ChainHash     string
}

// GetStats returns database statistics.
func (s *SecureStore) GetStats() (*Stats, error) {
	s.mu.RLock()
	integrityOK := s.integrityOK
	s.mu.RUnlock()

	stats := &Stats{
		IntegrityOK: integrityOK,
	}

	// Event count
	s.db.QueryRow(`SELECT COUNT(*) FROM secure_events`).Scan(&stats.EventCount)

	// Unique files
	s.db.QueryRow(`SELECT COUNT(DISTINCT file_path) FROM secure_events`).Scan(&stats.FileCount)

	// Time range
	var oldestNs, newestNs sql.NullInt64
	s.db.QueryRow(`SELECT MIN(timestamp_ns), MAX(timestamp_ns) FROM secure_events`).Scan(&oldestNs, &newestNs)
	if oldestNs.Valid {
		stats.OldestEvent = time.Unix(0, oldestNs.Int64)
		stats.NewestEvent = time.Unix(0, newestNs.Int64)
	}

	// Chain hash
	var chainHash []byte
	s.db.QueryRow(`SELECT chain_hash FROM integrity WHERE id = 1`).Scan(&chainHash)
	stats.ChainHash = hex.EncodeToString(chainHash)

	return stats, nil
}

// CountEventsForFile returns the number of events for a specific file.
func (s *SecureStore) CountEventsForFile(filePath string) (int64, error) {
	var count int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM secure_events WHERE file_path = ?`, filePath).Scan(&count)
	return count, err
}

// GetEventsForFile returns all events for a specific file in chronological order.
func (s *SecureStore) GetEventsForFile(filePath string) ([]SecureEvent, error) {
	rows, err := s.db.Query(`
		SELECT id, device_id, timestamp_ns, file_path, content_hash, file_size, size_delta, previous_hash, event_hash, context_type, context_note, vdf_input, vdf_output, vdf_iterations
		FROM secure_events
		WHERE file_path = ?
		ORDER BY id ASC`, filePath)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	return scanSecureEvents(rows)
}

// GetTotalVDFTime calculates total VDF-proven time for a file.
func (s *SecureStore) GetTotalVDFTime(filePath string, iterationsPerSecond uint64) (time.Duration, error) {
	var totalIterations int64
	err := s.db.QueryRow(`SELECT COALESCE(SUM(vdf_iterations), 0) FROM secure_events WHERE file_path = ?`, filePath).Scan(&totalIterations)
	if err != nil {
		return 0, err
	}
	if iterationsPerSecond == 0 {
		return 0, nil
	}
	seconds := float64(totalIterations) / float64(iterationsPerSecond)
	return time.Duration(seconds * float64(time.Second)), nil
}

// HMAC helpers

func (s *SecureStore) computeIntegrityHMAC(chainHash [32]byte, eventCount int64) []byte {
	h := hmac.New(sha256.New, s.hmacKey)
	h.Write([]byte("witnessd-integrity-v1"))
	h.Write(chainHash[:])
	h.Write(intToBytes(eventCount))
	return h.Sum(nil)
}

func (s *SecureStore) computeEventHMAC(deviceID []byte, timestampNs int64, filePath string, contentHash []byte, fileSize int64, sizeDelta int32, previousHash []byte, regionsRoot []byte) []byte {
	h := hmac.New(sha256.New, s.hmacKey)
	h.Write([]byte("witnessd-event-v2"))
	h.Write(deviceID)
	h.Write(intToBytes(timestampNs))
	h.Write([]byte(filePath))
	h.Write(contentHash)
	h.Write(intToBytes(fileSize))
	h.Write(int32ToBytes(sizeDelta))
	h.Write(previousHash)
	h.Write(regionsRoot)
	return h.Sum(nil)
}

func computeEventHash(deviceID []byte, timestampNs int64, filePath string, contentHash []byte, fileSize int64, sizeDelta int32, previousHash []byte, regionsRoot []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("witnessd-event-v2"))
	h.Write(deviceID)
	h.Write(intToBytes(timestampNs))
	h.Write([]byte(filePath))
	h.Write(contentHash)
	h.Write(intToBytes(fileSize))
	h.Write(int32ToBytes(sizeDelta))
	h.Write(previousHash)
	h.Write(regionsRoot)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func scanSecureEvents(rows *sql.Rows) ([]SecureEvent, error) {
	var events []SecureEvent
	for rows.Next() {
		var e SecureEvent
		var deviceID, contentHash, previousHash, eventHash []byte
		var vdfInput, vdfOutput []byte
		var contextType, contextNote sql.NullString
		var vdfIterations sql.NullInt64

		if err := rows.Scan(&e.ID, &deviceID, &e.TimestampNs, &e.FilePath, &contentHash, &e.FileSize, &e.SizeDelta, &previousHash, &eventHash, &contextType, &contextNote, &vdfInput, &vdfOutput, &vdfIterations); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}

		copy(e.DeviceID[:], deviceID)
		copy(e.ContentHash[:], contentHash)
		copy(e.PreviousHash[:], previousHash)
		copy(e.EventHash[:], eventHash)
		e.ContextType = contextType.String
		e.ContextNote = contextNote.String
		if len(vdfInput) == 32 {
			copy(e.VDFInput[:], vdfInput)
		}
		if len(vdfOutput) == 32 {
			copy(e.VDFOutput[:], vdfOutput)
		}
		e.VDFIterations = uint64(vdfIterations.Int64)

		events = append(events, e)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}

	return events, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func intToBytes(n int64) []byte {
	b := make([]byte, 8)
	b[0] = byte(n >> 56)
	b[1] = byte(n >> 48)
	b[2] = byte(n >> 40)
	b[3] = byte(n >> 32)
	b[4] = byte(n >> 24)
	b[5] = byte(n >> 16)
	b[6] = byte(n >> 8)
	b[7] = byte(n)
	return b
}

func int32ToBytes(n int32) []byte {
	b := make([]byte, 4)
	b[0] = byte(n >> 24)
	b[1] = byte(n >> 16)
	b[2] = byte(n >> 8)
	b[3] = byte(n)
	return b
}
