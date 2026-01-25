-- SQLite schema for witnessd event store

CREATE TABLE devices (
    device_id       BLOB PRIMARY KEY,      -- 16 bytes UUID
    created_at      INTEGER NOT NULL,      -- Unix nano
    signing_pubkey  BLOB NOT NULL,         -- 32 bytes Ed25519
    hostname        TEXT
);

CREATE TABLE events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       BLOB NOT NULL REFERENCES devices(device_id),
    mmr_index       INTEGER NOT NULL UNIQUE,
    mmr_leaf_hash   BLOB NOT NULL,         -- 32 bytes, cached
    timestamp_ns    INTEGER NOT NULL,
    file_path       TEXT NOT NULL,
    content_hash    BLOB NOT NULL,         -- 32 bytes
    file_size       INTEGER NOT NULL,
    size_delta      INTEGER NOT NULL,      -- Signed
    context_id      INTEGER REFERENCES contexts(id)
);

CREATE INDEX idx_events_timestamp ON events(timestamp_ns);
CREATE INDEX idx_events_file ON events(file_path, timestamp_ns);
CREATE INDEX idx_events_content ON events(content_hash);

CREATE TABLE edit_regions (
    event_id    INTEGER NOT NULL REFERENCES events(id),
    ordinal     INTEGER NOT NULL,
    start_pct   REAL NOT NULL,
    end_pct     REAL NOT NULL,
    delta_sign  INTEGER NOT NULL,          -- -1, 0, +1
    byte_count  INTEGER NOT NULL,
    PRIMARY KEY (event_id, ordinal)
);

CREATE TABLE contexts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT NOT NULL,             -- 'external', 'assisted', 'review'
    note        TEXT,
    start_ns    INTEGER NOT NULL,
    end_ns      INTEGER                    -- Nullable
);

CREATE TABLE verification_index (
    mmr_index       INTEGER PRIMARY KEY,
    leaf_hash       BLOB NOT NULL,
    metadata_hash   BLOB NOT NULL,
    regions_root    BLOB,                  -- Nullable
    verified_at     INTEGER                -- Nullable, Unix nano
);

CREATE TABLE weaves (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ns    INTEGER NOT NULL,
    device_roots    TEXT NOT NULL,         -- JSON: {device_id_hex: root_hex}
    weave_hash      BLOB NOT NULL,
    signature       BLOB NOT NULL
);
