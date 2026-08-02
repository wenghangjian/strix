BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS schema_migration (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blob (
    sha256 TEXT PRIMARY KEY,
    size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
    storage_name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS firmware_input (
    input_artifact_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    project_id TEXT,
    sha256 TEXT NOT NULL REFERENCES blob(sha256),
    size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
    storage_name TEXT NOT NULL,
    label TEXT,
    source_type TEXT NOT NULL,
    source_description TEXT,
    geometry_json TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS firmware_input_scan_idx
ON firmware_input(scan_id, created_at, input_artifact_id);

CREATE TABLE IF NOT EXISTS firmware_analysis (
    analysis_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    input_artifact_id TEXT NOT NULL REFERENCES firmware_input(input_artifact_id),
    status TEXT NOT NULL,
    resume_key TEXT,
    limitations_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT
);

CREATE INDEX IF NOT EXISTS firmware_analysis_scan_idx
ON firmware_analysis(scan_id, created_at, analysis_id);

CREATE TABLE IF NOT EXISTS commit_journal (
    commit_id TEXT PRIMARY KEY,
    input_artifact_id TEXT NOT NULL,
    artifact_json TEXT NOT NULL,
    staged_path TEXT NOT NULL,
    blob_path TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('staging', 'blobs_committed', 'metadata_committed', 'complete')
    ),
    updated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_migration(version, applied_at)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

COMMIT;
