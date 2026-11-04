PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER PRIMARY KEY CHECK (version = 1)
);
INSERT OR IGNORE INTO schema_info VALUES (1);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    label TEXT NOT NULL UNIQUE,
    build_identity TEXT,
    report_path TEXT NOT NULL,
    report_size INTEGER NOT NULL,
    report_mtime_ns INTEGER NOT NULL,
    overlay_path TEXT,
    overlay_size INTEGER,
    overlay_mtime_ns INTEGER,
    configuration_json TEXT NOT NULL,
    started_unix_seconds INTEGER,
    state TEXT NOT NULL CHECK (state IN ('importing', 'complete')),
    imported_files INTEGER NOT NULL DEFAULT 0,
    summary_json TEXT,
    imported_summary_json TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS file_versions (
    id INTEGER PRIMARY KEY,
    file_id INTEGER NOT NULL REFERENCES files(id),
    size_bytes INTEGER,
    modified_unix_seconds INTEGER,
    identity_key TEXT NOT NULL,
    UNIQUE(file_id, identity_key)
);
CREATE TABLE IF NOT EXISTS run_files (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    file_version_id INTEGER NOT NULL REFERENCES file_versions(id),
    status TEXT NOT NULL,
    error TEXT,
    elapsed_ms REAL,
    rejected_candidates_json TEXT NOT NULL,
    PRIMARY KEY(run_id, ordinal)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS run_files_version ON run_files(file_version_id, run_id);

CREATE TABLE IF NOT EXISTS profiles (
    id INTEGER PRIMARY KEY,
    settings_json TEXT NOT NULL UNIQUE,
    hash_algorithm TEXT,
    matching_type TEXT,
    strategy TEXT,
    add_policy TEXT,
    block_type_strategy TEXT,
    window_bits INTEGER,
    nice_length INTEGER,
    max_chain INTEGER,
    max_token_count INTEGER,
    max_dist_3_matches INTEGER,
    matches_to_start_detected INTEGER,
    very_far_matches_detected INTEGER
);
CREATE TABLE IF NOT EXISTS streams (
    id INTEGER PRIMARY KEY,
    file_version_id INTEGER NOT NULL REFERENCES file_versions(id),
    identity_key TEXT NOT NULL,
    signature_offset INTEGER NOT NULL,
    deflate_offset INTEGER,
    kind TEXT NOT NULL,
    member_name TEXT,
    deflate_bytes INTEGER NOT NULL,
    plaintext_bytes INTEGER NOT NULL,
    UNIQUE(file_version_id, identity_key)
);
CREATE TABLE IF NOT EXISTS stream_results (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    stream_id INTEGER NOT NULL REFERENCES streams(id),
    profile_id INTEGER REFERENCES profiles(id),
    status TEXT NOT NULL,
    verified INTEGER NOT NULL CHECK (verified IN (0,1)),
    signature_confidence TEXT,
    error_code TEXT,
    error TEXT,
    reconstruction_bytes INTEGER NOT NULL,
    chunks INTEGER NOT NULL,
    block_count INTEGER NOT NULL,
    elapsed_ms REAL,
    corrections_json TEXT NOT NULL,
    token_mismatches INTEGER,
    token_count INTEGER,
    block_detail TEXT NOT NULL CHECK (block_detail IN ('unavailable','partial','complete')),
    settings_source TEXT NOT NULL,
    estimator_evidence_state TEXT NOT NULL DEFAULT 'unavailable',
    PRIMARY KEY(run_id, stream_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS stream_results_stream ON stream_results(stream_id, run_id);

-- Offline measurements are separate from production estimator observations.
CREATE TABLE IF NOT EXISTS oracle_results (
    run_id INTEGER NOT NULL,
    stream_id INTEGER NOT NULL,
    evaluator_identity TEXT NOT NULL,
    report_path TEXT NOT NULL,
    report_size INTEGER NOT NULL,
    report_mtime_ns INTEGER NOT NULL,
    baseline_profile_id INTEGER NOT NULL REFERENCES profiles(id),
    baseline_bytes INTEGER NOT NULL CHECK (baseline_bytes>=0),
    baseline_mismatches INTEGER NOT NULL CHECK (baseline_mismatches>=0),
    best_profile_id INTEGER NOT NULL REFERENCES profiles(id),
    best_bytes INTEGER NOT NULL CHECK (best_bytes>=0 AND best_bytes<=baseline_bytes),
    best_mismatches INTEGER NOT NULL CHECK (best_mismatches>=0),
    perfect_profile_id INTEGER REFERENCES profiles(id),
    perfect_bytes INTEGER CHECK (perfect_bytes>=0),
    token_count INTEGER NOT NULL CHECK (token_count>=0),
    candidates_scored INTEGER NOT NULL CHECK (candidates_scored>0),
    candidates_evaluated INTEGER NOT NULL CHECK (candidates_evaluated>0),
    search_json TEXT NOT NULL,
    CHECK ((perfect_profile_id IS NULL) = (perfect_bytes IS NULL)),
    FOREIGN KEY(run_id,stream_id) REFERENCES stream_results(run_id,stream_id) ON DELETE CASCADE,
    PRIMARY KEY(run_id,stream_id)
) WITHOUT ROWID;

-- Only observed DEFLATE blocks belong here. Aggregate stream counts are not block rows.
CREATE TABLE IF NOT EXISTS block_results (
    run_id INTEGER NOT NULL,
    stream_id INTEGER NOT NULL,
    block_index INTEGER NOT NULL,
    chunk_index INTEGER NOT NULL,
    plaintext_offset INTEGER NOT NULL,
    plaintext_bytes INTEGER NOT NULL,
    kind TEXT NOT NULL,
    last INTEGER NOT NULL,
    literals INTEGER NOT NULL,
    references_count INTEGER NOT NULL,
    PRIMARY KEY(run_id, stream_id, block_index),
    FOREIGN KEY(run_id, stream_id) REFERENCES stream_results(run_id, stream_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS chunk_results (
    run_id INTEGER NOT NULL,
    stream_id INTEGER NOT NULL,
    chunk_index INTEGER NOT NULL,
    deflate_offset INTEGER,
    deflate_bytes INTEGER,
    plaintext_offset INTEGER,
    plaintext_bytes INTEGER,
    reconstruction_bytes INTEGER,
    block_count INTEGER,
    block_profile TEXT,
    elapsed_ms REAL,
    status TEXT,
    stage TEXT,
    error TEXT,
    corrections_json TEXT NOT NULL,
    PRIMARY KEY(run_id, stream_id, chunk_index),
    FOREIGN KEY(run_id, stream_id) REFERENCES stream_results(run_id, stream_id) ON DELETE CASCADE
) WITHOUT ROWID;
-- Reserved for genuinely recorded estimator decisions, never inferred from hash names.
CREATE TABLE IF NOT EXISTS estimator_results (
    run_id INTEGER NOT NULL,
    stream_id INTEGER NOT NULL,
    stage TEXT NOT NULL,
    candidate_index INTEGER NOT NULL,
    profile_id INTEGER REFERENCES profiles(id),
    selected INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY(run_id, stream_id, stage, candidate_index),
    FOREIGN KEY(run_id, stream_id) REFERENCES stream_results(run_id, stream_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS timing_batches (
    id INTEGER PRIMARY KEY,
    label TEXT NOT NULL UNIQUE,
    report_path TEXT NOT NULL,
    report_size INTEGER NOT NULL,
    report_mtime_ns INTEGER NOT NULL,
    run_mapping_json TEXT NOT NULL,
    verification_enabled INTEGER NOT NULL CHECK (verification_enabled IN (0,1)),
    controlled INTEGER NOT NULL CHECK (controlled IN (0,1)),
    scope TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS timing_samples (
    batch_id INTEGER NOT NULL REFERENCES timing_batches(id) ON DELETE CASCADE,
    sample_index INTEGER NOT NULL,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    case_label TEXT NOT NULL,
    iteration INTEGER NOT NULL,
    cpu_seconds REAL,
    wall_seconds REAL NOT NULL,
    PRIMARY KEY(batch_id, sample_index),
    UNIQUE(batch_id, run_id, case_label, iteration)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS timing_samples_run ON timing_samples(run_id, batch_id);
CREATE TABLE IF NOT EXISTS performance_imports (
    batch_id INTEGER PRIMARY KEY REFERENCES timing_batches(id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('importing','complete')),
    imported_samples INTEGER NOT NULL DEFAULT 0,
    summary_json TEXT
);
CREATE TABLE IF NOT EXISTS timing_file_results (
    batch_id INTEGER NOT NULL,
    sample_index INTEGER NOT NULL,
    file_version_id INTEGER NOT NULL REFERENCES file_versions(id),
    modified_unix_ns INTEGER NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    successful_streams INTEGER NOT NULL,
    verified_streams INTEGER NOT NULL,
    failed_candidates INTEGER NOT NULL,
    unsupported_candidates INTEGER NOT NULL,
    limited_candidates INTEGER NOT NULL,
    deflate_bytes INTEGER NOT NULL,
    plaintext_bytes INTEGER NOT NULL,
    reconstruction_bytes INTEGER NOT NULL,
    PRIMARY KEY(batch_id,sample_index),
    FOREIGN KEY(batch_id,sample_index) REFERENCES timing_samples(batch_id,sample_index) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE VIEW IF NOT EXISTS effective_file_timings AS
SELECT s.*, f.path, d.file_version_id, d.modified_unix_ns, d.status, d.error,
       d.successful_streams, d.verified_streams, d.failed_candidates, d.unsupported_candidates,
       d.limited_candidates, d.deflate_bytes, d.plaintext_bytes, d.reconstruction_bytes,
       b.label AS batch_label, b.controlled, b.verification_enabled, b.scope
FROM timing_samples s
JOIN timing_file_results d USING(batch_id,sample_index)
JOIN file_versions v ON v.id=d.file_version_id
JOIN files f ON f.id=v.file_id
JOIN timing_batches b ON b.id=s.batch_id
JOIN performance_imports i ON i.batch_id=s.batch_id AND i.state='complete';

CREATE VIEW IF NOT EXISTS effective_stream_settings AS
SELECT r.*, s.file_version_id, s.signature_offset, s.deflate_offset,
       s.kind, s.member_name, s.deflate_bytes, s.plaintext_bytes,
       f.path, v.size_bytes, v.modified_unix_seconds,
       p.settings_json, p.hash_algorithm, p.matching_type, p.strategy,
       p.add_policy, p.nice_length, p.max_chain, p.window_bits
FROM stream_results r
JOIN streams s ON s.id=r.stream_id
JOIN file_versions v ON v.id=s.file_version_id
JOIN files f ON f.id=v.file_id
LEFT JOIN profiles p ON p.id=r.profile_id;

CREATE VIEW IF NOT EXISTS effective_block_settings AS
SELECT b.*, e.path, e.file_version_id, e.signature_offset, e.deflate_offset,
       e.settings_json, e.settings_source, e.estimator_evidence_state,
       e.hash_algorithm, e.matching_type, e.add_policy, e.nice_length, e.max_chain
FROM block_results b
JOIN effective_stream_settings e USING(run_id, stream_id);

CREATE VIEW IF NOT EXISTS oracle_stream_settings AS
SELECT e.*, o.evaluator_identity, o.baseline_bytes AS oracle_baseline_bytes,
       o.baseline_mismatches AS oracle_baseline_mismatches,
       o.best_profile_id, o.best_bytes, o.best_mismatches,
       o.perfect_profile_id, o.perfect_bytes, o.candidates_scored, o.candidates_evaluated,
       o.token_count AS oracle_token_count, o.search_json,
       best.settings_json AS best_settings_json,
       perfect.settings_json AS perfect_settings_json,
       o.baseline_bytes-o.best_bytes AS demonstrated_savings_bytes
FROM effective_stream_settings e
LEFT JOIN oracle_results o USING(run_id,stream_id)
LEFT JOIN profiles best ON best.id=o.best_profile_id
LEFT JOIN profiles perfect ON perfect.id=o.perfect_profile_id;

CREATE VIEW IF NOT EXISTS investigation_areas AS
SELECT run_id, hash_algorithm, matching_type, add_policy,
       CASE WHEN deflate_bytes<=1024 THEN 'tiny' ELSE 'larger' END AS size_band,
       count(*) AS streams, sum(deflate_bytes) AS deflate_bytes,
       sum(reconstruction_bytes) AS reconstruction_bytes,
       sum(CASE WHEN status!='ok' THEN 1 ELSE 0 END) AS failures,
       sum(CASE WHEN status='ok' AND verified=0 THEN 1 ELSE 0 END) AS unverified,
       sum(CASE WHEN status='ok' THEN max(0,reconstruction_bytes-deflate_bytes*0.01)
                ELSE 0 END) AS excess_above_one_percent_bytes
FROM effective_stream_settings
GROUP BY run_id, hash_algorithm, matching_type, add_policy, size_band;
