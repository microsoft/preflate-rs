# SQLite corpus scans and analysis

This package supports **private/local directory scans** and analysis of both
private scans and public Common Crawl runs. Python 3.14+ uses the root uv project;
the release Rust scanner writes the shared [schema](schema.sql) directly.
There is no JSON report ingestion or import/resume/overlay compatibility path.
Existing version-1 SQLite databases remain readable.

## Scan private directories

```powershell
cargo build --release -p preflate_util --bin preflate_scan
uv run --locked python -m corpus.database --db "<private-folder>\private.sqlite" scan "<private-directory>" --label before --build-identity before-build
uv run --locked python -m corpus.database --db "<private-folder>\private.sqlite" scan "<private-directory>" --label after --build-identity after-build
```

Or use the native scanner directly, with all its diagnostic limits and flags:

```powershell
.\target\release\preflate_scan.exe "<private-directory>" --database "<private-folder>\private.sqlite" --label before --max-file-mib 256
```

Source files are never modified. Cloud-only files are skipped unless `--hydrate`
explicitly permits downloads. Reconstruction verification is enabled by default;
`--no-verify` is for explicitly labelled encode-only timing, with correctness
validated separately. SQLite output and its journal/WAL sidecars are excluded
from recursive scans. Keep databases outside the scanned tree where possible.

Existing databases are preserved and each scan needs a **new, nonempty label**.
The native writer commits each file transactionally and marks the run complete
only after row totals reconcile. Interrupted runs remain incomplete and are
excluded from analysis. Delete an unwanted incomplete run explicitly before
reusing its label; restarting a scan does not resume or overwrite it.

Private paths, member names and error messages may identify private documents.
Keep private databases outside the repository and never upload them. Common Crawl
uses its own database; its rarity logic never opens private scan history.

## Local configuration

Commands without `--db` discover the Git-ignored `corpus.local.toml` in the
working directory. `--config` selects another file. Explicit `--db` skips implicit
configuration; combine `--config` and `--db` to override a configured path.
Relative paths resolve against the TOML directory.

```toml
[database]
path = '<private-folder>/private.sqlite'
timeout_seconds = 60
journal_mode = 'WAL'
synchronous = 'NORMAL'
profile_cache_entries = 4096

[scope]
runs = ['before', 'after']

[queries]
limit = 30
min_deflate_bytes = 1025

[locations]
scanner = '<repository>/target/release/preflate_scan.exe'
```

Configure `scope.runs` directly; report-file scope discovery has been removed.
Foreign keys remain enabled; unsafe SQLite connection policies are rejected.
No actual machine paths belong in checked-in documentation.

## Queries and maintenance

```powershell
uv run --locked python -m corpus.database --db "<database.sqlite>" runs
uv run --locked python -m corpus.database --db "<database.sqlite>" compare before after
uv run --locked python -m corpus.database --db "<database.sqlite>" compare-set --before before-a --before before-b --after after-a --after after-b
uv run --locked python -m corpus.database --db "<database.sqlite>" families after
uv run --locked python -m corpus.database --db "<database.sqlite>" outliers after --setting hash_algorithm=RandomVector --one-per-file
uv run --locked python -m corpus.database --db "<database.sqlite>" priorities after
uv run --locked python -m corpus.database --db "<database.sqlite>" stream after 123
uv run --locked python -m corpus.database --db "<database.sqlite>" check
uv run --locked python -m corpus.database --db "<database.sqlite>" backup "<new-backup.sqlite>"
uv run --locked python -m corpus.database --db "<database.sqlite>" delete-run incomplete-label --confirm
```

For ordered run sets, the **last listed run replaces the entire file**, not just
matching streams. Comparisons require unchanged path, size, second-precision
modification time and stream boundaries; this is not a content-hash guarantee.
Changed or newly available files are reported separately from modelling gains.
Do not treat runs with different limits or verification settings as controlled
comparisons.

`merge "<scan.sqlite>" --label copy --source-label source` copies one completed
scanner run into another database, streaming one file at a time in a single
transaction. Select `--source-label` when the source has multiple runs. Duplicate
labels, incomplete sources, unsupported schemas and inconsistent totals fail
explicitly and roll back the copy. This copies scanner observations, not attached
historical oracle/timing analyses.

For an estimator parameter regression check against a completed run:

```powershell
cargo run --release -p preflate_util --bin preflate_match_check -- "<database.sqlite>" --run before --output "<new-match-check.json>"
```

The checker holds a read-only SQLite snapshot and reopens only eligible local
source files. It writes changes/errors and coverage to JSON without modifying
the database. The source root must be absolute in the saved configuration;
the current scanner records it automatically. For Common Crawl URL records,
scan the saved local extracts into a new run before checking parameters.

## Stored observations

- `runs`, `run_files`: execution/configuration, file outcomes and completion state.
- `files`, `file_versions`, `streams`: source snapshots and stream boundaries;
  missing size/mtime cannot establish cross-run equivalence.
- `profiles`, `stream_results`: deduplicated effective settings, reconstruction
  bytes, verification, failures and correction counts.
- `block_results`, `chunk_results`: real bounded trace observations only, never
  placeholder blocks inferred from aggregate counts.
- `effective_stream_settings`, `effective_block_settings`, `investigation_areas`:
  linked analysis views. Settings describe finalized predictor behaviour, not
  proven compressor identity or unrecorded estimator decisions.

Historical oracle, estimator and timing tables are preserved. The
`oracle-opportunities`, `oracle-cohorts` and `timings` commands can query existing
evidence; old JSON ingestion and offline private-document search commands are
not retained. JSON-valued metadata columns and source sidecars are not legacy
report ingestion.

The Python API provides `CorpusDatabase.record_run` for typed observations,
`merge_scan` for SQLite copies, comparison/query methods, and maintenance.
`corpus.database.scan.scan_records` reads a completed run read-only, one file at
a time, checking its totals. The profile cache is bounded to 4096 entries.
