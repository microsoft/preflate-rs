# SQLite corpus scans and analysis

This package supports **private/local directory scans** and analysis of both
private scans and public Common Crawl runs. Python 3.14+ uses the root uv project;
the release Rust scanner writes the shared [schema](schema.sql) directly.
The crawler exchanges current scanner JSON reports and streams them into its
persistent SQLite catalog; it does not create per-download SQLite databases.
There is no legacy archived-report import/resume/overlay compatibility path.
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

## Database-driven scans

The scanner can select input files from SQLite instead of walking a directory.
Choose exactly one source mode:

```powershell
# Distinct saved extracts, not original download URLs or deleted scratch documents:
.\target\release\preflate_scan.exe "<crawl-folder>\commoncrawl.sqlite" --from-crawl --output "<new-scan.json>"
# Select local source files from a completed prior run:
.\target\release\preflate_scan.exe "<private.sqlite>" --from-run before --database "<new-results.sqlite>" --label after
# The Python wrapper forwards the same input selection for SQLite output:
uv run --locked python -m corpus.database --db "<new-results.sqlite>" scan "<private.sqlite>" --from-run before --label after
```

Either source mode supports `--output` JSON or `--database` plus `--label`.
The source database is opened read-only in a consistent snapshot; source and
output databases must differ. Merge a completed output run afterwards if needed.
`--from-crawl` deduplicates `saved_streams.path` and defaults to the catalog's
parent as its storage root. Use `--source-root "<storage>"` when the catalog is
stored elsewhere. Relative saved paths resolve within that root.
`--from-run` uses only the selected run's recorded local file paths and saved
absolute input root, not newly discovered directory entries or URL rows.

These are full scans with current settings, not parameter-only checks: changed
files receive new snapshots; missing files become explicit errors. Directory
entries and symlinks are not followed, and files outside the source root are
rejected. Existing cloud, file, candidate and plaintext limits still apply.
Trace and performance-repetition modes remain single-file/directory diagnostics,
not database selection options.
Native scans use four file workers by default; `--jobs 1` selects serial execution.
Both SQLite and JSON outputs have a single ordered writer. The Python `scan`
wrapper forwards `--jobs`; memory budgets apply per worker.

## Read-only baseline comparisons

Use the native scanner to compare the current implementation with a **completed
run ID**, without creating a run or modifying the database:

```powershell
.\target\release\preflate_scan.exe "<baseline.sqlite>" --baseline-run 123 --output "<new-diff.json>" --build-identity current-build
```

Find IDs with the `runs` command below. Only recorded local files are selected;
new directory entries are not discovered. Current scanner defaults and explicit
flags apply, rather than silently inheriting baseline settings. Normal bit-exact
verification is mandatory; `--no-verify`, other source selectors, SQLite output,
traces and performance repetitions cannot be combined with this mode.

The streaming JSON envelope has `report_type: "baseline_diff"`, `baseline` and
`current` provenance, `configuration_differences`, `comparison_compatible`,
`differences`, and a final `summary`. Missing build labels remain null, not
inferred from the package version. Different limits, raw/verification modes or
candidate/trace retention settings flag an incompatible comparison; results
remain diagnostic, not controlled modelling gains.
`--jobs` also applies to baseline comparisons; worker-count differences do not
make modelling results incompatible. The SQLite snapshot and JSON writer stay
on the coordinator; workers only read source files and perform analysis.

Only differences are listed. Stream events carry the path/location,
classification and changed fields with `before`/`after` values. Newly detected
and missing streams carry the available observation. Equal-size changes to
settings, corrections or outcomes are distinct from size improvements and
regressions. Parameters are compared by their full JSON values, never by
database-local profile IDs. Timings and optional detailed traces are not compared.

`summary.coverage` counts unchanged and compared streams, failures/recoveries,
new/missing streams, boundary changes, same-size changes, unavailable files and
changed/unknown source identities. Its reconstruction-byte totals include only
verified pairs with matching boundaries; `summary.scan` contains normal current
scan totals, including excluded inputs. Source identity uses the recorded path,
size and second-precision mtime, **not content hashes**. Changed or unavailable
files are excluded from stream comparisons, not reported as modelling gains.
Unknown size/mtime cannot establish equivalence.

As with ordinary scans, a completed report can contain failures or incompatible
settings; inspect its summary and compatibility flag, not just the exit code.
Incomplete output is never a finished comparison. Existing output files are
never overwritten. This JSON is a comparison report, not a crawler scan envelope
or an importable persistent run.

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
`corpus.database.json_scan.json_scan_records` similarly streams current JSON
scanner output with `ijson`, validating completion and measured totals before
the crawler commits a persistent run.
