# Corpus tooling

The corpus project tree contains Python tooling, not a Rust workspace crate.
It uses the **root** `pyproject.toml`, `uv.lock` and Python 3.14 environment:

```powershell
uv sync --locked
cargo build --release -p preflate_util --bin preflate_scan
```

The root uv project always resolves dependencies through the configured
Microsoft Python feed; do not override it when updating the lockfile.

| Component | Purpose |
|---|---|
| [database/](database/README.md) | Scan private/local directories into SQLite; compare runs, inspect profiles and maintain databases |
| [crawl/](crawl/README.md) | Discover public streams through Common Crawl, with its own SQLite catalog and content-addressed saves |
| [gen_corpus.py](gen_corpus.py) | Generate synthetic fixtures under ignored `corpus/generated`; optional `--extra jpeg` |
| [gen_fuzz.py](gen_fuzz.py) | Generate fuzz seeds, by default under `fuzz/corpus/fuzz_container` |
| [profile_container.py](profile_container.py) | Release-mode Callgrind profiling on Linux/WSL; Windows wrapper alongside it |

## Data sources

**Private/local directories and Common Crawl are both supported.** They use the
same native release scanner and SQLite schema, but separate databases. Private
scans are read-only with respect to source files, skip cloud-only files by
default, and verify bit-exact reconstruction. Common Crawl is the public network
discovery source; it does not consult or import private scan history for rarity.

```powershell
uv run --locked python -m corpus.database --db "<private-folder>\private.sqlite" scan "<private-directory>" --label before
uv run --locked python -m corpus.crawl --config "<local-config.toml>" crawl --batches 5
```

Standalone scans can write JSON or normalized SQLite rows directly. Parallel
crawl workers analyze downloads and verify saved extracts using streaming JSON,
not temporary SQLite databases. The coordinator validates completed JSON reports
and records one transactional run in the persistent crawl database, replacing
scratch paths with capture URLs. Legacy archived-report, overlay and timing import
commands are not restored. Existing SQLite data remains readable.

Database-driven scans explicitly select saved payloads with `--from-crawl` or
local files from a completed run with `--from-run <label>`. Either selection can
write JSON or a new labelled run in a separate SQLite output database; see
[database-driven scans](database/README.md#database-driven-scans).

Use synthetic/public fixtures for committed tests. Keep private databases,
configuration, payloads, reports and profiling results outside commits and
external services. Synthetic generation is for testing, not source discovery.

## Validation

Build the release scanner first so native extraction tests execute:

```powershell
cargo build --release -p preflate_util --bin preflate_scan
uv run --locked --extra jpeg --extra parquet python -W error -m unittest corpus.database.test_database corpus.crawl.test_rare_crawl corpus.crawl.test_parquet_index
uv run --locked --extra jpeg corpus\gen_corpus.py --help
uv run --locked corpus\gen_fuzz.py --help
uv run --locked corpus\profile_container.py --help
```
