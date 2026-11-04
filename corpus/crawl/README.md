# Rare-compression stats and Common Crawl sampling

`corpus.crawl` discovers public DEFLATE streams through Common Crawl and keeps
rare or poorly modelled behaviour. Its commands are:

- `stats` reports signatures and representative distributions within the crawl database.
- `crawl` samples random Common Crawl records, scans them with the **release**
  `preflate_scan`, and keeps the DEFLATE streams that are rare or poorly modelled
  plus the streams of a uniform random sample of scanned files for a
  representative distribution. Only the streams and their source locations are
  kept, except for low-overhead standalone PNGs kept unchanged.
- `migrate-storage` reorganizes existing saves into content-addressed payloads
  and separate source metadata, retaining old whole documents separately.

Private/local directories are supported separately by
[directory scanning](../database/README.md); the crawler never opens their databases.
Common Crawl results go to a **separate** crawl database (`commoncrawl.sqlite`
under `storage` by default). It uses the shared corpus database schema plus the
crawl's sampling tables. Every batch scan is merged directly from SQLite as one
run, with scratch paths replaced by captured URLs and modification times by
capture times. No legacy JSON ingestion is used. Never mix private scan
databases and crawl databases; matching configured paths are rejected.

Dependencies (`requests`, `warcio`) are managed by the root uv project; run from
the repository root:

```powershell
cargo build --release -p preflate_util --bin preflate_scan
uv run --locked python -m corpus.crawl stats
uv run --locked python -m corpus.crawl stats --json --limit 50
uv run --locked python -m corpus.crawl crawl --batches 5
uv run --locked python -m corpus.crawl crawl --batches 5 --parallelism 4
uv run --locked python -m corpus.crawl crawl --batches 5 --no-mime-filter
uv run --locked python -m corpus.crawl crawl --batches 10 --exclude-text
uv run --locked python -m corpus.crawl crawl --batches 10 --office-only
uv run --locked python -m corpus.crawl crawl --batches 0 --max-download-mib 0   # until Ctrl+C
uv run --locked python -m corpus.crawl crawl --mime image/png --mime 'application/vnd.openxmlformats-officedocument.*'
uv run --locked python -m corpus.database --db <storage>/commoncrawl.sqlite runs
uv run --locked python -m unittest corpus.crawl.test_rare_crawl -v
uv run --locked --extra parquet python -m unittest corpus.crawl.test_parquet_index -v
```

The shared `corpus.database` queries (`runs`, `families`, `outliers`, `compare-set`,
...) work on the crawl database through `--db`.

`--no-mime-filter` accepts any content type, including records without MIME
metadata. It only disables the MIME filter: HTTP status 200, record/file size
limits, deduplication, download budgets and minimum saved stream size still
apply. It cannot be combined with `--mime`. For a persistent setting use
`no_mime_filter = true` in `[crawl]`; an explicit `--mime` re-enables filtering.
Unfiltered runs can download many HTML/text records with no usable DEFLATE
streams. Their selection markers and scan results are still recorded.

`--exclude-text` instead accepts everything except `text/*`, XML/JSON (including
`+xml`/`+json` types such as XHTML, Atom and SVG), JavaScript/ECMAScript and URL-encoded
form content. It uses detected MIME preferentially, falling back to declared MIME;
missing MIME stays eligible. Binary application types, images, archives and fonts
remain eligible without an allowlist. Other safety limits remain unchanged.
Use `exclude_text = true` in `[crawl]` to persist this mode; it takes precedence over
the configured MIME allowlist or `no_mime_filter`. The CLI modes `--mime`,
`--no-mime-filter` and `--exclude-text` are mutually exclusive and override the
configured mode.

`--office-only` selects legacy Word/Excel/PowerPoint, modern OOXML (including
macro-enabled documents and templates), OpenDocument and generic Tika Office
MIME types. It replaces the configured allowlist and disables the other MIME
modes. It is mutually exclusive with `--mime`, `--no-mime-filter` and
`--exclude-text`. Matching uses detected or declared MIME, not URL extensions;
Office documents labelled only as ZIP or octet-stream may be missed.
All size limits, save thresholds and sampling settings remain active.

## Optional Parquet index sampling

CDX byte slices remain the default. For scarce MIME types, use the Parquet URL
Index instead:

```powershell
uv run --locked --extra parquet python -m corpus.crawl crawl --index-source parquet --office-only --batches 10
uv run --locked --extra parquet python -m corpus.crawl crawl --index-source parquet --mime image/png
```

Persist the choice with `index_source = "parquet"` in `[crawl]`. The optional
`pyarrow` dependency is managed by uv; CDX runs do not require the extra.
All existing MIME modes, deduplication, sampling and stream verification apply.

The sampler chooses a random Parquet file and row group in the selected crawl.
It reads only the two MIME columns first. If matches exist, it reads the URL,
capture time, digest, status and WARC-location columns for that group, then
downloads only selected WARC records. MIME filtering is local to these compact
columns, not a server-side filter. A Parquet file can be hundreds of MiB without
being downloaded in full; location columns can still cost tens of MiB.

Up to 10,000 MIME-matching rows are selected uniformly per group before the
status and size checks. One candidate pool is reused across batches until
exhausted, then another crawl/file/group is drawn. Pools are not persisted across restarts; only
the manifests and file sizes are cached under the configured storage. Seen and
currently reserved digests are removed before each batch selection.

`--parquet-max-index-mib` (TOML `parquet_max_index_mib`, default 128) limits range
bytes per pool refill. A group exceeding this limit or four million rows fails
explicitly and follows the existing batch failure/backoff policy; there is no
silent CDX fallback. Index bytes count toward the overall download budget, which
remains checked between batches rather than being a strict transfer ceiling.
An empty or exhausted pool may produce an empty batch before another group is
sampled. Unsupported crawls or missing manifests are reported as batch failures.

This is a MIME-targeted discovery sample, not a uniform sample of all Common
Crawl records: files/groups are sampled uniformly, their populations differ,
and pools are capped. PNG availability depends on the crawl's index coverage.
In the sampling catalog, Parquet `range_start` identifies the row-group index,
`range_bytes` is zero, and `cdx_lines` records its row count.

## Long runs

`--batches 0` runs until Ctrl+C, and `max_download_mib = 0` removes the
download budget; the budget is checked before each batch, so the last batch can
overshoot it. Already-prefetched work is completed even if the budget is reached
while scanning; no further batch is queued. Each batch prints one line. Every `status_interval_seconds` the crawl
prints a cumulative status block: files per hour, streams, rare and sampled saves,
observed crawl signatures, and any newly discovered signatures since
the previous block. A failed batch (network or scanner) is logged and retried
with backoff; `max_consecutive_failures` failures in a row stop the run. Every
completed record is committed, so stopping with Ctrl+C or killing the process
loses at most the current batch, and a restart continues with fresh records.
On Ctrl+C the current scan's child processes are stopped and queued work is
cancelled. HTTP requests already in flight finish or reach their configured
timeout/retry limits before the downloader shuts down. Prefetched but
uncommitted records remain eligible on restart.

## Pipeline and parallelism

`parallelism` (default 4, or `--parallelism`) caps workers **per stage**:

- Downloads use up to `min(fetch_workers, parallelism)` HTTP workers.
- Scanning uses up to `parallelism` independent release scanner processes,
  scheduling files dynamically across CPU cores. Saved-extract verification
  uses the same limit, after the initial scan has finished.
- SQLite imports, rarity selection, sampling and payload saves run on the
  coordinator thread, preserving deterministic batch ordering and save caps.

One download batch is prefetched while the current batch is scanned and
imported. There is only one prefetch slot: at most the current and next batch's
HTTP bodies are retained, bounded by `records_per_batch` and record size limits.
Backpressure prevents an unbounded download backlog. Index selection stays on
the coordinator; a batch excludes digests already committed or reserved by the
current batch. No SQLite connections are shared with worker threads.

Worker SQLite scans are merged in input order into one batch SQLite run;
summary counts and byte totals are summed, the weighted correction ratio is
recomputed, and only the worst 20 streams are retained. The merger streams
file records instead of loading all worker reports at once. `parallelism = 1`
limits each stage to one worker but still overlaps downloading with scanning.

## Rare and sampled files

Each processed record has a `selection` marker in the crawl database's `records`
table:

| `selection` | Meaning |
|---|---|
| `rare` | Saved because of rare or poorly modelled evidence |
| `sampled` | Drawn into the representative sample |
| `both` | Rare and independently drawn into the sample |
| NULL | Scanned only (streams are still in the crawl database) |

The sample is a Bernoulli draw with probability `sample_rate` per scanned,
non-duplicate file, independent of rarity, so `selection IN ('sampled','both')`
is an unbiased sample of the crawled MIME population. Sampled files without
DEFLATE streams are marked but store nothing. Stream results for all scanned
files are imported, so `stats` reports the family distribution of all scanned
streams beside the sample-only distribution. Join a record to its streams with
`files.path = records.url` and `file_versions.size_bytes = records.body_bytes`.

## Saved streams

Payloads have content-addressed names; the corpus contains only replayable files:

```text
<storage>/
  corpus/
    deflate/<first-two-hash-characters>/<full-payload-sha256>.deflate
    png/<first-two-hash-characters>/<full-payload-sha256>.png
  sources/<first-two-hash-characters>/<full-document-sha256>.json
  legacy_documents/   # whole documents retained from the former layout
  commoncrawl.sqlite
  scratch/
  cache/
```

Rarity, sampling and estimated compressor settings belong in SQLite and source
metadata, not directory names: one payload can have multiple sources and be both
rare and sampled. Source-document extensions do not describe raw stream files.
Metadata and legacy documents live outside `corpus`, so recursive scans there
do not scan JSON files or duplicate document payloads.

A rare document keeps up to `max_saved_per_signature` triggering streams per
saved signature; a sampled document keeps all its streams, or a uniform draw of
`max_sampled_streams_per_file`, after filtering by `min_saved_deflate_bytes`.
The save threshold defaults to 4097 compressed DEFLATE bytes (strictly greater
than 4 KiB), excluding PNG framing and other wrappers. It applies to rare and
sampled saves, including failures whose reported processed size meets the threshold.
Small streams still appear in scan reports and statistics; they do not consume
rare save caps. Existing saved payloads are not removed. Override with
`--min-saved-deflate-bytes`; 0 disables the save threshold.
Raw DEFLATE files use `.deflate`, which
`preflate_scan` scans in raw mode; PNG payloads use `.png`.
Each source metadata JSON records the URL, crawl, WARC file/offset/length, capture time,
document SHA-256 and size, the selection and reasons, and for each saved stream
its location (`kind`, signature `offset`, `deflate_offset`, `member_name`, the
extracted byte `range`), original scan result and settings. Streams that cannot
be located (for example unsupported ZIP entries) are listed under `unlocated`.
The `saved_streams` table in the crawl database holds the same information.
Identical payload bytes are stored once. Each saved entry's `file` is relative
to its source JSON's directory. `records.saved_path` points at that source JSON
(or a preserved legacy document); `saved_streams.path` points at the payload.

To migrate existing saves, stop crawling and run:

```powershell
uv run --locked python -m corpus.crawl migrate-storage
```

The migration copies and verifies checksums before committing new SQLite and
JSON references, then removes the verified old files and empty old directories.
It preserves old whole documents and their sidecars under `legacy_documents`.
It is safe to rerun; locked empty directories are reported and retained for
cleanup on a later invocation.

- **zlib, gzip, ZIP and raw** streams are cut at
  `[deflate_offset, deflate_offset + deflate_bytes)`, excluding wrappers.
  Failed streams keep `failure_window_kib` from `deflate_offset`, because their
  reported length covers only what was processed before the failure.
- **PNG IDAT** streams from standalone PNGs are saved byte-for-byte unchanged
  when the original is at most 10% larger than the minimal PNG extract.
  Otherwise they are kept as a minimal PNG to exercise the
  container's IDAT handling: the PNG signature, the IHDR that the scanner pairs
  with the IDAT (the last one before it), any PLTE, the consecutive IDAT chunks
  copied verbatim (original chunk split, zlib header, Adler-32 and CRCs, even
  bad ones), and IEND. Source metadata lists the IHDR/PLTE offsets and every IDAT
  chunk's offset and length, plus `png_storage` (`original` or `minimal`).

With `verify_saved` (default), each batch's extracts are rescanned by the same
`preflate_scan`, and the result must reproduce the original detection: one raw
or `png_idat` stream with equal status, DEFLATE, plaintext and correction bytes
and verification (status and error code for failures). The outcome is stored as
`verify` = `match`/`mismatch` with a `verify_detail`; mismatches are logged,
counted in the status block and listed by `stats`. For PNG, a mismatch points at
IDAT parsing or reassembly rather than at the DEFLATE model.

Common Crawl rarely captures images directly, so PNG streams mostly come from
PNGs stored inside documents such as Office files, EPUBs, APKs and JARs;
`--mime` focuses a run on such types.

## Configuration

Settings come from the `[crawl]` table of the Git-ignored `corpus.local.toml`
(`--config` selects another file). Only `storage` is required; set `scanner`
there or in `locations.scanner` to select the release executable. Rarity uses
only crawl evidence. The removed `history_db` and `history_runs` settings are
rejected. Private `[database]` and `[scope]` settings are never used as rarity
inputs. Relative paths resolve against the TOML directory; unknown keys fail.

```toml
[crawl]
storage = '<crawl-folder>'     # commoncrawl.sqlite, corpus/, sources/, scratch/, cache/
# crawl_db = '<file>'          # optional; defaults to <storage>/commoncrawl.sqlite
crawls = ['random']            # 'latest', 'random' (among recent_crawls) or CC-MAIN-YYYY-WW labels
batches = 10                   # default for `crawl`; --batches overrides; 0 runs until Ctrl+C
max_download_mib = 4096        # per invocation, index ranges and records combined; 0 is unlimited
min_saved_deflate_bytes = 4097 # minimum compressed stream size to keep; >4 KiB
parallelism = 4               # maximum download workers and scanner processes per stage
```

| Setting | Default | Meaning |
|---|---|---|
| `sample_rate` | 0.05 | Probability of drawing each scanned file into the representative sample (0 disables) |
| `status_interval_seconds` | 300 | Cumulative status block interval (0 prints only the final block) |
| `max_consecutive_failures` | 5 | Consecutive failed batches before a long run stops |
| `recent_crawls` | 12 | Crawl pool for `random` |
| `mime_patterns` | PDF, PNG, TIFF, ICO, ZIP/Office/ODF/EPUB/JAR/APK, gzip, SWF, WOFF | `fnmatch` patterns against detected and declared MIME |
| `no_mime_filter` | false | Accept all MIME types (CLI `--no-mime-filter`); other limits remain active |
| `exclude_text` | false | Allow all non-text MIME types (CLI `--exclude-text`), including missing MIME |
| `cdx_range_mib` | 4 | Random byte range read from one CDX index shard per batch |
| `records_per_batch` | 64 | Records sampled from that range |
| `max_record_bytes` | 16 MiB | Skip larger WARC records |
| `parallelism` | 4 | Maximum workers per download/scan stage; CLI `--parallelism` (positive integer) |
| `fetch_workers` | 4 | HTTP workers, additionally capped by `parallelism`; throttling (429/5xx) backs off |
| `scan_max_file_mib`, `scan_timeout_seconds` | 64, 3600 | Scanner limits |
| `min_deflate_bytes` | 1025 | Successful crawl streams below this are ignored for rarity |
| `min_saved_deflate_bytes` | 4097 | Minimum compressed DEFLATE size for rare and sampled payload saves (0 disables); independent of statistics |
| `family_max_files` | 2 | Save when a family is in at most this many known files |
| `variant_max_files` | 0 | Save when a variant was never seen |
| `exact_max_files` | -1 | Exact-profile tier (-1 disables; estimates vary too much per stream) |
| `failure_max_files` | 2 | Save rare failure classes |
| `poor_ratio`, `poor_min_deflate_bytes` | 0.05, 4096 | Save streams whose correction bytes exceed this share of DEFLATE bytes |
| `max_saved_per_signature` | 3 | Stop saving a signature after this many files; also the streams kept per signature in one file |
| `max_sampled_streams_per_file` | 64 | Streams kept from one sampled file, drawn uniformly (0 keeps all) |
| `failure_window_kib` | 1024 | Bytes kept from `deflate_offset` for a failed stream |
| `verify_saved` | true | Rescan saved extracts and record whether they reproduce the original detection |
| `keep_scratch`, `seed` | false, none | Debugging aids |

## Signatures

Signatures group **effective estimated settings**, not proven producer identity:

| Tier | Contents |
|---|---|
| `family` | Hash algorithm, matching kind, strategy and insertion kind, with estimated numeric arguments removed (`AddFirst(106)` becomes `AddFirst`) |
| `variant` | Family plus full matching parameters, block-type strategy and window bits |
| `exact` | The complete effective profile (statistics only by default) |
| `failure` | Wrapper kind, status and error code of an unsuccessful stream |

A file counts once per signature. Crawl evidence accumulates in its own database
and is applied to each subsequent document, including within the same batch,
so a rare type stops being rare as it is found and save caps cannot be exceeded
by documents selected together.

## Crawl procedure

1. Choose a crawl, a random CDX index shard and a random byte range of that shard.
2. Resynchronize on whole gzip members in that range and filter `status=200` lines by MIME, size and unseen payload digest.
3. Fetch the sampled WARC records by HTTP range request, overlapping the next batch's downloads with processing the current batch. Write the current HTTP bodies to `storage/scratch/batch-*`.
4. Run bounded parallel release `preflate_scan` processes with verification enabled, merge their temporary SQLite results into the crawl database, then judge each file against earlier crawl evidence.
5. Extract the selected streams (see [Saved streams](#saved-streams)), rescan the extracts to check that they reproduce, and store payloads under `storage/corpus/` with source metadata under `storage/sources/`.
6. Record every processed payload and saved stream in the crawl database and delete the scratch batch, including the downloaded documents.

HTTP requests use one pooled `requests` session with urllib3 retry/backoff
(including `Retry-After`) on 429 and 5xx responses; WARC records are parsed with
`warcio`, keeping HTTP bodies undecoded so `Content-Encoding` gzip/deflate is
scanned too.
Incomplete response bodies are retried with the same bounded backoff policy;
exhausted retries are logged as fetch failures. Batch saved-document counts
count `both` records once.

Reasons, in priority order, are `rare_family`, `rare_variant`,
`rare_exact`, `rare_failure` and `poor_model`. Failures in truncated records
(`WARC-Truncated`, common for large PDFs) are ignored as truncation artifacts;
successful streams in them still count. Identical payloads are processed once.
An interrupted crawl keeps every completed record. Common Crawl payloads are
public, but keep the crawl database, reports and corpus out of commits, like other corpus data.
