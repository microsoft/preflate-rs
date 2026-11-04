# util (preflate_util CLI)

These instructions supplement the root [AGENTS.md](../AGENTS.md).

CLI tools for testing preflate compression and diagnosing corpus modelling.
The separate `preflate_scan` binary performs preflate-only scans without Zstd;
see the root README for native SQLite output, limits, traces and diagnostic
performance JSONL options.

## Usage

```
preflate_util [OPTIONS] <PATH>

Options:
  --max-chain <N>    Hash chain depth limit (default: 4096)
  -c, --level <N>    Zstd compression level 0-14 (default: 9)
  --loglevel <L>     Log level (default: Error)
  --verify          Enable round-trip verification (already enabled by default)
  --baseline        Measure baseline Zstd-only size (default: off)
```

`<PATH>` may be a single file or a directory (scanned recursively).
Boolean options are flags, not `true`/`false` values; the utility currently has
no verification-disable flag.

## What It Does

1. For each file, calls `PreflateContainerProcessor` to compress.
2. Optionally calls `RecreateContainerProcessor` to decompress and byte-compares the result.
3. Prints per-file and aggregate statistics: compressed size, baseline size, CPU time.

## Source

`src/main.rs` implements container compression. `src/scan_main.rs` implements the
preflate-only scanner, with SQLite persistence in `src/scan_database.rs` and
diagnostic CPU/wall JSONL output in `src/scan_perf.rs`.
`src/match_main.rs` implements `preflate_match_check`, a streaming parameter guard
for verified token-perfect streams in a completed SQLite run selected with
`--run`. It uses a read-only snapshot and writes diagnostic JSON; it does not
accept JSON baselines. Both diagnostics share cloud-file
checks in `src/scan_fs.rs`; parameter checks do not replace exact reconstruction.
The [corpus project](../corpus/README.md) supports private-directory scans and
Common Crawl with separate databases using the same normalized SQLite schema.
Python merges completed SQLite runs; legacy JSON ingestion is not supported.
See [database/README.md](../corpus/database/README.md) for identity and run-set
queries, and [crawl/README.md](../corpus/crawl/README.md) for Common Crawl sampling.
Run Python tools through the root uv project and release-build the scanner.
Keep crawl results separate; rarity counts use only the crawl catalog, never
private scan history.

Helper `assert_eq_array<T>()` provides detailed positional diff output for debugging
mismatches during verification.

## Dependencies

- `clap` (4, derive) — argument parsing
- `cpu-time` (1) — CPU time measurement
- `rusqlite` (bundled SQLite) — native scanner persistence
- `preflate-rs` and `preflate-container` — core logic
- `env_logger` / `log` — logging
