# preflate_util

Command-line tool for testing and benchmarking the preflate-rs workspace against real files.

For recursive, read-only preflate diagnostics without Zstd, use the separate
`preflate_scan` binary documented in the [root README](../README.md).
See [corpus database tooling](../corpus/database/README.md) for private-directory
scans and queries, and [Common Crawl sampling](../corpus/crawl/README.md) for
public rare-stream collection. Both sources write directly to separate SQLite
databases.
All Python tools use the root uv project; corpus scans and benchmarks require
release builds. Contributor guidance lives in [AGENTS.md](AGENTS.md).

Given a file or directory, `preflate_util` compresses each file using the preflate container pipeline, optionally decompresses it back, and prints compression statistics. It is primarily a development and validation tool rather than a production compressor.

## Usage

```shell
preflate_util [OPTIONS] <PATH>
```

`PATH` can be a single file or a directory. Directories are scanned recursively.

### Options

| Option | Default | Description |
|---|---|---|
| `--max-chain <N>` | 4096 | Hash chain depth limit for the DEFLATE predictor |
| `-c, --level <N>` | 9 | Zstd compression level (0–14) |
| `--loglevel <L>` | Error | Log verbosity (`Error`, `Warn`, `Info`, `Debug`, `Trace`) |
| `--verify` | true | Round-trip verification is enabled by default; this flag also enables it |
| `--baseline` | false | Also measure raw Zstd-only size for comparison |

### Output

For each file, a line is printed showing:
- Input file path
- Compression ratio and cumulative compressed/baseline/DEFLATE byte totals
- CPU time for compression

Cumulative totals are printed after each successfully compressed file.

If `--baseline` is set, the totals include raw Zstd size (without preflate), so you
can compare it with DEFLATE-aware re-compression.

A reconstructed-byte mismatch panics with its first differing position.
Compression and reconstruction errors are printed and the tool continues to the
next file; a successful process exit does not prove that every file was processed.

The boolean options are flags, not `true`/`false` arguments. The current CLI
does not expose a flag to disable verification.

## Diagnostic binaries

- `preflate_scan`: recursive read-only analysis, verified by default, with native
  SQLite runs or diagnostic JSON, bounded traces and optional CPU/wall JSONL
  alongside JSON output. No Zstd.
- `preflate_match_check`: compares every reported parameter against verified,
  token-perfect streams in a completed SQLite run, selected with `--run`.
  It reads the database in a read-only snapshot, one file at a time, and writes
  diagnostic JSON. It uses a bounded payload cache; it is not a round-trip test.

```shell
cargo run --release -p preflate_util --bin preflate_scan -- fixtures --output scan.json
cargo run --release -p preflate_util --bin preflate_scan -- fixtures --database private.sqlite --label before
cargo run --release -p preflate_util --bin preflate_match_check -- private.sqlite --run before --output match-check.json
```

JSON reports are never overwritten; SQLite scans append under new unique labels.
Both tools skip cloud-only sources
unless `--hydrate` is supplied. See the [root README](../README.md#scanning-a-document-corpus-sqlite-and-json-diagnostics-no-zstd)
for limits, report schemas, source-identity requirements and exit behavior.

## Building

```shell
cargo build --release -p preflate_util
# Binary at: target/release/preflate_util.exe (Windows) or target/release/preflate_util (Linux)
```

## Example

```shell
# Test a single ZIP file
preflate_util archive.zip

# Benchmark a directory with verbose logging and baseline comparison
preflate_util --loglevel Info --baseline ./test-corpus/
```
