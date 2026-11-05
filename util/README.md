# preflate_util

Command-line tool for testing and benchmarking the preflate-rs workspace against real files.

For recursive, read-only preflate diagnostics without Zstd, use the separate
`preflate_scan` binary documented in the [root README](../README.md).
See [corpus database tooling](../corpus/database/README.md) for private-directory
scans and queries, and [Common Crawl sampling](../corpus/crawl/README.md) for
public rare-stream collection. Private scans can write SQLite directly; crawl
workers return JSON for Python to persist in the separate crawl database.
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
  `--from-run <label>` selects local files from a completed SQLite run;
  `--from-crawl` selects distinct saved payload paths from a crawl catalog.
  Either source mode supports JSON or a separate labelled SQLite output database.
  `--baseline-run <id>` instead rescans a completed run into a read-only JSON
  difference report, with exact verification and unchanged-stream counts.
- `preflate_match_check`: compares every reported parameter against verified,
  token-perfect streams in a completed SQLite run, selected with `--run`.
  It reads the database in a read-only snapshot, one file at a time, and writes
  diagnostic JSON. It uses a bounded payload cache; it is not a round-trip test.
- `preflate_replay`: one JSON request in, one JSON result out, with explicit
  compressor parameters and no estimation, model retry or Zstd. See
  [JSON replay](#json-replay) below.

```shell
cargo run --release -p preflate_util --bin preflate_scan -- fixtures --output scan.json
cargo run --release -p preflate_util --bin preflate_scan -- fixtures --database private.sqlite --label before
cargo run --release -p preflate_util --bin preflate_scan -- commoncrawl.sqlite --from-crawl --output rescan.json
cargo run --release -p preflate_util --bin preflate_scan -- private.sqlite --from-run before --database after.sqlite --label after
cargo run --release -p preflate_util --bin preflate_scan -- private.sqlite --baseline-run 123 --output diff.json --build-identity current-build
cargo run --release -p preflate_util --bin preflate_match_check -- private.sqlite --run before --output match-check.json
```

JSON reports are never overwritten; SQLite scans append under new unique labels.
Console output shows progress at most every two seconds, plus startup/completion,
instead of logging each file. Database-selected scans include a percentage;
directory scans show counts without an extra filesystem pass.
Use `--jobs <1-64>` for bounded file-level concurrency (default 4). Results are
written by one coordinator in input order, with at most twice that many tasks
or results outstanding. File/chunk memory limits apply per worker. Performance
repetitions require one worker; traces default to one. Rust library calls do
not acquire a worker pool, and crawler processes explicitly pass `--jobs 1`.
Both tools skip cloud-only sources
unless `--hydrate` is supplied. See the [root README](../README.md#scanning-a-document-corpus-sqlite-and-json-diagnostics-no-zstd)
for limits, report schemas, source-identity requirements and exit behavior.

## JSON replay

Start with the complete, public synthetic [request example](examples/replay.json):

```shell
cargo run --release -p preflate_util --bin preflate_replay -- util/examples/replay.json
```

Omit the request filename to read one request from stdin. JSON goes to stdout;
`--output result.json` creates a new file and never overwrites an existing one.
A malformed request, limit violation or prediction failure produces
`{"status":"error","error":{"code":"...","message":"..."}}` and a nonzero exit.
Output/CLI errors are reported on stderr. A successful response is
`{"status":"ok","result":{...}}`.

The request contains `source`, complete structured JSON
`reconstruction_parameters`, and optional `options`. These are the authoritative
executable settings, with `max_token_count`, `block_type_strategy` and a typed
`behavior` tree. See the example request for the complete nested layout.
The core validates this JSON directly; estimator Rust types are not public.
Core chunk/trace reports expose executable settings through
`reconstruction_parameters_json()`. Their separate `estimator_parameters_json()`
method returns `{"reconstruction": {...}, "model": "..."}`.
`estimate_first_chunk_estimator_json()` returns this wrapper for the original
first-chunk estimate, before encoding-time normalization.
Scanner `parameters` fields and SQLite `settings_json` contain the same wrapper,
with structured enum names/payloads, never Rust debug strings.
To replay one, explicitly extract `reconstruction` into the request's
`reconstruction_parameters`. Unknown fields, invalid ranges, old flat settings
and full estimator wrappers are rejected. Regenerate old JSON/SQL baselines.

Supported `source` objects:

- `{"type":"file","path":"sample.deflate","offset":0,"length":1234}` reads that
  raw DEFLATE range. `offset` defaults to zero; omitted `length` means the rest
  of the file, subject to the input-byte limit. Extract container payloads first;
  this command does not scan wrappers or assemble PNG IDAT chunks.
- `{"type":"deflate","bytes":[...]}` supplies raw compressed bytes directly.
- `{"type":"blocks","blocks":[...]}` supplies synthetic blocks, as in the
  example. Huffman blocks contain `tokens` with tagged `literal`/`reference`
  objects; stored blocks contain `bytes`. Each block has an explicit `last`;
  only the final block may set it. Huffman blocks are encoded with fixed trees.
  Tokens determine plaintext, so a separate plaintext copy is unnecessary.
  Use original DEFLATE input to preserve original dynamic trees and padding.

Default options and hard ceilings:

| Option | Default | Maximum |
|---|---:|---:|
| `max_input_bytes` | 16 MiB | 64 MiB |
| `max_plaintext_bytes` | 32 MiB | 128 MiB |
| `max_tokens` | 2,097,152 | 4,194,304 |
| `max_blocks` | 4,096 | 65,536 |
| `max_mismatches` | 0 | 1,024 |

Token and block limits are enforced while parsing, before replay.
The JSON request itself is limited to 16 MiB. Sources are read-only, regular
non-symlink files; cloud-only files are rejected unless `--hydrate` is supplied.
File ranges are checked against EOF and source metadata is checked while reading.

The **entire first plaintext-limited chunk** is replayed with the supplied
parameters. `block_start` (zero-based, default 0) and optional positive
`block_count` select only the reported blocks; they never discard dictionary
history or change the chunk's flush context. Limits cover the whole chunk,
including unreported blocks. `stream_complete` and `compressed_bytes` identify
whether all of the first stream was consumed; trailing input is not verified.

Results include whole-chunk and selected-range mismatch counts/rates, per-block
positions/types, flush lookahead limits, dictionary-reset decisions, nonzero
correction counts, and bounded mismatch examples. Literal values and plaintext
are omitted from output. Token counts exclude uncompressed stored-block bytes.
`input_statistics` describes the whole parsed chunk independently of the supplied
parameters: literal/reference counts, reference-length frequencies, maximum
distance, full-length distance-one matches, and maximum tokens/plaintext bytes
per Huffman block. These observations remain available with `encode:false`.
Two-position libdeflate matching requires the `Libdeflate4` hash chain; incompatible
explicit combinations return an `InvalidParameter` JSON error instead of panicking.

`encode` defaults to `true`: complete reconstruction bytes include parameters and
framing, and exact reconstruction of consumed compressed bytes is verified.
`encode:false` still executes correction-aware prediction and counts corrections
but skips CABAC byte encoding/verification; both `reconstruction_bytes` and
`verified` are `null`. Counts are not CABAC costs. `normalize_parameters` defaults
to `false`; enable it explicitly to compare production's safe tiny-stream
canonicalization. `reconstruction_parameters` always echoes the request;
`effective_reconstruction_parameters`
reports any resulting normalization.

The replay Rust API is available under `preflate_rs::diagnostics` only with the
`diagnostics` feature. File access and the request envelope remain in the utility
crate; JSON serialization does not change the bitcode reconstruction format.

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
