# preflate_util

Command-line tool for testing and benchmarking the preflate-rs workspace against real files.

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
| `--verify <bool>` | true | Round-trip decompress and verify each file after compression |
| `--baseline <bool>` | false | Also measure raw Zstd-only size for comparison |

### Output

For each file, a line is printed showing:
- Input file path
- Original size, compressed size, and ratio
- Detected compressor (hash algorithm)
- CPU time for compression

A summary line at the end shows aggregate totals across all processed files.

If `--baseline true` is set, a second column shows what raw Zstd (without preflate) would produce, so you can see the benefit of DEFLATE-aware re-compression.

If verification fails (reconstructed output does not match original), the tool prints the first differing byte position and exits with an error.

Compression uses the default cumulative 8 GiB deterministic effort budget. If it
is exhausted, that file is skipped with `CompressionEffortLimit` rather than
silently falling back to a literal block. Library callers can adjust or disable
the budget with `PreflateContainerConfig::compression_effort_limit`; container
decompression is unaffected.

## Building

```shell
cargo build --release -p preflate_util
# Binary at: target/release/preflate_util.exe (Windows) or target/release/preflate_util (Linux)
```

## Adversarial input sweep

`preflate_adversarial` is a separate executable that deterministically tests boundary sizes,
repeated and pseudo-random bytes, false format signatures, zlib/gzip/ZIP/PNG streams,
damaged DEFLATE payloads and zlib/PNG checksums, tiny or invalid IDAT runs,
truncation, and adjacent streams.
Each case is compressed and reconstructed with multiple
input chunk sizes; recognized raw DEFLATE streams are also checked for bit-exact recreation.
The Lepton/JPEG library is not exercised intentionally.
Release-mode unit tests also flip bits within raw DEFLATE streams and check that
accepted mutations reconstruct byte-for-byte.

```shell
cargo run --release -p preflate_util --bin preflate_adversarial -- --seeds 4 --max-size 65536 --max-cases 1200
```

Use `--seed N` to reproduce a sweep and `--max-chain N` to set the predictor budget.
The runner writes only failing inputs under `target` in an `adversarial-failures` directory
(`--artifacts` overrides it) and exits nonzero on any panic, container error, or round-trip
mismatch. The reported count of unsupported raw DEFLATE streams is informational: the
container must still preserve them as literal bytes.

## Example

```shell
# Test a single ZIP file
preflate_util archive.zip

# Benchmark a directory with verbose logging and baseline comparison
preflate_util --loglevel Info --baseline true ./test-corpus/
```
