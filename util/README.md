# preflate_util

Command-line tool for testing and benchmarking the preflate-rs workspace against real files.

Given a file or directory, `preflate_util` compresses each file using the preflate container pipeline, optionally decompresses it back, and prints compression statistics. It is primarily a development and validation tool rather than a production compressor.

## Usage

```shell
preflate_util [OPTIONS] <INPUT>
```

`INPUT` can be a single file or a directory. Directories are scanned recursively.

### Options

| Option | Default | Description |
|---|---|---|
| `--max-chain <N>` | 4096 | Hash chain depth limit for the DEFLATE predictor |
| `-c, --level <N>` | 9 | Zstd compression level (0–14) |
| `--loglevel <L>` | Error | Log verbosity (`Error`, `Warn`, `Info`, `Debug`, `Trace`) |
| `--verify` | true | Round-trip decompress and verify each file after compression |
| `--baseline` | false | Also measure raw Zstd-only size for comparison |

`--verify` and `--baseline` are flags, not options accepting `true` or `false`.
The current parser enables verification by default and provides no disabling
flag. Use `preflate_util --help` for the accepted syntax.

### Output

For each file, a line is printed showing:
- Input file path
- Compression ratio and CPU time
- Running compressed, baseline, and original byte totals
- Decompression CPU time when verification succeeds

The running totals are printed after each successfully compressed file.

If `--baseline` is set, the totals include raw Zstd compression for comparison.

A byte mismatch causes an assertion failure with positional diagnostics.
Compression or reconstruction errors are printed and processing continues with
the next file.

## Implementation

The CLI is implemented in [`src/main.rs`](src/main.rs). Its `assert_eq_array`
helper reports positional differences when round-trip verification fails.
Dependency requirements are maintained in the root workspace manifest.

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
