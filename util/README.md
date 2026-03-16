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
preflate_util --loglevel Info --baseline true ./test-corpus/
```
