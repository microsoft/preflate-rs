# util (preflate_util CLI)

CLI tool for manually testing preflate compression on files and directories.

## Usage

```
preflate_util [OPTIONS] <PATH>

Options:
  --max-chain <N>    Hash chain depth limit (default: 4096)
  -c, --level <N>    Zstd compression level 0-14 (default: 9)
  --loglevel <L>     Log level (default: Error)
  --verify <bool>    Round-trip verify after compress (default: true)
  --baseline <bool>  Measure baseline Zstd-only size (default: false)
```

`<PATH>` may be a single file or a directory (scanned recursively).

## What It Does

1. For each file, calls `PreflateContainerProcessor` to compress.
2. Optionally calls `RecreateContainerProcessor` to decompress and byte-compares the result.
3. Prints per-file and aggregate statistics: compressed size, baseline size, CPU time.

## Source

Single file: `src/main.rs` (~193 lines).

Helper `assert_eq_array<T>()` provides detailed positional diff output for debugging
mismatches during verification.

## Dependencies

- `clap` (4, derive) — argument parsing
- `cpu-time` (1) — CPU time measurement
- `preflate-rs` and `preflate-container` — core logic
- `env_logger` / `log` — logging
