# tests (integration tests)

These instructions supplement the root [AGENTS.md](../AGENTS.md).

End-to-end round-trip tests against real sample files in `samples/`.

## What Is Tested

- **Core round-trip**: decompress a `.deflate` file with `preflate_whole_deflate_stream`,
  recompress with `recreate_whole_deflate_stream`, assert bitwise identical output.
- **Container round-trip**: compress a ZIP / PNG / DOCX / PDF through
  `PreflateContainerProcessor`, decompress with `RecreateContainerProcessor`,
  assert the output matches the original file byte-for-byte.

## Sample Files (`samples/`)

The `samples/` directory contains real-world compressed files used as test fixtures:
deflate streams, zlib streams, PNGs, ZIPs, PDFs, DOCX, JPEG, WebP, and binary blobs
from various compressors (zlib, zlib-ng, libdeflate, miniz, Windows zlib).

These files are checked into the repository. Do not remove or alter them without
updating the corresponding tests.

## Running

```bash
cargo test --all                    # workspace unit, integration, and doc tests
cargo test -p preflate-rs-root --test end_to_end  # root integration tests
cargo test --package preflate-rs    # core tests only
cargo test --package preflate-container  # container tests only
cargo test <test_name>              # single test by name
cargo test -- --nocapture           # show println! output
```

## Notes

- Tests live in `tests/end_to_end.rs` at the workspace root.
- Some tests use `libdeflate-sys` to generate reference compressions on the fly.
- Native zlib helpers require valid allocation/free callbacks; never create
  null function pointers for `zalloc`/`zfree`.
- Use `--release` for benchmarks, corpus replays, and ignored diagnostic exports.
- Test failures often mean a regression in the estimator or token predictor; check
  those modules first.
