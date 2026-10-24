# Integration tests

[`end_to_end.rs`](end_to_end.rs) checks the core and container pipelines against
real files and reference compressor output. Round-trip tests compare the
reconstructed output byte-for-byte with the original. The overhead benchmark
also checks the sizes of reconstruction corrections.

## Running

Run from the workspace root:

```shell
cargo test --test end_to_end
cargo test --test end_to_end <test_name>
```

For workspace and crate-level test commands, see the
[developer workflow](../README.md#developer-workflow).

## Fixtures and reference compressors

Fixtures in [`samples/`](../samples/) include raw DEFLATE and zlib streams,
PNGs, ZIPs, PDFs, DOCX files, JPEGs, WebP images, and binary data. Do not change
or remove fixtures without updating their tests.

Tests also generate reference compressions with zlib, zlib-ng, libdeflate, and
miniz_oxide. Predictor or estimator regressions can appear as a round-trip
failure or changed overhead. Investigate unexpected changes rather than
updating expected sizes without an explanation.
