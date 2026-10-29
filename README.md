# preflate-rs

**preflate-rs** is a Rust library for lossless re-compression of DEFLATE-compressed data. It analyzes an existing DEFLATE bitstream, extracts the uncompressed plaintext along with a compact set of reconstruction parameters, and later recreates the **bit-exact** original DEFLATE stream from those two pieces. This makes it possible to re-compress the plaintext with a more modern algorithm (Zstd, Brotli, LZMA) while preserving perfect binary round-trip fidelity.

The library is used in production cloud storage systems where content must be stored with bit-exact fidelity while still benefiting from better compression ratios.

[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

---

## Why preflate-rs?

DEFLATE streams are not uniquely determined by their plaintext. The same input can compress to many different valid bitstreams depending on the compressor, its version, and the parameters used. Simply decompressing and recompressing will produce a *different* bitstream — which is a problem for systems that need to verify or reproduce file hashes exactly.

preflate-rs solves this by treating the original DEFLATE stream as the ground truth and recording only the *differences* from what a reference model would predict. Since well-tuned compressors are highly predictable, these corrections are very small — typically well under 1% of the uncompressed data size.

---

## How It Works

### Analysis (compress direction)

1. **Parse** — The DEFLATE bitstream is decoded into a sequence of tokens: literals (raw bytes) and length/distance back-references.
2. **Estimate** — The token sequence is analyzed to fingerprint the original compressor: hash algorithm, chain depth, nice-length cutoff, window size, and block-splitting strategy.
3. **Predict** — Compression is re-run using the estimated parameters. For each token, the model predicts what the original compressor would have chosen.
4. **Encode differences** — Wherever the prediction differs from the actual token, a correction is recorded using CABAC (Context Adaptive Binary Arithmetic Coding, the same codec used in Lepton JPEG compression).

The result is the uncompressed plaintext plus a small corrections blob. Both can be stored or re-compressed with any modern algorithm.

### Reconstruction (decompress direction)

The plaintext and corrections are fed back into the predictor, which replays the original compression decisions step by step to recreate the exact original DEFLATE bitstream.

---

## Supported Compressors

The library detects and models the following DEFLATE implementations:

| Compressor | Notes |
|---|---|
| [zlib](https://github.com/madler/zlib) | All levels; near-zero overhead |
| [zlib-ng](https://github.com/zlib-ng/zlib-ng) | All levels except level 9 |
| [libdeflate](https://github.com/ebiggers/libdeflate) | 15-bit fastest buckets, adaptive greedy minimum lengths, distance-aware lazy and lazy2 profiles |
| [miniz / miniz_oxide](https://github.com/richgel999/miniz) | Distinct fastest hash and grouped-probe greedy/lazy profiles |
| Windows zlib | Built-in PNG codec and shell ZIP compression |

Unrecognized compressors still round-trip correctly — the corrections overhead is simply higher.

---

## Reconstruction Overhead

The table below shows overhead (corrections size as a percentage of uncompressed data) on [`samples/sample1.bin`](samples/sample1.bin), not a bound for all inputs. To benefit from re-compression, your target algorithm needs to beat the original by at least this margin.

| Compressor         | 0      | 1      | 2      | 3      | 4      | 5      | 6      | 7      | 8      | 9     |
|--------------------|--------|--------|--------|--------|--------|--------|--------|--------|--------|-------|
| **zlib**           | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.08%  | 0.03%  | 0.01%  |
| **zlib-ng**        | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.60%  | 0.43%  | 0.01%  | 0.01%  | N/A    |
| **libdeflate**     | 0.01%  | 0.03%  | 0.07%  | 0.06%  | 0.06%  | 0.07%  | 0.06%  | 0.05%  | 0.04%  | 0.06%  |
| **miniz_oxide**    | 0.01%  | 0.05%  | 0.02%  | 0.04%  | 0.02%  | 0.02%  | 0.02%  | 0.03%  | 0.02%  | 0.03%  |

Greedy/lazy recognition does not add another pass or trial compression. During
the existing hash-depth estimation pass, at most 256 length-three references per
candidate are sampled using one next-position hash-head lookup and a four-byte
comparison. Repeatedly skipping a longer, no-farther match identifies greedy
parsing in supported non-zlib streams. Surviving hash signatures and known search
budgets select implementation-specific profiles; ambiguous cases retain the
generic model. Miniz matching reproduces three-node probe groups, reduced lazy
budgets, and its window exclusions. Libdeflate lazy matching compares length and
distance cost, with bounded one- or two-position lookahead. Reconstruction uses the
serialized profile rather than repeating the fingerprint.

Libdeflate's fastest fingerprint shares the existing 16-bit hash calculations and
depth table, with at most 256 references checking the merged 15-bit, two-entry
buckets. The legacy 16-bit candidate remains available if that fingerprint fails.
Greedy levels inspect at most the first 4096 bytes of each block to reproduce the
minimum match length, stopping as soon as 80 distinct bytes establish length three.
These are bounded observations, not additional full-stream passes or trial encodes.

On [`samples/pptxplaintext.bin`](samples/pptxplaintext.bin), the low-level profiles
reduce correction bytes as follows:

| Libdeflate level | Previous model | Current model | Token mismatches |
|------------------|----------------|---------------|------------------|
| 1 | 1,061 | 645 | 0 |
| 2 | 5,114 | 762 | 2 |
| 3 | 5,299 | 707 | 0 |
| 4 | 4,930 | 836 | 0 |

Three alternating same-compiler release A/B rounds measured level 1 encoding
throughput at -2.3% on the binary fixture and -0.5% on the document fixture.
Document levels 2-4 gained 2.7-4.3%. Timings are workload-dependent; use the
throughput test below to check other inputs.

The new hash and matching modes require corrections format **0x83**. Older
**0x81**, **0x82**, and unversioned correction blobs are rejected; there is no
automatic conversion.

Remaining gaps include zlib-ng levels 5/6 (match-end lookahead and backward match
adjustment), libdeflate's adaptive minimum lengths in lazy modes, and Huffman-tree details.
The medium-parser investigation did not justify coercing unrelated hash profiles
or adding trial encodes. Some valid short streams with incomplete Huffman trees
also hit an existing reader limitation before fingerprinting.

---

### Isolating prediction overhead

The ignored diagnostic tests separate token prediction errors from Huffman-tree
corrections without changing production parameters or the reconstruction format.
Generate raw streams for every compressor at levels 0-9, then analyze them:

```shell
cargo test --test end_to_end export_compression_diagnostics -- --ignored --nocapture
cargo test -p preflate-rs diagnose_compression -- --ignored --nocapture
```

Fixtures default to `target/prediction-diagnostics`. Set `PREFLATE_DIAGNOSTICS`
to use another directory (or an existing directory of raw `.deflate` streams).
Set `PREFLATE_DIAGNOSTICS_INPUT` when exporting to use plaintext other than
`samples/sample1.bin`. Use a separate fixture directory for each input.

The report ranks reconstruction overhead relative to the original DEFLATE size,
prints estimated parameters and nonzero correction counts, and shows the first
eight token mismatches with plaintext offsets and actual/predicted tokens.
Reported token mismatches precede reference re-prediction; correction counts
reflect the subsequent recovery and encoding. Every baseline is verified against
the original bytes. Unsupported parameter estimates are reported separately.

For a focused experiment in PowerShell:

```powershell
$env:PREFLATE_DIAGNOSTICS_FILTER = "miniz_2"
$env:PREFLATE_DIAGNOSTICS_SWEEP = "1"
cargo test -p preflate-rs diagnose_compression -- --ignored --nocapture
Remove-Item Env:PREFLATE_DIAGNOSTICS_FILTER, Env:PREFLATE_DIAGNOSTICS_SWEEP
```

The filter is a filename substring. Sweeps first change one parameter at a time,
then combine matching mode, nice length, and chain-budget candidates while holding
the dictionary policy and hash algorithm fixed. Isolated variants and improving
combined candidates are verified byte-for-byte; rejected candidates are printed
explicitly. "Best tested" is not an exhaustive optimum. The normal overhead
benchmark remains `cargo test --test end_to_end compression_benchmark_overhead_size`.

To measure encoding throughput separately from fixture generation and verification:

```shell
cargo test --release -p preflate-rs benchmark_prediction_throughput -- --ignored --nocapture
```

This uses exported raw streams, reports plaintext MiB/s and correction sizes, and
disables the optional encode-time round-trip validator. Run timing comparisons
without other builds or tests running concurrently.

### Compressor regression coverage

The normal regression suite combines focused compressor-contract tests with
broader invariants and exact user-facing round trips:

- Seeded random, nearly periodic, structured-record and mixed-entropy data,
  alongside real fixtures and inputs around short-tail and dictionary boundaries.
- 486 miniz/libdeflate round trips across levels 1-9, plus 96 zlib/zlib-ng controls.
- 36 continuation cases across two inputs and two chunk limits, checking plaintext,
  exact reconstructed bytes and first-chunk-only parameters.
- An independent longest-prefix oracle for match searches, alphabet/depth
  invariants, candidate-order independence and diagnostic parameter isolation.

```shell
cargo test -p preflate-rs
cargo test --test end_to_end -- compressor_models_ compression_benchmark_overhead_size
```

An explicitly ignored periodic-miniz regression preserves a known reader
limitation: a native-accepted stream with an incomplete Huffman tree is rejected
before fingerprinting. It can be reproduced with
`cargo test --test end_to_end periodic_miniz_streams_roundtrip -- --ignored`.
This is not counted among the passing round trips.

## Workspace Layout

| Crate | Output | Description |
|---|---|---|
| [`preflate/`](preflate/) | library | Core DEFLATE analysis and reconstruction engine |
| [`container/`](container/) | library | Scans binary files (ZIP, PNG, JPEG) for DEFLATE streams and orchestrates the Zstd pipeline |
| [`util/`](util/) | `preflate_util.exe` | CLI tool for testing and benchmarking |
| [`dll/`](dll/) | `preflate_rs_0_8.dll` | C FFI wrapper for .NET interop |
| [`fuzz/`](fuzz/) | fuzz harnesses | libfuzzer targets for the core and container APIs |

---

## Getting Started

### Requirements

- [Rust 1.89 or above](https://www.rust-lang.org/tools/install)

### Build from Source

```shell
git clone https://github.com/microsoft/preflate-rs
cd preflate-rs
cargo build --all
cargo test --all
cargo build --release --all
```

### Using the CLI

The `preflate_util` binary lets you test the library against any file or directory of files:

```shell
preflate_util [OPTIONS] <PATH>

Options:
  --max-chain <N>    Hash chain depth limit (default: 4096)
  -c, --level <N>    Zstd compression level 0–14 (default: 9)
  --loglevel <L>     Log verbosity (default: Error)
  --verify <bool>    Round-trip verify after compression (default: true)
  --baseline <bool>  Also measure raw Zstd-only size for comparison (default: false)
```

### Library Usage

For direct use of the core DEFLATE analysis API, see the [`preflate` crate](preflate/). For processing full binary files containing embedded DEFLATE streams (ZIP, PNG, JPEG), see the [`container` crate](container/).

---

## Design Notes

- **No unsafe code** — `#![forbid(unsafe_code)]` is enforced in every crate.
- **Chunked processing** — memory use is bounded regardless of input size.
- **Format versioning** — the DLL name encodes the format version (`preflate_rs_0_8.dll`) so old decoders can coexist with new ones during upgrades. Corrections blobs and containers also start with a version byte, so data from an incompatible version is rejected.
- **CABAC coding** — the corrections codec is shared with the [Lepton](https://github.com/microsoft/lepton_jpeg_rust) JPEG re-compression library.
- Parameters are serialized via [`bitcode`](https://crates.io/crates/bitcode); corrections via CABAC.

---

## Contributing

* [Submit bugs and feature requests](https://github.com/microsoft/preflate-rs/issues)
* [Review or submit pull requests](https://github.com/microsoft/preflate-rs/pulls)
* The library uses only **stable Rust features**.

---

## Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). See the [FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with questions.

## License

Copyright (c) Microsoft Corporation. All rights reserved.

Licensed under the [Apache 2.0](LICENSE) license.
