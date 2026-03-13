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
| [libdeflate](https://github.com/ebiggers/libdeflate) | 4-byte hash table variant detected |
| [miniz / miniz_oxide](https://github.com/richgel999/miniz) | Fastest mode uses distinct hash function |
| Windows zlib | Built-in PNG codec and shell ZIP compression |

Unrecognized compressors still round-trip correctly — the corrections overhead is simply higher.

---

## Reconstruction Overhead

The table below shows overhead (corrections size as a percentage of uncompressed data) for each supported compressor at each compression level. To benefit from re-compression, your target algorithm needs to beat the original by at least this margin.

| Compressor         | 0      | 1      | 2      | 3      | 4      | 5      | 6      | 7      | 8      | 9     |
|--------------------|--------|--------|--------|--------|--------|--------|--------|--------|--------|-------|
| **zlib**           | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.08%  | 0.03%  | 0.01%  |
| **zlib-ng**        | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.97%  | 1.07%  | 0.90%  | 0.01%  | 0.01%  | N/A    |
| **libdeflate**     | 0.01%  | 0.25%  | 1.04%  | 0.91%  | 1.51%  | 1.04%  | 0.96%  | 0.87%  | 1.04%  | 1.03%  |
| **miniz_oxide**    | 0.01%  | 0.06%  | 2.70%  | 1.78%  | 0.53%  | 0.30%  | 0.09%  | 0.06%  | 0.08%  | 0.07%  |

---

## Workspace Layout

| Crate | Output | Description |
|---|---|---|
| [`preflate/`](preflate/) | library | Core DEFLATE analysis and reconstruction engine |
| [`container/`](container/) | library | Scans binary files (ZIP, PNG, JPEG) for DEFLATE streams and orchestrates the Zstd pipeline |
| [`util/`](util/) | `preflate_util.exe` | CLI tool for testing and benchmarking |
| [`dll/`](dll/) | `preflate_rs_0_7.dll` | C FFI wrapper for .NET interop |
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
- **Format versioning** — the DLL name encodes the format version (`preflate_rs_0_7.dll`) so old decoders can coexist with new ones during upgrades.
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
