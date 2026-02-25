# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Important:** This file (and all sub-project `CLAUDE.md` files) are checked into the
> repository. Only include information that is valid for **any** developer or machine:
> project conventions, architecture, commands, constraints. **Do not** add machine-specific
> paths, personal tool preferences, local environment settings, or anything that would
> not apply to every contributor.

## Commands

```bash
# Build
cargo build --all
cargo build --release --all

# Test
cargo test --all
cargo test <test_name>          # Run a single test by name
cargo test -- --nocapture       # Show test output

# Lint and format
cargo fmt --check --all
cargo clippy
```

The CI runs on `windows-latest` and builds for multiple targets: `wasm32-wasip1`, `aarch64-unknown-linux-musl`, `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`.

The release build uses Spectre mitigations (`/Qspectre /sdl`) and produces `preflate_rs_0_7.dll` and `preflate_util.exe`.

## Architecture

**preflate-rs** analyzes DEFLATE-compressed streams, extracts the uncompressed data plus a compact set of reconstruction parameters, and later recreates the exact original DEFLATE bitstream. This enables re-compression with modern algorithms (Zstd, Brotli) while preserving binary-exact round-trip fidelity. The key insight is detecting which compressor (zlib, libdeflate, zlib-ng, miniz, Windows zlib) produced a stream and storing only the differences from what that compressor would predict.

### Workspace layout

| Crate | Output | Role |
|---|---|---|
| `preflate/` | library | Core DEFLATE analysis and reconstruction |
| `container/` | library | Scans binary files (ZIP, PNG, PDF) for DEFLATE streams |
| `util/` | `preflate_util.exe` | CLI for testing on files/directories |
| `dll/` | `preflate_rs_0_7.dll` | C FFI wrapper for .NET interop |
| `fuzz/` | fuzz harnesses | libfuzzer targets |
| `tests/` | integration tests | End-to-end round-trip tests using `samples/` |

### preflate crate (core)

The processing pipeline in `preflate/src/stream_processor.rs`:
1. **`deflate/`** — Reads a DEFLATE bitstream into tokens (literals and length/distance back-references) and writes tokens back to DEFLATE with custom Huffman trees.
2. **`estimator/`** — Estimates the compressor's parameters (`TokenPredictorParameters`): hash algorithm, `nice_length`, `max_chain`, window bits, add policy, matching type.
3. **`token_predictor.rs`** — Replays the compression using estimated parameters and hash chains to predict what tokens the original compressor would have produced.
4. **`tree_predictor.rs`** — Predicts Huffman tree structure.
5. **`statistical_codec.rs` / `cabac_codec.rs`** — Encodes the *differences* from prediction using CABAC (Context Adaptive Binary Arithmetic Coding, shared with Lepton JPEG).
6. **`stream_processor.rs`** — Public API: `PreflateStreamProcessor::decompress()` and `RecreateStreamProcessor::recreate()`.

Parameters are serialized via `bitcode`; corrections via CABAC. The format is chunked to bound memory use.

### container crate

- **`scan_deflate.rs`** — Scans raw bytes to locate DEFLATE stream boundaries, identifying stream type (raw deflate, zlib-wrapped, PNG IDAT, etc.).
- **`idat_parse.rs`** — Extracts and reassembles PNG IDAT chunks.
- **`pdf_parse.rs`** — Detects PDF compressed object streams.
- **`zstd_compression.rs`** — Pipelines preflate output through Zstd for final storage.
- **`container_processor.rs`** — Orchestrates scanning → preflate → Zstd (compress) and Zstd → recreate → reassembly (decompress).

The optional `webp` feature (enabled by default) allows PNG images to be stored as WEBP instead of losslessly.

### Code constraints

- **No unsafe code** — enforced via `#![forbid(unsafe_code)]` in each crate.
- Minimum Rust version: **1.85**, Edition **2024**.
- `.cargo/config.toml` sets Windows MSVC linker flags (`/DYNAMICBASE`, `/CETCOMPAT`, `/guard:cf`).
