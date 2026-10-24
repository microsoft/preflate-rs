# preflate

Core DEFLATE analysis and reconstruction engine for the preflate-rs workspace.

This crate takes an existing DEFLATE-compressed bitstream and splits it into two parts:
- The **uncompressed plaintext**
- A compact **corrections blob** that captures everything needed to recreate the original bitstream exactly

Given those two parts, the original DEFLATE stream can be reconstructed bit-for-bit. This enables re-compressing the plaintext with a modern algorithm (Zstd, Brotli, LZMA) while preserving binary-exact fidelity.

[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

## How It Works

### Analysis pipeline

1. **Parse** (`deflate/`) — Decode the DEFLATE bitstream into a token sequence: literals and length/distance back-references.
2. **Estimate** (`estimator/`) — Analyze the token sequence to fingerprint the original compressor. Identifies hash algorithm, chain depth, nice-length cutoff, window size, and add policy.
3. **Predict** (`token_predictor.rs`) — Re-run compression using the estimated parameters, generating a predicted token sequence.
4. **Encode** (`statistical_codec.rs`, `cabac_codec.rs`) — Record each position where the actual token differs from the prediction, using CABAC arithmetic coding.

Huffman tree prediction is handled separately by [`tree_predictor.rs`](src/tree_predictor.rs).

### Reconstruction pipeline

Feed the plaintext and corrections back into the predictor. It replays every compression decision, applying corrections where recorded, and writes the resulting tokens back to a DEFLATE bitstream using the original Huffman trees.

## API

### Whole-stream (simple)

```rust
use preflate_rs::{preflate_whole_deflate_stream, recreate_whole_deflate_stream, PreflateConfig};

let config = PreflateConfig::default();

// Analysis: DEFLATE → plaintext + corrections
let (result, plain_text) = preflate_whole_deflate_stream(&compressed_data, &config)?;

// Reconstruction: plaintext + corrections → original DEFLATE
let recreated = recreate_whole_deflate_stream(plain_text.text(), &result.corrections)?;

assert_eq!(&compressed_data[..result.compressed_size], recreated.as_slice());
```

This helper performs one analysis call. Check `result.compressed_size`: the
plaintext limit or block boundaries can leave an unconsumed suffix. Use the
streaming processors to handle subsequent chunks.

### Streaming (chunked)

For large streams where memory is a concern, use the streaming processors:

```rust
use preflate_rs::{PreflateStreamProcessor, RecreateStreamProcessor, PreflateConfig};
use std::io::Cursor;

let config = PreflateConfig::default();
// Keep both processors alive across chunks; one successful chunk is shown.
let mut processor = PreflateStreamProcessor::new(&config);
let mut recreator = RecreateStreamProcessor::new();

// Analysis
let chunk_result = processor.decompress(&compressed_chunk)?;
let plain_text = processor.plain_text().text().to_vec();
processor.shrink_to_dictionary();

// Reconstruction
let (deflate_output, _blocks) = recreator.recompress(
    &mut Cursor::new(plain_text),
    &chunk_result.corrections,
)?;
```

Advance the compressed input by `chunk_result.compressed_size`, not by the size
of the supplied slice. Retain any unconsumed suffix; a `ShortRead` means more
compressed input is needed. Copy or consume the current plaintext before
shrinking it to dictionary history. Feed each plaintext/corrections pair to
the same recreator in order, and use `processor.is_done()` to detect completion.

## Configuration

```rust
pub struct PreflateConfig {
    /// Maximum hash chain traversal depth. Higher values improve prediction
    /// accuracy for streams compressed with high chain limits, at the cost
    /// of analysis time. Default: 4096.
    pub max_chain_length: u32,

    /// Plaintext processing limit per chunk. Default: 128 MiB.
    pub plain_text_limit: usize,

    /// Verify round-trip correctness after analysis. Default: true.
    pub verify_compression: bool,
}
```

## Supported Compressors

The estimator detects the following DEFLATE implementations by their token patterns and hash algorithms:

| Compressor | Detection method |
|---|---|
| zlib | Default hash, standard chain behavior |
| zlib-ng | Distinct hash variant |
| libdeflate | 4-byte hash tables |
| miniz / miniz_oxide | Fastest-mode hash function |
| Windows zlib | Built-in PNG/ZIP codec fingerprint |

Unknown compressors can require more corrections or fail analysis when the
predictor cannot model them. Successful analysis is verified by default;
disabling verification requires an equivalent caller-side round-trip check.

## Key Types

| Type | Description |
|---|---|
| `PreflateStreamChunkResult` | Output of analysis: corrections blob, compressed size, estimated parameters |
| `TokenPredictorParameters` | Compressor fingerprint: hash algorithm, nice_length, max_chain, window_bits, add policy |
| `HashAlgorithm` | Enum of detected compressor families |
| `PlainText` | Decompressed data with sliding-window dictionary support |
| `PreflateError` | Rich error type with detailed exit codes |

## Encoding Format

Parameters are serialized with [`bitcode`](https://crates.io/crates/bitcode).
Corrections use the local [`cabac`](../cabac/README.md) crate's VP8 arithmetic
coder, also used in [Lepton JPEG](https://github.com/microsoft/lepton_jpeg_rust)
compression. The format supports processing plaintext in chunks.

The following differences from the predicted stream are encoded:

- Block type (uncompressed, static Huffman, dynamic Huffman)
- Token count per block
- Dynamic Huffman tree encoding
- Literal vs. length/distance choice
- Incorrect distance or length (encoded as hop count back through the hash chain)

## Source map

- [`lib.rs`](src/lib.rs) defines the public re-exports and configuration.
- [`stream_processor.rs`](src/stream_processor.rs) coordinates chunked analysis and reconstruction.
- [`deflate/`](src/deflate/) contains token parsing, Huffman coding, and bitstream writing.
- [`estimator/`](src/estimator/) estimates compressor parameters, matching policy, and block strategy.
- [`hash_chain.rs`](src/hash_chain.rs), [`hash_chain_holder.rs`](src/hash_chain_holder.rs),
  and [`hash_algorithm.rs`](src/hash_algorithm.rs) implement predictor dictionaries.
- [`preflate_input.rs`](src/preflate_input.rs) manages plaintext and retained history.
- [`preflate_error.rs`](src/preflate_error.rs) defines exit codes and error context.

## Constraints

- **No unsafe code** — `#![forbid(unsafe_code)]`
- Toolchain requirements and contributor commands are in the [project README](../README.md#requirements).
