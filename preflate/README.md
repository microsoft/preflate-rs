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
3. **Predict** (`prediction_state.rs`) — Shared codec-free matching state predicts
   tokens and accepts the resolved actual tokens. `token_predictor.rs` handles
   correction recovery/coding, tree frequencies, traces, and parameter reporting.
4. **Encode** (`statistical_codec.rs`, `cabac_codec.rs`) — Record each position where the actual token differs from the prediction, using CABAC arithmetic coding.

Estimation first collects candidate-independent evidence in `PreflateStreamInfo`:
token and block statistics, whether the chunk ends with the final DEFLATE block,
ordinary versus flush/final block boundaries, bounded
short-match signatures, and references into earlier match interiors. The existing
statistics and insertion traversals remain separate; stored/Huffman-only fast
paths skip insertion analysis. Insertion policies and other parameter hypotheses
are derived from those observations, not stored as facts. Hash-chain depths,
parser contradictions, and prediction scores remain candidate-dependent.

### Reconstruction pipeline

Feed the plaintext and corrections back into the predictor. It replays every compression decision, applying corrections where recorded, and writes the resulting tokens back to a DEFLATE bitstream using the original Huffman trees.

Estimation uses the same state directly through bounded replay in
`estimator/prediction_scoring.rs`; candidate scoring and stopping remain outside
the state. The lifecycle is predict, resolve corrections, then accept the actual
token. Block setup/finish retain one private active context. The state reports
safe normalization bounds; the wrapper selects profile-specific canonical values.
See [AGENTS.md](AGENTS.md) for contributor constraints.
Shared parameter types live in `parameters.rs`; runtime modules import them
directly rather than depending on estimator modules. Family-specific behavior
remains in `models/`, and public parameter re-exports are unchanged.

## API

### Whole-stream (simple)

```rust
use preflate_rs::{preflate_whole_deflate_stream, recreate_whole_deflate_stream, PreflateConfig};

let config = PreflateConfig::default();

// Analysis: DEFLATE → plaintext + corrections
let (result, plain_text) = preflate_whole_deflate_stream(&compressed_data, &config)?;

// Reconstruction: plaintext + corrections → original DEFLATE
let recreated = recreate_whole_deflate_stream(plain_text.text(), &result.corrections)?;

assert_eq!(compressed_data, recreated);
```

The analysis helper processes one plaintext-limited chunk, not an arbitrary-size
stream. Use the streaming API when the stream can exceed `plain_text_limit`;
`compressed_size` reports how much of the supplied compressed input was consumed.

### Streaming (chunked)

For large streams where memory is a concern, use the streaming processors:

```rust
use std::io::Cursor;
use preflate_rs::{PreflateStreamProcessor, RecreateStreamProcessor};

let mut processor = PreflateStreamProcessor::new(&config);
let mut recreator = RecreateStreamProcessor::new();
let mut remaining = compressed_data.as_slice();
let mut recreated = Vec::new();
while !processor.is_done() {
    let chunk = processor.decompress(remaining)?;
    remaining = &remaining[chunk.compressed_size..];
    let (output, _blocks) = recreator.recompress(
        &mut Cursor::new(processor.plain_text().text()),
        &chunk.corrections,
    )?;
    recreated.extend_from_slice(&output);
    processor.shrink_to_dictionary();
}
assert_eq!(compressed_data, recreated);
```

Retain both processors between chunks. The first chunk carries serialized
parameters; continuation chunks carry only corrections. Shrink the analysis
plaintext only after consuming it; reconstruction retains its own dictionary.

## Configuration

```rust
pub struct PreflateConfig {
    /// Maximum hash chain traversal depth. Higher values improve prediction
    /// accuracy for streams compressed with high chain limits, at the cost
    /// of analysis time. Default: 4096.
    pub max_chain_length: u32,

    /// Maximum plaintext held in memory at once. Default: 128 MB.
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
| Chromium zlib | Conservative 15-bit non-CRC hash recognition |
| zlib-ng | Distinct hash variant |
| libdeflate | 4-byte hash tables |
| miniz / miniz_oxide | Fastest-mode hash function |
| Windows zlib | Built-in PNG/ZIP codec fingerprint |

Unknown compressors still round-trip correctly with higher corrections overhead.

## Key Types

| Type | Description |
|---|---|
| `PreflateStreamChunkResult` | Output of analysis: corrections blob, compressed size, estimated parameters |
| `TokenPredictorParameters` | Compressor fingerprint: hash algorithm, nice_length, max_chain, window_bits, add policy |
| `HashAlgorithm` | Hash implementations; hash identity alone does not prove producer identity |
| `PlainText` | Decompressed data with sliding-window dictionary support |
| `PreflateError` | Rich error type with detailed exit codes |

## Encoding Format

Parameters are serialized with [`bitcode`](https://crates.io/crates/bitcode). Corrections use CABAC (Context Adaptive Binary Arithmetic Coding), the same codec used in [Lepton JPEG](https://github.com/microsoft/lepton_jpeg_rust) compression. The format is chunked so memory use is bounded regardless of input size.

The first chunk's corrections blob starts with `0x84`, followed by nested,
behavior-specific reconstruction parameters and CABAC corrections. The public
parameter and diagnostic interfaces remain flat. The decoder also accepts the
existing `0x83` flat-parameter format through its legacy prediction mode; `0x81`,
`0x82`, unversioned 0.7 blobs and unknown tags are rejected with
`ExitCode::InvalidCompressedWrapper`.
The developing 0.8 format intentionally permits breaking changes under its
current tag; it is not a stable compatibility promise.

The following differences from the predicted stream are encoded:

- Block type (uncompressed, static Huffman, dynamic Huffman)
- Token count per block
- Dynamic Huffman tree encoding
- Literal vs. length/distance choice
- Incorrect distance or length (encoded as hop count back through the hash chain)

## Diagnostics

The optional `diagnostics` feature exposes bounded token-mismatch traces and
`estimate_first_chunk_parameters`. The latter parses and estimates only the first
chunk, including any bounded candidate scoring; it does not encode corrections
or verify reconstruction. Tiny complete streams may normalize parameters during
encoding, so raw estimates can differ from the parameters reported after analysis.

## Constraints

- **No unsafe code** — `#![forbid(unsafe_code)]`
- Minimum Rust version: **1.89**, Edition **2024**
