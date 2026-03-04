# preflate (core library)

Core DEFLATE analysis and reconstruction. Analyzes a DEFLATE bitstream, extracts the
uncompressed plaintext plus a compact set of reconstruction parameters, and later recreates
the bit-exact original bitstream.

## Public API (`lib.rs`)

```rust
// Compress: analyze a DEFLATE stream and produce plaintext + correction data
PreflateStreamProcessor::new(config) -> Self
PreflateStreamProcessor::decompress(input: &[u8]) -> Result<PreflateStreamChunkResult>

// Recreate: given plaintext + correction data, reproduce the original DEFLATE stream
RecreateStreamProcessor::new() -> Self
RecreateStreamProcessor::recreate(chunk: PreflateStreamChunkResult) -> Result<Vec<u8>>

// One-shot helpers
preflate_whole_deflate_stream(input, config) -> Result<(Vec<u8>, Vec<u8>)>
recreate_whole_deflate_stream(plaintext, correction_data) -> Result<Vec<u8>>
```

`PreflateConfig` controls `max_chain_length`, `plain_text_limit`, and `verify_compression`.

## Processing Pipeline

```
DEFLATE bytes
    └─ deflate/deflate_reader.rs  → tokens (literals + back-refs)
    └─ estimator/                 → TokenPredictorParameters (hash algo, nice_len, max_chain…)
    └─ token_predictor.rs         → predicted tokens (replaying the original compressor)
    └─ tree_predictor.rs          → predicted Huffman trees
    └─ cabac_codec.rs             → encode *differences* from prediction → correction bytes
```

Reconstruction runs the same pipeline in reverse.

## Key Types

| Type | Where | Purpose |
|---|---|---|
| `PlainText` | `preflate_input.rs` | Wraps uncompressed data |
| `TokenPredictorParameters` | `token_predictor.rs` | Compressor fingerprint |
| `HashAlgorithm` | `hash_algorithm.rs` | Zlib / Miniz / Libdeflate / zlib-ng / … |
| `PreflateError` / `ExitCode` | `preflate_error.rs` | 29 error variants with context |
| `DeflateToken` | `deflate/deflate_token.rs` | Literal or length/distance match |

## Module Layout

```
src/
  lib.rs                      ← public API, PreflateConfig
  stream_processor.rs         ← PreflateStreamProcessor, RecreateStreamProcessor
  deflate/
    deflate_reader.rs         ← DEFLATE bitstream → tokens
    deflate_writer.rs         ← tokens → DEFLATE bitstream
    bit_reader.rs / bit_writer.rs
    huffman_calc.rs / huffman_encoding.rs
    deflate_token.rs / deflate_constants.rs
  estimator/
    preflate_parameter_estimator.rs  ← main estimator entry point
    complevel_estimator.rs
    depth_estimator.rs
    add_policy_estimator.rs
    preflate_parse_config.rs
    preflate_stream_info.rs
  token_predictor.rs
  tree_predictor.rs
  statistical_codec.rs
  cabac_codec.rs
  hash_algorithm.rs
  hash_chain.rs / hash_chain_holder.rs
  preflate_input.rs
  preflate_error.rs
  bit_helper.rs / utils.rs
```

## Constraints

- `#![forbid(unsafe_code)]` — strictly enforced.
- Serialization: parameters via `bitcode`; correction data via CABAC (`cabac` crate).
- The format is chunked to bound peak memory use.
- `#![deny(trivial_casts, non_ascii_idents)]` also set.
