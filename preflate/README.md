# preflate

Core DEFLATE analysis and reconstruction engine for the preflate-rs workspace.

This crate takes an existing DEFLATE-compressed bitstream and splits it into two parts:
- The **uncompressed plaintext**
- A compact **corrections blob** that captures everything needed to recreate the original bitstream exactly

Given those two parts, the original DEFLATE stream can be reconstructed bit-for-bit. This enables re-compressing the plaintext with a modern algorithm (Zstd, Brotli, LZMA) while preserving binary-exact fidelity.

[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

## How It Works

### Analysis pipeline

For explicit-parameter experiments without editing Rust tests, use the
diagnostic-only JSON-parameter replay API and the utility's
[JSON replay command](../util/README.md#json-replay). It supports synthetic blocks
or original DEFLATE, preserves full chunk context when reporting a block range,
and optionally measures complete reconstruction bytes with exact verification.

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

Estimation replay does not spend its informative sample budget on length-258,
distance-one references. It still predicts and accepts every token, retaining
mismatches, hash state, frequencies and block/flush transitions. Shorter matches
and literals remain informative. Replays stop at 32,768 total tokens or upon
reaching 8 MiB plaintext, checked before each token. Encoding uses the selected
profile once; there is no alternative-model retry.

### Reconstruction pipeline

Feed the plaintext and corrections back into the predictor. It replays every compression decision, applying corrections where recorded, and writes the resulting tokens back to a DEFLATE bitstream using the original Huffman trees.

Estimation uses the same state directly through bounded replay in
`estimator/prediction_scoring.rs`; candidate scoring and stopping remain outside
the state. The lifecycle is predict, resolve corrections, then accept the actual
token. Block setup/finish retain one private active context. The state reports
safe normalization bounds; typed reconstruction settings select canonical wire values.
See [AGENTS.md](AGENTS.md) for contributor constraints.
Shared option enums live in `parameters.rs`; executable settings live in
`reconstruction_parameters.rs`. Candidates use those authoritative typed settings;
compressor profiles, supplementary estimation metadata and family models live
under `estimator/`. There is no parallel flat executable parameter record.
Before candidate construction, `InitialEstimate` combines selected hash/depth
evidence, borrowed stream observations, and inferred block/window/insertion settings.
Family models consume it to construct complete executable candidates, rather than
using provisional reconstruction settings as estimation evidence. Scoring and
refinement continue to operate directly on `ReconstructionParameters`.
The generic model constructs a complete candidate rather than applying defaults
to provisional parameters. MiniZ shares typed candidate construction between
initial recognition and later refinements.
`CompressorProfile` is a payload-free model enum. `EstimationResult` stores that
typed hypothesis directly alongside the reconstruction settings; neither the
enum nor family-specific wrappers own a second configuration.
Runtime prediction retains only typed settings, not an estimator profile.
Deterministic search, lookahead, and dictionary insertion live in the peer
`compressors/` module and consume narrowed runtime settings. Prediction and
reconstruction import them directly, never through the estimator.
Family recognition and candidate proposals remain in `estimator/models/`;
`estimator/compressor_profile.rs` owns model identity, selection, and candidate
ordering. Model and selection modules are private; encoding
and feature-gated parameter diagnostics are exposed at the estimator boundary.
Additional policy access for unit tests lives in `estimator::test_support`, not
the production exports. Estimator parameter types are not publicly exported.
Chunk results retain a private report. `reconstruction_parameters_json()` returns
only executable settings; `estimator_parameters_json()` wraps those settings as
`{"reconstruction": {...}, "model": "..."}`, with the selected
model hypothesis as supplementary metadata, never proven producer identity.
Both serialize only when requested and return `None` for continuation
chunks. `hash_algorithm()`
provides the first chunk's hash statistic without JSON. Traces expose their latest
report through the same two JSON methods. Reporting is available without the optional
`diagnostics` feature so basic container diagnostics keep working; serialization
does not run during ordinary compression. Older JSON and SQL parameter reports must
be regenerated; no compatibility adapter is provided.

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
| `PreflateStreamChunkResult` | Output of analysis: corrections blob, compressed size, private parameter report accessible as JSON |
| `HashAlgorithm` | Hash implementations; hash identity alone does not prove producer identity |
| `PlainText` | Decompressed data with sliding-window dictionary support |
| `PreflateError` | Rich error type with detailed exit codes |

## Encoding Format

Parameters are serialized with [`bitcode`](https://crates.io/crates/bitcode). Corrections use CABAC (Context Adaptive Binary Arithmetic Coding), the same codec used in [Lepton JPEG](https://github.com/microsoft/lepton_jpeg_rust) compression. The format is chunked so memory use is bounded regardless of input size.

The first chunk's corrections blob starts with `0x84`, followed by nested,
behavior-specific reconstruction parameters and CABAC corrections. The JSON
reconstruction interface uses the same authoritative typed configuration. Only the current `0x84` tag is
accepted; `0x81`, `0x82`, `0x83`, unversioned blobs and unknown tags are rejected with
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

Insertion observations constrain the minimum required dictionary updates, not
the exact compressor cutoff. Incomplete first chunks default ambiguous
three-/four-byte fast insertion to `AddFirst(4)` when a nonfinal interior of a
three-byte match was referenced and no endpoint in a match longer than four bytes
requires first-and-last insertion. Complete streams retain their observed policy:
all reference requirements are already known. Stronger boundary evidence and
other observed cutoffs are preserved.

The optional `diagnostics` feature exposes bounded token-mismatch traces and
`estimate_first_chunk_estimator_json`. The latter returns the two-section estimator
report after parsing and estimating only the first
chunk, including any bounded candidate scoring; it does not encode corrections
or verify reconstruction. Tiny complete streams may normalize parameters during
encoding, so raw estimates can differ from the parameters reported after analysis.

`diagnostics::replay_deflate(compressed, reconstruction_parameters_json, options)`
accepts only executable reconstruction JSON. Runtime configuration validation
rejects invalid settings, old flat objects and full estimator report wrappers.
To replay an estimator report, explicitly extract its `reconstruction` object.
No model estimation, conversion from estimator settings or retry occurs.
Replay results remain serializable reports, with private requested/effective
parameter fields named `reconstruction_parameters` and
`effective_reconstruction_parameters`.

For an offline insertion-origin audit, set `PREFLATE_REFERENCE` to a local raw
DEFLATE file and run
`cargo test --release -p preflate-rs diagnose_dictionary_insertion_origins -- --ignored --nocapture`.
The audit bounds compressed input to 8 MiB and plaintext to 128 MiB, prints at
most 32 omitted-source examples without plaintext, and compares first-chunk
and complete-stream insertion evidence. For inferred three-byte cutoffs, it
also verifies diagnostic replays with the existing four-byte cutoff policies.
These replays do not change production selection or establish production savings.
For a selected dual-hash Libdeflate model, it also reports at most 16 unreachable
three-byte references and compares existing zlib parser tuples offline, retaining
the independently inferred window. Exact reconstruction of a diagnostic
alternative does not identify the original compressor.

## Constraints

- **No unsafe code** — `#![forbid(unsafe_code)]`
- Minimum Rust version: **1.89**, Edition **2024**
