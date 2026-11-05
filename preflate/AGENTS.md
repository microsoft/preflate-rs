# preflate (core library)

These instructions supplement the root [AGENTS.md](../AGENTS.md).

Core DEFLATE analysis and reconstruction. Analyzes a DEFLATE bitstream, extracts the
uncompressed plaintext plus a compact set of reconstruction parameters, and later recreates
the bit-exact original bitstream.

## Public API (`lib.rs`)

```rust
// Compress: analyze a DEFLATE stream and produce plaintext + correction data
PreflateStreamProcessor::new(config: &PreflateConfig) -> Self
PreflateStreamProcessor::decompress(input: &[u8]) -> Result<PreflateStreamChunkResult>

// Recreate: given plaintext + correction data, reproduce the original DEFLATE stream
RecreateStreamProcessor::new() -> Self
RecreateStreamProcessor::recompress(
    plain_text: &mut impl BufRead,
    corrections: &[u8],
) -> Result<(Vec<u8>, Vec<DeflateTokenBlock>)>

// One-shot helpers
preflate_whole_deflate_stream(input, config) -> Result<(PreflateStreamChunkResult, PlainText)>
recreate_whole_deflate_stream(plaintext, correction_data) -> Result<Vec<u8>>
```

`PreflateConfig` controls `max_chain_length`, `plain_text_limit`, and `verify_compression`.
Plaintext is accessed through the processor, not returned in each chunk result.
Retain the processors across chunks; pass each chunk's newly produced plaintext
and corrections to reconstruction.

## Processing Pipeline

```
DEFLATE bytes
    └─ deflate/deflate_reader.rs  → tokens (literals + back-refs)
    └─ estimator/                 → ReconstructionParameters + supplementary metadata
    └─ prediction_state.rs        → shared token prediction and actual-token acceptance
    └─ token_predictor.rs         → correction recovery/coding and parameter reporting
    └─ tree_predictor.rs          → predicted Huffman trees
    └─ cabac_codec.rs             → encode *differences* from prediction → correction bytes
```

Reconstruction uses the serialized parameters and the same prediction state,
applies corrections, and writes tokens with the recovered Huffman trees.
It does not rerun estimation.

## Key Types

| Type | Where | Purpose |
|---|---|---|
| `PlainText` | `preflate_input.rs` | Wraps uncompressed data |
| `ReconstructionParameters` | `reconstruction_parameters.rs` | Authoritative typed candidate, prediction and wire configuration |
| `HashAlgorithm` | `hash_algorithm.rs` | Diagnostic and estimator index/hash signature; not executable behavior |
| `PreflateError` / `ExitCode` | `preflate_error.rs` | Error codes with context |
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
    complevel_estimator.rs           ← candidate selection and evidence snapshots
    initial_estimate.rs              ← initial evidence and inferred inputs to family construction
    depth_estimator.rs               ← existing hash/depth observation walk
    evidence_policy.rs               ← family-specific observation restrictions
    compressor_profile.rs            ← model identity, candidate ordering, selection and provenance
    parser_estimator.rs              ← bounded evidence inference and matching policy
    prediction_scoring.rs            ← candidate scoring, work limits and refinement stopping
    prediction_encoding.rs           ← selected typed settings, encoding and finalized report
    test_support.rs                  ← test-only estimation and scoring access
    estimation_result.rs             ← canonical settings plus supplementary model metadata
    models/                          ← family evidence, defaults and candidate proposals
    add_policy_estimator.rs
    preflate_stream_info.rs
  token_predictor.rs
  compressors/                 ← deterministic family matching, lookahead and insertion rules
  configuration_access.rs      ← narrowed access to active typed settings, never a flat record
  configuration_fixtures.rs    ← test-only typed configuration fixtures
  prediction_state.rs         ← common codec-free state used directly by estimation and token prediction
  parameters.rs               ← shared compressor option enums
  reconstruction_parameters.rs ← typed behavior settings and serialized parameters
  reconstruction_validation.rs ← feature-gated strict canonical JSON replay validation
  block_predictor.rs          ← block strategy and tail predictions
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

- In estimator modules, use plain `pub` for shared items and keep local implementation
  helpers private. Keep implementation modules private; `estimator/mod.rs` exposes
  only encoding, internal report storage, feature-gated parameter
  diagnostics, and selected deterministic helpers through explicit `pub use`
  declarations.
  Estimator children import private sibling modules directly. Keep additional
  test access behind `cfg(test)` in `estimator::test_support`, not among production
  exports. The private root `estimator` module and explicit `lib.rs` re-exports
  control the external API. Do not add root exports unintentionally. Internal inherent methods
  on publicly re-exported types must retain restricted visibility; hiding their
  defining module does not hide public methods.
- Do not publicly export estimator parameter types or fields containing them.
  Chunk results retain private reports and serialize JSON only on request.
  Container compression uses the typed hash statistic, never diagnostic JSON.
  Replay JSON is validated alongside typed runtime reconstruction settings, not
  converted from estimator parameters. Keep executable reconstruction settings
  separate from the supplementary model hypothesis.
- Family recognition, evidence interpretation, and candidate proposals belong in
  `estimator/models/`. Deterministic matching, lookahead, and insertion rules
  belong in the peer `compressors/` module and must not import estimator internals.
  The profile coordinator owns candidate ordering, refinement slots, and
  inferred/fingerprinted/prefix-validated provenance. Hash identity alone is not
  compressor identity. Keep candidate ordering and existing observation/refinement
  bounds stable when relocating policy.
- Runtime callers import helpers directly from `compressors`, never through
  `estimator/mod.rs`. Use aliases to disambiguate family-specific helpers.
  Profiles, candidate evidence, and selection/scoring policy stay private to estimation.
- `InitialEstimate` combines selected `CandidateEvidence`, borrowed stream
  observations, and inferred block/window/insertion settings. Keep candidate
  evidence as observations, not a second executable configuration. Initial family
  recognition consumes this record and chooses complete parser/search settings
  before constructing `ReconstructionParameters`; do not use placeholder runtime
  settings as its input. Scoring and later refinements retain complete typed
  reconstruction candidates. Initial estimates are private, nonserialized, and
  never retained by prediction.
  Expose neutral source-history constraints to family builders rather than
  deriving one engine's behavior through another engine's configuration.
  Initial test fixtures supply observations and evidence directly; do not
  reverse-project runtime parameters into supposed observations.
- Block-size estimation retains all-block maxima as lower bounds and separately
  tracks nonterminal Huffman boundaries without intervening stored/flush blocks.
  Empty fixed blocks must not hide a subsequent flush marker; trailing data in
  final or partial chunks supplies no capacity-confidence evidence.
  A canonical ordinary-boundary token count consistent with the all-block maximum
  supports the memory-sized zlib hash only as a conservative equal-depth tie-break.
  It is not proof of buffer capacity or compressor identity; preserve stronger
  fingerprints and parser/search contradictions. Ambiguous canonical fast
  insertion may admit one adjacent memory-sized hash in the existing depth walk;
  do not broaden this into a sweep or add observation passes.
- Hash calculation (`compressors::zlib::memory_hash`) is separate from search policy.
  Family models propose hashes; `compressor_profile::candidate_hashes` owns stable ordering,
  deduplication, and the seven-state ceiling (six normally). Chromium evidence
  replaces the small alternate first, then the default alternate, never the memory-sized hash.
  For ambiguous three-byte fast insertion (AddFirst 4..6), append the adjacent
  larger memory hash if distinct. Keep supported capacities and existing ordering
  unchanged. The otherwise-empty generic lazy refinement slot may test that hash
  with the selected greedy tuple; retain the existing perfect-prefix acceptance,
  work limits, and already-perfect-prefix guard. Missing-match prediction evidence,
  not shallow chain rank alone, establishes the refinement.
- `estimator::compressor_profile::CompressorProfile` is a payload-free model hypothesis enum
  with a `Custom` fallback, not an owner of executable parameters.
  `EstimationResult` pairs it with authoritative `ReconstructionParameters`;
  metadata stores the typed enum, not a string or another parameter record.
  Family policies construct and refine settings directly without family-owned
  parameter wrappers. `ParameterEstimate` stores the shared result separately
  from `EstimateProvenance`; only inferred provenance carries parser context.
  Keep complete selected tuples and inferred/fingerprinted/prefix-validated
  provenance through parser resolution and bounded refinements. A family candidate is not proof of producer
  identity, and an inferred family must not gain fingerprint protection.
  `estimate_preflate_profile` retains this result inside the estimator; prediction
  receives the same authoritative `ReconstructionParameters`. Do not retain
  profiles in runtime state, serialize these family tags in reconstruction data, replace
  unknown combinations with a guessed family, or add family dispatch to matching.
- No observed three-byte references does not rule out a three-byte hash. The
  existing table-hash prefix-refinement slot admits the complete Windows lazy
  tuple for ambiguous full-insertion lazy streams with power-of-two token
  buffers, without another depth-walk hash state or trial slot. Do not carry a
  different hash's inferred chain rank into that coupled hypothesis; require
  the existing perfect-prefix acceptance before selecting it.
- If no coupled fallback applies and the generic lazy alternative duplicates the selected table-hash tuple,
  reuse that refinement slot for zlib's memory-sized hash when a full canonical
  token buffer and zlib-compatible distances support it. Keep the search tuple,
  candidate count, prefix bounds, and perfect-prefix acceptance unchanged; a
  perfect shorter prefix does not establish hash identity.
- The empty generic lazy refinement slot also admits zlib's complete filtered
  lazy-16/chain-128 tuple for compatible Libdeflate4Fast aliases with a full
  canonical token buffer and no observed references below six bytes. Keep
  this hypothesis family-owned, require the existing perfect longer prefix,
  and preserve already-perfect prefixes, shorter-reference cases, and
  recognized fast/chained libdeflate profiles.
- For ambiguous three-byte-reference streams with noncanonical partial insertion,
  the existing generic lazy slot can propose zlib's complete level-6 search,
  insertion, hash, and distance tuple. Do not retain fallback chain ranks or
  full-window flags in that coupled hypothesis. Preserve recognized fast
  insertion policies and already-perfect prefixes; require the existing
  zero-error prefix gate without adding candidates or observation passes.
- Table-hash fallbacks may reuse the generic insertion slot for a coupled fast
  zlib tuple when observed three-byte references exceed the lazy short-match
  cutoff. The generic lazy slot may test the complete memory-sized zlib
  lazy-16/nice-128/chain-128 tuple with a full canonical token buffer, including
  smaller windows. Keep position-zero and window-distance guards; narrow a
  full-window flag only for complete streams. Require the proposed hash to survive
  the existing depth walk with zlib-window evidence. Preserve perfect-prefix acceptance,
  candidate counts, work limits, and recognized profiles.
- Complete streams below 1024 compressed bytes may canonicalize only proven
  equivalent insertion thresholds and token-buffer capacities. Reuse existing
  reference/block observations; preserve token-count corrections and Windows
  buffer-edge behavior, and never grow the serialized parameter width.
- Lazy cutoff proofs must preserve pending-reference state, not just the current
  literal. Reuse existing fresh searches and the default chain's virtual literal
  insertion; unresolved proofs and block/reset boundaries retain their bounds.
- Generic greedy chain rank is a search-budget lower bound, not evidence for a
  small `nice_length`. Preserve its independent limit; recognized fast insertion
  policies select family-owned lengths. Keep lazy tuples and validated profiles coupled.
- Generic primary-only four-byte-hash lazy defaults may reuse an empty refinement
  slot for greedy parsing when references and a full canonical token buffer support
  it. Preserve hash, insertion, nice length and chain budget. Only this custom
  fallback may accept a non-perfect sample: require at least 75% fewer mismatches
  and 16 fewer errors, with identical sampled token counts. Keep perfect-prefix
  protection and existing perfect refinements' precedence. Restrict its prediction
  window only with complete-stream distance evidence; do not extend this acceptance
  policy to recognized compressor profiles or add encoding retries.
- Infer 32 KiB slide-boundary insertion only from references into earlier matches
  at that boundary. Without any interior-match insertion evidence, retain the
  generic first-only policy rather than inventing boundary insertions.
  Finalized complete streams ending at or before the first slide point may use
  the smaller, behaviorally equivalent boundary-policy encoding, without
  upgrading family identity; partial or longer streams cannot use that proof.
- Estimator replay excludes only length-258, distance-one references from its
  informative token/byte budget. Predict and accept them normally, retaining
  errors, hash insertions, frequencies and block/flush transitions. Preserve
  shorter-match and literal boundary evidence. Stop each replay at 32,768 total
  tokens or upon reaching 8 MiB plaintext, checked before each token.
  Keep existing candidate sets and acceptance gates; do not add an
  alternative-model encoding retry.
- Shared collectors and predictors execute the selected behavior and manage state.
  Shared runtime types belong in `parameters`, not estimator modules.
  Keep that module independent of estimator, model, prediction, and codec policy.
  Family-specific parameter projection belongs to `estimator/models`; runtime
  dictionary insertion and matching behavior belong to `compressors`.
  Estimation only observes and selects their settings.
  `prediction_state` owns matching, lazy lookahead, and block/flush
  transitions; scoring and correction coding share its predict/accept transitions.
  Candidate replay, error counting, and refinement stopping belong in
  `estimator::prediction_scoring`, not in the common state.
  General profile refinement orchestration and acceptance also live there;
  `estimator::compressor_profile::profile_alternatives` retains candidate
  construction and slot ordering.
  Keep state fields private; expose semantic transitions and recovery operations,
  not mutable hash/lookahead access. Tests inspecting internals belong with the state.
  Pair block setup with finishing through one internal active context. Known-token
  Huffman setup infers limit/reset decisions; decoded setup applies them. Retain
  framing decisions and pre-setup reset-tag presence in that context.
  Keep limit cleanup and stored/
  empty-block history in common finishing, not in the codec or estimator callers.
  Reject nested setup and unmatched finishing; clear the context only after
  successful finishing. Early scoring stops discard their unfinished state.
  Keep correction codecs and diagnostic traces in the `TokenPredictor` wrapper.
  Keep profile-specific reconstruction parameter canonicalization in that wrapper;
  the common state reports only the safe normalization bounds it observes.
  Keep family helpers statically called/inlined; do not duplicate generic traversal
  or add trait-object family dispatch inside probe loops to organize policy.
  Reconstruction must use the same helpers with finalized parameters, not
  encoder-only estimation evidence.

- `#![forbid(unsafe_code)]` — strictly enforced.
- Serialization: parameters via `bitcode`; correction data via CABAC (`src/cabac/`).
- Candidates, scoring, runtime prediction and serialization all use
  `ReconstructionParameters` directly. Do not reintroduce a parallel flat
  executable configuration or a conversion adapter.
  `reconstruction_parameters_json()` serializes only those settings;
  `estimator_parameters_json()` serializes `{"reconstruction": {...}, "model": "..."}`.
  Keep metadata genuinely supplementary, never duplicate active settings.
  Replay accepts only reconstruction JSON; reject estimator wrappers and old
  flat records. Regenerate JSON/SQL baselines rather than adding compatibility.
  Normalization operates directly on typed settings and shared bounds; it must
  finalize the exact settings used both for the wire and the report, without
  retaining estimator profiles in runtime state.
  Pass shared typed dictionary, search-budget, chain, and lookahead structs to
  helpers; do not pass estimator evidence into matching helpers.
  Select concrete hash/search implementations at holder construction rather
  than adding search-enum dispatch inside the matching loop.
  Only inactive settings are omitted;
  active overrides and correction bytes must survive selection and finalization unchanged.
  Canonicalize the behaviorally identical `Mixed` block strategy to `Dynamic`;
  retain `Static` and `Uncompressed` as distinct active choices.
  The outer behavior enum selects no dictionary, chain search, or MiniZ search.
  Chain behavior composes one common matching struct with a parser enum; nested
  matches bind shared settings and parser-specific options together. Do not copy
  the common matching fields into each parser payload or merge distinct parser
  algorithms merely because their settings have the same shape.
  Encode the active typed settings directly; the current development format and
  diagnostic JSON may change without compatibility adapters.
  Chain and MiniZ common structs pair search settings with engine-specific distance policies;
  dictionary storage shares only index, window, and insertion settings.
  The index selects a single chain with a pure hash function or the supported
  four-byte chain/three-byte singleton-head layout. Do not derive parser,
  input-tail, or window restrictions from hash identity at runtime.
  Chain distance selects disabled, RLE, or an explicit bounded window. Window
  bounds distinguish full, oldest-excluded, lookahead, and one-position-tighter
  lookahead limits. MiniZ distance selects disabled or enabled. Only window and
  enabled MiniZ policies carry source-history settings; RLE has no source-start flag.
  Search settings explicitly carry the normal-prediction input-tail rule.
  Estimator candidate construction supplies coupled defaults before scoring;
  JSON replay and reconstruction execute explicit settings unchanged.
  Keep the window size even for disabled prediction because hop-based correction
  recovery uses it.
  Precompute invariant distance ceilings for normal and expanded searches at
  holder construction. Pass prediction/recovery purpose explicitly, rather than
  infer it from the search budget, and preserve correction candidate ordering.
  History/reset clamps and MiniZ's available-input adjustment remain per lookup.
- The first chunk's corrections blob starts with `RECONSTRUCTION_DATA_VERSION`
  (`0x84`, in `stream_processor.rs`); only this current tag is accepted.
  Older tags, including the flat-parameter `0x83` format, and untagged blobs
  are rejected without a compatibility decoding mode.
  Follow the current breaking-0.8 format policy in [AGENTS.md](../AGENTS.md);
  do not add versioning or compatibility layers unless requested.
- The format is chunked to bound peak memory use.
- Block prediction recognizes bounded empty terminal layouts, including
  fixed/stored/fixed. Tail types, zero token counts, and final/chunk-end bits
  must agree between encoding and reconstruction; nonempty or incomplete tails
  retain ordinary correction coding.
- `#![forbid(trivial_casts)]`, `#![forbid(trivial_numeric_casts)]`, and
  `#![forbid(non_ascii_idents)]` also set.
