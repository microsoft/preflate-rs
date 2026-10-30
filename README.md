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
| [Chromium zlib](https://chromium.googlesource.com/chromium/src/+/main/third_party/zlib/) | Conservative recognition of the 15-bit non-CRC hash; native synthetic fixtures cover levels 0-9 |
| [zlib-ng](https://github.com/zlib-ng/zlib-ng) | All levels except level 9 |
| [libdeflate](https://github.com/ebiggers/libdeflate) | 15-bit fastest buckets, adaptive greedy/lazy minimum lengths, distance-aware lazy and lazy2 profiles |
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
budgets select implementation-specific profiles; ambiguous cases use bounded
prediction comparisons. Miniz matching reproduces three-node probe groups, reduced lazy
budgets, and its window exclusions. Libdeflate lazy matching compares length and
distance cost, with bounded one- or two-position lookahead. Reconstruction uses the
serialized profile rather than repeating the fingerprint.

Libdeflate's fastest fingerprint shares the existing 16-bit hash calculations and
depth table, with at most 256 references checking the merged 15-bit, two-entry
buckets. The legacy 16-bit candidate remains available if that fingerprint fails.
Greedy and lazy levels inspect at most the first 4096 bytes of each block to reproduce the
minimum match length, stopping as soon as 80 distinct bytes establish length three.
Lazy profiles recalculate it from the block's existing emitted-literal frequencies,
starting at 10,000 plaintext bytes with progressively spaced updates. Deferred
lookahead matches retain their original search decision. Encoding, reconstruction,
and bounded scoring apply the same rules without another plaintext pass or histogram.
These are bounded observations, not additional full-stream passes or trial encodes.

When no three-byte references occur, the 16-bit fallback hash also supplies
libdeflate's primary-chain evidence: the primary hashes are identical, so no
extra hash table or traversal is required. The chained model allows for its
secondary slot and uses native window and short-match limits. This inference
retains the fastest fingerprint and requires a block reaching the 300,000-byte
soft limit without exceeding the 304,999-byte upper bound. Smaller ambiguous
streams retain their existing selection; compatible hash evidence is not proof
of producer identity.
An insertion cutoff that never excludes an observed match is equivalent to full
insertion for that history and can be normalized for the chained profile.
Alternative zlib refinements retain their own inferred window and distance limits,
not the libdeflate profile's limits.

Ambiguous PDF-style streams also retain zlib hash candidates when no three-byte
matches are observed: filtered zlib commonly emits only matches of length six or
more. A partial-insertion threshold equal to the longest observed match does not
prove greedy parsing. The established filtered-zlib refinement first compares up
to 1024 tokens starting within the first 256 KiB against surviving zlib profiles.
Additional ambiguity signals are gathered inside the existing hash-depth walk,
without replaying tokens or adding hash candidates. At most 256 literal/reference
pairs per stream probe each candidate's existing hash head, comparing at most
129 bytes. Only a mismatch proving that the current match is shorter than the
following reference supplies lazy-parser evidence; four such observations can
correct an ambiguous greedy classification when at least one current match is
six bytes or longer. Evidence consisting only of shorter matches is ambiguous
with filtered greedy parsing and does not change the matching mode.
Three-byte matches beyond the inferred short-match distance limit are excluded:
a greedy parser rejects those
too, so they are not evidence of lazy matching. Probes also respect the inferred
window instead of treating all streams as having 32 KiB of usable history. Only
the matching mode changes: search budgets, nice lengths, insertion policies, and working
filtered-zlib choices are preserved. Libdeflate's adaptive greedy minimum is
accounted for when collecting these observations.

Parser observations are separate from policy selection: evidence resolves to
unresolved, greedy, or lazy with a deferred-match length bound. An insertion cutoff
that covers every observed match leaves insertion unresolved rather than proving
greedy parsing. Policy selection uses these constraints without changing search
budgets.

Pass-zero estimation keeps stream facts, candidate evidence, and compressor
profiles separate. The existing depth walk produces immutable snapshots of the
selected hash's required search depth, distance policy, and parser inference;
surviving zlib candidates remain available to the bounded prefix refinement.
The profile coordinator delegates coupled matching, nice-length, window, and search
settings to family policy modules. Its result explicitly distinguishes inferred defaults, compressor
fingerprints, and accepted prefix-prediction refinements. The evidence-only parser
resolver cannot overwrite either protected choice, even if the hash is unchanged.
Prefix validation measures token fit over its bounded sample, not full-stream
optimality. The existing traversal count, candidate set, refinement order, and
confidence thresholds are preserved.

Compressor policies and library-specific runtime behavior live in `preflate/src/models/`, with modules for
zlib, zlib-ng, libdeflate, miniz, Windows DEFLATE, and the generic fallback.
The family modules own candidate signatures, recognition preferences, evidence
restrictions, coupled profile settings, and family-specific refinements. They also
own lazy-match decisions, library-specific search restrictions, adaptive match
minimums, and insertion-boundary rules. Zlib's
shipped parser tables live with its policy; their previous public paths remain
re-exports. The generic fallback borrows those tables without asserting zlib
identity. Windows and zlib-ng currently register their signatures and retain
generic inference where no stronger fingerprint exists.

Collectors, hash-chain traversal, and predictor state management remain shared
mechanics; they do not independently select a compressor family. Family helpers
are statically called/inlined, not dispatched through a new trait. Parsing helpers
return a token decision and any deferred-reference/literal state; the shared predictor
applies that decision identically during prediction and reconstruction. Miniz's
specialized grouped-probe loop lives with its family and reuses shared comparison
helpers. All runtime rules depend only on finalized parameters and current input,
not encoder-only estimation evidence. Policy relocation
adds no prediction passes, candidate sweeps, serialized family tag, or changes to
normalization. Recognition tests live alongside the corresponding family policies;
cross-family ambiguity and protected-profile tests remain at the coordinator.
For an offline refactor comparison, `compare_model_family_snapshots` captures or
compares exact parameters and complete correction records for local `.deflate`
fixtures, reconstructing every supported stream. Set `PREFLATE_MODEL_SNAPSHOTS` to
an existing separate directory; set `PREFLATE_CAPTURE_MODEL_BASELINE` only when
capturing new snapshots, and always run this diagnostic in release mode.

Exact observations remain in estimation rather than reconstruction parameters.
The lazy parser variant carries its lookahead limit, filtered-match setting,
and behavior. Zlib behavior stores the good-match threshold, quarters the
lookahead budget after a good match, and reuses a deferred reference. The other
behavior keeps the full budget and recomputes after emitting a literal.
Filtering is independent of that choice: a zlib hash with lazy matching and an
observed minimum reference length of at least six enables it. Compatibility and
the precise minimum remain search context until parser resolution; protected
fingerprints and prefix-validated choices retain their selected behavior.
Prefix trials project the same evidence for each candidate before scoring.
Reconstruction and scanner parameter reports carry lazy settings inside
`matching_type`, not global `zlib_compatible`, `use_filtered_matching`, or
observed `min_len` fields. Exact chain budgets and insertion cutoffs remain
unchanged. Tiny complete streams can canonicalize reconstruction distance limits
as described below.

For complete streams smaller than 1024 compressed bytes, zlib-shaped greedy/lazy
models may canonicalize their reconstruction window to 32 KiB. The encoder
collects an admissible upper window bound from candidates already rejected by
the normal prediction searches, including lazy lookahead and later chain hops.
It preserves history/position-zero exclusions and makes no additional probes or
prediction passes. The serialized window changes only if the standard window
preserves those exclusions. Incomplete first chunks are excluded: their first reconstruction
parameters must remain valid for later chunks. Other model families and
full-window search policies retain their existing windows.

The same complete-tiny-stream gate permits short-match cutoff canonicalization
for all model families. During existing prediction, accepted three-byte
candidates raise an inclusive lower bound and rejected candidates lower an
inclusive upper bound. Only cutoffs inside this decision-preserving interval
are eligible: zero, common cutoffs (4096, 8192, 32768), then binary range endpoints,
with the original retained if none fits. A zero cutoff is not blindly replaced,
and compressor identity is not inferred from a hash signature. Selection respects
the current singleton-u32 encoding width, so it cannot grow the parameter field;
it requires no trial encoding. Window and cutoff normalization preserve the
same prediction path and CABAC payload. Partial initial chunks and streams at
least 1024 compressed bytes retain both original settings.

Large zlib-style streams can separately select short-match suppression from
contradictory token evidence. The existing depth walk inspects at most 256
three-literal runs using existing hash heads, stopping sampling at stored blocks
that may indicate a dictionary flush. At least 16 usable three-byte head matches
must have been rejected, and three-byte references must account for at most one
in 512 of at least 4096 references. Evidence stays associated with its hash through
prefix refinement, and only the finalized full-insertion zlib-style profile can
select a zero cutoff. Genuine short references remain recoverable through
corrections. Unlike tiny-stream canonicalization, this deliberately changes
predictions to reduce correction cost; it adds no pass, trial encoding, hash table,
or serialized parameter.

Run the ignored `profile_tiny_parameter_normalization` test in release mode with
`PREFLATE_DIAGNOSTICS` pointing at local tiny `.deflate` fixtures and
`PREFLATE_TINY_NORMALIZATION_RESULTS` naming a new TSV file. It compares
actual production records with fixed-parameter baselines, checks unchanged CABAC
bytes, non-growing record sizes and exact cutoff bounds, and verifies byte-exact reconstruction. A separate
guarded-zlib control remains an offline experiment, not a production default.

The ignored `profile_tiny_state_collapse` diagnostic tests whether tiny streams
can share reconstruction settings, independently of parameter packing. Set
`PREFLATE_DIAGNOSTICS` to local raw `.deflate` fixtures and
`PREFLATE_TINY_STATE_RESULTS` to a new TSV file, then run it in release mode.
It records equivalent short-match distance intervals during a test-only replay,
verifies unchanged CABAC bytes and exact reconstruction after canonicalization,
and separately tests a shared zlib-style profile. These are offline experiments,
not production selectors or promised savings.

The ignored `profile_tiny_standard_cutoffs` diagnostic tests replacing observed
three-byte distance maxima with zlib-style parser defaults: 4096 for lazy parsing
and no additional cutoff for fast greedy parsing. Larger observed maxima are
retained; other profiles remain unchanged. Set `PREFLATE_TINY_DEFAULT_RESULTS` to
a new TSV file and use the same local fixtures in release mode. The report includes
complete record sizes, CABAC sizes, corrections, rejected trials, and parameter
states. Every successful trial is reconstructed exactly. A zlib-style parser is
an inferred model, not proof of compressor identity; this remains an offline test.
The baseline and default columns also permit evaluating a deterministic exception
that retains cutoff zero when no three-byte matches were emitted, without replaying
either verified configuration.

The ignored `profile_tiny_distance_windows` diagnostic extends that study to
libdeflate-style cutoffs (4096 for greedy, 8192 for lazy), Windows-style hash
cutoff hypotheses (4096, 8192, or unrestricted), and 32 KiB window normalization.
It preserves zero cutoffs and above-default observations. Hash identity alone
does not establish the compressor or its settings. Set
`PREFLATE_TINY_DISTANCE_WINDOW_RESULTS` to a new TSV file and use the same local
tiny fixtures in release mode. Every successful trial reconstructs exactly;
full record sizes, CABAC changes, parameter states, and rejected trials are
reported separately. An additional conservative window trial changes the window
only when the entire plaintext fits within the original window minus zlib's
lookahead reservation; this cannot expose additional history. These trials do
not alter production parameter selection or introduce production replay passes.

Family-specific observation restrictions are defined by the family modules.
[`evidence_policy.rs`](preflate/src/estimator/evidence_policy.rs) carries their
small shared policy value, selected once during candidate construction; the generic
depth collector applies it without testing compressor identity during probes. For
example, libdeflate's adaptive greedy minimum raises the deferred-match evidence
floor to nine. Dictionary-specific mechanics remain in specialized collectors,
while shared sampling limits and inference confidence remain family-independent.

Strategy inference ignores empty structural blocks: an empty stored flush tail
does not turn a literal-only or RLE stream into a general dictionary stream.
Physical blocks still contribute to block-type prediction. Zlib's lazy parser
permits three-byte matches at distance 4096, rejecting only greater distances.

An inferred insertion cutoff below the longest match can suggest fast-zlib
parsing. If one hash repeatedly implies lazy decisions despite that cutoff, a
surviving zlib hash with the shipped fast-level search budget and no such
contradictions is preferred. No additional stream pass, prefix-prediction replay,
trial encoding, per-byte hash bookkeeping, parameter field, or format change is
introduced by these ambiguity signals.

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

New corrections use the developing **0.8 / 0x84** format, including the six-byte
minimum for filtered zlib predictions and adaptive Huffman tree profiles.
Breaking changes within 0.8 intentionally retain this tag; older 0.8 builds
cannot necessarily decode new corrections. Existing **0x83** blobs remain
readable. Older **0x81**, **0x82**, and unversioned correction blobs are rejected.

Dynamic Huffman blocks retain the existing prediction when it is perfect.
Otherwise, at most eight tree profiles compare zlib/miniz/Floyd heap rules,
single-symbol dummy handling, and combined versus separate literal/distance RLE.
Selection measures isolated CABAC tree payloads including the profile selector,
and changes profiles only for a strictly smaller payload. The surrounding chunk
still shares CABAC contexts. Token prediction is not replayed for these trials.
The `TreeProfile` diagnostic action is profile metadata, not a token/tree error;
it reuses a reserved correction slot and does not enlarge the action mask.

Block prediction also recognizes six common empty flush/end tails: one or two
fixed blocks, a stored block followed by a fixed block, two stored blocks followed
by a fixed block, and one or two stored blocks. A selected tail predicts the
preceding data block's end, the empty blocks' types and sizes, and their final/
chunk-end flags. Other layouts still use ordinary corrections. The first
`BlockTypeCorrection` packs the tail profile with its type difference (six
possible difference values per profile); this is metadata, not necessarily a
wrong block-type prediction. No CABAC channel or parameter field is added.
Detailed traces expose the selected `block_profile` for each chunk.

Stored lengths predict the previous nonempty stored length, capped by the
remaining plaintext, starting with 65,535 when no length has been observed.
Empty flush markers do not erase this learned length, which persists across chunks.
Chunks whose stored blocks are exclusively empty internal flush markers select
a composable `ZeroStored` profile instead, avoiding repeated variable-size
corrections as the remaining plaintext decreases.
Huffman-only token limits use the observed block sizes rather than a fixed
16,386-token limit. Legacy 0x83 decoding retains its original stored-length rule.

Remaining gaps include zlib-ng levels 5/6 (match-end lookahead and backward match
adjustment), libdeflate's adaptive minimum lengths in lazy modes, and Huffman-tree details.
The medium-parser investigation did not justify coercing unrelated hash profiles
or adding trial encodes.

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

For a bounded profile investigation, run the ignored
`diagnose_fixed_family_profiles` test in release mode with `PREFLATE_DIAGNOSTICS`
pointing to the selected raw fixtures and `PREFLATE_FAMILY_RESULTS` naming a new
TSV file. It compares zlib slow/filtered and miniz profiles for zlib-hash streams,
and generic/filtered Windows-hash and six libdeflate parser profiles otherwise.
`PREFLATE_DIAGNOSTICS_FILTER` optionally selects fixture names. It records prefix scores, complete
record sizes, rejected candidates, and reference-length distributions, and
verifies each encodable trial byte-for-byte. These are offline hypotheses, not
production selection results or proof of compressor identity.

The ignored `diagnose_prediction_residual_shapes` test uses the same fixture
directory and optional filter. It classifies up to one million initial mismatches
by actual/predicted reference length (zero denotes a literal), failing if that
bound truncates the result. It also verifies a small neighborhood of lazy search
budgets or three-byte cutoffs. These deliberately different predictions are not
decision-preserving parameter canonicalization.

The ignored `diagnose_short_match_policy` test reports short-reference distances,
block coverage, and bounded literal-run contradictions without printing plaintext
values. It compares complete records for cutoff, insertion, lazy-search, and
early-stop hypotheses, verifying every encodable trial byte-for-byte. Its
actual/predicted-length histogram is capped at one million mismatches; the
reported total mismatch count is not capped. Best offline trials are not
automatic production selections or compressor identifications.

For a broader search, run the ignored `sweep_compressor_parameters` test in
release mode with `PREFLATE_REFERENCE` naming one raw stream and
`PREFLATE_SWEEP_RESULTS` naming a new output prefix. It scores the entire stream
for canonical family profiles and a coarse grid of hashes, parser families, chain budgets, early-stop lengths,
lazy settings and short-match cutoffs, then explores two rounds of neighborhoods
including insertion policies and distance-boundary flags. Window size and block
fingerprints remain fixed. Unsupported cross-family lazy/hash pairings are not
generated. No production selector or search pass is changed.

The `.scores.tsv` file records all distinct scored candidates. The
`.verified.tsv` file records complete record sizes and exact reconstruction checks
for family representatives, the production baseline and the lowest-mismatch
candidates until 64 trials have verified (or candidates are exhausted).
Unencodable candidates are explicitly rejected and do not consume that quota.
Final byte ranking is among these
verified trials, not every scored candidate or an exhaustive parameter optimum.
The `.residuals.tsv` file retains up to 4096 residual positions with actual and
predicted lengths/distances, never literal values. Outputs are never overwritten.

The ignored `diagnose_chromium_profiles` test compares Chromium's non-CRC hash
with six standard slow-zlib profiles and 15/16-bit masks. Use release mode and
`PREFLATE_DIAGNOSTICS` with its optional filter to select raw `.deflate` fixtures.
Every encodable complete record is verified byte-for-byte; rejected profiles are
reported explicitly. This test remains an offline comparison.

Chromium's [non-CRC hash](https://github.com/chromium/chromium/blob/main/third_party/zlib/contrib/optimizations/insert_string.h)
is `((word * 66521 + 66521) >> 16) & mask`, using a little-endian four-byte word
and wrapping 32-bit arithmetic. A 15-bit mask discards the fourth byte's high bit,
so apparent three-byte backup matches can arise from the primary hash alone.
Its source-specific window boundary is used only for normal prediction;
expanded-budget correction searches retain their existing recovery limits.
The source-defined hash and canonical profiles are also included in the broader sweep.

Automatic recognition of the 15-bit non-CRC Chromium variant samples at most 64
three-byte references during the existing stream-information walk. At least 16
must show the characteristic fourth-byte high-bit alias, with no incompatible
nonextending samples. It substitutes an optional alternate hash candidate,
preserving the memory-level hash and candidate count. The existing depth walk
must still accept the candidate across the stream. Native fast/slow defaults
are selected from insertion, depth and lazy evidence; this is not proof of an
exact compression level. Streams without enough evidence keep existing selection.

Static native Chromium fixtures cover **all levels 0 through 9** using a fully
synthetic input. The regression test
`native_chromium_all_levels_select_and_reconstruct` checks automatic selection,
zero token mismatches, complete records no larger than 32 bytes, and exact
reconstruction. Ordinary tests need no C compiler or network access.
To regenerate them with PowerShell 7, CMake, Ninja, tar and GCC on `PATH`, run:

```powershell
.\tests\generate_chromium_samples.ps1 -WorkDirectory "<external-build-directory>"
```

The generator pins the upstream Chromium revision and disables SIMD/CRC and
canonical-zlib hash overrides. The sample manifest records source settings and
SHA-256 hashes. The C generator is independent of our predictor.

The ignored `diagnose_three_byte_backup_insertion` test uses `PREFLATE_REFERENCE`
to compare bounded insertion-policy hypotheses and aggregate fourth-byte
relationships without printing plaintext. A compatible source alone does not
identify the producing binary or library version.

The ignored `diagnose_hash_chain_constraints` test takes one raw stream through
`PREFLATE_REFERENCE`. It compares three zlib hash sizes and the Windows-style
three-byte hash under inferred and full insertion, reporting reference hash/depth
consistency and required chain ranks. Run it in release mode. Compatible chain
constraints do not establish the original hash or parser, and this test does not
replay or verify complete reconstruction records.

The ignored `diagnose_hash_head_collisions` test uses the same raw-stream input
to compare zlib and Windows-style bucket heads at each actual reference. It
counts cases where only one head is the actual source, distinguishes unrelated
collisions, and compares the first matching three-byte prefix after skipping
collisions. Examples are capped at four per direction and insertion policy and
contain positions and lengths, not plaintext. More direct-head hits alone do
not identify a chain-searching compressor's hash; known-zlib controls demonstrate
this limitation. These offline checks do not change production hash selection.

To compare actual native compressor outputs, run the ignored
`compare_native_compressor_outputs` integration test in release mode with
`PREFLATE_NATIVE_INPUT` naming one raw payload and `PREFLATE_NATIVE_OUTPUT` naming
a new directory. It recompresses the decoded bytes with libdeflate levels 5-12
and zlib/zlib-ng levels 6, 8, and 9, verifies their plaintext, and reports exact
bitstream equality. Nonidentical output alone does not establish a version
difference: settings, input boundaries, and producer wrappers can also differ.
Private native outputs remain private data and must be removed after analysis.

The ignored `diagnose_compressor_constraints` test uses `PREFLATE_DIAGNOSTICS`
and its optional filter to report expanded block sizes, a block-token histogram,
minimum reference length, maximum distance, and references crossing 32 KiB
boundaries. These structural constraints can exclude historical compressor
implementations; compression ratio or a compatible hash alone cannot identify
a particular library version.

To compare native tokenization directly, set `PREFLATE_REFERENCE` to the original
raw stream and run the ignored `compare_compressor_tokens` test with the same
fixture directory and filter. It requires identical plaintext, aligns tokens by
plaintext position rather than token index, and reports exact-token byte coverage
and up to eight differing length/distance shapes without printing literal data.
It also counts three-byte references in each stream, reports how many agree,
and separately retains up to eight differing three-byte-reference positions.

For tiny-stream investigations, put raw `.deflate` fixtures smaller than 1 KiB in
`PREFLATE_DIAGNOSTICS` and set `PREFLATE_TINY_RESULTS` to a new TSV output path:

```shell
cargo test --release -p preflate-rs diagnose_tiny_streams -- --ignored --nocapture
```

This records block layouts, CABAC versus total reconstruction bytes, nonzero
actions, and bounded parameter trials. Trials prioritize fewer nonzero actions,
then smaller reconstruction data; fewer actions do not always mean fewer bytes.
Baselines and improving trials are verified byte-for-byte. The report also tests
a hypothetical preset for a data block followed by up to three empty static or
stored blocks, reconstructing the data block with zero corrections. Trailer types
and final bits are preset metadata, not free information. These experiments do
not change production parameter selection or the reconstruction format.

For byte-cost attribution without parameter trials, use the same tiny fixtures
and set `PREFLATE_TINY_PROFILE_RESULTS` to a new TSV output path:

```shell
cargo test --release -p preflate-rs profile_tiny_overhead -- --ignored --nocapture
```

This verifies exact reconstruction and separates standalone parameter bytes,
net wrapper cost, and correction coding. It records the selected block profile
and attributes correction bytes to tokens, Huffman-profile choices, detailed
Huffman corrections, and block layout/length/termination. Attribution re-encodes
recorded events for all 16 family subsets and averages marginal costs over all
24 family orders; `components_x24` stores these contributions multiplied by 24.
Their sum plus the all-default CABAC size equals the actual CABAC size.
Zeroing recorded events measures coding cost, not a decodable alternative model
or guaranteed savings. This is offline instrumentation only.

For a mixed-size PDF investigation, set `PREFLATE_DIAGNOSTICS` to exported raw
streams and `PREFLATE_PDF_RESULTS` to a new TSV output path:

```shell
cargo test --release -p preflate-rs diagnose_pdf_overhead -- --ignored --nocapture
```

This verifies every stream and records total reconstruction bytes, raw CABAC
bytes, net framing/parameter cost (total minus raw CABAC, including vector
serialization effects), standalone parameter size, reference-distance statistics,
and correction counts. Use single-chunk fixtures when comparing against scanner
reports; this harness measures the whole stream as one chunk.

Optionally set `PREFLATE_PDF_PROBES` to comma-separated fixture stems. Each selected
stream scores bounded parameter combinations over at most 4,096 tokens or
512 KiB, then measures up to eight distinct hash/parser combinations whose prefix
score is no worse than the baseline. Every encodable trial is reconstructed and
compared byte-for-byte; incompatible trials are logged and counted as rejected.
The best result is chosen by complete reconstruction size, not action count.
These are bounded offline trials, not an exhaustive optimum or a production
parameter-selection change.

To isolate Huffman corrections, use `PREFLATE_DIAGNOSTICS` for raw `.deflate`
fixtures and `PREFLATE_HUFFMAN_RESULTS` for a new TSV output path:

```shell
cargo test --release -p preflate-rs diagnose_huffman_trees -- --ignored --nocapture
```

This compares zlib and miniz construction, Floyd-heap tie-breaking,
the zlib single-symbol dummy rule, and separate literal/distance RLE boundaries.
It records actual frequencies, trees, and correction counts, verifies corrected
headers through both encoder and decoder, and checks exact stream reconstruction.
This isolates the individual rules independently of production cost-aware
selection. To validate actual production correction sizes and exact round trips
on the same fixtures, set a new `PREFLATE_HUFFMAN_RESULTS` path and run:

```shell
cargo test --release -p preflate-rs verify_huffman_profile_selection -- --ignored --nocapture
```

The production validation uses 32 MiB plaintext chunks, matching the scanner
default, and reports profile selections separately from residual tree corrections.

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
- 486 miniz/libdeflate round trips across levels 1-9, plus 96 zlib/zlib-ng controls
  and 24 periodic miniz cases exercising one-symbol distance alphabets.
- 36 continuation cases across two inputs and two chunk limits, checking plaintext,
  exact reconstructed bytes and first-chunk-only parameters.
- An independent longest-prefix oracle for match searches, alphabet/depth
  invariants, candidate-order independence and diagnostic parameter isolation.

```shell
cargo test -p preflate-rs
cargo test --test end_to_end -- compressor_models_ compression_benchmark_overhead_size
```

Huffman regressions also cover one-symbol literal/length trees, empty distance
alphabets in literal-only blocks, and rejection of unused branches, missing
end-of-block codes, oversubscribed trees and other invalid incomplete trees.
The periodic miniz cases verify the compressor's own inflater accepts each stream
before checking plaintext and exact reconstruction:
`cargo test --test end_to_end periodic_miniz_streams_roundtrip`.

## Workspace Layout

| Crate | Output | Description |
|---|---|---|
| [`preflate/`](preflate/) | library | Core DEFLATE analysis and reconstruction engine |
| [`container/`](container/) | library | Scans binary files (ZIP, PNG, JPEG) for DEFLATE streams and orchestrates the Zstd pipeline |
| [`util/`](util/) | `preflate_util.exe` | CLI tool for testing and benchmarking |
| [`util/`](util/) | `preflate_scan.exe` | Recursive read-only DEFLATE modelling diagnostics and JSON reports, without Zstd |
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
cargo test --release --all
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

### Scanning a document corpus (JSON diagnostics, no Zstd)

Build the standalone scanner:

```shell
cargo build --release -p preflate_util --bin preflate_scan
```

Then recursively scan a folder, including ZIP-based Office documents:

```powershell
.\target\release\preflate_scan.exe "C:\Users\you\OneDrive" --output scan-report.json
```

For an initial local corpus run excluding files larger than 20 MiB:

```powershell
.\target\release\preflate_scan.exe "$env:USERPROFILE\Downloads" --max-file-mib 20 --output downloads-report.json
```

Use the **release** executable for corpus scans and traces; debug builds are much slower.

The scanner reads source files without modifying them. It runs **preflate only**,
with bit-exact DEFLATE reconstruction verification enabled by default, and writes
a JSON report. It never runs Zstd, WebP or Lepton. Windows cloud-only files are
skipped unless `--hydrate` explicitly allows downloading them. Symlinks and
junctions are not followed. Unreadable files/directories and preflate panics are
recorded without stopping the scan; report-write failures stop it with a nonzero
exit code. A completed report exits successfully even when individual files fail.
Existing reports are never overwritten.

Useful options:

| Option | Default | Meaning |
|---|---|---|
| `--poor-ratio-percent` | `1` | Flag corrections exceeding this percent of original DEFLATE bytes |
| `--min-stream-bytes` | `1024` | Minimum original DEFLATE bytes for flags/rankings; smaller streams are still recorded |
| `--max-chain` | `4096` | Maximum permitted estimated hash-chain depth |
| `--max-file-mib` | `256` | Skip larger files; one source file is buffered at a time |
| `--chunk-mib` | `32` | Plaintext budget per preflate chunk; an oversized single block is reported as a limit |
| `--max-stream-mib` | `512` | Per-stream plaintext budget, checked at chunk boundaries |
| `--max-candidates` | `10000` | Maximum signature attempts per file, followed by a limit record if exceeded |
| `--raw` | off | Treat every file as raw DEFLATE; `.deflate` files do this automatically |
| `--no-verify` | off | Disable reconstruction verification for faster profiling |
| `--hydrate` | off | Allow reading cloud-only files |
| `--include-rejected-candidates` | off | Retain every rejected heuristic signature instead of compact counts and examples |
| `--trace` | off | Detailed trace for one file (not a directory) |
| `--trace-limit` | `64` | Maximum mismatch examples and block descriptions per traced stream |
| `--stream-offset` | all | Trace one signature offset from a previous report; requires `--trace` |

The report contains:

- `schema_version`, `tool_version`, start time, resolved root and scan configuration.
- `files`: path, size, modification time, status, errors, elapsed time and stream records.
  Rejected heuristic signatures are stored as `rejected_candidates` counts
  by error code and up to eight `rejected_candidate_examples` per file by default.
  These counts remain included in the summary's failed-candidate totals and
  `rejected_signature_candidates`; ordinary files with only rejected signatures
  are classified as `no_streams`. Strong wrapper failures and modelling failures
  are always retained as individual stream records.
- Each stream: source signature offset, wrapper kind, ZIP member name when available,
  estimated compressor parameters, processed DEFLATE/plaintext/correction bytes,
  chunk/block counts, verification status, timing, throughput, and nonzero
  correction counts by category. `ranking_eligible` and `poor_model` identify
  streams meeting the configured size and overhead thresholds.
  `deflate_offset` locates the contiguous raw payload in the source file; it is
  null for PNG IDAT streams, whose payload is assembled from multiple chunks.
  `signature_confidence` distinguishes heuristic byte matches from recognizable
  wrapper headers and explicitly requested raw streams.
- `summary`: successful/failed/unsupported/limited candidate counts, filesystem
  errors and skips, error-code histogram, successful-byte totals, weighted
  correction ratio, and the 20 highest-overhead streams.

`correction_ratio` is a **fraction**, not a percentage: `0.01` means 1%.
Correction bytes include serialized parameters as well as CABAC data; small
streams can therefore have high ratios even with accurate token predictions.
By default, streams smaller than 1024 DEFLATE bytes are excluded from flags and
rankings to avoid fixed-header overhead dominating the results; use
`--min-stream-bytes 0` to include them.
The ratio measures **modelling overhead**, not final compression savings.
Nonzero correction counts include structural decisions and recovery actions;
they are neither raw token-mismatch counts nor per-category bit costs.
Failed or limited streams retain successful-chunk measurements, but have no
final ratio and are excluded from successful-byte totals and rankings.

For example, inspect the worst cases in PowerShell:

```powershell
$report = Get-Content -Raw .\scan-report.json | ConvertFrom-Json
$report.summary
$report.summary.worst_streams | Format-Table path, member_name, correction_ratio, correction_bytes
```

#### Investigating a single file

```powershell
.\target\release\preflate_scan.exe "C:\path\problem.docx" --trace --output file-trace.json

# Focus on one stream's signature offset from the corpus report:
.\target\release\preflate_scan.exe "C:\path\problem.docx" --trace --stream-offset 1234 --trace-limit 128 --output stream-trace.json
```

Trace mode adds `trace` to attempted stream records:

- Total initial token predictions and mismatches, measured **before** correction recovery.
- Bounded actual/predicted token examples, with stream-relative plaintext offsets.
  Tokens are structured literals (`value`) or references (`length`, `distance`).
- Per-chunk raw DEFLATE/plaintext offsets, sizes, corrections, timings and errors,
  including the failed chunk when processing stops. `stage` / `last_stage` identify
  parsing, parameter estimation, chain-limit checks, prediction or verification;
  estimated parameters are retained even when the chain limit rejects them.
- Bounded per-block type (stored/static/dynamic Huffman), plaintext range,
  literal/reference counts and final-block flag.
- Explicit `mismatches_truncated` and `blocks_truncated` indicators; total counts
  are not truncated. Stored blocks do not contribute token-prediction counts.

Chunk DEFLATE offsets are relative to the raw payload (the assembled payload for
PNG), not the file. Block indices, chunk indices and offsets are zero-based.
Trace sampling spans the whole stream, not just its first chunk. Normal scans
omit trace data and do not allocate mismatch samples; the libraries' trace
instrumentation is behind the optional `diagnostics` feature, enabled by this EXE.
Missing correction-recovery matches are reported as `MatchNotFound` and can be
investigated using the prediction-stage trace.
Trace mode retains rejected-signature details automatically; `--stream-offset`
avoids unrelated candidates. A missing requested signature is reported explicitly
and exits with failure. Trace timings include verification unless `--no-verify`
is specified and should not be compared directly to untraced throughput.

Focused release regressions use generated data and checked-in fixtures, without
requiring a local document corpus:

```shell
cargo test --release -p preflate-container --features diagnostics diagnostics::tests
cargo test --release --test end_to_end compressor_models_roundtrip_across_chunks
cargo test --release --test end_to_end pdf_zlib_profiles_have_low_correction_overhead
cargo test --release --test end_to_end native_compressor_bounds_roundtrip_incompressible_boundaries
```

These cover malformed signatures, truncation and bit flips, optional gzip
headers, ZIP data descriptors, trace/normal correction-byte parity across chunk
boundaries, and native compressor output bounds on incompressible inputs.

Discovery uses zlib, gzip, ZIP local-header and PNG IDAT signatures. Signature
matches in arbitrary data can be false positives: a failed candidate is **not**
proof of a modelling bug. Error codes distinguish invalid data, unsupported
parameter estimates, prediction/reconstruction failures and configured limits.
Stored/encrypted/non-DEFLATE ZIP members are reported as unsupported. The scanner
does not recursively scan expanded member contents, infer raw DEFLATE in
arbitrary files, or parse every document format. PNG IDAT CRCs are checked by the
existing parser; ZIP/gzip/zlib wrapper checksums are not validated.
`verified` refers to exact reconstruction of the raw DEFLATE bytes.

Records are flushed after each file to keep memory independent of corpus size.
The JSON document is finalized with its summary only on normal completion;
interrupted scans leave an incomplete report. Reports contain local paths and
archive member names, but no document plaintext or correction payloads; review
them before sharing. Trace reports additionally expose sampled literal byte
values and match locations, so treat them as potentially sensitive document data.

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
