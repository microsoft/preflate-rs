# Repository instructions

These instructions apply throughout this repository. Keep checked-in guidance
applicable to every contributor: no machine-specific paths, personal settings,
private corpus locations, or temporary investigation results.

## Project

preflate-rs extracts plaintext and compact reconstruction data from DEFLATE streams
and recreates the exact original compressed bytes. Bit-exact reconstruction is
the primary invariant, including for unrecognized compressors.

- `preflate/`: DEFLATE parsing, compressor estimation, token/tree prediction, and
  reconstruction.
- `container/`: locating streams in documents and container reassembly.
- `util/`: command-line tools, including the recursive `preflate_scan` diagnostic.
- `dll/`: C interop wrapper.
- `tests/` and `samples/`: end-to-end fixtures and round-trip tests.
- `fuzz/`: fuzz harnesses.
- `corpus/`: optional Python corpus discovery, SQLite analysis and generation,
  using the root uv project rather than a Rust workspace crate.

See [README.md](README.md) for architecture, supported compressor models, and
scanner usage. Consult subproject `AGENTS.md` files for additional details;
the corpus testing and current format policy below apply to those docs too.

## Build and validation

Run all project Python scripts, tests, and diagnostic helpers with
`uv run --locked`, not a directly invoked system Python. Use the root
`pyproject.toml` and `uv.lock`; add Python dependencies there instead of
installing them with pip. For optional JPEG corpus generation, use
`uv run --locked --extra jpeg corpus/gen_corpus.py`.
Always use the Microsoft Python feed
(`https://packagefeedproxy.microsoft.io/pypi/simple/`) for Python dependency
resolution. Keep it configured as the default index in the root `pyproject.toml`;
do not override it with PyPI or another index when updating `uv.lock`.

Use the workspace Rust minimum and edition declared in `Cargo.toml`. Preserve
the existing unsafe-code restrictions and chunked, bounded-memory processing.
The core and container crates enforce `#![forbid(unsafe_code)]`; the DLL's C FFI
entry points have their own safety requirements in [dll/AGENTS.md](dll/AGENTS.md).

For non-corpus development, debug builds and tests are also available:

```sh
cargo build --all
cargo test --all
cargo test <test_name>
cargo test -- --nocapture
```

GitHub Rust CI runs on `windows-latest`, installs four target toolchains
(`wasm32-wasip1`, `aarch64-unknown-linux-musl`, `x86_64-pc-windows-msvc`,
`x86_64-unknown-linux-gnu`), and builds/tests the host target.
Its separate MSRV job checks all workspace targets and features on Rust 1.89.
The Azure pipeline adds `/Qspectre /sdl` for its native release build; these
are not automatic flags for local Cargo builds. Windows release outputs include
`preflate_rs_0_8.dll` and the utility binaries. `.cargo/config.toml` enables
Control Flow Guard and sets `/DYNAMICBASE /CETCOMPAT` linker flags for Windows MSVC.

**Always use release builds for corpus testing, scans, profiling, and benchmarks.**
Debug builds are too slow for meaningful corpus work. This also applies to ignored
diagnostic tests that replay corpus payloads.

```sh
cargo build --release --all
cargo build --release -p preflate_util --bin preflate_scan
cargo test --release --all
cargo test --release -p preflate-rs <test_name>
cargo fmt --check --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy -p preflate-container --no-default-features --all-targets -- -D warnings
cargo clippy -p preflate-rs --no-default-features --all-targets -- -D warnings
```

Keep compiler, Clippy and Rustdoc output warning-free, including test targets
and optional-feature builds. Use `RUSTDOCFLAGS="-D warnings"` when running
`cargo doc --workspace --all-features --no-deps` (set the environment variable
using the syntax for your shell).

For a corpus scan without subsequent Zstd compression:

```sh
cargo run --release -p preflate_util --bin preflate_scan -- "<folder>" --output "<new-report.json>"
```

Run focused tests first, then the relevant broader round-trip coverage. Preserve
existing sample files and validate byte-for-byte reconstruction, not just
successful decompression.

## Rust imports

Always use `use` declarations at the top of the Rust file or enclosing module
instead of fully qualified paths in code. Keep test-only imports at the top of
the gated test module. Use import aliases to resolve name collisions; retain
fully qualified syntax only when Rust requires it for disambiguation.

## Rust test organization

Always put inline Rust unit tests in a `#[cfg(test)] mod tests` at the end of the
source file or enclosing inline module, with `use super::*;` to access the code
under test. Keep test-only imports and private fixtures/helpers inside that
module rather than interleaving them with production code. Shared test support
may live in a separate `#[cfg(test)]` module; integration tests remain in their
dedicated test targets.

## Architecture

The core pipeline parses DEFLATE tokens, estimates compressor parameters, predicts
tokens and Huffman trees, and encodes prediction differences with CABAC.
Parameters use `bitcode`; processing is chunked to bound memory use.
See [preflate/AGENTS.md](preflate/AGENTS.md) for the shared prediction state,
estimator, correction codec, and streaming API boundaries.

The container pipeline locates streams, extracts plaintext and corrections,
compresses them with a single persistent Zstd encoder, and recreates the original
container on decode. PNG IDAT chunks are extracted and reassembled separately.
The default-enabled `webp` feature can store PNG pixel data as lossless WebP;
PDF streams are not scanned. See [container/AGENTS.md](container/AGENTS.md)
for framing, finalization, and reassembly details.
Current containers finish with a raw CRC-32 end block verifying reconstructed
bytes; preserve its single-finalization behavior.

Shared `PredictionState` owns matching, lazy lookahead, block lifecycle, and safe
normalization observations. `TokenPredictor` owns correction coding, tree
frequencies, traces, and profile-specific parameter canonicalization.
Shared runtime types live in `parameters`, independent of estimation and family
policy; lower-level modules must not import them through `estimator`.
Bounded candidate replay and stopping policy belong in
`estimator::prediction_scoring`; all consumers share predict/resolve/accept
semantics. Do not move estimator policy or correction codecs into the common state.
Whole-file container convenience helpers read their entire input; use
`ProcessBuffer` or `copy_to_end` for bounded streaming.

Python tooling lives in [corpus/database](corpus/database/README.md) and
[corpus/crawl](corpus/crawl/README.md). Discover machine-local configuration
through the ignored `corpus.local.toml`, without recording its values in guidance.
Private-directory scans and Common Crawl use separate SQLite databases.
The crawl uses only its own catalog for rarity; it never opens private history.
Do not import crawl runs into private history. See [corpus/README.md](corpus/README.md)
for warning-strict Python validation and optional dependency extras.

## Rust visibility

- For crate-internal data structs, prefer `pub(crate) struct` with `pub` fields
  over restricting each field individually with `pub(crate)`. Keep fields private
  when encapsulation is needed to preserve invariants.

## Compressor modelling and performance

- Reuse existing estimation passes and existing hash state. Bound additional
  observations; do not add passes, prediction replays, trial encodes, candidate
  sweeps, or per-byte bookkeeping without explicit approval.
- Do not significantly slow the algorithm. Measure release-mode before/after
  CPU and wall time on identical inputs; do not run competing scans or builds
  during a controlled benchmark.
- Preserve working compressor fingerprints and refinements. An inferred search
  budget or insertion cutoff is evidence, not proof of compressor identity;
  parameters are not independent.
- Optimize total reconstruction bytes, including parameter/framing costs and
  correction coding. Correction counts or per-stream percentages alone are
  insufficient. Report tiny-stream results and regressions separately.
- Offline parameter sweeps are diagnostic only. Do not present their best-case
  savings as production results unless the production selector achieves them.
- The current 0.8 development intentionally breaks the format. Do not add new
  versioning or backward-compatibility layers unless requested. Keep encoding,
  reconstruction, and tests consistent.

## Improvements

- Prioritize systematic prediction errors affecting p90 overhead within common
  prediction-choice buckets, not isolated worst cases or their large byte totals.
  Outliers that will be excluded from the target population are not the primary
  optimization target; state exclusion criteria explicitly.
- Use verified streams with at least 4 KiB of raw DEFLATE for the main comparison.
  Bucket by selected hash and parser behavior, not assumed compressor identity,
  and report size strata so small-stream overhead does not obscure modelling quality.
- Investigate recurring token, reference-length, and block prediction errors across
  representative streams in common profiles before pursuing exceptional profiles.
  Measure production-selector p90 and total reconstruction bytes on unchanged
  cohorts, with regressions and excluded/tiny streams reported separately.

## Corpus diagnostics and data handling

- Scan read-only; skip cloud-only files by default rather than hydrating them.
  Respect configured file, candidate, plaintext, and trace limits.
- Keep preflate-only diagnostics separate from subsequent Zstd compression.
  Keep detailed traces opt-in and bounded.
- Verify reconstruction by default. Label encode-only timing runs that disable
  verification, and validate correctness separately.
- Compare streams in unchanged source files using path, size, modification time,
  and stream boundaries. Separate newly available or changed files from measured
  modelling gains. Stream large JSON reports instead of loading them wholesale.
- Keep private documents, raw payload exports, and their contents out of commits
  and external services. Use synthetic/public fixtures for committed regression
  tests. Remove temporary private payload exports after investigation.
