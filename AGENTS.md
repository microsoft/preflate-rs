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

See [README.md](README.md) for architecture, supported compressor models, and
scanner usage. Consult subproject `CLAUDE.md` files for additional details;
the corpus testing and current format policy below apply to those docs too.

## Build and validation

Use the workspace Rust minimum and edition declared in `Cargo.toml`. Preserve
the existing unsafe-code restrictions and chunked, bounded-memory processing.

**Always use release builds for corpus testing, scans, profiling, and benchmarks.**
Debug builds are too slow for meaningful corpus work. This also applies to ignored
diagnostic tests that replay corpus payloads.

```sh
cargo build --release --all
cargo build --release -p preflate_util --bin preflate_scan
cargo test --release --all
cargo test --release -p preflate-rs <test_name>
cargo fmt --check --all
cargo clippy --workspace --all-targets
```

For a corpus scan without subsequent Zstd compression:

```sh
cargo run --release -p preflate_util --bin preflate_scan -- "<folder>" --output "<new-report.json>"
```

Run focused tests first, then the relevant broader round-trip coverage. Preserve
existing sample files and validate byte-for-byte reconstruction, not just
successful decompression.

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
