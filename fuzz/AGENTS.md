# fuzz (preflate-rs-fuzz)

These instructions supplement the root [AGENTS.md](../AGENTS.md).

libfuzzer harnesses for fuzzing the core and container APIs. Not published;
requires nightly Rust and cargo-fuzz. The `fuzzing` feature is currently empty
and is not required by the targets.

## Harnesses

### `fuzz_target_1` — core round-trip

Feeds arbitrary bytes to `preflate_whole_deflate_stream()` as a raw DEFLATE stream,
then attempts `recreate_whole_deflate_stream()` on the result. Verifies no crash or panic.

### `fuzz_container` — container round-trip

Feeds arbitrary bytes (minimum 1 byte) to `preflate_whole_into_container()`, then
`recreate_whole_from_container()`, and asserts the output matches the original input.

## Running Fuzz Tests

```bash
# Requires nightly and cargo-fuzz
cargo +nightly fuzz run fuzz_target_1
cargo +nightly fuzz run fuzz_container
```

## Notes

- Edition 2021 (older than the main workspace crates which use 2024).
- `libfuzzer-sys` (0.4) provides the fuzzing harness glue.
- Corpus and artifacts are stored under `fuzz/corpus/` and `fuzz/artifacts/` (gitignored).
