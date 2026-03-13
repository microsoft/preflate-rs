# preflate-rs-fuzz

libfuzzer harnesses for the preflate-rs workspace.

These targets feed arbitrary bytes into the core and container APIs to find crashes, panics, or round-trip failures. Fuzzing requires nightly Rust.

## Targets

### `fuzz_target_1` — core round-trip

Feeds arbitrary bytes to `preflate_whole_deflate_stream` as a raw DEFLATE stream. If analysis succeeds, the result is immediately fed to `recreate_whole_deflate_stream` and the output must match the input exactly.

```rust
fuzz_target!(|data: &[u8]| {
    if let Ok((result, plain_text)) = preflate_whole_deflate_stream(data, &config) {
        recreate_whole_deflate_stream(plain_text.text(), &result.corrections).unwrap();
    }
});
```

### `fuzz_container` — container round-trip

Feeds arbitrary bytes through the full container pipeline. If compression succeeds, the compressed output is decompressed and compared byte-for-byte with the original input.

```rust
fuzz_target!(|data: &[u8]| {
    if let Ok(_) = preflate_whole_into_container(&config, &mut Cursor::new(data), &mut output) {
        recreate_whole_from_container(&mut Cursor::new(&output), &mut original).unwrap();
        assert_eq!(data, &original[..]);
    }
});
```

## Running

```shell
# Run the core round-trip fuzzer
cargo +nightly fuzz run fuzz_target_1

# Run the container round-trip fuzzer
cargo +nightly fuzz run fuzz_container

# Run with a specific corpus directory
cargo +nightly fuzz run fuzz_container fuzz/corpus/fuzz_container/

# Limit to N iterations
cargo +nightly fuzz run fuzz_target_1 -- -runs=1000000
```

## Corpus and Artifacts

Crash inputs and corpus entries are stored under `fuzz/artifacts/` and `fuzz/corpus/` respectively (both gitignored). To seed the corpus with real files, copy them into the appropriate corpus directory before running.
