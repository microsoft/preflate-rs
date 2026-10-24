# preflate_rs_0_7

C-compatible DLL exposing the preflate-rs container pipeline for .NET interop.

The DLL name encodes the compatibility series (`0_7`); this is distinct from the
container's format byte, documented in the [container guide](../container/README.md#container-format).
Versioned DLL names allow old decoders to coexist with new ones. Incompatible
format changes require reviewing both the container marker and DLL/package naming.

## Exported API

The DLL exports a streaming compress/decompress API as `extern "C"` functions.

### Compression

```c
// Create a compression context.
// See create_compression_context in src/unmanaged_api.rs for flag masks.
void* create_compression_context(uint32_t flags);
void  free_compression_context(void* context);

// Feed input data and receive compressed output.
// Call repeatedly until done == true.
// Returns: 1 = done, 0 = more data needed/available, <0 = error code.
int32_t compress_buffer(
    void*          context,
    const uint8_t* input,            uint64_t input_size,
    bool           input_complete,
    uint8_t*       output,           uint64_t output_size,
    uint64_t*      result_size,
    uint8_t*       error_string,     uint64_t error_string_buffer_len
);

// Read compression statistics after processing completes.
void get_compression_stats(
    void*     context,
    uint64_t* deflate_compressed_size,
    uint64_t* zstd_compressed_size,
    uint64_t* zstd_baseline_size,
    uint64_t* uncompressed_size,
    uint64_t* overhead_bytes,
    uint32_t* hash_algorithm
);
```

The current implementation decodes compression flags as follows:

| Mask | Meaning |
|---|---|
| `0x0F` | Zstd compression level |
| `0x10` | Measure baseline Zstd compression |
| `0x20` | Enable internal round-trip verification |

For example, `9 | 0x20` selects level 9 with verification enabled. Leaving
`0x20` clear disables internal verification; callers must then verify the
round-trip themselves. The DLL uses a maximum predictor chain length of 1024.

### Decompression

```c
// Create a decompression context.
// flags: currently unused.
// capacity: nonzero maximum input bytes appended per decoder iteration.
void* create_decompression_context(uint32_t flags, uint64_t capacity);
void  free_decompression_context(void* context);

// Feed compressed input and receive reconstructed output.
// Call repeatedly until done == true.
// Returns: 1 = done, 0 = more data needed/available, <0 = error code.
int32_t decompress_buffer(
    void*          context,
    const uint8_t* input,            uint64_t input_size,
    bool           input_complete,
    uint8_t*       output,           uint64_t output_size,
    uint64_t*      result_size,
    uint8_t*       error_string,     uint64_t error_string_buffer_len
);
```

## Streaming Pattern

Both compress and decompress follow the same loop:

1. Create a context; check that the returned pointer is not null.
2. Supply each input chunk exactly once and consume `result_size` output bytes.
   A small output buffer does not mean that the input should be resubmitted.
3. Set `input_complete = true` on the final input call.
4. After the final input call, if the return value is `0`, drain remaining output with empty input and
   `input_complete = true` until the return value is `1`. Negative values are errors.
5. Free the context with its matching `free_*_context` function.

The DLL buffers output that does not fit internally. Use a nonzero output buffer
size so that draining can make progress.

## Safety

- Context magic values are checked to detect mismatched context types.
- The FFI error-handling wrapper uses `catch_unwind` to contain Rust panics.
- Error messages are copied as UTF-8 into the caller-provided buffer with null termination.
- Callers must supply valid context pointers, writable result/error buffers, and
  correct buffer lengths. Magic checks do not make dangling pointers safe.
- The core Rust codecs and container pipeline forbid unsafe code; the FFI
  boundary and native dependencies have their own safety requirements.

## Implementation

[`src/unmanaged_api.rs`](src/unmanaged_api.rs) defines the exported functions,
flag decoding, context magic values, and `catch_unwind_result` error translation.
Compression and decompression contexts retain a processor and a `VecDeque<u8>`
for output that does not fit in the caller's buffer. Preserve that output across
calls and keep panics from crossing the FFI boundary.

The boundary uses `unsafe extern "C"` functions and `#[unsafe(no_mangle)]`
exports. Keep unsafe operations isolated to this layer.

## Building

```shell
cargo build --release -p preflate_rs_0_7
# Output: target/release/preflate_rs_0_7.dll (Windows)
```

Windows linker hardening is configured in [`.cargo/config.toml`](../.cargo/config.toml).
The [Azure release pipeline](../azure-pipelines.yml) additionally sets
`/Qspectre /sdl` when building native dependencies; a standalone Cargo release
build does not set those environment flags automatically.
