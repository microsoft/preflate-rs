# preflate_rs_0_7

C-compatible DLL exposing the preflate-rs container pipeline for .NET interop.

The DLL name encodes the container format version (`0_7`). This allows multiple format versions to coexist side-by-side on the same machine — old decoders remain functional while new encoders produce newer formats.

## Exported API

The DLL exports a streaming compress/decompress API as `extern "C"` functions.

### Compression

```c
// Create a compression context.
// flags bits 0-4: Zstd compression level (0-14)
// flags bit  5:   measure baseline Zstd-only size (for stats)
// flags bit  6:   skip round-trip verification
void* create_compression_context(uint32_t flags);
void  free_compression_context(void* context);

// Feed input data and receive compressed output.
// Call repeatedly until done == true.
// Returns: 1 = done, 0 = more data needed/available, <0 = error code.
int32_t compress_buffer(
    void*          context,
    const uint8_t* input,            size_t input_size,
    bool           input_complete,
    uint8_t*       output,           size_t output_size,
    size_t*        result_size,
    char*          error_string,     size_t error_string_buffer_len
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

### Decompression

```c
// Create a decompression context.
// capacity: initial output buffer hint (0 = use default).
void* create_decompression_context(uint32_t flags, size_t capacity);
void  free_decompression_context(void* context);

// Feed compressed input and receive reconstructed output.
// Call repeatedly until done == true.
// Returns: 1 = done, 0 = more data needed/available, <0 = error code.
int32_t decompress_buffer(
    void*          context,
    const uint8_t* input,            size_t input_size,
    bool           input_complete,
    uint8_t*       output,           size_t output_size,
    size_t*        result_size,
    char*          error_string,     size_t error_string_buffer_len
);
```

## Streaming Pattern

Both compress and decompress follow the same loop:

1. Call `compress_buffer` / `decompress_buffer` with a chunk of input.
2. If `result_size > 0`, consume the output bytes.
3. If return value is `0`, call again — either with more input or with the same position if the output buffer was too small.
4. When all input has been fed, set `input_complete = true`.
5. Continue calling until return value is `1` (done).

The DLL buffers any output that does not fit in the provided output buffer internally, so the output buffer can be any convenient size.

## Safety

- Magic numbers (`0x4K3CFF2E` for compression, `0x053D2AB1` for decompression contexts) are validated on every call to catch dangling or mismatched pointers.
- All entry points use `catch_unwind` to prevent Rust panics from crossing the FFI boundary.
- Error messages are copied as UTF-8 into the caller-provided buffer with null termination.
- All logic outside the FFI boundary layer is safe Rust (`#![forbid(unsafe_code)]` on all dependencies).

## Building

```shell
cargo build --release -p preflate_rs_dll
# Output: target/release/preflate_rs_0_7.dll (Windows)
```

The release build applies Spectre mitigations (`/Qspectre /sdl`) and Control Flow Guard (`/guard:cf`).
