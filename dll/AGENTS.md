# dll (preflate_rs_0_8)

These instructions supplement the root [AGENTS.md](../AGENTS.md).

C-compatible DLL for .NET interop. Exposes a streaming compress/decompress API as
`extern "C"` functions. The version number is baked into the crate name
(`preflate_rs_0_8`) for binary compatibility.

## Exported C API (`src/unmanaged_api.rs`)

### Compression

```c
void* create_compression_context(uint32_t flags);
void  free_compression_context(void* context);
int32_t compress_buffer(
    void*        context,
    const uint8_t* input,      uint64_t input_size,
    bool         input_complete,
    uint8_t*     output,       uint64_t output_size,
    uint64_t*    result_size,
    uint8_t*     error_string, uint64_t error_string_buffer_len
);
void get_compression_stats(void* context, /* stat out-params */);
```

`flags` encoding:
- bits 0-3: Zstd compression level
- bit 4: `test_baseline`
- bit 5: enable `verify`

Return value of `compress_buffer`: `0` = more input needed or output available,
`1` = done, `<0` = error. Each input chunk is consumed once; drain overflow with
empty input rather than resubmitting the chunk.

### Decompression

```c
void* create_decompression_context(uint32_t flags, uint64_t capacity);
void  free_decompression_context(void* context);
int32_t decompress_buffer(
    void*        context,
    const uint8_t* input,      uint64_t input_size,
    bool         input_complete,
    uint8_t*     output,       uint64_t output_size,
    uint64_t*    result_size,
    uint8_t*     error_string, uint64_t error_string_buffer_len
);
```

## Internal Structs

```rust
struct CompressionContext {
    magic: u32,                   // MAGIC_COMPRESSION_CONTEXT = 12345678
    internal: PreflateContainerProcessor,
    output_extra: VecDeque<u8>,   // buffers overflow when C buffer is too small
}
struct DecompressionContext {
    magic: u32,                   // MAGIC_DECOMRESSION_CONTEXT = 87654321
    internal: RecreateContainerProcessor,
    output_extra: VecDeque<u8>,
}
```

Magic numbers check context type but do not make dangling or arbitrary pointers
safe. Callers must provide live contexts and valid buffers.

## Safety Notes

- Exported functions use `#[unsafe(no_mangle)]`, unsafe pointer operations, and
  `Box::from_raw` for context ownership.
- `catch_unwind_result()` wraps creation and buffer-processing operations, not
  context freeing or statistics retrieval. Do not assume every export catches panics.
- Keep unsafe operations confined to the FFI layer; core/container forbid unsafe code.

## Build Output

`cdylib` — produces `preflate_rs_0_8.dll` on Windows.
