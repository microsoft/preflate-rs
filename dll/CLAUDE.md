# dll (preflate_rs_0_7)

C-compatible DLL for .NET interop. Exposes a streaming compress/decompress API as
`extern "C"` functions. The version number is baked into the crate name
(`preflate_rs_0_7`) for binary compatibility.

## Exported C API (`src/unmanaged_api.rs`)

### Compression

```c
void* create_compression_context(uint32_t flags);
void  free_compression_context(void* context);
int32_t compress_buffer(
    void*        context,
    const uint8_t* input,      size_t input_size,
    bool         input_complete,
    uint8_t*     output,       size_t output_size,
    size_t*      result_size,
    char*        error_string, size_t error_string_buffer_len
);
void get_compression_stats(void* context, /* stat out-params */);
```

`flags` encoding:
- bits 0–4: Zstd compression level
- bit 5: `test_baseline`
- bit 6: `verify`

Return value of `compress_buffer`: `0` = more output available, `1` = done, `<0` = error.

### Decompression

```c
void* create_decompression_context(uint32_t flags, size_t capacity);
void  free_decompression_context(void* context);
int32_t decompress_buffer(
    void*        context,
    const uint8_t* input,      size_t input_size,
    bool         input_complete,
    uint8_t*     output,       size_t output_size,
    size_t*      result_size,
    char*        error_string, size_t error_string_buffer_len
);
```

## Internal Structs

```rust
struct CompressionContext {
    magic: u32,                   // MAGIC_COMPRESSION_CONTEXT = 0x4B3CFF2E
    internal: PreflateContainerProcessor,
    output_extra: VecDeque<u8>,   // buffers overflow when C buffer is too small
}
struct DecompressionContext {
    magic: u32,                   // MAGIC_DECOMPRESSION_CONTEXT = 0x053D2AB1
    internal: RecreateContainerProcessor,
    output_extra: VecDeque<u8>,
}
```

Magic numbers are validated on every call to catch dangling/wrong pointer bugs.

## Safety Notes

- Uses `#[unsafe(no_mangle)]` on exported functions — the only place in the workspace
  where `unsafe` appears (required for C FFI entry points).
- `catch_unwind_result()` wraps every entry point to prevent panics crossing the FFI boundary.
- All other code in the crate remains safe Rust.

## Build Output

`cdylib` — produces `preflate_rs_0_7.dll` on Windows.
