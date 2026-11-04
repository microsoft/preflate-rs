# preflate_rs_0_8

C-compatible DLL exposing the preflate-rs container pipeline for .NET interop.

The DLL name encodes the library's `0_8` release family, not the container's wire
version (currently 3). Different release families can coexist, but the developing
0.8 format can still change incompatibly without renaming the DLL. See the
[core format notes](../preflate/README.md#encoding-format).

## Exported API

The DLL exports a streaming compress/decompress API as `extern "C"` functions.

### Compression

```c
// Create a compression context.
// flags bits 0-3: Zstd compression level (0-14)
// flags bit  4:   measure baseline Zstd-only size (for stats)
// flags bit  5:   enable round-trip verification
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

### Decompression

```c
// Create a decompression context.
// flags: currently ignored; capacity: initial processing buffer capacity.
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

1. Call `compress_buffer` / `decompress_buffer` with a chunk of input.
2. If `result_size > 0`, consume the output bytes.
3. If return value is `0`, supply the next input chunk or drain buffered output
   with empty input. Do not resubmit an already supplied chunk.
4. When all input has been fed, set `input_complete = true`.
5. Continue calling until return value is `1` (done).

The DLL buffers any output that does not fit in the provided output buffer internally, so the output buffer can be any convenient size.

## Safety

- Context magic values (12345678 for compression, 87654321 for decompression)
  check context type; they cannot validate dangling or arbitrary pointers.
  Callers must provide live contexts and valid buffers, and free each context once.
- Context creation and buffer processing catch panics. Freeing contexts and
  retrieving statistics do not; invalid pointers or contexts remain caller errors.
- Error messages are copied as UTF-8 into the caller-provided buffer with null termination.
- Buffer lengths must fit the platform's `usize`; mutable buffers and output
  parameters must not alias each other or the input. `result_size` is required.
  Null input/output pointers are treated as empty buffers. Compression permits a
  null error buffer; decompression requires a valid non-null error buffer, even
  at zero length. See each exported function's Rustdoc safety contract.
- Core and container crates forbid unsafe code; unsafe pointer operations are
  confined to the DLL FFI layer. See [AGENTS.md](AGENTS.md).

## Building

```shell
cargo build --release -p preflate_rs_0_8
# Output: target/release/preflate_rs_0_8.dll (Windows)
```

Windows MSVC Cargo builds enable Control Flow Guard through the workspace
configuration. The Azure release pipeline additionally sets `/Qspectre /sdl`;
local release builds do not automatically set those native compiler flags.
