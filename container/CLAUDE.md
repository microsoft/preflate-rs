# container (preflate-container)

Scans binary files (ZIP, PNG, PDF, JPEG) for DEFLATE streams, orchestrates the
preflate + Zstd pipeline, and reassembles the output. Only format version 2 exists
(v1 was removed).

## Public API (`lib.rs`)

```rust
// Compress a file/buffer containing embedded DEFLATE streams
PreflateContainerProcessor::new(config, level, test_baseline) -> Self
impl ProcessBuffer for PreflateContainerProcessor {
    fn process_buffer(&mut self, input: &[u8], input_complete: bool) -> Result<Vec<u8>>;
}

// Decompress a preflate container back to the original file
RecreateContainerProcessor::new(capacity) -> Self
impl ProcessBuffer for RecreateContainerProcessor {
    fn process_buffer(&mut self, input: &[u8], input_complete: bool) -> Result<Vec<u8>>;
}

// DLL helper: wraps process_buffer to respect a max output size per call
fn process_limited_buffer(processor, input, input_complete, max_output) -> Result<(Vec<u8>, bool)>;

// Stats after compression
PreflateContainerProcessor::get_stats() -> &PreflateStats
```

`PreflateContainerConfig` holds knobs like `max_chain_length`, `verify_compression`, etc.

## Wire Format (v2 only)

### Outer framing (always raw / uncompressed)

```
[0x02]                             ← COMPRESSED_WRAPPER_VERSION_2 (1 byte, raw)

Repeat for each block:
  [type]                           ← block type byte (1 byte, raw) — see bit-field below
  [varint(content_len)]            ← byte count of what follows (1–5 bytes, raw)
  [content_bytes × content_len]    ← meaning depends on type (see below)
```

All framing bytes (`type`, `varint`) are written directly to the output stream —
they are **never** inside the Zstd encoder.

### Block type byte bit-field

Each block type byte encodes two fields:

```
Bit 7-6  BLOCK_COMPRESSION_*   00 = none/raw   01 = Zstd   10-11 = reserved
Bit 5-0  BLOCK_TYPE_*          block content kind (0–63)
```

Mask constants (defined in `container_processor.rs`):

| Constant | Value | Meaning |
|---|---|---|
| `BLOCK_COMPRESSION_MASK` | `0xC0` | extracts bits 7–6 |
| `BLOCK_TYPE_MASK` | `0x3F` | extracts bits 5–0 |
| `BLOCK_COMPRESSION_NONE` | `0x00` | content is raw (not Zstd) |
| `BLOCK_COMPRESSION_ZSTD` | `0x40` | content is a Zstd flush segment |

### Block content kinds and combined wire values

| `BLOCK_TYPE_*` | Value | Combined wire byte | Description |
|---|---|---|---|
| `BLOCK_TYPE_LITERAL` | `0x00` | `0x40` | Raw input bytes with no detectable DEFLATE stream |
| `BLOCK_TYPE_DEFLATE` | `0x01` | `0x41` | A raw/zlib DEFLATE stream (start of a new stream) |
| `BLOCK_TYPE_PNG` | `0x02` | `0x42` | A PNG IDAT stream stored without WebP |
| `BLOCK_TYPE_DEFLATE_CONTINUE` | `0x03` | `0x43` | Continuation of a DEFLATE stream that spanned a chunk boundary |
| `BLOCK_TYPE_JPEG_LEPTON` | `0x04` | `0x04` | JPEG re-compressed with Lepton; bypasses Zstd entirely |
| `BLOCK_TYPE_WEBP` | `0x05` | `0x05` | PNG image stored as WebP lossless; bypasses Zstd entirely |
| `BLOCK_TYPE_EOS` | `0x3F` | `0x7F` | The `encoder.finish()` bytes that close the Zstd stream |

### Zstd encoder/decoder lifecycle

- A **single persistent `zstd::stream::write::Encoder`** is created once and shared across
  all Zstd-compressed blocks (compression bits `0x40`).
- After writing each block's inner payload into the encoder, `encoder.flush()` is called,
  which emits a Zstd `ZSTD_e_flush` segment. Those bytes are what get stored as
  `content_bytes` in the outer framing.
- Each flush segment is decodable in sequence: the decoder is a persistent
  `zstd::stream::raw::Decoder` that maintains cross-block history, so compression
  quality benefits from all previously seen blocks.
- The `BLOCK_TYPE_EOS` (`0x7F`) end-of-stream block carries the `encoder.finish()` output
  that closes the Zstd frame cleanly. No decompressed bytes are expected from it.

### Inner payload layout (inside Zstd, after decompression)

**`BLOCK_TYPE_LITERAL` (wire `0x40`)**
```
varint(data_len)
data[data_len]         ← verbatim bytes from the original input
```

**`BLOCK_TYPE_DEFLATE` (wire `0x41`) and `BLOCK_TYPE_DEFLATE_CONTINUE` (wire `0x43`)**
```
varint(corrections_len)
varint(plaintext_len)
corrections[corrections_len]   ← CABAC-encoded differences from predicted tokens
plaintext[plaintext_len]       ← uncompressed data
```
`BLOCK_TYPE_DEFLATE_CONTINUE` has the same layout; the decoder reuses the
`RecreateStreamProcessor` state from the preceding `BLOCK_TYPE_DEFLATE` block.

**`BLOCK_TYPE_PNG` (wire `0x42`) — non-WebP path**
```
varint(corrections_len)
varint(plaintext_len)
IdatContents metadata:
  varint(chunk_size_1) … varint(chunk_size_N) varint(0)   ← IDAT chunk size list (0-terminated)
  zlib_header[2]
  addler32[4]
  0xFF                                                     ← sentinel: no png_header present
corrections[corrections_len]
plaintext[plaintext_len]         ← raw unfiltered pixel data
```

### Raw block payload layout (outside Zstd)

**`BLOCK_TYPE_JPEG_LEPTON` (wire `0x04`)**
```
lepton_bytes[content_len]      ← Lepton-compressed JPEG; decoded by lepton_jpeg::decode_lepton()
```

**`BLOCK_TYPE_WEBP` (wire `0x05`)**
```
varint(corrections_len)
varint(webp_data_len)
IdatContents metadata:
  varint(chunk_size_1) … varint(chunk_size_N) varint(0)
  zlib_header[2]
  addler32[4]
  color_type[1]                                ← PngColorType (RGB=2, RGBA=6)
  varint(width)
  varint(height)
filters[height]                ← PNG row filter bytes (one per row)
corrections[corrections_len]
webp_data[webp_data_len]       ← WebP lossless encoded pixel data
```
On decode, the WebP bytes are decompressed back to pixels, PNG filters are re-applied,
and the result is re-deflated using the corrections to recreate the original IDAT stream.

## Idempotent Finalization (important bug history)

`process_buffer` may be called with `input_complete=true` multiple times (DLL pattern).
The finalization block must guard against double-finalization:

```rust
if input_complete && !self.input_complete {   // NOT just `if input_complete`
    self.input_complete = true;
    // ... encoder.take().unwrap()
}
```

## Module Layout

```
src/
  lib.rs                  ← public types and re-exports
  container_processor.rs  ← PreflateContainerProcessor, RecreateContainerProcessor,
                            V2BlockInfo enum, process_v2_compressed_block()
  scan_deflate.rs         ← locates DEFLATE stream boundaries in raw bytes
                            identifies: raw deflate, zlib-wrapped, PNG IDAT, ZIP, JPEG, PDF
  idat_parse.rs           ← extracts / reassembles PNG IDAT chunks; parses IHDR
  pdf_parse.rs            ← detects PDF FlateDecode compressed object streams
  zstd_compression.rs     ← ZstdCompressContext / ZstdDecompressContext (internal)
  scoped_read.rs          ← bounded reader adapter
  utils.rs                ← process_limited_buffer() and other helpers
```

## Key Internal Types

| Type | Purpose |
|---|---|
| `V2BlockInfo` | `Compressed(u8)` or `Jpeg(Vec<u8>)` — one entry per scanned block |
| `MeasureWriteSink` | `pub(crate)` sink that counts bytes; used for baseline measurement |
| `PreflateStats` | `deflate_compressed_size`, `zstd_compressed_size`, `zstd_baseline_size`, … |

## Features

- `webp` (default-enabled) — allows PNG images to be stored as WebP instead of lossless PNG,
  using the `webp` crate.

## Dependencies of Note

- `lepton_jpeg` (0.5.1) — JPEG blocks are recompressed with Lepton, not Zstd.
- `zstd` (0.13) — single persistent encoder across all non-JPEG blocks.
- `preflate-rs` — core analysis/reconstruction (path dependency).

## Constraints

- `#![forbid(unsafe_code)]` enforced.
- `main.rs` exists but is a stub; this crate is a library.
