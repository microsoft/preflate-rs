# preflate-container

File-level scanning and re-compression pipeline for the preflate-rs workspace.

This crate handles real-world binary files that contain embedded DEFLATE streams — ZIP archives, PNG images, JPEG files, and arbitrary binary blobs. It scans input bytes for DEFLATE stream boundaries, passes each stream through the [`preflate`](../preflate/) core for analysis, and packages everything into a Zstd-compressed container format that can be fully reconstructed to the original byte-for-byte input.

[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

## Features

- Detects and processes raw DEFLATE, zlib-wrapped, PNG IDAT, ZIP, and JPEG streams
- Optionally re-encodes PNG images as lossless WebP for additional savings
- JPEG files are re-compressed using [Lepton](https://github.com/microsoft/lepton_jpeg_rust)
- Non-DEFLATE bytes are passed through as literal blocks
- Streaming API with configurable input and plaintext processing thresholds
- Single persistent Zstd encoder for cross-block compression quality

## API

### Whole-file (simple)

```rust
use preflate_container::{
    preflate_whole_into_container, recreate_whole_from_container, PreflateContainerConfig,
};

let config = PreflateContainerConfig::default();

// Compress: scan file → extract DEFLATE streams → write container
preflate_whole_into_container(&config, &mut input_reader, &mut output_writer)?;

// Decompress: read container → recreate DEFLATE streams → original file
recreate_whole_from_container(&mut container_reader, &mut output_writer)?;
```

These convenience helpers read their entire input into memory. Use the
streaming processors below when the caller needs incremental input handling.

### Streaming

Both processors implement the `ProcessBuffer` trait for incremental use:

```rust
use preflate_container::{PreflateContainerProcessor, RecreateContainerProcessor, ProcessBuffer};

// Compression
let mut compressor = PreflateContainerProcessor::new(&config, 9, false);
compressor.process_buffer(&input_chunk, input_complete, &mut output)?;
let stats = compressor.stats();

// Decompression
let mut decompressor = RecreateContainerProcessor::new(128 * 1024 * 1024);
decompressor.process_buffer(&container_chunk, input_complete, &mut output)?;
```

The decoder's capacity must be nonzero. It controls the maximum input bytes
appended per processing iteration, not a total output size limit.
Once `input_complete` is true, subsequent calls must contain no new input and
must keep it true.

### DLL / fixed-size output buffer

For C FFI use where the output buffer size is fixed, `process_limited_buffer` handles overflow internally:

```rust
use preflate_container::process_limited_buffer;
use std::collections::VecDeque;

let mut overflow = VecDeque::new();
let (done, written) = process_limited_buffer(
    &mut compressor,
    &input,
    input_complete,
    &mut output_buffer,
    &mut overflow,
)?;
```

## Configuration

```rust
pub struct PreflateContainerConfig {
    /// Minimum input buffer size before scanning begins. Default: 1 MiB.
    pub min_chunk_size: usize,

    /// Buffered-input threshold for waiting on incomplete candidates.
    /// Beyond it, incomplete candidates fall back to literals. Default: 64 MiB.
    pub max_chunk_size: usize,

    /// Cumulative plaintext processing budget per container. Default: 512 MiB.
    /// Once exceeded, further candidates are not expanded.
    pub total_plain_text_limit: u64,

    /// Per-chunk plaintext processing limit. Default: 128 MiB.
    pub chunk_plain_text_limit: usize,

    /// Verify round-trip correctness after each stream. Default: true.
    pub validate_compression: bool,

    /// Hash chain traversal limit passed to the core engine. Default: 4096.
    pub max_chain_length: u32,
}
```

## Statistics

After compression, `stats()` returns a `PreflateStats` struct:

```rust
pub struct PreflateStats {
    pub deflate_compressed_size: u64,  // Total original input bytes
    pub zstd_compressed_size: u64,     // Encoded payload bytes, excluding outer framing
    pub uncompressed_size: u64,        // Expanded bytes counted for recognized streams
    pub overhead_bytes: u64,           // Accumulated corrections bytes
    pub hash_algorithm: HashAlgorithm, // Most recently recorded compressor family
    pub zstd_baseline_size: u64,       // Raw Zstd-only size (if measured)
}
```

Use the actual output length for the complete container size; the payload
counter does not include all framing bytes.

## Container Format

The output is a self-describing binary format (version 2). Framing bytes are written raw; block payloads go through a single persistent Zstd encoder:

```
[0x02]                           ← format version byte

For each block:
  [type_byte]                    ← block kind + compression flag
  [varint: content_length]
  [content_bytes]                ← Zstd-compressed or raw, depending on type

[0xFF][crc32_le: 4 bytes]         ← CRC-32 of the original input; no length field
```

### Block type byte

Bits 7-6 encode compression (`00` = raw, `01` = Zstd; `10` and `11` are
reserved). Bits 5-0 identify the content kind. The constants are defined in
[`container_common.rs`](src/container_common.rs).

| Block | Kind | Wire byte | Description |
|---|---|---|---|
| Literal | `0x00` | `0x40` | Original bytes without a detected DEFLATE stream, inside Zstd |
| Deflate | `0x01` | `0x41` | Corrections and plaintext for a new DEFLATE stream, inside Zstd |
| PNG | `0x02` | `0x42` | PNG IDAT metadata, corrections, and plaintext, inside Zstd |
| Deflate-continue | `0x03` | `0x43` | Continuation using the previous stream's reconstruction state, inside Zstd |
| JPEG/Lepton | `0x04` | `0x04` | Lepton-compressed JPEG, outside Zstd |
| WebP | `0x05` | `0x05` | PNG metadata, corrections, and lossless WebP, outside Zstd |

All framing bytes are raw, never inside Zstd. A single persistent encoder is
flushed after each Zstd payload; the decoder must consume these flush segments
in sequence with persistent history. They are not independent Zstd frames.
JPEG and WebP payloads bypass that encoder. The CRC end block terminates the
container.

### Payload layouts

Lengths below use the varint helpers in `container_common.rs`.

```text
Literal (after Zstd decoding):
  varint(data_len), data[data_len]

Deflate / Deflate-continue (after Zstd decoding):
  varint(corrections_len), varint(plaintext_len)
  corrections[corrections_len], plaintext[plaintext_len]

PNG (after Zstd decoding):
  varint(corrections_len), varint(plaintext_len)
  IDAT metadata
  corrections[corrections_len], plaintext[plaintext_len]

JPEG/Lepton (raw):
  lepton_bytes[content_length]

WebP (raw):
  varint(corrections_len), varint(webp_data_len)
  IDAT metadata, filters[height]
  corrections[corrections_len], webp_data[webp_data_len]
```

IDAT metadata records a zero-terminated list of varint chunk sizes, the two-byte
zlib header, and the four-byte Adler-32. Non-WebP PNGs use a `0xFF` sentinel
instead of an image header. WebP metadata records the color type and varint
width and height. See [`idat_parse.rs`](src/idat_parse.rs) for serialization.
Reconstruction restores the original PNG chunk boundaries and compression.

### Finalization

Callers draining fixed-size output buffers may call `process_buffer` repeatedly
with `input_complete = true`. Finalization must remain idempotent: guard it with
`input_complete && !self.input_complete`, not just `input_complete`, so the
encoder and CRC end block are finalized only once.

## Source map

- [`container_common.rs`](src/container_common.rs): configuration, statistics,
  `ProcessBuffer`, block constants, and varint helpers.
- [`container_write.rs`](src/container_write.rs): scanning and container encoding.
- [`container_read.rs`](src/container_read.rs): container decoding and reconstruction.
- [`scan_deflate.rs`](src/scan_deflate.rs): stream detection.
- [`idat_parse.rs`](src/idat_parse.rs): PNG IDAT extraction and reassembly.
- [`scoped_read.rs`](src/scoped_read.rs): bounded reader adapter.
- [`utils.rs`](src/utils.rs): fixed-size output buffering and test helpers.

## Stream Detection

The scanner (`scan_deflate.rs`) identifies DEFLATE stream boundaries by looking for:

- **zlib headers** — CMF/FLG byte pair validation
- **gzip markers** — `\x1f\x8b` magic
- **PNG signatures** — IHDR/IDAT chunk structure
- **ZIP local file headers** — `PK\x03\x04` magic
- **JPEG markers** — SOI/APP0 structure

Non-DEFLATE regions between streams are emitted as literal blocks.
PDF-specific scanning is not implemented.

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `webp` | enabled | Re-encode PNG images as lossless WebP |

## Constraints

- **No unsafe code** — `#![forbid(unsafe_code)]`
- Toolchain requirements and contributor commands are in the [project README](../README.md#requirements).
