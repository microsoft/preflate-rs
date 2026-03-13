# preflate-container

File-level scanning and re-compression pipeline for the preflate-rs workspace.

This crate handles real-world binary files that contain embedded DEFLATE streams — ZIP archives, PNG images, JPEG files, and arbitrary binary blobs. It scans input bytes for DEFLATE stream boundaries, passes each stream through the [`preflate`](../preflate/) core for analysis, and packages everything into a Zstd-compressed container format that can be fully reconstructed to the original byte-for-byte input.

[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

## Features

- Detects and processes raw DEFLATE, zlib-wrapped, PNG IDAT, ZIP, and JPEG streams
- Optionally re-encodes PNG images as lossless WebP for additional savings
- JPEG files are re-compressed using [Lepton](https://github.com/microsoft/lepton_jpeg_rust)
- Non-DEFLATE bytes are passed through as literal blocks
- Streaming API with bounded memory use regardless of input size
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

### Streaming

Both processors implement the `ProcessBuffer` trait for incremental use:

```rust
use preflate_container::{PreflateContainerProcessor, RecreateContainerProcessor, ProcessBuffer};

// Compression
let mut compressor = PreflateContainerProcessor::new(&config);
compressor.process_buffer(&input_chunk, input_complete, &mut output)?;
let stats = compressor.stats();

// Decompression
let mut decompressor = RecreateContainerProcessor::new();
decompressor.process_buffer(&container_chunk, input_complete, &mut output)?;
```

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
    /// Minimum input buffer size before scanning begins. Default: 1 MB.
    pub min_chunk_size: usize,

    /// Maximum DEFLATE stream size to process. Larger streams are passed through
    /// as literals. Default: 64 MB.
    pub max_chunk_size: usize,

    /// Global cap on total plaintext held in memory. Default: 512 MB.
    pub total_plain_text_limit: u64,

    /// Per-chunk plaintext memory limit. Default: 128 MB.
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
    pub deflate_compressed_size: u64,  // Original DEFLATE bytes
    pub zstd_compressed_size: u64,     // Final container size
    pub uncompressed_size: u64,        // Total plaintext bytes
    pub overhead_bytes: u64,           // Corrections blob size
    pub hash_algorithm: HashAlgorithm, // Detected compressor family
    pub zstd_baseline_size: u64,       // Raw Zstd-only size (if measured)
}
```

## Container Format

The output is a self-describing binary format (version 2). Framing bytes are written raw; block payloads go through a single persistent Zstd encoder:

```
[0x02]                           ← format version byte

For each block:
  [type_byte]                    ← block kind + compression flag
  [varint: content_length]
  [content_bytes]                ← Zstd-compressed or raw, depending on type
```

Block types:

| Block | Description |
|---|---|
| Literal | Raw input bytes that contain no DEFLATE stream |
| Deflate | A DEFLATE stream: corrections + plaintext (Zstd) |
| PNG | PNG IDAT stream with chunk metadata (Zstd, or WebP if enabled) |
| Deflate-continue | Continuation of a previous DEFLATE stream |
| JPEG/Lepton | Lepton-recompressed JPEG (raw, bypasses Zstd) |
| WebP | PNG stored as lossless WebP (raw, bypasses Zstd) |

The Zstd encoder is flushed after each block payload so each block is independently decodable, while the persistent encoder context maintains cross-block history for better compression.

## Stream Detection

The scanner (`scan_deflate.rs`) identifies DEFLATE stream boundaries by looking for:

- **zlib headers** — CMF/FLG byte pair validation
- **gzip markers** — `\x1f\x8b` magic
- **PNG signatures** — IHDR/IDAT chunk structure
- **ZIP local file headers** — `PK\x03\x04` magic
- **JPEG markers** — SOI/APP0 structure

Non-DEFLATE regions between streams are emitted as literal blocks.

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `webp` | enabled | Re-encode PNG images as lossless WebP |

## Constraints

- **No unsafe code** — `#![forbid(unsafe_code)]`
- Minimum Rust version: **1.89**, Edition **2024**
