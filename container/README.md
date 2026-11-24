# preflate-container

File-level scanning and re-compression pipeline for the preflate-rs workspace.

This crate handles real-world binary files that contain embedded DEFLATE streams — ZIP archives, PNG images, JPEG files, and arbitrary binary blobs. It scans input bytes for DEFLATE stream boundaries, passes each stream through the [`preflate`](../preflate/) core for analysis, and packages everything into a Zstd-compressed container format that can be fully reconstructed to the original byte-for-byte input.

[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

## Features

- Detects DEFLATE through zlib, gzip, PNG IDAT and ZIP signatures, and processes JPEG files
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
let mut compressor = PreflateContainerProcessor::new(&config, 9, false);
compressor.process_buffer(&input_chunk, input_complete, &mut output)?;
let stats = compressor.stats();

// Decompression
let mut decompressor = RecreateContainerProcessor::new(128 * 1024 * 1024);
decompressor.process_buffer(&container_chunk, input_complete, &mut output)?;
```

Whole-file helpers read the entire input into memory. Use the streaming processors
or `ProcessBuffer::copy_to_end` for bounded input processing.

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

    /// Global cap on total plaintext processed, not simultaneous memory. Default: 512 MB.
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

The output is a self-describing binary format (version 3). Version 3 uses the
developing 0.8 corrections format described in the [core README](../preflate/README.md#encoding-format);
versions 1 and 2 are incompatible and rejected. Framing bytes are written raw;
Zstd-compressed block payloads share a single persistent encoder:

```
[0x03]                           ← format version byte

For each block:
  [type_byte]                    ← block kind + compression flag
  [varint: content_length]
  [content_bytes]                ← Zstd-compressed or raw, depending on type

[0xFF] [crc32_le: 4 bytes]       ← final CRC-32 of original input, no length varint
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

The Zstd encoder is flushed after each block payload. Decode flush segments in
sequence with the persistent decoder: they depend on preceding history and are
not independently decodable frames.
The final raw CRC block verifies the reconstructed output.
See [AGENTS.md](AGENTS.md) for the wire layout and finalization rules.

## Stream Detection

The scanner (`scan_deflate.rs`) identifies DEFLATE stream boundaries by looking for:

- **zlib headers** — CMF/FLG byte pair validation
- **gzip markers** — `\x1f\x8b` magic
- **PNG signatures** — IHDR/IDAT chunk structure
- **ZIP local file headers** — `PK\x03\x04` magic
- **JPEG markers** — SOI/APP0 structure

Non-DEFLATE regions between streams are emitted as literal blocks.
The compression scanner does not discover unwrapped raw DEFLATE in arbitrary
data; wrapper bytes are preserved outside the transformed payload.

## Diagnostics

`scan_deflate_diagnostics` and `scan_deflate_diagnostics_with_options` analyze
wrapper signatures without Zstd, WebP or Lepton. Raw mode instead attempts one
DEFLATE stream at offset zero. Candidate and plaintext limits bound the work;
the callback receives successful streams and failures, including possible
signature false positives. Verification follows `PreflateConfig::verify_compression`.

The optional `diagnostics` feature adds bounded traces and
`diagnostic_deflate_payload`, which extracts a saved payload range or assembles
PNG IDAT chunks. The [scanner CLI](../README.md#scanning-a-document-corpus-sqlite-and-json-diagnostics-no-zstd)
uses these APIs for read-only reports.

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `webp` | enabled | Re-encode PNG images as lossless WebP |
| `diagnostics` | disabled | Detailed traces and saved-payload extraction; enables core diagnostics |

## Constraints

- **No unsafe code** — `#![forbid(unsafe_code)]`
- Minimum Rust version: **1.89**, Edition **2024**
