use std::io::{BufRead, Read, Write};

use preflate_rs::{AddContext, HashAlgorithm, PreflateConfig, Result};

/// Configuration for the deflate process
#[derive(Debug, Clone)]
pub struct PreflateContainerConfig {
    /// As we scan for deflate streams, we need to have a minimum memory
    /// chunk to process. We scan this chunk for deflate streams and at least
    /// deflate one block has to fit into a chunk for us to recognize it.
    pub min_chunk_size: usize,

    /// The maximum size of a deflate or PNG compressed block we will consider. If
    /// a deflate stream is larger than this, we will not decompress it and
    /// just write it out as a literal block.
    pub max_chunk_size: usize,

    /// The maximum overall size of plain text that we will compress. This is
    /// global to the entire container and limits the amount of processing that
    /// we will do to avoid running out of CPU time on a single file. Once we
    /// hit this limit, we will stop looking for deflate streams and just write
    /// out the rest of the data as literal blocks.
    pub total_plain_text_limit: u64,

    /// The maximum size of a plain text chunk that we will decompress at a time. This limits
    /// the memory usage of the decompression process.
    pub chunk_plain_text_limit: usize,

    /// true if we should verify that the decompressed data can be recompressed to the same bytes.
    /// This is important since there may be corner cases where the data may not yield the same bytes.
    ///
    /// If this is false, we will not verify the decompressed data and just write it out as is and it is
    /// up to the caller to make sure the data is valid. In no case should you just assume that you
    /// can get the same data back without verifying it.
    pub validate_compression: bool,

    /// Maximum number of lookups we will do in the hash chain. This will limit the CPU time we spend
    /// on deflate stream processing but also means that we won't be able to recompress deflate streams
    /// that were compressed with a larger chain length (eg level 9 has 4096).
    pub max_chain_length: u32,
}

impl Default for PreflateContainerConfig {
    fn default() -> Self {
        PreflateContainerConfig {
            min_chunk_size: 1024 * 1024,
            max_chunk_size: 64 * 1024 * 1024,
            total_plain_text_limit: 512 * 1024 * 1024,
            chunk_plain_text_limit: 128 * 1024 * 1024,
            max_chain_length: 4096,
            validate_compression: true,
        }
    }
}

impl PreflateContainerConfig {
    pub fn preflate_config(&self) -> PreflateConfig {
        PreflateConfig {
            max_chain_length: self.max_chain_length,
            plain_text_limit: self.chunk_plain_text_limit,
            verify_compression: self.validate_compression,
        }
    }
}

pub(crate) const COMPRESSED_WRAPPER_VERSION_2: u8 = 2;

// Bit-field masks for the block type byte
// Bits 7-6: compression algorithm  Bits 5-0: block content kind
pub(crate) const BLOCK_COMPRESSION_MASK: u8 = 0xC0;
pub(crate) const BLOCK_TYPE_MASK: u8 = 0x3F;

// Compression algorithms (top 2 bits)
pub(crate) const BLOCK_COMPRESSION_NONE: u8 = 0x00;
pub(crate) const BLOCK_COMPRESSION_ZSTD: u8 = 0x40;

// Block content kinds (bottom 6 bits)
pub(crate) const BLOCK_TYPE_LITERAL: u8 = 0x00;
pub(crate) const BLOCK_TYPE_DEFLATE: u8 = 0x01;
pub(crate) const BLOCK_TYPE_PNG: u8 = 0x02;
pub(crate) const BLOCK_TYPE_DEFLATE_CONTINUE: u8 = 0x03;
pub(crate) const BLOCK_TYPE_JPEG_LEPTON: u8 = 0x04;
pub(crate) const BLOCK_TYPE_WEBP: u8 = 0x05;

pub(crate) fn write_varint(destination: &mut impl Write, value: u32) -> std::io::Result<()> {
    let mut value = value;
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        destination.write_all(&[byte])?;
        if value == 0 {
            break;
        }
    }

    Ok(())
}

pub(crate) fn read_varint(source: &mut impl Read) -> std::io::Result<u32> {
    let mut result = 0;
    let mut shift = 0;
    loop {
        let mut byte = [0u8; 1];
        source.read_exact(&mut byte)?;
        let byte = byte[0];
        result |= ((byte & 0x7F) as u32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok(result)
}

#[test]
fn test_variant_roundtrip() {
    let values = [
        0, 1, 127, 128, 255, 256, 16383, 16384, 2097151, 2097152, 268435455, 268435456, 4294967295,
    ];

    let mut buffer = Vec::new();
    for &v in values.iter() {
        write_varint(&mut buffer, v).unwrap();
    }

    let mut buffer = &buffer[..];

    for &v in values.iter() {
        assert_eq!(v, read_varint(&mut buffer).unwrap());
    }
}

/// Statistics about the preflate process
#[derive(Debug, Copy, Clone, Default)]
pub struct PreflateStats {
    pub deflate_compressed_size: u64,
    pub zstd_compressed_size: u64,
    pub uncompressed_size: u64,
    pub overhead_bytes: u64,
    pub hash_algorithm: HashAlgorithm,
    pub zstd_baseline_size: u64,
}

/// Processes an input buffer and writes the output to a writer
pub trait ProcessBuffer {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
    ) -> Result<()>;

    #[cfg(test)]
    fn process_vec(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut writer = Vec::new();

        self.copy_to_end(&mut std::io::Cursor::new(&input), &mut writer)
            .context()?;

        Ok(writer)
    }

    #[cfg(test)]
    fn process_vec_size(&mut self, input: &[u8], read_chunk_size: usize) -> Result<Vec<u8>> {
        let mut writer = Vec::new();

        self.copy_to_end_size(
            &mut std::io::Cursor::new(&input),
            &mut writer,
            read_chunk_size,
        )
        .context()?;

        Ok(writer)
    }

    /// Reads everything from input and writes it to the output.
    /// Wraps calls to process buffer
    fn copy_to_end(&mut self, input: &mut impl BufRead, output: &mut impl Write) -> Result<()> {
        self.copy_to_end_size(input, output, 1024 * 1024)
    }

    /// Reads everything from input and writes it to the output.
    /// Wraps calls to process buffer
    fn copy_to_end_size(
        &mut self,
        input: &mut impl BufRead,
        output: &mut impl Write,
        read_chunk_size: usize,
    ) -> Result<()> {
        let mut input_complete = false;
        loop {
            let buffer: &[u8];
            if input_complete {
                buffer = &[];
            } else {
                buffer = input.fill_buf().context()?;
                if buffer.len() == 0 {
                    input_complete = true
                }
            };

            if input_complete {
                self.process_buffer(&[], true, output).context()?;
                break;
            } else {
                // process buffer a piece at a time to avoid overflowing memory
                let mut amount_read = 0;
                while amount_read < buffer.len() {
                    let chunk_size = (buffer.len() - amount_read).min(read_chunk_size);

                    self.process_buffer(
                        &buffer[amount_read..amount_read + chunk_size],
                        false,
                        output,
                    )
                    .context()?;

                    amount_read += chunk_size;
                }

                let buflen = buffer.len();
                input.consume(buflen);
            }
        }

        Ok(())
    }

    fn stats(&self) -> PreflateStats {
        PreflateStats::default()
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::io::Write;

    use preflate_rs::{AddContext, Result};

    use crate::container_common::{
        BLOCK_COMPRESSION_MASK, BLOCK_COMPRESSION_NONE, BLOCK_COMPRESSION_ZSTD, BLOCK_TYPE_DEFLATE,
        BLOCK_TYPE_DEFLATE_CONTINUE, BLOCK_TYPE_JPEG_LEPTON, BLOCK_TYPE_LITERAL, BLOCK_TYPE_MASK,
        BLOCK_TYPE_PNG, BLOCK_TYPE_WEBP, COMPRESSED_WRAPPER_VERSION_2, PreflateContainerConfig,
        ProcessBuffer, read_varint,
    };
    use crate::container_read::RecreateContainerProcessor;
    use crate::container_write::PreflateContainerProcessor;

    pub struct NopProcessBuffer {}

    impl ProcessBuffer for NopProcessBuffer {
        fn process_buffer(
            &mut self,
            input: &[u8],
            _input_complete: bool,
            writer: &mut impl Write,
        ) -> Result<()> {
            writer.write_all(input).context()?;

            Ok(())
        }
    }

    fn roundtrip_deflate_chunks(filename: &str) {
        use crate::utils::assert_eq_array;

        let f = crate::utils::read_file(filename);

        println!("Processing file: {}", filename);

        let mut expanded = Vec::new();
        let mut ctx =
            PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false);
        ctx.copy_to_end(&mut std::io::Cursor::new(&f), &mut expanded)
            .unwrap();

        println!("Recreating file: {}", filename);

        let mut destination = Vec::new();
        let mut ctx = RecreateContainerProcessor::new(usize::MAX);
        ctx.copy_to_end(&mut std::io::Cursor::new(expanded), &mut destination)
            .unwrap();

        assert_eq_array(&destination, &f);
    }

    #[test]
    fn roundtrip_skip_length_crash() {
        roundtrip_deflate_chunks("skiplengthcrash.bin");
    }

    #[test]
    fn roundtrip_png_chunks() {
        roundtrip_deflate_chunks("treegdi.png");
    }

    #[test]
    fn roundtrip_zip_chunks() {
        roundtrip_deflate_chunks("samplezip.zip");
    }

    #[test]
    fn roundtrip_gz_chunks() {
        roundtrip_deflate_chunks("sample1.bin.gz");
    }

    #[test]
    fn roundtrip_png_chunks2() {
        roundtrip_deflate_chunks("starcontrol.samplesave");
    }

    #[test]
    fn roundtrip_small_chunk() {
        use crate::utils::{assert_eq_array, read_file};

        let original = read_file("pptxplaintext.zip");

        let mut context = PreflateContainerProcessor::new(
            &PreflateContainerConfig {
                min_chunk_size: 100000,
                max_chunk_size: 100000,
                total_plain_text_limit: u64::MAX,
                ..Default::default()
            },
            1,
            false,
        );

        let compressed = context.process_vec_size(&original, 20001).unwrap();

        let mut context = RecreateContainerProcessor::new(usize::MAX);
        let recreated = context.process_vec_size(&compressed, 20001).unwrap();

        assert_eq_array(&original, &recreated);
    }

    #[test]
    fn roundtrip_small_plain_text() {
        use crate::utils::{assert_eq_array, read_file};

        let original = read_file("pptxplaintext.zip");

        let mut context = PreflateContainerProcessor::new(
            &PreflateContainerConfig {
                min_chunk_size: 100000,
                max_chunk_size: 100000,
                total_plain_text_limit: u64::MAX,
                ..Default::default()
            },
            1,
            false,
        );

        let compressed = context.process_vec_size(&original, 2001).unwrap();

        let mut context = RecreateContainerProcessor::new(usize::MAX);
        let recreated = context.process_vec_size(&compressed, 2001).unwrap();

        assert_eq_array(&original, &recreated);
    }

    #[test]
    fn roundtrip_zstd_per_block() {
        use crate::utils::{assert_eq_array, read_file};

        let original = read_file("samplezip.zip");

        let mut context =
            PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false);

        let compressed = context.process_vec(&original).unwrap();

        let mut context = RecreateContainerProcessor::new(usize::MAX);
        let recreated = context.process_vec(&compressed).unwrap();

        assert_eq_array(&original, &recreated);
    }

    // ── Block type bit-field tests ───────────────────────────────────────────────

    /// Parse the outer framing of a v2 container and return each block's
    /// (compression_bits, block_type_bits) in order, stopping at the 0xFF CRC end block.
    fn parse_wire_block_types(data: &[u8]) -> Vec<(u8, u8)> {
        use byteorder::ReadBytesExt;
        let mut cursor = std::io::Cursor::new(data);
        let version = cursor.read_u8().unwrap();
        assert_eq!(version, COMPRESSED_WRAPPER_VERSION_2);
        let mut blocks = Vec::new();
        while (cursor.position() as usize) < data.len() {
            let type_byte = cursor.read_u8().unwrap();
            if type_byte == 0xFF {
                break; // CRC end block; 4 raw bytes follow but we stop here
            }
            let compression = type_byte & BLOCK_COMPRESSION_MASK;
            let block_type = type_byte & BLOCK_TYPE_MASK;
            blocks.push((compression, block_type));
            let size = read_varint(&mut cursor).unwrap() as u64;
            cursor.set_position(cursor.position() + size);
        }
        blocks
    }

    /// Feed `stream` to the decoder with input_complete=true and assert the
    /// error exit code matches `expected`.
    fn assert_decoder_fails(stream: &[u8], expected: preflate_rs::ExitCode) {
        let mut ctx = RecreateContainerProcessor::new(usize::MAX);
        let mut out = Vec::new();
        let err = ctx
            .process_buffer(stream, true, &mut out)
            .expect_err("expected an error, but decoder returned Ok");
        assert_eq!(
            err.exit_code(),
            expected,
            "wrong exit code for stream {stream:02X?}"
        );
    }

    /// The two masks must partition the byte: non-overlapping and together covering all 8 bits.
    /// Every content-kind constant must sit entirely within BLOCK_TYPE_MASK, and every
    /// compression constant within BLOCK_COMPRESSION_MASK.
    #[test]
    fn test_bit_field_masks_partition_byte() {
        assert_eq!(
            BLOCK_COMPRESSION_MASK | BLOCK_TYPE_MASK,
            0xFF,
            "masks do not cover all bits"
        );
        assert_eq!(
            BLOCK_COMPRESSION_MASK & BLOCK_TYPE_MASK,
            0x00,
            "masks overlap"
        );
        for kind in [
            BLOCK_TYPE_LITERAL,
            BLOCK_TYPE_DEFLATE,
            BLOCK_TYPE_PNG,
            BLOCK_TYPE_DEFLATE_CONTINUE,
            BLOCK_TYPE_JPEG_LEPTON,
            BLOCK_TYPE_WEBP,
        ] {
            assert_eq!(
                kind & BLOCK_COMPRESSION_MASK,
                0,
                "BLOCK_TYPE 0x{kind:02X} bleeds into compression bits"
            );
        }
        for comp in [BLOCK_COMPRESSION_NONE, BLOCK_COMPRESSION_ZSTD] {
            assert_eq!(
                comp & BLOCK_TYPE_MASK,
                0,
                "BLOCK_COMPRESSION 0x{comp:02X} bleeds into type bits"
            );
        }
    }

    /// The combined (compression | kind) wire bytes must match the expected values
    /// documented in CLAUDE.md. This catches accidental constant drift.
    #[test]
    fn test_combined_wire_values() {
        assert_eq!(BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_LITERAL, 0x40);
        assert_eq!(BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_DEFLATE, 0x41);
        assert_eq!(BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_PNG, 0x42);
        assert_eq!(BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_DEFLATE_CONTINUE, 0x43);
        assert_eq!(BLOCK_COMPRESSION_NONE | BLOCK_TYPE_JPEG_LEPTON, 0x04);
        assert_eq!(BLOCK_COMPRESSION_NONE | BLOCK_TYPE_WEBP, 0x05);
    }

    /// Reserved compression bits 0x80 (10xx_xxxx) must be rejected by the decoder.
    #[test]
    fn test_decoder_rejects_reserved_compression_bits_10() {
        assert_decoder_fails(
            &[COMPRESSED_WRAPPER_VERSION_2, 0x80],
            preflate_rs::ExitCode::InvalidCompressedWrapper,
        );
    }

    /// Reserved compression bits 0xC0 (11xx_xxxx) must be rejected by the decoder.
    #[test]
    fn test_decoder_rejects_reserved_compression_bits_11() {
        assert_decoder_fails(
            &[COMPRESSED_WRAPPER_VERSION_2, 0xC0],
            preflate_rs::ExitCode::InvalidCompressedWrapper,
        );
    }

    /// BLOCK_COMPRESSION_NONE | BLOCK_TYPE_LITERAL (0x00) must be rejected:
    /// literal blocks are Zstd-only; there is no raw literal block type.
    #[test]
    fn test_decoder_rejects_raw_literal_block_type() {
        let byte = BLOCK_COMPRESSION_NONE | BLOCK_TYPE_LITERAL; // == 0x00
        assert_decoder_fails(
            &[COMPRESSED_WRAPPER_VERSION_2, byte],
            preflate_rs::ExitCode::InvalidCompressedWrapper,
        );
    }

    /// Any BLOCK_COMPRESSION_NONE byte that is not JPEG_LEPTON or WEBP must be rejected.
    #[test]
    fn test_decoder_rejects_undefined_raw_block_types() {
        // 0x10 is arbitrary: not 0x04 (JPEG) or 0x05 (WEBP)
        let byte = BLOCK_COMPRESSION_NONE | 0x10;
        assert_decoder_fails(
            &[COMPRESSED_WRAPPER_VERSION_2, byte],
            preflate_rs::ExitCode::InvalidCompressedWrapper,
        );
    }

    /// Compressing plain bytes (no embedded DEFLATE streams) must produce a stream
    /// whose first block carries BLOCK_COMPRESSION_ZSTD and BLOCK_TYPE_LITERAL.
    #[test]
    fn test_encoder_literal_block_carries_zstd_compression_bit() {
        let input = vec![0xABu8; 512];
        let mut ctx =
            PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false);
        let compressed = ctx.process_vec(&input).unwrap();

        let blocks = parse_wire_block_types(&compressed);
        assert!(
            !blocks.is_empty(),
            "expected at least one block in the output"
        );
        assert_eq!(
            blocks[0],
            (BLOCK_COMPRESSION_ZSTD, BLOCK_TYPE_LITERAL),
            "first block should be a Zstd literal block"
        );
    }

    /// Every block type byte in a real compressed output must have compression bits
    /// of either BLOCK_COMPRESSION_NONE or BLOCK_COMPRESSION_ZSTD — never the
    /// reserved patterns 0x80 or 0xC0.
    #[test]
    fn test_encoder_never_emits_reserved_compression_bits() {
        let input = crate::utils::read_file("samplezip.zip");
        let mut ctx =
            PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false);
        let compressed = ctx.process_vec(&input).unwrap();

        for &(compression, _) in &parse_wire_block_types(&compressed) {
            assert!(
                compression == BLOCK_COMPRESSION_NONE || compression == BLOCK_COMPRESSION_ZSTD,
                "found reserved compression bits 0x{compression:02X} in output"
            );
        }
    }

    /// Verify that the decoder extracts the lower 6 bits as block_type rather
    /// than passing the full byte to process_compressed_block. If it passed the
    /// full byte (0x41) instead of the kind bits (0x01), the match would fall
    /// through to the error arm and the round-trip would fail.
    #[test]
    fn test_decoder_strips_compression_bits_before_dispatch() {
        use crate::utils::{assert_eq_array, read_file};
        // A zip file exercises DEFLATE blocks (wire type 0x41 = ZSTD|DEFLATE).
        // A successful round-trip proves the decoder is matching on 0x01, not 0x41.
        let original = read_file("samplezip.zip");
        let mut enc =
            PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false);
        let compressed = enc.process_vec(&original).unwrap();

        // Confirm the stream actually contains DEFLATE blocks (type 0x41),
        // so the test is meaningful and not trivially passing.
        let has_deflate = parse_wire_block_types(&compressed)
            .iter()
            .any(|&(c, t)| c == BLOCK_COMPRESSION_ZSTD && t == BLOCK_TYPE_DEFLATE);
        assert!(
            has_deflate,
            "test file produced no DEFLATE blocks — test is vacuous"
        );

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        assert_eq_array(&original, &recreated);
    }

    /// A PNG file must produce at least one PNG or WebP IDAT block (not merely a DEFLATE
    /// block), and must round-trip to the original bytes.  The PNG code path in the encoder
    /// is distinct from the plain DEFLATE path: it reconstructs IDAT framing and, when the
    /// `webp` feature is enabled, may store pixels as WebP lossless instead of raw.
    #[test]
    fn test_png_produces_idat_block_and_roundtrips() {
        use crate::utils::{assert_eq_array, read_file};
        let original = read_file("treegdi.png");
        let mut enc =
            PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false);
        let compressed = enc.process_vec(&original).unwrap();

        let blocks = parse_wire_block_types(&compressed);
        let has_png_block = blocks
            .iter()
            .any(|&(_, t)| t == BLOCK_TYPE_PNG || t == BLOCK_TYPE_WEBP);
        assert!(
            has_png_block,
            "PNG input should produce at least one PNG (0x02) or WebP (0x05) block, \
             got: {blocks:?}"
        );

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        assert_eq_array(&original, &recreated);
    }

    /// A PDF containing embedded JPEG images must produce JPEG_LEPTON blocks (raw,
    /// outside Zstd) as well as DEFLATE blocks for the PDF's own compressed object
    /// streams. Both must survive a full round-trip.
    #[test]
    fn test_pdf_with_jpegs_produces_lepton_and_deflate_blocks_and_roundtrips() {
        use crate::utils::{assert_eq_array, read_file};
        let original = read_file("embedded-images.pdf");
        let mut enc =
            PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false);
        let compressed = enc.process_vec(&original).unwrap();

        let blocks = parse_wire_block_types(&compressed);

        let has_lepton = blocks
            .iter()
            .any(|&(c, t)| c == BLOCK_COMPRESSION_NONE && t == BLOCK_TYPE_JPEG_LEPTON);
        assert!(
            has_lepton,
            "PDF with embedded JPEGs should produce at least one JPEG_LEPTON block"
        );

        let has_deflate = blocks.iter().any(|&(_, t)| t == BLOCK_TYPE_DEFLATE);
        assert!(
            has_deflate,
            "PDF with embedded JPEGs should also produce DEFLATE blocks for compressed objects"
        );

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        assert_eq_array(&original, &recreated);
    }

    /// DEFLATE_CONTINUE blocks are produced when the compressed-data buffer is
    /// truncated mid-stream: `DeflateParser::parse` reads to EOF and returns
    /// `Ok` with `is_done()=false`, the encoder emits a DEFLATE block for the
    /// plaintext decoded so far, saves the mid-stream state, and resumes on
    /// subsequent calls via DEFLATE_CONTINUE blocks.
    ///
    /// `sample1.bin.gz` is a single gzip stream with ~418 KiB of uncompressed
    /// content.  Feeding it in 10 KiB slices (with `min_chunk_size=5000` so the
    /// processor starts immediately) means the scanner always sees only a
    /// partial window of the compressed stream, forcing many DEFLATE_CONTINUE
    /// blocks that must all round-trip correctly.
    #[test]
    fn test_deflate_continue_blocks_appear_and_roundtrip() {
        use crate::utils::{assert_eq_array, read_file};
        let original = read_file("sample1.bin.gz");
        // min_chunk_size: 0 so the loop processes data immediately after Start,
        // letting Searching run with the first truncated chunk rather than waiting
        // for an additional min_chunk_size bytes before beginning.
        let mut enc = PreflateContainerProcessor::new(
            &PreflateContainerConfig {
                min_chunk_size: 0,
                ..PreflateContainerConfig::default()
            },
            1,
            false,
        );
        // Feed the 263 KiB file in two pieces. The first piece (200 KiB) truncates
        // the DEFLATE stream mid-way; decompress() hits EOF with at least one
        // complete block already parsed, so it returns Ok(partial) / is_done()=false,
        // causing the encoder to emit a DEFLATE block and enter DeflateContinue.
        // The second piece completes the stream → DEFLATE_CONTINUE block.
        let mut compressed = Vec::new();
        {
            let chunk1 = &original[..200_000.min(original.len())];
            enc.process_buffer(chunk1, false, &mut compressed).unwrap();
            if original.len() > 200_000 {
                let chunk2 = &original[200_000..];
                enc.process_buffer(chunk2, false, &mut compressed).unwrap();
            }
            enc.process_buffer(&[], true, &mut compressed).unwrap();
        }

        let blocks = parse_wire_block_types(&compressed);
        let n_continue = blocks
            .iter()
            .filter(|&&(_, t)| t == BLOCK_TYPE_DEFLATE_CONTINUE)
            .count();
        assert!(
            n_continue > 0,
            "200 KiB chunks on a ~263 KiB gzip should force at least one DEFLATE_CONTINUE block; \
             blocks seen: {blocks:?}"
        );

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec_size(&compressed, 10_000).unwrap();
        assert_eq_array(&original, &recreated);
    }

    /// When `total_plain_text_limit` is exceeded the encoder stops analysing
    /// deflate streams and writes the remaining bytes as LITERAL blocks.  The
    /// decoder must still reproduce the original bytes exactly, including the
    /// unprocessed portion.
    #[test]
    fn test_total_plain_text_limit_forces_literal_fallback_and_roundtrips() {
        use crate::utils::{assert_eq_array, read_file};
        // samplezip.zip has several DEFLATE entries; setting the limit to 1 byte
        // ensures that after the first DEFLATE entry's plaintext is accumulated,
        // every subsequent scan sees total_plain_text_seen > limit and falls back
        // to writing remaining content as a single LITERAL block.
        let original = read_file("samplezip.zip");
        let mut enc = PreflateContainerProcessor::new(
            &PreflateContainerConfig {
                total_plain_text_limit: 1,
                ..PreflateContainerConfig::default()
            },
            1,
            false,
        );
        let compressed = enc.process_vec(&original).unwrap();

        let blocks = parse_wire_block_types(&compressed);

        // At least one LITERAL block must appear (the fallback content).
        let has_literal = blocks.iter().any(|&(_, t)| t == BLOCK_TYPE_LITERAL);
        assert!(
            has_literal,
            "after total_plain_text_limit is exceeded, remaining content must be LITERAL"
        );

        // The stream must still decode back to the original bytes.
        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        assert_eq_array(&original, &recreated);
    }

    // ── Multi-scheme fixture tests ───────────────────────────────────────────────

    /// Helper: compress `data` in one shot and return `(compressed, blocks)`.
    fn compress_default(data: &[u8]) -> (Vec<u8>, Vec<(u8, u8)>) {
        let mut enc =
            PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false);
        let compressed = enc.process_vec(data).unwrap();
        let blocks = parse_wire_block_types(&compressed);
        (compressed, blocks)
    }

    /// Helper: full roundtrip assertion — compress then decompress, check byte equality.
    fn assert_roundtrip(original: &[u8]) {
        let (compressed, _) = compress_default(original);
        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        crate::utils::assert_eq_array(original, &recreated);
    }

    /// Count how many blocks have a given block-type kind.
    fn count_block_type(blocks: &[(u8, u8)], kind: u8) -> usize {
        blocks.iter().filter(|&&(_, t)| t == kind).count()
    }

    /// Two concatenated gzip streams — each contains plaintext well above
    /// MIN_BLOCKSIZE=1024, so the scanner must emit exactly two DEFLATE blocks.
    ///
    /// Fixture: `test_two_gzip_streams.bin`
    /// Expected wire sequence: literal, deflate, literal, deflate, literal, EOS
    #[test]
    fn test_two_gzip_streams_produce_two_deflate_blocks_and_roundtrip() {
        use crate::utils::read_file;
        let original = read_file("test_two_gzip_streams.bin");
        let (compressed, blocks) = compress_default(&original);

        assert_eq!(
            count_block_type(&blocks, BLOCK_TYPE_DEFLATE),
            2,
            "two consecutive gzip streams should each produce one DEFLATE block; blocks={blocks:?}"
        );

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        crate::utils::assert_eq_array(&original, &recreated);
    }

    /// A gzip stream whose plaintext is below MIN_BLOCKSIZE (500 < 1024) must NOT
    /// be promoted to a DEFLATE block — the whole file becomes a single literal chunk.
    ///
    /// Fixture: `test_tiny_gzip.bin`
    /// Expected wire sequence: literal, EOS (no DEFLATE blocks)
    #[test]
    fn test_tiny_gzip_below_min_blocksize_becomes_literal_and_roundtrip() {
        use crate::utils::read_file;
        let original = read_file("test_tiny_gzip.bin");
        let (compressed, blocks) = compress_default(&original);

        assert_eq!(
            count_block_type(&blocks, BLOCK_TYPE_DEFLATE),
            0,
            "gzip with 500-byte plaintext (<MIN_BLOCKSIZE) must not become a DEFLATE block; \
             blocks={blocks:?}"
        );

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        crate::utils::assert_eq_array(&original, &recreated);
    }

    /// File contains a large gzip (plaintext > MIN_BLOCKSIZE) immediately followed by
    /// a tiny gzip (plaintext < MIN_BLOCKSIZE).  Only the large stream must become a
    /// DEFLATE block; the small one stays literal.
    ///
    /// Fixture: `test_big_then_small_gzip.bin`
    /// Expected wire sequence: literal, deflate, literal, EOS (exactly 1 DEFLATE block)
    #[test]
    fn test_big_gzip_deflate_small_gzip_literal_and_roundtrip() {
        use crate::utils::read_file;
        let original = read_file("test_big_then_small_gzip.bin");
        let (compressed, blocks) = compress_default(&original);

        assert_eq!(
            count_block_type(&blocks, BLOCK_TYPE_DEFLATE),
            1,
            "only the large gzip stream should become a DEFLATE block; blocks={blocks:?}"
        );

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        crate::utils::assert_eq_array(&original, &recreated);
    }

    /// A file with a valid gzip header but a deliberately corrupted DEFLATE body
    /// (0xFF leading byte) must not crash.  The scanner must gracefully abandon the
    /// stream and encode the entire file as a literal block.
    ///
    /// Fixture: `test_corrupted_deflate.bin`
    /// Expected wire sequence: literal, EOS (0 DEFLATE blocks)
    #[test]
    fn test_corrupted_deflate_body_falls_back_to_literal_and_roundtrip() {
        use crate::utils::read_file;
        let original = read_file("test_corrupted_deflate.bin");
        let (compressed, blocks) = compress_default(&original);

        assert_eq!(
            count_block_type(&blocks, BLOCK_TYPE_DEFLATE),
            0,
            "corrupted DEFLATE body must not produce a DEFLATE block; blocks={blocks:?}"
        );

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        crate::utils::assert_eq_array(&original, &recreated);
    }

    /// A file containing padding bytes, then two zlib streams (each with plaintext
    /// > MIN_BLOCKSIZE), then more padding.  The scanner must find both zlib headers
    /// and emit exactly two DEFLATE blocks.
    ///
    /// Fixture: `test_two_zlib_streams.bin`
    ///   layout: 100 × `\xDE\xAD` | zlib(EEEE×6000) | 100 × `\xDE\xAD` | zlib(FFFF×6000) | 100 × `\xDE\xAD`
    /// Expected wire sequence: literal, deflate, literal, deflate, literal, EOS
    #[test]
    fn test_two_zlib_streams_produce_two_deflate_blocks_and_roundtrip() {
        use crate::utils::read_file;
        let original = read_file("test_two_zlib_streams.bin");
        let (compressed, blocks) = compress_default(&original);

        assert_eq!(
            count_block_type(&blocks, BLOCK_TYPE_DEFLATE),
            2,
            "two zlib streams surrounded by literal bytes should each produce a DEFLATE block; \
             blocks={blocks:?}"
        );

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        crate::utils::assert_eq_array(&original, &recreated);
    }

    /// A ZIP file containing three DEFLATE-compressed entries must produce exactly three
    /// DEFLATE blocks — one per entry — and round-trip correctly.
    ///
    /// Fixture: `test_zip_3entries.zip`  (entries G×20000, H×20000, I×20000 bytes)
    /// Expected wire sequence: literal, deflate, literal, deflate, literal, deflate, literal, EOS
    #[test]
    fn test_zip_three_deflated_entries_produce_three_deflate_blocks_and_roundtrip() {
        use crate::utils::read_file;
        let original = read_file("test_zip_3entries.zip");
        let (compressed, blocks) = compress_default(&original);

        assert_eq!(
            count_block_type(&blocks, BLOCK_TYPE_DEFLATE),
            3,
            "ZIP with 3 DEFLATED entries should produce 3 DEFLATE blocks; blocks={blocks:?}"
        );

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        crate::utils::assert_eq_array(&original, &recreated);
    }

    /// A ZIP file with a STORED entry (method=0) followed by a DEFLATED entry (method=8).
    /// `parse_zip_stream` returns `Err` for STORED entries so they become literal blocks;
    /// only the DEFLATED entry is analysed and emitted as a DEFLATE block.
    ///
    /// Fixture: `test_zip_stored_then_deflated.zip`  (J×8000 STORED, K×20000 DEFLATED)
    /// Expected wire sequence: literal, deflate, literal, EOS (exactly 1 DEFLATE block)
    #[test]
    fn test_zip_stored_entry_stays_literal_deflated_entry_becomes_deflate_and_roundtrip() {
        use crate::utils::read_file;
        let original = read_file("test_zip_stored_then_deflated.zip");
        let (compressed, blocks) = compress_default(&original);

        assert_eq!(
            count_block_type(&blocks, BLOCK_TYPE_DEFLATE),
            1,
            "only the DEFLATED entry should become a DEFLATE block; STORED stays literal; \
             blocks={blocks:?}"
        );

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        crate::utils::assert_eq_array(&original, &recreated);
    }

    /// A buffer filled with pseudo-random bytes contains no recognisable DEFLATE/zlib/gzip
    /// signatures.  The entire file must be emitted as a single literal block with no
    /// DEFLATE analysis.
    ///
    /// Fixture: `test_random_bytes.bin`  (32 KiB pseudo-random)
    /// Expected wire sequence: literal, EOS
    #[test]
    fn test_random_bytes_produce_no_deflate_blocks_and_roundtrip() {
        use crate::utils::read_file;
        let original = read_file("test_random_bytes.bin");
        let (compressed, blocks) = compress_default(&original);

        assert_eq!(
            count_block_type(&blocks, BLOCK_TYPE_DEFLATE),
            0,
            "random bytes contain no DEFLATE streams; blocks={blocks:?}"
        );

        // The literal block must survive the round-trip.
        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        crate::utils::assert_eq_array(&original, &recreated);
    }

    /// Two gzip streams separated by a 1000-byte null gap.  Both streams have
    /// plaintext > MIN_BLOCKSIZE, so both must produce DEFLATE blocks, and the gap
    /// must appear as a literal block between them.
    ///
    /// Fixture: `test_gzip_with_gap.bin`
    /// Expected wire sequence: literal, deflate, literal, deflate, literal, EOS
    #[test]
    fn test_two_gzip_streams_with_null_gap_produce_two_deflate_blocks_and_roundtrip() {
        use crate::utils::read_file;
        let original = read_file("test_gzip_with_gap.bin");
        let (compressed, blocks) = compress_default(&original);

        assert_eq!(
            count_block_type(&blocks, BLOCK_TYPE_DEFLATE),
            2,
            "both gzip streams should become DEFLATE blocks; null gap stays literal; \
             blocks={blocks:?}"
        );
        // There should be at least one literal block (the gap between the two streams).
        assert!(
            count_block_type(&blocks, BLOCK_TYPE_LITERAL) >= 1,
            "null gap between gzip streams should produce at least one literal block; \
             blocks={blocks:?}"
        );

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        crate::utils::assert_eq_array(&original, &recreated);
    }

    /// Feed a fixture containing two gzip streams in very small chunks (64 bytes at a
    /// time) via the incremental `process_buffer` API to exercise boundary handling.
    /// The round-trip result must be byte-exact regardless of where chunk boundaries fall.
    #[test]
    fn test_two_gzip_streams_incremental_small_chunks_roundtrip() {
        use crate::utils::{assert_eq_array, read_file};
        let original = read_file("test_two_gzip_streams.bin");

        let mut enc = PreflateContainerProcessor::new(
            &PreflateContainerConfig {
                min_chunk_size: 0,
                ..PreflateContainerConfig::default()
            },
            1,
            false,
        );
        let mut compressed = Vec::new();
        let chunk_size = 64;
        let mut pos = 0;
        while pos < original.len() {
            let end = (pos + chunk_size).min(original.len());
            enc.process_buffer(&original[pos..end], false, &mut compressed)
                .unwrap();
            pos = end;
        }
        enc.process_buffer(&[], true, &mut compressed).unwrap();

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        assert_eq_array(&original, &recreated);
    }

    /// Feed `test_two_zlib_streams.bin` in small chunks (128 bytes) to confirm that
    /// the incremental path handles mixed literal padding + zlib streams correctly.
    #[test]
    fn test_two_zlib_streams_incremental_small_chunks_roundtrip() {
        use crate::utils::{assert_eq_array, read_file};
        let original = read_file("test_two_zlib_streams.bin");

        let mut enc = PreflateContainerProcessor::new(
            &PreflateContainerConfig {
                min_chunk_size: 0,
                ..PreflateContainerConfig::default()
            },
            1,
            false,
        );
        let mut compressed = Vec::new();
        let chunk_size = 128;
        let mut pos = 0;
        while pos < original.len() {
            let end = (pos + chunk_size).min(original.len());
            enc.process_buffer(&original[pos..end], false, &mut compressed)
                .unwrap();
            pos = end;
        }
        enc.process_buffer(&[], true, &mut compressed).unwrap();

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        assert_eq_array(&original, &recreated);
    }

    /// Feed a ZIP fixture in small chunks (256 bytes) to check that chunk boundaries
    /// inside the ZIP local-file headers and DEFLATE bodies are handled gracefully.
    #[test]
    fn test_zip_three_entries_incremental_small_chunks_roundtrip() {
        use crate::utils::{assert_eq_array, read_file};
        let original = read_file("test_zip_3entries.zip");

        let mut enc = PreflateContainerProcessor::new(
            &PreflateContainerConfig {
                min_chunk_size: 0,
                ..PreflateContainerConfig::default()
            },
            1,
            false,
        );
        let mut compressed = Vec::new();
        let chunk_size = 256;
        let mut pos = 0;
        while pos < original.len() {
            let end = (pos + chunk_size).min(original.len());
            enc.process_buffer(&original[pos..end], false, &mut compressed)
                .unwrap();
            pos = end;
        }
        enc.process_buffer(&[], true, &mut compressed).unwrap();

        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec(&compressed).unwrap();
        assert_eq_array(&original, &recreated);
    }

    /// Verify that the decoder also handles the recreated stream correctly when fed in
    /// small chunks, not just when given the entire buffer at once.
    /// Uses `test_zip_stored_then_deflated.zip` (mixed STORED + DEFLATED entries).
    #[test]
    fn test_zip_stored_then_deflated_decoder_small_chunks_roundtrip() {
        use crate::utils::{assert_eq_array, read_file};
        let original = read_file("test_zip_stored_then_deflated.zip");

        let mut enc =
            PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false);
        let compressed = enc.process_vec(&original).unwrap();

        // Decompress in 512-byte chunks to exercise the incremental decoder.
        let mut dec = RecreateContainerProcessor::new(usize::MAX);
        let recreated = dec.process_vec_size(&compressed, 512).unwrap();
        assert_eq_array(&original, &recreated);
    }
}
