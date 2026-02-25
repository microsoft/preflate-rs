use byteorder::ReadBytesExt;
use lepton_jpeg::{DEFAULT_THREAD_POOL, EnabledFeatures};

use std::{
    collections::VecDeque,
    io::{BufRead, Cursor, Read, Write},
    usize,
};

use crate::{
    idat_parse::{IdatContents, PngHeader, recreate_idat},
    scan_deflate::{FindStreamResult, FoundStream, FoundStreamType, find_compressable_stream},
    scoped_read::ScopedRead,
};

use preflate_rs::{
    AddContext, ExitCode, HashAlgorithm, PreflateConfig, PreflateError, PreflateStreamProcessor,
    RecreateStreamProcessor, Result, err_exit_code, recreate_whole_deflate_stream,
};

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

const COMPRESSED_WRAPPER_VERSION_2: u8 = 2;

// Bit-field masks for the block type byte
// Bits 7-6: compression algorithm  Bits 5-0: block content kind
const BLOCK_COMPRESSION_MASK: u8 = 0xC0;
const BLOCK_TYPE_MASK: u8 = 0x3F;

// Compression algorithms (top 2 bits)
const BLOCK_COMPRESSION_NONE: u8 = 0x00;
const BLOCK_COMPRESSION_ZSTD: u8 = 0x40;

// Block content kinds (bottom 6 bits)
const BLOCK_TYPE_LITERAL: u8 = 0x00;
const BLOCK_TYPE_DEFLATE: u8 = 0x01;
const BLOCK_TYPE_PNG: u8 = 0x02;
const BLOCK_TYPE_DEFLATE_CONTINUE: u8 = 0x03;
const BLOCK_TYPE_JPEG_LEPTON: u8 = 0x04;
const BLOCK_TYPE_WEBP: u8 = 0x05;
const BLOCK_TYPE_EOS: u8 = 0x3F; // end-of-stream

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

/// Flushes the encoder, writes [block_type][varint(compressed_size)][compressed_bytes] to
/// destination, clears the encoder's inner buffer, and returns the compressed byte count.
fn emit_compressed_block(
    block_type: u8,
    encoder: &mut zstd::stream::write::Encoder<'static, Vec<u8>>,
    destination: &mut impl Write,
) -> Result<usize> {
    encoder.flush().context()?;
    let compressed = encoder.get_mut();
    let len = compressed.len();
    destination.write_all(&[block_type])?;
    write_varint(destination, len as u32)?;
    destination.write_all(compressed)?;
    compressed.clear();
    Ok(len)
}

/// V2 variant of write_chunk_block: block content goes through the persistent Zstd encoder.
/// JPEG blocks are written raw to writer (bypass encoder).
/// Returns (total compressed bytes written, optional continue state).
fn write_chunk_block_v2(
    encoder: &mut zstd::stream::write::Encoder<'static, Vec<u8>>,
    writer: &mut impl Write,
    chunk: FoundStream,
    stats: &mut PreflateStats,
) -> Result<(usize, Option<PreflateStreamProcessor>)> {
    match chunk.chunk_type {
        FoundStreamType::DeflateStream(parameters, state) => {
            write_varint(encoder, chunk.corrections.len() as u32)?;
            write_varint(encoder, state.plain_text().text().len() as u32)?;
            encoder.write_all(&chunk.corrections)?;
            encoder.write_all(&state.plain_text().text())?;

            let compressed_size = emit_compressed_block(
                BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_DEFLATE,
                encoder,
                writer,
            )?;

            stats.overhead_bytes += chunk.corrections.len() as u64;
            stats.uncompressed_size += state.plain_text().len() as u64;
            stats.hash_algorithm = parameters.hash_algorithm;

            if !state.is_done() {
                return Ok((compressed_size, Some(state)));
            }
            Ok((compressed_size, None))
        }

        FoundStreamType::IDATDeflate(parameters, mut idat, plain_text) => {
            log::debug!(
                "IDATDeflate param {:?} corrections {}",
                parameters,
                chunk.corrections.len()
            );

            let mut temp_vec = Vec::new();

            if webp_compress(&mut temp_vec, plain_text.text(), &chunk.corrections, &idat).is_ok() {
                // WebP is already compressed — write raw, bypassing the Zstd encoder.
                // temp_vec[0] is the BLOCK_TYPE_PNG placeholder byte; temp_vec[1..] is the payload.
                let payload = &temp_vec[1..];
                writer.write_all(&[BLOCK_COMPRESSION_NONE | BLOCK_TYPE_WEBP])?;
                write_varint(writer, payload.len() as u32)?;
                writer.write_all(payload)?;

                stats.uncompressed_size += plain_text.len() as u64;
                stats.hash_algorithm = parameters.hash_algorithm;
                stats.overhead_bytes += chunk.corrections.len() as u64;

                Ok((payload.len(), None))
            } else {
                // Non-WebP PNG: corrections + plaintext are compressible, send through Zstd.
                log::debug!("non-Webp compressed {}", idat.total_chunk_length);
                write_varint(encoder, chunk.corrections.len() as u32)?;
                write_varint(encoder, plain_text.text().len() as u32)?;
                idat.png_header = None;
                idat.write_to_bytestream(encoder)?;
                encoder.write_all(&chunk.corrections)?;
                encoder.write_all(plain_text.text())?;

                let compressed_size = emit_compressed_block(
                    BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_PNG,
                    encoder,
                    writer,
                )?;

                stats.uncompressed_size += plain_text.len() as u64;
                stats.hash_algorithm = parameters.hash_algorithm;
                stats.overhead_bytes += chunk.corrections.len() as u64;

                Ok((compressed_size, None))
            }
        }

        FoundStreamType::JPEGLepton(data) => {
            // JPEG is written raw (bypasses the encoder entirely)
            writer.write_all(&[BLOCK_COMPRESSION_NONE | BLOCK_TYPE_JPEG_LEPTON])?;
            write_varint(writer, data.len() as u32)?;
            writer.write_all(&data)?;

            stats.uncompressed_size += data.len() as u64;
            Ok((0, None))
        }
    }
}

/// used to measure the length of the output without storing it
struct MeasureWriteSink {
    pub length: usize,
}

impl Write for MeasureWriteSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.length += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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

#[derive(Debug)]
enum ChunkParseState {
    Start,
    /// we are looking for a deflate stream or PNG chunk. The data of the PNG file
    /// is stored later than the IHDR chunk that will tell us the dimensions of the image,
    /// so we need to keep track of the IHDR chunk so we can use it later to properly
    /// compress the PNG data.
    Searching(Option<PngHeader>),
    DeflateContinue(PreflateStreamProcessor),
}

/// Takes a sequence of bytes that may contain deflate streams, find
/// the streams, and emits a new stream that containus the decompressed
/// streams along with the corrections needed to recreate the original.
///
/// This output can then be compressed with a better algorithm, like Zstandard
/// and achieve much better compression than if we tried to compress the
/// deflate stream directlyh.
pub struct PreflateContainerProcessor {
    content: Vec<u8>,
    compression_stats: PreflateStats,
    input_complete: bool,
    total_plain_text_seen: u64,

    /// used to track the last attempted chunk size, in case we
    /// need more input to continue, we will collect at least min_chunk_size
    /// more input before trying to process again until we reach max_chunk_size
    last_attempt_chunk_size: usize,

    state: ChunkParseState,
    config: PreflateContainerConfig,

    /// each block is individually compressed with this encoder (v2 format)
    encoder: Option<zstd::stream::write::Encoder<'static, Vec<u8>>>,

    /// when present, all raw input is also fed to this encoder so we can measure
    /// baseline Zstd compression (without preflate processing)
    baseline_encoder: Option<zstd::stream::write::Encoder<'static, MeasureWriteSink>>,
}

impl PreflateContainerProcessor {
    /// Creates a processor that uses v2 format with a persistent Zstd encoder shared
    /// across all non-JPEG blocks. JPEG blocks bypass the encoder entirely.
    pub fn new(config: &PreflateContainerConfig, level: i32, test_baseline: bool) -> Self {
        PreflateContainerProcessor {
            content: Vec::new(),
            compression_stats: PreflateStats::default(),
            input_complete: false,
            state: ChunkParseState::Start,
            total_plain_text_seen: 0,
            last_attempt_chunk_size: 0,
            config: config.clone(),
            encoder: Some(zstd::stream::write::Encoder::new(Vec::new(), level).unwrap()),
            baseline_encoder: if test_baseline {
                Some(
                    zstd::stream::write::Encoder::new(MeasureWriteSink { length: 0 }, level)
                        .unwrap(),
                )
            } else {
                None
            },
        }
    }
}

impl ProcessBuffer for PreflateContainerProcessor {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
    ) -> Result<()> {
        if self.input_complete && (input.len() > 0 || !input_complete) {
            return Err(PreflateError::new(
                ExitCode::InvalidParameter,
                "more data provided after input_complete signaled",
            ));
        }

        if input.len() > 0 {
            self.compression_stats.deflate_compressed_size += input.len() as u64;
            self.content.extend_from_slice(input);

            if let Some(encoder) = &mut self.baseline_encoder {
                encoder.write_all(input).context()?;
            }
        }

        loop {
            // wait until we have at least min_chunk_size before we start processing
            if self.content.is_empty()
                || (!input_complete
                    && (self.content.len() - self.last_attempt_chunk_size)
                        < self.config.min_chunk_size
                    && self.content.len() <= self.config.max_chunk_size)
            {
                break;
            }

            self.last_attempt_chunk_size = self.content.len();

            match &mut self.state {
                ChunkParseState::Start => {
                    writer.write_all(&[COMPRESSED_WRAPPER_VERSION_2])?;
                    self.state = ChunkParseState::Searching(None);
                }
                ChunkParseState::Searching(prev_ihdr) => {
                    if self.total_plain_text_seen > self.config.total_plain_text_limit {
                        // once we've exceeded our limit, we don't do any more compression
                        let encoder = self.encoder.as_mut().unwrap();
                        write_varint(encoder, self.content.len() as u32)?;
                        encoder.write_all(&self.content)?;
                        let sz = emit_compressed_block(
                            BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_LITERAL,
                            encoder,
                            writer,
                        )?;
                        self.compression_stats.zstd_compressed_size += sz as u64;

                        self.last_attempt_chunk_size = 0;
                        self.content.clear();
                        break;
                    }

                    // here we are looking for a deflate stream or PNG chunk
                    match find_compressable_stream(
                        &self.content,
                        prev_ihdr,
                        input_complete,
                        &self.config,
                    ) {
                        FindStreamResult::Found(next, chunk) => {
                            // the gap between the start and the beginning of the deflate stream
                            // is written out as a literal block
                            if next.start != 0 {
                                let encoder = self.encoder.as_mut().unwrap();
                                write_varint(encoder, next.start as u32)?;
                                encoder.write_all(&self.content[..next.start])?;
                                let sz = emit_compressed_block(
                                    BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_LITERAL,
                                    encoder,
                                    writer,
                                )?;
                                self.compression_stats.zstd_compressed_size += sz as u64;
                            }

                            let (compressed_size, next_state) = write_chunk_block_v2(
                                self.encoder.as_mut().unwrap(),
                                writer,
                                chunk,
                                &mut self.compression_stats,
                            )
                            .context()?;
                            self.compression_stats.zstd_compressed_size += compressed_size as u64;

                            if let Some(mut state) = next_state {
                                self.total_plain_text_seen += state.plain_text().len() as u64;
                                state.shrink_to_dictionary();
                                self.state = ChunkParseState::DeflateContinue(state);
                            }

                            self.content.drain(0..next.end);
                            self.last_attempt_chunk_size = self.content.len();
                        }
                        FindStreamResult::ShortRead => {
                            if input_complete || self.content.len() > self.config.max_chunk_size {
                                // if we have too much data or have no more data,
                                // we just write it out as a literal block with everything we have
                                let encoder = self.encoder.as_mut().unwrap();
                                write_varint(encoder, self.content.len() as u32)?;
                                encoder.write_all(&self.content)?;
                                let sz = emit_compressed_block(
                                    BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_LITERAL,
                                    encoder,
                                    writer,
                                )?;
                                self.compression_stats.zstd_compressed_size += sz as u64;

                                self.content.clear();
                                self.last_attempt_chunk_size = 0;
                            } else {
                                // we don't have enough data to process the stream, so we just
                                // wait for more data
                                break;
                            }
                        }
                        FindStreamResult::None => {
                            // couldn't find anything, just write the rest as a literal block
                            let encoder = self.encoder.as_mut().unwrap();
                            write_varint(encoder, self.content.len() as u32)?;
                            encoder.write_all(&self.content)?;
                            let sz = emit_compressed_block(
                                BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_LITERAL,
                                encoder,
                                writer,
                            )?;
                            self.compression_stats.zstd_compressed_size += sz as u64;

                            self.content.clear();
                            self.last_attempt_chunk_size = 0;
                        }
                    }
                }
                ChunkParseState::DeflateContinue(state) => {
                    // here we have a deflate stream that we need to continue
                    match state.decompress(&self.content) {
                        Err(ref e) if e.exit_code() == ExitCode::ShortRead
                            && !input_complete
                            && self.content.len() <= self.config.max_chunk_size =>
                        {
                            // Not enough data to complete the next block yet; wait for more.
                            break;
                        }
                        Err(_e) => {
                            // Stream analysis diverged or no more data is coming; give up on
                            // continuation and fall back to treating the remaining bytes as raw.
                            self.state = ChunkParseState::Searching(None);

                            log::debug!("Error while trying to continue compression {:?}", _e);
                        }
                        Ok(res) => {
                            log::debug!(
                                "Deflate continue: {} -> {}",
                                state.plain_text().len(),
                                res.compressed_size
                            );

                            let encoder = self.encoder.as_mut().unwrap();
                            write_varint(encoder, res.corrections.len() as u32)?;
                            write_varint(encoder, state.plain_text().len() as u32)?;
                            encoder.write_all(&res.corrections)?;
                            encoder.write_all(&state.plain_text().text())?;
                            let sz = emit_compressed_block(
                                BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_DEFLATE_CONTINUE,
                                encoder,
                                writer,
                            )?;
                            self.compression_stats.zstd_compressed_size += sz as u64;

                            self.total_plain_text_seen += state.plain_text().len() as u64;
                            self.compression_stats.overhead_bytes += res.corrections.len() as u64;
                            self.compression_stats.uncompressed_size +=
                                state.plain_text().len() as u64;

                            self.content.drain(0..res.compressed_size);
                            self.last_attempt_chunk_size = self.content.len();

                            if state.is_done() {
                                self.state = ChunkParseState::Searching(None);
                            } else {
                                state.shrink_to_dictionary();
                            }
                        }
                    }
                }
            }
        }

        if input_complete && !self.input_complete {
            self.input_complete = true;

            if self.content.len() > 0 {
                let encoder = self.encoder.as_mut().unwrap();
                write_varint(encoder, self.content.len() as u32)?;
                encoder.write_all(&self.content)?;
                let sz = emit_compressed_block(
                    BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_LITERAL,
                    encoder,
                    writer,
                )?;
                self.compression_stats.zstd_compressed_size += sz as u64;
            }
            self.content.clear();

            // Finalize the Zstd encoder and write the end-of-stream marker
            let encoder = self.encoder.take().unwrap();
            let finish_bytes = encoder.finish().context()?;
            writer.write_all(&[BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_EOS])?;
            write_varint(writer, finish_bytes.len() as u32)?;
            writer.write_all(&finish_bytes)?;
            self.compression_stats.zstd_compressed_size += finish_bytes.len() as u64;

            // Finalize baseline encoder for stats
            if let Some(mut encoder) = self.baseline_encoder.take() {
                encoder.flush().context()?;
                encoder.do_finish().context()?;
                self.compression_stats.zstd_baseline_size = encoder.get_mut().length as u64;
            }
        }

        Ok(())
    }

    fn stats(&self) -> PreflateStats {
        self.compression_stats
    }
}

enum DecompressionState {
    Start,
    StartSegment,
    /// accumulate compressed_size bytes then decode and process the block immediately.
    AccumulateBlock {
        block_type: u8,
        compressed_size: usize,
    },
    /// accumulate lepton bytes then decode the JPEG block immediately.
    JpegAccumulate {
        lepton_length: usize,
    },
    /// accumulate raw WebP-compressed PNG bytes then process the block immediately.
    WebpAccumulate {
        total_len: usize,
    },
    /// accumulate the final Zstd finish bytes to close the frame cleanly.
    ZstdEndOfStream {
        final_size: usize,
    },
}

/// recreates the orignal content from the chunked data
pub struct RecreateContainerProcessor {
    capacity: usize,
    input: VecDeque<u8>,
    input_complete: bool,
    state: DecompressionState,

    /// state of the predictor and plain text if we need to contiune a deflate stream
    /// if it was too big to complete in a single chunk
    deflate_continue_state: Option<RecreateStreamProcessor>,

    /// persistent Zstd decoder — maintains the streaming context across blocks
    zstd_decoder: zstd::stream::raw::Decoder<'static>,
}

impl RecreateContainerProcessor {
    pub fn new(capacity: usize) -> Self {
        RecreateContainerProcessor {
            input: VecDeque::new(),
            capacity,
            input_complete: false,
            state: DecompressionState::Start,
            deflate_continue_state: None,
            zstd_decoder: zstd::stream::raw::Decoder::new().expect("failed to create zstd decoder"),
        }
    }
}

impl ProcessBuffer for RecreateContainerProcessor {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
    ) -> Result<()> {
        if self.input_complete && (input.len() > 0 || !input_complete) {
            return Err(PreflateError::new(
                ExitCode::InvalidParameter,
                "more data provided after input_complete signaled",
            ));
        }

        // we could have been passed a big buffer, so we need to process it in chunks
        let mut amount_read = 0;
        loop {
            let amount_to_read = (input.len() - amount_read).min(self.capacity);

            // when we get to the end and we've read everything, we can signal that we are done
            if amount_read + amount_to_read == input.len() && input_complete {
                self.input_complete = true;
            }

            self.input
                .extend(&input[amount_read..amount_read + amount_to_read]);

            amount_read += amount_to_read;

            self.process_buffer_internal(writer)?;

            if amount_read == input.len() {
                break;
            }
        }

        Ok(())
    }
}

impl RecreateContainerProcessor {
    fn process_buffer_internal(&mut self, writer: &mut impl Write) -> Result<()> {
        loop {
            match &mut self.state {
                DecompressionState::Start => {
                    if !self.input_complete && self.input.len() == 0 {
                        break;
                    }

                    let version = self.input.read_u8()?;

                    match version {
                        COMPRESSED_WRAPPER_VERSION_2 => {
                            self.state = DecompressionState::StartSegment;
                        }
                        _ => {
                            return err_exit_code(
                                ExitCode::InvalidCompressedWrapper,
                                format!("Invalid version {version}"),
                            );
                        }
                    }
                }
                DecompressionState::StartSegment => {
                    // here's a good place to stop if we run out of input
                    if self.input.len() == 0 {
                        break;
                    }

                    // read type byte, then dispatch
                    self.state = match self.input.scoped_read(|r| {
                        let type_byte = r.read_u8()?;
                        let compression = type_byte & BLOCK_COMPRESSION_MASK;
                        let block_type = type_byte & BLOCK_TYPE_MASK;
                        match compression {
                            BLOCK_COMPRESSION_NONE => match block_type {
                                BLOCK_TYPE_JPEG_LEPTON => {
                                    let lepton_length = read_varint(r)? as usize;
                                    Ok(DecompressionState::JpegAccumulate { lepton_length })
                                }
                                BLOCK_TYPE_WEBP => {
                                    let total_len = read_varint(r)? as usize;
                                    Ok(DecompressionState::WebpAccumulate { total_len })
                                }
                                _ => err_exit_code(
                                    ExitCode::InvalidCompressedWrapper,
                                    "unknown raw block type",
                                ),
                            },
                            BLOCK_COMPRESSION_ZSTD => match block_type {
                                BLOCK_TYPE_EOS => {
                                    let final_size = read_varint(r)? as usize;
                                    Ok(DecompressionState::ZstdEndOfStream { final_size })
                                }
                                other => {
                                    let compressed_size = read_varint(r)? as usize;
                                    Ok(DecompressionState::AccumulateBlock {
                                        block_type: other,
                                        compressed_size,
                                    })
                                }
                            },
                            _ => err_exit_code(
                                ExitCode::InvalidCompressedWrapper,
                                "unknown compression algorithm",
                            ),
                        }
                    }) {
                        Ok(s) => s,
                        Err(e) => {
                            if !self.input_complete && e.exit_code() == ExitCode::ShortRead {
                                break;
                            } else {
                                return Err(e);
                            }
                        }
                    };
                }

                DecompressionState::AccumulateBlock {
                    block_type,
                    compressed_size,
                } => {
                    if self.input.len() < *compressed_size {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input in block",
                            ));
                        }
                        break;
                    }

                    let block_type = *block_type;
                    let compressed_bytes: Vec<u8> = self.input.drain(0..*compressed_size).collect();
                    let decoded = drain_zstd_block(&mut self.zstd_decoder, &compressed_bytes)?;
                    process_compressed_block(
                        block_type,
                        &mut Cursor::new(decoded),
                        &mut self.deflate_continue_state,
                        writer,
                    )?;
                    self.state = DecompressionState::StartSegment;
                }

                DecompressionState::JpegAccumulate { lepton_length } => {
                    if self.input.len() < *lepton_length {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input in jpeg block",
                            ));
                        }
                        break;
                    }

                    let lepton_bytes: Vec<u8> = self.input.drain(0..*lepton_length).collect();
                    match lepton_jpeg::decode_lepton(
                        &mut Cursor::new(&lepton_bytes),
                        writer,
                        &EnabledFeatures::compat_lepton_vector_read(),
                        &DEFAULT_THREAD_POOL,
                    ) {
                        Err(e) => {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                format!("JPEG Lepton decode failed: {}", e),
                            ));
                        }
                        Ok(_) => {}
                    }
                    self.state = DecompressionState::StartSegment;
                }

                DecompressionState::WebpAccumulate { total_len } => {
                    if self.input.len() < *total_len {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input in webp block",
                            ));
                        }
                        break;
                    }

                    let webp_bytes: Vec<u8> = self.input.drain(0..*total_len).collect();
                    // Payload is what webp_compress wrote after the BLOCK_TYPE_PNG type byte,
                    // so process_compressed_block can parse it directly.
                    process_compressed_block(
                        BLOCK_TYPE_PNG,
                        &mut Cursor::new(webp_bytes),
                        &mut self.deflate_continue_state,
                        writer,
                    )?;
                    self.state = DecompressionState::StartSegment;
                }

                DecompressionState::ZstdEndOfStream { final_size } => {
                    if self.input.len() < *final_size {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input in end-of-stream",
                            ));
                        }
                        break;
                    }

                    // Feed the finish bytes to cleanly close the Zstd frame.
                    // No decompressed output is expected since the encoder flushes after each block.
                    let finish_bytes: Vec<u8> = self.input.drain(0..*final_size).collect();
                    drain_zstd_block(&mut self.zstd_decoder, &finish_bytes)?;

                    self.state = DecompressionState::StartSegment;
                }
            }
        }

        Ok(())
    }
}

/// Feeds `compressed` bytes into the persistent `decoder` and returns all decompressed output.
///
/// Each call corresponds to one Zstd flush frame (written by the encoder via `flush()`).
/// After consuming all input bytes the decoder is drained until it produces no more output,
/// which is guaranteed because `ZSTD_e_flush` ensures all data is available to the decoder
/// before the next block starts.
fn drain_zstd_block(
    decoder: &mut zstd::stream::raw::Decoder<'static>,
    compressed: &[u8],
) -> Result<Vec<u8>> {
    use zstd::stream::raw::{InBuffer, Operation, OutBuffer};

    let mut output = Vec::new();
    let mut scratch = vec![0u8; 65536];
    let mut in_buf = InBuffer::around(compressed);

    loop {
        let mut out_buf = OutBuffer::around(scratch.as_mut_slice());
        decoder.run(&mut in_buf, &mut out_buf).map_err(|e| {
            PreflateError::new(
                ExitCode::InvalidCompressedWrapper,
                format!("zstd decode failed: {e}"),
            )
        })?;
        let produced = out_buf.pos();
        output.extend_from_slice(&scratch[..produced]);

        // Stop when all input has been consumed and the decoder produced no more output.
        // zstd guarantees progress (either bytes_read > 0 or bytes_written > 0) so this
        // loop always terminates.
        if in_buf.pos() >= compressed.len() && produced == 0 {
            break;
        }
    }

    Ok(output)
}

/// Parses and processes a single non-JPEG/non-WebP block.
///
/// `cursor` wraps the output of `drain_zstd_block` for compressed blocks,
/// or the raw WebP payload for `BLOCK_TYPE_PNG` blocks stored outside Zstd.
///
/// Layout written by the encoder for each block type (block_type = lower 6 bits):
///   BLOCK_TYPE_LITERAL:          varint(len) + data
///   BLOCK_TYPE_DEFLATE:          varint(corrections_len) + varint(plaintext_len) + corrections + plaintext
///   BLOCK_TYPE_DEFLATE_CONTINUE: same as BLOCK_TYPE_DEFLATE
///   BLOCK_TYPE_PNG:              varint(correction_length) + varint(uncompressed_length) +
///                                IdatContents + [filters if png_header present] +
///                                corrections + (webp_data or raw_plaintext)
fn process_compressed_block(
    block_type: u8,
    cursor: &mut Cursor<Vec<u8>>,
    deflate_continue_state: &mut Option<RecreateStreamProcessor>,
    writer: &mut impl Write,
) -> Result<()> {
    match block_type {
        BLOCK_TYPE_LITERAL => {
            let length = read_varint(cursor)? as usize;
            let mut data = vec![0u8; length];
            cursor.read_exact(&mut data).map_err(|e| {
                PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
            })?;
            writer.write_all(&data)?;
        }
        BLOCK_TYPE_DEFLATE => {
            *deflate_continue_state = None;

            let correction_length = read_varint(cursor)? as usize;
            let uncompressed_length = read_varint(cursor)? as usize;

            let mut corrections = vec![0u8; correction_length];
            cursor.read_exact(&mut corrections).map_err(|e| {
                PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
            })?;

            let mut plain_text_buf = vec![0u8; uncompressed_length];
            cursor.read_exact(&mut plain_text_buf).map_err(|e| {
                PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
            })?;

            let mut reconstruct = RecreateStreamProcessor::new();
            let (comp, _) = reconstruct
                .recompress(&mut Cursor::new(&plain_text_buf), &corrections)
                .context()?;

            writer.write_all(&comp)?;
            *deflate_continue_state = Some(reconstruct);
        }
        BLOCK_TYPE_DEFLATE_CONTINUE => {
            let correction_length = read_varint(cursor)? as usize;
            let uncompressed_length = read_varint(cursor)? as usize;

            let mut corrections = vec![0u8; correction_length];
            cursor.read_exact(&mut corrections).map_err(|e| {
                PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
            })?;

            let mut plain_text_buf = vec![0u8; uncompressed_length];
            cursor.read_exact(&mut plain_text_buf).map_err(|e| {
                PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
            })?;

            let reconstruct = deflate_continue_state.as_mut().ok_or_else(|| {
                PreflateError::new(
                    ExitCode::InvalidCompressedWrapper,
                    "no deflate state to continue",
                )
            })?;

            let (comp, _) = reconstruct
                .recompress(&mut Cursor::new(&plain_text_buf), &corrections)
                .context()?;

            writer.write_all(&comp)?;
        }
        BLOCK_TYPE_PNG => {
            let correction_length = read_varint(cursor)? as usize;
            let uncompressed_length = read_varint(cursor)? as usize;
            let idat = IdatContents::read_from_bytestream(cursor)?;

            let mut filters = Vec::new();
            if let Some(png_header) = &idat.png_header {
                filters.resize(png_header.height as usize, 0);
                cursor.read_exact(&mut filters[..]).map_err(|e| {
                    PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
                })?;
            }

            let mut corrections = vec![0u8; correction_length];
            cursor.read_exact(&mut corrections).map_err(|e| {
                PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
            })?;

            let plain_text;
            if let Some(header) = &idat.png_header {
                let mut webp = vec![0u8; uncompressed_length];
                cursor.read_exact(&mut webp).map_err(|e| {
                    PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
                })?;
                plain_text = webp_decompress(&filters, webp, header).context()?;
            } else {
                let mut raw = vec![0u8; uncompressed_length];
                cursor.read_exact(&mut raw).map_err(|e| {
                    PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
                })?;
                plain_text = raw;
            }

            let recompressed =
                recreate_whole_deflate_stream(&plain_text, &corrections).context()?;

            recreate_idat(&idat, &recompressed[..], writer).context()?;
        }
        _ => {
            return err_exit_code(
                ExitCode::InvalidCompressedWrapper,
                format!("Unknown block type {block_type}"),
            );
        }
    }
    Ok(())
}

fn webp_compress(
    result: &mut impl Write,
    plain_text: &[u8],
    corrections: &[u8],
    idat: &IdatContents,
) -> Result<()> {
    log::debug!("{:?}", idat);

    #[cfg(feature = "webp")]
    if let Some(png_header) = idat.png_header {
        use crate::idat_parse::{PngColorType, undo_png_filters};
        use std::ops::Deref;

        let bbp = png_header.color_type.bytes_per_pixel();
        let w = png_header.width as usize;
        let h = png_header.height as usize;

        log::debug!(
            "plain text compressing {} bytes ({}x{}x{})",
            plain_text.len(),
            w,
            h,
            bbp
        );

        // see if the bitmap looks like the way with think it should (bits per pixel map + 1 height worth of filter bytes)
        if (bbp * w * h) + h == plain_text.len() {
            let (bitmap, filters) = undo_png_filters(plain_text, w, h, bbp);

            let enc = webp::Encoder::new(
                &bitmap,
                match png_header.color_type {
                    PngColorType::RGB => webp::PixelLayout::Rgb,
                    PngColorType::RGBA => webp::PixelLayout::Rgba,
                },
                png_header.width,
                png_header.height,
            );

            let mut webpconfig = webp::WebPConfig::new().unwrap();
            webpconfig.lossless = 1;
            webpconfig.alpha_compression = 0;
            webpconfig.exact = 1; // undocumented option, but required to not throw away color if alpha channel is zero

            // this is the default quality setting for webp lossless, we could dial it up
            // but the quality gains are marginal for the CPU cost, although the
            // CPU decompression cost is the same.
            webpconfig.quality = 75.0; // 0..100 higher is slower but better compression
            webpconfig.method = 4; // 0..6 higher is slower but better compression

            let comp = match enc.encode_advanced(&webpconfig) {
                Ok(c) => c,
                Err(e) => {
                    return err_exit_code(
                        ExitCode::WebPDecodeError,
                        format!("Webp encode failed: {:?}", e),
                    );
                }
            };

            result.write_all(&[BLOCK_TYPE_PNG])?; // placeholder — caller skips this byte

            write_varint(result, corrections.len() as u32)?;
            write_varint(result, comp.deref().len() as u32)?;

            log::debug!(
                "Webp compressed {} bytes (vs {})",
                comp.deref().len(),
                idat.total_chunk_length
            );

            idat.write_to_bytestream(result)?;
            result.write_all(&filters)?;

            result.write_all(&corrections)?;
            result.write_all(comp.deref())?;

            return Ok(());
        }
    }

    return err_exit_code(
        ExitCode::InvalidCompressedWrapper,
        "Webp compression not supported",
    );
}

fn webp_decompress(
    filters: &[u8],
    webp: Vec<u8>,
    header: &crate::idat_parse::PngHeader,
) -> Result<Vec<u8>> {
    #[cfg(feature = "webp")]
    match webp::Decoder::new(webp.as_slice()).decode() {
        Some(result) => {
            use crate::idat_parse::apply_png_filters_with_types;
            use std::ops::Deref;

            let m = result.deref();

            return Ok(apply_png_filters_with_types(
                m,
                header.width as usize,
                header.height as usize,
                if result.is_alpha() { 4 } else { 3 },
                header.color_type.bytes_per_pixel(),
                &filters,
            ));
        }
        _ => {}
    }
    return err_exit_code(ExitCode::InvalidCompressedWrapper, "Webp decode failed");
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

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
    /// (compression_bits, block_type_bits) in order, stopping after EOS.
    fn parse_wire_block_types(data: &[u8]) -> Vec<(u8, u8)> {
        let mut cursor = std::io::Cursor::new(data);
        let version = cursor.read_u8().unwrap();
        assert_eq!(version, COMPRESSED_WRAPPER_VERSION_2);
        let mut blocks = Vec::new();
        while (cursor.position() as usize) < data.len() {
            let type_byte = cursor.read_u8().unwrap();
            let compression = type_byte & BLOCK_COMPRESSION_MASK;
            let block_type = type_byte & BLOCK_TYPE_MASK;
            blocks.push((compression, block_type));
            let size = read_varint(&mut cursor).unwrap() as u64;
            cursor.set_position(cursor.position() + size);
            if compression == BLOCK_COMPRESSION_ZSTD && block_type == BLOCK_TYPE_EOS {
                break;
            }
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
            BLOCK_TYPE_EOS,
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
        assert_eq!(BLOCK_COMPRESSION_ZSTD | BLOCK_TYPE_EOS, 0x7F);
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

    /// The EOS block that closes the Zstd frame must always use BLOCK_COMPRESSION_ZSTD.
    #[test]
    fn test_encoder_eos_uses_zstd_compression_bit() {
        // Plain bytes with no DEFLATE streams → [version][literal][EOS].
        let input = vec![0xABu8; 64];
        let mut ctx =
            PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false);
        let compressed = ctx.process_vec(&input).unwrap();

        let blocks = parse_wire_block_types(&compressed);
        assert_eq!(
            blocks.last(),
            Some(&(BLOCK_COMPRESSION_ZSTD, BLOCK_TYPE_EOS)),
            "last block must be the Zstd EOS marker"
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

        let has_deflate = blocks
            .iter()
            .any(|&(_, t)| t == BLOCK_TYPE_DEFLATE);
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
}
