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

/// literal chunks are just copied to the output
const LITERAL_CHUNK: u8 = 0;

/// zlib compressed chunks are zlib compressed
const DEFLATE_STREAM: u8 = 1;

/// PNG chunks are IDAT chunks that are zlib compressed
const PNG_COMPRESSED: u8 = 2;

/// deflate stream that continues the previous one with the same dictionary, bitstream etc
const DEFLATE_STREAM_CONTINUE: u8 = 3;

/// JPEG Lepton compressed chunks are JPEG Lepton compressed
const JPEG_LEPTON_COMPRESSED: u8 = 4;

/// PNG chunk stored as WebP lossless — already compressed, written raw (bypasses Zstd)
const WEBP_COMPRESSED: u8 = 5;

/// V2 end-of-stream marker that carries the final Zstd finish bytes
const ZSTD_END_OF_STREAM: u8 = 0xFF;

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

            let compressed_size = emit_compressed_block(DEFLATE_STREAM, encoder, writer)?;

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
                // temp_vec[0] is the PNG_COMPRESSED type byte; temp_vec[1..] is the payload.
                let payload = &temp_vec[1..];
                writer.write_all(&[WEBP_COMPRESSED])?;
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

                let compressed_size = emit_compressed_block(PNG_COMPRESSED, encoder, writer)?;

                stats.uncompressed_size += plain_text.len() as u64;
                stats.hash_algorithm = parameters.hash_algorithm;
                stats.overhead_bytes += chunk.corrections.len() as u64;

                Ok((compressed_size, None))
            }
        }

        FoundStreamType::JPEGLepton(data) => {
            // JPEG is written raw (bypasses the encoder entirely)
            writer.write_all(&[JPEG_LEPTON_COMPRESSED])?;
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
            encoder: Some(
                zstd::stream::write::Encoder::new(Vec::new(), level).unwrap(),
            ),
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
                        let sz = emit_compressed_block(LITERAL_CHUNK, encoder, writer)?;
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
                                let sz = emit_compressed_block(LITERAL_CHUNK, encoder, writer)?;
                                self.compression_stats.zstd_compressed_size += sz as u64;
                            }

                            let (compressed_size, next_state) =
                                write_chunk_block_v2(self.encoder.as_mut().unwrap(), writer, chunk, &mut self.compression_stats)
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
                                let sz = emit_compressed_block(LITERAL_CHUNK, encoder, writer)?;
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
                            let sz = emit_compressed_block(LITERAL_CHUNK, encoder, writer)?;
                            self.compression_stats.zstd_compressed_size += sz as u64;

                            self.content.clear();
                            self.last_attempt_chunk_size = 0;
                        }
                    }
                }
                ChunkParseState::DeflateContinue(state) => {
                    // here we have a deflate stream that we need to continue
                    // right now we error out if the continuation cannot be processed
                    match state.decompress(&self.content) {
                        Err(_e) => {
                            // indicate that we got an error while trying to continue
                            // the compression of a previous chunk, this happens
                            // when the stream significantly diverged from the behavior we estimated
                            // in the first chunk that we saw
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
                            let sz = emit_compressed_block(DEFLATE_STREAM_CONTINUE, encoder, writer)?;
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
                let sz = emit_compressed_block(LITERAL_CHUNK, encoder, writer)?;
                self.compression_stats.zstd_compressed_size += sz as u64;
            }
            self.content.clear();

            // Finalize the Zstd encoder and write the end-of-stream marker
            let encoder = self.encoder.take().unwrap();
            let finish_bytes = encoder.finish().context()?;
            writer.write_all(&[ZSTD_END_OF_STREAM])?;
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

#[cfg(test)]
pub struct NopProcessBuffer {}

#[cfg(test)]
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

enum DecompressionState {
    Start,
    StartSegment,
    /// accumulate compressed_size bytes into compressed_data, then record block_type.
    AccumulateBlock {
        block_type: u8,
        compressed_size: usize,
    },
    /// accumulate lepton bytes and store as BlockInfo::Jpeg (processed at end).
    JpegAccumulate {
        lepton_length: usize,
    },
    /// accumulate raw WebP-compressed PNG bytes (stored directly, bypass Zstd).
    WebpAccumulate {
        total_len: usize,
    },
    /// accumulate final Zstd finish bytes, then batch-decode the whole stream.
    DecodeAll {
        final_size: usize,
    },
}

/// Describes a single block in the encoded stream, used to replay processing after batch decode.
enum BlockInfo {
    /// A non-JPEG block; its content comes from the batch-decoded Zstd output.
    Compressed(u8),
    /// A JPEG/Lepton block stored raw; bytes are kept here and decoded directly.
    Jpeg(Vec<u8>),
    /// A WebP-compressed PNG block stored raw; bytes are kept here and decoded directly.
    RawWebp(Vec<u8>),
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

    /// ordered list of all blocks seen so far
    blocks: Vec<BlockInfo>,

    /// concatenated Zstd-compressed bytes from all non-JPEG blocks
    compressed_data: Vec<u8>,
}

impl RecreateContainerProcessor {
    pub fn new(capacity: usize) -> Self {
        RecreateContainerProcessor {
            input: VecDeque::new(),
            capacity,
            input_complete: false,
            state: DecompressionState::Start,
            deflate_continue_state: None,
            blocks: Vec::new(),
            compressed_data: Vec::new(),
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
                        match type_byte {
                            JPEG_LEPTON_COMPRESSED => {
                                let lepton_length = read_varint(r)? as usize;
                                Ok(DecompressionState::JpegAccumulate { lepton_length })
                            }
                            WEBP_COMPRESSED => {
                                let total_len = read_varint(r)? as usize;
                                Ok(DecompressionState::WebpAccumulate { total_len })
                            }
                            ZSTD_END_OF_STREAM => {
                                let final_size = read_varint(r)? as usize;
                                Ok(DecompressionState::DecodeAll { final_size })
                            }
                            other => {
                                let compressed_size = read_varint(r)? as usize;
                                Ok(DecompressionState::AccumulateBlock {
                                    block_type: other,
                                    compressed_size,
                                })
                            }
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
                    let compressed_size = *compressed_size;
                    self.compressed_data
                        .extend(self.input.drain(0..compressed_size));
                    self.blocks.push(BlockInfo::Compressed(block_type));
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
                    self.blocks.push(BlockInfo::Jpeg(lepton_bytes));
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
                    self.blocks.push(BlockInfo::RawWebp(webp_bytes));
                    self.state = DecompressionState::StartSegment;
                }

                DecompressionState::DecodeAll { final_size } => {
                    if self.input.len() < *final_size {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input in end-of-stream",
                            ));
                        }
                        break;
                    }

                    // Collect final finish bytes and batch-decode the entire Zstd stream.
                    self.compressed_data
                        .extend(self.input.drain(0..*final_size));
                    let decoded = zstd::decode_all(Cursor::new(&self.compressed_data))
                        .map_err(|e| {
                            PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                format!("zstd decode failed: {e}"),
                            )
                        })?;

                    let mut cursor = Cursor::new(decoded);
                    let blocks = std::mem::take(&mut self.blocks);
                    for block_info in blocks {
                        match block_info {
                            BlockInfo::Compressed(block_type) => {
                                process_compressed_block(
                                    block_type,
                                    &mut cursor,
                                    &mut self.deflate_continue_state,
                                    writer,
                                )?;
                            }
                            BlockInfo::Jpeg(lepton_data) => {
                                match lepton_jpeg::decode_lepton(
                                    &mut Cursor::new(&lepton_data),
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
                            }
                            BlockInfo::RawWebp(webp_bytes) => {
                                // Payload is what webp_compress wrote after the PNG_COMPRESSED
                                // type byte, so process_compressed_block can parse it directly.
                                process_compressed_block(
                                    PNG_COMPRESSED,
                                    &mut Cursor::new(webp_bytes),
                                    &mut self.deflate_continue_state,
                                    writer,
                                )?;
                            }
                        }
                    }

                    self.state = DecompressionState::StartSegment;
                }
            }
        }

        Ok(())
    }
}

/// Parses and processes a single non-JPEG block from a cursor over the batch-decoded output.
///
/// The encoded layout (as written by the encoder) for each block type is:
///   LITERAL_CHUNK:          varint(len) + data
///   DEFLATE_STREAM:         varint(corrections_len) + varint(plaintext_len) + corrections + plaintext
///   DEFLATE_STREAM_CONTINUE: same layout as DEFLATE_STREAM
///   PNG_COMPRESSED:         varint(correction_length) + varint(uncompressed_length) +
///                           IdatContents + [filters if png_header present] +
///                           corrections + (webp_data or raw_plaintext)
fn process_compressed_block(
    block_type: u8,
    cursor: &mut Cursor<Vec<u8>>,
    deflate_continue_state: &mut Option<RecreateStreamProcessor>,
    writer: &mut impl Write,
) -> Result<()> {
    match block_type {
        LITERAL_CHUNK => {
            let length = read_varint(cursor)? as usize;
            let mut data = vec![0u8; length];
            cursor.read_exact(&mut data).map_err(|e| {
                PreflateError::new(ExitCode::InvalidCompressedWrapper, e.to_string())
            })?;
            writer.write_all(&data)?;
        }
        DEFLATE_STREAM => {
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
        DEFLATE_STREAM_CONTINUE => {
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
        PNG_COMPRESSED => {
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

            result.write_all(&[PNG_COMPRESSED])?;

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
fn roundtrip_deflate_chunks(filename: &str) {
    use crate::utils::assert_eq_array;

    let f = crate::utils::read_file(filename);

    println!("Processing file: {}", filename);

    let mut expanded = Vec::new();
    let mut ctx = PreflateContainerProcessor::new(&PreflateContainerConfig::default(), 1, false);
    ctx.copy_to_end(&mut std::io::Cursor::new(&f), &mut expanded).unwrap();

    println!("Recreating file: {}", filename);

    let mut destination = Vec::new();
    let mut ctx = RecreateContainerProcessor::new(usize::MAX);
    ctx.copy_to_end(&mut std::io::Cursor::new(expanded), &mut destination).unwrap();

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

    let mut context = PreflateContainerProcessor::new(&PreflateContainerConfig {
        min_chunk_size: 100000,
        max_chunk_size: 100000,
        total_plain_text_limit: u64::MAX,
        ..Default::default()
    }, 1, false);

    let compressed = context.process_vec_size(&original, 20001).unwrap();

    let mut context = RecreateContainerProcessor::new(usize::MAX);
    let recreated = context.process_vec_size(&compressed, 20001).unwrap();

    assert_eq_array(&original, &recreated);
}

#[test]
fn roundtrip_small_plain_text() {
    use crate::utils::{assert_eq_array, read_file};

    let original = read_file("pptxplaintext.zip");

    let mut context = PreflateContainerProcessor::new(&PreflateContainerConfig {
        min_chunk_size: 100000,
        max_chunk_size: 100000,
        total_plain_text_limit: u64::MAX,
        ..Default::default()
    }, 1, false);

    let compressed = context.process_vec_size(&original, 2001).unwrap();

    let mut context = RecreateContainerProcessor::new(usize::MAX);
    let recreated = context.process_vec_size(&compressed, 2001).unwrap();

    assert_eq_array(&original, &recreated);
}

#[test]
fn roundtrip_zstd_per_block() {
    use crate::utils::{assert_eq_array, read_file};

    let original = read_file("samplezip.zip");

    let mut context = PreflateContainerProcessor::new(
        &PreflateContainerConfig::default(),
        1,
        false,
    );

    let compressed = context.process_vec(&original).unwrap();

    let mut context = RecreateContainerProcessor::new(usize::MAX);
    let recreated = context.process_vec(&compressed).unwrap();

    assert_eq_array(&original, &recreated);
}
