use byteorder::ReadBytesExt;

use std::{
    collections::VecDeque,
    io::{BufRead, Read, Write},
    usize,
};

use crate::{
    hash_algorithm::HashAlgorithm,
    idat_parse::{IdatContents, PngHeader, recreate_idat},
    preflate_error::{AddContext, ExitCode, PreflateError, Result, err_exit_code},
    preflate_input::PlainText,
    scan_deflate::{FindStreamResult, FoundStream, FoundStreamType, find_deflate_stream},
    scoped_read::ScopedRead,
    stream_processor::{
        PreflateStreamProcessor, RecreateStreamProcessor, recreate_whole_deflate_stream,
    },
    utils::{TakeReader, write_dequeue},
};

/// Configuration for the deflate process
#[derive(Debug, Copy, Clone)]
pub struct PreflateConfig {
    /// internal log level for the deflate process (used only by testing)
    pub log_level: u32,

    /// As we scan for deflate streams, we need to have a minimum memory
    /// chunk to process. We scan this chunk for deflate streams and at least
    /// deflate one block has to fit into a chunk for us to recognize it.
    pub min_chunk_size: usize,

    /// The maximum size of a deflate or PNG compressed block we will consider. If
    /// a deflate stream is larger than this, we will not decompress it and
    /// just write it out as a literal block.
    pub max_chunk_size: usize,

    /// The maximum size of a plain text block that we will compress per
    /// deflate stream we find. This is in proportion to the min_chunk_size,
    /// so as we are decompressing we don't run out of memory. If we hit
    /// this limit, then we will skip this stream and write out the
    /// deflate stream without decompressing it.
    pub plain_text_limit: usize,

    /// The maximum overall size of plain text that we will compress. This is
    /// global to the entire container and limits the amount of processing that
    /// we will do to avoid running out of CPU time on a single file. Once we
    /// hit this limit, we will stop looking for deflate streams and just write
    /// out the rest of the data as literal blocks.
    pub total_plain_text_limit: u64,
}

impl Default for PreflateConfig {
    fn default() -> Self {
        PreflateConfig {
            log_level: 0,
            min_chunk_size: 1024 * 1024,
            max_chunk_size: 64 * 1024 * 1024,
            plain_text_limit: 128 * 1024 * 1024,
            total_plain_text_limit: 512 * 1024 * 1024,
        }
    }
}

const COMPRESSED_WRAPPER_VERSION_1: u8 = 1;

/// literal chunks are just copied to the output
const LITERAL_CHUNK: u8 = 0;

/// zlib compressed chunks are zlib compressed
const DEFLATE_STREAM: u8 = 1;

/// PNG chunks are IDAT chunks that are zlib compressed
const PNG_COMPRESSED: u8 = 2;

/// deflate stream that continues the previous one with the same dictionary, bitstream etc
const DEFLATE_STREAM_CONTINUE: u8 = 3;

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

fn write_literal_block(content: &[u8], destination: &mut impl Write) -> Result<()> {
    destination.write_all(&[LITERAL_CHUNK])?;
    write_varint(destination, content.len() as u32)?;
    destination.write_all(content)?;
    Ok(())
}

fn write_chunk_block(
    result: &mut impl Write,
    chunk: FoundStream,
    stats: &mut PreflateStats,
) -> Result<Option<PreflateStreamProcessor>> {
    match chunk.chunk_type {
        FoundStreamType::DeflateStream(parameters, state) => {
            result.write_all(&[DEFLATE_STREAM])?;

            write_varint(result, chunk.corrections.len() as u32)?;
            write_varint(result, state.plain_text().text().len() as u32)?;

            result.write_all(&chunk.corrections)?;
            result.write_all(&state.plain_text().text())?;

            stats.overhead_bytes += chunk.corrections.len() as u64;
            stats.uncompressed_size += state.plain_text().len() as u64;
            stats.hash_algorithm = parameters.hash_algorithm;

            if !state.is_done() {
                return Ok(Some(state));
            }
        }

        FoundStreamType::IDATDeflate(parameters, mut idat, plain_text) => {
            if webp_compress(result, &plain_text, &chunk.corrections, &idat).is_err() {
                log::debug!("non-Webp compressed {}", idat.total_chunk_length);

                result.write_all(&[PNG_COMPRESSED])?;
                write_varint(result, chunk.corrections.len() as u32)?;
                write_varint(result, plain_text.text().len() as u32)?;

                idat.png_header = None;
                idat.write_to_bytestream(result)?;

                result.write_all(&chunk.corrections)?;
                result.write_all(&plain_text.text())?;
            }

            stats.uncompressed_size += plain_text.len() as u64;
            stats.hash_algorithm = parameters.hash_algorithm;
            stats.overhead_bytes += chunk.corrections.len() as u64;
        }
    }
    Ok(None)
}

/// Scans for multiple deflate streams in an arbitrary binary file, decompresses the streams and
/// returns an uncompressed file that can then be recompressed using a better algorithm.
/// This can then be passed back into recreate_whole_from_container to recreate the exact original file.
///
/// Note that the result is NOT compressed and has to be compressed by some other algorithm
/// in order to see any savings.
///
/// This is a wrapper for PreflateContainerProcessor.
pub fn preflate_whole_into_container(
    config: PreflateConfig,
    compressed_data: &mut impl BufRead,
    write: &mut impl Write,
) -> Result<PreflateStats> {
    let mut context = PreflateContainerProcessor::new(config);
    context.copy_to_end(compressed_data, write).unwrap();

    Ok(context.stats())
}

/// Takes the binary output of preflate_whole_into_container and recreates the original file.
///
/// This is a wrapper for RecreateContainerProcessor.
pub fn recreate_whole_from_container(
    source: &mut impl BufRead,
    destination: &mut impl Write,
) -> Result<()> {
    let mut recreate = RecreateContainerProcessor::new(usize::MAX);
    recreate.copy_to_end(source, destination).context()
}

#[cfg(test)]
fn read_chunk_block_slow(
    source: &mut impl BufRead,
    destination: &mut impl Write,
) -> std::result::Result<(), PreflateError> {
    let mut p = RecreateContainerProcessor::new_single_chunk(usize::MAX);
    p.copy_to_end_size(source, destination, 1, 1).context()
}

#[test]
fn roundtrip_chunk_block_literal() {
    let mut buffer = Vec::new();

    write_literal_block(b"hello", &mut buffer).unwrap();

    let mut read_cursor = std::io::Cursor::new(buffer);
    let mut destination = Vec::new();
    read_chunk_block_slow(&mut read_cursor, &mut destination).unwrap();

    assert!(destination == b"hello");
}

#[test]
fn roundtrip_chunk_block_deflate() {
    let contents = crate::utils::read_file("compressed_zlib_level1.deflate");

    let mut stream_state = PreflateStreamProcessor::new(usize::MAX, true);
    let results = stream_state.decompress(&contents, 1).unwrap();

    let mut buffer = Vec::new();

    let mut stats = PreflateStats::default();
    write_chunk_block(
        &mut buffer,
        FoundStream {
            chunk_type: FoundStreamType::DeflateStream(results.parameters.unwrap(), stream_state),
            corrections: results.corrections,
        },
        &mut stats,
    )
    .unwrap();

    let mut read_cursor = std::io::Cursor::new(buffer);
    let mut destination = Vec::new();
    read_chunk_block_slow(&mut read_cursor, &mut destination).unwrap();

    assert!(destination == contents);
}

#[test]
fn roundtrip_chunk_block_png() {
    let f = crate::utils::read_file("treegdi.png");

    // we know the first IDAT chunk starts at 83 (avoid testing the scan_deflate code in a unit teast)
    let (idat_contents, deflate_stream) = crate::idat_parse::parse_idat(None, &f[83..]).unwrap();
    let mut stream = PreflateStreamProcessor::new(usize::MAX, true);
    let results = stream.decompress(&deflate_stream, 1).unwrap();

    let total_chunk_length = idat_contents.total_chunk_length;

    let mut buffer = Vec::new();

    let mut stats = PreflateStats::default();
    write_chunk_block(
        &mut buffer,
        FoundStream {
            chunk_type: FoundStreamType::IDATDeflate(
                results.parameters.unwrap(),
                idat_contents,
                stream.detach_plain_text(),
            ),
            corrections: results.corrections,
        },
        &mut stats,
    )
    .unwrap();

    let mut read_cursor = std::io::Cursor::new(buffer);
    let mut destination = Vec::new();
    read_chunk_block_slow(&mut read_cursor, &mut destination).unwrap();

    assert!(destination == &f[83..83 + total_chunk_length]);
}

#[cfg(test)]
fn roundtrip_deflate_chunks(filename: &str) {
    use crate::utils::assert_eq_array;

    let f = crate::utils::read_file(filename);

    println!("Processing file: {}", filename);

    let mut expanded = Vec::new();
    preflate_whole_into_container(
        PreflateConfig::default(),
        &mut std::io::Cursor::new(&f),
        &mut expanded,
    )
    .unwrap();

    println!("Recreating file: {}", filename);

    let mut read_cursor = std::io::Cursor::new(expanded);

    let mut destination = Vec::new();
    recreate_whole_from_container(&mut read_cursor, &mut destination).unwrap();

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
fn verify_zip_compress() {
    use crate::utils::read_file;
    let v = read_file("samplezip.zip");

    let mut expanded = Vec::new();
    preflate_whole_into_container(
        PreflateConfig::default(),
        &mut std::io::Cursor::new(&v),
        &mut expanded,
    )
    .unwrap();

    let mut recompressed = Vec::new();
    recreate_whole_from_container(&mut std::io::Cursor::new(expanded), &mut recompressed).unwrap();

    assert!(v == recompressed);
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
        max_output_write: usize,
    ) -> Result<bool>;

    #[cfg(test)]
    fn process_vec(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut writer = Vec::new();

        self.copy_to_end(&mut std::io::Cursor::new(&input), &mut writer)
            .context()?;

        Ok(writer)
    }

    #[cfg(test)]
    fn process_vec_size(
        &mut self,
        input: &[u8],
        read_chunk_size: usize,
        write_chunk_size: usize,
    ) -> Result<Vec<u8>> {
        let mut writer = Vec::new();

        self.copy_to_end_size(
            &mut std::io::Cursor::new(&input),
            &mut writer,
            read_chunk_size,
            write_chunk_size,
        )
        .context()?;

        Ok(writer)
    }

    /// Reads everything from input and writes it to the output.
    /// Wraps calls to process buffer
    fn copy_to_end(&mut self, input: &mut impl BufRead, output: &mut impl Write) -> Result<()> {
        self.copy_to_end_size(input, output, 1024 * 1024, 1024 * 1024)
    }

    /// Reads everything from input and writes it to the output.
    /// Wraps calls to process buffer
    fn copy_to_end_size(
        &mut self,
        input: &mut impl BufRead,
        output: &mut impl Write,
        read_chunk_size: usize,
        write_chunk_size: usize,
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
                if self
                    .process_buffer(&[], true, output, usize::MAX)
                    .context()?
                {
                    break;
                }
            } else {
                // process buffer a piece at a time to avoid overflowing memory
                let mut amount_read = 0;
                while amount_read < buffer.len() {
                    let chunk_size = (buffer.len() - amount_read).min(read_chunk_size);

                    assert!(
                        !self
                            .process_buffer(
                                &buffer[amount_read..amount_read + chunk_size],
                                false,
                                output,
                                write_chunk_size,
                            )
                            .context()?,
                        "process_buffer should not return done until input is done"
                    );

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
    result: VecDeque<u8>,
    compression_stats: PreflateStats,
    input_complete: bool,
    total_plain_text_seen: u64,

    state: ChunkParseState,
    config: PreflateConfig,
}

impl PreflateContainerProcessor {
    pub fn new(config: PreflateConfig) -> Self {
        PreflateContainerProcessor {
            content: Vec::new(),
            compression_stats: PreflateStats::default(),
            result: VecDeque::new(),
            input_complete: false,
            state: ChunkParseState::Start,
            total_plain_text_seen: 0,
            config,
        }
    }
}

impl ProcessBuffer for PreflateContainerProcessor {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
        max_output_write: usize,
    ) -> Result<bool> {
        if self.input_complete && (input.len() > 0 || !input_complete) {
            return Err(PreflateError::new(
                ExitCode::InvalidParameter,
                "more data provided after input_complete signaled",
            ));
        }

        if input.len() > 0 {
            self.compression_stats.deflate_compressed_size += input.len() as u64;
            self.content.extend_from_slice(input);
        }

        loop {
            // wait until we have at least min_chunk_size before we start processing
            if self.content.is_empty()
                || (!input_complete && self.content.len() < self.config.min_chunk_size)
            {
                break;
            }

            match &mut self.state {
                ChunkParseState::Start => {
                    self.result.write_all(&[COMPRESSED_WRAPPER_VERSION_1])?;
                    self.state = ChunkParseState::Searching(None);
                }
                ChunkParseState::Searching(prev_ihdr) => {
                    if self.total_plain_text_seen > self.config.total_plain_text_limit {
                        // once we've exceeded our limit, we don't do any more compression
                        // this is to ensure we don't suck the CPU time for too long on
                        // a single file
                        write_literal_block(&self.content, &mut self.result)?;

                        self.content.clear();
                        break;
                    }

                    // here we are looking for a deflate stream or PNG chunk
                    match find_deflate_stream(
                        &self.content,
                        self.config.log_level,
                        self.config.plain_text_limit,
                        prev_ihdr,
                    ) {
                        FindStreamResult::Found(next, chunk) => {
                            // the gap between the start and the beginning of the deflate stream
                            // is written out as a literal block
                            if next.start != 0 {
                                write_literal_block(&self.content[..next.start], &mut self.result)?;
                            }

                            if let Some(mut state) = write_chunk_block(
                                &mut self.result,
                                chunk,
                                &mut self.compression_stats,
                            )
                            .context()?
                            {
                                self.total_plain_text_seen += state.plain_text().len() as u64;
                                state.shrink_to_dictionary();

                                self.state = ChunkParseState::DeflateContinue(state);
                            }

                            self.content.drain(0..next.end);
                        }
                        FindStreamResult::ShortRead => {
                            if input_complete || self.content.len() > self.config.max_chunk_size {
                                // if we have too much data or have no more data,
                                // we just write it out as a literal block with everything we have
                                write_literal_block(&self.content, &mut self.result)?;

                                self.content.clear();
                            } else {
                                // we don't have enough data to process the stream, so we just
                                // wait for more data
                                break;
                            }
                        }
                        FindStreamResult::None => {
                            // couldn't find anything, just write the rest as a literal block
                            write_literal_block(&self.content, &mut self.result)?;

                            self.content.clear();
                        }
                    }
                }
                ChunkParseState::DeflateContinue(state) => {
                    // here we have a deflate stream that we need to continue
                    // right now we error out if the continuation cannot be processed
                    match state.decompress(&self.content, 0) {
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

                            self.result.write_all(&[DEFLATE_STREAM_CONTINUE])?;

                            write_varint(&mut self.result, res.corrections.len() as u32)?;
                            write_varint(&mut self.result, state.plain_text().len() as u32)?;

                            self.result.write_all(&res.corrections)?;
                            self.result.write_all(&state.plain_text().text())?;

                            self.total_plain_text_seen += state.plain_text().len() as u64;
                            self.compression_stats.overhead_bytes += res.corrections.len() as u64;
                            self.compression_stats.uncompressed_size +=
                                state.plain_text().len() as u64;

                            self.content.drain(0..res.compressed_size);

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

        if input_complete {
            self.input_complete = true;

            if self.content.len() > 0 {
                write_literal_block(&self.content, &mut self.result)?;
            }
            self.content.clear();
        }

        // write any output we have pending in the queue into the output buffer
        write_dequeue(&mut self.result, writer, max_output_write).context()?;

        Ok(self.input_complete && self.result.len() == 0)
    }

    fn stats(&self) -> PreflateStats {
        self.compression_stats
    }
}

#[cfg(test)]
pub struct NopProcessBuffer {
    result: VecDeque<u8>,
}

#[cfg(test)]
impl NopProcessBuffer {
    pub fn new() -> Self {
        NopProcessBuffer {
            result: VecDeque::new(),
        }
    }
}

#[cfg(test)]
impl ProcessBuffer for NopProcessBuffer {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
        max_output_write: usize,
    ) -> Result<bool> {
        self.result.extend(input);

        write_dequeue(&mut self.result, writer, max_output_write).context()?;

        Ok(input_complete && self.result.len() == 0)
    }
}

enum DecompressionState {
    Start,
    StartSegment,
    LiteralBlock(usize),
    DeflateBlock(usize, usize),
    PNGBlock {
        correction_length: usize,
        uncompressed_length: usize,
        idat: IdatContents,
        filters: Vec<u8>,
    },
}

/// recreates the orignal content from the chunked data
pub struct RecreateContainerProcessor {
    capacity: usize,
    input: VecDeque<u8>,
    result: VecDeque<u8>,
    input_complete: bool,
    state: DecompressionState,

    /// state of the predictor and plain text if we need to contiune a deflate stream
    /// if it was too big to complete in a single chunk
    deflate_continue_state: Option<RecreateStreamProcessor>,
}

impl RecreateContainerProcessor {
    pub fn new(capacity: usize) -> Self {
        RecreateContainerProcessor {
            input: VecDeque::new(),
            result: VecDeque::new(),
            capacity,
            input_complete: false,
            state: DecompressionState::Start,
            deflate_continue_state: None,
        }
    }

    /// for testing reading a single chunk (skip header)
    pub fn new_single_chunk(capacity: usize) -> Self {
        RecreateContainerProcessor {
            input: VecDeque::new(),
            result: VecDeque::new(),
            capacity,
            input_complete: false,
            state: DecompressionState::StartSegment,
            deflate_continue_state: None,
        }
    }
}

impl ProcessBuffer for RecreateContainerProcessor {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
        mut max_output_write: usize,
    ) -> Result<bool> {
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

            self.process_buffer_internal()?;
            let amount_written =
                write_dequeue(&mut self.result, writer, max_output_write).context()?;

            max_output_write -= amount_written;
            if amount_read == input.len() {
                break;
            }
        }

        Ok(self.input_complete && self.result.len() == 0)
    }
}

impl RecreateContainerProcessor {
    fn process_buffer_internal(&mut self) -> Result<()> {
        loop {
            match &mut self.state {
                DecompressionState::Start => {
                    if !self.input_complete && self.input.len() == 0 {
                        break;
                    }

                    let version = self.input.read_u8()?;

                    if version != COMPRESSED_WRAPPER_VERSION_1 {
                        return err_exit_code(
                            ExitCode::InvalidCompressedWrapper,
                            format!("Invalid version {version}"),
                        );
                    }

                    self.state = DecompressionState::StartSegment;
                }
                DecompressionState::StartSegment => {
                    // here's a good place to stop if we run out of input
                    if self.input.len() == 0 {
                        break;
                    }

                    // use scoped read so that if we run out of bytes we can undo the read and wait for more input
                    self.state = match self.input.scoped_read(|r| match r.read_u8()? {
                        LITERAL_CHUNK => {
                            let length = read_varint(r)? as usize;

                            Ok(DecompressionState::LiteralBlock(length))
                        }
                        DEFLATE_STREAM => {
                            let correction_length = read_varint(r)? as usize;
                            let uncompressed_length = read_varint(r)? as usize;

                            // clear the deflate state if we are starting a new block
                            self.deflate_continue_state = None;

                            Ok(DecompressionState::DeflateBlock(
                                correction_length,
                                uncompressed_length,
                            ))
                        }
                        DEFLATE_STREAM_CONTINUE => {
                            let correction_length = read_varint(r)? as usize;
                            let uncompressed_length = read_varint(r)? as usize;

                            if self.deflate_continue_state.is_none() {
                                return err_exit_code(
                                    ExitCode::InvalidCompressedWrapper,
                                    "no deflate state to continue",
                                );
                            }

                            Ok(DecompressionState::DeflateBlock(
                                correction_length,
                                uncompressed_length,
                            ))
                        }
                        PNG_COMPRESSED => {
                            let correction_length = read_varint(r)? as usize;
                            let uncompressed_length = read_varint(r)? as usize;
                            let idat = IdatContents::read_from_bytestream(r)?;

                            let mut filters = Vec::new();
                            if let Some(png_header) = &idat.png_header {
                                filters.resize(png_header.height as usize, 0);
                                r.read_exact(&mut filters[..])?;
                            }

                            Ok(DecompressionState::PNGBlock {
                                correction_length,
                                uncompressed_length,
                                idat,
                                filters,
                            })
                        }

                        _ => Err(PreflateError::new(
                            ExitCode::InvalidCompressedWrapper,
                            "Invalid chunk",
                        )),
                    }) {
                        Ok(s) => s,
                        Err(e) => {
                            if !self.input_complete && e.exit_code() == ExitCode::ShortRead {
                                // wait for more input if we ran out of bytes here
                                break;
                            } else {
                                return Err(e);
                            }
                        }
                    }
                }

                DecompressionState::LiteralBlock(length) => {
                    let source_size = self.input.len();
                    if source_size < *length {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input",
                            ));
                        }
                        self.result.extend(self.input.drain(..));
                        *length -= source_size;
                        break;
                    }

                    self.result.extend(self.input.drain(0..*length));
                    self.state = DecompressionState::StartSegment;
                }

                DecompressionState::DeflateBlock(correction_length, uncompressed_length) => {
                    let source_size = self.input.len();
                    let total_length = *correction_length + *uncompressed_length;

                    if source_size < total_length {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input",
                            ));
                        }
                        break;
                    }

                    let corrections: Vec<u8> = self.input.drain(0..*correction_length).collect();

                    if let Some(reconstruct) = &mut self.deflate_continue_state {
                        let (comp, _) = reconstruct
                            .recompress(
                                &mut TakeReader::new(&mut self.input, *uncompressed_length),
                                &corrections,
                            )
                            .context()?;

                        self.result.extend(&comp);
                    } else {
                        let mut reconstruct = RecreateStreamProcessor::new();
                        let (comp, _) = reconstruct
                            .recompress(
                                &mut TakeReader::new(&mut self.input, *uncompressed_length),
                                &corrections,
                            )
                            .context()?;

                        self.result.extend(&comp);

                        self.deflate_continue_state = Some(reconstruct);
                    }

                    self.state = DecompressionState::StartSegment;
                }

                DecompressionState::PNGBlock {
                    correction_length,
                    uncompressed_length,
                    idat,
                    filters,
                } => {
                    let source_size = self.input.len();

                    let total_length = *correction_length + *uncompressed_length;
                    if source_size < total_length {
                        // wait till we have the full block
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input",
                            ));
                        }
                        break;
                    }

                    let corrections: Vec<u8> = self.input.drain(0..*correction_length).collect();

                    let plain_text;

                    if let Some(header) = &idat.png_header {
                        let webp: Vec<u8> = self.input.drain(0..*uncompressed_length).collect();

                        plain_text = webp_decompress(filters, webp, header).context()?;
                    } else {
                        plain_text = self.input.drain(0..*uncompressed_length).collect();
                    }

                    let recompressed =
                        recreate_whole_deflate_stream(&plain_text, &corrections).context()?;

                    recreate_idat(&idat, &recompressed[..], &mut self.result).context()?;

                    self.state = DecompressionState::StartSegment;
                }
            }
        }

        Ok(())
    }
}

fn webp_compress(
    result: &mut impl Write,
    plain_text: &PlainText,
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
            let (bitmap, filters) = undo_png_filters(plain_text.text(), w, h, bbp);

            let enc = webp::Encoder::new(
                &bitmap,
                match png_header.color_type {
                    PngColorType::RGB => webp::PixelLayout::Rgb,
                    PngColorType::RGBA => webp::PixelLayout::Rgba,
                },
                png_header.width,
                png_header.height,
            );

            let comp = enc.encode_lossless();
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

#[test]
fn test_baseline_calc() {
    use crate::utils::read_file;
    use crate::zstd_compression::ZstdCompressContext;

    let v = read_file("samplezip.zip");

    let mut context = ZstdCompressContext::new(
        PreflateContainerProcessor::new(PreflateConfig::default()),
        9,
        true,
    );

    let _r = context.process_vec(&v).unwrap();

    let stats = context.stats();

    println!("stats: {:?}", stats);

    // these change if the compression algorithm is altered, update them
    assert_eq!(stats.overhead_bytes, 463);
    assert_eq!(stats.zstd_compressed_size, 12444);
    assert_eq!(stats.uncompressed_size, 54871);
    assert_eq!(stats.zstd_baseline_size, 13661);
}

#[test]
fn roundtrip_small_chunk() {
    use crate::utils::{assert_eq_array, read_file};

    let original = read_file("pptxplaintext.zip");

    let mut context = PreflateContainerProcessor::new(PreflateConfig {
        log_level: 1,
        min_chunk_size: 100000,
        max_chunk_size: 100000,
        plain_text_limit: usize::MAX,
        total_plain_text_limit: u64::MAX,
    });

    let compressed = context.process_vec_size(&original, 20001, 997).unwrap();

    let mut context = RecreateContainerProcessor::new(usize::MAX);
    let recreated = context.process_vec_size(&compressed, 20001, 997).unwrap();

    assert_eq_array(&original, &recreated);
}

#[test]
fn roundtrip_small_plain_text() {
    use crate::utils::{assert_eq_array, read_file};

    let original = read_file("pptxplaintext.zip");

    let mut context = PreflateContainerProcessor::new(PreflateConfig {
        log_level: 1,
        min_chunk_size: 100000,
        max_chunk_size: 100000,
        plain_text_limit: 1000000,
        total_plain_text_limit: u64::MAX,
    });

    let compressed = context.process_vec_size(&original, 2001, 20001).unwrap();

    let mut context = RecreateContainerProcessor::new(usize::MAX);
    let recreated = context.process_vec_size(&compressed, 2001, 20001).unwrap();

    assert_eq_array(&original, &recreated);
}

#[test]
fn roundtrip_png_e2e() {
    use crate::utils::{assert_eq_array, read_file};

    let original = read_file("figma.png");

    println!("Compressing file");

    let mut context = PreflateContainerProcessor::new(PreflateConfig {
        log_level: 1,
        min_chunk_size: 100000,
        max_chunk_size: original.len(),
        plain_text_limit: usize::MAX,
        total_plain_text_limit: u64::MAX,
    });

    let compressed = context.process_vec_size(&original, 100100, 100100).unwrap();

    println!("Recreating file");

    let mut context = RecreateContainerProcessor::new(usize::MAX);
    let recreated = context
        .process_vec_size(&compressed, 100100, 100100)
        .unwrap();

    assert_eq_array(&original, &recreated);
}
