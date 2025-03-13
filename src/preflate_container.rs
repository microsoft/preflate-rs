use byteorder::ReadBytesExt;
use std::{
    collections::VecDeque,
    io::{Cursor, Read, Write},
    usize,
};

use crate::{
    deflate_stream::{
        recompress_deflate_stream, recompress_deflate_stream_with_predictor, DeflateStreamState,
        ReconstructionData,
    },
    hash_algorithm::HashAlgorithm,
    idat_parse::{recreate_idat, IdatContents},
    preflate_error::{err_exit_code, AddContext, ExitCode, PreflateError, Result},
    preflate_input::PlainText,
    scan_deflate::{find_deflate_stream, FoundStream, FoundStreamType},
    scoped_read::ScopedRead,
    token_predictor::TokenPredictor,
    utils::write_dequeue,
};

const COMPRESSED_WRAPPER_VERSION_1: u8 = 1;

/// literal chunks are just copied to the output
const LITERAL_CHUNK: u8 = 0;

/// zlib compressed chunks are zlib compressed
const DEFLATE_STREAM: u8 = 1;

/// PNG chunks are IDAT chunks that are zlib compressed
const PNG_COMPRESSED: u8 = 2;

pub fn write_varint(destination: &mut impl Write, value: u32) -> std::io::Result<()> {
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

pub fn read_varint(source: &mut impl Read) -> std::io::Result<u32> {
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
    stats: &mut CompressionStats,
) -> Result<Option<DeflateStreamState>> {
    match chunk.chunk_type {
        FoundStreamType::DeflateStream(parameters, state) => {
            result.write_all(&[DEFLATE_STREAM, !state.is_done() as u8])?;

            write_varint(result, chunk.corrections.len() as u32)?;
            write_varint(result, state.plain_text().text().len() as u32)?;

            result.write_all(&chunk.corrections)?;
            result.write_all(&state.plain_text().text())?;

            stats.overhead_bytes += chunk.corrections.len() as u64;
            stats.hash_algorithm = parameters.predictor.hash_algorithm;

            if !state.is_done() {
                return Ok(Some(state));
            }
        }
        FoundStreamType::IDATDeflate(parameters, idat, plain_text) => {
            result.write_all(&[PNG_COMPRESSED])?;
            write_varint(result, chunk.corrections.len() as u32)?;
            write_varint(result, plain_text.text().len() as u32)?;

            idat.write_to_bytestream(result)?;

            result.write_all(&chunk.corrections)?;
            result.write_all(&plain_text.text())?;

            stats.overhead_bytes += chunk.corrections.len() as u64;
            stats.hash_algorithm = parameters.predictor.hash_algorithm;
        }
    }
    Ok(None)
}

#[cfg(test)]
fn read_chunk_block(
    source: &mut impl Read,
    destination: &mut impl Write,
) -> std::result::Result<(), PreflateError> {
    let mut p = RecreateFromChunksContext::new_single_chunk(usize::MAX);
    p.copy_to_end_slow(source, destination).context()
}

#[test]
fn roundtrip_chunk_block_literal() {
    let mut buffer = Vec::new();

    write_literal_block(b"hello", &mut buffer).unwrap();

    let mut read_cursor = std::io::Cursor::new(buffer);
    let mut destination = Vec::new();
    read_chunk_block(&mut read_cursor, &mut destination).unwrap();

    assert!(destination == b"hello");
}

#[test]
fn roundtrip_chunk_block_deflate() {
    use crate::deflate_stream::DeflateStreamState;

    let contents = crate::utils::read_file("compressed_zlib_level1.deflate");

    let mut stream_state = DeflateStreamState::new();
    let results = stream_state.decompress(&contents, true, 1).unwrap();

    let mut buffer = Vec::new();

    let mut stats = CompressionStats::default();
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
    read_chunk_block(&mut read_cursor, &mut destination).unwrap();

    assert!(destination == contents);
}

#[test]
fn roundtrip_chunk_block_png() {
    let f = crate::utils::read_file("treegdi.png");

    // we know the first IDAT chunk starts at 83 (avoid testing the scan_deflate code in a unit teast)
    let (idat_contents, deflate_stream) = crate::idat_parse::parse_idat(&f[83..], 1).unwrap();
    let mut stream = crate::deflate_stream::DeflateStreamState::new();
    let results = stream.decompress(&deflate_stream, true, 1).unwrap();

    let total_chunk_length = idat_contents.total_chunk_length;

    let mut buffer = Vec::new();

    let mut stats = CompressionStats::default();
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
    read_chunk_block(&mut read_cursor, &mut destination).unwrap();

    assert!(destination == &f[83..83 + total_chunk_length]);
}

/// scans for deflate streams in a zlib compressed file, decompresses the streams and
/// returns an uncompressed file that can then be recompressed using a better algorithm.
/// This can then be passed back into recreated_zlib_chunks to recreate the exact original file.
pub fn expand_zlib_chunks(
    compressed_data: &[u8],
    loglevel: u32,
    compression_stats: &mut CompressionStats,
    write: &mut impl Write,
) -> Result<()> {
    let mut context = PreflateCompressionContext::new(loglevel, 1024 * 1024);
    context
        .copy_to_end(&mut Cursor::new(compressed_data), write)
        .unwrap();

    *compression_stats = context.stats();

    Ok(())
}

/// takes a binary chunk of data that was created by expand_zlib_chunks and recompresses it back to its
/// original form.
pub fn recreated_zlib_chunks(
    source: &mut impl Read,
    destination: &mut impl Write,
) -> std::result::Result<(), PreflateError> {
    let mut recreate = RecreateFromChunksContext::new(usize::MAX);
    recreate.copy_to_end(source, destination)
}

#[cfg(test)]
fn roundtrip_deflate_chunks(filename: &str) {
    use crate::utils::assert_eq_array;

    let f = crate::utils::read_file(filename);

    let mut stats = CompressionStats::default();
    let mut expanded = Vec::new();
    expand_zlib_chunks(&f, 1, &mut stats, &mut expanded).unwrap();

    let mut read_cursor = std::io::Cursor::new(expanded);

    let mut destination = Vec::new();
    recreated_zlib_chunks(&mut read_cursor, &mut destination).unwrap();

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

    let mut stats = CompressionStats::default();
    let mut expanded = Vec::new();
    expand_zlib_chunks(&v, 1, &mut stats, &mut expanded).unwrap();

    let mut recompressed = Vec::new();
    recreated_zlib_chunks(&mut Cursor::new(expanded), &mut recompressed).unwrap();

    assert!(v == recompressed);
}

#[derive(Debug, Copy, Clone, Default)]
pub struct CompressionStats {
    pub deflate_compressed_size: u64,
    pub zstd_compressed_size: u64,
    pub uncompressed_size: u64,
    pub overhead_bytes: u64,
    pub hash_algorithm: HashAlgorithm,
    pub zstd_baseline_size: u64,
}

pub trait ProcessBuffer {
    fn process_buffer(
        &mut self,
        input: &[u8],
        input_complete: bool,
        writer: &mut impl Write,
        max_output_write: usize,
    ) -> Result<bool>;

    fn process_vec(
        &mut self,
        input: &[u8],
        read_chunk_size: usize,
        write_chunk_size: usize,
    ) -> Result<Vec<u8>> {
        let mut writer = Vec::new();
        let mut done = false;

        let mut input_start_offset: usize = 0;

        while !done {
            let input_end_offset =
                (input_start_offset.saturating_add(read_chunk_size)).min(input.len());

            done = self.process_buffer(
                &input[input_start_offset..input_end_offset],
                input_start_offset == input.len(),
                &mut writer,
                write_chunk_size,
            )?;

            input_start_offset = input_end_offset;
        }
        Ok(writer)
    }

    /// reads everything from input and writes it to the output
    fn copy_to_end(&mut self, input: &mut impl Read, output: &mut impl Write) -> Result<()> {
        let mut buffer = [0; 65536];
        let mut input_complete = false;
        loop {
            let amount_read;

            if input_complete {
                amount_read = 0;
            } else {
                amount_read = input.read(&mut buffer).context()?;
                if amount_read == 0 {
                    input_complete = true
                }
            };

            let done = self
                .process_buffer(&buffer[0..amount_read], input_complete, output, usize::MAX)
                .context()?;
            if done {
                break;
            }
        }

        Ok(())
    }

    /// reads everything from input and writes it to the output, but one byte a time to test worst case parsing
    #[cfg(test)]
    fn copy_to_end_slow(&mut self, input: &mut impl Read, output: &mut impl Write) -> Result<()> {
        let mut buffer = [0; 1];
        let mut input_complete = false;
        loop {
            let amount_read;

            if input_complete {
                amount_read = 0;
            } else {
                amount_read = input.read(&mut buffer).context()?;
                if amount_read == 0 {
                    input_complete = true
                }
            };

            let done = self
                .process_buffer(&buffer[0..amount_read], input_complete, output, 1)
                .context()?;
            if done {
                break;
            }
        }

        Ok(())
    }

    fn stats(&self) -> CompressionStats {
        CompressionStats::default()
    }
}

#[derive(Debug)]
enum ChunkParseState {
    Start,
    Searching,
    DeflateContinue(DeflateStreamState),
}

pub struct PreflateCompressionContext {
    content: Vec<u8>,
    result: VecDeque<u8>,
    compression_stats: CompressionStats,

    log_level: u32,

    state: ChunkParseState,
    min_chunk_size: usize,
    input_complete: bool,
}

impl PreflateCompressionContext {
    pub fn new(log_level: u32, min_chunk_size: usize) -> Self {
        PreflateCompressionContext {
            content: Vec::new(),
            compression_stats: CompressionStats::default(),
            result: VecDeque::new(),
            log_level,
            input_complete: false,
            min_chunk_size,
            state: ChunkParseState::Start,
        }
    }
}

impl ProcessBuffer for PreflateCompressionContext {
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
            self.content.extend_from_slice(input);
        }

        loop {
            // wait until we have at least min_chunk_size before we start processing
            if self.content.is_empty()
                || (!input_complete && self.content.len() < self.min_chunk_size)
            {
                break;
            }

            match &mut self.state {
                ChunkParseState::Start => {
                    self.result.write_all(&[COMPRESSED_WRAPPER_VERSION_1])?;
                    self.state = ChunkParseState::Searching;
                }
                ChunkParseState::Searching => {
                    // here we are looking for a deflate stream or PNG chunk
                    if let Some((next, chunk)) = find_deflate_stream(&self.content, self.log_level)
                    {
                        // the gap between the start and the beginning of the deflate stream
                        // is written out as a literal block
                        if next.start != 0 {
                            write_literal_block(&self.content[..next.start], &mut self.result)?;
                        }

                        if let Some(mut state) =
                            write_chunk_block(&mut self.result, chunk, &mut self.compression_stats)
                                .context()?
                        {
                            state.shrink_to_dictionary();

                            self.state = ChunkParseState::DeflateContinue(state);
                        }

                        self.content.drain(0..next.end);
                    } else {
                        // couldn't find anything, just write the rest as a literal block
                        write_literal_block(&self.content, &mut self.result)?;

                        self.content.clear();
                    }
                }
                ChunkParseState::DeflateContinue(state) => {
                    // here we have a deflate stream that we need to continue
                    // right now we error out if the continuation cannot be processed
                    let res = state.decompress(&self.content, true, 0).context()?;
                    self.result.write_all(&[!state.is_done() as u8])?;

                    write_varint(&mut self.result, res.corrections.len() as u32)?;
                    write_varint(&mut self.result, state.plain_text().len() as u32)?;

                    self.result.write_all(&res.corrections)?;
                    self.result.write_all(&state.plain_text().text())?;

                    self.compression_stats.overhead_bytes += res.corrections.len() as u64;

                    self.content.drain(0..res.compressed_size);

                    if state.is_done() {
                        self.state = ChunkParseState::Searching;
                    } else {
                        state.shrink_to_dictionary();
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

    fn stats(&self) -> CompressionStats {
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
    DeflateBlock(usize, usize, bool),
    DeflateBlockContinue(PlainText, TokenPredictor),
    PNGBlock(usize, usize, IdatContents),
}

/// recreates the orignal content from the chunked data
pub struct RecreateFromChunksContext {
    capacity: usize,
    input: VecDeque<u8>,
    result: VecDeque<u8>,
    input_complete: bool,
    state: DecompressionState,
}

impl RecreateFromChunksContext {
    pub fn new(capacity: usize) -> Self {
        RecreateFromChunksContext {
            input: VecDeque::new(),
            result: VecDeque::new(),
            capacity,
            input_complete: false,
            state: DecompressionState::Start,
        }
    }

    /// for testing reading a single chunk (skip header)
    pub fn new_single_chunk(capacity: usize) -> Self {
        RecreateFromChunksContext {
            input: VecDeque::new(),
            result: VecDeque::new(),
            capacity,
            input_complete: false,
            state: DecompressionState::StartSegment,
        }
    }
}

impl ProcessBuffer for RecreateFromChunksContext {
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
            self.input.write_all(input).context()?;

            if self.input.len() > self.capacity {
                return Err(PreflateError::new(
                    ExitCode::InvalidParameter,
                    "input data exceeds capacity",
                ));
            }
        }

        if input_complete {
            self.input_complete = true;
        }

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
                            let partial = r.read_u8()? != 0;
                            let correction_length = read_varint(r)? as usize;
                            let uncompressed_length = read_varint(r)? as usize;

                            Ok(DecompressionState::DeflateBlock(
                                correction_length,
                                uncompressed_length,
                                partial,
                            ))
                        }
                        PNG_COMPRESSED => {
                            let correction_length = read_varint(r)? as usize;
                            let uncompressed_length = read_varint(r)? as usize;
                            let idat = IdatContents::read_from_bytestream(r)?;

                            Ok(DecompressionState::PNGBlock(
                                correction_length,
                                uncompressed_length,
                                idat,
                            ))
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

                DecompressionState::DeflateBlock(
                    correction_length,
                    uncompressed_length,
                    partial,
                ) => {
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
                    let mut plain_text = PlainText::new_with_data(
                        self.input.drain(0..*uncompressed_length).collect(),
                    );

                    let r = ReconstructionData::read(&corrections)?;
                    let mut predictor = TokenPredictor::new(&r.parameters.predictor);

                    self.result.extend(recompress_deflate_stream_with_predictor(
                        &plain_text,
                        &r.corrections,
                        &mut predictor,
                    )?);

                    if *partial {
                        plain_text.shrink_to_dictionary();

                        self.state =
                            DecompressionState::DeflateBlockContinue(plain_text, predictor);
                    } else {
                        self.state = DecompressionState::StartSegment;
                    }
                }

                DecompressionState::DeflateBlockContinue(dictionary, predictor) => {
                    let (partial, correction_length, uncompressed_length) =
                        self.input.scoped_read(|r| {
                            Ok((
                                r.read_u8()? != 0,
                                read_varint(r)? as usize,
                                read_varint(r)? as usize,
                            ))
                        })?;

                    let source_size = self.input.len();
                    let total_length = correction_length + uncompressed_length;

                    if source_size < total_length {
                        if self.input_complete {
                            return Err(PreflateError::new(
                                ExitCode::InvalidCompressedWrapper,
                                "unexpected end of input",
                            ));
                        }
                        break;
                    }

                    let corrections: Vec<u8> = self.input.drain(0..correction_length).collect();
                    dictionary.append_iter(self.input.drain(0..uncompressed_length));

                    self.result.extend(recompress_deflate_stream_with_predictor(
                        dictionary,
                        &corrections,
                        predictor,
                    )?);

                    if partial {
                        dictionary.shrink_to_dictionary();
                    } else {
                        self.state = DecompressionState::StartSegment;
                    }
                }

                DecompressionState::PNGBlock(correction_length, uncompressed_length, idat) => {
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
                    let plain_text: Vec<u8> = self.input.drain(0..*uncompressed_length).collect();

                    let recompressed = recompress_deflate_stream(
                        &PlainText::new_with_data(plain_text),
                        &corrections,
                    )
                    .context()?;

                    recreate_idat(&idat, &recompressed[..], &mut self.result).context()?;

                    self.state = DecompressionState::StartSegment;
                }
            }
        }

        write_dequeue(&mut self.result, writer, max_output_write).context()?;

        Ok(self.input_complete && self.result.len() == 0)
    }
}

#[test]
fn test_baseline_calc() {
    use crate::utils::read_file;
    use crate::zstd_compression::ZstdCompressContext;

    let v = read_file("samplezip.zip");

    let mut context =
        ZstdCompressContext::new(PreflateCompressionContext::new(0, 1024 * 1024), 9, true);

    let _r = context.process_vec(&v, usize::MAX, usize::MAX).unwrap();

    let stats = context.stats();

    println!("stats: {:?}", stats);

    // these change if the compression algorithm is altered, update them
    assert_eq!(stats.overhead_bytes, 466);
    assert_eq!(stats.zstd_compressed_size, 12432);
    assert_eq!(stats.zstd_baseline_size, 13661);
}

#[test]
fn roundtrip_contexts() {
    use crate::utils::{assert_eq_array, read_file};
    use crate::zstd_compression::{ZstdCompressContext, ZstdDecompressContext};

    let original = read_file("pptxplaintext.zip");

    let mut context =
        ZstdCompressContext::new(PreflateCompressionContext::new(0, 100000), 9, false);

    let compressed = context.process_vec(&original, 997, 997).unwrap();

    let stats = context.stats();
    println!("stats: {:?} buffer:{}", stats, compressed.len());
    println!(
        "zstd baseline size: {} -> comp {}",
        stats.zstd_baseline_size,
        compressed.len()
    );

    let mut context = ZstdDecompressContext::new(RecreateFromChunksContext::new(usize::MAX));

    let recreated = context.process_vec(&compressed, 997, 997).unwrap();

    assert_eq_array(&original, &recreated);
}
