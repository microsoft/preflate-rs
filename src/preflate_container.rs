use byteorder::ReadBytesExt;
use std::{
    collections::VecDeque,
    io::{Cursor, Read, Write},
    usize,
};

use crate::{
    decompress_deflate_stream,
    deflate_stream::{
        recompress_deflate_stream, recompress_deflate_stream_pred, DeflateContinueState,
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
    block: &FoundStream,
    compression_stats: &mut CompressionStats,
    destination: &mut impl Write,
    partial: bool,
) -> std::io::Result<usize> {
    match &block.chunk_type {
        FoundStreamType::DeflateStream(parameters) => {
            destination.write_all(&[DEFLATE_STREAM, partial as u8])?;

            write_varint(destination, block.corrections.len() as u32)?;
            write_varint(destination, block.plain_text.text().len() as u32)?;

            destination.write_all(&block.corrections)?;
            destination.write_all(&block.plain_text.text())?;

            compression_stats.overhead_bytes += block.corrections.len() as u64;
            compression_stats.hash_algorithm = parameters.predictor.hash_algorithm;
            Ok(block.compressed_size)
        }

        FoundStreamType::IDATDeflate(parameters, idat) => {
            destination.write_all(&[PNG_COMPRESSED])?;
            write_varint(destination, block.corrections.len() as u32)?;
            write_varint(destination, block.plain_text.text().len() as u32)?;

            idat.write_to_bytestream(destination)?;

            destination.write_all(&block.corrections)?;
            destination.write_all(&block.plain_text.text())?;

            compression_stats.overhead_bytes += block.corrections.len() as u64;
            compression_stats.hash_algorithm = parameters.predictor.hash_algorithm;

            Ok(idat.total_chunk_length)
        }
    }
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
    use crate::deflate_stream::decompress_deflate_stream;

    let contents = crate::utils::read_file("compressed_zlib_level1.deflate");
    let results = decompress_deflate_stream(None, &contents, true, 1).unwrap();

    let mut buffer = Vec::new();

    let mut stats = CompressionStats::default();
    write_chunk_block(
        &FoundStream {
            chunk_type: FoundStreamType::DeflateStream(results.parameters.unwrap()),
            compressed_size: contents.len() as usize,
            corrections: results.corrections,
            plain_text: results.plain_text,
        },
        &mut stats,
        &mut buffer,
        false,
    )
    .unwrap();

    let mut read_cursor = std::io::Cursor::new(buffer);
    let mut destination = Vec::new();
    read_chunk_block(&mut read_cursor, &mut destination).unwrap();

    assert!(destination == contents);
}

#[test]
fn roundtrip_chunk_block_png() {
    use crate::deflate_stream::decompress_deflate_stream;

    let f = crate::utils::read_file("treegdi.png");

    // we know the first IDAT chunk starts at 83 (avoid testing the scan_deflate code in a unit teast)
    let (idat_contents, deflate_stream) = crate::idat_parse::parse_idat(&f[83..], 1).unwrap();
    let results = decompress_deflate_stream(None, &deflate_stream, true, 1).unwrap();

    let total_chunk_length = idat_contents.total_chunk_length;

    let mut buffer = Vec::new();

    let mut stats = CompressionStats::default();
    write_chunk_block(
        &FoundStream {
            chunk_type: FoundStreamType::IDATDeflate(results.parameters.unwrap(), idat_contents),
            compressed_size: deflate_stream.len(),
            corrections: results.corrections,
            plain_text: results.plain_text,
        },
        &mut stats,
        &mut buffer,
        false,
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
    let mut context = PreflateCompressionContext::new(loglevel);
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
    let f = crate::utils::read_file(filename);

    let mut stats = CompressionStats::default();
    let mut expanded = Vec::new();
    expand_zlib_chunks(&f, 1, &mut stats, &mut expanded).unwrap();

    let mut read_cursor = std::io::Cursor::new(expanded);

    let mut destination = Vec::new();
    recreated_zlib_chunks(&mut read_cursor, &mut destination).unwrap();

    assert_eq!(destination.len(), f.len());
    for i in 0..destination.len() {
        assert_eq!(destination[i], f[i], "Mismatch at index {}", i);
    }
    assert!(destination == f);
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

    fn process_vec(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut writer = Vec::new();
        let mut done = self.process_buffer(input, true, &mut writer, usize::MAX)?;
        while !done {
            done = self.process_buffer(&[], true, &mut writer, usize::MAX)?;
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
    DeflateContinue(Option<DeflateContinueState>),
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
    pub fn new(log_level: u32) -> Self {
        PreflateCompressionContext {
            content: Vec::new(),
            compression_stats: CompressionStats::default(),
            result: VecDeque::new(),
            log_level,
            input_complete: false,
            min_chunk_size: 1024 * 1024,
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
                    if let Some((next, chunk, continue_state)) =
                        find_deflate_stream(&self.content, self.log_level)
                    {
                        // the gap between the start and the beginning of the deflate stream
                        // is written out as a literal block
                        if next.start != 0 {
                            write_literal_block(&self.content[..next.start], &mut self.result)?;
                        }

                        write_chunk_block(
                            &chunk,
                            &mut self.compression_stats,
                            &mut self.result,
                            continue_state.is_some(),
                        )?;

                        self.content.drain(0..next.end);

                        if let Some(continue_state) = continue_state {
                            self.state = ChunkParseState::DeflateContinue(Some(continue_state));
                        }
                    } else {
                        // couldn't find anything, just write the rest as a literal block
                        write_literal_block(&self.content, &mut self.result)?;

                        self.content.clear();
                    }
                }
                ChunkParseState::DeflateContinue(continue_state) => {
                    // here we have a deflate stream that we need to continue
                    let res = decompress_deflate_stream(
                        continue_state.take(),
                        &self.content,
                        true,
                        self.log_level,
                    );
                    if let Ok(res) = res {
                        self.result
                            .write_all(&[res.continue_state.is_some() as u8])?;

                        write_varint(&mut self.result, res.corrections.len() as u32)?;
                        write_varint(&mut self.result, res.plain_text.text().len() as u32)?;

                        self.result.write_all(&res.corrections)?;
                        self.result.write_all(&res.plain_text.text())?;

                        self.compression_stats.overhead_bytes += res.corrections.len() as u64;

                        if let Some(c) = res.continue_state {
                            self.state = ChunkParseState::DeflateContinue(Some(c));
                        } else {
                            self.state = ChunkParseState::Searching;
                        }

                        self.content.drain(0..res.compressed_size);
                    } else {
                        // error decompressing, just switch to a literal
                        self.state = ChunkParseState::Searching;
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

                    self.result.extend(recompress_deflate_stream_pred(
                        &plain_text,
                        &r.corrections,
                        &mut predictor,
                        *partial,
                    )?);

                    plain_text.shrink_to_dictionary();

                    if *partial {
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

                    self.result.extend(recompress_deflate_stream_pred(
                        dictionary,
                        &corrections,
                        predictor,
                        partial,
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

    let mut context = ZstdCompressContext::new(PreflateCompressionContext::new(0), 9, true);

    let _r = context.process_vec(&v).unwrap();

    let stats = context.stats();

    println!("stats: {:?}", stats);

    // these change if the compression algorithm is altered, update them
    assert_eq!(stats.overhead_bytes, 466);
    assert_eq!(stats.zstd_compressed_size, 12445);
    assert_eq!(stats.zstd_baseline_size, 13661);
}

#[test]
fn roundtrip_contexts() {
    use crate::utils::read_file;
    use crate::zstd_compression::{ZstdCompressContext, ZstdDecompressContext};

    let v = read_file("samplezip.zip");

    let mut context = ZstdCompressContext::new(PreflateCompressionContext::new(0), 9, false);

    let mut buffer = Vec::new();
    let mut pos = 0;
    loop {
        let amount_to_write = std::cmp::min(1024, v.len() - pos);
        let input = &v[pos..pos + amount_to_write];
        pos += amount_to_write;

        let done = context
            .process_buffer(input, pos == v.len(), &mut buffer, 333)
            .unwrap();
        if done {
            break;
        }
    }

    let stats = context.stats();
    println!("stats: {:?} buffer:{}", stats, buffer.len());
    println!(
        "zstd baseline size: {} -> comp {}",
        stats.zstd_baseline_size,
        buffer.len()
    );

    let mut context = ZstdDecompressContext::new(RecreateFromChunksContext::new(usize::MAX));
    let mut buffer2 = Vec::new();
    let mut pos = 0;
    loop {
        let amount_to_write = std::cmp::min(1024, buffer.len() - pos);
        let input = &buffer[pos..pos + amount_to_write];
        pos += amount_to_write;

        let done = context
            .process_buffer(input, pos == buffer.len(), &mut buffer2, 517)
            .unwrap();
        if done {
            break;
        }
    }

    assert!(v == buffer2);
}
